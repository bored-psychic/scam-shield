import builtins, contextlib, io, json, logging, os, re, shutil, socket, subprocess, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from unittest import mock
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin
from fastapi.testclient import TestClient
from shield.api.main import app
from shield.ocr import reader
from shield.core.report import to_report
from shield.core.router import analyse
from shield.ocr.reader import ImageRejected, ImageTooLarge, UnsupportedImage, clean_lines, read_image
from textprep import extract_urls

# python tests/test_ocr.py   (from the project root; needs tesseract + eng/hin/kan data and both models; no pytest required, but pytest collects test_ocr() too)
# Every image is drawn IN MEMORY with Pillow and never saved. Each check prints PASS / FAIL; O1-O3 also print their character error rates (CER).
#   O1 the 10 scam texts of docs/demo/demo_set.json as light-theme chat bubbles: CER <= 0.08 each, "OTP" and the URL survive, and the OCR text gets the
#      same verdict as the original; the rupee amounts are measured and printed as a KNOWN LIMIT, not asserted (see the note in the output)
#   O2 three of them in dark mode (white on dark grey): CER <= 0.08; with Tesseract's own auto-invert switched off, our invert step still reads them
#      and the un-inverted image does not (so the step is doing the work, not Tesseract's fallback)
#   O3 one Hindi sentence in a Devanagari font: CER printed (no threshold; skipped if no font)
#   O4 chat noise ("10:42 pm", "Today", "Forwarded", ticks, a dated header) is dropped and counted; links, amounts, OTP / PIN / UPI lines stay
#   O5 rejects over HTTP: 9 MB -> 413; text renamed .png -> 415; 1x1 png -> 422 "No text found in the screenshot."; plus reader-level limits (6001 px, truncated
#      file, GIF); accepted: JPEG, WEBP, a transparent PNG, an EXIF-rotated JPEG; no Tesseract / no language data -> 503, timeout -> 422, unexpected error -> generic 500
#   O6 no disk writes: builtins.open, os.open and every tempfile entry point (incl. the spill of a >1 MB upload) are made to raise; TMPDIR stays empty
#   O7 no network: sockets patched to record and refuse every connection / lookup while read_image runs
#   O8 API end to end: POST /api/ocr (d02 image) -> text with "OTP"; POST that text to /api/analyse -> suspicious or likely_scam; nothing is logged
#   O10 repair_links: the spaced-colon and space-after-a-dot repairs, the old pattern, and the cases that must stay unchanged (D19b). O9 / O11-O13 are not in this file yet.
MAX_CER = 0.08
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DEMO = [x for x in json.load(open(os.path.join(ROOT, "docs", "demo", "demo_set.json"), encoding="utf-8")) if x["kind"] == "scam"]
DARK_IDS = ["d02", "d06", "d08"]
HINDI = "आपका बैंक खाता आज बंद हो जाएगा। ओटीपी भेजें।"   # no short-i matra and no conjuncts: this Pillow build has no raqm, so nothing is shaped
LATIN_FONTS = ["/System/Library/Fonts/Helvetica.ttc", "/System/Library/Fonts/SFNS.ttf"]   # Arial / Verdana here have no rupee sign (they draw a box)
DEVANAGARI_FONTS = ["/System/Library/Fonts/Supplemental/Devanagari Sangam MN.ttc", "/System/Library/Fonts/KohinoorDevanagari.ttc"]
INFO = {}
_cache = {}


def note(tid, line):
    INFO.setdefault(tid, []).append(line)

def norm(s):
    return " ".join(s.split())

def cer(ref, hyp):
    """Levenshtein distance / len(ref), both whitespace-normalised."""
    ref, hyp = norm(ref), norm(hyp)
    prev = list(range(len(hyp) + 1))
    for i, a in enumerate(ref, 1):
        cur = [i]
        for j, b in enumerate(hyp, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a != b)))
        prev = cur
    return prev[-1] / max(len(ref), 1)

def font(paths, size):
    for p in paths:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return None

def to_png(img, **kw):
    b = io.BytesIO()
    img.save(b, "PNG", **kw)
    return b.getvalue()

def bubble(text, dark=False, width=1080, size=40, stamp="10:42 pm", fonts=LATIN_FONTS):
    """A chat screenshot: a 'Today' pill, one incoming bubble with the text wrapped at word boundaries, a timestamp under the text."""
    f, small = font(fonts, size), font(fonts, 28)
    bg, box, ink, faint = ((11, 20, 26), (32, 44, 51), (255, 255, 255), (134, 150, 160)) if dark else ((239, 234, 226), (255, 255, 255), (17, 27, 33), (102, 119, 129))
    left, pad, inner = 40, 30, 1080 - 2 * 40 - 2 * 30
    lines, cur = [], ""
    for word in text.split():
        t = (cur + " " + word).strip()
        if f.getlength(t) <= inner or not cur:
            cur = t
        else:
            lines.append(cur)
            cur = word
    lines.append(cur)
    lh = int(size * 1.4)
    top = 150
    h = top + pad + len(lines) * lh + 50 + pad + 120
    img = Image.new("RGB", (width, h), bg)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((width // 2 - 80, 40, width // 2 + 80, 100), 24, fill=box)
    d.text((width // 2, 70), "Today", font=small, fill=faint, anchor="mm")
    d.rounded_rectangle((left, top, width - left, top + pad + len(lines) * lh + 50 + pad), 28, fill=box)
    for i, line in enumerate(lines):
        d.text((left + pad, top + pad + i * lh), line, font=f, fill=ink)
    d.text((width - left - pad, top + pad + len(lines) * lh + 25), stamp, font=small, fill=faint, anchor="rm")
    return to_png(img)

def image(key, **kw):
    if key not in _cache:
        _cache[key] = bubble(**kw)
    return _cache[key]

def light(item):
    return image(("light", item["id"]), text=item["text"])

def dark(item):
    return image(("dark", item["id"]), text=item["text"], dark=True)

def amounts(text):
    return re.findall(r"₹\s?[\d,]+", text)

def phrases_lost(item, got):
    """Key phrases of the original that are not in the OCR text: OTP, and every URL (spaces ignored)."""
    flat = "".join(got.split())
    lost = ["OTP"] if "OTP" in item["text"] and "OTP" not in got else []
    return lost + [u for u in extract_urls(item["text"]) if u not in flat]

def amount_stats(item, got):
    """(amounts in the original, rupee sign kept before the number, number present on its own). 'On its own' = not glued to another digit:
    Tesseract often reads the rupee sign as a '2', which turns 5,000 into 25,000, so a substring test would call that a survivor."""
    n = sign = alone = 0
    for a in amounts(item["text"]):
        digits = a.lstrip("₹ ")
        n += 1
        sign += bool(re.search(r"(?:₹|Rs\.?|INR)\s?" + re.escape(digits), got))
        alone += bool(re.search(r"(?<![\d,])" + re.escape(digits) + r"(?![\d])", got))
    return n, sign, alone

def level_of(c, text):
    return to_report(text, analyse(text, c.app.state.text_model, c.app.state.url_model)).level.value


def o1(c):
    bad, tot = [], [0, 0, 0]
    for item in DEMO:
        res = read_image(light(item))
        e, lost, got = cer(item["text"], res["text"]), phrases_lost(item, res["text"]), res["text"]
        n, sign, alone = amount_stats(item, got)
        tot = [tot[0] + n, tot[1] + sign, tot[2] + alone]
        want_level, got_level = level_of(c, item["text"]), level_of(c, got)
        note("O1", f"{item['id']}  CER {e:.3f}  {res['ms']:5.0f} ms  dropped {res['dropped']}  lost {lost or '-'}  level {want_level} -> {got_level}")
        if e > MAX_CER:
            bad.append(f"{item['id']}: CER {e:.3f} > {MAX_CER}   got: {norm(got)}")
        if lost:
            bad.append(f"{item['id']}: key phrases lost {lost}   got: {norm(got)}")
        if got_level != want_level:
            bad.append(f"{item['id']}: the OCR text gets a different verdict ({want_level} -> {got_level})   got: {norm(got)}")
    note("O1", f"KNOWN LIMIT (not asserted): of {tot[0]} rupee amounts the sign is kept {tot[1]}x and the number stands alone {tot[2]}x; "
               f"Tesseract's eng/hin/kan data reads the rupee sign as 2 / ~ / $ / a Devanagari digit, or drops it (the user must check amounts)")
    return bad

def tesseract_raw(png, *extra):
    """The same Tesseract call as the reader's, with extra options (here: its own auto-invert switched off)."""
    p = subprocess.run([reader._find_tesseract(), "stdin", "stdout", "-l", reader.LANGS, "--psm", "6", *extra], input=png, capture_output=True, timeout=30)
    return " ".join(clean_lines(p.stdout.decode("utf-8", "replace"))[0])

def median_of(png):
    return reader._median(Image.open(io.BytesIO(png)))

def o2(c):
    bad = []
    for item in [x for x in DEMO if x["id"] in DARK_IDS]:
        res = read_image(dark(item))
        e = cer(item["text"], res["text"])
        ours, plain = reader._prepare(dark(item)), reader._prepare(dark(item), invert=False)
        # Tesseract 5 re-reads a page inverted when its first pass looks bad, which hides the need for our step (and costs a second pass);
        # with that fallback off (-c tessedit_do_invert=0) the un-inverted dark image is unreadable.
        off_ours, off_plain = cer(item["text"], tesseract_raw(ours, "-c", "tessedit_do_invert=0")), cer(item["text"], tesseract_raw(plain, "-c", "tessedit_do_invert=0"))
        note("O2", f"{item['id']}  CER {e:.3f}   (Tesseract's own auto-invert off: {off_ours:.3f} with our invert, {off_plain:.3f} without it)")
        if e > MAX_CER:
            bad.append(f"{item['id']}: CER {e:.3f} > {MAX_CER}   got: {norm(res['text'])}")
        if off_ours > MAX_CER:
            bad.append(f"{item['id']}: with Tesseract's own invert off, our inverted image reads with CER {off_ours:.3f}")
        if off_plain <= MAX_CER:
            bad.append(f"{item['id']}: the un-inverted dark image also reads (CER {off_plain:.3f}), so this fixture no longer shows what the invert step is for")
        if median_of(ours) < 128 or median_of(reader._prepare(light(item))) < 128:
            bad.append(f"{item['id']}: the prepared image is dark (dark median {median_of(ours)}), the invert step did not run as intended")
    return bad

def o3(c):
    f = font(DEVANAGARI_FONTS, 44)
    if f is None:
        note("O3", "SKIPPED: no Devanagari font found")
        return []
    img = bubble(HINDI, fonts=DEVANAGARI_FONTS, size=44)
    res = read_image(img)
    note("O3", f"CER {cer(HINDI, res['text']):.3f} (informational; Pillow here has no raqm, so the sentence is drawn unshaped)")
    note("O3", "got: " + norm(res["text"]).encode("ascii", "backslashreplace").decode())
    return [] if res["text"] else ["Hindi image gave no text"]

REPAIRS = [   # (label, text in, text out)
    ("spaced colon, bet365", "https :/Awww.bet365.com/", "https://www.bet365.com/"),
    ("spaced colon, example.in", "http : /Aexample.in/x", "http://example.in/x"),
    ("spaced colon, host without www", "https :/Aexample.in", "https://example.in"),
    ("spaced colon inside a sentence", "Click https :/Awww.bet365.com/ now", "Click https://www.bet365.com/ now"),
    ("spaced colon, proper slashes", "https : //www.x.com/a", "https://www.x.com/a"),
    ("old pattern: https:/A", "https:/Awww.bet365.com/", "https://www.bet365.com/"),
    ("old pattern: stray bracket", "https://(www.x.com/a", "https://www.x.com/a"),
    ("old pattern: one slash", "https:/www.x.com", "https://www.x.com"),
    ("old pattern: valid link unchanged", "https://www.x.com/", "https://www.x.com/"),
    ("unspaced single slash + host stays", "https:/sbi.top/x", "https:/sbi.top/x"),
    ("http:/ in a sentence stays", "see http:/ note", "see http:/ note"),
    ("Awww without a scheme stays", "Awww.x.com and https://bit.ly/a", "Awww.x.com and https://bit.ly/a"),
    ("valid link unchanged", "https://ok.com/a", "https://ok.com/a"),
    ("not a scheme: ratio 3 :/A", "ratio 3 :/A done", "ratio 3 :/A done"),
    ("bare https :/A stays", "https :/A", "https :/A"),
    ("bare https :/A in a sentence stays", "see https :/A now", "see https :/A now"),
    ("capitalised host keeps its E", "https :/Example.in", "https :/Example.in"),
    ("space after the colon but no slash stays", "score http : 3 /A", "score http : 3 /A"),
    ("space after a dot, the Jio link", "https://t. jio/TIOCPN/x48NuN", "https://t.jio/TIOCPN/x48NuN"),
    ("space after a dot, www", "https://www. example.com/a", "https://www.example.com/a"),
    ("space after a dot, no path", "https://t. jio", "https://t.jio"),
    ("no scheme: Visit t. Then go", "Visit t. Then go", "Visit t. Then go"),
    ("sentence-final link, capital next word", "https://ok.com. Next line", "https://ok.com. Next line"),
    ("sentence-final link, lower-case next word", "Visit https://ok.com. then pay", "Visit https://ok.com. then pay"),
    ("sentence-final link with a path, lower-case next word", "see https://bit.ly/a. then go", "see https://bit.ly/a. then go"),
    ("two valid parts stay", "https://t.jio/a b", "https://t.jio/a b"),
    ("both repairs in one line", "Claim now: https://t. jio/TIOCPN/x48NuN T&C*", "Claim now: https://t.jio/TIOCPN/x48NuN T&C*"),
]

def o10(c):
    bad = []
    for label, src, want in REPAIRS:
        got = reader.repair_links(src)
        if got != want:
            bad.append(f"{label}: repair_links({src!r}) = {got!r}, wanted {want!r}")
        if reader.repair_links(got) != got:
            bad.append(f"{label}: not idempotent ({got!r} -> {reader.repair_links(got)!r})")
    note("O10", f"{len(REPAIRS)} cases, each also checked to be idempotent")
    return bad

def o4(c):
    raw = "\n".join(["Forwarded many times", "Today", "Hello, pay Rs 500 now", "10:42 pm", "", "22:05", "✓✓", "Visit http://x.top/a",
                     "12 October 2026", "10:42 pm ✓✓", "Your OTP is 123456", "Forwarded", "Yesterday", "Pay by 12 October", "Monday",
                     "bit.ly/abc", "₹500", "Enter UPI PIN", "10.42 AM", "Forwarded OTP"])
    lines, dropped = clean_lines(raw)
    want = ["Hello, pay Rs 500 now", "Visit http://x.top/a", "Your OTP is 123456", "Pay by 12 October", "Monday", "bit.ly/abc", "₹500", "Enter UPI PIN", "Forwarded OTP"]
    bad = [] if lines == want else [f"kept {lines}, wanted {want}"]
    if dropped != 10:
        bad.append(f"dropped {dropped}, wanted 10 (Forwarded many times, Today, 10:42 pm, 22:05, ticks, 12 October 2026, 10:42 pm + ticks, Forwarded, Yesterday, 10.42 AM; the blank line is not counted)")
    for src, want in [("https:/Awww.bet365.com/", "https://www.bet365.com/"), ("https://(www.x.com/a", "https://www.x.com/a"), ("https:/www.x.com", "https://www.x.com"),
                      ("https://www.x.com/", "https://www.x.com/"), ("https:/sbi.top/x", "https:/sbi.top/x"), ("see http:/ note", "see http:/ note"),
                      ("Awww.x.com and https://bit.ly/a", "Awww.x.com and https://bit.ly/a")]:
        if reader.repair_links(src) != want:
            bad.append(f"repair_links({src!r}) = {reader.repair_links(src)!r}, wanted {want!r}")
    res = read_image(light(DEMO[1]))
    if res["dropped"] < 2:
        bad.append(f"the 'Today' pill and the timestamp of a rendered bubble were not both dropped (dropped {res['dropped']}): {res['lines']}")
    return bad

def o5_reader():
    bad = []
    cases = [("9 MB", b"\x89PNG\r\n\x1a\n" + b"\0" * (9 * 1024 * 1024), ImageTooLarge), ("text", b"hello this is not an image", UnsupportedImage),
             ("gif", b"GIF89a" + b"\0" * 50, UnsupportedImage), ("riff but not webp", b"RIFF\0\0\0\0WAVE" + b"\0" * 20, UnsupportedImage),
             ("truncated png", to_png(Image.new("RGB", (400, 200), "white"))[:60], ImageRejected),
             ("6001 px wide", to_png(Image.new("L", (6001, 20), 255), compress_level=9), ImageRejected)]
    for label, data, exc in cases:
        try:
            read_image(data)
            bad.append(f"reader {label}: no error")
        except exc as e:
            if type(e) is not exc and exc is not ImageRejected:
                bad.append(f"reader {label}: {type(e).__name__}")
            if not str(e) or any(ch in str(e) for ch in "\\{}"):
                bad.append(f"reader {label}: message is not plain text: {e!r}")
        except Exception as e:
            bad.append(f"reader {label}: {type(e).__name__}: {e}")
    return bad

def o5_accepts(c):
    """JPEG, WEBP, a transparent PNG (black text, no background: a naive grayscale conversion would be all black) and a JPEG whose EXIF
    orientation says it was stored rotated are all read."""
    bad = []
    base = Image.open(io.BytesIO(light(DEMO[1]))).convert("RGB")
    def save(img, fmt, **kw):
        b = io.BytesIO()
        img.save(b, fmt, **kw)
        return b.getvalue()
    clear = Image.new("RGBA", (1080, 200), (0, 0, 0, 0))
    ImageDraw.Draw(clear).text((30, 60), "Your OTP is 482913", font=font(LATIN_FONTS, 48), fill=(0, 0, 0, 255))
    exif = Image.Exif()
    exif[0x0112] = 6   # "rotate 90 degrees clockwise to display": the pixels are stored rotated 90 degrees counter-clockwise
    cases = [("jpeg", save(base, "JPEG", quality=85), "image/jpeg", "OTP"), ("webp", save(base, "WEBP"), "image/webp", "OTP"),
             ("transparent png", to_png(clear), "image/png", "482913"), ("exif-rotated jpeg", save(base.rotate(90, expand=True), "JPEG", quality=90, exif=exif), "image/jpeg", "OTP")]
    for label, data, ctype, want in cases:
        r = c.post("/api/ocr", files={"image": ("shot", data, ctype)})
        if r.status_code != 200 or want not in r.json().get("text", ""):
            bad.append(f"{label}: {r.status_code} {r.text[:150]}")
    return bad

def o5_errors(c):
    """Every failure maps to its status with a fixed plain message; an unexpected error is a generic 500 that does not carry its text."""
    bad = []
    png = light(DEMO[1])
    def post():
        return c.post("/api/ocr", files={"image": ("a.png", png, "image/png")})
    def boom(_png):
        raise RuntimeError("SECRET message text")
    cases = [("no Tesseract", dict(_find_tesseract=lambda: None), 503, "not installed"), ("no language data", dict(LANGS="zzz"), 503, "language data"),
             ("timeout", dict(TIMEOUT_S=0.01), 422, "took too long"), ("unexpected error", dict(_tesseract=boom), 500, "Reading the screenshot failed.")]
    for label, patch, status, fragment in cases:
        with contextlib.ExitStack() as stack:
            for name, value in patch.items():
                stack.enter_context(mock.patch.object(reader, name, value))
            r = post()
        if r.status_code != status or fragment not in r.text or "SECRET" in r.text:
            bad.append(f"{label}: {r.status_code} {r.text[:150]}")
    return bad

def o5(c):
    bad = o5_reader() + o5_accepts(c) + o5_errors(c)
    def up(data, name="shot.png", ctype="image/png"):
        return c.post("/api/ocr", files={"image": (name, data, ctype)})
    r = up(b"\x89PNG\r\n\x1a\n" + b"\0" * (9 * 1024 * 1024))
    if r.status_code != 413:
        bad.append(f"9 MB: {r.status_code} {r.text[:100]}")
    r = up(b"hello, this is a text file", "notes.png")
    if r.status_code != 415:
        bad.append(f".txt renamed .png: {r.status_code} {r.text[:100]}")
    r = up(to_png(Image.new("RGB", (1, 1), "white")))
    if (r.status_code, r.json()) != (422, {"detail": "No text found in the screenshot."}):
        bad.append(f"1x1 png: {r.status_code} {r.text[:100]}")
    r = up(to_png(Image.new("L", (6001, 20), 255), compress_level=9))
    if r.status_code != 422:
        bad.append(f"6001 px wide: {r.status_code} {r.text[:100]}")
    for label, r in (("no image field", c.post("/api/ocr", files={"other": ("a.png", b"x", "image/png")})), ("json body", c.post("/api/ocr", json={"image": "x"})),
                     ("GET", c.get("/api/ocr"))):
        want = 405 if label == "GET" else 422
        if r.status_code != want:
            bad.append(f"{label}: {r.status_code} {r.text[:100]}")
    return bad

def padded(img_png, extra_chunks=4, chunk_bytes=400_000):
    """The same screenshot as a valid PNG of more than 1 MB (text chunks of filler), the size at which an UploadFile would spill to disk."""
    img = Image.open(io.BytesIO(img_png))
    info = PngImagePlugin.PngInfo()
    for i in range(extra_chunks):
        info.add_text(f"filler{i}", "x" * chunk_bytes)
    return to_png(img, pnginfo=info)

@contextlib.contextmanager
def no_disk_writes():
    hits = []
    def refuse(name):
        def f(*a, **k):
            hits.append(name)
            raise OSError(f"O6: disk access blocked ({name})")
        return f
    targets = [(builtins, "open"), (os, "open"), (tempfile, "mkstemp"), (tempfile, "mkdtemp"), (tempfile, "TemporaryFile"),
               (tempfile, "NamedTemporaryFile"), (tempfile.SpooledTemporaryFile, "rollover")]
    saved = [(o, n, o.__dict__[n]) for o, n in targets]
    try:
        for o, n, _ in saved:
            setattr(o, n, refuse(f"{getattr(o, '__name__', 'SpooledTemporaryFile')}.{n}"))
        yield hits
    finally:
        for o, n, f in saved:
            setattr(o, n, f)

def o6(c):
    item = DEMO[1]
    png = light(item)
    big = padded(png)
    assert len(big) > 1024 * 1024, len(big)
    read_image(png)   # warm-up: lazy imports and the mimetypes table are read here, not under the patch
    c.post("/api/ocr", files={"image": ("w.png", png, "image/png")})
    bad, scratch = [], tempfile.mkdtemp()   # TMPDIR for the Tesseract child: it must stay empty
    old_tmp = os.environ.get("TMPDIR")
    os.environ["TMPDIR"] = scratch
    try:
        with no_disk_writes() as hits:
            probes = [("builtins.open", lambda: open(__file__)), ("os.open", lambda: os.open(__file__, os.O_RDONLY)), ("tempfile.mkstemp", tempfile.mkstemp),
                      ("SpooledTemporaryFile spill", lambda: tempfile.SpooledTemporaryFile(max_size=1).write(b"xx"))]
            for name, probe in probes:
                try:
                    probe()
                    bad.append(f"the guard is not live: {name} did not raise")
                except OSError:
                    pass
            hits.clear()   # the probes above are not attempts by the code under test
            res = read_image(png)
            r = c.post("/api/ocr", files={"image": ("big.png", big, "image/png")})
        if hits:
            bad.append(f"disk access attempted: {hits}")
        if "OTP" not in res["text"]:
            bad.append(f"read_image under the patch lost the text: {res['text']!r}")
        if r.status_code != 200 or "OTP" not in r.json().get("text", ""):
            bad.append(f"{len(big) // 1024} KB upload under the patch: {r.status_code} {r.text[:150]}")
        if os.listdir(scratch):
            bad.append(f"Tesseract left files in TMPDIR: {os.listdir(scratch)}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        if old_tmp is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old_tmp
    note("O6", f"{len(big) // 1024} KB upload (> the 1 MB spill size) read in memory; patched: builtins.open, os.open, tempfile.mkstemp / mkdtemp / TemporaryFile / NamedTemporaryFile / SpooledTemporaryFile.rollover")
    return bad

def o7(c):
    png, attempts, names = light(DEMO[1]), [], ("connect", "connect_ex")
    saved_methods = {n: socket.socket.__dict__.get(n) for n in names}   # None = inherited from the C base class
    saved_funcs = {n: getattr(socket, n) for n in ("create_connection", "getaddrinfo", "gethostbyname")}
    def refuse(name):
        def f(*a, **k):
            attempts.append(name)
            raise OSError(f"O7: outbound network call blocked ({name})")
        return f
    try:
        for n in names:
            setattr(socket.socket, n, refuse(n))
        for n in saved_funcs:
            setattr(socket, n, refuse(n))
        try:
            socket.create_connection(("127.0.0.1", 9))
            return ["the guard is not live: create_connection did not raise"]
        except OSError:
            pass
        attempts.clear()   # the line above was the probe
        res = read_image(png)
        bad = [] if "OTP" in res["text"] else [f"no text under the network guard: {res['text']!r}"]
        if attempts:
            bad.append(f"outbound attempts during read_image: {attempts}")
        return bad
    finally:
        for n, f in saved_methods.items():
            delattr(socket.socket, n) if f is None else setattr(socket.socket, n, f)
        for n, f in saved_funcs.items():
            setattr(socket, n, f)

def o8(c):
    item = DEMO[1]
    secret = "sbi-kyc-update"
    records, sink = [], io.StringIO()
    class Keep(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())
    root, old_level = logging.getLogger(), logging.getLogger().level
    h = Keep(level=logging.DEBUG)
    root.addHandler(h)
    root.setLevel(logging.DEBUG)
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            r = c.post("/api/ocr", files={"image": ("d02.png", light(item), "image/png")})
            j = r.json() if r.status_code == 200 else {}
            r2 = c.post("/api/analyse", json={"text": j.get("text", "")}) if j else None
    finally:
        root.removeHandler(h)
        root.setLevel(old_level)
    bad = []
    if r.status_code != 200:
        return [f"/api/ocr: {r.status_code} {r.text[:150]}"]
    if set(j) != {"text", "lines", "dropped", "ms"}:
        bad.append(f"response keys {sorted(j)}")
    if "OTP" not in j["text"]:
        bad.append(f"no OTP in the OCR text: {j['text']!r}")
    if j["text"] != "\n".join(j["lines"]) or not isinstance(j["dropped"], int) or not isinstance(j["ms"], float):
        bad.append(f"inconsistent fields: {j['dropped']!r} {j['ms']!r}")
    if r2.status_code != 200 or r2.json()["level"] not in ("likely_scam", "suspicious"):
        bad.append(f"/api/analyse on the OCR text: {r2.status_code} {r2.json().get('level') if r2.status_code == 200 else r2.text[:100]}")
    else:
        note("O8", f"ocr {j['ms']:.0f} ms, {len(j['lines'])} lines, dropped {j['dropped']} -> analyse level {r2.json()['level']}")
    leaked = [m[:80] for m in records + [sink.getvalue()] if secret in m or "OTP" in m]
    if leaked:
        bad.append(f"message text reached a log record or stdout / stderr: {leaked}")
    return bad


CHECKS = [("O1", "10 demo scam texts as light chat bubbles: CER <= 0.08, key phrases survive", o1),
          ("O2", "3 of them in dark mode: CER <= 0.08 (the invert step is needed once Tesseract's own fallback is off)", o2),
          ("O3", "Hindi sentence (informational CER)", o3),
          ("O4", "chat noise dropped and counted; links / amounts / OTP lines kept", o4),
          ("O5", "413 for 9 MB, 415 for text renamed .png, 422 for a 1x1 png; JPEG / WEBP / transparent / EXIF-rotated images read; 503 / 500 / timeout mapped", o5),
          ("O6", "no disk writes (open, os.open, tempfile, upload spill), TMPDIR stays empty", o6),
          ("O7", "no network while reading", lambda c: o7(c)),
          ("O8", "API end to end: /api/ocr -> /api/analyse, nothing logged", o8),
          ("O10", "narrow link repairs: spaced colon, space after a dot; the old pattern and everything that must stay unchanged", o10)]

def run():
    out = []
    with TestClient(app) as c:
        for tid, what, fn in CHECKS:
            out.append((tid, what, fn(c)))
    return out

def test_ocr():
    bad = [f"{tid}: {b}" for tid, _, bs in run() for b in bs]
    assert not bad, "\n".join(bad)

if __name__ == "__main__":
    results = run()
    for tid, what, bad in results:
        print(f"{'FAIL' if bad else 'PASS'} {tid} {what}")
        for line in INFO.get(tid, []):
            print("    " + line)
        for b in bad[:10]:
            print("    ! " + b.encode("ascii", "backslashreplace").decode()[:300])
    print(f"\n{sum(not b for _, _, b in results)}/{len(results)} passed")
    sys.exit(1 if any(b for _, _, b in results) else 0)
