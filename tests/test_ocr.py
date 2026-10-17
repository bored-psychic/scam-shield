from urllib.parse import urlsplit
import builtins, contextlib, io, json, logging, os, re, shutil, socket, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from unittest import mock
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin
from fastapi.testclient import TestClient
from shield.api.main import app
from shield.ocr import reader
from shield.core.report import to_report
from shield.core.router import analyse
from shield.ocr.reader import ImageRejected, ImageTooLarge, Line, UnsupportedImage, clean_lines, join_wrapped_lines, parse_tsv, read_image
from textprep import extract_urls
from ocr_render import DEVANAGARI_FONTS, LATIN_FONTS, bubble, font, to_png
from test_demo import LOCKED as DEMO_LEVELS

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
#   O10 repair_links: the spaced-colon and space-after-a-dot repairs, the old pattern, and the cases that must stay unchanged (D19b)
#   O13 the real Jio screenshot tests/fixtures/real/jio_kiwi_dark.jpg: link with host t.jio + a / path, "Dear User" / "Claim now" / "JioCoupons" lines, verdict Likely scam
#       (as for the typed text), the Link panel lists the link; and with the colour step switched off the link is lost (the fixture still exercises the fix). O11-O12 are unused.
#   O14 soft-wrapped lines on the REAL screenshot: the bubble's wraps are joined with a space, the typed breaks (and the two blank lines) stay, exactly
#       JIO_JOINED once the two known misreads are mapped back (T&C* -> 740", JIOCPN -> TIOCPN). Prints the text before (every wrap a line) and after.
#   O15 join_wrapped_lines on hand-built line boxes (no Tesseract): every rule alone - sentence end, open bracket, blank line, links on either side, list item,
#       left margin, short column, 0.7 ratio, next-word test, noise lines as barriers, leading / trailing noise, other bubbles' columns
#   O16 synthetic renders: two paragraphs keep their blank line; a short-line list is not joined; "...:" + a link is not joined; a long line + a link is not
#       joined; a wrapped paragraph + a typed sign-off; and all 14 demo messages as screenshots keep the verdict of the text (the levels locked in test_demo.py)
#   O9 coloured, underlined links in dark mode (iOS Messages blue, plain blue; plus WhatsApp / Google Messages / Telegram dark, and iOS light / white-on-blue as
#      guards): every link survives with CER <= 0.08; with the recovery step switched off the first two lose it (the fixture still exercises the fix); an exactly
#      grey theme and a saturated bubble on a light page (PNG + a JPEG that gets inverted) give a byte-identical prepared image with and without the step
MAX_CER = 0.08
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DEMO = [x for x in json.load(open(os.path.join(ROOT, "docs", "demo", "demo_set.json"), encoding="utf-8")) if x["kind"] == "scam"]
DARK_IDS = ["d02", "d06", "d08"]
HINDI = "आपका बैंक खाता आज बंद हो जाएगा। ओटीपी भेजें।"   # no short-i matra and no conjuncts: this Pillow build has no raqm, so nothing is shaped
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

# Chat apps draw links in a colour and underline them; the plain-ink fixtures above cannot show what happens to those. (page, bubble, ink, faint, link)
THEMES = {
    "Google Messages dark (MEASURED)": ((0, 0, 0), (32, 33, 37), (240, 240, 240), (140, 140, 145), (40, 105, 220)),   # page, bubble, text and link measured from tests/fixtures/real/jio_kiwi_dark.jpg; the timestamp colour is assumed
    "iOS Messages dark": ((0, 0, 0), (38, 38, 41), (255, 255, 255), (140, 140, 145), (10, 132, 255)),   # every other theme: colours assumed (remembered from the apps), not sampled
    "plain blue on dark grey": ((18, 18, 18), (40, 40, 40), (235, 235, 235), (140, 140, 140), (0, 0, 238)),
    "WhatsApp dark": ((11, 20, 26), (32, 44, 51), (233, 237, 239), (134, 150, 160), (83, 189, 235)),
    "Google Messages dark": ((32, 33, 36), (60, 64, 67), (232, 234, 237), (154, 160, 166), (138, 180, 248)),
    "Telegram dark": ((14, 22, 33), (24, 37, 51), (255, 255, 255), (109, 127, 143), (106, 179, 243)),
    "iOS Messages light": ((255, 255, 255), (233, 233, 235), (0, 0, 0), (130, 130, 135), (0, 122, 255)),
    "iOS sent (white on a blue bubble)": ((255, 255, 255), (0, 122, 255), (255, 255, 255), (200, 225, 255), (255, 255, 255)),
    "WhatsApp dark outgoing (teal)": ((11, 20, 26), (0, 92, 75), (233, 237, 239), (150, 190, 180), (83, 189, 235)),
    "Telegram dark outgoing (blue)": ((14, 22, 33), (43, 82, 120), (255, 255, 255), (160, 190, 220), (140, 200, 255)),
    "neutral grey (no colour at all)": ((18, 18, 18), (40, 40, 40), (235, 235, 235), (140, 140, 140), (235, 235, 235)),
}
LOST_BEFORE = ["Google Messages dark (MEASURED)", "iOS Messages dark", "plain blue on dark grey"]   # the themes whose links the old greyscale conversion lost
LINKED = [x for x in DEMO if extract_urls(x["text"])]

def themed(name, item):
    return image(("theme", name, item["id"]), text=item["text"], theme=THEMES[name])

def as_jpeg(png, quality=80):
    b = io.BytesIO()
    Image.open(io.BytesIO(png)).convert("RGB").save(b, "JPEG", quality=quality)
    return b.getvalue()

def step_off():
    """The recovery of coloured strokes switched off: _prepare is then the plain luma conversion it was before."""
    return mock.patch.object(reader, "_coloured_ink", lambda rgb, grey, box: grey)

def o9(c):
    bad = []
    runs = ([(t, x) for t in LOST_BEFORE for x in LINKED]                                                                                   # all four links, every theme the old conversion lost
            + [(t, x) for t in ("WhatsApp dark", "Google Messages dark", "Telegram dark") for x in LINKED if x["id"] in ("d06", "d10")]    # dark themes that already worked
            + [(t, x) for t in ("iOS Messages light", "iOS sent (white on a blue bubble)") for x in LINKED if x["id"] in ("d02", "d10")])   # must not get worse
    for theme, item in runs:
        res = read_image(themed(theme, item))
        e, lost = cer(item["text"], res["text"]), phrases_lost(item, res["text"])
        note("O9", f"{theme:34s} {item['id']}  CER {e:.3f}  lost {lost or '-'}")
        if lost or e > MAX_CER:
            bad.append(f"{theme} / {item['id']}: lost {lost}, CER {e:.3f}   got: {norm(res['text'])}")
    # The fixture must still show what the step is for: without it, the coloured link of at least one of these is lost, as it was.
    with step_off():
        lost_without = [t for t in LOST_BEFORE if phrases_lost(DEMO[1], read_image(themed(t, DEMO[1]))["text"])]
    note("O9", f"with the step switched off the d02 link is lost in: {lost_without}")
    if lost_without != LOST_BEFORE:
        bad.append(f"with the step off the link should be lost in {LOST_BEFORE}, but only in {lost_without}: the fixture no longer exercises the fix")
    # Where it must change nothing: an exactly grey theme (PNG and JPEG) and a saturated bubble on a light page (PNG, and a JPEG whose median
    # brightness is below 128, so it is inverted: the case a first version of the step damaged by blackening the gaps between white letters).
    d01 = DEMO[0]
    d07 = next(x for x in DEMO if x["id"] == "d07")   # has a link, so there is a coloured stroke on the page: the teal / blue bubbles must still be left alone
    checks = [("neutral grey png", themed("neutral grey (no colour at all)", d01)), ("neutral grey jpeg", as_jpeg(themed("neutral grey (no colour at all)", d01))),
              ("iOS sent png", themed("iOS sent (white on a blue bubble)", d01)), ("iOS sent jpeg", as_jpeg(themed("iOS sent (white on a blue bubble)", d01))),
              ("teal outgoing png", themed("WhatsApp dark outgoing (teal)", d07)), ("teal outgoing jpeg", as_jpeg(themed("WhatsApp dark outgoing (teal)", d07))),
              ("blue outgoing png", themed("Telegram dark outgoing (blue)", d07)), ("blue outgoing jpeg", as_jpeg(themed("Telegram dark outgoing (blue)", d07)))]
    if median_of(checks[3][1]) >= 128:
        bad.append("the iOS sent JPEG is no longer inverted (median brightness >= 128), so it does not exercise the saturated-bubble gate")
    for label, png in checks:
        with_step = reader._prepare(png)
        with step_off():
            without = reader._prepare(png)
        if with_step != without:
            bad.append(f"{label}: the prepared image changed ({len(with_step)} vs {len(without)} bytes) although the step must not touch it")
    tall = Image.open(io.BytesIO(themed("iOS Messages dark", LINKED[0]))).convert("RGB").resize((1170, 2532))   # a phone-sized screenshot
    b = io.BytesIO()
    tall.save(b, "PNG")
    t0 = time.perf_counter()
    reader._prepare(b.getvalue())
    note("O9", f"_prepare on a 1170 x 2532 dark screenshot: {1000 * (time.perf_counter() - t0):.0f} ms (the step included)")
    return bad

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

REAL = os.path.join(ROOT, "tests", "fixtures", "real", "jio_kiwi_dark.jpg")   # a real Android (Google Messages style) dark-mode screenshot of a Jio promo SMS: dev-set fixture, never test-set
JIO_TEXT = "Dear User,\nYou've earned Lifetime Free\nKiwi UPI Credit Card (CC:\nJIOKIWI) on JioRecharge.\nClaim now:\nhttps://t.jio/JIOCPN/x48NuN\nT&C*\nJioCoupons"   # what the screenshot says

def jio_links(text):
    """Links in `text` whose host is t.jio and whose path starts with '/'."""
    found = []
    for u in extract_urls(text):
        p = urlsplit(u if "://" in u else "http://" + u)
        if p.hostname == "t.jio" and p.path.startswith("/"):
            found.append(u)
    return found

def o13(c):
    bad = []
    data = open(REAL, "rb").read()
    res = read_image(data)
    text, lines = res["text"], res["lines"]
    note("O13", f"{res['ms']:.0f} ms; OCR lines: " + " | ".join(lines))
    # 1. the link is there: host t.jio, a path starting with /
    links = jio_links(text)
    if not links:
        bad.append(f"no link with host t.jio and a path starting with / in the OCR text: {norm(text)}")
    # 2. the other lines still read
    for want in ("Dear User", "Claim now", "JioCoupons"):
        if not any(want in line for line in lines):
            bad.append(f"line {want!r} is missing from the OCR text: {lines}")
    # 3. the verdict is the one the typed text gets, and the Link panel lists the link
    rep, ref = to_report(text, analyse(text, c.app.state.text_model, c.app.state.url_model)), to_report(JIO_TEXT, analyse(JIO_TEXT, c.app.state.text_model, c.app.state.url_model))
    panel = [e.quote for ch in rep.children if ch.module == "links" for e in ch.evidence if e.id == "model.url"]
    note("O13", f"verdict {rep.level.value} (typed text: {ref.level.value}); Link panel: {panel}")
    if rep.level.value != "likely_scam" or rep.level != ref.level:
        bad.append(f"verdict {rep.level.value}, wanted likely_scam (the typed text gets {ref.level.value})")
    if not jio_links("\n".join(panel)):
        bad.append(f"the Link panel does not list the t.jio link: {panel}")
    # The fixture must still show what the step is for: without the dark-mode colour step this screenshot loses the link.
    with step_off():
        plain = read_image(data)["text"]
    note("O13", f"with the colour step switched off the link is {'present (the fixture no longer shows what the step is for)' if jio_links(plain) else 'lost, as before'}")
    if jio_links(plain):
        bad.append("with the colour step switched off the link is still read: this fixture no longer exercises the fix")
    return bad

# ---- soft-wrapped lines (2026-10-18) --------------------------------------------------------------------------------------------------
JIO_JOINED = "Dear User,\n\nYou've earned Lifetime Free Kiwi UPI Credit Card (CC: JIOKIWI) on JioRecharge.\nClaim now:\nhttps://t.jio/JIOCPN/x48NuN\nT&C*\n\nJioCoupons"
JIO_MISREADS = [("https://t.jio/ TIOCPN/x48NuN", "https://t.jio/JIOCPN/x48NuN"), ('740"', "T&C*")]   # what Tesseract 5.5.3 reads on this image (BUGS.md D19 (10), (12)); the link repair does not cover them on purpose

def o14(c):
    bad = []
    data = open(REAL, "rb").read()
    res = read_image(data)
    page_w, lines = parse_tsv(reader._tesseract(reader._prepare(data)))
    before = "\n".join(clean_lines("\n".join(x.text for x in lines))[0])   # every bubble wrap a line, blank lines gone: what read_image returned before
    note("O14", "before: " + repr(before))
    note("O14", "after:  " + repr(res["text"]))
    got = res["text"]
    for wrong, right in JIO_MISREADS:
        got = got.replace(wrong, right)
    if got != JIO_JOINED:
        bad.append(f"the OCR text is not the joined message (after mapping the two known misreads back):\n      got    {got!r}\n      wanted {JIO_JOINED!r}")
    if "Kiwi UPI Credit Card (CC:\n" in res["text"] or "Lifetime Free\n" in res["text"]:
        bad.append("a bubble wrap is still a line break")
    if res["text"] != "\n".join(res["lines"]) or res["lines"].count("") != 2 or res["dropped"] != 0:
        bad.append(f"lines / dropped inconsistent: {res['lines']} dropped {res['dropped']}")
    return bad

H, PAGE = 30, 1000   # a hand-built page: line boxes 30 px high on a 40 px pitch (a normal gap is 10 px = a third of a line), 1000 px wide

def box(text, row=0, left=100, right=700, first=80):
    top = 100 + row * 40
    return Line(text, left, top, right, top + H, first)

def lay(*lines, page=PAGE):
    return join_wrapped_lines(page, list(lines))

GEOMETRY = [   # (label, lines, expected lines, expected dropped)
    ("a wrap is joined", [box("your account will be blocked due to"), box("pending KYC", 1, right=400, first=90)], ["your account will be blocked due to pending KYC"], 0),
    ("a three-line paragraph is one line", [box("your account will be", 0), box("blocked due to pending", 1, right=690, first=70), box("KYC", 2, right=300, first=60)],
     ["your account will be blocked due to pending KYC"], 0),
    ("ends in a full stop", [box("pay now."), box("next line", 1, right=400)], ["pay now.", "next line"], 0),
    ("ends in !", [box("pay now!"), box("next line", 1, right=400)], ["pay now!", "next line"], 0),
    ("ends in ?", [box("pay now?"), box("next line", 1, right=400)], ["pay now?", "next line"], 0),
    ("ends in a colon", [box("pay now:"), box("next line", 1, right=400)], ["pay now:", "next line"], 0),
    ("ends in a full stop and a closing quote", [box('he said "pay now."'), box("next line", 1, right=400)], ['he said "pay now."', "next line"], 0),
    ("ends in a full stop and a closing bracket", [box("(pay now.)"), box("next line", 1, right=400)], ["(pay now.)", "next line"], 0),
    ("ends in a Devanagari danda", [box("भुगतान करें।"), box("अगली पंक्ति", 1, right=400)], ["भुगतान करें।", "अगली पंक्ति"], 0),
    ("a colon inside an open bracket is not an end", [box("Kiwi UPI Credit Card (CC:"), box("JIOKIWI) on JioRecharge.", 1, right=500, first=90)], ["Kiwi UPI Credit Card (CC: JIOKIWI) on JioRecharge."], 0),
    ("a comma is not an end", [box("Dear Sir, your account is blocked,"), box("please update", 1, right=400, first=90)], ["Dear Sir, your account is blocked, please update"], 0),
    ("a blank line stays and nothing is joined across it", [box("your account will be blocked due to"), box("pending KYC", 2, right=400, first=90)], ["your account will be blocked due to", "", "pending KYC"], 0),
    ("a link line is never joined onto", [box("Update now:"), box("https://sbi.top/x", 1, right=500, first=300)], ["Update now:", "https://sbi.top/x"], 0),
    ("a long line before a link is not joined", [box("please verify your account at the link below"), box("https://sbi.top/x", 1, right=500, first=300)],
     ["please verify your account at the link below", "https://sbi.top/x"], 0),
    ("a line that starts with a bare domain is a link line", [box("pay at the link below to avoid it"), box("sbi-kyc.top/login now", 1, right=500, first=200)],
     ["pay at the link below to avoid it", "sbi-kyc.top/login now"], 0),
    ("a link line is not joined into", [box("https://sbi.top/x"), box("more text here", 1, right=400, first=60)], ["https://sbi.top/x", "more text here"], 0),
    ("a line holding a link is not joined", [box("see sbi.top/login now and then"), box("pay it", 1, right=400, first=60)], ["see sbi.top/login now and then", "pay it"], 0),
    ("a list item is a new line (-)", [box("your account will be blocked due to"), box("- pending KYC", 1, right=400, first=20)], ["your account will be blocked due to", "- pending KYC"], 0),
    ("a list item is a new line (1.)", [box("your account will be blocked due to"), box("1. pending KYC", 1, right=400, first=30)], ["your account will be blocked due to", "1. pending KYC"], 0),
    ("a list item is a new line (2))", [box("your account will be blocked due to"), box("2) pending KYC", 1, right=400, first=30)], ["your account will be blocked due to", "2) pending KYC"], 0),
    ("a list item is a new line (bullet)", [box("your account will be blocked due to"), box("\u2022 pending KYC", 1, right=400, first=20)], ["your account will be blocked due to", "\u2022 pending KYC"], 0),
    ("a *word is not a list item", [box("your account will be blocked due to"), box("*pending KYC", 1, right=400, first=90)], ["your account will be blocked due to *pending KYC"], 0),
    ("the next line starts further right than a line height", [box("your account will be blocked due to"), box("pending KYC", 1, left=140, right=440, first=90)],
     ["your account will be blocked due to", "pending KYC"], 0),
    ("the next line starts within a line height", [box("your account will be blocked due to"), box("pending KYC", 1, left=120, right=420, first=90)],
     ["your account will be blocked due to pending KYC"], 0),
    ("a short column is not a wrapped paragraph", [box("Dear User,", right=350), box("Thanks", 1, right=250, first=140)], ["Dear User,", "Thanks"], 0),
    ("the longest line spans 40% of the page: still not a column", [box("Do not share it with anyone", right=500), box("Valid for ten minutes", 1, right=450, first=60)],
     ["Do not share it with anyone", "Valid for ten minutes"], 0),
    ("under 0.7 of the widest line is not a wrap", [box("the longest line in this bubble."), box("a typed middle line", 1, right=500), box("end", 2, right=300, first=250)],
     ["the longest line in this bubble.", "a typed middle line", "end"], 0),
    ("0.72 of the widest is a wrap", [box("the longest line in this bubble."), box("a typed middle line", 1, right=532), box("end", 2, right=300, first=250)],
     ["the longest line in this bubble.", "a typed middle line end"], 0),
    ("the next word would have fitted: a typed break", [box("the longest line in this bubble."), box("a typed middle line", 1, right=600), box("end", 2, right=300, first=80)],
     ["the longest line in this bubble.", "a typed middle line", "end"], 0),
    ("the next word would not have fitted: a wrap", [box("the longest line in this bubble."), box("a typed middle line", 1, right=600), box("end", 2, right=300, first=120)],
     ["the longest line in this bubble.", "a typed middle line end"], 0),
    ("a noise line is a barrier and is counted", [box("your account will be blocked due to"), box("10:42 pm", 1, right=220, first=60), box("pending KYC", 2, right=400, first=90)],
     ["your account will be blocked due to", "pending KYC"], 1),
    ("a gap across a dropped noise line is a blank line", [box("your account will be blocked due to"), box("10:42 pm", 1, right=220, first=60), box("pending KYC", 3, right=400, first=90)],
     ["your account will be blocked due to", "", "pending KYC"], 1),
    ("no blank line before the first text", [box("Today", 0, left=300, right=380), box("hello there", 3, right=400, first=80)], ["hello there"], 1),
    ("no blank line after the last text", [box("hello there", 0, right=400, first=80), box("10:42 pm", 3, right=220)], ["hello there"], 1),
    ("only noise", [box("Today", 0, left=300, right=380), box("10:42 pm", 1, right=220)], [], 2),
    ("nothing at all", [], [], 0),
    ("another bubble's column does not move this one's edge", [box("your account will be blocked due to"), box("pending KYC", 1, right=400, first=90), box("a reply from the other side", 3, left=500, right=990, first=90)],
     ["your account will be blocked due to pending KYC", "", "a reply from the other side"], 0),
    ("a different column is not joined to", [box("your account will be blocked due to"), box("a reply", 1, left=500, right=700, first=90)], ["your account will be blocked due to", "a reply"], 0),
]

def o15(c):
    bad = []
    for label, lines, want, want_dropped in GEOMETRY:
        got, dropped = lay(*lines)
        if got != want or dropped != want_dropped:
            bad.append(f"{label}: got {got!r} (dropped {dropped}), wanted {want!r} (dropped {want_dropped})")
    note("O15", f"{len(GEOMETRY)} cases on hand-built line boxes")
    return bad

def shot(text, **kw):
    return bubble(text, breaks=True, inner=700, **kw)   # wrap at 65% of the page, like the chat apps (the default 87% is wider than any of them)

LONG_PARA = "Your account will be blocked today due to pending KYC verification please click the link below to update your details now"
SHOTS = [   # (label, text typed, lines expected back)
    ("two paragraphs keep their blank line", "Dear Customer your SBI account will be blocked today due to pending KYC verification and must be updated now to avoid closure of the account\n\n"
     "Share the OTP sent to your number to complete the verification within one hour or the account will be suspended permanently",
     ["Dear Customer your SBI account will be blocked today due to pending KYC verification and must be updated now to avoid closure of the account", "",
      "Share the OTP sent to your number to complete the verification within one hour or the account will be suspended permanently"]),
    ("short lines are not joined", "Dear User,\nThanks\nTeam X", ["Dear User,", "Thanks", "Team X"]),
    ("short lines of an OTP message are not joined", "Your OTP is 482913\nDo not share it with anyone\nValid for 10 minutes", ["Your OTP is 482913", "Do not share it with anyone", "Valid for 10 minutes"]),
    ("a line ending in a colon before a link is not joined", LONG_PARA + ":\nhttps://sbi-kyc.top/login", [LONG_PARA + ":", "https://sbi-kyc.top/login"]),
    ("a long line without punctuation before a link is not joined", LONG_PARA + "\nhttps://sbi-kyc.top/login", [LONG_PARA, "https://sbi-kyc.top/login"]),
    ("a wrapped paragraph and a typed sign-off", LONG_PARA + "\nRegards\nSBI Team", [LONG_PARA, "Regards", "SBI Team"]),
    ("typed sentences, one per line, with a wrap inside one", "Your parcel is held at our warehouse due to an incomplete address and will be returned to the sender soon.\nUpdate your address now.\nThanks India Post",
     ["Your parcel is held at our warehouse due to an incomplete address and will be returned to the sender soon.", "Update your address now.", "Thanks India Post"]),
]

def o16(c):
    bad = []
    for label, text, want in SHOTS:
        res = read_image(shot(text))
        if res["lines"] != want or res["text"] != "\n".join(want):
            bad.append(f"{label}: got {res['lines']!r}, wanted {want!r}")
    # A limit, recorded and not asserted: a typed line that stops within a word of the longest line looks like a wrapped paragraph, and without end punctuation
    # it is merged with the next line. Here "Your SBI account ... KYC verification" wraps inside the bubble and its last piece is nearly full, so the typed line below it joins it.
    typed = ["Dear Customer,", "Your SBI account will be blocked today due to pending KYC verification", "Update now to avoid closure", "Regards", "SBI Team"]
    limit = read_image(shot("\n".join(typed)))["lines"]
    note("O16", f"KNOWN LIMIT (not asserted): {len(typed)} typed lines come back as {len(limit)}: {limit!r}")
    # The 14 demo messages as screenshots keep the verdict of the text (the levels test_demo.py locks): joining lines must not move a verdict.
    moved = []
    for item in json.load(open(os.path.join(ROOT, "docs", "demo", "demo_set.json"), encoding="utf-8")):
        got = read_image(image(("light", item["id"]), text=item["text"]))["text"]
        level = level_of(c, got)
        if level != DEMO_LEVELS[item["id"]] or level != level_of(c, item["text"]):
            moved.append(f"{item['id']}: {level} (text: {level_of(c, item['text'])}, locked: {DEMO_LEVELS[item['id']]})")
    note("O16", "14 demo messages as light screenshots: " + ("all keep their locked verdict" if not moved else f"MOVED: {moved}"))
    bad += [f"demo screenshot verdict moved: {m}" for m in moved]
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
          ("O9", "coloured underlined links survive dark mode; the step changes nothing on grey or saturated-bubble images", o9),
          ("O10", "narrow link repairs: spaced colon, space after a dot; the old pattern and everything that must stay unchanged", o10),
          ("O13", "the REAL dark-mode Jio screenshot (tests/fixtures/real): link t.jio/..., three anchor lines, verdict Likely scam, Link panel lists it", o13),
          ("O14", "the REAL screenshot: bubble wraps joined, typed breaks and blank lines kept, exactly the message", o14),
          ("O15", "join_wrapped_lines on hand-built boxes: every rule alone (ends, brackets, blanks, links, lists, margins, columns, ratio, next word, noise)", o15),
          ("O16", "synthetic renders: blank line kept, short lists / colon+link / long line+link not joined, 14 demo screenshots keep their verdict", o16)]

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
