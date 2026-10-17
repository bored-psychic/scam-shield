"""Read the text out of a screenshot of a chat message, locally.

    read_image(png_or_jpeg_or_webp_bytes) -> {"text", "lines", "langs", "ms", "dropped"}

Local-first (docs/ARCHITECTURE.md §1, §5.4; decision D19): the image and the text in it are never written to disk, logged or sent anywhere.
  * The image is decoded and re-encoded in memory with Pillow, and that PNG goes to `tesseract stdin stdout` over a pipe. Nothing is
    saved, and pytesseract is not used (it writes temp files). Only a PNG that Pillow made is ever piped in: given bytes that are not an
    image, Tesseract treats its stdin as a file NAME and tries to open it.
  * No network: Tesseract is a local program, the language data is on disk (`brew install tesseract tesseract-lang`).
  * Tesseract's stderr is never kept or put in an exception message; exception messages here are fixed strings with no user text.
Tesseract is asked for TSV (word boxes) rather than plain text, so the lines a chat bubble wrapped can be joined back (join_wrapped_lines); the image never leaves the pipe either way.
The caller (the page) shows the extracted text to the user to check and edit before it goes through /api/analyse.
"""
import io
import os
import re
import shutil
import subprocess
import time
from typing import NamedTuple

import numpy as np
from PIL import Image, ImageOps
from scipy import ndimage

from textprep import extract_urls

LANGS = "eng+hin+kan"
PAPER_MIN = 170          # _coloured_ink acts only on paper at least this light in every channel after the invert, i.e. a bubble whose brightest channel is < 85 (grey 204 / 188 / 218 in the apps measured or assumed; teal and blue outgoing bubbles 163 / 135 stay out)
INK_PEAK_MIN = 40        # _coloured_ink touches pixels only near a stroke whose extra ink peaks at least this high (tinted backgrounds and JPEG noise make <= 23) ...
INK_FLOOR = 110          # ... and lifts a weaker one to this contrast, never a stronger one (measured on a real screenshot and on a colour sweep, see the docstring)
INK_GAIN_MAX = 3.0       # at most this factor
MAX_BYTES = 8 * 1024 * 1024
MAX_SIDE = 6000          # px, either side
UPSCALE_BELOW = 1200     # px: an image narrower than this is enlarged by UPSCALE
UPSCALE = 1              # 1 = never enlarge. Measured against x2 (BUGS.md): x1 keeps the rupee sign more often (37 vs 22 of 96) with CER and verdicts equal or better, also at 540-900 px wide
TIMEOUT_S = 20
FORMATS = ("PNG", "JPEG", "WEBP")   # a JPEG with a second picture (MPO, some phone photos) opens as a plain JPEG; listing "MPO" breaks WEBP: Pillow looks it up before its plugin is loaded
_TESSERACT_FALLBACKS = ("/opt/homebrew/bin/tesseract", "/usr/local/bin/tesseract")   # a service started outside a login shell may lack Homebrew on PATH


class ImageRejected(ValueError):
    """The image cannot be read; the message is plain text for the user and never contains anything from the image."""

class ImageTooLarge(ImageRejected):
    """More than MAX_BYTES (the API answers 413)."""

class UnsupportedImage(ImageRejected):
    """Not a PNG, JPEG or WEBP by its first bytes (the API answers 415)."""

class OcrUnavailable(RuntimeError):
    """Tesseract or its eng / hin / kan data is not installed (the API answers 503)."""


def _kind(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def _median(img):
    hist, half, acc = img.histogram(), img.width * img.height / 2, 0
    for level, n in enumerate(hist):
        acc += n
        if acc >= half:
            return level
    return 255


def _stroke_box(width):
    """Side (odd, px) of the square that tells a thin stroke from a large region: 15 px on a 1080 px wide screenshot, where chat text strokes and
    link underlines are 2-6 px, 9 px at the narrowest, 31 at the widest."""
    return min(31, max(9, (round(width / 72) // 2) * 2 + 1))


def _coloured_ink(rgb, grey, box):
    """Dark mode only: `rgb` is the INVERTED image (dark ink on light paper) and `grey` its luma. Returns `grey` with coloured strokes darkened.

    Why: the invert step turns a mid-brightness link colour into a light grey. iOS Messages' dark-mode blue (10, 132, 255) on its grey bubble has luma 109
    against 38, so after the invert the link is 145 on 217 and Tesseract drops it (the same for a plain (0, 0, 238) blue, and for the (40, 105, 220) link
    of a real Google Messages screenshot against its (32, 33, 37) bubble). In the inverted image the darkest channel is 255 minus the BRIGHTEST channel
    of the original, so a coloured stroke stands out from the paper there while luma flattens it. It cannot simply replace luma: a saturated bubble has a
    near-zero channel too, which hides white text on it. So it is only used for what luma misses, and only where it can be trusted:
      * a black top-hat (closing minus image: a closing of `box` px fills any stroke thinner than that and keeps large regions) of the darkest channel gives
        the ink that channel sees, the same of luma gives the ink luma sees; `grey` is darkened by the difference, never lightened;
      * only where the paper around the stroke is light in every channel (its median darkest channel >= PAPER_MIN, i.e. a bubble that is dark in every
        channel): on a saturated paper the darkest channel is ~0 for the ink and the paper alike, and JPEG chroma bleed from the text then shows up as
        phantom ink (measured: 20k pixels on a blue bubble). 128 let a Telegram-blue outgoing bubble (paper 135) through and 4 JPEG renders of it read
        worse, so it is 170. The level is a median over ~44 px, not the closing used for the ink: a closing is a max-then-min and rides up to the noise
        peak, which let JPEG noise lift a teal bubble (paper 162) over 170 on half its area and changed the link characters;
      * only within 1.5 boxes of a stroke whose extra ink is real (a local peak >= INK_PEAK_MIN, above the ~23 that a tinted background and JPEG noise
        produce); everywhere else the image is byte-identical to the luma one. Without this, noise-level changes all over the page flipped a line 100 px away
        from the link (`JioCoupons` read as digits by the Hindi / Kannada models, Tesseract 5.3.4);
      * such a stroke that is weak (peak < INK_FLOOR) is lifted to INK_FLOOR, at most INK_GAIN_MAX times. Tesseract's threshold is set by the white text, so a dim colour (a link with value 0.45, 115 against
        a 37 bubble) has too little contrast and drops out. Stronger strokes are left alone on purpose: a fixed gain bloats them (x2 on the real screenshot:
        link recovered in 34 of 64 re-encodings instead of 50, x3 in 14).
    Not used: chroma (max - min of the colour), which also handles dim colours but is stored at half resolution in a JPEG, so it smears thin strokes
    (real screenshot 20 of 64, and 83-90% on JPEG renders at every brightness).
    For grey text on a grey background the darkest channel IS luma, the difference is exactly 0 and the image is bit-identical to before."""
    m = np.asarray(rgb).min(axis=2)
    g = np.asarray(grey)
    size = (box, box)
    paper_m = ndimage.grey_closing(m, size=size)
    ink_m = paper_m.astype(np.int16) - m
    ink_g = ndimage.grey_closing(g, size=size).astype(np.int16) - g
    extra = np.clip(ink_m - ink_g, 0, 255).astype(np.uint8)
    typical = ndimage.median_filter(m[::4, ::4], size=11)   # the paper level, robust to noise and strokes (a closing rides up to the noise peak)
    extra[np.repeat(np.repeat(typical, 4, axis=0), 4, axis=1)[:m.shape[0], :m.shape[1]] < PAPER_MIN] = 0
    peak = ndimage.maximum_filter(extra, size=(3 * box, 3 * box))
    lift = np.clip(INK_FLOOR / np.maximum(peak, 1), 1.0, INK_GAIN_MAX).astype(np.float32)
    extra = np.where(peak >= INK_PEAK_MIN, np.clip(extra * lift, 0, 255), 0).astype(np.int16)   # no real coloured stroke within 1.5 boxes: not a pixel is touched
    return Image.fromarray(np.clip(g.astype(np.int16) - extra, 0, 255).astype(np.uint8))


def _prepare(data, invert=None):
    """Bytes -> grayscale PNG bytes for Tesseract: EXIF-oriented, flattened onto white, dark-mode inverted (with coloured strokes recovered, see
    _coloured_ink), narrow images enlarged by UPSCALE. `invert` None = automatic (median brightness below 128); True / False forces it (tests only)."""
    try:
        img = Image.open(io.BytesIO(data), formats=FORMATS)
        w, h = img.size   # from the header, before any pixel is decoded
        if max(w, h) > MAX_SIDE:
            raise ImageRejected(f"The screenshot is too large ({w} x {h} px); the longest side can be at most {MAX_SIDE} px.")
        img = ImageOps.exif_transpose(img)
        if img.mode in ("RGBA", "LA", "PA") or "transparency" in img.info:
            rgba = img.convert("RGBA")
            flat = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
            flat.alpha_composite(rgba)
            img = flat
        colour, grey = img, img.convert("L")
    except ImageRejected:
        raise
    except Exception:   # a truncated or corrupt file: Pillow raises OSError, SyntaxError, ValueError, DecompressionBombError ...
        raise ImageRejected("The image could not be read.") from None
    if (_median(grey) < 128) if invert is None else invert:
        grey = _coloured_ink(ImageOps.invert(colour.convert("RGB")), ImageOps.invert(grey), _stroke_box(grey.width))
    img = grey
    if UPSCALE > 1 and img.width < UPSCALE_BELOW:
        img = img.resize((img.width * UPSCALE, img.height * UPSCALE), Image.Resampling.LANCZOS)
    out = io.BytesIO()
    img.save(out, "PNG", compress_level=1)
    return out.getvalue()


def _find_tesseract():
    return shutil.which("tesseract") or next((p for p in _TESSERACT_FALLBACKS if os.access(p, os.X_OK)), None)


def _tesseract(png):
    """Tesseract's TSV for the image: one row per page / block / paragraph / line / word with its box. Same single call, pipes only, as the plain-text
    output it replaced; the TSV carries the line geometry that join_wrapped_lines needs."""
    exe = _find_tesseract()
    if exe is None:
        raise OcrUnavailable("Screenshot reading is not available: Tesseract is not installed.")
    try:
        p = subprocess.run([exe, "stdin", "stdout", "-l", LANGS, "--psm", "6", "tsv"], input=png, capture_output=True, timeout=TIMEOUT_S)
    except subprocess.TimeoutExpired:
        raise ImageRejected("Reading the screenshot took too long. Try a smaller or cropped image.") from None
    if p.returncode != 0:
        if b"Failed loading language" in p.stderr or b"couldn't load any languages" in p.stderr:
            raise OcrUnavailable("Screenshot reading is not available: the English, Hindi and Kannada language data is missing.")
        raise RuntimeError(f"tesseract exited with status {p.returncode}")   # the status only: stderr can echo what it was given
    return p.stdout.decode("utf-8", "replace")


# --- link repair --------------------------------------------------------------------------------------------------------------------
# Tesseract reads the "//" before "www" as "/A", "/(" and the like, and then the link is no longer a link for the rest of the pipeline
# (measured on the demo set: bet365 went from Likely scam to Suspicious because the gambling lookup never saw the host). "http:/" with one
# slash is never valid, so this one pattern is repaired: a scheme, one or two slashes, up to two stray characters, then "www.". Nothing else
# is rewritten: a misread inside a host name or a number cannot be told from the real thing, and a wrong-but-plausible repair would hide it.
_BROKEN_SCHEME = re.compile(r"\b(https?):/{1,2}[^\s/w]{0,2}(?=www\.)", re.I)

# Second shape (D19b): Tesseract puts a space beside the colon, "https :/Awww.bet365.com/" or "http : /Aexample.in/x". Still only a scheme: a space next to
# the colon is never valid, a host-like token must follow at once ("www." or a lower-case name with a dot and an alphabetic ending), and the one stray
# character must be one that Tesseract produces for a "/" (A ( [ | ! \), so a capitalised host such as "https :/Example.in" does not lose its "E".
_HOST = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,24}"
_SPACED_SCHEME = re.compile(rf"\b(?i:(https?))(?:[ \t]+:[ \t]?|[ \t]?:[ \t]+)/{{1,2}}[ \t]?[A(\[|!\\]?(?=www\.|{_HOST}(?:[/:?#]|\b))")

# Third shape (D19b): a space right after a dot inside a host, "https://t. jio/TIOCPN/x" (the dot is followed by a gap). Only inside a token that already
# starts with scheme://, only when what follows the space is 2-24 lower-case letters (dotted names allowed) and then "/" or the end of the token. Without a "/"
# it is joined only if the part before the space is a single label ("https://t.", "https://www."): "Visit https://ok.com. then pay" must not become ok.com.then.
_SPLIT_HOST = re.compile(r"(?<!\S)((?i:https?)://[^\s/?#]*\.)[ \t]([a-z]{2,24}(?:\.[a-z]{2,24})*)(?=/|\s|$)")


def _join_split_host(m):
    before = m.group(1).split("://", 1)[1]
    if m.string[m.end():m.end() + 1] == "/" or before.count(".") == 1:
        return m.group(1) + m.group(2)
    return m.group(0)


def repair_links(text):
    text = _SPACED_SCHEME.sub(r"\1://", text)
    text = _BROKEN_SCHEME.sub(r"\1://", text)
    return _SPLIT_HOST.sub(_join_split_host, text)


# --- chat-noise cleanup -------------------------------------------------------------------------------------------------------------
# Conservative: a line goes only if the WHOLE line is one of these, and never if it holds a link, an amount or OTP / PIN / UPI.
_GLYPHS = "✓✔✅☑√✗✕✖"   # tick marks and the like (WhatsApp's read ticks come out of OCR as these, or as letters, which are left alone)
_KEEP = re.compile(r"(?:₹|\brs\.?|\binr)\s*\d|\d\s*(?:₹|\brs\b)|\b(?:otp|pin|upi)\b", re.I)
_TIME = re.compile(r"^\d{1,2}\s*[:.]\s*\d{2}(?:\s*[:.]\s*\d{2})?\s*(?:[ap]\.?\s?m\.?)?$", re.I)
_FORWARDED = re.compile(r"^\W*forwarded(?: many times)?\W*$", re.I)
_DAY = re.compile(r"^(?:Today|Yesterday|TODAY|YESTERDAY)$")   # case-sensitive: a wrapped "today" in a sentence stays
_MONTH = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
_DATE = re.compile(rf"^(?:\d{{1,2}}\s+{_MONTH}\.?,?\s+\d{{4}}|{_MONTH}\.?\s+\d{{1,2}},?\s+\d{{4}})$", re.I)   # the year is required: "12 October" may be content
# Not dropped on purpose: a bare weekday ("Monday") or a number-only date ("14-10-26"), because a wrapped line of a real message can be just that.


def _is_noise(line):
    if _KEEP.search(line) or extract_urls(line):
        return False
    core = re.sub(f"[{_GLYPHS}\\s]+", " ", line).strip()
    return not core or bool(_TIME.match(core) or _DAY.match(core) or _DATE.match(core) or _FORWARDED.match(core))


def clean_lines(raw):
    """Raw OCR text -> (kept lines, number of noise lines dropped). Empty lines go silently and are not counted."""
    kept, dropped = [], 0
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if _is_noise(line):
            dropped += 1
        else:
            kept.append(line)
    return kept, dropped


# --- soft-wrapped lines --------------------------------------------------------------------------------------------------------------
# A chat bubble breaks its text where the bubble is full, and Tesseract reports every piece as a line ("You've earned Lifetime Free" / "Kiwi UPI Credit
# Card (CC:" / "JIOKIWI) on JioRecharge."). Those breaks belong to the screenshot, not to the message, so they are joined back with one space; the
# breaks the author typed stay. Text alone cannot tell them apart, so this uses the line boxes from Tesseract's TSV.
#
# The physics of a bubble does the work. Text is wrapped greedily: a word moves to the next line only when it would not fit on this one. So if a line
# ends more than (the next line's first word + a space) short of the bubble's edge, the next word WOULD have fitted and the break was typed. The edge
# is not visible, but no line goes past it, so the right end of the widest line in the same column is a lower bound for it. A line that stops further
# from that bound than the next word is wide is therefore certainly a typed break (the real edge is even further away); the test cannot veto a true wrap.
# The converse does not hold, see the last paragraph below.
#
# A break is joined only when all of these hold (anything else stays as a line break):
#   * neither line is chat noise, holds a link, or is separated from the other by a blank line (a vertical gap above BLANK_GAP line heights); a link is
#     never joined to or into (re-joining a wrapped link is a separate, deferred problem: BUGS.md D19 (3));
#   * the line does not end a sentence (. ! ? : or a Devanagari danda, after any closing quote or bracket), unless it has an open bracket: "(CC:" is
#     still inside its parenthesis; and the next line is not a list item;
#   * the next line starts at the same left margin (within LEFT_TOL line heights);
#   * the line reaches at least SOFT_WRAP_RATIO of the widest line in its column. With greedy wrapping the slack is at most the next word, which in a
#     bubble of 25-40 characters is up to about 1/3 of the width, so 0.7 keeps a line that precedes a long word; the next-word test below is the
#     sharper one, this is the cheap filter (on synthetic renders anything from 0.5 to 0.7 gave the same result);
#   * that widest line spans at least MIN_COLUMN of the image width. Chat bubbles wrap only once the text reaches the app's maximum bubble width, and the
#     text in it is then about 55-70% of a phone screenshot (the real Jio screenshot: 65% with its link line, 58% without), so a short list
#     ("Dear User," / "Thanks" / "Team X") or an OTP message whose longest line is the whole bubble is not a wrapped paragraph, however long that line is
#     compared with the others. At 0.5, no soft wrap was missed in 234 synthetic wraps at a 65% bubble; 0.6 missed 22. Screenshots whose text column is
#     narrower than half the image (a wide desktop window) are simply not joined, which is today's behaviour;
#   * the next line's first word would not have fitted on this line (the test above).
# What is left, and cannot be told from geometry: a typed line that stops within one word of the widest line of its message looks exactly like a
# bubble wrap, and the widest line of a message is always "full" (nothing on the page shows the bubble's real edge). Without end punctuation these
# are merged; with it (one sentence per line, which is how most messages are typed) they are not. Measured numbers: tests/test_ocr.py O14-O15 and BUGS.md.
SOFT_WRAP_RATIO = 0.7
MIN_COLUMN = 0.5
BLANK_GAP = 1.25    # a vertical gap between two lines of more than this many line heights is a blank line. Normal gaps are 0.5 or less, an empty line makes it 1.7 (real
                    # screenshot) to 2.0 (renders); on synthetic renders 1.0-1.8 all gave the same result, 0.85 and below invent blank lines, 2.0 and up miss them
LEFT_TOL = 1.0      # line heights
SPACE_OF_H = 0.3    # a space is ~0.45 of a line box high in the fonts measured; 0.3 under-estimates it, so the next-word test never vetoes a real wrap
_CLOSERS = "\"'”’)]}»›"
_ENDERS = ".!?:।॥…"   # . ! ? : the Devanagari danda and double danda, and the ellipsis
_LIST_START = re.compile(r"^(?:[-–—•*·▪●◦]|\(?\d{1,2}[.)])\s")


class Line(NamedTuple):
    """One line of text as Tesseract placed it: the words joined by a space (links already repaired) and the box around them, in pixels."""
    text: str
    left: int
    top: int
    right: int
    bottom: int
    first_w: int   # width of the line's first word


def parse_tsv(tsv):
    """Tesseract's TSV -> (page width, [Line] in reading order). Rows that are not words, or are empty, are ignored."""
    page_w, words = 0, {}
    for row in tsv.splitlines()[1:]:
        c = row.split("\t", 11)
        if len(c) < 12:
            continue
        try:
            level, left, top, w, h = int(c[0]), int(c[6]), int(c[7]), int(c[8]), int(c[9])
        except ValueError:
            continue
        if level == 1:
            page_w = w
        elif level == 5 and c[11].strip():
            words.setdefault((c[2], c[3], c[4]), []).append((left, top, w, h, c[11].strip()))   # (block, paragraph, line); dicts keep reading order
    lines = []
    for ws in words.values():
        lines.append(Line(repair_links(" ".join(x[4] for x in ws)), min(x[0] for x in ws), min(x[1] for x in ws), max(x[0] + x[2] for x in ws),
                          max(x[1] + x[3] for x in ws), ws[0][2]))
    return page_w, lines


def _ends_sentence(text):
    if text.count("(") > text.count(")") or text.count("[") > text.count("]"):
        return False   # still inside a bracket, as in "Kiwi UPI Credit Card (CC:"
    core = text.rstrip(_CLOSERS + " ")
    return bool(core) and core[-1] in _ENDERS


def _is_soft_wrap(a, b, kept, h, page_w):
    """Is the break between line `a` and the line `b` below it only the bubble's edge? `kept` is every line of the screenshot that is not noise."""
    if extract_urls(a.text) or extract_urls(b.text) or _ends_sentence(a.text) or _LIST_START.match(b.text):
        return False
    if abs(b.left - a.left) > LEFT_TOL * h:
        return False
    edge = max(x.right for x in kept if abs(x.left - a.left) <= LEFT_TOL * h)   # a's column: the lines at the same left margin, a itself among them
    widest = edge - a.left
    if widest < MIN_COLUMN * page_w or a.right - a.left < SOFT_WRAP_RATIO * widest:
        return False
    return edge - a.right < b.first_w + SPACE_OF_H * h   # the next word would not have fitted


def join_wrapped_lines(page_w, lines):
    """The image width and [Line] in reading order (what parse_tsv returns) -> (the message's lines, number of noise lines dropped).
    Noise lines (clean_lines' rules) are dropped and counted. A vertical gap of more than BLANK_GAP line heights is kept as a blank line, an empty ""
    entry (the plain-text reader dropped every blank line), also across a dropped noise line (a timestamp between two bubbles). A soft-wrapped line is
    joined to the next with one space (see the block comment above). The result joined with "\\n" is the text."""
    noise = [_is_noise(x.text) for x in lines]
    kept = [x for x, n in zip(lines, noise) if not n]
    if not kept:
        return [], len(lines)
    heights = sorted(x.bottom - x.top for x in kept)
    h = max(1, heights[len(heights) // 2])   # the usual height of a line box
    out, dropped, blank, prev, prev_noise = [], 0, False, None, False
    for x, n in zip(lines, noise):
        if prev is not None and x.top - prev.bottom > BLANK_GAP * h:
            blank = True
        if n:
            dropped += 1
        else:
            if not out:
                out.append(x.text)
            elif blank:
                out += ["", x.text]
            elif not prev_noise and _is_soft_wrap(prev, x, kept, h, page_w):
                out[-1] += " " + x.text
            else:
                out.append(x.text)
            blank = False
        prev, prev_noise = x, n
    return out, dropped


def read_image(data):
    """PNG / JPEG / WEBP bytes -> {"text", "lines", "langs", "ms", "dropped"}. Raises ImageRejected (a ValueError with a plain message;
    ImageTooLarge and UnsupportedImage are subclasses) or OcrUnavailable. An image with no readable text gives text == "".
    `lines` are the message's lines after soft wraps are joined, with "" for a blank line; "\\n".join(lines) == text."""
    t0 = time.perf_counter()
    if len(data) > MAX_BYTES:
        raise ImageTooLarge(f"The screenshot is too large (max {MAX_BYTES // (1024 * 1024)} MB).")
    if _kind(data) is None:
        raise UnsupportedImage("Only PNG, JPEG or WEBP screenshots can be read.")
    lines, dropped = join_wrapped_lines(*parse_tsv(_tesseract(_prepare(data))))
    return {"text": "\n".join(lines), "lines": lines, "langs": LANGS, "ms": round((time.perf_counter() - t0) * 1000, 1), "dropped": dropped}
