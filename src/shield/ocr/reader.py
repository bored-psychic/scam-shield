"""Read the text out of a screenshot of a chat message, locally.

    read_image(png_or_jpeg_or_webp_bytes) -> {"text", "lines", "langs", "ms", "dropped"}

Local-first (docs/ARCHITECTURE.md §1, §5.4; decision D19): the image and the text in it are never written to disk, logged or sent anywhere.
  * The image is decoded and re-encoded in memory with Pillow, and that PNG goes to `tesseract stdin stdout` over a pipe. Nothing is
    saved, and pytesseract is not used (it writes temp files). Only a PNG that Pillow made is ever piped in: given bytes that are not an
    image, Tesseract treats its stdin as a file NAME and tries to open it.
  * No network: Tesseract is a local program, the language data is on disk (`brew install tesseract tesseract-lang`).
  * Tesseract's stderr is never kept or put in an exception message; exception messages here are fixed strings with no user text.
The caller (the page) shows the extracted text to the user to check and edit before it goes through /api/analyse.
"""
import io
import os
import re
import shutil
import subprocess
import time

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
    exe = _find_tesseract()
    if exe is None:
        raise OcrUnavailable("Screenshot reading is not available: Tesseract is not installed.")
    try:
        p = subprocess.run([exe, "stdin", "stdout", "-l", LANGS, "--psm", "6"], input=png, capture_output=True, timeout=TIMEOUT_S)
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


def read_image(data):
    """PNG / JPEG / WEBP bytes -> {"text", "lines", "langs", "ms", "dropped"}. Raises ImageRejected (a ValueError with a plain message;
    ImageTooLarge and UnsupportedImage are subclasses) or OcrUnavailable. An image with no readable text gives text == ""."""
    t0 = time.perf_counter()
    if len(data) > MAX_BYTES:
        raise ImageTooLarge(f"The screenshot is too large (max {MAX_BYTES // (1024 * 1024)} MB).")
    if _kind(data) is None:
        raise UnsupportedImage("Only PNG, JPEG or WEBP screenshots can be read.")
    lines, dropped = clean_lines(repair_links(_tesseract(_prepare(data))))
    return {"text": "\n".join(lines), "lines": lines, "langs": LANGS, "ms": round((time.perf_counter() - t0) * 1000, 1), "dropped": dropped}
