"""The chat-bubble renderer shared by tests/test_ocr.py and src/ocr_sweep.py. Everything is drawn in memory with Pillow and never saved.
Moved out of test_ocr.py unchanged: the images it makes are pixel-identical to before."""
import io, os
from PIL import Image, ImageDraw, ImageFont
from textprep import extract_urls

LATIN_FONTS = ["/System/Library/Fonts/Helvetica.ttc", "/System/Library/Fonts/SFNS.ttf"]   # Arial / Verdana here have no rupee sign (they draw a box)
DEVANAGARI_FONTS = ["/System/Library/Fonts/Supplemental/Devanagari Sangam MN.ttc", "/System/Library/Fonts/KohinoorDevanagari.ttc"]


def font(paths, size):
    for p in paths:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return None

def to_png(img, **kw):
    b = io.BytesIO()
    img.save(b, "PNG", **kw)
    return b.getvalue()

def bubble(text, dark=False, width=1080, size=40, stamp="10:42 pm", fonts=LATIN_FONTS, theme=None, breaks=False, inner=None):
    """A chat screenshot: a 'Today' pill, one incoming bubble with the text wrapped at word boundaries, a timestamp under the text.
    `theme` = (page, bubble, ink, faint, link) colours replaces the two built-in themes; with it every link is drawn in the link colour and underlined.
    `breaks` keeps the line breaks typed in `text` (each line is wrapped on its own, an empty line is a blank line); off, all white space is one space.
    `inner` is the width in px at which a line wraps (default 940, the bubble's own width; real chat apps wrap at about 65-75% of the screen)."""
    f, small = font(fonts, size), font(fonts, 28)
    link = None
    if theme:
        bg, box, ink, faint, link = theme
    else:
        bg, box, ink, faint = ((11, 20, 26), (32, 44, 51), (255, 255, 255), (134, 150, 160)) if dark else ((239, 234, 226), (255, 255, 255), (17, 27, 33), (102, 119, 129))
    left, pad = 40, 30
    inner = inner or 1080 - 2 * 40 - 2 * 30
    lines = []
    for para in (text.split("\n") if breaks else [text]):
        cur = ""
        for word in para.split():
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
        x, y = left + pad, top + pad + i * lh
        if link is None:
            d.text((x, y), line, font=f, fill=ink)
            continue
        for word in line.split():
            colour = link if extract_urls(word) else ink
            d.text((x, y), word, font=f, fill=colour)
            if colour == link:
                d.line((x, y + size, x + f.getlength(word), y + size), fill=colour, width=max(2, size // 18))   # the underline
            x += f.getlength(word + " ")
    d.text((width - left - pad, top + pad + len(lines) * lh + 25), stamp, font=small, fill=faint, anchor="rm")
    return to_png(img)
