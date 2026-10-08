import re
from pii import mask_text
from url_features import parse_url, tld_ext

# The one preprocessing step every text model sees: URLs become the token <URL>, then the text is cut to MAX_CHARS.
# Used by baseline.py and sanity_checks.py (training / evaluation), app.py (inference) and, when it is written, the fine-tuning
# script (CLAUDE.md): import model_text, don't re-implement it. A model trained on one version of this function must be scored with
# the same one.
#
# Why: the text models read character n-grams, so a link is otherwise a pile of n-grams of one domain (`.ly/`, `bit.`, `htt`, `xyz`)
# that identify a campaign, a source or a shortener rather than the message. With <URL> the model still learns "a link is here"
# but not which one; the URL head (url_head.py) is where the link itself is judged. Defanged links (hxxp, [.]) map to the same token,
# so that obfuscation can't hide a link from the text head either.
#
# Applied at model-input time only. data/final/messages.csv, text_hash, the near-duplicate clusters and split_map.csv are
# built from the raw text and are not touched. Mask order matches ingestion: PII masks first (already in messages.csv; app.py
# applies pii.mask_text itself), then URLs.
#
# Link placeholders ([Link], [URL], {link}, <url>) map to the same token: `[Link]` is a template slot that appears in 201
# india_fraud_final scam rows and in no benign row, so as a literal it would be a label shortcut. As <URL> it still marks "a link goes
# here", but now shares its n-grams with the real links in that source's other rows (check the label rate per source: reports/url_token.md).
# A word that happens to end in a real public suffix with no space before it ('photo.mov', 'contact.us') is replaced like a bare domain.
URL_TOKEN = "<URL>"
MAX_CHARS = 2000        # what the text models read; baseline.py has always cut here
SCAN_CHARS = 50_000     # only the first 50k raw characters are scanned (one text is 17 MB); the cut to MAX_CHARS follows

_DOT = r"(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))"
_SCHEME = r"(?:https?|hxxps?)(?:://|\[://\]|\[:\]//)"
_REST = r"[^\s<>\"'`]+"
_OCT = r"\d{1,3}"
URL_RE = re.compile("|".join([
    _SCHEME + _REST,                                                                                       # http://x, hxxp[://]x
    rf"(?<![@\w./-])www{_DOT}{_REST}",                                                                     # www.x
    rf"(?<![\w.]){_OCT}(?:{_DOT}{_OCT}){{3}}(?::\d+)?(?:/[^\s<>\"'`]*)?",                                  # 1.2.3.4:80/x
    rf"(?<![@\w./-])(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?{_DOT})+[a-z]{{2,24}}(?::\d+)?(?:/[^\s<>\"'`]*)?",   # bare domain.tld/x
]), re.I)
PLACEHOLDER_RE = re.compile(r"\[(?:link|url)\]|\{(?:link|url)\}|<(?:link|url)>", re.I)   # <URL> itself maps to <URL>, so this is idempotent
_PAIRS = {")": "(", "]": "[", "}": "{"}
# Bare-name guard (_is_url). In this corpus 81% of unguarded bare-domain matches were sentence boundaries ('position.You', 'growing.In',
# '.in' and '.you'-style words are real suffixes): a bare name with no path must have an all-lowercase suffix ('News.com', 'sf.net') or be
# all upper case ('NEWS.COM'); 'form.HOW', 'Makefile.PL', 'enterprises.BCG' are rejected. Source-file endings that are also country
# codes are rejected too (hammie.py). Links with a scheme, www. or a path are never subject to this.
FILE_LIKE_TLDS = {"py", "pm", "pl", "sh", "md", "rs"}

def refang(s):
    """Restore a defanged link: hxxp -> http, [.] (.) {.} [dot] (dot) -> '.', [://] -> '://'."""
    s = re.sub(r"\[:\]//|\[://\]", "://", s)
    s = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", s, flags=re.I)
    return re.sub(r"^hxxp", "http", s, flags=re.I)

def _split_tail(m):
    """Trailing sentence punctuation is not part of the link; a closing bracket stays if it balances one inside."""
    core = m
    while core:
        c = core[-1]
        if c in ".,;:!?'\"।>" or (c in _PAIRS and core.count(c) > core.count(_PAIRS[c])):
            core = core[:-1]
        else:
            break
    return core, m[len(core):]

def _is_url(core):
    """Scheme and www. forms need a host; a bare IP needs octets <= 255; a bare domain needs a real public suffix, so 'e.g.' and
    'Rs.500' are not links."""
    link = refang(core)
    host, _ = parse_url(link)
    if not host:
        return False
    if re.match(r"(?:https?|hxxps?)(?:://|\[://\]|\[:\]//)|www(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))", core, re.I):
        return True
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return all(int(p) <= 255 for p in host.split("."))
    suffix = tld_ext(host).suffix
    if not suffix:
        return False
    if "/" not in core:   # a bare name with no path: the usual false positive is a sentence with a missing space ('position.You')
        tld = refang(core).rsplit(".", 1)[-1]
        if not (tld.islower() or refang(core).isupper()) or tld.lower() in FILE_LIKE_TLDS:
            return False
    return True

def _urls(text):
    for m in URL_RE.finditer(text):
        core, tail = _split_tail(m.group(0))
        if core and _is_url(core):
            yield m.start(), m.start() + len(core), core

def replace_urls(text):
    """Every link, defanged or not, and every link placeholder becomes <URL>; everything else is left as it was."""
    text = PLACEHOLDER_RE.sub(URL_TOKEN, text)
    out, pos = [], 0
    for a, b, _ in _urls(text):
        out += [text[pos:a], URL_TOKEN]
        pos = b
    out.append(text[pos:])
    return "".join(out)

def extract_urls(text, limit=None):
    """The links in text, refanged, in order, duplicates dropped (app.py scores these)."""
    found = []
    for _, _, core in _urls(text):
        link = refang(core)
        if link not in found:
            found.append(link)
    return found[:limit]

def model_text(text, mask_pii=False):
    """The string a text model reads. Training and evaluation pass messages.csv text (already PII-masked); app.py passes
    mask_pii=True for what a user pasted, so the same masks run before the URLs are replaced."""
    text = str(text).strip()[:SCAN_CHARS]
    return replace_urls(mask_text(text) if mask_pii else text)[:MAX_CHARS]
