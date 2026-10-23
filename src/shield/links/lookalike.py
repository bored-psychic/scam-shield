import ipaddress, json, re, unicodedata
from functools import lru_cache

from shield.config import ABUSE_TLDS_PATH, BRAND_TLDS_PATH, BRANDS_INDIA_PATH, EXACT_BRANDS_PATH, RESTRICTED_ZONES_PATH
from shield.links.platforms import FREE_HOSTING, SHORTENERS, platform_of, suffix_match
from url_features import parse_url

# Name checks on a link's host (decision D23): pure string work on the tracked reference files beside this module, no list download needed.
#   brand_tld()        signal 1 / P1: the TLD is a verified .brand TLD (brand_tlds.json, checked against ICANN + IANA by update_link_lists.py)
#   restricted_zone()  .bank.in (P1), .gov.in / .nic.in (display only)                                     restricted_zones.json
#   lookalike()        signal 5 / R4: an Indian brand's name in a domain the brand does not own            brands_india.json
#   exact_brand()      R10: the registered domain's label IS a brand's name, on a domain the brand does not own   exact_brands.json
#   homograph()        signal 6 / R3: letters from another alphabet that imitate a brand or a top-10k site
#   raw_ip()           signal 6 / R5: the host is an IP address (dotted, integer, hex or IPv6)
#   abuse_tld()        signal 2: a cited high-abuse TLD (display only)                                     abuse_tlds.json

def _json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

@lru_cache(maxsize=1)
def reference():
    brands = _json(BRANDS_INDIA_PATH)["brands"]
    verified = _json(BRAND_TLDS_PATH)
    tlds = {t["tld"]: dict(t, verified=verified["verified_utc"][:10]) for t in verified["tlds"]}
    zones = {z["zone"]: z for z in _json(RESTRICTED_ZONES_PATH)["zones"]}
    abuse = _json(ABUSE_TLDS_PATH)
    tokens = frozenset(t for b in brands for t in b["tokens"])
    exact = {lab: b for b in _json(EXACT_BRANDS_PATH)["brands"] for lab in b["labels"]}
    return {"brands": brands, "tlds": tlds, "zones": zones, "abuse": abuse, "tokens": tokens, "exact": exact}


def restricted_zone(host):
    """The restricted_zones.json entry whose zone the host is under (sbi.bank.in -> bank.in), or None. The zone itself is not a site."""
    return next((z for zone, z in reference()["zones"].items() if host.endswith("." + zone)), None)

def link_domain(url):
    """(host, registered domain) for the link checks: url_features.parse_url, except that the zones above count as public suffixes
    (the bundled suffix list predates bank.in, so parse_url gives "bank.in" for sbi.bank.in). The URL model keeps parse_url's view."""
    host, reg = parse_url(url)
    host = host.rstrip(".")
    z = restricted_zone(host)
    if z:
        reg = host[: -len(z["zone"]) - 1].rsplit(".", 1)[-1] + "." + z["zone"]
    return host, reg

def brand_tld(host):
    """The verified brand_tlds.json entry for the host's TLD (t.jio -> Jio), or None. Any name under a .brand TLD is registered by the
    brand, its affiliates or licensees only (ICANN Specification 13)."""
    t = reference()["tlds"].get(host.rsplit(".", 1)[-1])
    return t if t and "." in host else None

def abuse_tld(reg):
    """(tld, score) when the registered domain's TLD is on the cited high-abuse list, else None."""
    tld = reg.rsplit(".", 1)[-1]
    score = reference()["abuse"]["tlds"].get(tld)
    return (tld, score) if score is not None else None


def raw_ip(host):
    """The host as an IP address string if it is one: dotted IPv4, IPv6, or the integer / hex forms browsers also accept (http://3232235777/)."""
    h = host.strip("[]")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    try:
        if re.fullmatch(r"\d{1,10}", h) and int(h) < 2 ** 32:
            return str(ipaddress.IPv4Address(int(h)))
        if re.fullmatch(r"0x[0-9a-f]{1,8}", h):
            return str(ipaddress.IPv4Address(int(h, 16)))
    except ValueError:
        return None
    if re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){1,3}", h):   # dotted with hex / octal parts (0x7f.1): an IP to a browser
        return h
    return None


# ------------------------------------------------------------ R4: brand lookalike
# Digits and letter pairs scammers swap in for letters (as gen_typosquat.ASCII_LOOK), undone before the near-miss comparison only.
_FOLD = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("4", "a"), ("5", "s"), ("8", "b"), ("9", "g")]

def _fold(s):
    for a, b in _FOLD:
        s = s.replace(a, b)
    return s

def osa(a, b, cap=3):
    """Optimal string alignment distance (Levenshtein + adjacent transposition: 'patym' is 1 from 'paytm'), capped."""
    if abs(len(a) - len(b)) >= cap:
        return cap
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] != b[j - 1]))
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return min(d[-1][-1], cap)

def _near(tok, bt):
    """tok is a near miss of the brand token bt: after undoing digit swaps (amaz0n), edit distance 0-1 for 5-7 letters, 0-2 for 8+, or the
    brand inside the folded token (amaz0npay); short tokens never (sbi / abc are 2 apart). Called only when tok does not contain bt as written."""
    if len(bt) < 5 or len(tok) < 5:
        return False
    folded = _fold(tok)
    return bt in folded or osa(folded, bt) <= (1 if len(bt) <= 7 else 2)

def _token_hit(tok, bt):
    """How the host token tok names the brand token bt: "name", "near" or None."""
    if len(bt) <= 4:   # sbi, jio, hdfc, bsnl: the whole token, or its start / end (sbikyc, onlinesbi), never inside (lesbian)
        return "name" if tok == bt or (len(tok) > len(bt) and (tok.startswith(bt) or tok.endswith(bt))) else None
    if bt in tok:
        return "name"
    return "near" if _near(tok, bt) else None

def lookalike(host, reg, tranco_rank=None):
    """{"brand", "token", "how": "name" | "near", "owned": [the brand's own domains]} when a host part someone could choose names an Indian
    brand that does not own the registered domain; else None. Exempt: the brand's own domains and brand TLDs, any .brand TLD, the restricted
    zones, the Tranco top 100k (owned-domain lists are incomplete), shorteners and free hosting (free hosting keeps its own brand rule)."""
    if not host or raw_ip(host) or brand_tld(host) or restricted_zone(host) or suffix_match(host, SHORTENERS) or suffix_match(host, FREE_HOSTING):
        return None
    root = platform_of(host)
    if root:   # a user-content platform: only the part the uploader picks (a bucket or page name before the platform)
        chosen = host[: -len(root) - 1] if host != root else ""
    else:
        if tranco_rank is not None and tranco_rank <= 100_000:
            return None
        suffix = reg.split(".", 1)[1] if "." in reg else ""
        chosen = host[: -len(suffix) - 1] if suffix and host.endswith("." + suffix) else host
    tokens = [t for t in re.split(r"[^a-z0-9]+", chosen.lower()) if t]
    for b in reference()["brands"]:
        if reg in b["owned"] or reg.rsplit(".", 1)[-1] in b["tlds"]:
            continue
        for tok in tokens:
            for bt in b["tokens"]:
                how = _token_hit(tok, bt)
                if how:
                    return {"brand": b["brand"], "token": tok, "how": how, "owned": b["owned"][:2] + [f"anything under .{t}" for t in b["tlds"][:1]]}
    return None


# ------------------------------------------------------------ R10: the exact brand name on someone else's domain
def exact_brand(host, reg):
    """{"brand", "label", "official": [the brand's registered domains]} when the registered domain's first label equals a brand label from
    exact_brands.json exactly and the registered domain is not one of that brand's official domains (roblox.com.am, roblox.ly: yes; roblox.com,
    robloxfans.com, pineapple.com: no). No substring and no fuzzy match. Not for IPs, brand TLDs, the restricted zones, shorteners or hosting
    platforms (there the registered domain is the platform's, and the part the user picks is R4's business). Switched off by
    config.EXACT_BRAND_CHECK."""
    from shield import config
    if not config.EXACT_BRAND_CHECK or not host or not reg or raw_ip(host) or brand_tld(host) or restricted_zone(host) or platform_of(host):
        return None
    b = reference()["exact"].get(reg.split(".", 1)[0])
    return None if b is None or reg in b["official"] else {"brand": b["brand"], "label": reg.split(".", 1)[0], "official": b["official"]}


# ------------------------------------------------------------ R3: IDN homograph
# Letters of other alphabets that look like Latin ones (Unicode confusables, the ones phishing uses): Cyrillic, Greek, Armenian.
_CONFUSABLE = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "һ": "h",
                             "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g", "ν": "v", "ο": "o", "α": "a", "ι": "i", "κ": "k", "ρ": "p",
                             "τ": "t", "χ": "x", "υ": "u", "ε": "e", "β": "b", "ո": "n", "օ": "o", "ս": "u", "հ": "h", "ց": "g", "ⅼ": "l"})
_LOOKALIKE_SCRIPTS = {"CYRILLIC", "GREEK", "ARMENIAN"}

def _script(ch):
    try:
        return unicodedata.name(ch).split()[0]
    except ValueError:
        return "UNKNOWN"

def unicode_host(host):
    """The host with xn-- labels decoded (for display and the homograph check); labels that do not decode are kept."""
    out = []
    for lab in host.split("."):
        if lab.startswith("xn--"):
            try:
                lab = lab.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        out.append(lab)
    return ".".join(out)

def skeleton(label):
    """Confusables mapped to Latin and accents stripped ('аррlе' -> 'apple', 'ạmazon' -> 'amazon')."""
    s = unicodedata.normalize("NFKD", label.translate(_CONFUSABLE))
    return "".join(c for c in s if not unicodedata.combining(c))

def homograph(host, top_labels=frozenset()):
    """{"label" (as shown), "looks_like", "kind": "mixed" | "confusable"} when a label of the host imitates Latin letters with another alphabet:
    Latin mixed with Cyrillic / Greek / Armenian in one label, or a non-ASCII label whose skeleton is a brand token or the name of a Tranco
    top-10k site. A label written wholly in one script that imitates nothing (Devanagari .भारत) is not a homograph. None otherwise."""
    for lab in unicode_host(host).split("."):
        if lab.isascii():
            continue
        scripts = {_script(c) for c in lab if c.isalpha()}
        skel = skeleton(lab)
        if "LATIN" in scripts and scripts & _LOOKALIKE_SCRIPTS:
            return {"label": lab, "looks_like": skel if skel.isascii() else None, "kind": "mixed"}
        if skel.isascii() and len(skel) >= 3 and (skel in reference()["tokens"] or skel in top_labels):
            return {"label": lab, "looks_like": skel, "kind": "confusable"}
    return None
