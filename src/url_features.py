import math, os, re
from collections import Counter
from urllib.parse import urlsplit
import tldextract

# Lexical URL features shared by url_head.py (training) and app.py (scoring), so the two cannot drift apart.
# BRANDS .. path_features are moved verbatim from url_head.py; parse_url mirrors build_urls.parse (same bundled
# suffix list, no network) so a URL typed into the app is featurised exactly like a training row.
# Nothing here fetches a URL: strings only (CLAUDE.md rule 8).
tld_ext = tldextract.TLDExtract(suffix_list_urls=())   # uses bundled list, no network

# brand -> registered domains that genuinely own it. A brand token on any other domain is the lookalike signal.
BRANDS = {
    "sbi": ["onlinesbi.sbi", "sbi.co.in", "sbi.bank.in", "onlinesbi.com", "sbicard.com"], "onlinesbi": ["onlinesbi.sbi", "onlinesbi.com"],
    "hdfcbank": ["hdfcbank.com"], "icicibank": ["icicibank.com"], "axisbank": ["axisbank.com"], "kotak": ["kotak.com"],
    "paytm": ["paytm.com", "paytmbank.com"], "phonepe": ["phonepe.com"], "npci": ["npci.org.in"],
    "indiapost": ["indiapost.gov.in"], "irctc": ["irctc.co.in"], "incometax": ["incometax.gov.in", "incometaxindia.gov.in"],
    "uidai": ["uidai.gov.in"], "parivahan": ["parivahan.gov.in"], "flipkart": ["flipkart.com"], "cybercrime": ["cybercrime.gov.in"],
    "epfindia": ["epfindia.gov.in"], "amazon": ["amazon.in", "amazon.com", "amazon.co.uk", "amazon.de"], "google": ["google.com", "google.co.in"],
    "microsoft": ["microsoft.com", "live.com"], "apple": ["apple.com"], "paypal": ["paypal.com"], "facebook": ["facebook.com"],
    "instagram": ["instagram.com"], "whatsapp": ["whatsapp.com"], "netflix": ["netflix.com"],
}
SUSPICIOUS = ["login", "signin", "verify", "secure", "account", "update", "kyc", "bank", "wallet", "confirm", "support", "otp",
              "refund", "claim", "bonus", "prize", "free", "gift", "reward", "unlock", "suspend", "alert", "billing", "recover"]
EXEC_EXT = {".exe", ".apk", ".php", ".html", ".htm", ".zip", ".sh", ".js", ".asp", ".aspx"}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())

def lev(a, b, cap=3):
    """Levenshtein distance, capped (returns cap as soon as it can't be below it)."""
    if abs(len(a) - len(b)) >= cap:
        return cap
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) >= cap:
            return cap
        prev = cur
    return min(prev[-1], cap)

def host_features(host, reg):
    labels = host.split(".")
    reg_label = reg.split(".")[0]
    toks = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    is_ip = bool(IP_RE.match(host))
    f = {"host_len": len(host), "n_labels": len(labels), "subdomain_depth": 0 if is_ip else max(0, len(labels) - len(reg.split("."))),
         "n_hyphens": host.count("-"), "n_digits": sum(c.isdigit() for c in host), "host_entropy": entropy(host),
         "reg_label_len": len(reg_label), "reg_label_entropy": entropy(reg_label), "longest_label": max(map(len, labels)),
         "has_ip": int(is_ip), "punycode": int("xn--" in host), "non_ascii": sum(ord(c) > 127 for c in host),
         "n_suspicious_host": sum(k in host for k in SUSPICIOUS)}
    f["digit_ratio"] = f["n_digits"] / max(1, len(host))
    f["tld"] = reg.rsplit(".", 1)[-1] if "." in reg and not is_ip else ""
    # brand lookalikes: a brand as a whole token or long substring on a domain that doesn't own it, and the smallest edit
    # distance (cap 3) from a name token to a brand it isn't (exact matches on a legitimate domain score the cap)
    off_tok = off_sub = 0
    best = 3
    for b, legit in BRANDS.items():
        owns = reg in legit
        if not owns and b in toks:
            off_tok += 1
        if not owns and len(b) >= 5 and b in host:
            off_sub += 1
        if not owns and len(b) >= 4 and not is_ip:
            for t in {reg_label, *toks}:
                if len(t) >= 4 and t != b:
                    best = min(best, lev(t, b))
    f.update(brand_token_offsite=off_tok, brand_substr_offsite=off_sub, brand_min_dist=best)
    return f

def path_features(url):
    s = urlsplit(url if "://" in url else "http://" + url)
    path, q = s.path, s.query
    ext = os.path.splitext(path)[1].lower()
    return {"url_len": len(url), "path_len": len(path), "n_slashes": path.count("/"), "query_len": len(q),
            "n_params": q.count("&") + bool(q), "path_digits": sum(c.isdigit() for c in path + q), "path_entropy": entropy(path + q),
            "has_at": int("@" in url), "n_pct": url.count("%"), "double_slash_path": int("//" in path),
            "exec_ext": int(ext in EXEC_EXT), "n_suspicious_path": sum(k in (path + q).lower() for k in SUSPICIOUS)}

HOST_NORMS = ("none", "strip_www")
WWW_LABEL = re.compile(r"^www[1-9]?\.")   # "www." and "www1." .. "www9."

def normalise_host(host, mode="none", reg=None):
    """Optional host normalisation before featurising. "none" (default) returns the host unchanged. "strip_www" removes ONE leading
    www / www1..www9 label ("www.www.a.com" -> "www.a.com"). `reg` is the registered domain of `host`; the label is kept when it is part
    of it (reg "www.com" or "www.co.uk": host == reg) so the result still ends with `reg`. Without `reg` the label is kept when
    nothing with a dot would be left."""
    if mode == "none":
        return host
    if mode != "strip_www":
        raise ValueError(f"host_norm must be one of {HOST_NORMS}, got {mode!r}")
    m = WWW_LABEL.match(host)
    if not m:
        return host
    rest = host[m.end():]
    if reg is not None:
        return rest if rest == reg or rest.endswith("." + reg) else host
    return rest if "." in rest else host

def parse_url(url, host_norm="none"):
    """(host, registered domain) exactly as build_urls.parse derives them; ('', '') if there is no host. host_norm="strip_www" drops a
    leading www label from the host returned (the registered domain is unaffected); the default leaves the output unchanged."""
    try:
        s = urlsplit(url if "://" in url else "http://" + url)
        host = (s.hostname or "").lower()
    except ValueError:   # e.g. an unbalanced '[' in a pasted fragment
        return "", ""
    if not host:
        return "", ""
    reg = tld_ext(host).top_domain_under_public_suffix or host
    return normalise_host(host, host_norm, reg), reg

def host_row(url, top_tld, host_norm="none"):
    """Host-only feature dict for one URL, with the same tld_code the model was trained on (top_tld = the 40 most
    frequent train TLDs in order, saved in models/url_head.joblib; anything else is code len(top_tld)). None if no host.
    host_norm: see normalise_host (the default is today's behaviour)."""
    host, reg = parse_url(url, host_norm)
    if not host:
        return None
    f = host_features(host, reg)
    f["tld_code"] = top_tld.index(f["tld"]) if f["tld"] in top_tld else len(top_tld)
    return f
