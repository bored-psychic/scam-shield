import csv, glob, hashlib, os, re, tarfile
import pandas as pd
import tldextract

# Shared helpers for the gambling_spam class (UT1 "gambling" + Blocklist Project "gambling" snapshots in data/raw/, see
# src/pull_gambling.py). Used by build_urls.py (labels), gambling_lookup.py (lookup files) and gambling_report.py.
# Everything here treats entries as strings: nothing is resolved or visited (CLAUDE.md rule 8).
#
# What the label means: a gambling *category*, not "scam": the registered domain is on both gambling lists, or the user decided
# `gambling_spam` for it in reports/gambling_manual_review.csv (2026-10-10 policy: operators, result / tip sites and affiliate,
# bonus and odds sites count; only B2B or unrelated sites are benign). Licensed operators (bet365, betfair, fanduel) are on the lists. The class exists so the Links engine and a later URL-head can tell
# "gambling site" from "phishing site"; is_bad stays phishing / malware only (build_urls.py).

RAW = "data/raw"
ext = tldextract.TLDExtract(suffix_list_urls=())   # build_urls.py's rule: bundled list, PSL private suffixes are NOT split
ext_priv = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)   # used only to spot hosting platforms
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def latest(pattern, raw=RAW):
    files = sorted(glob.glob(os.path.join(raw, pattern)))
    return files[-1] if files else None

def snapshot_date(path):
    return re.search(r"(\d{4}-\d{2}-\d{2})", os.path.basename(path)).group(1)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def _reg(host):
    return host if IP_RE.match(host) else (ext(host).top_domain_under_public_suffix or host)

def read_ut1(path):
    """Hosts of gambling/domains inside the UT1 tarball, read in memory (nothing is extracted to disk). A leading dot
    ('.betway.ug') means 'this domain and its subdomains' in UT1 and is dropped."""
    with tarfile.open(path) as t:
        raw = t.extractfile("gambling/domains").read().decode("utf-8", "replace")
    out = []
    for ln in raw.splitlines():
        h = ln.strip().lower().lstrip(".")
        if h and not re.search(r"[/\s*:]", h):
            out.append(h)
    return out

def read_blp(path):
    """Hosts of a Blocklist Project hosts-format file ('0.0.0.0 domain'); '#' lines are the header."""
    out = []
    for ln in open(path, encoding="utf-8", errors="replace"):
        if ln.startswith("#") or not ln.strip():
            continue
        p = ln.split()
        h = (p[1] if len(p) > 1 else p[0]).lower().lstrip(".")
        if h and not re.search(r"[/*:]", h):
            out.append(h)
    return out

def load_lists(raw=RAW):
    """(DataFrame[src, host, reg, platform, ip], info). reg = registered domain by the pipeline's rule. platform = the host sits
    under a public-suffix-list *private* suffix (pages.dev, cloudfront.net, com.de, blogspot.com ...): many unrelated parties
    share such a suffix, so it can't be a registered-domain entry; these are kept as host-level entries only. None if a
    snapshot is missing."""
    ut_path, bl_path = latest("ut1_gambling_*.tar.gz", raw), latest("blocklistproject_gambling_*.txt", raw)
    if not (ut_path and bl_path):
        return None, None
    rows = []
    for src, hosts in (("ut1", set(read_ut1(ut_path))), ("blp", set(read_blp(bl_path)))):
        for h in hosts:
            ip = bool(IP_RE.match(h))
            reg = _reg(h)
            rows.append((src, h, reg, (not ip) and (ext_priv(h).top_domain_under_public_suffix or h) != reg, ip))
    info = {"ut1": ut_path, "blp": bl_path, "ut1_date": snapshot_date(ut_path), "blp_date": snapshot_date(bl_path),
            "ut1_sha256": sha256(ut_path), "blp_sha256": sha256(bl_path)}
    return pd.DataFrame(rows, columns=["src", "host", "reg", "platform", "ip"]), info

def domain_sets(G):
    """Registered domains per list, platform and IP entries excluded: (ut1, blp)."""
    d = G[~G.platform & ~G.ip]
    return set(d[d.src == "ut1"].reg), set(d[d.src == "blp"].reg)

def tranco_ranks(raw=RAW):
    """{domain: rank} from the top-100k snapshot (rank,domain lines; .txt on purpose, build_urls.py globs data/raw/*.csv)."""
    p = latest("tranco_top100k_*.txt", raw)
    if not p:
        return {}
    r = pd.read_csv(p, names=["rank", "domain"])
    return dict(zip(r["domain"], r["rank"]))

# ---- keyword candidates: benign-labelled domains whose name looks like gambling ----------------------------------------------
# Which already-labelled domains are *candidates* for gambling_spam. A candidate is relabelled only if a list confirms it; a
# candidate on neither list goes to reports/gambling_manual_review.csv. The regex matches the first label of the registered
# domain; NOISE are look-alikes (betterhelp, bethesda, alphabet-city, loksatta ...) removed by eye on 2026-10-09 from the hits in
# the current urls.csv. Not exhaustive: a gambling domain with no gambling word in its name is never a candidate.
KW_RX = re.compile(r"(^|[-_])bet|bet($|[-_])|bet\d|\d+bet|casino|satta|matka|rummy|aviator|xbet|betting|teenpatti|poker|parimatch|"
                   r"betway|betfair|1win|mostbet|melbet|megapari|fun88|dream11|slots?|jackpot|dpboss", re.I)   # dpboss added 2026-10-09 (India rule)
NOISE = {"betweendigital.com", "betterstackdata.com", "betterhelp.com", "bethesda.net", "betterttv.net", "betterstack.com",
         "betanews.com", "betrad.com", "pokerogue.net", "loksatta.com", "jansatta.com", "tibet.ca", "bettyconfidential.com",
         "betterhearing.org", "lostaviators.com",
         "alphabet-city.com.au", "bettergreenerlife.com", "betcartpartners.com", "taste-better.com", "bettiati.com.br",
         "betterbettafarms.com"}

def keyword_candidate(reg):
    return reg not in NOISE and bool(KW_RX.search(reg.split(".")[0]))

# ---- India rule --------------------------------------------------------------------------------------------------------------
# UT1 and the Blocklist Project have almost no Satta / Matka coverage, so India gets its own seed list and token rule
# (gambling_lookup.py writes data/final/gambling_india.json). Measured on the Tranco top-100k on 2026-10-09: the strong tokens
# hit 81 domains, 3 of them look like false positives (loksatta, jansatta, sattacademy); a weak token alone was about 64%
# gambling (13 of 22: kalyanjewellers, kalyansilks, the Finnish aurinkomatkat.fi are not), so it never matches alone.
INDIA_STRONG = ("satta", "sattaking", "dpboss")
INDIA_WEAK = ("matka", "kalyan")
INDIA_EXEMPT_SUFFIXES = ("gov.in", "nic.in", "edu.in", "ac.in", "res.in")
INDIA_ALLOW = {"loksatta.com", "jansatta.com", "sattacademy.com"}

def india_hit(host):
    """'strong' (a strong token, or two different India tokens), 'weak' (one weak token) or None. Substring of the host."""
    host = (host or "").lower().rstrip(".")
    if not host or _reg(host) in INDIA_ALLOW or any(host == s or host.endswith("." + s) for s in INDIA_EXEMPT_SUFFIXES):
        return None
    strong = [t for t in INDIA_STRONG if t in host]
    weak = [t for t in INDIA_WEAK if t in host]
    if strong or len(weak) >= 2:
        return "strong"
    return "weak" if weak else None

# ---- manual review sheet -----------------------------------------------------------------------------------------------------
REVIEW_PATH = os.environ.get("GAMBLING_REVIEW_PATH", "reports/gambling_manual_review.csv")   # env override is for tests only
# decision = the user's column (blank until marked). search_evidence / suggested_decision / confidence were added by a web-search pass
# (search result titles and snippets only, no site opened); they are suggestions and never feed a label by themselves.
REVIEW_COLS = ["domain", "suggested_label", "reason", "india", "decision", "search_evidence", "suggested_decision", "confidence"]
INFO_SITES = {"chessandpoker.com", "casinobonustips.com", "casinovendordirectory.com", "betexplorer.com"}

def _review_row(reg, listed_regs):
    sld = reg.split(".")[0]
    same = sorted(r for r in listed_regs if r != reg and r.split(".")[0] == sld)
    ind = india_hit(reg)
    india = "yes" if (ind or reg.endswith(".in") or "cric" in sld) else ""   # a hint only; the user sets it
    if reg in INFO_SITES:
        sib = f"; a sibling is listed ({', '.join(same[:2])})" if same else ""
        return reg, "unsure", f"name suggests an information / affiliate / odds site rather than an operator; on neither list{sib}", india
    if ind == "strong":
        return reg, "gambling_spam", "India satta / matka / dpboss name; the lists carry no Indian satta sites, so no list evidence", india
    if same:
        return reg, "gambling_spam", (f"same name is listed under {len(same)} other domain(s) (e.g. {', '.join(same[:3])}); "
                                       "this TLD variant itself is not listed"), india
    if ind == "weak":
        return reg, "unsure", "India matka / kalyan word alone (weak token: also a Finnish word and a common name); on neither list", india
    return reg, "unsure", "gambling word in the name, on neither list; name only, nothing was opened", india

def write_review_sheet(domains, listed_regs, path=REVIEW_PATH):
    """Written once and never overwritten (the user fills `decision` = gambling_spam | benign). Suggestions come from the name
    and the lists only; no site was visited."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(REVIEW_COLS)
        for d in sorted(domains):
            w.writerow([*_review_row(d, listed_regs), "", "", "", ""])

def append_review_rows(domains, listed_regs, path=REVIEW_PATH):
    """Add pending domains that are not yet in the sheet. Existing rows (and the user's decisions) are never touched."""
    cur = pd.read_csv(path, keep_default_na=False, dtype=str)
    todo = sorted(set(domains) - set(cur["domain"]))
    if todo:
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            for d in todo:
                row = dict(zip(["domain", "suggested_label", "reason", "india"], _review_row(d, listed_regs)))
                w.writerow([row.get(c, "") for c in cur.columns])   # follows the sheet's own column order
    return todo

def read_review_suggestions(path=REVIEW_PATH):
    """{domain: suggested_decision} from the search pass ('' if the sheet has no such column or the row was not searched)."""
    if not os.path.exists(path):
        return {}
    r = pd.read_csv(path, keep_default_na=False, dtype=str)
    return {row.domain: row.suggested_decision.strip().lower() for row in r.itertuples()} if "suggested_decision" in r else {}

def decision_provenance(decision, suggested):
    """A decision that equals the search suggestion is 'search_review' (accepted from the search pass); anything else the user
    decided is 'manual_review'. A suggestion of 'unsure' can never be accepted, so it is always manual."""
    return "search_review" if decision and decision == suggested and suggested in ("gambling_spam", "benign") else "manual_review"

def read_review(path=REVIEW_PATH):
    """{domain: (decision, india)}; decision is '' until the user has marked the row."""
    if not os.path.exists(path):
        return {}
    r = pd.read_csv(path, keep_default_na=False, dtype=str)
    return {row.domain: (row.decision.strip().lower(), row.india.strip().lower()) for row in r.itertuples()}
