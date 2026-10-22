"""Live link checks on a fresh phishing sample: how well do the D23 link signals (src/shield/links/) catch links that are live today?
Edition 1 (231db07) measured only. Edition 2 (2026-10-23, decision C1) re-scores the SAME sample offline after the list changes (platforms.py, gambling.py,
crt.sh off by default) and adds the URL-model rule variants and a before/after section; the "before" numbers are read from the results CSV committed in
231db07, so the cached replies are never re-pulled. Re-runnable on a new date.

    .venv/bin/python src/update_link_lists.py --only openphish urlhaus     # 1. fresh feed (the sanctioned list download, rule 8)
    .venv/bin/python scripts/eval_live_links.py                            # 2. sample + network pass (rate-limited) + report
    .venv/bin/python scripts/eval_live_links.py --offline                  # 3. rerun from the reply cache, no network

What it does
  * The function judged is the one the API calls: shield.core.router.analyse(text, ..., live=True) wrapped by shield.core.report.to_report.
    Each sampled link is the whole message text (a bare link: the text head is skipped, so the verdict is the link verdict).
  * Phishing set: the current OpenPhish public feed, one link per registered domain (tldextract top_domain_under_public_suffix).
    Benign set: Tranco ranks 1-10k and 100k-1M, one https://<domain>/ per domain, half each. Regression set: gambling cases (see REGRESSION below).
    Samples are saved DEFANGED (hxxp, [.]) in data/eval_live/; a rerun on the same date reuses those files (--resample to redraw).
  * Network: only through shield.core.net (RDAP, Cloudflare DoH, crt.sh). This script wraps net.request to (a) refuse anything else, (b) keep
    <= 1 request per second per service (all RDAP registries count as one service), (c) retry RDAP / crt.sh failures twice, (d) cache every reply
    (failures too, as "unavailable") in data/eval_live/netcache_<date>.jsonl.gz, (e) log each call by host. A socket.getaddrinfo guard refuses to
    resolve any sampled host: a sampled link is never connected to, whatever the code does.
  * Ablations are made by giving router.analyse a copy of the link lists with a signal switched off (the repo code is not edited):
    all ON / OpenPhish + URLhaus OFF / OpenPhish + URLhaus + Tranco OFF (the honest headline) / the honest one again with first attempts only.
  * The 4 s message deadline of live.run is lifted (60 s) because the 1 req/s throttle would otherwise cause artificial timeouts; the app-equivalent
    latency per link is reported separately from the cached first-attempt timings.
Outputs: data/eval_live/{phish,benign,regression,results}_<date>.csv, reports/eval_live_links.md
"""
import argparse, base64, collections, copy, csv, datetime as dt, gzip, hashlib, io, json, math, os, random, re, socket, subprocess, sys, threading, time
from pathlib import Path
from urllib.parse import unquote, urlsplit

os.environ.setdefault("HF_HUB_OFFLINE", "1")          # the text head is loaded from disk; nothing may reach huggingface.co
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]

import numpy as np
import pandas as pd

from shield import config
from shield.config import LINKLISTS_DIR
from shield.contracts import Level
from shield.core import net, router
from shield.core.report import to_report
from shield.links import live as live_checks
from shield.core.verdict import LEVELS
from shield.links.gambling import GAMBLING_VERDICT, load_gambling
from shield.links.lexical import load_url_model
from shield.links.lists import LinkLists, load_lists, warm as warm_lists
from shield.links.lookalike import link_domain, raw_ip
from shield.links.platforms import FREE_HOSTING, SHORTENERS, USER_CONTENT, platform_of, suffix_match
from shield.messages.text_head import load_text_model
from url_features import tld_ext      # TLDExtract(suffix_list_urls=()): the bundled suffix list, never the network

OUT_DIR = ROOT / "data" / "eval_live"
REPORT = ROOT / "reports" / "eval_live_links.md"
SERVICE_INTERVAL = 1.0        # seconds between two requests to the same service
RETRIES = 2                   # RDAP / crt.sh failures are retried twice, then recorded as unavailable
EVAL_DEADLINE = 60.0          # live.run's message deadline while the throttle is on (the app's is 4 s)
RETRY_STATUS = {429, 500, 502, 503, 504}
RETRY_ERR = {"offline", "timeout", "bad_response"}
OK_STATUS = {"rdap": {200, 404}, "doh": {200}, "crtsh": {200}, "sb": {200}}
BANDS = [("top 10k", 1, 10_000), ("10k-100k", 10_001, 99_999), ("100k-1M", 100_000, 1_000_000)]
LABEL = {Level.LIKELY_SCAM: "Likely scam", Level.SUSPICIOUS: "Suspicious", Level.NO_WARNING_SIGNS: "No warning signs", Level.CANT_JUDGE: "Can't judge"}
VERDICTS = ["Likely scam", "Suspicious", "No warning signs", "Can't judge"]
CJ = "Can't judge"
SETTINGS = [("all_on", "All signals ON", dict(blocklists=True, tranco=True), "retry"),
            ("no_blocklists", "OpenPhish + URLhaus OFF", dict(blocklists=False, tranco=True), "retry"),
            ("honest", "OpenPhish + URLhaus + Tranco OFF (honest headline)", dict(blocklists=False, tranco=False), "retry"),
            ("honest_first", "Honest setting, first attempt only (no retries: as the app answers)", dict(blocklists=False, tranco=False), "first")]

# URL-model rule variants (decision C2 proposal), each scored in the honest setting. They are applied by wrapping router.assess_background, so the app code
# is not changed: after the link's background checks have run, a link the URL model scored whose checks raised no red flag is re-levelled:
#   (a) current        nothing changes: the URL model alone can give Suspicious or Likely scam
#   (b) cap            the URL model alone gives at most Suspicious (a red flag keeps the original level, so flag + model can still reach Likely scam)
#   (c) weight only    the URL model alone gives nothing; with a red flag it keeps its weight (flag + a high model level still reaches Likely scam)
# A gambling-list hit keeps its own Suspicious floor in all three. Free-hosting and shortener links are not scored by the URL model and are untouched.
EXTRA_SETTINGS = [("honest_b", "Honest setting, variant (b): URL model alone at most Suspicious", dict(blocklists=False, tranco=False), "retry", "b"),
                  ("honest_c", "Honest setting, variant (c): URL model alone cannot raise the verdict", dict(blocklists=False, tranco=False), "retry", "c")]
VARIANT_ROWS = [("(a) current", "honest"), ("(b) URL model alone: at most Suspicious", "honest_b"), ("(c) URL model alone: no effect, weight only with a red flag", "honest_c")]
BEFORE_COMMIT = "231db07"      # the first edition of this evaluation: its results CSV is the "before"

def variant_hook(real, variant):
    def hooked(l, lists, live=None, state="pending", now=None):
        c = real(l, lists, live, state, now)
        if variant != "a" and l["kind"] == "model" and not (c and c["flags"]):
            if variant == "b" and (l["level"] or 0) > 1:
                l["base_level"], l["level"], l["verdict"] = min(l["base_level"] or 0, 1), 1, LEVELS[1]
            elif variant == "c":
                l["base_level"] = 0
                l["level"], l["verdict"] = (1, GAMBLING_VERDICT) if l["gambling"] else (0, "not flagged")
        return c
    return hooked

# Regression group (gambling / spam-ad). The exact link of the reported miss ("a spam-ad link that led to a gambling site was rated safe") was never
# supplied (BUGS.md, gambling entry), so this group is built from what the repo documents:
#   unlisted: gambling sites BUGS.md says the gambling lookup misses ("about two dozen of the 66 Blocklist-Project-only domains in the Tranco top 10k
#             that are still gambling or betting sites"; the 8 it names). All sit in the top 10k, i.e. P2 (a well-known website) would apply.
#   unconfirmed: the 4 `pending_review` domains of reports/gambling_manual_review.csv (gambling-looking, never decided by the user).
#   control: domains the lookup does list (G1 must still say Suspicious).
#   message: spam-ad text with a gambling link, a hidden short link (never expanded here) and an unlisted gambling site.
UNLISTED = ["sportpesa.com", "msport.com", "bingoplus.com", "tippmix.hu", "skyvegas.com", "pocketoption.com", "szerencsejatek.hu", "juan365.com"]
UNCONFIRMED = ["betonuzzz.ru", "casino50.com", "metabet.tv", "parimatchs123.com"]
CONTROL = ["bet365.com", "1xbet.com", "stake.com", "dpboss.tax", "betika.com", "sportybet.com"]
AD = "Congratulations! You have won a 500% welcome bonus on your first deposit. Play now and win big: "
MESSAGES = [("msg-listed", "spam ad + listed gambling site", AD + "https://bet365.com/", "Suspicious"),
            ("msg-short", "spam ad + short link (destination hidden, never expanded)", AD + "https://bit.ly/3Xk9Qp", "Suspicious or Can't judge"),
            ("msg-unlisted", "spam ad + gambling site missing from the lookup", AD + "https://sportpesa.com/", "Suspicious")]


# ------------------------------------------------------------------------------------------------ small helpers
def defang(s):
    return re.sub(r"^http", "hxxp", s, flags=re.I).replace(".", "[.]")

def refang(s):
    return re.sub(r"\bhxxp", "http", s, flags=re.I).replace("[.]", ".")

def defang_text(s):
    return re.sub(r"https?://\S+", lambda m: defang(m.group(0)), s)

def reg_of(url):
    t = tld_ext(url)
    return t.top_domain_under_public_suffix or t.domain or urlsplit(url).hostname or ""

def kind_of(host):
    if suffix_match(host, SHORTENERS):
        return "shortener"
    if raw_ip(host):
        return "raw_ip"
    if suffix_match(host, FREE_HOSTING):
        return "free_hosting"
    if suffix_match(host, USER_CONTENT):
        return "user_content"
    return "own_domain"

def band_of(rank):
    if rank is None:
        return "not in top 1M"
    return next((n for n, lo, hi in BANDS if lo <= rank <= hi), "not in top 1M")

def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))

def pct(k, n, ci=False):
    if n == 0:
        return "n/a"
    s = f"{100 * k / n:.0f}%"
    if ci:
        lo, hi = wilson(k, n)
        s += f" [{100 * lo:.0f}-{100 * hi:.0f}]"
    return s

def md_table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" if i == 0 else "---:" for i in range(len(head))) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


# ------------------------------------------------------------------------------------------------ network wrapper (rate limit, retry, cache, log)
class NetHarness:
    """Wraps shield.core.net.request. The real net.request (allowlist, https only, no redirects, <= 2 s, no logging) still makes every call."""
    def __init__(self, cache_path, offline):
        self.path, self.offline, self.mode = cache_path, offline, "retry"
        self.real = net.request
        self.lock, self.next_at = threading.Lock(), {}
        self.cache, self.log = {}, []          # log: one dict per logical call (host, service, replay?, ...)
        self.forbidden_hosts = set()           # sampled hosts: never requested
        self.misses = 0
        if cache_path.exists():
            with gzip.open(cache_path, "rt", encoding="utf-8") as f:
                for line in f:
                    e = json.loads(line)
                    self.cache[e["key"]] = e

    @staticmethod
    def service_of(host):
        return "doh" if host == "cloudflare-dns.com" else "crtsh" if host == "crt.sh" else "sb" if host == "safebrowsing.googleapis.com" else "rdap"

    @staticmethod
    def reg_of(url, params):
        p = dict(params) if isinstance(params, dict) else dict(params or [])
        if "name" in p:
            return str(p["name"])
        if "q" in p:
            return str(p["q"])
        path = urlsplit(url).path
        return unquote(path.split("/domain/", 1)[1]) if "/domain/" in path else ""

    def _wait(self, svc):
        with self.lock:
            now = time.monotonic()
            t = max(now, self.next_at.get(svc, 0.0))
            self.next_at[svc] = t + SERVICE_INTERVAL
        if t > now:
            time.sleep(t - now)

    def _once(self, url, kw):
        t0 = time.perf_counter()
        try:
            r = self.real(url, "check", **kw)
            return {"status": r.status, "err": None, "ms": round((time.perf_counter() - t0) * 1000, 1), "headers": r.headers, "body": base64.b64encode(r.body).decode()}
        except net.NetError as e:
            return {"status": None, "err": e.status, "ms": round((time.perf_counter() - t0) * 1000, 1), "headers": {}, "body": ""}

    def request(self, url, kind="check", *, method="GET", params=None, headers=None, timeout=net.CALL_TIMEOUT, max_bytes=2_000_000):
        host = net.allowed(url, kind) if kind == "check" else None
        if host is None:
            raise net.NetError("refused")        # only the live checks are allowed here: no expand, no update
        if host in self.forbidden_hosts:
            raise net.NetError("refused")        # a sampled link's host is never requested
        svc = self.service_of(host)
        plist = sorted((k, str(v)) for k, v in (params.items() if isinstance(params, dict) else (params or [])))
        key = hashlib.sha1(json.dumps([method, url, plist]).encode()).hexdigest()
        reg = self.reg_of(url, params)
        with self.lock:
            e = self.cache.get(key)
        if e is None:
            if self.offline:
                with self.lock:
                    self.misses += 1
                raise net.NetError("offline")
            kw = dict(method=method, params=params, headers=headers, timeout=timeout, max_bytes=max_bytes)
            attempts = []
            for i in range(1 + (RETRIES if svc in ("rdap", "crtsh") else 0)):
                if i:
                    time.sleep(2.0 * i)          # back off before a retry
                self._wait(svc)
                a = self._once(url, kw)
                attempts.append(a)
                if a["err"] is None and a["status"] not in RETRY_STATUS:
                    break
                if a["err"] is not None and a["err"] not in RETRY_ERR:
                    break
            for a in attempts[:-1]:
                a["body"] = ""                   # only the last reply's body is kept
            e = {"key": key, "service": svc, "host": host, "reg": reg, "attempts": attempts}
            with self.lock:
                self.cache[key] = e
                with gzip.open(self.path, "at", encoding="utf-8") as f:
                    f.write(json.dumps(e) + "\n")
            fresh = True
        else:
            fresh = False
        a = e["attempts"][0] if self.mode == "first" else e["attempts"][-1]
        with self.lock:
            self.log.append({"host": host, "service": svc, "fresh": fresh, "reg": reg})
        if a["err"] is not None:
            raise net.NetError(a["err"])
        return net.Response(a["status"], a["headers"], base64.b64decode(a["body"]), host)


class ResolveGuard:
    """socket.getaddrinfo wrapper: logs every name the process resolves and refuses the sampled hosts. With refuse_all (an --offline run) it refuses every
    name and every socket connect, and counts them: the report states they are 0."""
    def __init__(self, refuse_all=False):
        self.names, self.forbidden, self.orig = collections.Counter(), set(), socket.getaddrinfo
        self.refuse_all, self.connects = refuse_all, 0
    def install(self):
        def guarded(host, *a, **k):
            h = (host.decode() if isinstance(host, bytes) else str(host or "")).lower().rstrip(".")
            self.names[h] += 1
            if self.refuse_all or h in self.forbidden:
                raise OSError("blocked by eval_live_links: " + ("offline run" if self.refuse_all else "sampled host"))
            return self.orig(host, *a, **k)
        socket.getaddrinfo = guarded
        if self.refuse_all:
            def no_connect(sock, *a, **k):
                self.connects += 1
                raise OSError("blocked by eval_live_links: offline run")
            socket.socket.connect = no_connect
            socket.socket.connect_ex = no_connect
            socket.create_connection = no_connect


# ------------------------------------------------------------------------------------------------ link-list views (ablations)
def view(base, blocklists, tranco):
    v = copy.copy(base)
    v.status = dict(base.status)
    if not blocklists:
        v.status["openphish"] = v.status["urlhaus"] = "switched off for the evaluation"
        v.bad_ips = set()                         # R6 reads the IPs of the two lists
    if not tranco:
        v._t_hash, v._t_rank, v.top_labels = np.array([], np.int64), np.array([], np.int32), frozenset()
        v.status["tranco"] = "switched off for the evaluation"
    return v


# ------------------------------------------------------------------------------------------------ sampling
def read_feed():
    path = LINKLISTS_DIR / "openphish.txt"
    man = json.loads((LINKLISTS_DIR / "manifest.json").read_text())
    return [l.strip() for l in path.read_text(errors="replace").splitlines() if l.strip()], man

def sample_phish(base, n, seed, date):
    urls, man = read_feed()
    by_reg = collections.defaultdict(list)
    for u in urls:
        host, reg = link_domain(u)
        app_reg = reg
        k = reg_of(u) if not raw_ip(host) else host
        by_reg[k].append((u, host, app_reg))
    rng = random.Random(f"phish|{date}|{seed}")
    regs = sorted(by_reg)
    rng.shuffle(regs)
    rows = []
    for k in regs[:n]:
        u, host, app_reg = rng.choice(by_reg[k])
        rows.append({"url": u, "reg": k, "app_reg": app_reg, "kind": kind_of(host), "rank": base.tranco_rank(k)})
    info = {"feed_rows": len(urls), "unique_regs": len(by_reg), "taken": len(rows), "downloaded_utc": man["openphish"]["downloaded_utc"],
            "feed_sha256": man["openphish"]["sha256"], "reg_mismatch": sum(r["reg"] != r["app_reg"] for r in rows),
            "urls_per_kind": dict(collections.Counter(kind_of(link_domain(u)[0]) for u in urls)),
            "regs_per_kind": dict(collections.Counter(kind_of(link_domain(by_reg[k][0][0])[0]) for k in by_reg))}
    return rows, info

def sample_benign(base, n_each, seed, date, taken):
    df = pd.read_csv(LINKLISTS_DIR / "tranco_top1m.csv", names=["rank", "domain"], keep_default_na=False)
    rng = random.Random(f"benign|{date}|{seed}")
    rows, info = [], {}
    for name, lo, hi in (("top 10k", 1, 10_000), ("100k-1M", 100_000, 1_000_000)):
        pool = df[(df["rank"] >= lo) & (df["rank"] <= hi)]
        keep, skipped = [], collections.Counter()
        for rank, dom in zip(pool["rank"], pool["domain"]):
            d = dom.lower()
            host, reg = link_domain("https://" + d + "/")
            if d in taken:
                skipped["already in another set"] += 1
            elif reg != d or host != d:
                skipped["not a bare registered domain"] += 1
            elif platform_of(d) or kind_of(d) != "own_domain":
                skipped["platform / shortener / user content (judged by other rules)"] += 1
            else:
                keep.append((int(rank), d))
        pick = rng.sample(keep, n_each)
        pick.sort()
        rows += [{"url": f"https://{d}/", "reg": d, "band": name, "rank": r, "kind": "own_domain"} for r, d in pick]
        info[name] = {"pool": len(pool), "eligible": len(keep), "skipped": dict(skipped), "taken": n_each}
    return rows, info

def control_extra(seed, date, taken, k=4):
    """k more listed gambling domains outside the Tranco top 1M: on both lists, a .com with bet / casino in the name."""
    df = pd.read_csv(ROOT / "data" / "final" / "gambling_domains.tsv", sep="\t", keep_default_na=False, dtype=str)
    cand = sorted(d for d, l, t in zip(df["domain"], df["lists"], df["tranco_rank"]) if l == "both" and t == "" and d.endswith(".com")
                  and re.search(r"(bet|casino)", d) and d not in taken)
    return random.Random(f"control|{date}|{seed}").sample(cand, k)

def save_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


# ------------------------------------------------------------------------------------------------ one link through the real path
def signals_of(item, res, live, base, today):
    """Everything about one analysed link that the report needs (res: router.analyse() dict; live: that link's live.run output)."""
    l = res["links"][0] if res["links"] else None
    out = {"flags": [], "positive": None, "gambling": None, "url_score": None, "checks": [], "rdap": "n/a", "age_days": None, "crt": "n/a", "dns": "n/a",
           "lists": "", "link_level": None}
    if l is None:
        out["rdap"] = out["crt"] = out["dns"] = "no link extracted"
        return out
    host, reg = link_domain(l["url"])
    out["flags"] = list(l["flags"])
    out["positive"] = l["positive"]
    out["gambling"] = (l["gambling"] or {}).get("basis")
    out["url_score"] = l["score"]
    out["link_level"] = l["level"]
    out["checks"] = live_checks.plan(l["url"])[2]
    out["lists"] = ",".join(sorted({n for n, _ in base.listed(l["url"], host)}))
    reg_res = (live or {}).get("registration")
    if "registration" in out["checks"]:
        rd = (reg_res or {}).get("rdap") or {"status": "failed", "why": "timeout"}
        if rd.get("status") == "ok" and rd.get("created"):
            out["rdap"], out["age_days"] = "date", (today - rd["created"]).days
        elif rd.get("status") == "ok":
            out["rdap"] = "no_date"
        elif rd.get("status") in ("not_found", "unsupported"):
            out["rdap"] = rd["status"]
        else:
            out["rdap"] = "failed:" + str(rd.get("why"))
        ct = (reg_res or {}).get("crtsh")
        if ct is not None:
            out["crt"] = ("first_cert_%dd" % (today - ct["first"]).days) if ct.get("status") == "ok" else ct.get("status") if ct.get("status") == "none" else "failed:" + str(ct.get("why"))
            out["crt_days"] = (today - ct["first"]).days if ct.get("status") == "ok" else None
        else:
            out["crt"] = "not needed"
        dn = (live or {}).get("dns") or {"status": "failed", "why": "timeout"}
        out["dns"] = dn["status"] if dn["status"] in ("ok", "nxdomain") else "failed:" + str(dn.get("why"))
    return out


def run_all(items, text_model, url_model, harness, base, today, log):
    """items x SETTINGS -> {setting: {item_id: record}}"""
    capture = {}
    orig_run = live_checks.run
    def run_wrapped(urls, lists, expand_urls=(), deadline_s=live_checks.MESSAGE_DEADLINE):
        out = orig_run(urls, lists, expand_urls=expand_urls, deadline_s=EVAL_DEADLINE)
        capture.update(out)
        return out
    live_checks.run = run_wrapped
    results = {}
    real_assess = router.assess_background
    try:
        for sid, title, opts, mode, variant in [(*x, "a") for x in SETTINGS] + EXTRA_SETTINGS:
            lists_view = view(base, **opts)
            router.load_lists = lambda lv=lists_view: lv
            router.assess_background = variant_hook(real_assess, variant)
            harness.mode = mode
            results[sid] = {}
            t0 = time.time()
            for i, it in enumerate(items):
                live_checks.CACHE.clear()
                capture.clear()
                res = router.analyse(it["text"], text_model, url_model, live=True)
                rep = to_report(it["text"], res)
                lv = capture.get(res["links"][0]["url"]) if res["links"] else None
                rec = signals_of(it, res, lv, base, today)
                rec["verdict"] = LABEL.get(rep.level, str(rep.level.value))
                rec["risk_score"] = rep.risk_score
                results[sid][it["id"]] = rec
                if (i + 1) % 25 == 0:
                    log(f"  [{sid}] {i + 1}/{len(items)} items, {time.time() - t0:.0f}s")
            log(f"[{sid}] {title}: {len(items)} items in {time.time() - t0:.0f}s")
    finally:
        live_checks.run = orig_run
        router.load_lists = load_lists
        router.assess_background = real_assess
    return results


# ------------------------------------------------------------------------------------------------ report
def counts(recs):
    c = collections.Counter(r["verdict"] for r in recs)
    return [c.get(v, 0) for v in VERDICTS]

def flagged(recs):
    return sum(r["verdict"] in ("Likely scam", "Suspicious") for r in recs)

def call_stats(harness, today):
    """Per logical call timings from the cache: first attempt (what the app does) and the final outcome after retries."""
    by = collections.defaultdict(list)
    for e in harness.cache.values():
        by[e["service"]].append(e)
    rows = []
    for svc in ("rdap", "doh", "crtsh"):
        es = by.get(svc, [])
        if not es:
            continue
        ok = OK_STATUS[svc]
        def good(a):
            return a["err"] is None and a["status"] in ok
        first_bad = [e for e in es if not good(e["attempts"][0])]
        final_bad = [e for e in es if not good(e["attempts"][-1])]
        why = collections.Counter((e["attempts"][0]["err"] or f"http_{e['attempts'][0]['status']}") for e in first_bad)
        ms = [e["attempts"][0]["ms"] for e in es]
        rows.append([svc, len(es), len(first_bad), pct(len(first_bad), len(es)), len(first_bad) - len(final_bad), len(final_bad), pct(len(final_bad), len(es)),
                     ", ".join(f"{k} {v}" for k, v in why.most_common()) or "-", f"{np.median(ms):.0f}", f"{np.percentile(ms, 95):.0f}"])
    return rows

def link_latency(harness, regs):
    """App-equivalent latency per link: its checks run in parallel (registration = RDAP, then crt.sh only if RDAP had no date; DNS), one try each."""
    ent = collections.defaultdict(dict)
    for e in harness.cache.values():
        ent[e["reg"]][e["service"]] = e["attempts"][0]["ms"]
    out = []
    for reg in regs:
        d = ent.get(reg)
        if d:
            out.append(max(d.get("rdap", 0) + d.get("crtsh", 0), d.get("doh", 0)))
    return out

def build_report(args, ctx):
    items, R, harness, info, guard, base = ctx["items"], ctx["results"], ctx["harness"], ctx["info"], ctx["guard"], ctx["base"]
    S = dict(R)
    sets = collections.defaultdict(list)
    for it in items:
        sets[it["set"]].append(it)
    phish, b10, b100 = sets["phish"], sets["benign_top10k"], sets["benign_100k_1m"]
    benign = b10 + b100
    reg_items = sets["regression_domain"] + sets["regression_message"]
    def recs(sid, its):
        return [S[sid][i["id"]] for i in its]
    own = [i for i in phish if i["kind"] == "own_domain"]
    plat = [i for i in phish if i["kind"] != "own_domain"]
    h = "honest"
    ph, bh = recs(h, phish), recs(h, benign)
    L = []
    w = L.append

    # ---- 3-line summary
    nflag, nlikely = flagged(ph), sum(r["verdict"] == "Likely scam" for r in ph)
    nws = sum(r["verdict"] == "No warning signs" for r in ph)
    ncj = sum(r["verdict"] == "Can't judge" for r in ph)
    fa10, fa100 = flagged(recs(h, b10)), flagged(recs(h, b100))
    gam = lambda sid: [S[sid][i["id"]]["verdict"] for i in sets["regression_domain"] if i["group"] == "gambling_unlisted"]
    gu_all, gu_h = gam("all_on"), gam("honest")
    w("# Live link checks on a fresh OpenPhish sample\n")
    w(f"*Eval date {args.date}. Generated by `scripts/eval_live_links.py`. **Edition 2 (2026-10-23, decision C1):** the same sample and the same cached replies were re-scored "
      f"offline after the platform lists, the gambling additions and the crt.sh switch changed; edition 1 (commit {BEFORE_COMMIT}) is the \"before\" of section 9. "
      f"Sample and cached replies: `data/eval_live/`. Re-run: `.venv/bin/python scripts/eval_live_links.py --date {args.date} --offline`.*\n")
    w(f"> **Read this first.** The \"after\" numbers were tuned on this same 96 + 200 + 22 link sample, so they are optimistic and must be confirmed on a fresh pull "
      f"(a separate task). The URL-model variants of section 10 are also scored on it.\n")
    w("## Summary\n")
    w(f"1. **Phishing, honest setting** (OpenPhish, URLhaus and Tranco switched off): of {len(phish)} fresh OpenPhish links (one per registered domain; the feed held "
      f"only {info['phish']['unique_regs']} such domains, not 200) the app flagged {nflag} ({pct(nflag, len(phish), True)}), {nlikely} of them as Likely scam; "
      f"{nws} were rated \"No warning signs\" and {ncj} \"Can't judge\" (free hosting / shorteners). With all signals ON it flags {pct(flagged(recs('all_on', phish)), len(phish))}, "
      f"which is mostly the app finding its own source list.")
    w(f"2. **Benign, honest setting:** {pct(fa10, len(b10), True)} of {len(b10)} Tranco top-10k domains and {pct(fa100, len(b100), True)} of {len(b100)} domains ranked 100k-1M "
      f"were flagged Suspicious or Likely scam (95% intervals in brackets). The top-10k figure is what you get when Tranco is off; with Tranco on it is "
      f"{pct(flagged(recs('all_on', b10)), len(b10))}, which is circular because the benign domains came from Tranco.")
    w(f"3. **Known gambling miss:** the original spam-ad link was never recorded, so it cannot be replayed. For the {len(gu_all)} gambling sites BUGS.md says the lookup misses "
      f"(all Tranco top 10k), {sum(v == 'No warning signs' for v in gu_all)} are rated \"No warning signs\" with Tranco ON and {sum(v == 'No warning signs' for v in gu_h)} with it OFF: "
      f"{'the miss is still there' if sum(v == 'No warning signs' for v in gu_all) else 'no longer rated safe'} (section f).\n")

    # ---- sample
    w("## 1. What was measured\n")
    w(f"**Function judged:** `shield.core.router.analyse(text, text_model, url_model, live=True)` followed by `shield.core.report.to_report(text, r)`, "
      f"exactly what `POST /api/analyse` runs (`src/shield/api/main.py`). Text head: `{type(ctx['text_model']).__name__}`. "
      f"Each sampled link is the whole message, so the text head is skipped and the verdict is the link verdict. "
      f"The verdict is `Report.level`; \"flagged\" = Likely scam or Suspicious.\n")
    p = info["phish"]
    w(f"**Phishing set ({len(phish)} links).** OpenPhish public feed, downloaded {p['downloaded_utc']} (SHA-256 `{p['feed_sha256'][:16]}…`), {p['feed_rows']} URLs, "
      f"{p['unique_regs']} unique registered domains (`tldextract.top_domain_under_public_suffix`, which is the same value as the app's `link_domain` for all {len(phish)} links"
      f"{'' if p['reg_mismatch'] == 0 else ' except ' + str(p['reg_mismatch'])}). **The target was 200; the feed cannot give more** because "
      f"{p['urls_per_kind'].get('free_hosting', 0) + p['urls_per_kind'].get('user_content', 0)} of its {p['feed_rows']} URLs are pages on free-hosting / user-content platforms "
      f"(pages.dev alone is one registered domain). All {p['unique_regs']} were taken. By kind of host: "
      + ", ".join(f"{k} {v}" for k, v in sorted(collections.Counter(i['kind'] for i in phish).items())) + ". "
      f"**Only {len(own)} are ordinary domains** with registry and DNS facts; for the {len(plat)} platform-hosted or shortened links the app looks up neither (the registration of "
      f"pages.dev says nothing about the page), so domain age, certificate age and DNS cannot fire on them by design.\n")
    w("**Benign set (200 domains).** Tranco list on disk (" + base.manifest["tranco"]["downloaded_utc"][:10] + "), 100 random domains from ranks 1-10,000 and 100 from 100,000-1,000,000, "
      "one `hxxps://<domain>/` each, none also in another set. Skipped before sampling: " + "; ".join(
          f"{band}: " + ", ".join(f"{v:,} {k}" for k, v in x["skipped"].items()) for band, x in info["benign"].items()) + ". "
      "Tranco is not a list of verified-good sites (the 100k-1M band contains some hosting, adult, gambling and a few abusive sites), so a few \"false alarms\" there can be correct.\n")
    w(f"**Regression group ({len(sets['regression_domain'])} domains + {len(sets['regression_message'])} messages).** Described in section f.\n")
    w("**Not measured / not on:** Google Safe Browsing (no `SAFE_BROWSING_KEY`, so the app skips it), shortener expansion (never run), the sender rule. "
      "The URLhaus list is the 30-day export. Samples are only strings: no link was fetched, resolved or connected to (section 8).\n")
    w(f"**crt.sh certificate-age check (R8):** {'ON (--crtsh)' if config.CRTSH_CHECK else 'OFF, the new default (decision C1)'} in this run. The cached replies of edition 1 still hold the 68 crt.sh requests "
      "(section 8 describes them); with the check off the app sends none, so the certificate rows of section 2 are empty and R8 cannot fire.\n")
    w("**Lifted limits (so the throttle does not fake failures):** the 4 s message deadline of `live.run` is 60 s here; per-call timeout stays 2 s (`net.CALL_TIMEOUT`). "
      "RDAP / crt.sh failures were retried twice; the \"first attempt only\" row below uses the first try of every call, which is what the app does.\n")

    # ---- (a) per-signal
    w("## 2. (a) Each signal: how often it fired and how often it was unavailable\n")
    w("All-signals-ON run. *Applicable* = the app runs this check on the link (not for free-hosting, user-content, shortener or raw-IP links). *Fired* = the check "
      "raised its red flag (age < 30 d; first certificate < 7 d; server shared with a listed IP; on the list) or, for Tranco, the domain is in the top 10k. "
      "*Unavailable* = applicable but no usable answer after retries (details below the table).\n")
    def sig_rows(its):
        rr = [S["all_on"][i["id"]] for i in its]
        n = len(rr)
        app_reg = [r for r in rr if "registration" in r["checks"]]
        age_ok = [r for r in app_reg if r["rdap"] == "date"]
        crt_run = [r for r in app_reg if r["crt"] not in ("n/a", "not needed")]
        crt_ok = [r for r in crt_run if r["crt"].startswith("first_cert") or r["crt"] == "none"]
        rows = [["Domain age (RDAP, R7 < 30 d)", len(app_reg), sum("R7" in r["flags"] for r in app_reg), len(app_reg) - len(age_ok)],
                ["Certificate age (crt.sh, R8 < 7 d; only when RDAP gives no date)", len(crt_run), sum("R8" in r["flags"] for r in crt_run), len(crt_run) - len(crt_ok)],
                ["DNS (R6 shared listed server)", len(app_reg), sum("R6" in r["flags"] for r in app_reg), sum(r["dns"].startswith("failed") for r in app_reg)],
                ["Tranco (top 10k = well-known; top 1M = any rank)", n, sum((i["rank"] or 10**9) <= 10_000 for i in its), 0],
                ["OpenPhish (R1)", n, sum("OpenPhish" in r["lists"] for r in rr), 0],
                ["URLhaus (R1)", n, sum("URLhaus" in r["lists"] for r in rr), 0]]
        return [[a, b, f"{c} ({pct(c, b)})" if b else "0", f"{d} ({pct(d, b)})" if b else "0"] for a, b, c, d in rows], n
    for name, its in (("Phishing, ordinary domains", own), ("Phishing, platform-hosted / shortened", plat), ("Benign, Tranco top 10k", b10), ("Benign, Tranco 100k-1M", b100)):
        rows, n = sig_rows(its)
        w(f"**{name} (n = {n})**\n")
        w(md_table(["Signal", "Applicable", "Fired", "Unavailable"], rows) + "\n")
    # rdap detail
    def rdap_detail(its):
        c = collections.Counter(S["all_on"][i["id"]]["rdap"] for i in its if "registration" in S["all_on"][i["id"]]["checks"])
        return ", ".join(f"{k} {v}" for k, v in c.most_common()) or "-"
    w("RDAP outcomes (ordinary domains only): phishing: " + rdap_detail(own) + "; benign top 10k: " + rdap_detail(b10) + "; benign 100k-1M: " + rdap_detail(b100) + ". "
      "`unsupported` = the TLD has no public RDAP service in IANA's bootstrap file; `no_date` = the registry answered without a registration event; `not_found` = the registry has no such name.\n")
    nx = lambda its: sum(S["all_on"][i["id"]]["dns"] == "nxdomain" for i in its)
    w(f"DNS names that no longer resolve (NXDOMAIN): phishing {nx(own)} of {len(own)} ordinary domains, benign top 10k {nx(b10)}, benign 100k-1M {nx(b100)}.\n")
    other = lambda its, code: sum(code in S["all_on"][i["id"]]["flags"] for i in its)
    w("Other offline signals that fired (all-ON): " + "; ".join(
        f"{n}: phishing {other(phish, c)}/{len(phish)}, benign {other(benign, c)}/{len(benign)}" for c, n in
        (("R3", "homograph R3"), ("R4", "brand lookalike R4"), ("R5", "raw IP R5"), ("R9", "two or more red flags R9"))) + ". "
      f"URL model (host-only head) rated Suspicious or higher before the link checks: phishing {sum((S['all_on'][i['id']]['url_score'] or 0) >= 0.5 for i in phish)} of {len(phish)} at score >= 0.5 "
      f"(for orientation only; the app's cut-offs are in `models/url_head.joblib`).\n")

    # ---- (b) verdict tables
    w("## 3. (b) Final verdicts, three signal settings\n")
    w("Rows add up to the set size (checked by the script: it stops if they do not). These tables are edition 2 (current code).\n")
    for name, its in (("Phishing (all)", phish), ("Phishing, ordinary domains", own), ("Phishing, platform-hosted / shortened", plat),
                      ("Benign (all 200)", benign), ("Benign, Tranco top 10k", b10), ("Benign, Tranco 100k-1M", b100)):
        w(f"**{name}** (n = {len(its)})\n")
        rows = []
        for sid, title, _, _ in SETTINGS:
            c = counts(recs(sid, its))
            assert sum(c) == len(its), (name, sid, c)
            rows.append([title] + c + [sum(c)])
        w(md_table(["Setting", *VERDICTS, "Total"], rows) + "\n")

    # ---- (c)
    w("## 4. (c) Recall and false-alarm rate by Tranco band\n")
    w("Recall = share of phishing links flagged (Suspicious or Likely scam); \"Likely only\" counts Likely scam alone. False-alarm rate = share of benign domains flagged. "
      "Can't judge is neither (it counts against recall, not against the false-alarm rate). 95% Wilson interval in brackets. The phishing bands are the Tranco rank of the link's registered domain "
      "(\"not in top 1M\" is most of them: platform roots such as pages.dev are in the list, ordinary scam domains are not).\n")
    for sid in ("honest", "all_on"):
        title = dict((a, b) for a, b, *_ in SETTINGS)[sid]
        w(f"**{title}**\n")
        rows = []
        for lbl, its, role in (("Phishing, all", phish, "r"), *[(f"Phishing, {b}", [i for i in phish if band_of(i['rank']) == b], "r") for b in [x[0] for x in BANDS] + ["not in top 1M"]],
                               ("Phishing, ordinary domains only", own, "r"), ("Benign, all", benign, "f"), ("Benign, Tranco top 10k", b10, "f"), ("Benign, Tranco 100k-1M", b100, "f")):
            if not its:
                continue
            rr = recs(sid, its)
            n, f_, lk = len(rr), flagged(rr), sum(r["verdict"] == "Likely scam" for r in rr)
            gam_n = sum(1 for r in rr if r["gambling"]) if role == "f" else 0
            rows.append([lbl, n, f"{f_} ({pct(f_, n, True)})", f"{lk} ({pct(lk, n)})", sum(r['verdict'] == 'No warning signs' for r in rr), sum(r['verdict'] == "Can't judge" for r in rr),
                         "recall" if role == "r" else f"false alarm; {gam_n} of the flags are gambling-list hits"])
        w(md_table(["Group", "n", "Flagged", "Likely only", "No warning signs", "Can't judge", "Meaning"], rows) + "\n")
    bf_ = [r for r in recs(h, benign) if r["verdict"] in ("Likely scam", "Suspicious")]
    w(f"What drives the {len(bf_)} benign false alarms in the honest setting: gambling lookup {sum(bool(r['gambling']) for r in bf_)}; a link-check red flag "
      f"{sum(bool(r['flags']) and not r['gambling'] for r in bf_)}; the host-only URL model alone (no red flag, no gambling hit) {sum(not r['flags'] and not r['gambling'] for r in bf_)}.\n")

    # ---- (d)
    w("## 5. (d) Domain age of the phishing domains\n")
    ages = sorted(S["all_on"][i["id"]]["age_days"] for i in own if S["all_on"][i["id"]]["age_days"] is not None)
    bages = sorted(S["all_on"][i["id"]]["age_days"] for i in benign if S["all_on"][i["id"]]["age_days"] is not None)
    def dist(a):
        return ["n/a"] * 5 if not a else [len(a), f"{np.median(a):.0f}", pct(sum(x < 7 for x in a), len(a)), pct(sum(x < 30 for x in a), len(a)), pct(sum(x < 365 for x in a), len(a))]
    w(md_table(["Group", "Age known (n)", "Median age (days)", "< 7 days", "< 30 days", "< 365 days"],
               [["Phishing, ordinary domains"] + dist(ages), ["Benign (both bands)"] + dist(bages),
                ["Benign, top 10k"] + dist(sorted(S["all_on"][i["id"]]["age_days"] for i in b10 if S["all_on"][i["id"]]["age_days"] is not None)),
                ["Benign, 100k-1M"] + dist(sorted(S["all_on"][i["id"]]["age_days"] for i in b100 if S["all_on"][i["id"]]["age_days"] is not None))]) + "\n")
    w(f"Of {len(own)} ordinary phishing domains, the registration date was available for {len(ages)}; {len(own) - len(ages)} had none (see RDAP outcomes above). "
      f"The {len(plat)} platform-hosted links have no age by design. Ages are the registry's creation date measured to {args.date}; a compromised old site looks old, which is the honest weakness of the signal.\n")

    # ---- (e) misses
    w("## 6. (e) Phishing links still rated \"No warning signs\" in the honest setting\n")
    miss = [i for i in phish if S[h][i["id"]]["verdict"] == "No warning signs"]
    miss.sort(key=lambda i: (S[h][i["id"]]["url_score"] if S[h][i["id"]]["url_score"] is not None else 1.0))
    ctx["misses"] = miss
    def missing(i):
        r = S[h][i["id"]]
        parts = []
        if "registration" not in r["checks"]:
            parts.append(f"no registry/DNS look-up for a {i['kind'].replace('_', ' ')} link")
        else:
            parts.append("age " + (f"{r['age_days']} d (>= 30, no flag)" if r["age_days"] is not None else f"unavailable ({r['rdap']})"))
            if r["crt"] not in ("n/a", "not needed"):
                parts.append(f"first cert {r['crt'].removeprefix('first_cert_').removesuffix('d')} d" if r["crt"].startswith("first_cert") else f"cert {r['crt']}" if not r["crt"].startswith("failed") else f"cert unavailable ({r['crt']})")
            parts.append("DNS " + ("no address (site down)" if r["dns"] == "nxdomain" else "ok" if r["dns"] == "ok" else f"unavailable ({r['dns']})"))
        parts.append("OpenPhish/URLhaus/Tranco off")
        return "; ".join(parts)
    if miss:
        w(f"{len(miss)} of {len(phish)} (sorted by the URL model's score, lowest first). \"Signals missing\" says what the link checks could not or did not provide.\n")
        w(md_table(["#", "Link (defanged)", "Kind", "URL-model score", "Signals missing / what the checks saw"],
                   [[k + 1, f"`{defang(i['url'])[:110]}`", i["kind"], "-" if S[h][i["id"]]["url_score"] is None else f"{S[h][i['id']]['url_score']:.3f}", missing(i)] for k, i in enumerate(miss)]) + "\n")
    else:
        w("None.\n")
    cj = [i for i in phish if S[h][i["id"]]["verdict"] == "Can't judge"]
    w(f"Also not flagged: {len(cj)} phishing links rated \"Can't judge\" ({', '.join(f'{k} {v}' for k, v in collections.Counter(i['kind'] for i in cj).most_common())}); "
      f"the app says it cannot judge these by domain, so they are misses for a user who reads \"Can't judge\" as \"fine\".\n")

    # ---- (f) regression
    w("## 7. (f) Regression group: gambling / spam-ad links\n")
    w("**The reported link is not available.** BUGS.md says the exact message \"was never supplied\", so \"a spam-ad link that led to a gambling site was rated safe\" cannot be replayed. "
      "If you have the link or message, add it to `UNLISTED` / `MESSAGES` in the script and rerun. What is tested instead, from what the repo documents: "
      "`unlisted` = gambling sites BUGS.md names as missing from the gambling lookup; `unconfirmed` = the 4 gambling-looking domains still `pending_review`; "
      "`control` = domains the lookup lists (G1 must say Suspicious); `message` = spam-ad text with a gambling link in the three forms the problem could take. "
      "A short link's destination is never fetched, so a spam ad behind a short link can only be \"Can't judge\" here.\n")
    rows = []
    for it in sets["regression_domain"]:
        a, hh = S["all_on"][it["id"]], S[h][it["id"]]
        rows.append([f"`{defang(it['url'])}`", it["group"], it["rank"] or "-", a["gambling"] or "no", a["verdict"], ", ".join(a["flags"]) or "-", a["positive"] or "-", hh["verdict"], ", ".join(hh["flags"]) or "-"])
    w(md_table(["Domain (defanged)", "Group", "Tranco rank", "Gambling lookup", "Verdict, all ON", "Flags", "Positive (P2)", "Verdict, honest", "Flags (honest)"], rows) + "\n")
    rows = []
    for it in sets["regression_message"]:
        a, hh = S["all_on"][it["id"]], S[h][it["id"]]
        rows.append([it["id"], it["note"], f"`{defang_text(it['text'])[:150]}`", it["expected"], a["gambling"] or "no", a["verdict"], hh["verdict"], ", ".join(hh["flags"]) or "-"])
    w(md_table(["Case", "What", "Message (defanged)", "Expected", "Gambling lookup", "Verdict, all ON", "Verdict, honest", "Flags (honest)"], rows) + "\n")
    un = sets["regression_domain"]
    ug = [i for i in un if i["group"] == "gambling_unlisted"]
    cg = [i for i in un if i["group"] == "gambling_control"]
    uc = [i for i in un if i["group"] == "gambling_unconfirmed"]
    nws_ = lambda sid, its: sum(S[sid][i["id"]]["verdict"] == "No warning signs" for i in its)
    w(f"**Result.** Unlisted gambling sites rated \"No warning signs\": {nws_('all_on', ug)} of {len(ug)} with all signals ON, {nws_(h, ug)} of {len(ug)} in the honest setting. "
      f"Unconfirmed: {nws_('all_on', uc)} of {len(uc)} / {nws_(h, uc)} of {len(uc)}. Controls flagged: {flagged(recs('all_on', cg))} of {len(cg)} (all ON), {flagged(recs(h, cg))} of {len(cg)} (honest). "
      f"Reading it: P2 (\"a well-known website\") is on every unlisted top-10k site in the all-ON run, but switching Tranco off still leaves {nws_(h, ug)} of {len(ug)} at \"No warning signs\", "
      "so P2 is not the cause: nothing in the URL model or the link checks knows these sites are gambling sites; only the gambling lookup does. "
      "In the message cases the verdict comes from the text head reading the ad wording, not from the link.\n")

    # ---- (g) latency / failures
    w("## 8. (g) Latency and service failures\n")
    regs_all = [i["reg"] for i in items]
    lat = link_latency(harness, [r for r in dict.fromkeys(regs_all)])
    latp = link_latency(harness, [i["reg"] for i in phish if i["kind"] == "own_domain"])
    latb = link_latency(harness, [i["reg"] for i in benign])
    def lrow(name, a):
        return [name, len(a), f"{np.median(a):.0f}", f"{np.percentile(a, 95):.0f}", sum(x > 4000 for x in a)] if a else [name, 0, "-", "-", "-"]
    w("Latency per link as the app would see it: RDAP (then crt.sh only if RDAP gave no date) and DNS run in parallel, one try each, 2 s per call; taken from the first attempt of each call in the cache "
      "(the throttle waits are not counted). Platform-hosted and shortened links make no network call.\n")
    w(md_table(["Links", "With network calls", "Median ms", "p95 ms", "Over the 4 s message deadline"], [lrow("All with calls", lat), lrow("Phishing (ordinary domains)", latp), lrow("Benign", latb)]) + "\n")
    w("Service failures (one row per distinct request; \"first try\" is what the app experiences, \"after 2 retries\" is what the tables above use for RDAP and crt.sh; DNS is not retried):\n")
    w(md_table(["Service", "Requests", "Failed, first try", "%", "Recovered by retry", "Failed after retries", "%", "First-try failure reasons", "Median ms", "p95 ms"], call_stats(harness, args.date)) + "\n")

    # ---- before / after, variants
    for line in before_after(args, ctx, S, phish, b10, b100, benign, sets, h):
        w(line)
    for line in variants_section(S, phish, own, b10, b100, benign):
        w(line)

    # ---- checks
    w("## 11. Checks\n")
    cached_hosts = collections.Counter(e["host"] for e in harness.cache.values())
    attempts = collections.Counter()
    for e in harness.cache.values():
        attempts[e["host"]] += len(e["attempts"])
    hosts = sorted(cached_hosts)
    w("**`net.py` call log grouped by host.** Every call went through `shield.core.net.request` (the script wraps it; the allowlist, https-only, no-redirect and 2 s rules are net.py's). "
      "Read from the reply cache, so it is the same on an offline rerun: \"Requests\" = distinct requests, \"Network attempts\" = requests actually sent, retries included.\n")
    w(md_table(["Host", "Service", "Requests", "Network attempts"], [[f"`{x}`", harness.service_of(x), cached_hosts[x], attempts[x]] for x in hosts]
               + [["**Total**", "", sum(cached_hosts.values()), sum(attempts.values())]]) + "\n")
    run_calls = collections.Counter((e["host"], e["fresh"]) for e in harness.log)
    w(f"**This run ({'offline' if args.offline else 'online'}).** Calls the analysis made through `net.request` (every setting and variant, {len(harness.log):,} logical calls), by host and by whether the reply came from the cache "
      f"or was sent. Cache misses: {harness.misses}. A guard on `socket.getaddrinfo`, `socket.connect` and `socket.create_connection` "
      + ("refused every name and connection in this process: names asked " + str(sum(ctx['guard'].names.values())) + ", connect attempts " + str(ctx['guard'].connects) + ".\n" if args.offline else "refused only the sampled hosts.\n"))
    w(md_table(["Host", "Answered from the cache", "Sent to the network"], [[f"`{x}`", run_calls.get((x, False), 0), run_calls.get((x, True), 0)] for x in sorted({k[0] for k in run_calls})]
               + [["**Total**", sum(v for (x, f), v in run_calls.items() if not f), sum(v for (x, f), v in run_calls.items() if f)]]) + "\n")
    sampled_hosts = {link_domain(i["url"])[0] for i in items} | {i["reg"] for i in items}
    hit = sorted(set(hosts) & sampled_hosts)
    w(f"Hosts contacted that are also a sampled link's host or registered domain: **{len(hit)}** {hit or ''}. Only the registered domain was sent, to a registry (RDAP), Cloudflare DoH or crt.sh; the IP in a DNS answer was never connected to.\n")
    names = ctx["resolved"]
    w(f"Names the process resolved while evaluating, from a `socket.getaddrinfo` guard that logs every name and refuses the {len(sampled_hosts)} sampled hosts "
      f"({sum(names.values())} lookups, summed over the runs that filled the cache): " + ", ".join(f"`{k}` {v}" for k, v in sorted(names.items())) +
      f". Sampled hosts among them: **{sum(1 for k in names if k in sampled_hosts)}**.\n")
    w("Lists were refreshed before the run with `src/update_link_lists.py --only openphish urlhaus` (a separate process, so not in the log above: hosts `openphish.com` -> its GitHub mirror `raw.githubusercontent.com`, and `urlhaus-api.abuse.ch`, per `net.UPDATE_HOSTS`).\n")
    w(f"Lists as read by the app: " + "; ".join(f"{n} {base.manifest[n]['downloaded_utc'][:16]}Z ({base.manifest[n]['rows']:,} rows)" for n in ("openphish", "urlhaus", "tranco") if n in base.manifest) + ".\n")
    w("Files hold only defanged URLs (`hxxp`, `[.]`): " + ", ".join(f"`{p}`" for p in ctx["written"]) + ".\n")
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------------------------------------ before / after, variants
def load_before(date):
    """{setting: {id: row}} from the results CSV committed in BEFORE_COMMIT (edition 1)."""
    txt = subprocess.run(["git", "show", f"{BEFORE_COMMIT}:data/eval_live/results_{date}.csv"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    df = pd.read_csv(io.StringIO(txt), keep_default_na=False)
    out = collections.defaultdict(dict)
    for r in df.to_dict("records"):
        out[r["setting"]][r["id"]] = r
    return out

def fa_cell(k, n):
    return f"{k} ({pct(k, n, True)})"

def before_after(args, ctx, S, phish, b10, b100, benign, sets, h):
    items, base = ctx["items"], ctx["base"]
    B = load_before(args.date)
    L = []
    w = L.append
    ids_ok = {i["id"] for i in items}
    assert ids_ok == set(B[h]), "the before CSV and this sample differ"
    bv = lambda sid, its: [B[sid][i["id"]]["verdict"] for i in its]
    av = lambda sid, its: [S[sid][i["id"]]["verdict"] for i in its]
    cnt = lambda vs: [vs.count(v) for v in VERDICTS]
    flag = lambda vs: sum(v in ("Likely scam", "Suspicious") for v in vs)
    lk = lambda vs: sum(v == "Likely scam" for v in vs)
    ug = [i for i in sets["regression_domain"] if i["group"] == "gambling_unlisted"]
    own = [i for i in phish if i["kind"] == "own_domain"]
    w("## 9. Before vs after (decision C1)\n")
    w(f"*Before* = edition 1, read from `data/eval_live/results_{args.date}.csv` as committed in `{BEFORE_COMMIT}` (replies from the same cache). *After* = this run. Same links, same cached "
      "replies, same honest setting (OpenPhish, URLhaus and Tranco off, variant (a) = the app's rule). What changed in the code: the platform lists (short links, dynamic DNS, site builders: "
      "`platforms.py`), the 8 gambling additions (`gambling.py`), the crt.sh check off by default. **The \"after\" numbers were tuned on this same sample and must be confirmed on a fresh pull "
      "(a separate task); they are an upper bound on what the changes will do on new links.** The sample's `kind` column (own domain / free hosting) is the one saved at sampling time, so the groups "
      "do not move between before and after.\n")
    w("**Honest-setting verdicts, before and after**\n")
    rows = []
    for name, its in (("Phishing (n = 96)", phish), ("Benign, Tranco top 10k (n = 100)", b10), ("Benign, Tranco 100k-1M (n = 100)", b100), (f"Unlisted gambling sites (n = {len(ug)})", ug)):
        for tag, vs in (("before", bv(h, its)), ("after", av(h, its))):
            rows.append([name if tag == "before" else "", tag, *cnt(vs), len(vs)])
    w(md_table(["Group", "", *VERDICTS, "Total"], rows) + "\n")
    w("**Recall and false alarms by Tranco band, honest setting** (flagged = Suspicious or Likely scam; 95% Wilson interval; Can't judge is neither)\n")
    rows = []
    groups = [("Phishing, all", phish, "recall")] + [(f"Phishing, {b}", [i for i in phish if band_of(i['rank']) == b], "recall") for b in [x[0] for x in BANDS] + ["not in top 1M"]]
    groups += [("Phishing, ordinary domains (sample-time kind)", own, "recall"), ("Benign, all", benign, "false alarm"), ("Benign, Tranco top 10k", b10, "false alarm"), ("Benign, Tranco 100k-1M", b100, "false alarm")]
    for name, its, role in groups:
        if not its:
            continue
        b_, a_ = bv(h, its), av(h, its)
        rows.append([name, len(its), role, fa_cell(flag(b_), len(its)), fa_cell(flag(a_), len(its)), f"{lk(b_)} -> {lk(a_)}", f"{b_.count('No warning signs')} -> {a_.count('No warning signs')}",
                     f"{b_.count(CJ)} -> {a_.count(CJ)}"])
    w(md_table(["Group", "n", "Meaning", "Flagged before", "Flagged after", "Likely only (before -> after)", "No warning signs (before -> after)", "Can't judge (before -> after)"], rows) + "\n")

    # the misses
    miss = [i for i in phish if B[h][i["id"]]["verdict"] == "No warning signs"]
    miss.sort(key=lambda i: (S[h][i["id"]]["url_score"] if S[h][i["id"]]["url_score"] is not None else 1.0))
    w(f"**The {len(miss)} phishing links rated \"No warning signs\" before** (the list of section 6 in edition 1), and what the app says now:\n")
    rows = []
    for k, i in enumerate(miss):
        r = S[h][i["id"]]
        now_kind = kind_of(link_domain(i["url"])[0])
        rows.append([k + 1, f"`{defang(i['url'])[:90]}`", i["kind"] + (" -> " + now_kind if now_kind != i["kind"] else ""), B[h][i["id"]]["verdict"], r["verdict"],
                     ", ".join(r["flags"]) or "-"])
    w(md_table(["#", "Link (defanged)", "Kind (sample -> now)", "Before", "After", "Flags after"], rows) + "\n")
    after = [S[h][i["id"]]["verdict"] for i in miss]
    n_flag, n_cj, n_ws = flag(after), after.count(CJ), after.count("No warning signs")
    ctx["miss_after"] = (len(miss), n_flag, n_cj, n_ws)
    w(f"Of the {len(miss)}: **{n_flag} are now flagged** (Suspicious or Likely scam), **{n_cj} are now \"Can't judge\"** (the short-link, dynamic-DNS and site-builder lists: the app says it cannot judge the "
      f"link by its domain, which is honest but is not a catch), **{n_ws} are still \"No warning signs\"** (ordinary old domains with no signal: a compromised or purpose-bought site that the "
      "checks cannot tell from a normal one).\n")

    # ledger
    trans = collections.defaultdict(list)
    for i in items:
        b_, a_ = B[h][i["id"]]["verdict"], S[h][i["id"]]["verdict"]
        if b_ != a_:
            trans[(b_, a_, i["set"])].append(i["id"])
    w(f"**Every verdict that changed in the honest setting** (all {len(items)} items; unchanged items are not listed). Each change has one of three causes: platform list, gambling addition, "
      "or (not expected) something else.\n")
    rows = []
    for (b_, a_, st), ids in sorted(trans.items(), key=lambda kv: -len(kv[1])):
        causes = collections.Counter()
        for x in ids:
            it = next(i for i in items if i["id"] == x)
            g = S[h][x]["gambling"]
            causes["gambling addition" if g and not B[h][x]["gambling"] else "platform list" if kind_of(link_domain(it["url"])[0]) != it["kind"] else "other"] += 1
        rows.append([f"{b_} -> {a_}", st, len(ids), ", ".join(f"{k} {v}" for k, v in causes.most_common())])
    w(md_table(["Change", "Set", "Items", "Cause"], rows or [["none", "", 0, ""]]) + "\n")
    ctx["changes_other"] = sum(int(c.split()[-1]) for r in rows for c in r[3].split(", ") if c.startswith("other"))
    ao = [S["all_on"][i["id"]]["verdict"] for i in benign]
    w(f"All-signals-ON run, benign (n = {len(benign)}): flagged {flag(bv('all_on', benign))} before, {flag(ao)} after.\n")
    return L

def variants_section(S, phish, own, b10, b100, benign):
    L = []
    w = L.append
    w("## 10. URL-model rule variants (honest setting)\n")
    w("The host-only URL model is the only thing that fired on 27 of the 29 benign false alarms of edition 1. Three rules for it are scored on the same links with the same cached replies "
      "(OpenPhish, URLhaus and Tranco off, current lists). **The app still uses (a); nothing changes until the choice is made.** Applied by wrapping `router.assess_background` in this script: "
      "a link the URL model scored and whose link checks raised no red flag is re-levelled. (b) caps its level at Suspicious; (c) sets it to nothing. With a red flag (R1-R9) the original level "
      "is kept, so a flag plus a high model score can still reach Likely scam. A gambling-list hit keeps its Suspicious floor in all three. Free-hosting and short links are not scored by the URL model, so no variant touches them.\n")
    rows = []
    for name, sid in VARIANT_ROWS:
        ph, p_own = [S[sid][i["id"]]["verdict"] for i in phish], [S[sid][i["id"]]["verdict"] for i in own]
        f10, f100, fall = [S[sid][i["id"]]["verdict"] for i in b10], [S[sid][i["id"]]["verdict"] for i in b100], [S[sid][i["id"]]["verdict"] for i in benign]
        fl = lambda vs: sum(v in ("Likely scam", "Suspicious") for v in vs)
        lk = lambda vs: sum(v == "Likely scam" for v in vs)
        rows.append([name, fa_cell(fl(ph), len(ph)), lk(ph), fa_cell(fl(p_own), len(p_own)), fa_cell(fl(f10), len(f10)), lk(f10), fa_cell(fl(f100), len(f100)), lk(f100), fa_cell(fl(fall), len(fall)), lk(fall)])
    w(md_table(["Variant", "Phishing recall, all (96)", "Likely only", "Recall, ordinary domains (83)", "False alarms, top 10k (100)", "Likely only", "False alarms, 100k-1M (100)", "Likely only",
                "False alarms, all benign (200)", "Likely only"], rows) + "\n")
    a = {i["id"]: S["honest"][i["id"]]["verdict"] for i in phish}
    c = {i["id"]: S["honest_c"][i["id"]]["verdict"] for i in phish}
    only_model = [k for k in a if a[k] in ("Likely scam", "Suspicious") and c[k] not in ("Likely scam", "Suspicious")]
    w(f"Phishing links flagged in (a) and not in (c), i.e. caught by the URL model alone: **{len(only_model)} of {len(phish)}**. "
      f"Benign domains flagged in (a) and not in (c): **{sum(S['honest'][i['id']]['verdict'] in ('Likely scam', 'Suspicious') and S['honest_c'][i['id']]['verdict'] not in ('Likely scam', 'Suspicious') for i in benign)} of {len(benign)}**. "
      "Recall, false alarms and the same figures with the intervals are computed from the same rows, so a difference of 1-2 links is inside the noise of 96 / 100 links.\n")
    return L


# ------------------------------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--date", default=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"), help="UTC date of the sample (names the files)")
    ap.add_argument("--n-phish", type=int, default=200)
    ap.add_argument("--n-benign", type=int, default=200, help="in total, half per band")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--offline", action="store_true", help="never use the network: replay data/eval_live/netcache_<date>.jsonl.gz (a miss is recorded as unavailable)")
    ap.add_argument("--crtsh", action="store_true", help="switch the crt.sh certificate-age check on for this run (off by default since decision C1)")
    ap.add_argument("--resample", action="store_true", help="redraw the samples even if the CSVs for this date exist")
    ap.add_argument("--out-dir", default=str(OUT_DIR))
    ap.add_argument("--report", default=str(REPORT))
    args = ap.parse_args()
    out = Path(args.out_dir)
    log = lambda s: print(s, file=sys.stderr, flush=True)
    today = dt.date.fromisoformat(args.date)

    config.CRTSH_CHECK = args.crtsh or config.CRTSH_CHECK
    log("loading models and lists ...")
    text_model, url_model = load_text_model(), load_url_model()
    load_gambling()
    warm_lists()
    base = load_lists()
    now = dt.datetime.now(dt.timezone.utc)
    for name in ("openphish", "urlhaus", "tranco"):
        assert not base.status.get(name), f"{name} list is not usable ({base.status.get(name)}): run src/update_link_lists.py first"

    # ---- samples
    pf, bf, rf = out / f"phish_{args.date}.csv", out / f"benign_{args.date}.csv", out / f"regression_{args.date}.csv"
    info = {}
    if pf.exists() and bf.exists() and rf.exists() and not args.resample:
        log("reusing the saved samples of this date")
        P = pd.read_csv(pf, keep_default_na=False)
        B = pd.read_csv(bf, keep_default_na=False)
        G = pd.read_csv(rf, keep_default_na=False)
        phish_rows = [{"url": refang(r.url_defanged), "reg": refang(r.reg_domain_defanged), "kind": r.kind, "rank": int(r.tranco_rank) if r.tranco_rank != "" else None} for r in P.itertuples()]
        ben_rows = [{"url": refang(r.url_defanged), "reg": refang(r.reg_domain_defanged), "band": r.band, "rank": int(r.tranco_rank), "kind": "own_domain"} for r in B.itertuples()]
        reg_rows = [{"id": r.id, "group": r.group, "text": refang(r.text_defanged), "url": refang(r.url_defanged), "reg": refang(r.reg_domain_defanged),
                     "note": r.note, "expected": r.expected, "rank": int(r.tranco_rank) if r.tranco_rank != "" else None} for r in G.itertuples()]
        meta = json.loads((out / f"sample_info_{args.date}.json").read_text())
        info = meta
    else:
        log("sampling ...")
        phish_rows, pinfo = sample_phish(base, args.n_phish, args.seed, args.date)
        taken = {r["reg"] for r in phish_rows}
        reg_domains = [(d, "gambling_unlisted") for d in UNLISTED] + [(d, "gambling_unconfirmed") for d in UNCONFIRMED] + [(d, "gambling_control") for d in CONTROL]
        reg_domains += [(d, "gambling_control") for d in control_extra(args.seed, args.date, taken | {d for d, _ in reg_domains})]
        taken |= {d for d, _ in reg_domains}
        ben_rows, binfo = sample_benign(base, args.n_benign // 2, args.seed, args.date, taken)
        info = {"phish": pinfo, "benign": binfo}
        reg_rows = [{"id": f"reg{k + 1:02d}", "group": g, "text": f"https://{d}/", "url": f"https://{d}/", "reg": d, "rank": base.tranco_rank(d), "note": g,
                     "expected": "Suspicious" } for k, (d, g) in enumerate(reg_domains)]
        reg_rows += [{"id": mid, "group": "gambling_message", "text": text, "url": (u := re.search(r"https?://\S+", text).group(0)), "reg": reg_of(u), "rank": None,
                      "note": note, "expected": exp} for mid, note, text, exp in MESSAGES]
        out.mkdir(parents=True, exist_ok=True)
        save_csv(pf, [{"id": f"p{k + 1:03d}", "url_defanged": defang(r["url"]), "reg_domain_defanged": defang(r["reg"]), "kind": r["kind"],
                       "tranco_rank": r["rank"] if r["rank"] is not None else "", "tranco_band": band_of(r["rank"]), "source": "openphish_public_feed",
                       "feed_downloaded_utc": pinfo["downloaded_utc"]} for k, r in enumerate(phish_rows)],
                 ["id", "url_defanged", "reg_domain_defanged", "kind", "tranco_rank", "tranco_band", "source", "feed_downloaded_utc"])
        save_csv(bf, [{"id": f"b{k + 1:03d}", "url_defanged": defang(r["url"]), "reg_domain_defanged": defang(r["reg"]), "tranco_rank": r["rank"], "band": r["band"],
                       "kind": r["kind"]} for k, r in enumerate(ben_rows)], ["id", "url_defanged", "reg_domain_defanged", "tranco_rank", "band", "kind"])
        save_csv(rf, [{"id": r["id"], "group": r["group"], "text_defanged": defang_text(r["text"]), "url_defanged": defang(r["url"]), "reg_domain_defanged": defang(r["reg"]),
                       "tranco_rank": r["rank"] if r["rank"] is not None else "", "note": r["note"], "expected": r["expected"]} for r in reg_rows],
                 ["id", "group", "text_defanged", "url_defanged", "reg_domain_defanged", "tranco_rank", "note", "expected"])
        (out / f"sample_info_{args.date}.json").write_text(json.dumps(info, indent=1))
    if len(phish_rows) < args.n_phish:
        log(f"NOTE: only {len(phish_rows)} unique registered domains in the feed (wanted {args.n_phish})")

    items = []
    for k, r in enumerate(phish_rows):
        items.append({"id": f"p{k + 1:03d}", "set": "phish", "text": r["url"], "url": r["url"], "reg": r["reg"], "kind": r["kind"], "rank": r["rank"], "group": "phishing"})
    for k, r in enumerate(ben_rows):
        items.append({"id": f"b{k + 1:03d}", "set": "benign_top10k" if r["band"] == "top 10k" else "benign_100k_1m", "text": r["url"], "url": r["url"], "reg": r["reg"],
                      "kind": "own_domain", "rank": r["rank"], "group": "benign"})
    for r in reg_rows:
        items.append({"id": r["id"], "set": "regression_message" if r["group"] == "gambling_message" else "regression_domain", "text": r["text"], "url": r["url"],
                      "reg": r["reg"], "kind": kind_of(link_domain(r["url"])[0]), "rank": r["rank"], "group": r["group"], "note": r["note"], "expected": r["expected"]})
    ids = [i["id"] for i in items]
    assert len(ids) == len(set(ids))
    regs = [i["reg"] for i in items if i["set"] in ("phish", "benign_top10k", "benign_100k_1m")]
    assert len(regs) == len(set(regs)), "a registered domain appears in two sets"
    for fpath in (pf, bf, rf):                            # nothing but defanged URLs on disk
        txt = fpath.read_text()
        assert not re.search(r"https?://", txt, re.I), f"{fpath.name} holds a live URL"

    # ---- network harness
    sampled_hosts = set()
    for i in items:
        sampled_hosts |= {link_domain(u)[0] for u in re.findall(r"https?://\S+", i["text"])} | {i["reg"]}
    guard = ResolveGuard(refuse_all=args.offline)
    guard.forbidden = sampled_hosts
    guard.install()
    harness = NetHarness(out / f"netcache_{args.date}.jsonl.gz", args.offline)
    harness.forbidden_hosts = sampled_hosts
    net.request = harness.request

    results = run_all(items, text_model, url_model, harness, base, today, log)
    if args.offline:
        assert harness.misses == 0, f"{harness.misses} requests were not in the cache"

    rl = out / f"resolved_{args.date}.json"
    resolved = collections.Counter(json.loads(rl.read_text()) if rl.exists() else {})
    if not args.offline:
        resolved.update(guard.names)                  # an offline rerun adds nothing (its guard refuses every name)
    rl.write_text(json.dumps(dict(sorted(resolved.items())), indent=1))

    # ---- results csv
    rows = []
    for sid in results:
        for it in items:
            r = results[sid][it["id"]]
            rows.append({"setting": sid, "set": it["set"], "id": it["id"], "group": it["group"], "url_defanged": defang(it["url"]), "kind": it["kind"],
                         "tranco_rank": it["rank"] or "", "verdict": r["verdict"], "flags": ",".join(r["flags"]), "positive": r["positive"] or "", "gambling": r["gambling"] or "",
                         "lists": r["lists"], "url_score": "" if r["url_score"] is None else round(r["url_score"], 4), "rdap": r["rdap"],
                         "age_days": "" if r["age_days"] is None else r["age_days"], "crtsh": r["crt"], "dns": r["dns"]})
    rpath = out / f"results_{args.date}.csv"
    save_csv(rpath, rows, list(rows[0]))
    written = [f"data/eval_live/{p.name}" for p in (pf, bf, rf, rpath)]
    assert not re.search(r"https?://", rpath.read_text(), re.I), "results hold a live URL"

    # ---- report
    for it in items:
        it.setdefault("note", "")
    ctx = dict(items=items, results=results, resolved=resolved, harness=harness, info=info, guard=guard, base=base, text_model=text_model, written=written)
    md = build_report(args, ctx)
    Path(args.report).write_text(md)
    assert not re.search(r"https?://", md, re.I), f"the report holds a live URL: {re.findall(r'https?://[^ ]{0,40}', md, re.I)[:3]}"
    log(f"wrote {args.report}")


if __name__ == "__main__":
    main()
