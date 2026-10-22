import os, random, sys, time, tracemalloc
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import pandas as pd
from fastapi.testclient import TestClient
import gambling_lists as gl
from shield.api.main import app
from shield.config import GAMBLING_DOMAINS_PATH, GAMBLING_PLATFORM_HOSTS_PATH
from shield.contracts import Report
from shield.core.router import analyse
from shield.links.gambling import GAMBLING_ADDED, GAMBLING_NOT_GAMBLING, GAMBLING_PLATFORM_ROOTS, GAMBLING_VERDICT, load_gambling, registered_domain
from url_features import parse_url

# python tests/test_gambling.py   (from the project root; needs the two models and the lookup files from src/gambling_lookup.py)
# Decision G1 (docs/decisions/README.md): a link on the gambling lookup is Suspicious with its own reason, never Likely scam on its own.
#   G1 a list domain -> "list"   G2 loksatta.com -> None (allow-listed)   G3 a WordPress blog -> None (platform root)
#   G4 a listed platform host -> "platform_host"   G5 a Satta name -> "india_token"   G6 kalyanjewellers.net -> None (one weak token)
#   G7 a gov.in host -> None (exempt)   G8 google.com, onlinesbi.sbi, hdfcbank.com -> None
#   G9 the registered-domain function maps https://<domain>/ back to <domain> for 1,000 random lookup domains
#   G10 fusion with stub models   G11 over HTTP with the real models   G12 load time and memory
# Beyond the spec: G13 all 1,338 platform hosts are reachable   G14 the 121 India seed domains match   G15 the rule in gambling_india.json
# agrees with gambling_lists.india_hit (the build-time rule)   G16 platform roots: only the owner's part of a host is read by the name rule
# User review of the Tranco top 10k, 2026-10-17: G17 the 13 GAMBLING_NOT_GAMBLING domains never match   G18 the 9 GAMBLING_PLATFORM_ROOTS are host-level
# only   G19 operators that must stay flagged still match by "list"   G20 150m.com (a free web host, added 2026-10-17) is a hosting root too
URL_GAMBLING = "https://bet365.com/"


class StubText:
    """A text head with a fixed score: 0.5 is Suspicious, 0.1 is level 0, 0.9 is Likely scam under thresholds (0.4, 0.7)."""
    name, thresholds = "stub", (0.4, 0.7)
    def __init__(self, score):
        self.s = score
    def score(self, text):
        return self.s
    def explain(self, text, k=8):
        return []

class StubUrl:
    """A URL head with a level per URL (default 0), so the phishing side of the fusion is exactly what the test says."""
    t_flag, t_high = 0.5, 0.8
    def __init__(self, levels=None):
        self.levels = levels or {}
    def score_many(self, urls):
        lv = [self.levels.get(u, 0) for u in urls]
        scored = pd.DataFrame({"url": urls, "host": [parse_url(u)[0] for u in urls], "score": [(0.2, 0.6, 0.9)[v] for v in lv], "level": lv})
        return scored, pd.DataFrame({"x": range(len(urls))})
    def breakdown(self, row):
        return pd.DataFrame()


def match(url):
    return load_gambling().match(url)

def basis(url):
    m = match(url)
    return m and m["basis"]

def expect(url, want):
    got = basis(url)
    return [] if got == want else [f"{url}: got {got!r}, wanted {want!r}"]

def tsv():
    return pd.read_csv(GAMBLING_DOMAINS_PATH, sep="\t", dtype=str, keep_default_na=False)

def g1():
    d = tsv()
    dom = "bet365.com" if "bet365.com" in set(d["domain"]) else d[(d["lists"] == "both") & d["domain"].str.endswith(".com")]["domain"].iloc[0]
    return expect(f"https://{dom}/", "list"), f"{dom}"

def g2():
    return expect("https://www.loksatta.com/", None), ""

def g3():
    return expect("https://myblog.wordpress.com/post", None), f"wordpress.com is {'on' if 'wordpress.com' in load_gambling().domains else 'not on'} the domain list"

def g4():
    h = pd.read_csv(GAMBLING_PLATFORM_HOSTS_PATH, sep="\t", dtype=str, keep_default_na=False)["host"].iloc[0]
    return expect(f"https://{h}/", "platform_host"), h

def g5():
    return expect("https://satta-result-today.example.org", "india_token"), ""

def g6():
    on_list = "kalyanjewellers.net" in load_gambling().domains
    return expect("https://kalyanjewellers.net", "list" if on_list else None), "not on the lists, one weak token only" if not on_list else "on a list"

def g7():
    return expect("https://sattaresults.gov.in", None), ""

def g8():
    return [b for u in ("https://google.com", "https://onlinesbi.sbi", "https://hdfcbank.com") for b in expect(u, None)], ""

def g9():
    doms = list(tsv()["domain"])
    sample = random.Random(0).sample(doms, 1000)
    lk, bad = load_gambling(), []
    for d in sample:
        host = parse_url(f"https://{d}/")[0].rstrip(".")
        if registered_domain(host) != d:
            bad.append(f"{d}: maps to {registered_domain(host)!r}")
    skipped = [d for d in sample if d in lk.allow or any(d == s or d.endswith("." + s) for s in lk.exempt) or d in lk.platform_suffixes]
    bad += [f"{d}: match() is None" for d in sample if d not in skipped and match(f"https://{d}/") is None]
    return bad, f"1,000 of {len(doms):,} domains; {len(skipped)} exempt or platform roots excluded from the match() half"

def run_pair(text, text_score, url_levels):
    return analyse(text, StubText(text_score), StubUrl(url_levels))

def g10():
    bad, promo, free_host = [], "Get a 500% welcome bonus, play now: ", "0005vip.pages.dev"
    def want(label, cond):
        if not cond:
            bad.append(label)
    r = run_pair(promo + URL_GAMBLING, 0.5, {})
    l = r["links"][0]
    want(f"text Suspicious + gambling-only link: level {r['level']}, wanted 1 (not 2)", r["level"] == 1)
    want(f"gambling-only link: level {l['level']} base_level {l['base_level']} verdict {l['verdict']!r}", (l["level"], l["base_level"], l["verdict"]) == (1, 0, GAMBLING_VERDICT))
    want(f"url_level must stay the phishing side (0), got {r['url_level']}", r["url_level"] == 0)
    r = run_pair(promo + "https://welcome-bonus-shop.top/ " + URL_GAMBLING, 0.5, {"https://welcome-bonus-shop.top/": 1})
    want(f"text Suspicious + a link the URL model puts at 1: level {r['level']}, wanted 2 (unchanged)", r["level"] == 2)
    r = run_pair(promo + URL_GAMBLING, 0.5, {URL_GAMBLING: 1})
    l = r["links"][0]
    want(f"URL model at 1 on a gambling domain: verdict {l['verdict']!r}, wanted the model's 'Suspicious'; level {r['level']} wanted 2 (both heads)", l["verdict"] == "Suspicious" and r["level"] == 2)
    r = run_pair(URL_GAMBLING, 0.5, {})
    want(f"bare gambling link: level {r['level']}, text_level {r['text_level']}; wanted 1 and no text level", r["level"] == 1 and r["text_level"] is None)
    r = run_pair(f"https://{free_host}/", 0.5, {})
    l = r["links"][0]
    want(f"gambling link on free hosting: kind {l['kind']}, base_level {l['base_level']}, level {r['level']}; wanted free, None, 1", (l["kind"], l["base_level"], r["level"]) == ("free", None, 1))
    r = run_pair("Share your OTP with me now: " + URL_GAMBLING, 0.1, {})
    want(f"OTP request + gambling link: level {r['level']}, escalated {r['escalated']}; wanted at least 1, escalated by the OTP rule", r["level"] >= 1 and r["escalated"] and r["cred_request"])
    r = run_pair(promo + URL_GAMBLING, 0.1, {})
    want(f"text level 0 + gambling link: level {r['level']}, escalated {r['escalated']}; wanted 1, not escalated", r["level"] == 1 and not r["escalated"])
    r = run_pair(promo + URL_GAMBLING, 0.9, {})
    want(f"text Likely scam + gambling link: level {r['level']}, wanted 2 (the floor never lowers)", r["level"] == 2)
    r = run_pair("Welcome back, see your balance here: " + URL_GAMBLING, 0.1, {URL_GAMBLING: 2})
    l = r["links"][0]
    want(f"URL model at 2 on a gambling domain: level {r['level']} verdict {l['verdict']!r}; wanted 2 / 'Likely scam'", r["level"] == 2 and l["verdict"] == "Likely scam")
    r = run_pair("Free bonus here https://bit.ly/bet365", 0.1, {})
    want(f"a shortener is never looked up: gambling {r['links'][0]['gambling']}, level {r['level']}", r["links"][0]["gambling"] is None and r["level"] == 0)
    r = run_pair("Hello, how are you today my friend", 0.1, {})
    want(f"no link: level {r['level']}, wanted 0", r["level"] == 0)
    return bad, ""

def g11():
    text = f"Get a 500% welcome bonus, play now: {URL_GAMBLING}"
    with TestClient(app) as c:
        resp = c.post("/api/analyse", json={"text": text})
        if resp.status_code != 200:
            return [f"status {resp.status_code} {resp.text}"], ""
        rep = Report.model_validate(resp.json())
        bad = []
        ev = [e for ch in rep.children for e in ch.evidence if e.id == "link.gambling"]
        if not ev or ev[0].tag != "Gambling site" or ev[0].module != "links" or ev[0].effect.value != "caution":
            bad.append(f"link.gambling evidence in a child: {ev}")
        elif ev[0].quote != URL_GAMBLING or ev[0].span != (text.index(URL_GAMBLING), len(text)):
            bad.append(f"quote / span of the link: {ev[0].quote!r} {ev[0].span}")
        if rep.category != "gambling":
            bad.append(f"category {rep.category!r}")
        if "Gambling or betting site" not in rep.reasons:
            bad.append(f"'Gambling or betting site' is not among the reasons: {rep.reasons}")
        text_danger = any(e.id == "model.text" and e.effect.value == "danger" for e in rep.evidence)
        url_flag = any(e.id == "model.url" and e.effect.value in ("caution", "danger") for ch in rep.children for e in ch.evidence)
        if rep.level.value == "likely_scam" and not text_danger:
            # Likely scam without the text model alone saying so is only allowed through the existing rule "both heads at least Suspicious"
            bad.append(f"likely_scam although model.text is not danger (URL model flagged the link: {url_flag})")
        plain = c.post("/api/analyse", json={"text": "See you at lunch tomorrow, bring the notes from class"}).json()
        if plain["category"] is not None:
            bad.append(f"category {plain['category']!r} on a message with no link")
    return bad, f"level {rep.level.value}, reasons {rep.reasons}, URL model flagged the link: {url_flag}"

def g12():
    load_gambling.cache_clear()
    t0 = time.perf_counter()
    load_gambling()
    secs = time.perf_counter() - t0
    load_gambling.cache_clear()
    tracemalloc.start()
    load_gambling()
    peak = tracemalloc.get_traced_memory()[1] / 1e6
    tracemalloc.stop()
    return [], f"load {secs:.2f} s, tracemalloc peak {peak:.0f} MB"

def g13():
    lk = load_gambling()
    bad = []
    for h in lk.platform_hosts:
        m = match(f"https://{h}/")
        if m is None or m["basis"] != "platform_host" or m["domain"] != h:
            bad.append(f"{h}: {m}")
    return bad[:10], f"{len(lk.platform_hosts):,} platform hosts, {len(bad)} unreachable, {len(lk.platform_suffixes)} platform suffixes"

def g14():
    import json
    seeds = [s["domain"] for s in json.load(open(os.path.join(os.path.dirname(GAMBLING_DOMAINS_PATH), "gambling_india.json")))["seed_domains"]]
    decided = [d for d in seeds if d in GAMBLING_NOT_GAMBLING]   # the user's top-10k review (2026-10-17) overrides the seed list for these
    seeds = [d for d in seeds if d not in GAMBLING_NOT_GAMBLING]
    return [f"{d}: {match(f'https://{d}/')}" for d in seeds if match(f"https://{d}/") is None], f"{len(seeds)} seed domains match; {len(decided)} skipped as reviewed non-gambling: {decided or 'none'}"

def g15():
    rng, doms = random.Random(1), list(tsv()["domain"])
    hosts = rng.sample(doms, 3000) + ["satta-king.net", "matka.kalyan.net", "kalyan.in", "matka.fi", "www.dpboss.mobi", "loksatta.com", "x.gov.in", "sattaking.gov.in", "a.b.nic.in", "satta.edu.in", "jansatta.com", "www.sattacademy.com"]
    lk, bad = load_gambling(), []
    for h in hosts:
        want = gl.india_hit(h) == "strong"
        if want != bool(lk._india(h)) and not (registered_domain(h) in lk.allow or any(h == s or h.endswith("." + s) for s in lk.exempt)):   # match() applies both exceptions first
            bad.append(f"{h}: build-time rule {gl.india_hit(h)}, runtime tokens {lk._india(h)}")
    return bad[:10], f"{len(hosts):,} hosts"

def g16():
    return (expect("https://wordpress.com/", None) + expect("https://www.wordpress.com/", None) + expect("https://satta-news.wordpress.com/", "india_token")
            + expect("https://myblog.wordpress.com/satta-king", None) + expect("https://bit.ly/sattaking", None)), ""

def g17():
    bad = [b for d in sorted(GAMBLING_NOT_GAMBLING) for u in (f"https://{d}/", f"https://www.{d}/x") for b in expect(u, None)]
    return bad, f"{len(GAMBLING_NOT_GAMBLING)} domains, 2 URLs each"

def g18():
    hosts = set(pd.read_csv(GAMBLING_PLATFORM_HOSTS_PATH, sep="\t", dtype=str, keep_default_na=False)["host"])
    bad, listed = [], []
    for d in sorted(GAMBLING_PLATFORM_ROOTS):
        bad += expect(f"https://{d}/", None)                       # the root itself is never matched by the domain list
        host = f"somebody.{d}"
        if host in hosts:
            listed.append(host)
        bad += expect(f"https://{host}/", "platform_host" if host in hosts else None)
        bad += expect(f"https://{d}/satta-king", None)             # the name rule reads the owner's part of the host only, and a root has none
        bad += expect(f"https://satta-news.{d}/", "india_token")   # ... but a subdomain below the root is the owner's part
    return bad, f"{len(GAMBLING_PLATFORM_ROOTS)} roots; somebody.<root> in the platform-hosts file: {listed or 'none'}"

def g19():
    return [b for d in ("bet365.com", "1xbet.com", "dpboss.tax", "stake.com", "fanduel.com") for b in expect(f"https://{d}/", "list")], ""

def g20():
    # 150m.com (user decision 2026-10-17): a free web host, on the domain list but host-level only, like tripod.com
    return (expect("https://somebody.150m.com/", None) + expect("https://150m.com/", None) + expect("https://satta-news.150m.com/", "india_token")
            + ([] if "150m.com" in GAMBLING_PLATFORM_ROOTS and "150m.com" in load_gambling().domains else ["150m.com must be a platform root AND still on the domain list"])), ""

def g21():
    # the 8 sites BUGS.md named as missing (added 2026-10-23, decision C1): a plain URL and a www. + path URL both match by "list" with the added-site reason
    bad = [b for d in sorted(GAMBLING_ADDED) for u in (f"https://{d}/", f"https://www.{d}/promo") for b in expect(u, "list")]
    return bad + ([] if len(GAMBLING_ADDED) == 8 else [f"{len(GAMBLING_ADDED)} added sites, wanted 8"]), f"{len(GAMBLING_ADDED)} domains, 2 URLs each"

CHECKS = [("G1", "a list domain (bet365.com) -> list", g1), ("G2", "loksatta.com -> None (allow-listed)", g2), ("G3", "a WordPress blog -> None (platform root)", g3),
          ("G4", "the first listed platform host -> platform_host", g4), ("G5", "a Satta name on an unlisted domain -> india_token", g5),
          ("G6", "kalyanjewellers.net -> None (one weak token)", g6), ("G7", "sattaresults.gov.in -> None (exempt)", g7),
          ("G8", "google.com, onlinesbi.sbi, hdfcbank.com -> None", g8), ("G9", "registered-domain function round-trips 1,000 lookup domains", g9),
          ("G10", "fusion with stub models: gambling is Suspicious, never Likely scam on its own", g10),
          ("G11", "API: link.gambling evidence, category, level", g11), ("G12", "lookup load time and memory", g12),
          ("G13", "every listed platform host is reachable through match()", g13), ("G14", "the India seed domains match", g14),
          ("G15", "runtime India rule == gambling_lists.india_hit", g15), ("G16", "platform roots: only the owner's part of a host is read", g16),
          ("G17", "the 13 reviewed non-gambling domains (and www.) -> None", g17),
          ("G18", "the 9 hosting roots (8 reviewed + 150m.com): host-level only (somebody.<root> -> None unless listed)", g18),
          ("G19", "bet365.com, 1xbet.com, dpboss.tax, stake.com, fanduel.com still -> list", g19),
          ("G20", "somebody.150m.com and 150m.com -> None (hosting root); satta-news.150m.com -> india_token", g20),
          ("G21", "the 8 BUGS.md-named sites (added 2026-10-23) -> list", g21)]

def run():
    return [(gid, what, *fn()) for gid, what, fn in CHECKS]

def test_gambling():
    bad = [f"{gid}: {b}" for gid, _, bs, _ in run() for b in bs]
    assert not bad, "\n".join(bad)

if __name__ == "__main__":
    results = run()
    for gid, what, bad, note in results:
        print(f"{'FAIL' if bad else 'PASS'} {gid} {what}" + (f"  [{note}]" if note else ""))
        for b in bad[:10]:
            print("    " + b.encode("ascii", "backslashreplace").decode()[:300])
    print(f"\n{sum(not b for _, _, b, _ in results)}/{len(results)} passed")
    sys.exit(1 if any(b for _, _, b, _ in results) else 0)
