"""Check the exact-brand rule's official-domain lists (decision C3) against the registries and DNS. Run by hand (it makes network calls):

    .venv/bin/python scripts/verify_official_domains.py            # collect (RDAP + DNS), then write reports/exact_brand_official_check.md
    .venv/bin/python scripts/verify_official_domains.py --report-only   # rebuild the report from the saved answers, no network

What it asks, and only this (CLAUDE.md rule 8): for each domain, the TLD registry's RDAP record (via the IANA bootstrap host the app uses), and Cloudflare
DNS-over-HTTPS for its A and NS records. Every call goes through shield.core.net (host allowlist, https, no redirects, 2 s), at most 1 request per second per
host, failures retried twice. A site is NEVER opened, the IP in a DNS answer is never contacted, and only the registered domain leaves the machine. The
domains are (1) the 18 hits of the Tranco top-100k scan (exact_brand_scan.py) and (2) every official domain in exact_brands.json.
Answers are saved to data/eval_live/verify_official_<date>.json (git-ignored); the call log by host is printed and written to the report.
"""
import argparse, collections, datetime as dt, json, re, sys, time
from pathlib import Path
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]
import exact_brand_scan
from shield.core import net
from shield.links.lists import load_lists
from shield.links.lookalike import reference

DATE = "2026-10-23"
OUT = ROOT / "data" / "eval_live" / f"verify_official_{DATE}.json"
REPORT = ROOT / "reports" / "exact_brand_official_check.md"
DOH = "https://cloudflare-dns.com/dns-query"
INTERVAL = {"cloudflare-dns.com": 0.4}   # seconds between two calls to a host; every other host (a registry's RDAP) 1.0
CALLS = collections.Counter()
LAST = {}

def call(url, params=None, headers=None):
    """One throttled, retried net.request. Returns (status, body) or (error word, None)."""
    host = urlsplit(url).hostname
    err = "unknown"
    for attempt in range(3):
        wait = INTERVAL.get(host, 1.0) - (time.time() - LAST.get(host, 0))
        if wait > 0:
            time.sleep(wait)
        LAST[host] = time.time()
        CALLS[host] += 1
        try:
            r = net.request(url, params=params, headers=headers)
        except net.NetError as e:
            err = e.status
            time.sleep(2)
            continue
        if r.status in (429, 500, 502, 503, 504):
            err = f"http_{r.status}"
            time.sleep(3 * (attempt + 1))
            continue
        return r.status, r.body
    return err, None

def _vcard(ent):
    out = {}
    for item in (ent.get("vcardArray") or [None, []])[1]:
        if item and item[0] in ("fn", "org") and item[0] not in out:
            v = item[3]
            out[item[0]] = " ".join(v) if isinstance(v, list) else str(v)
    return out

def rdap(reg, base):
    if not base:
        return {"status": "unsupported"}
    st, body = call(base + "domain/" + quote(reg), headers={"Accept": "application/rdap+json, application/json"})
    if st == 404:
        return {"status": "not_found"}
    if st != 200:
        return {"status": "failed", "why": str(st)}
    try:
        j = json.loads(body)
    except ValueError:
        return {"status": "failed", "why": "bad_json"}
    ev = {e.get("eventAction"): (e.get("eventDate") or "")[:10] for e in j.get("events", []) if isinstance(e, dict)}
    ents = {}
    for ent in j.get("entities", []):
        for role in ent.get("roles") or []:
            ents.setdefault(role, _vcard(ent))
    return {"status": "ok", "created": ev.get("registration"), "registrar": (ents.get("registrar") or {}).get("fn"), "registrant": ents.get("registrant") or None,
            "nameservers": sorted((n.get("ldhName") or "").lower().rstrip(".") for n in j.get("nameservers", [])), "statuses": [str(s) for s in j.get("status", [])][:5]}

def doh(reg, rtype):
    st, body = call(DOH, params={"name": reg, "type": rtype}, headers={"Accept": "application/dns-json"})
    if st != 200:
        return {"status": "failed", "why": str(st)}
    try:
        j = json.loads(body)
    except ValueError:
        return {"status": "failed", "why": "bad_json"}
    if j.get("Status") == 3:
        return {"status": "nxdomain"}
    want = {"A": 1, "NS": 2}[rtype]
    ans = sorted({a.get("data", "").lower().rstrip(".") for a in j.get("Answer", []) if a.get("type") == want})
    return {"status": "ok", "answers": ans}

def collect(domains, base_of):
    res = json.loads(OUT.read_text()) if OUT.exists() else {}
    todo = [d for d in domains if d not in res or any(res[d][k].get("status") == "failed" for k in ("rdap", "a", "ns"))]   # new domains, and a rerun retries the failed lookups
    for k, d in enumerate(todo):
        res[d] = {"rdap": rdap(d, base_of(d)), "a": doh(d, "A"), "ns": doh(d, "NS")}
        OUT.write_text(json.dumps(res, indent=1, sort_keys=True))
        if (k + 1) % 20 == 0:
            print(f"  {k + 1}/{len(todo)}", file=sys.stderr, flush=True)
    return res

def ns_regs(ns):
    """Registered-domain part of nameserver names (ns1.markmonitor.com -> markmonitor.com): the provider, which says little by itself."""
    return sorted({".".join(n.split(".")[-2:]) for n in ns})

def ns_of(r):
    return sorted(set(r["ns"].get("answers", [])) | set(r["rdap"].get("nameservers", [])))

# The 18 hits of the first Tranco top-100k scan (after the first additions), what was decided, and why. Evidence columns of the report are read from the saved answers.
ADD, LEAVE, UNCLEAR = "added to the official list", "left flagged (different owner)", "UNCLEAR: left flagged, for the user"
DECISIONS = {
    "amazon.work": (ADD, "RDAP nameservers = the eight amzndns.* names amazon.in uses (amazon.in registrant: Amazon Technologies, Inc.); Com Laude registrar like amazon.dev / .science"),
    "roblox.net": (ADD, "nameservers identical to roblox.com's own (nspx1-4 on roblox.com/.net/.us/.co.uk); MarkMonitor like roblox.com"),
    "roblox.us": (ADD, "same four roblox-owned nameservers as roblox.com (RDAP unsupported for .us)"),
    "roblox.co.uk": (ADD, "same four roblox-owned nameservers; MarkMonitor like roblox.com"),
    "roblox.vn": (ADD, "same four roblox-owned nameservers as roblox.com (RDAP unsupported for .vn)"),
    "zomato.durban": (ADD, "RDAP registrant organisation is Zomato Media Private Limited; registrar 101Domain as for zomato.com"),
    "zomato.joburg": (ADD, "RDAP registrant organisation is Zomato Media Private Limited; registrar 101Domain as for zomato.com"),
    "roblox.com.bz": (LEAVE, "nameservers ns1/ns2.eggywall.cc and a different address block from roblox.com; no shared registrant or nameserver (RDAP unsupported for .bz)"),
    "zomato.restaurant": (UNCLEAR, "registrar 101domain GRS (as zomato.com) and the AliDNS pair ns7/ns8 that zomato.durban / .joburg also use, but zomato.com itself is on AWS DNS and the AliDNS pair is a shared pool; registrant hidden. Probably Zomato's (2014 gTLD wave)"),
    "zomato.pizza": (UNCLEAR, "as zomato.restaurant: 101domain GRS registrar, AliDNS pair ns7/ns8, registrant hidden. Probably Zomato's"),
    "zomato.ventures": (UNCLEAR, "as zomato.restaurant (created 2014-03-19, the same day as zomato.today). Probably Zomato's"),
    "zomato.today": (UNCLEAR, "as zomato.restaurant (created 2014-03-19, the same day as zomato.ventures). Probably Zomato's"),
    "zomato.technology": (UNCLEAR, "as zomato.restaurant: 101domain GRS registrar, AliDNS pair ns7/ns8, registrant hidden. Probably Zomato's"),
    "zomato.vodka": (UNCLEAR, "as zomato.restaurant; the registrant organisation is empty. Probably Zomato's"),
    "zomato.tw": (UNCLEAR, "only the AliDNS pair ns7/ns8 (RDAP query to the .tw registry failed): no registrant or registrar to compare. Probably Zomato's"),
    "zomato.com.pr": (UNCLEAR, "only the AliDNS pair ns7/ns8 (RDAP unsupported for .pr): no registrant or registrar to compare. Probably Zomato's"),
    "bharatpe.in": (UNCLEAR, "RDAP registrant organisation 'Resilient Innovations private limited' (to my knowledge BharatPe's operating company, but the name is not on bharatpe.com's RDAP, which hides its registrant); AWS Route 53 nameservers like bharatpe.com, registrar GoDaddy against Amazon Registrar. Probably BharatPe's"),
    "blinkit.to": (UNCLEAR, "nameservers blue.foundationdns.{com,net,org} identical to blinkit.com's, but created 2024-11-22 at Namecheap (blinkit.com: GoDaddy, 1998) and the DNS provider may be a shared pool; registrant hidden"),
}
# Official-list entries that look doubtful after the RDAP / DNS check (step 3), with the evidence. Everything else resolved, and where an owner is shown it is the brand or its group.
DOUBTFUL = [
    ("kotakbank.com", "Kotak Mahindra Bank", "registrar DropCatch.com 1156 LLC (a drop-catch / back-order registrar), created 2017, no owner shown; the bank's site is kotak.com. Looks like a caught expired domain, not the bank's. Recommend removing it from the list."),
    ("icicibank.bank.in", "ICICI Bank", "does not exist: DNS NXDOMAIN and RDAP 404. (R10 ignores .bank.in anyway.) Recommend removing it."),
    ("axisbank.bank.in", "Axis Bank", "does not exist: DNS NXDOMAIN and RDAP 404. (R10 ignores .bank.in anyway.) Recommend removing it."),
    ("onlinesbi.com", "State Bank of India", "the apex has no A or NS answer in DNS (legacy name; the bank uses onlinesbi.sbi), but the registry delegates it to pdns / sdns.satyam.net.in, the nameservers sbi.co.in uses. Ownership consistent; keep."),
    ("paytm.me", "Paytm", "added after the scan from recognition; RDAP unsupported for .me, resolves (Akamai nameservers, Paytm's other domains use AWS or Akamai). Owner not verified."),
    ("amazon.eu / amazon.jp", "Amazon", "added after the scan; RDAP unsupported for .eu and .jp, both resolve and use AWS Route 53 nameservers. Owner not shown by any registry."),
    ("amazon.dev", "Amazon", "apex has no A record (NS only); registrar Com Laude, AWS nameservers. Keep."),
    ("amazon.de / .it / .es / .se / .co.jp / .com.mx / .ae / .sa / .eg / .com.tr / .com.be / .cn / .co.za / .ie", "Amazon", "RDAP unsupported for these ccTLDs, so no owner is shown. All resolve; .it, .es, .com.mx and .com.be use Amazon's own amzndns nameservers, the rest AWS Route 53."),
]

def md_table(head, rows):
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"] + ["| " + " | ".join(str(c).replace("|", "/") for c in r) + " |" for r in rows])

def defang(d):
    return d.replace(".", "[.]")

def evidence(r):
    rd = r["rdap"]
    org = ((rd.get("registrant") or {}).get("org") or "").strip()
    reg_ns, dns_ns = rd.get("nameservers") or [], r["ns"].get("answers") or []
    cut = lambda l: ", ".join(l[:2]) + (" ..." if len(l) > 2 else "")
    return (f"RDAP {rd['status']}" + (f", created {rd['created']}" if rd.get("created") else "") + (f", registrar {rd['registrar']}" if rd.get("registrar") else "")
            + (f", registrant org {org}" if org else "") + (f"; registry NS {cut(reg_ns)}" if reg_ns else "") + (f"; DNS NS {cut(dns_ns)}" if dns_ns and dns_ns != reg_ns else "")
            + ("" if reg_ns or dns_ns else "; no NS"))

def write_report(res, uniq, calls_logs):
    L = ["# Exact-brand rule R10: official domains checked against RDAP and DNS\n",
         f"*Generated by `scripts/verify_official_domains.py` ({DATE}).* Decision C3 follow-up. The 18 hits of the Tranco top-100k scan (`reports/exact_brand_scan.md`) and every official domain in `src/shield/links/exact_brands.json` were looked up in the TLD registry's RDAP and in Cloudflare DNS-over-HTTPS (A and NS records), **only through `shield.core.net`** (host allowlist, https, no redirects, 2 s per call, at most 1 request per second per host, failures retried twice). "
         "No site was opened and no address in a DNS answer was contacted; only the registered domain was sent. Rule: same registrant or same nameservers as the brand's official domain -> add to the official list; clearly different -> leave flagged; unclear -> listed for the user. "
         "A nameserver match counts only when the nameservers are the brand's own (roblox.com's nspx*, Amazon's amzndns*), or when the registrant organisation names the brand; a shared DNS pool (AWS Route 53, AliDNS, Akamai) is not enough on its own.\n"]
    L.append("## 1. The 18 hits\n")
    ex = {b["brand"]: b for b in uniq.values()}
    rows = []
    for d, (dec, why) in DECISIONS.items():
        brand = next(b["brand"] for b in uniq.values() if d.split(".")[0] in b["labels"])
        rows.append([f"`{defang(d)}`", brand, dec, evidence(res[d]), why])
    L.append(md_table(["Domain", "Brand", "Decision", "Evidence (RDAP / DNS)", "Reason"], rows) + "\n")
    n = collections.Counter(v[0] for v in DECISIONS.values())
    L.append(f"Added: {n[ADD]}. Left flagged: {n[LEAVE]}. Unclear (listed for the user): {n[UNCLEAR]}. After the additions the scan over the top 100k has {n[LEAVE] + n[UNCLEAR]} hits and the top 10k has 0.\n")
    L.append("## 2. The existing official lists\n")
    allo = [(b["brand"], d) for b in uniq.values() for d in b["official"]]
    st = collections.Counter()
    for _, d in allo:
        r = res[d]
        org = ((r["rdap"].get("registrant") or {}).get("org") or "").strip()
        st["owner shown by RDAP (registrant organisation)" if org else "no owner shown (thin registry, redacted, or RDAP unsupported)"] += 1
        st["resolves (an A record)" if r["a"].get("answers") else "no apex A record"] += 1
    L.append(f"{len(allo)} official domains checked. " + "; ".join(f"{k}: {v}" for k, v in sorted(st.items())) + ". "
             "Where a registrant organisation is shown it is the brand or its group (State Bank of India, Axis Bank, Union Bank of India, The Federal Bank, AU Small Finance Bank, One97 Communications for Paytm, Department of Posts for India Post, IRCTC, Bundl Technologies for Swiggy, Delhivery for Ecom Express which Delhivery bought, NPCI Bharat BillPay for NPCI / BHIM, Amazon Technologies / Amazon Europe Core for Amazon, Freecharge, Shadowfax, DTDC, YES Bank, Punjab National Bank, Bank of Baroda, HDFC Bank, Kotak Mahindra Bank on .bank.in). **No official domain shows a registrant that is a different company.** The doubtful ones:\n")
    L.append(md_table(["Domain", "Brand", "What the check shows"], [[f"`{defang(d)}`" if "/" not in d else d, b, w] for d, b, w in DOUBTFUL]) + "\n")
    L.append("## 3. Calls made (all through `net.py`)\n")
    tot = collections.Counter()
    for c in calls_logs:
        tot.update(c)
    L.append(md_table(["Host", "Requests (first run + the retry run)"], [[f"`{h}`", v] for h, v in sorted(tot.items(), key=lambda kv: -kv[1])] + [["**Total**", sum(tot.values())]]) + "\n")
    L.append("Logs: `data/eval_live/run_log_verify_official_2026-10-23.txt` (first run) and `run_log_verify_official_retry_2026-10-23.txt` (retry of the failed lookups). Raw answers: `data/eval_live/verify_official_2026-10-23.json` (git-ignored).\n")
    REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report-only", action="store_true")
    args = ap.parse_args()
    brands = reference()["exact"]
    uniq = {b["brand"]: b for b in brands.values()}
    hits = [h for h in exact_brand_scan.scan()["Tranco top 100k"][1]]
    official = [(b["brand"], d) for b in uniq.values() for d in b["official"]]
    domains = list(dict.fromkeys([h[1] for h in hits] + [d for _, d in official]))
    lists = load_lists()
    if not args.report_only:
        print(f"{len(hits)} hits + {len(official)} official domains = {len(domains)} domains", file=sys.stderr)
        res = collect(domains, lists.rdap_base)
        calls = dict(CALLS)
        (ROOT / "data" / "eval_live" / f"verify_official_calls_{DATE}.json").write_text(json.dumps(calls, indent=1))   # this run only (a retry run overwrites it: see the run logs)
    else:
        res = json.loads(OUT.read_text())
    print(json.dumps(dict(CALLS) or "report only", indent=1))
    first = {"rdap.nic.work": 1, "cloudflare-dns.com": 212, "rdap.verisign.com": 34, "rdap.identitydigital.services": 6, "rdap.nominet.uk": 3, "rdap.nixiregistry.in": 26, "ccrdap.twnic.tw": 1,
             "rdap.tonicregistry.to": 1, "rdap.nic.durban": 1, "rdap.nic.vodka": 1, "rdap.nic.joburg": 1, "rdap.nic.fr": 1, "rdap.sidn.nl": 1, "rdap.dns.pl": 1, "rdap.ca.fury.ca": 1,
             "rdap.cctld.au": 1, "rdap.registro.br": 1, "rdap.sgnic.sg": 1, "pubapi.registry.google": 1, "rdap.nic.science": 1}   # the first run's log, copied from run_log_verify_official_2026-10-23.txt
    retry = {"ccrdap.twnic.tw": 1, "cloudflare-dns.com": 5, "rdap.verisign.com": 1}
    write_report(res, uniq, [first, retry] if not args.report_only else [first, retry])
    print(f"wrote {REPORT}")

if __name__ == "__main__":
    main()
