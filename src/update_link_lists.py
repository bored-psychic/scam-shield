"""Download the lists the offline link checks read (decision D23), and verify the brand-owned TLDs. Run on the Mac, by hand:

    .venv/bin/python src/update_link_lists.py                      # all lists + brand-TLD verification
    .venv/bin/python src/update_link_lists.py --only openphish urlhaus   # just these (OpenPhish refreshes every 12 h)

Everything goes through shield.core.net (kind "update": only the list hosts in net.UPDATE_HOSTS, https, no redirects). Files land in
data/final/linklists/ (git-ignored; OpenPhish forbids redistribution) with a manifest.json recording, per list, the source URL, licence,
download time (UTC), SHA-256 and row count. The URLhaus Auth-Key is read from the environment (URLHAUS_AUTH_KEY) and only ever placed in
the request: never printed, logged or written (the manifest writes the placeholder <URLHAUS_AUTH_KEY>). Without it URLhaus is skipped and
the app says "couldn't verify (no URLhaus key)".

Brand TLDs: every candidate in BRAND_TLD_CANDIDATES is kept only if ICANN's gtlds.json marks it specification13 (a .brand TLD: only the
owner, its affiliates and trademark licensees may register), its contract is not terminated and it has no removal date, its registryOperator
contains the expected owner, and IANA's root zone database page names the same manager and IANA's TLD list contains it. The result is
written to the TRACKED file src/shield/links/brand_tlds.json, so the app needs no download to recognise t.jio.
"""
import argparse, datetime as dt, gzip, hashlib, io, json, os, re, sys, zipfile
from pathlib import Path
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).resolve().parent))
from shield.core import net
from shield.config import BRAND_TLDS_PATH, LINKLISTS_DIR

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
OPENPHISH_URL = "https://openphish.com/feed.txt"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"   # URLs added in the past 30 days (abuse.ch export)
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
IP2ASN_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
ICANN_GTLDS_URL = "https://www.icann.org/resources/registries/gtlds/v2/gtlds.json"
IANA_TLDS_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
IANA_ROOT_DB = "https://www.iana.org/domains/root/db/{tld}.html"

LICENCE = {
    "tranco": "No licence stated for the list itself; built from Cisco Umbrella (free), Majestic (CC BY 3.0), Farsight, CrUX (CC BY-SA 4.0), "
              "Cloudflare Radar (CC BY-NC 4.0): non-commercial use. Cite Le Pochat et al., NDSS 2019.",
    "openphish": "OpenPhish terms (openphish.com/terms.html): academic / independent / personal research only, no commercial use, "
                 "no redistribution without written permission.",
    "urlhaus": "abuse.ch fair-use terms, free with an Auth-Key (free account); commercial use may need a paid plan.",
    "rdap_bootstrap": "IANA RDAP bootstrap registry (RFC 9224), public.",
    "ip2asn": "iptoasn.com, Public Domain Dedication and License (PDDL) 1.0.",
}

# (tld, brand shown to the user, owner name(s) expected in ICANN's registryOperator AND in IANA's 'Manager'; a tuple = any of them).
# A candidate that fails any check is dropped.
BRAND_TLD_CANDIDATES = [
    ("jio", "Jio", "Reliance Industries"), ("reliance", "Reliance", "Reliance Industries"), ("ril", "Reliance", "Reliance Industries"),
    ("sbi", "SBI (State Bank of India)", "State Bank of India"), ("hdfcbank", "HDFC Bank", "HDFC Bank"), ("hdfc", "HDFC Bank", ("HDFC Bank", "Housing Development Finance Corporation")),   # HDFC Ltd merged into HDFC Bank (2023): ICANN shows the bank, IANA still the old name
    ("icici", "ICICI", "ICICI"), ("airtel", "Airtel", "Bharti Airtel"), ("bharti", "Bharti", "Bharti Enterprises"),
    ("tata", "Tata", "Tata"), ("tatamotors", "Tata Motors", "Tata Motors"), ("star", "Star India", "Star India"),
    ("amazon", "Amazon", "Amazon"), ("google", "Google", "Charleston Road Registry"), ("goog", "Google", "Charleston Road Registry"),
    ("youtube", "YouTube (Google)", "Charleston Road Registry"), ("microsoft", "Microsoft", "Microsoft"), ("apple", "Apple", "Apple"),
    ("netflix", "Netflix", "Netflix"), ("flipkart", "Flipkart", "Flipkart"), ("lic", "LIC", "Life Insurance Corporation"),
]


def now_utc():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

def get(url, max_bytes=300_000_000):
    """The body of url. A redirect is followed (at most 3) only to a host that is itself on net.UPDATE_HOSTS: tranco-list.eu sends the
    daily file from its own /download/ path, openphish.com's feed.txt points at OpenPhish's own GitHub mirror (openphish/public_feed)."""
    for _ in range(4):
        r = net.request(url, "update", timeout=net.UPDATE_TIMEOUT, max_bytes=max_bytes)
        if r.status in (301, 302, 303, 307, 308) and r.headers.get("location"):
            url = urljoin(url, r.headers["location"])
            continue
        if r.status != 200:
            raise net.NetError(f"http_{r.status}")
        return r.body
    raise net.NetError("too_many_redirects")

def save(name, filename, data: bytes, url_shown, rows, manifest):
    LINKLISTS_DIR.mkdir(parents=True, exist_ok=True)
    (LINKLISTS_DIR / filename).write_bytes(data)
    manifest[name] = {"file": filename, "url": url_shown, "licence": LICENCE[name], "downloaded_utc": now_utc(),
                      "sha256": hashlib.sha256(data).hexdigest(), "rows": rows}
    print(f"  {name}: {rows:,} rows -> {filename}")


def pull_tranco(manifest):
    with zipfile.ZipFile(io.BytesIO(get(TRANCO_URL))) as z:
        data = z.read("top-1m.csv")
    save("tranco", "tranco_top1m.csv", data, TRANCO_URL, data.count(b"\n"), manifest)

def pull_openphish(manifest):
    data = get(OPENPHISH_URL, max_bytes=50_000_000)
    save("openphish", "openphish.txt", data, OPENPHISH_URL, sum(1 for l in data.splitlines() if l.strip()), manifest)

def pull_urlhaus(manifest):
    key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if not key:
        print("  urlhaus: skipped, URLHAUS_AUTH_KEY is not set (the app will say: couldn't verify, no URLhaus key)")
        manifest.pop("urlhaus", None)
        return
    try:
        data = get(URLHAUS_URL.format(key=key))
    except net.NetError as e:
        print(f"  urlhaus: failed ({e.status})")   # the status word only: the URL holds the key
        return
    finally:
        key = None
    if data[:2] == b"PK":   # some exports come zipped
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            data = z.read(z.namelist()[0])
    rows = sum(1 for l in data.splitlines() if l.strip() and not l.startswith(b"#"))
    save("urlhaus", "urlhaus_recent.csv", data, URLHAUS_URL.format(key="<URLHAUS_AUTH_KEY>"), rows, manifest)

def pull_rdap(manifest):
    data = get(RDAP_BOOTSTRAP_URL, max_bytes=5_000_000)
    services = json.loads(data)["services"]
    save("rdap_bootstrap", "rdap_dns.json", data, RDAP_BOOTSTRAP_URL, sum(len(s[0]) for s in services), manifest)

def pull_ip2asn(manifest):
    data = get(IP2ASN_URL, max_bytes=100_000_000)
    save("ip2asn", "ip2asn-v4.tsv.gz", data, IP2ASN_URL, gzip.decompress(data).count(b"\n"), manifest)


def verify_brand_tlds():
    gtlds = {g["gTLD"]: g for g in json.loads(get(ICANN_GTLDS_URL, max_bytes=20_000_000))["gTLDs"]}
    delegated = {l.strip().lower() for l in get(IANA_TLDS_URL, max_bytes=1_000_000).decode().splitlines() if l and not l.startswith("#")}
    kept, dropped = [], []
    for tld, brand, owner in BRAND_TLD_CANDIDATES:
        owners = [o.lower() for o in (owner if isinstance(owner, tuple) else (owner,))]
        g, why = gtlds.get(tld), None
        if tld not in delegated:
            why = "not in IANA's TLD list"
        elif g is None:
            why = "not in ICANN's gtlds.json"
        elif not g.get("specification13"):
            why = "not a Specification 13 (.brand) TLD"
        elif g.get("contractTerminated") or g.get("removalDate"):
            why = "contract terminated or removed"
        elif not any(o in (g.get("registryOperator") or "").lower() for o in owners):
            why = f"registryOperator is {g.get('registryOperator')!r}"
        manager = None
        if why is None:
            try:
                html = get(IANA_ROOT_DB.format(tld=tld), max_bytes=2_000_000).decode("utf-8", "replace")
            except net.NetError as e:
                why = f"IANA page: {e.status}"
            else:
                m = re.search(r">\s*Manager\s*</div>.*?<h2>\s*([^<]+?)\s*</h2>", html, re.S)   # the 'Manager' row's organisation
                manager = m.group(1).strip() if m else ""
                if not any(o in manager.lower() for o in owners):
                    why = f"IANA manager is {manager!r}"
        if why:
            dropped.append((tld, why))
            continue
        kept.append({"tld": tld, "brand": brand, "registry_operator": g["registryOperator"], "iana_manager": manager,
                     "specification13": True, "delegation_date": g.get("delegationDate")})
    out = {"verified_utc": now_utc(), "sources": [ICANN_GTLDS_URL, IANA_TLDS_URL, IANA_ROOT_DB.format(tld="<tld>")],
           "rule": "specification13 true, not terminated / removed, registryOperator and IANA manager contain the expected owner, delegated",
           "tlds": kept}
    BRAND_TLDS_PATH.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"  brand TLDs: kept {len(kept)} ({', '.join('.' + k['tld'] for k in kept)}) -> {BRAND_TLDS_PATH.name}")
    for tld, why in dropped:
        print(f"    dropped .{tld}: {why}")


STEPS = {"tranco": pull_tranco, "openphish": pull_openphish, "urlhaus": pull_urlhaus, "rdap_bootstrap": pull_rdap, "ip2asn": pull_ip2asn}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="+", choices=[*STEPS, "brand_tlds"])
    args = ap.parse_args()
    todo = args.only or [*STEPS, "brand_tlds"]
    path = LINKLISTS_DIR / "manifest.json"
    manifest = json.loads(path.read_text()) if path.exists() else {}
    failed = []
    for name in todo:
        try:
            verify_brand_tlds() if name == "brand_tlds" else STEPS[name](manifest)
        except net.NetError as e:
            print(f"  {name}: failed ({e.status})")
            failed.append(name)
    LINKLISTS_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=1) + "\n")
    if failed:
        sys.exit(f"failed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
