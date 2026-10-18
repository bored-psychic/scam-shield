import contextlib, datetime as dt, io, json, logging, os, socket, sys, time
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_links_live.py")))
sys.path[:0] = [os.path.join(HERE, "..", "src"), HERE]
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from shield.contracts import Level, Report
from shield.core import net
from shield.core import router
from shield.core.report import to_report
from shield.core.router import analyse
from shield.links import live
from shield.links.lexical import load_url_model
from shield.links.lists import LinkLists
from shield.links.lookalike import link_domain, lookalike
from shield.links.platforms import SHORTENERS
from shield.messages.text_head import load_text_model

# python tests/test_links_live.py   (from the project root; needs both models). Decision D23 (safe link checks). EVERY network call is answered by
# an httpx.MockTransport (net.set_transport), and a socket guard refuses and records any real connection or lookup for the whole run (L13).
# The lists come from tests/fixtures/linklists/ (committed, tiny, test data only), read with a fixed "now" so they never go stale.
#   L1  lookalikes: sbi-kyc-update.top, hdfcbank-verify.com, paytm-refund.in flagged; sbi.co.in, onlinesbi.sbi, hdfcbank.com not (+ a few edges)
#   L2  the Jio promo: t.jio is Jio's own (P1) -> Suspicious (was Likely scam); not with a mobile number in the text, not with a hard-risk signal
#   L3  offline flags: punycode homograph -> Likely scam (R3), raw IP -> Suspicious (R5), abuse TLD -> a note only, no level change; .bank.in = P1
#   L4  blocklists (R1): host, platform page (only that page), shortener link; stale list -> "couldn't verify (list out of date)"; no URLhaus -> named
#   L5  live: RDAP 3 days -> R7 Suspicious; + lookalike -> R9 Likely scam; shared IP (non-CDN) -> R6, a CDN IP -> no R6; crt.sh only without an RDAP
#       date (R8); Safe Browsing only with SAFE_BROWSING_KEY, hash prefixes only (R2); P1 links: age never a flag
#   L6  failures: offline / timeout -> "Couldn't verify (...)", status failed, never reassuring, level as offline; the 4 s deadline holds
#   L7  net.py: only allowlisted https hosts, no IP literals, no redirects followed, update hosts refused after forbid_updates()
#   L8  the message text never appears in any outbound request; only the registered domain (or hash prefixes / the short link) does
#   L9  the expand button: bit.ly -> 301 -> destination checks apply to the short link; the destination host is never requested; 2 hops; no Location
#   L10 API: live / expand fields (expand must be a short link of this text, with live) -> 422 otherwise; Report v4 with link facts
#   L11 no domain, URL or IP in any log record or on stdout / stderr during live checks (DEBUG everywhere)
#   L12 the in-memory cache: a repeated live run sends nothing new; nothing is written to disk
#   L13 no real network: the socket guard saw 0 attempts
#   L14 the offline call (live=False) makes no transport call at all and marks the live checks pending
FIXTURES = Path(HERE) / "fixtures" / "linklists"
NOW = dt.datetime(2026, 10, 18, 6, 0, tzinfo=dt.timezone.utc)
TODAY = NOW.date()
JIO = "Dear User,\nYou've earned Lifetime Free\nKiwi UPI Credit Card (CC:\nJIOKIWI) on JioRecharge.\nClaim now:\nhttps://t.jio/JIOCPN/x48NuN\nT&C*\nJioCoupons"
MARK = "ZQXJMARKERWORD"


class Net:
    """A fake internet: RDAP answers by domain, DoH answers by domain, crt.sh, Safe Browsing, shorteners. Records every request."""
    def __init__(self, created=None, ips=None, crt=None, sb_hit=None, redirects=None, fail=None, slow=0.0):
        self.created, self.ips, self.crt, self.sb_hit = created or {}, ips or {}, crt or {}, sb_hit or set()
        self.redirects, self.fail, self.slow, self.seen = redirects or {}, fail, slow, []

    def __call__(self, req: httpx.Request):
        self.seen.append(req)
        if self.slow:
            time.sleep(self.slow)
        if self.fail:
            raise self.fail("fixture failure", request=req)
        host, path = req.url.host, req.url.path
        if host.startswith("rdap.fixture"):
            dom = path.rsplit("/", 1)[-1]
            if dom not in self.created:
                return httpx.Response(404, json={"errorCode": 404})
            c = self.created[dom]
            ev = [{"eventAction": "expiration", "eventDate": f"{(c or TODAY).year + 1}-01-01T00:00:00Z"}]
            if c:
                ev.append({"eventAction": "registration", "eventDate": f"{c.isoformat()}T10:00:00Z"})
            return httpx.Response(200, json={"objectClassName": "domain", "ldhName": dom, "events": ev, "status": ["active"],
                                             "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Fixture Registrar Ltd"]]]}]})
        if host == "cloudflare-dns.com":
            dom = req.url.params["name"]
            ips = self.ips.get(dom)
            if ips is None:
                return httpx.Response(200, json={"Status": 3})
            return httpx.Response(200, json={"Status": 0, "Answer": [{"name": dom, "type": 1, "data": ip} for ip in ips]})
        if host == "crt.sh":
            first = self.crt.get(req.url.params["q"])
            return httpx.Response(200, json=[{"not_before": f"{first.isoformat()}T00:00:00"}] if first else [])
        if host == "safebrowsing.googleapis.com":
            import base64, hashlib
            hits = []
            for p in req.url.params.get_list("hashPrefixes"):
                for expr in self.sb_hit:
                    full = hashlib.sha256(expr.encode()).digest()
                    if base64.b64encode(full[:4]).decode() == p:
                        hits.append({"fullHash": base64.b64encode(full).decode(), "fullHashDetails": [{"threatType": "SOCIAL_ENGINEERING"}]})
            return httpx.Response(200, json={"fullHashes": hits, "cacheDuration": "300s"})
        if host in self.redirects:
            target = self.redirects[host]
            return httpx.Response(301, headers={"Location": target}) if target else httpx.Response(200, text="interstitial page")
        return httpx.Response(599, text="the fixture internet has no such host")   # anything else is a bug: L8 / L9 look for it


@contextlib.contextmanager
def fixture(fake=None, sb_key=None):
    """Fixture lists + the fake internet + a fresh cache; SAFE_BROWSING_KEY set only when sb_key is given."""
    lists = LinkLists(root=FIXTURES, now=NOW)
    net.add_expand_hosts(SHORTENERS)
    fake = fake or Net()
    saved_lists, saved_key = router.load_lists, os.environ.pop("SAFE_BROWSING_KEY", None)
    router.load_lists = lambda: lists
    if sb_key:
        os.environ["SAFE_BROWSING_KEY"] = sb_key
    net.set_transport(httpx.MockTransport(fake))
    live.CACHE.clear()
    try:
        yield fake, lists
    finally:
        net.set_transport(None)
        router.load_lists = saved_lists
        os.environ.pop("SAFE_BROWSING_KEY", None)
        if saved_key is not None:
            os.environ["SAFE_BROWSING_KEY"] = saved_key
        live.CACHE.clear()


def days_ago(n):
    return TODAY - dt.timedelta(days=n)

def child(rep, i=0):
    return rep.children[i]

def ev_ids(rep):
    return [e.id for c in rep.children for e in c.evidence]

def fact(c, key):
    return next((f for f in c.link.facts if f.key == key), None)


def l1(m):
    bad = []
    cases = {"sbi-kyc-update.top": True, "hdfcbank-verify.com": True, "paytm-refund.in": True, "sbi.co.in": False, "onlinesbi.sbi": False,
             "hdfcbank.com": False, "lesbian-news.com": False, "jiomart.com": False, "amaz0n-pay.in": True, "hdfcbnak-login.xyz": True,
             "secure.sbi-login.co.in": True, "sbi.bank.in": False, "incometax.gov.in": False}
    lists = LinkLists(root=FIXTURES, now=NOW)
    for d, want in cases.items():
        host, reg = link_domain("https://" + d)
        got = lookalike(host, reg, lists.tranco_rank(reg)) is not None
        if got != want:
            bad.append(f"{d}: flagged {got}, wanted {want}")
    with fixture():
        for d in ("sbi-kyc-update.top", "hdfcbank-verify.com", "paytm-refund.in"):
            rep = to_report(f"see https://{d}/x", analyse(f"see https://{d}/x", *m))
            if "link.lookalike" not in ev_ids(rep) or child(rep).level == Level.NO_WARNING_SIGNS:
                bad.append(f"{d}: link {child(rep).level.value}, evidence {ev_ids(rep)}")
    return bad

def l2(m):
    bad = []
    with fixture():
        r = analyse(JIO, *m)
        rep = to_report(JIO, r)
        c = child(rep)
        if rep.level != Level.SUSPICIOUS or r["positive_cap"] is None or r["hard_risks"]:
            bad.append(f"Jio: level {rep.level.value}, cap {r['positive_cap']}, hard risks {r['hard_risks']}")
        if "link.brand_owned" not in ev_ids(rep) or c.level != Level.NO_WARNING_SIGNS or "Jio" not in fact(c, "owner").value:
            bad.append(f"Jio link: {c.level.value}, evidence {ev_ids(rep)}, owner {fact(c, 'owner')}")
        with_mobile = JIO + "\nCall 9876543210 to activate"
        rep = to_report(with_mobile, analyse(with_mobile, *m))
        if rep.level != Level.LIKELY_SCAM:
            bad.append(f"Jio + a mobile number in the text: {rep.level.value}, wanted likely_scam (the P1 cap needs no mobile number)")
        otp = JIO + "\nShare the OTP sent to you to claim."
        r = analyse(otp, *m)
        if to_report(otp, r).level != Level.LIKELY_SCAM or "otp_request" not in r["hard_risks"] or r["positive_cap"]:
            bad.append(f"Jio + OTP request: {r['level']}, hard risks {r['hard_risks']}, cap {r['positive_cap']}")
    return bad

def l3(m):
    bad = []
    with fixture():
        for text, want_link, want_id in (("Login: https://xn--pple-43d.com/id", Level.LIKELY_SCAM, "link.homograph"),
                                         ("Pay here http://192.0.2.10/upi", None, "link.raw_ip"),
                                         ("Our menu is at https://zqxj-cafe.icu/menu", None, "link.abuse_tld")):
            rep = to_report(text, analyse(text, *m))
            c = child(rep)
            if want_id not in ev_ids(rep):
                bad.append(f"{text}: no {want_id} in {ev_ids(rep)}")
            if want_link and c.level != want_link:
                bad.append(f"{text}: link {c.level.value}, wanted {want_link.value}")
            if want_id == "link.raw_ip" and c.level not in (Level.SUSPICIOUS, Level.LIKELY_SCAM):
                bad.append(f"raw IP link {c.level.value}")
        # an abuse TLD is a note: the same message without it must have the same level
        a, b = "Our menu is at https://zqxj-cafe.icu/menu", "Our menu is at https://zqxj-cafe.com/menu"
        la, lb = analyse(a, *m), analyse(b, *m)
        if la["links"][0]["flags"] or la["links"][0]["risk_level"] != la["links"][0]["base_level"]:
            bad.append(f"abuse TLD changed the link level: flags {la['links'][0]['flags']}")
        # .bank.in = P1
        t = "Your statement is ready: https://sbi.bank.in/statement"
        r = analyse(t, *m)
        if r["links"][0]["positive"] != "p1" or "link.bank_in" not in ev_ids(to_report(t, r)):
            bad.append(f".bank.in: positive {r['links'][0]['positive']}, evidence {ev_ids(to_report(t, r))}")
    return bad

def l4(m):
    bad = []
    with fixture():
        for text, want in (("http://zqxj-listed-phish.top/login now", True), ("Fill https://docs.google.com/forms/d/e/zqxjlistedform/viewform", True),
                           ("Fill https://docs.google.com/forms/d/e/anotherform/viewform", False), ("Open https://bit.ly/zqxjlisted", True),
                           ("Get http://zqxj-malware-host.xyz/payload.apk", True)):
            rep = to_report(text, analyse(text, *m))
            got = "link.listed" in ev_ids(rep)
            if got != want or (want and child(rep).level != Level.LIKELY_SCAM):
                bad.append(f"{text}: listed {got} (wanted {want}), link {child(rep).level.value}")
        c = child(to_report("http://zqxj-listed-phish.top/login", analyse("http://zqxj-listed-phish.top/login", *m)))
        if fact(c, "lists").effect.value != "danger" or "OpenPhish" not in fact(c, "lists").value:
            bad.append(f"lists fact {fact(c, 'lists')}")
    stale = LinkLists(root=FIXTURES, now=NOW + dt.timedelta(days=9))
    if stale.blocklist_problems() != {"OpenPhish": "list out of date", "URLhaus": "list out of date"} or stale.listed("http://zqxj-listed-phish.top/x", "zqxj-listed-phish.top"):
        bad.append(f"stale lists: {stale.blocklist_problems()}")
    key = os.environ.pop("URLHAUS_AUTH_KEY", None)
    try:
        import tempfile, shutil
        with tempfile.TemporaryDirectory() as tmp:   # a copy of the fixtures without the URLhaus file (the test's own temp dir)
            for f in FIXTURES.iterdir():
                if f.name != "urlhaus_recent.csv":
                    shutil.copy(f, tmp)
            no_uh = LinkLists(root=Path(tmp), now=NOW)
            if no_uh.blocklist_problems() != {"URLhaus": "no URLhaus key"}:
                bad.append(f"no URLhaus file and no key: {no_uh.blocklist_problems()}")
    finally:
        if key is not None:
            os.environ["URLHAUS_AUTH_KEY"] = key
    return bad

def l5(m):
    bad = []
    fake = Net(created={"zqxj-newshop.com": days_ago(3), "sbi-zqxj-kyc.top": days_ago(2), "zqxj-oldshop.com": days_ago(3000), "t.jio": days_ago(1),
                        "zqxj-shared.com": days_ago(900), "zqxj-cdn.com": days_ago(900), "zqxj-nodate.com": None},
               ips={"zqxj-newshop.com": ["192.0.2.5"], "zqxj-oldshop.com": ["192.0.2.6"], "zqxj-shared.com": ["198.51.100.77"],
                    "zqxj-cdn.com": ["203.0.113.66"], "zqxj-nodate.com": ["192.0.2.7"], "t.jio": ["1.0.0.1"]},
               crt={"zqxj-nodate.com": days_ago(2)})
    with fixture(fake):
        def go(text):
            r = analyse(text, *m, live=True)
            return r, to_report(text, r)
        r, rep = go("Order at https://zqxj-newshop.com/sale")
        if r["links"][0]["flags"] != ["R7"] or child(rep).level != Level.SUSPICIOUS or fact(child(rep), "age").effect.value != "caution":
            bad.append(f"3-day-old domain: flags {r['links'][0]['flags']}, link {child(rep).level.value}")
        r, _ = go("Verify at https://sbi-zqxj-kyc.top/login")
        if sorted(r["links"][0]["flags"]) != ["R4", "R7", "R9"] or r["links"][0]["risk_level"] != 2 or r["level"] != 2:
            bad.append(f"lookalike + new: flags {r['links'][0]['flags']}, link {r['links'][0]['risk_level']}, message {r['level']}")
        r, rep = go("Order at https://zqxj-oldshop.com/sale")
        if r["links"][0]["flags"] or "FIXTURE-INDIA-HOSTING" not in fact(child(rep), "server").value or "India" not in fact(child(rep), "server").value:
            bad.append(f"old domain: flags {r['links'][0]['flags']}, server {fact(child(rep), 'server')}")
        r, _ = go("See https://zqxj-shared.com/a")
        if r["links"][0]["flags"] != ["R6"]:
            bad.append(f"shared non-CDN IP: flags {r['links'][0]['flags']}")
        r, _ = go("See https://zqxj-cdn.com/a")
        if r["links"][0]["flags"]:
            bad.append(f"listed IP on a CDN network: flags {r['links'][0]['flags']} (R6 must not fire)")
        crt_calls = [q for q in fake.seen if q.url.host == "crt.sh"]
        if [q.url.params["q"] for q in crt_calls]:
            bad.append(f"crt.sh asked although RDAP had a date: {[q.url.params['q'] for q in crt_calls]}")
        r, rep = go("See https://zqxj-nodate.com/a")
        if r["links"][0]["flags"] != ["R8"] or [q.url.params["q"] for q in fake.seen if q.url.host == "crt.sh"] != ["zqxj-nodate.com"]:
            bad.append(f"no RDAP date -> crt.sh fallback: flags {r['links'][0]['flags']}")
        r, rep = go(JIO)   # registered "1 day ago" in the fake registry: a .brand name's age is never a flag
        if r["links"][0]["flags"] or rep.level != Level.SUSPICIOUS:
            bad.append(f"Jio live: flags {r['links'][0]['flags']}, level {rep.level.value}")
        if any(q.url.host == "safebrowsing.googleapis.com" for q in fake.seen):
            bad.append("Safe Browsing was asked without SAFE_BROWSING_KEY")
    fake = Net(created={"zqxj-sbhit.com": days_ago(900)}, ips={"zqxj-sbhit.com": ["192.0.2.8"]}, sb_hit={"zqxj-sbhit.com/"})
    with fixture(fake, sb_key="fixture-key-123"):
        r = analyse("Open https://www.zqxj-sbhit.com/page", *m, live=True)
        sb = [q for q in fake.seen if q.url.host == "safebrowsing.googleapis.com"]
        if r["links"][0]["flags"] != ["R2"] or r["links"][0]["risk_level"] != 2:
            bad.append(f"Safe Browsing hit: flags {r['links'][0]['flags']}")
        if not sb or any("zqxj" in str(q.url) or "page" in str(q.url) for q in sb):
            bad.append(f"Safe Browsing request carries the name or path in clear: {[str(q.url) for q in sb]}")
        if any(len(__import__('base64').b64decode(p)) != 4 for q in sb for p in q.url.params.get_list("hashPrefixes")):
            bad.append("a Safe Browsing prefix is not 4 bytes")
    return bad

def l6(m):
    bad = []
    text = "Order at https://zqxj-newshop.com/sale"
    off = analyse(text, *m)
    for fail, word in ((httpx.ConnectError, "offline"), (httpx.ReadTimeout, "timed out")):
        with fixture(Net(fail=fail)):
            r = analyse(text, *m, live=True)
            rep = to_report(text, r)
            c = child(rep)
            for key in ("age", "server"):
                f = fact(c, key)
                if f is None or f.status != "failed" or f.effect.value == "reassuring" or f.value != f"Couldn't verify ({word})":
                    bad.append(f"{fail.__name__}: {key} fact {f}")
            if r["level"] != off["level"] or r["links"][0]["flags"]:
                bad.append(f"{fail.__name__}: level {r['level']} vs offline {off['level']}, flags {r['links'][0]['flags']}")
    with fixture(Net(created={"zqxj-newshop.com": days_ago(3)}, slow=1.0)):
        t0 = time.monotonic()
        res = live.run(["https://zqxj-newshop.com/sale"], router.load_lists(), deadline_s=0.3)
        took = time.monotonic() - t0
        if took > 0.8 or res["https://zqxj-newshop.com/sale"]["dns"].get("why") != "timeout":
            bad.append(f"deadline: took {took:.2f} s, dns {res['https://zqxj-newshop.com/sale']['dns']}")
    if live.MESSAGE_DEADLINE != 4.0 or net.CALL_TIMEOUT != 2.0:
        bad.append(f"deadline {live.MESSAGE_DEADLINE} s / call timeout {net.CALL_TIMEOUT} s, wanted 4 / 2")
    return bad

def l7(m):
    bad = []
    with fixture() as (fake, _):
        for url, kind in (("https://evil.example/x", "check"), ("http://crt.sh/", "check"), ("https://192.0.2.1/", "check"),
                          ("https://user@crt.sh/", "check"), ("https://crt.sh:8443/", "check"), ("https://bit.ly/x", "check"),
                          ("https://crt.sh/", "expand"), ("https://zqxj-dest.top/", "expand")):
            try:
                net.request(url, kind)
                bad.append(f"{kind} {url} was allowed")
            except net.NetError as e:
                if e.status != "refused":
                    bad.append(f"{kind} {url}: {e.status}")
        if fake.seen:
            bad.append(f"refused calls reached the transport: {[str(q.url) for q in fake.seen]}")
        fake.redirects["bit.ly"] = "https://zqxj-dest.top/"
        r = net.request("https://bit.ly/abc", "expand", method="HEAD")
        if r.status != 301 or [q.url.host for q in fake.seen] != ["bit.ly"]:
            bad.append(f"a redirect was followed: {[str(q.url) for q in fake.seen]}")
    saved = net._updates_forbidden
    net.forbid_updates()
    try:
        net.request("https://data.iana.org/rdap/dns.json", "update")
        bad.append("an update host was allowed after forbid_updates()")
    except net.NetError:
        pass
    finally:
        net._updates_forbidden = saved
    return bad

def l8(m):
    bad = []
    text = (f"{MARK} dear customer your account needs KYC {MARK}. Visit https://sbi-zqxj-kyc.top/login?u={MARK} and https://www.zqxj-oldshop.com/x "
            f"or https://bit.ly/zqxj{MARK.lower()} and https://docs.google.com/forms/d/e/zqxjform/viewform")
    fake = Net(created={"sbi-zqxj-kyc.top": days_ago(2), "zqxj-oldshop.com": days_ago(3000)},
               redirects={"bit.ly": "https://zqxj-dest.top/landing"})
    with fixture(fake, sb_key="fixture-key-123"):
        analyse(text, *m, live=True, expand=(f"https://bit.ly/zqxj{MARK.lower()}",))
    words = {w.lower() for w in ("dear", "customer", "account", "needs", "Visit", MARK, "login", "landing", "viewform")}   # none is part of a domain
    for q in fake.seen:
        blob = (str(q.url) + " " + " ".join(f"{k}:{v}" for k, v in q.headers.items()) + " " + q.content.decode("utf-8", "replace")).lower()
        if q.url.host == "bit.ly":
            blob = blob.replace(f"/zqxj{MARK.lower()}", "")   # the short link itself is what the expand button sends (D23)
        found = [w for w in words if w in blob]
        if found:
            bad.append(f"{q.method} {q.url.host}: message words {found} in the request")
        if q.url.host == "zqxj-dest.top" or q.url.host.endswith("zqxj-oldshop.com") and q.url.host != "cloudflare-dns.com":
            bad.append(f"the link's own server was contacted: {q.url.host}")
        if q.url.host == "cloudflare-dns.com" and q.url.params["name"] not in ("sbi-zqxj-kyc.top", "zqxj-oldshop.com", "zqxj-dest.top"):
            bad.append(f"DNS asked for {q.url.params['name']} (not a registered domain)")
    hosts = {q.url.host for q in fake.seen}
    allowed = {"cloudflare-dns.com", "crt.sh", "safebrowsing.googleapis.com", "bit.ly", "rdap.fixture-gtld.example", "rdap.fixture-registry.example"}
    if not hosts <= allowed:
        bad.append(f"requests to {sorted(hosts - allowed)}")
    return bad

def l9(m):
    bad = []
    fake = Net(created={"sbi-zqxj-dest.top": days_ago(400)}, ips={"sbi-zqxj-dest.top": ["192.0.2.9"]},
               redirects={"bit.ly": "https://tinyurl.com/zqxjhop", "tinyurl.com": "https://sbi-zqxj-dest.top/kyc", "cutt.ly": None})
    with fixture(fake):
        text = "Update KYC here https://bit.ly/zqxjabc"
        off = to_report(text, analyse(text, *m))
        if not child(off).link.expandable or fact(child(off), "destination").value is not None:
            bad.append(f"offline: expandable {child(off).link.expandable}, destination {fact(child(off), 'destination')}")
        r = analyse(text, *m, live=True, expand=("https://bit.ly/zqxjabc",))
        rep = to_report(text, r)
        c = child(rep)
        if c.link.destination != "https://sbi-zqxj-dest.top/kyc" or "R4" not in r["links"][0]["flags"] or c.level == Level.CANT_JUDGE:
            bad.append(f"expanded: destination {c.link.destination}, flags {r['links'][0]['flags']}, link {c.level.value}")
        if any(q.url.host == "sbi-zqxj-dest.top" for q in fake.seen):
            bad.append("the destination itself was requested")
        if [q.url.host for q in fake.seen if q.url.host in ("bit.ly", "tinyurl.com")] != ["bit.ly", "tinyurl.com"]:
            bad.append(f"hops asked: {[q.url.host for q in fake.seen]}")
        if not any(f.key.startswith("dest_") for f in c.link.facts):
            bad.append("no destination facts")
        text2 = "Offer https://cutt.ly/zqxjnone"
        c2 = child(to_report(text2, analyse(text2, *m, live=True, expand=("https://cutt.ly/zqxjnone",))))
        if fact(c2, "destination").status != "failed" or "Couldn't reveal" not in fact(c2, "destination").value:
            bad.append(f"no Location: {fact(c2, 'destination')}")
        # without the button, live checks do not touch the shortener
        n = len(fake.seen)
        live.CACHE.clear()
        analyse("Update KYC here https://bit.ly/zqxjother", *m, live=True)
        if any(q.url.host == "bit.ly" for q in fake.seen[n:]):
            bad.append("the shortener was asked without the button")
    return bad

def l10(m):
    from shield.api.main import app
    bad = []
    with fixture(Net(created={"zqxj-newshop.com": days_ago(3)})):
        with TestClient(app) as cl:
            router.load_lists = lambda: LinkLists(root=FIXTURES, now=NOW)   # the lifespan warmed the real lists; analyse() must read the fixture
            j = cl.post("/api/analyse", json={"text": "Order at https://zqxj-newshop.com/sale", "live": True}).json()
            rep = Report.model_validate(j)
            if rep.schema_version != "5" or child(rep).link is None or fact(child(rep), "age").status != "ok" or rep.pending:
                bad.append(f"live response: {j.get('schema_version')}, pending {rep.pending}")
            j = cl.post("/api/analyse", json={"text": "Order at https://zqxj-newshop.com/sale"}).json()
            if j["pending"] != ["links"] or j["children"][0]["pending"] != ["registration", "dns"]:
                bad.append(f"offline response pending {j['pending']} / {j['children'][0]['pending']}")
            for body in ({"text": "go https://zqxj-newshop.com/sale", "live": True, "expand": ["https://zqxj-newshop.com/sale"]},
                         {"text": "go https://bit.ly/zqxj", "live": True, "expand": ["https://bit.ly/other"]},
                         {"text": "go https://bit.ly/zqxj", "expand": ["https://bit.ly/zqxj"]},
                         {"text": "go https://bit.ly/a https://bit.ly/b https://bit.ly/c https://bit.ly/d", "live": True,
                          "expand": ["https://bit.ly/a", "https://bit.ly/b", "https://bit.ly/c", "https://bit.ly/d"]}):
                r = cl.post("/api/analyse", json=body)
                if r.status_code != 422:
                    bad.append(f"{body['expand']}: {r.status_code}")
    return bad

def l11(m):
    bad = []
    records, buf = [], io.StringIO()
    class Keep(logging.Handler):
        def emit(self, record):
            records.append(self.format(record) + " " + repr(record.args))
    h = Keep(level=logging.DEBUG)
    names = ["", "httpx", "httpcore", "uvicorn", "uvicorn.error", "shield", "concurrent.futures"]
    saved = [(logging.getLogger(n), logging.getLogger(n).level) for n in names]
    fake = Net(created={"zqxj-logmark.top": days_ago(3)}, ips={"zqxj-logmark.top": ["192.0.2.77"]}, redirects={"bit.ly": "https://zqxj-logdest.top/x"})
    try:
        for lg, _ in saved:
            lg.addHandler(h)
            lg.setLevel(logging.DEBUG)
        with fixture(fake, sb_key="fixture-key-123"), contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            analyse("pay at https://zqxj-logmark.top/pay or https://bit.ly/zqxjlog", *m, live=True, expand=("https://bit.ly/zqxjlog",))
        with fixture(Net(fail=httpx.ConnectError)), contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            analyse("pay at https://zqxj-logmark.top/pay", *m, live=True)
    finally:
        for lg, lvl in saved:
            lg.removeHandler(h)
            lg.setLevel(lvl)
    seen = "\n".join(records) + buf.getvalue()
    bad += [f"{w} in the logs / output" for w in ("zqxj", "192.0.2.77", "bit.ly", "fixture-key-123") if w in seen]
    return bad

def l12(m):
    bad = []
    fake = Net(created={"zqxj-oldshop.com": days_ago(3000)}, ips={"zqxj-oldshop.com": ["192.0.2.6"]})
    with fixture(fake):
        analyse("see https://zqxj-oldshop.com/a", *m, live=True)
        n = len(fake.seen)
        analyse("see https://zqxj-oldshop.com/b", *m, live=True)
        if len(fake.seen) != n or n != 2:
            bad.append(f"requests: first run {n}, second run {len(fake.seen) - n} (wanted 2 then 0)")
    return bad

def l14(m):
    bad = []
    with fixture() as (fake, _):
        text = "Order at https://zqxj-newshop.com/sale and https://bit.ly/zqxj"
        rep = to_report(text, analyse(text, *m))
        if fake.seen:
            bad.append(f"the offline call made {len(fake.seen)} requests")
        if rep.pending != ["links"] or child(rep).pending != ["registration", "dns"] or fact(child(rep), "age").status != "pending":
            bad.append(f"pending {rep.pending} / {child(rep).pending}")
    return bad


CHECKS = [("L1", "lookalike cases", l1), ("L2", "Jio: Jio-owned -> Suspicious; mobile number / OTP keep Likely scam", l2),
          ("L3", "offline flags R3 / R5, abuse TLD note only, .bank.in P1", l3), ("L4", "blocklists R1, page-only on platforms, stale / no key", l4),
          ("L5", "live R6 / R7 / R8 / R9 / R2, crt.sh fallback only, Safe Browsing only with a key", l5),
          ("L6", "failures -> couldn't verify, never safe; the deadline holds", l6), ("L7", "net.py allowlist, no redirects, no updates", l7),
          ("L8", "no message text in any outbound request; only allowed hosts", l8), ("L9", "expand button: hops, destination never requested", l9),
          ("L10", "API live / expand fields and validation", l10), ("L11", "no domain / URL / IP / key in logs", l11),
          ("L12", "in-memory cache", l12), ("L14", "offline call: no requests, pending marked", l14)]


@contextlib.contextmanager
def socket_guard():
    attempts, names = [], ("connect", "connect_ex")
    saved_methods = {n: socket.socket.__dict__.get(n) for n in names}
    saved_funcs = {n: getattr(socket, n) for n in ("create_connection", "getaddrinfo", "gethostbyname")}
    def refuse(name):
        def f(*a, **k):
            attempts.append(name)
            raise OSError(f"L13: real network blocked ({name})")
        return f
    try:
        for n in names:
            setattr(socket.socket, n, refuse(n))
        for n in saved_funcs:
            setattr(socket, n, refuse(n))
        yield attempts
    finally:
        for n, f in saved_methods.items():
            delattr(socket.socket, n) if f is None else setattr(socket.socket, n, f)
        for n, f in saved_funcs.items():
            setattr(socket, n, f)

def run():
    m = (load_text_model(), load_url_model())
    out = []
    with socket_guard() as attempts:
        for tid, what, fn in CHECKS:
            out.append((tid, what, fn(m)))
        out.append(("L13", "no real network during the whole run", [f"{len(attempts)} real connection / lookup attempts: {attempts[:5]}"] if attempts else []))
    return out

def test_links_live():
    bad = [f"{tid}: {b}" for tid, _, bs in run() for b in bs]
    assert not bad, "\n".join(bad)

if __name__ == "__main__":
    results = run()
    for tid, what, bad in results:
        print(f"{'FAIL' if bad else 'PASS'} {tid} {what}")
        for b in bad[:10]:
            print("    " + b.encode("ascii", "backslashreplace").decode()[:300])
    print(f"\n{sum(not b for _, _, b in results)}/{len(results)} passed")
    sys.exit(1 if any(b for _, _, b in results) else 0)
