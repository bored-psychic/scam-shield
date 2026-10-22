import base64, concurrent.futures as cf, datetime as dt, hashlib, json, os, threading, time
from collections import OrderedDict
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from shield import config
from shield.core import net
from shield.links.lookalike import link_domain, raw_ip
from shield.links.platforms import SHORTENERS, platform_of, suffix_match

# The live link checks (decision D23, signals 7-11). Every call goes through shield.core.net (allowlist, https, no redirects, <= 2 s), and
# only a registered domain leaves the machine (for Safe Browsing: 4-byte hash prefixes of the host's names; for the expand button: the short
# link, to its shortener). The link's own server or IP is never contacted. A message gets MESSAGE_DEADLINE seconds in all; the checks of all
# its links run in parallel and whatever has not answered by then is "timed out". Results live in an in-process cache (no disk, no log).
MESSAGE_DEADLINE = 4.0
MAX_WORKERS = 8
MAX_HOPS = 3                  # shortener -> shortener hops followed; the first non-shortener host is the destination and is never requested
DOH_URL = "https://cloudflare-dns.com/dns-query"
CRTSH_URL = "https://crt.sh/"
SB_URL = "https://safebrowsing.googleapis.com/v5/hashes:search"
TTL = {"rdap": 24 * 3600, "dns": 3600, "crtsh": 24 * 3600, "sb": 1800, "expand": 3600}   # seconds; failures are never cached


class _Cache:
    """A small thread-safe LRU with per-entry expiry, in memory only."""
    def __init__(self, size=2000):
        self.size, self.data, self.lock = size, OrderedDict(), threading.Lock()

    def get(self, key):
        with self.lock:
            v = self.data.get(key)
            if v is None or v[0] < time.monotonic():
                self.data.pop(key, None)
                return None
            self.data.move_to_end(key)
            return v[1]

    def put(self, key, value, ttl):
        with self.lock:
            self.data[key] = (time.monotonic() + ttl, value)
            self.data.move_to_end(key)
            while len(self.data) > self.size:
                self.data.popitem(last=False)

    def clear(self):
        with self.lock:
            self.data.clear()

CACHE = _Cache()


def _left(deadline):
    return deadline - time.monotonic()

def _date(s):
    try:
        t = dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        # crt.sh writes "2026-10-16T00:00:00" with no zone and means UTC; astimezone() on a naive value would read it as the machine's local time
        return (t.replace(tzinfo=dt.timezone.utc) if t.tzinfo is None else t.astimezone(dt.timezone.utc)).date()
    except (TypeError, ValueError):
        return None

def _failed(e, sent):
    return {"status": "failed", "why": e.status if isinstance(e, net.NetError) else "bad_response", "sent": sent}


# ------------------------------------------------------------ 7. RDAP (+ 9. crt.sh when RDAP has no registration date)
def rdap(reg, base, deadline):
    """{"status": ok | not_found | unsupported | failed, created, expires, registrar, statuses, sent}"""
    if not base:
        return {"status": "unsupported", "sent": None}
    if (hit := CACHE.get(("rdap", reg))):
        return hit
    host = urlsplit(base).hostname
    sent = f"domain {reg} → {host} (registry)"
    try:
        r = net.request(base + "domain/" + quote(reg), timeout=_left(deadline), headers={"Accept": "application/rdap+json, application/json"})
        if r.status == 404:
            out = {"status": "not_found", "sent": sent}
        elif r.status != 200:
            return _failed(net.NetError(f"http_{r.status}"), sent)
        else:
            j = json.loads(r.body)
            ev = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", []) if isinstance(e, dict)}
            registrar = None
            for ent in j.get("entities", []):
                if "registrar" in (ent.get("roles") or []):
                    for item in (ent.get("vcardArray") or [None, []])[1]:
                        if item and item[0] == "fn":
                            registrar = str(item[3])[:80]
            out = {"status": "ok", "created": _date(ev.get("registration")), "expires": _date(ev.get("expiration")), "registrar": registrar,
                   "statuses": [str(s) for s in j.get("status", [])][:6], "sent": sent}
    except net.NetError as e:
        return _failed(e, sent)
    except (ValueError, TypeError, AttributeError, IndexError):
        return _failed(None, sent)
    CACHE.put(("rdap", reg), out, TTL["rdap"])
    return out

def crtsh(reg, deadline):
    """{"status": ok | none | failed, first (date of the first certificate ever logged for the domain), sent}"""
    if (hit := CACHE.get(("crtsh", reg))):
        return hit
    sent = f"domain {reg} → crt.sh (certificate log)"
    try:
        r = net.request(CRTSH_URL, params={"q": reg, "output": "json"}, timeout=_left(deadline), max_bytes=3_000_000)
        if r.status != 200:
            return _failed(net.NetError(f"http_{r.status}"), sent)
        dates = [d for c in json.loads(r.body or b"[]") if (d := _date(c.get("not_before")))]
    except net.NetError as e:
        return _failed(e, sent)
    except (ValueError, TypeError, AttributeError):
        return _failed(None, sent)
    out = {"status": "ok", "first": min(dates), "sent": sent} if dates else {"status": "none", "sent": sent}
    CACHE.put(("crtsh", reg), out, TTL["crtsh"])
    return out

def registration(reg, base, deadline):
    out = {"rdap": rdap(reg, base, deadline)}
    if not out["rdap"].get("created") and config.CRTSH_CHECK:   # D2 / D23: crt.sh only when the registry gave no registration date, and only when switched on (C1: off by default)
        out["crtsh"] = crtsh(reg, deadline)
    return out


# ------------------------------------------------------------ 8. DNS over HTTPS (the IP is looked up, never contacted)
def dns(reg, deadline):
    """{"status": ok | nxdomain | failed, ips, sent}. Only the registered domain is looked up, never the full host."""
    if (hit := CACHE.get(("dns", reg))):
        return hit
    sent = f"domain {reg} → cloudflare-dns.com (DNS)"
    try:
        r = net.request(DOH_URL, params={"name": reg, "type": "A"}, headers={"Accept": "application/dns-json"}, timeout=_left(deadline),
                        max_bytes=200_000)
        if r.status != 200:
            return _failed(net.NetError(f"http_{r.status}"), sent)
        j = json.loads(r.body)
    except net.NetError as e:
        return _failed(e, sent)
    except ValueError:
        return _failed(None, sent)
    if j.get("Status") == 3:
        out = {"status": "nxdomain", "ips": [], "sent": sent}
    elif j.get("Status") != 0:
        return _failed(net.NetError("bad_response"), sent)
    else:
        out = {"status": "ok", "ips": [a["data"] for a in j.get("Answer", []) if a.get("type") == 1][:8], "sent": sent}
    CACHE.put(("dns", reg), out, TTL["dns"])
    return out


# ------------------------------------------------------------ 10. Google Safe Browsing v5 (hash prefixes only; only with SAFE_BROWSING_KEY)
def sb_expressions(host, reg):
    """The host-level URL expressions Safe Browsing defines (path "/" only, as D23 sends no path): the exact host, and up to four names
    from the registered domain upward. An IP host is checked as itself only."""
    if raw_ip(host):
        return [host + "/"]
    labels, n = host.split("."), len(reg.split("."))
    names = [".".join(labels[i:]) for i in range(len(labels) - n, -1, -1)][:4]
    if host not in names:
        names.append(host)
    return [h + "/" for h in names]

def safe_browsing(host, reg, deadline):
    """{"status": ok | skipped | failed, threats, sent}. Skipped (no row shown) when SAFE_BROWSING_KEY is not set."""
    key = os.environ.get("SAFE_BROWSING_KEY", "").strip()
    if not key:
        return {"status": "skipped", "sent": None}
    if (hit := CACHE.get(("sb", host))):
        return hit
    full = {hashlib.sha256(e.encode()).digest(): e for e in sb_expressions(host, reg)}
    prefixes = [base64.b64encode(h[:4]).decode() for h in full]
    sent = f"{len(prefixes)} hash prefixes of {host} → safebrowsing.googleapis.com"
    try:
        r = net.request(SB_URL, params=[("key", key)] + [("hashPrefixes", p) for p in prefixes], headers={"Accept": "application/json"},
                        timeout=_left(deadline), max_bytes=500_000)
        if r.status != 200:
            return _failed(net.NetError(f"http_{r.status}"), sent)
        j = json.loads(r.body or b"{}")
        threats = sorted({d.get("threatType", "UNSPECIFIED") for fh in j.get("fullHashes", [])
                          if base64.b64decode(fh.get("fullHash", "")) in full for d in fh.get("fullHashDetails", [{}])})
    except net.NetError as e:
        return _failed(e, sent)
    except (ValueError, TypeError, AttributeError):
        return _failed(None, sent)
    finally:
        key = None
    out = {"status": "ok", "threats": threats, "sent": sent}
    CACHE.put(("sb", host), out, TTL["sb"])
    return out


# ------------------------------------------------------------ 11. shortener expansion (button only)
def expand(url, deadline):
    """{"status": ok | no_redirect | too_many_hops | failed, destination, hops, sent}. Asks only listed shorteners where their link points
    (HEAD, or GET when HEAD is refused; redirects off), hop by hop while the next host is again a shortener; the destination is never requested."""
    if (hit := CACHE.get(("expand", url))):
        return hit
    cur, hops, sent = url if "://" in url else "https://" + url, [], []
    for _ in range(MAX_HOPS):
        s = urlsplit(cur)
        cur = urlunsplit(("https", s.netloc, s.path, s.query, ""))   # shorteners answer on https; never a fragment
        host = (s.hostname or "").lower()
        sent.append(f"short link {host}{s.path} → {host}")
        try:
            r = net.request(cur, "expand", method="HEAD", timeout=_left(deadline))
            if r.status in (400, 403, 405) or (r.status == 200 and "location" not in r.headers):
                r = net.request(cur, "expand", method="GET", timeout=_left(deadline), max_bytes=200_000)
        except net.NetError as e:
            return {"status": "failed", "why": e.status, "hops": hops, "sent": "; ".join(sent)}
        loc = r.headers.get("location")
        if r.status not in (301, 302, 303, 307, 308) or not loc:
            return {"status": "no_redirect", "why": f"http_{r.status}", "hops": hops, "sent": "; ".join(sent)}
        nxt = urljoin(cur, loc)
        hops.append(nxt)
        nhost = (urlsplit(nxt).hostname or "").lower()
        if not suffix_match(nhost, SHORTENERS):
            out = {"status": "ok", "destination": nxt, "hops": hops, "sent": "; ".join(sent)}
            CACHE.put(("expand", url), out, TTL["expand"])
            return out
        cur = nxt
    return {"status": "too_many_hops", "hops": hops, "sent": "; ".join(sent)}


# ------------------------------------------------------------ the per-message run
def plan(url):
    """Which network checks a link gets: (host, registered domain, [check names]). Shorteners get none until the button is pressed; a
    platform host (free hosting, user content) gets only Safe Browsing, because registry and DNS facts would describe the platform."""
    host, reg = link_domain(url)
    if not host or suffix_match(host, SHORTENERS):
        return host, reg, []
    if raw_ip(host) or platform_of(host):
        return host, reg, ["sb"]
    return host, reg, ["registration", "dns", "sb"]

def _domain_jobs(host, reg, checks, lists, deadline):
    jobs = {}
    if "registration" in checks:
        jobs["registration"] = (registration, reg, lists.rdap_base(reg), deadline)
    if "dns" in checks:
        jobs["dns"] = (dns, reg, deadline)
    if "sb" in checks:
        jobs["sb"] = (safe_browsing, host, reg, deadline)
    return jobs

def run(urls, lists, expand_urls=(), deadline_s=MESSAGE_DEADLINE):
    """{url: {"registration" | "dns" | "sb" | "expand" | "dest": result}} for the given links; "dest" holds the same checks for a revealed
    destination. A check that has not answered within deadline_s (counted from the call) is {"status": "failed", "why": "timeout"}."""
    deadline = time.monotonic() + deadline_s
    out = {u: {} for u in urls}
    pool = cf.ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="linkcheck")
    running = {}   # future -> (url, check name, for the destination?)
    try:
        for u in urls:
            host, reg, checks = plan(u)
            for name, (fn, *args) in _domain_jobs(host, reg, checks, lists, deadline).items():
                running[pool.submit(fn, *args)] = (u, name, False)
            if u in expand_urls and suffix_match(host, SHORTENERS):
                running[pool.submit(expand, u, deadline)] = (u, "expand", False)
        while running and _left(deadline) > 0:
            done, _ = cf.wait(running, timeout=_left(deadline), return_when=cf.FIRST_COMPLETED)
            for f in done:
                u, name, dest = running.pop(f)
                try:
                    res = f.result()
                except Exception:   # a bug in a parser must not fail the analysis: the check just could not be verified
                    res = _failed(None, None)
                if name == "registration" and "rdap" not in res:
                    res = {"rdap": res}
                (out[u].setdefault("dest", {}) if dest else out[u])[name] = res
                if name == "expand" and res.get("status") == "ok":   # check the revealed domain exactly like a link in the message
                    dhost, dreg, dchecks = plan(res["destination"])
                    out[u]["dest"] = {"host": dhost, "reg": dreg}
                    for dname, (fn, *args) in _domain_jobs(dhost, dreg, dchecks, lists, deadline).items():
                        running[pool.submit(fn, *args)] = (u, dname, True)
        for f, (u, name, dest) in running.items():
            late = {"status": "failed", "why": "timeout", "sent": None}
            (out[u].setdefault("dest", {}) if dest else out[u])[name] = {"rdap": late} if name == "registration" else late
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return out
