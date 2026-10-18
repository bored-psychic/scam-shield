"""The only code in src/shield (and src/update_link_lists.py) that may talk to the network (CLAUDE.md rule 8, decision D23).

What goes out, and where:
  * checks  (the live link checks, src/shield/links/live.py): a registered domain to its TLD registry over RDAP (hosts from IANA's RDAP bootstrap
             file, added by add_check_hosts()), the same domain to Cloudflare DNS-over-HTTPS and, only when RDAP has no registration date, to crt.sh;
             4-byte hash prefixes to Google Safe Browsing when SAFE_BROWSING_KEY is set. The link's own server or IP is never contacted.
  * expand  (the "Where does this short link go?" button only): the short URL to a known link shortener, one request per hop, redirects off;
             the destination is never requested.
  * update  (src/update_link_lists.py only, refused once forbid_updates() is called, which the API does at start-up): the list hosts.

Every call: https only, the host must match an allowlist exactly, IP literals are refused, redirects are off, no cookies, proxies or .netrc
(trust_env=False), a fixed User-Agent, a timeout of at most 2 s (CALL_TIMEOUT) and a capped response size. Nothing is logged: the httpx /
httpcore loggers are switched off below, and a failure becomes a NetError with a fixed status word, never the exception's text (which
contains the URL). Tests swap the transport with set_transport() so no test touches the real network.
"""
import ipaddress
import logging

import httpx

CALL_TIMEOUT = 2.0             # seconds, per call (D23: <= 2 s per call, <= 4 s per message; the message deadline is live.py's)
USER_AGENT = "ScamShield-linkcheck/1 (student project; domain lookups only)"
UPDATE_TIMEOUT = 120.0         # list downloads (update_link_lists.py) are large; never used by a check

CHECK_HOSTS = {"cloudflare-dns.com", "crt.sh", "safebrowsing.googleapis.com"}
UPDATE_HOSTS = {"tranco-list.eu", "openphish.com", "raw.githubusercontent.com", "urlhaus-api.abuse.ch", "data.iana.org", "www.iana.org", "www.icann.org", "iptoasn.com"}
_rdap_hosts: set[str] = set()      # filled from the RDAP bootstrap file by add_check_hosts()
_expand_hosts: set[str] = set()    # the link shorteners (shield.links.platforms.SHORTENERS), filled by add_expand_hosts()
_updates_forbidden = False
_transport = None                  # tests: an httpx.MockTransport

# Off for good: at INFO httpx writes "HTTP Request: GET <url>", at DEBUG httpcore writes the host it connects to.
for _name in ("httpx", "httpcore"):
    _lg = logging.getLogger(_name)
    _lg.setLevel(logging.CRITICAL + 1)
    _lg.propagate = False
    _lg.addFilter(lambda record: False)


class NetError(Exception):
    """A failed call. .status is one of: refused (not allowed: never sent), offline, timeout, http_<code>, too_large, bad_response.
    The message is the status word only, so it can never carry a URL into a log or a traceback."""
    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


class Response:
    def __init__(self, status: int, headers: dict, body: bytes, host: str):
        self.status, self.headers, self.body, self.host = status, headers, body, host


def add_check_hosts(hosts):
    _rdap_hosts.update(h.lower() for h in hosts)

def add_expand_hosts(hosts):
    _expand_hosts.update(h.lower() for h in hosts)

def forbid_updates():
    global _updates_forbidden
    _updates_forbidden = True

def set_transport(transport):
    """Tests only: route every call through this httpx transport (None = the real network)."""
    global _transport
    _transport = transport


def allowed(url: str, kind: str) -> str | None:
    """The host if url may be requested for this kind of call, else None."""
    try:
        u = httpx.URL(url)
    except Exception:
        return None
    host = (u.host or "").lower()
    if u.scheme != "https" or not host or u.userinfo or u.port not in (None, 443):
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return None                      # an IP literal is never requested, whatever the list says
    except ValueError:
        pass
    if kind == "check":
        ok = host in CHECK_HOSTS or host in _rdap_hosts
    elif kind == "expand":
        ok = host in _expand_hosts
    elif kind == "update":
        ok = host in UPDATE_HOSTS and not _updates_forbidden
    else:
        ok = False
    return host if ok else None


def request(url: str, kind: str = "check", *, method: str = "GET", params=None, headers=None, timeout: float = CALL_TIMEOUT,
            max_bytes: int = 2_000_000) -> Response:
    """One call, under the rules above. Raises NetError; never follows a redirect (a 3xx comes back as a Response)."""
    host = allowed(url, kind)
    if host is None:
        raise NetError("refused")
    if kind != "update":
        timeout = min(timeout, CALL_TIMEOUT)
    if timeout <= 0:
        raise NetError("timeout")
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    hdrs.update(headers or {})
    try:
        with httpx.Client(transport=_transport, follow_redirects=False, trust_env=False, timeout=timeout, cookies=None) as client:
            with client.stream(method, url, params=params, headers=hdrs) as r:
                body = bytearray()
                if method != "HEAD":
                    for chunk in r.iter_bytes():
                        body += chunk
                        if len(body) > max_bytes:
                            raise NetError("too_large")
                return Response(r.status_code, {k.lower(): v for k, v in r.headers.items()}, bytes(body), host)
    except NetError:
        raise
    except httpx.TimeoutException:
        raise NetError("timeout") from None
    except (httpx.ConnectError, httpx.NetworkError):
        raise NetError("offline") from None
    except Exception:
        raise NetError("bad_response") from None
