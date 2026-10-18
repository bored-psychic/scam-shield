import csv, datetime as dt, gzip, ipaddress, json, os
from functools import lru_cache
from urllib.parse import urlsplit

import numpy as np
import pandas as pd

from shield.config import LINKLISTS_DIR
from shield.core import net
from shield.links.platforms import SHORTENERS, platform_of
from url_features import parse_url

# Offline link lists (decision D23), read once per process from data/final/linklists/, which src/update_link_lists.py fills (git-ignored:
# OpenPhish forbids redistribution). A missing or stale file switches its signal to "couldn't verify (<reason>)": the app still runs.
#   tranco_top1m.csv     rank,domain (popularity; P2 = top 10k, the lookalike exemption = top 100k)
#   openphish.txt        one phishing URL per line (community feed, refreshed every 12 h)
#   urlhaus_recent.csv   abuse.ch export, URLs added in the past 30 days (needs URLHAUS_AUTH_KEY at download time)
#   rdap_dns.json        IANA's RDAP bootstrap: TLD -> registry RDAP base URL (the live RDAP hosts allowed in net.py)
#   ip2asn-v4.tsv.gz     iptoasn.com: IPv4 range -> ASN, country, AS name (provider of a resolved IP; display + the CDN exemption of R6)
#   manifest.json        per list: url, licence, downloaded_utc, sha256, rows
BLOCKLIST_MAX_AGE = dt.timedelta(days=7)    # an older blocklist says "couldn't verify (list out of date)" instead of "not listed"
TOP_POPULAR, TOP_LOOKALIKE_EXEMPT = 10_000, 100_000
BLOCKLISTS = {"openphish": "OpenPhish", "urlhaus": "URLhaus"}


def _ip_of(host):
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return None


class LinkLists:
    def __init__(self, root=LINKLISTS_DIR, now=None):
        self.root, self.now = root, now or dt.datetime.now(dt.timezone.utc)
        mpath = root / "manifest.json"
        self.manifest = json.loads(mpath.read_text()) if mpath.exists() else {}
        self.status = {}          # list name -> None (usable) or the reason it is not: "list not downloaded", "list out of date", "no URLhaus key"
        self._load_tranco()
        self._load_blocklists()
        self._load_rdap()
        self._asn = None          # loaded on first use (only the live checks need it)

    # ------------------------------------------------------------ bookkeeping
    def updated(self, name):
        """The download time of a list (aware datetime) or None."""
        m = self.manifest.get(name)
        return dt.datetime.fromisoformat(m["downloaded_utc"]) if m else None

    def _file(self, name, filename, max_age=None):
        path = self.root / filename
        if not path.exists() or name not in self.manifest:
            self.status[name] = "no URLhaus key" if name == "urlhaus" and not os.environ.get("URLHAUS_AUTH_KEY") else "list not downloaded"
            return None
        if max_age and self.now - self.updated(name) > max_age:
            self.status[name] = "list out of date"
            return None
        self.status[name] = None
        return path

    # ------------------------------------------------------------ Tranco
    def _load_tranco(self):
        # hash -> rank in sorted arrays: 19 MB instead of 112 MB for a dict of 1M strings (measured). hash() is per process, which is all a
        # lookup needs; a 64-bit collision among 1M names is negligible.
        self._t_hash, self._t_rank, self.top_labels = np.array([], np.int64), np.array([], np.int32), frozenset()
        path = self._file("tranco", "tranco_top1m.csv")
        if path is None:
            return
        df = pd.read_csv(path, names=["rank", "domain"], keep_default_na=False, dtype={"rank": np.int32, "domain": str})
        h = np.fromiter((hash(d) for d in df["domain"].tolist()), dtype=np.int64, count=len(df))
        order = np.argsort(h, kind="stable")
        self._t_hash, self._t_rank = h[order], df["rank"].to_numpy(np.int32)[order]
        # names of the top 10k for the homograph check (R3): the label before the suffix, 4+ letters ("google", "paypal")
        self.top_labels = frozenset(lab for d in df["domain"].head(TOP_POPULAR).tolist() if len(lab := d.split(".")[0]) >= 4)

    @property
    def has_tranco(self):
        return bool(len(self._t_hash))

    def tranco_rank(self, reg):
        if not reg or not len(self._t_hash):
            return None
        h = hash(reg)
        i = int(np.searchsorted(self._t_hash, h))
        return int(self._t_rank[i]) if i < len(self._t_hash) and self._t_hash[i] == h else None

    # ------------------------------------------------------------ blocklists (R1) and their IPs (R6)
    def _load_blocklists(self):
        self.hosts = {n: set() for n in BLOCKLISTS}          # listed hosts that are nobody else's (not a platform root)
        self.prefixes = {n: {} for n in BLOCKLISTS}          # platform root host -> listed paths (a page on docs.google.com, a bit.ly link)
        self.bad_ips = set()                                 # IPs that are the host of a listed URL
        for name, filename in (("openphish", "openphish.txt"), ("urlhaus", "urlhaus_recent.csv")):
            path = self._file(name, filename, BLOCKLIST_MAX_AGE)
            if path is None:
                continue
            with open(path, encoding="utf-8", errors="replace", newline="") as f:
                urls = ([l.strip() for l in f if l.strip()] if name == "openphish"
                        else [row[2] for row in csv.reader(l for l in f if not l.startswith("#")) if len(row) > 2])
            for u in urls:
                self._add_listed(name, u)

    def _add_listed(self, name, url):
        host = parse_url(url)[0].rstrip(".")
        if not host:
            return
        if (ip := _ip_of(host)):
            self.bad_ips.add(ip)
            self.hosts[name].add(ip)
            return
        # Only that page is listed, not the whole host, when the host is a platform's own root (docs.google.com, bit.ly) or is itself a popular
        # site (a Tranco top-100k registered domain, or its www.): such an entry is a compromised page or a test entry, and matching the host
        # would flag the whole site (URLhaus has http://example.com/test_drop_check). A popular site listed without a path is not used at all.
        reg = parse_url("http://" + host)[1]
        popular = host in (reg, "www." + reg) and (rank := self.tranco_rank(reg)) is not None and rank <= TOP_LOOKALIKE_EXEMPT
        if platform_of(host) == host or popular:
            path = urlsplit(url if "://" in url else "http://" + url).path.rstrip("/")
            if path:
                self.prefixes[name].setdefault(host.removeprefix("www."), set()).add(path)
            return
        self.hosts[name].add(host)

    def listed(self, url, host):
        """[(list display name, how)] for the lists that have this link: "host" (the host itself is listed) or "page" (this page of a
        platform). Lists that cannot be checked are not in the answer: see blocklist_problems()."""
        out = []
        path = urlsplit(url if "://" in url else "http://" + url).path.rstrip("/")
        for name, shown in BLOCKLISTS.items():
            if self.status.get(name):
                continue
            if host in self.hosts[name] or (host.startswith("www.") and host[4:] in self.hosts[name]):
                out.append((shown, "host"))
            elif path and any(path == p or path.startswith(p + "/") for p in self.prefixes[name].get(host.removeprefix("www."), ())):
                out.append((shown, "page"))
        return out

    def blocklist_problems(self):
        """{display name: reason} for each blocklist that could not be checked."""
        return {shown: self.status[n] for n, shown in BLOCKLISTS.items() if self.status.get(n)}

    # ------------------------------------------------------------ RDAP bootstrap (signal 7)
    def _load_rdap(self):
        self.rdap = {}
        path = self._file("rdap_bootstrap", "rdap_dns.json")
        if path is None:
            return
        for tlds, urls in json.loads(path.read_text())["services"]:
            https = [u for u in urls if u.startswith("https://")]
            for t in tlds:
                if https:
                    self.rdap[t.lower()] = https[0] if https[0].endswith("/") else https[0] + "/"
        net.add_check_hosts(urlsplit(u).hostname for u in self.rdap.values())

    def rdap_base(self, reg):
        return self.rdap.get(reg.rsplit(".", 1)[-1].lower())

    # ------------------------------------------------------------ IP -> ASN (signal 8)
    def _load_asn(self):
        path = self._file("ip2asn", "ip2asn-v4.tsv.gz")
        if path is None:
            self._asn = False
            return
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            df = pd.read_csv(f, sep="\t", names=["start", "end", "asn", "country", "name"], keep_default_na=False, quoting=csv.QUOTE_NONE,
                             dtype={"start": str, "end": str, "asn": np.int64, "country": "category", "name": "category"})
        def to_int(col):   # dotted IPv4 -> integer, vectorised (539k rows: a Python loop took ~2 s)
            q = df[col].str.split(".", expand=True).astype(np.int64).to_numpy()
            return (q[:, 0] << 24) | (q[:, 1] << 16) | (q[:, 2] << 8) | q[:, 3]
        df["s"], df["e"] = to_int("start"), to_int("end")
        df = df.sort_values("s", kind="stable").reset_index(drop=True)   # searchsorted needs the ranges in order (the file is, but do not rely on it)
        self._asn = (df["s"].to_numpy(), df["e"].to_numpy(), df["asn"].to_numpy(), df["country"], df["name"])

    def asn(self, ip):
        """(asn, country, AS name) for an IPv4 address, or None (unknown, IPv6, not routed, or no table)."""
        if self._asn is None:
            self._load_asn()
        if not self._asn:
            return None
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        start, end, asn, country, name = self._asn
        i = int(np.searchsorted(start, n, side="right")) - 1
        if i < 0 or n > end[i] or asn[i] == 0:
            return None
        return int(asn[i]), str(country.iloc[i]), str(name.iloc[i])


@lru_cache(maxsize=1)
def load_lists() -> LinkLists:
    """The lists, read once per process (the API warms this at start-up, the IP table included). Also allows the shortener hosts for the
    expand button."""
    net.add_expand_hosts(SHORTENERS)
    return LinkLists()


def warm():
    """Read every list now, the IP -> ASN table too (otherwise the first live check pays for it)."""
    load_lists().asn("1.1.1.1")
