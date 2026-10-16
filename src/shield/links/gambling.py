import csv, json
from functools import lru_cache
from gambling_lists import _reg as registered_domain   # the function src/gambling_lookup.py built the domain file with
from url_features import parse_url                      # URL -> host, the pipeline's rule (build_urls.parse)
from shield.config import GAMBLING_DOMAINS_PATH, GAMBLING_INDIA_PATH, GAMBLING_PLATFORM_HOSTS_PATH
from shield.links.platforms import FREE_HOSTING, SHORTENERS

# Gambling / betting links (decision G1, docs/decisions/README.md): a link on the gambling lookup gets the verdict Suspicious with its
# own reason, never "scam" and never Likely scam on its own. Local files only, nothing is fetched or resolved (CLAUDE.md rule 8).
#
#   data/final/gambling_domains.tsv         registered domains on the UT1 and / or Blocklist Project gambling lists, + review-sheet decisions
#   data/final/gambling_platform_hosts.tsv  gambling HOSTS on shared hosting platforms (pages.dev, cloudfront.net, com.de ...)
#   data/final/gambling_india.json          Satta / Matka name rule (the lists barely cover India)
# They are built by src/gambling_lookup.py. The lists are a gambling CATEGORY, not a scam verdict (licensed operators are on them), and
# Tranco popularity never lowers a hit (G1); the reviewed exceptions are the two constants below, see match().
GAMBLING_VERDICT = "Suspicious - gambling or betting site"

# User decision 2026-10-17, review of reports/gambling_app_check.md (the 117 lookup domains in the Tranco top 10k that were not platform roots):
#   GAMBLING_PLATFORM_ROOTS  hosting roots (free sites, CDNs, storage): treated exactly like the other platform roots, never matched by the
#                            domain list, only at host level (gambling_platform_hosts.tsv) and by the India token rule on the owner's part
#   GAMBLING_NOT_GAMBLING    not gambling sites (ISPs, CDNs, login provider, media, sports-score sites): never match, same step as allow_domains
# The other 96 stay flagged. Lower-ranked domains on the lists were not reviewed (BUGS.md).
# "150m.com" is not one of the 8 reviewed: user decision 2026-10-17, a free web host like tripod.com (Tranco rank 71,514, outside the top 10k);
# it was the one val / test message with a gambling hit left.
GAMBLING_PLATFORM_ROOTS = frozenset({"tripod.com", "eu.cc", "amebaownd.com", "b-cdn.net", "imgix.net", "wasabisys.com", "itch.io", "free.fr",
                                     "150m.com"})
GAMBLING_NOT_GAMBLING = frozenset({"onelink.me", "okta.com", "uol.com.br", "orange.fr", "sfr.fr", "mundodeportivo.com", "about.com",
                                   "itv.com", "dhnet.be", "sofascore.com", "flashscore.fr", "flashscore.com.br", "livescore.in"})

_LISTS = {"both": "the UT1 and Blocklist Project gambling lists", "ut1": "the UT1 gambling list", "blp": "the Blocklist Project gambling list"}
_REVIEW = "Marked as a gambling site in this project's manual review"

def _read_tsv(path, *cols):
    if not path.exists():
        raise FileNotFoundError(f"{path} is missing: run src/gambling_lookup.py")
    with open(path, encoding="utf-8", newline="") as f:
        rows = csv.reader(f, delimiter="\t", quoting=csv.QUOTE_NONE)
        head = next(rows)
        ix = [head.index(c) for c in cols]
        for row in rows:
            yield [row[i] for i in ix]


class GamblingLookup:
    def __init__(self, domains, platform_hosts, platform_suffixes, india):
        self.domains = domains                      # registered domain -> detail sentence
        self.platform_hosts = platform_hosts        # host on a hosting platform -> detail sentence
        self.platform_suffixes = platform_suffixes | GAMBLING_PLATFORM_ROOTS  # hosting platforms and shorteners: their root is never matched by the domain list
        self.strong, self.weak = tuple(india["strong_tokens"]), tuple(india["weak_tokens"])
        self.exempt, self.allow = tuple(india["exempt_suffixes"]), frozenset(india["allow_domains"]) | GAMBLING_NOT_GAMBLING

    def _platform(self, host):
        """(suffix, matched host) if host is on a hosting platform: the longest suffix of host that is a platform, and the listed host
        (host itself or a parent host below the suffix) if there is one. (None, None) for an ordinary host."""
        labels = host.split(".")
        for i in range(len(labels)):
            suffix = ".".join(labels[i:])
            if suffix in self.platform_suffixes:
                hit = next((h for j in range(i) if (h := ".".join(labels[j:])) in self.platform_hosts), None)
                return suffix, hit
        return None, None

    def _india(self, text):
        """The matching India tokens in text (a host, or the part of it the site's owner picks): one strong token, or two different
        weak ones; a single weak token never matches (gambling_lists.india_hit). [] = no match."""
        strong, weak = [t for t in self.strong if t in text], [t for t in self.weak if t in text]
        return strong + weak if strong or len(weak) >= 2 else []

    def match(self, url):
        """None, or {basis: "list" | "platform_host" | "india_token", domain, detail} for a URL whose host is a gambling site."""
        host = parse_url(url)[0].rstrip(".")
        if not host:
            return None
        reg = registered_domain(host)
        # 1. reviewed exceptions: government / academic hosts, the three known false positives, GAMBLING_NOT_GAMBLING (merged into self.allow)
        if reg in self.allow or any(host == s or host.endswith("." + s) for s in self.exempt):
            return None
        # 2. a hosting platform or shortener hosts anyone's site, so its root is never matched by the domain list (wordpress.com is on both
        #    lists): only the listed host, or a parent host below the platform suffix, counts, and the name rule reads the owner's part only
        suffix, hit = self._platform(host)
        if hit:
            return {"basis": "platform_host", "domain": hit, "detail": self.platform_hosts[hit]}
        if suffix:
            owned = host[:-len(suffix) - 1] if host != suffix else ""
        else:
            # 3. the domain list (no Tranco check: G1)
            if reg in self.domains:
                return {"basis": "list", "domain": reg, "detail": self.domains[reg]}
            owned = host
        # 4. the Satta / Matka name rule
        tokens = self._india(owned)
        if tokens:
            return {"basis": "india_token", "domain": host if suffix else reg, "detail": f"Matches the Satta/Matka name rule ({', '.join(tokens)})"}
        return None


@lru_cache(maxsize=1)
def load_gambling() -> GamblingLookup:
    """The lookup, read once per process. FileNotFoundError names the missing file and the script that builds it."""
    domains = {}
    for d, lists, review in _read_tsv(GAMBLING_DOMAINS_PATH, "domain", "lists", "review"):
        domains[d] = f"On {_LISTS[lists]}" if lists else _REVIEW
    platform_hosts, suffixes = {}, set()
    for h, suffix, lists in _read_tsv(GAMBLING_PLATFORM_HOSTS_PATH, "host", "platform_suffix", "lists"):
        platform_hosts[h] = f"On {_LISTS[lists]} (a page on a shared hosting platform)"
        suffixes.add(suffix)
    if not GAMBLING_INDIA_PATH.exists():
        raise FileNotFoundError(f"{GAMBLING_INDIA_PATH} is missing: run src/gambling_lookup.py")
    with open(GAMBLING_INDIA_PATH, encoding="utf-8") as f:
        india = json.load(f)
    # The platform file only knows the platforms that have a listed host; FREE_HOSTING and SHORTENERS add the ones that do not (wordpress.com).
    return GamblingLookup(domains, platform_hosts, frozenset(suffixes) | FREE_HOSTING | SHORTENERS, india)
