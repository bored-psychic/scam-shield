import re
from urllib.parse import unquote, urlsplit
from shield import config
from url_features import BRANDS, SUSPICIOUS, parse_url

# ---------------------------------------------------------------- risky hosting
# Links the URL model should not judge. Neither list is exhaustive; a host matches a domain by suffix (www.bit.ly, a.b.pages.dev).
#  shortener     the destination is hidden and is never fetched (CLAUDE.md rule 8), so there is nothing to score. Say so, and read
#                the path for scam keywords.
#  free hosting  anyone can publish under these domains. The URL head never saw a benign site on them (BUGS.md), so it reads
#                priya-portfolio.pages.dev as phishing; its score is not shown for these links. Only the subdomain, the part the
#                site's owner picks, is checked for a brand or scam keyword, and only a hit raises the link (to Suspicious).
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "tiny.cc", "rebrand.ly",
              "s.id", "t.ly", "buff.ly", "v.gd", "bl.ink", "short.io", "j.mp", "adf.ly", "shorte.st", "clck.ru", "tiny.one", "bit.do", "soo.gd"}
FREE_HOSTING = {"pages.dev", "workers.dev", "vercel.app", "netlify.app", "github.io", "gitlab.io", "bitbucket.io", "web.app", "firebaseapp.com",
                "glitch.me", "herokuapp.com", "onrender.com", "railway.app", "fly.dev", "replit.app", "repl.co", "replit.dev", "streamlit.app",
                "hf.space", "surge.sh", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "azurewebsites.net", "appspot.com", "blogspot.com",
                "wordpress.com", "weebly.com", "wixsite.com", "webflow.io", "framer.website", "carrd.co", "godaddysites.com", "000webhostapp.com",
                "infinityfreeapp.com", "pythonanywhere.com"}
# Additions of 2026-10-23 (reports/eval_live_links.md, decision C1): the 2026-10-22 live evaluation found phishing links on short-link services, dynamic-DNS hosts
# and a site builder that none of the lists above knew, so they were judged as ordinary domains and rated "No warning signs". Each group says where it comes from.
#
#  SHORTENERS_ADDED   the first three were in the OpenPhish public feed of 2026-10-22 and were rated safe (eval_live_links.md section 6 rows 1, 2, 4). The
#                     rest are well-known public URL-shortening services added from memory, NOT checked against a list in this session (offline task). A
#                     maintained list exists (github.com/PeterDaveHello/url-shorteners, CC BY-SA 4.0); since 2026-10-23 (decision C2) src/update_link_lists.py
#                     downloads it through the update path (raw.githubusercontent.com is on net.UPDATE_HOSTS) and load_downloaded_shorteners() below merges it
#                     in, so these hand-added ones are the fallback when the file is missing and the ones the list lacks (10 of the 36 hand-listed shorteners
#                     were not on it on 2026-10-23). Like every shortener, D3 applies: the destination is shown only after the user presses the expand button.
#  DYNAMIC_DNS        free sub-domain services (anyone picks a name under the provider's domain). Every entry is in the PRIVATE section of the Public Suffix
#                     List (publicsuffix.org, the snapshot bundled with tldextract), which is the PSL's record that the domain hands out sub-domains to
#                     independent users; `dpdns.org` is the one seen in the eval (row 3), `ddns.net` the other (row 7). Checked by tests/test_links_live.py L15.
#  SITE_BUILDERS      page builders where anyone publishes a page under the builder's domain. `craftum.io` was seen in the eval (row 5; it is not in the PSL);
#                     the other four are in the PSL private section (checked by L15).
SHORTENERS_ADDED = {"zd.lc", "g5.lu", "lnk.ink", "gg.gg", "x.gd", "qrco.de", "tr.ee", "shorturl.asia", "cutt.us", "ouo.io", "kutt.it", "short.gy"}
DYNAMIC_DNS = {"dpdns.org", "ddns.net", "duckdns.org", "hopto.org", "zapto.org", "myftp.org", "no-ip.org", "no-ip.biz", "no-ip.info", "dynu.net",
               "3utilities.com", "sytes.net", "servebeer.com", "redirectme.net", "bounceme.net", "ddnsking.com", "dnsalias.com", "dnsalias.net", "dnsalias.org"}
SITE_BUILDERS = {"craftum.io", "myshopify.com", "square.site", "yolasite.com", "bubbleapps.io"}
SHORTENERS |= SHORTENERS_ADDED
FREE_HOSTING |= DYNAMIC_DNS | SITE_BUILDERS
# Additions of 2026-10-23 (decision C3). reports/eval_live_links.md section 10 listed the phishing links that an age gate would lose: pages on hosting platforms the
# lists above did not know, so the platform's own old registration made them look like old ordinary domains. All nine were in the OpenPhish public feed of
# 2026-10-22. Where a platform is in the bundled Public Suffix List (a 2026 snapshot) it says so; the others are not in that snapshot, so their kind is read from
# the pages seen in the feed and from the platform's own name, NOT checked against a list in this offline task.
#   Moved from FREE_HOSTING to USER_CONTENT the same day (decision C3, follow-up): as FREE_HOSTING the eight cost 8 caught phishing links, which read "Can't judge" instead of
#   Suspicious (reports/eval_live_links.md section 10) and removed no benign false alarm. USER_CONTENT keeps the URL model's vote, which is what those links need; the link
#   checks still treat them as platform pages (no registry age, no top-10k "well-known" credit, only the part the uploader picks is checked for a brand name).
#   edgeone.dev           Tencent EdgeOne Pages (feed: central-crimson-*.edgeone.dev), a free-hosting service                not in the PSL snapshot
#   4everland.app         4EVERLAND web3 hosting (feed: <name>.4everland.app), free-hosting service                          not in the PSL snapshot
#   azurestaticapps.net   Microsoft Azure Static Web Apps (feed: *.4.azurestaticapps.net), free-hosting service             in the PSL private section ("Microsoft Azure")
#   cloudworkstations.dev Google Cloud Workstations, a per-user dev server on a public name                                  not in the PSL snapshot
#   crabdance.com         a free sub-domain provider (feed: detaillogs.*.crabdance.com)                                      not in the PSL snapshot; kind inferred from the feed row only
#   flazio.online         Flazio website builder (feed: user-*.flazio.online)                                                not in the PSL snapshot
#   typedream.app         Typedream site builder (feed: *.typedream.app)                                                     in the PSL private section ("Typedream")
#   teleporthq.app        TeleportHQ site builder (feed: *.teleporthq.app)                                                   not in the PSL snapshot
#   backblazeb2.com       Backblaze B2 cloud storage buckets (feed: f005.backblazeb2.com/file/<bucket>/...)                  not in the PSL snapshot (user content from the start)
PLATFORMS_C3_USER_CONTENT = {"edgeone.dev", "4everland.app", "azurestaticapps.net", "cloudworkstations.dev", "crabdance.com", "flazio.online", "typedream.app", "teleporthq.app",
                             "backblazeb2.com"}
CANT_VERIFY, CANT_JUDGE = "Can't verify - hidden destination", "Can't judge by domain - free hosting"
# User-content hosts (D23): popular sites where anyone can post a page, a form, a file, a chat invite or a profile, so the site's popularity (P2)
# and its registration facts say nothing about the page a link points to, and a blocklist entry there marks that page only. The URL model still
# scores them (unchanged); only the D23 link checks read this list. Matched like the lists above (the host or a subdomain of it).
USER_CONTENT = {"t.me", "telegram.me", "wa.me", "chat.whatsapp.com", "api.whatsapp.com", "docs.google.com", "drive.google.com", "forms.gle",
                "sites.google.com", "script.google.com", "storage.googleapis.com", "firebasestorage.googleapis.com", "amazonaws.com",
                "cloudfront.net", "dropbox.com", "dropboxusercontent.com", "onedrive.live.com", "1drv.ms", "sharepoint.com", "notion.site",
                "linktr.ee", "instagram.com", "facebook.com", "fb.me", "youtube.com", "youtu.be", "github.com", "githubusercontent.com",
                "gitlab.com", "medium.com", "pastebin.com", "discord.gg", "discord.com", "x.com", "twitter.com", "linkedin.com", "lnkd.in",
                "canva.site", "my.canva.site", "typeform.com", "jotform.com", "wixstudio.com", "translate.goog", "ipfs.io"}

# Entries of the downloaded shortener list that must NOT become shorteners (reviewed 2026-10-23, 1,454 entries):
#  - a domain that is already a user-content, free-hosting, dynamic-DNS or site-builder platform (9: 1drv.ms, discord.gg, fb.me, forms.gle, lnkd.in, on.fb.me,
#    t.me, wa.me, youtu.be). Those keep their own rule; a YouTube or WhatsApp link is not a hidden destination.
#  - two entries in the Tranco top 10k that are whole websites, not redirectors: dw.com (a news site, listed for its dw.com/p/... short links) and ibb.co
#    (an image host whose pages anyone can create).
SHORTENERS_EXCLUDED = {"dw.com", "ibb.co"}

def load_downloaded_shorteners(path=None):
    """The domains in data/final/linklists/url_shorteners.txt (src/update_link_lists.py, PeterDaveHello/url-shorteners), minus the platform hosts above and
    SHORTENERS_EXCLUDED. An empty set when the file is missing: the app then knows only the hand-written lists."""
    path = path or config.LINKLISTS_DIR / "url_shorteners.txt"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    plat = USER_CONTENT | FREE_HOSTING
    return {d for d in (l.strip().lower() for l in lines) if re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,24}", d)
            and d not in SHORTENERS_EXCLUDED and not suffix_match(d, plat) and not any(u.endswith("." + d) for u in plat)}

USER_CONTENT |= PLATFORMS_C3_USER_CONTENT

def platform_of(host):
    """The root of the shortener, free-hosting or user-content platform host is on (e.g. "pages.dev", "docs.google.com"), or None."""
    return suffix_match(host, SHORTENERS) or suffix_match(host, FREE_HOSTING) or suffix_match(host, USER_CONTENT)

def suffix_match(host, domains):
    return next((d for d in domains if host == d or host.endswith("." + d)), None)

def _tokens(s):
    return {t for t in re.split(r"[^a-z0-9]+", s.lower()) if t}

def keyword_hits(s):
    """SUSPICIOUS words in s: as a whole token, or as a substring when the word has 5+ letters ('freelance' is not 'free', 'support-desk' is 'support')."""
    t, low = _tokens(s), s.lower()
    return [k for k in SUSPICIOUS if k in t or (len(k) >= 5 and k in low)]

def brand_hits(s):
    """BRANDS named in s, same rule. On a free-hosting subdomain no brand owns the name, so any hit is a lookalike."""
    t, low = _tokens(s), s.lower()
    return [b for b in BRANDS if b in t or (len(b) >= 5 and b in low)]

def assess_link(url):
    """None for an ordinary host (the URL model scores it); otherwise the dict for a shortened or free-hosted link:
    kind, verdict, level (None = not judged, 1 = Suspicious), note."""
    host, _ = parse_url(url)
    if (d := suffix_match(host, SHORTENERS)):
        s = urlsplit(url if "://" in url else "http://" + url)
        hits = keyword_hits(unquote(s.path + " " + s.query))
        note = f"`{d}` is a link shortener: the real destination is hidden and was not followed."
        return {"kind": "shortener", "verdict": CANT_VERIFY, "level": None,
                "note": note + (f" Scam keywords in the path: {', '.join(hits)}." if hits else "")}
    if (d := suffix_match(host, FREE_HOSTING)):
        sub = host[:-len(d) - 1] if host != d else ""
        found = [f"brand {b}" for b in brand_hits(sub)] + [f"keyword {k}" for k in keyword_hits(sub)]
        note = f"hosted on a free platform anyone can use (`{d}`), so the domain says nothing about who runs the site."
        if found:
            return {"kind": "free", "verdict": "Suspicious - brand or scam keyword in subdomain", "level": 1,
                    "note": f"{note} Subdomain `{sub}` has {', '.join(found)}, which raises it to Suspicious."}
        return {"kind": "free", "verdict": CANT_JUDGE, "level": None,
                "note": f"{note} Subdomain `{sub or '(none)'}`: no brand or scam keyword found."}
    return None

DOWNLOADED_SHORTENERS = load_downloaded_shorteners()   # merged last: it needs suffix_match; every reader looks SHORTENERS up at call time
SHORTENERS |= DOWNLOADED_SHORTENERS
