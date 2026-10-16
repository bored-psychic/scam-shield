import re
from urllib.parse import unquote, urlsplit
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
CANT_VERIFY, CANT_JUDGE = "Can't verify - hidden destination", "Can't judge by domain - free hosting"

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
