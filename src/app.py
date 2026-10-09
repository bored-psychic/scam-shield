import os
os.environ.setdefault("GRADIO_ANALYTICS_ENABLED", "False")   # local-first: no telemetry from the UI library
import argparse, html, re
from pathlib import Path
from typing import Protocol
from urllib.parse import unquote, urlsplit
import joblib
import numpy as np, pandas as pd
import gradio as gr
from pii import mask_text
from url_features import BRANDS, SUSPICIOUS, parse_url, host_row
from textprep import URL_TOKEN, MAX_CHARS, extract_urls, model_text, replace_urls

# MVP Gradio app: paste a message, email or link -> risk level, tactic tags, top n-grams, URL feature breakdown.
#   python src/app.py [--port 7860]         (run from the project root; serves on 127.0.0.1 only)
#
# Text head: the TF-IDF + logistic regression baseline, saved by `python src/baseline.py --save models/text_baseline.joblib`. It reads
# textprep.model_text(text): links replaced by <URL>, so the link itself is judged only by the URL head below.
# URL head: models/url_head.joblib (host-only gradient boosting from url_head.py). Links are only parsed as strings,
# never fetched (CLAUDE.md rule 8), and nothing the user pastes is logged or stored.
#
# What the numbers are NOT. Both scores are uncalibrated model outputs; the three levels come from thresholds chosen on the
# validation split (never test). Combining the two heads is a placeholder rule (fuse()) until the fusion model exists.
# Tactic tags are hand-written regexes: they explain the message, they do not feed the score.
ROOT = Path(__file__).resolve().parent.parent
TEXT_MODEL_PATH, URL_MODEL_PATH = ROOT / "models" / "text_baseline.joblib", ROOT / "models" / "url_head.joblib"
LEVELS = ["No warning signs found", "Suspicious", "Likely scam"]   # level 0 is never called "Safe": it only means nothing strong was found
GRAM_COLS = ["n-gram (_ = word edge)", "pushes toward", "contribution"]
URL_COLS = ["url", "host", "score", "verdict"]
FEAT_COLS = ["feature", "value", "typical benign", "effect on score", "what it measures"]
COLORS = ["#1a7f37", "#9a6700", "#c62828"]
MAX_TEXT_CHARS, MAX_URLS = 20000, 10
MIN_PROSE_WORDS = 3   # fewer words than this once links are removed -> a bare link, the text head has nothing to read

r3 = lambda x: round(float(x), 3)
def level_of(score, lo, hi):
    """Scores and cut-offs are shown to 3 decimals, so they are compared at 3 decimals: the level can then never contradict the numbers
    on screen (a score shown as 0.428 against 'Suspicious from 0.428' is Suspicious). Moves a cut-off by at most 0.0005."""
    return 0 if score < lo else (1 if score < hi else 2)


# ---------------------------------------------------------------- text head
class TextScorer(Protocol):
    """What the app needs from a text head. A MuRIL scorer replaces the baseline by implementing this and being returned
    from load_text_model(); nothing else in the app changes. Both methods receive text already passed through textprep.model_text (PII masked, links replaced by <URL>)."""
    name: str
    thresholds: tuple[float, float]   # (suspicious, likely scam): score cut-offs chosen on val

    def score(self, text: str) -> float:
        """Scam score in [0, 1]."""

    def explain(self, text: str, k: int = 8) -> list[tuple[str, float]]:
        """The k strongest (token or n-gram, signed contribution) pairs; positive pushes toward scam."""


class TfidfLrScorer:
    name = "TF-IDF char n-grams + logistic regression (baseline)"

    def __init__(self, bundle):
        self.vec, self.clf = bundle["vectorizer"], bundle["model"]
        self.thresholds = (bundle["threshold_suspicious"], bundle["threshold_likely"])
        self.grams, self.coef = self.vec.get_feature_names_out(), self.clf.coef_[0]

    def score(self, text):
        return float(self.clf.predict_proba(self.vec.transform([text]))[0, 1])

    def explain(self, text, k=8):
        # logit = intercept + sum(coef_j * tfidf_j), so coef_j * tfidf_j is exactly n-gram j's share of the score
        x = self.vec.transform([text])
        contrib = x.data * self.coef[x.indices]
        kept = []
        for i in np.argsort(-np.abs(contrib)):
            g = self.grams[x.indices[i]]
            # overlapping n-grams of one word ('urg', 'urge', 'rgent') say the same thing: keep the strongest of each overlap
            if any(np.sign(contrib[i]) == np.sign(c) and (g in h or h in g) for h, c in kept):
                continue
            kept.append((g, float(contrib[i])))
            if len(kept) == k:
                break
        return kept


def load_text_model() -> TextScorer:
    """The one place the text head is chosen. To switch to MuRIL: return a MurilScorer here."""
    if not TEXT_MODEL_PATH.exists():
        raise SystemExit(f"{TEXT_MODEL_PATH} not found: run `python src/baseline.py --save models/text_baseline.joblib` first")
    bundle = joblib.load(TEXT_MODEL_PATH)
    if bundle.get("textprep", {}).get("url_token") != URL_TOKEN:   # a model trained on raw URLs would see <URL> as an unknown token
        raise SystemExit("models/text_baseline.joblib predates the <URL> preprocessing: rerun `python src/baseline.py --save models/text_baseline.joblib`")
    return TfidfLrScorer(bundle)


# ---------------------------------------------------------------- URL head
FEATURE_HELP = {
    "host_len": "characters in the hostname", "n_labels": "dot-separated parts of the hostname",
    "subdomain_depth": "parts to the left of the registered domain", "n_hyphens": "hyphens in the hostname",
    "n_digits": "digits in the hostname", "digit_ratio": "digits / hostname length",
    "host_entropy": "randomness of the hostname's characters (bits)", "reg_label_len": "length of the registrable name (the 'paytm' in paytm.com)",
    "reg_label_entropy": "randomness of the registrable name", "longest_label": "longest dot-separated part",
    "has_ip": "1 = the host is a raw IP address", "punycode": "1 = an xn-- (internationalised) label, a look-alike trick",
    "non_ascii": "non-ASCII characters in the host", "n_suspicious_host": "words like login / verify / kyc / otp in the host",
    "brand_token_offsite": "known brands named as a whole word on a domain that does not own them",
    "brand_substr_offsite": "same, as a substring (brands of 5+ letters)",
    "brand_min_dist": "edit distance (max 3) to a brand name it is not; 1-2 looks like a typo-squat",
    "tld_code": "top-level domain (the 40 most frequent in training have their own code)",
}


class UrlScorer:
    def __init__(self, bundle):
        self.model, self.features, self.top_tld = bundle["model"], bundle["features"], bundle["top_tld"]
        self.t_flag, self.t_high, self.reference = r3(bundle["threshold"]), r3(bundle["threshold_high"]), bundle["reference"]

    def level(self, score):
        return level_of(r3(score), self.t_flag, self.t_high)

    def tld_name(self, code):
        return "." + self.top_tld[int(code)] if int(code) < len(self.top_tld) else "(other)"

    def score_many(self, urls):
        """One row per scoreable URL: url, host, score, level. URLs without a parseable host are dropped."""
        rows = [(u, host_row(u, self.top_tld)) for u in urls]
        rows = [(u, f) for u, f in rows if f is not None]
        if not rows:
            return pd.DataFrame(columns=["url", "host", "score", "level"]), []
        X = pd.DataFrame([f for _, f in rows])[self.features]
        s = np.round(self.model.predict_proba(X)[:, 1], 3)
        out = pd.DataFrame({"url": [u for u, _ in rows], "host": [parse_url(u)[0] for u, _ in rows], "score": s})
        out["level"] = [self.level(v) for v in s]
        return out, X

    def breakdown(self, x_row):
        """Occlusion: effect = score - score with that one feature replaced by a typical benign host's value. Positive pushes
        toward phishing. Features are correlated (host_len / n_digits / entropy), so single-feature effects understate shared signals."""
        X = pd.concat([x_row.to_frame().T] * len(self.features), ignore_index=True).astype(float)
        for i, c in enumerate(self.features):
            X.loc[i, c] = self.reference[c]
        base = self.model.predict_proba(x_row.to_frame().T.astype(float)[self.features])[0, 1]
        eff = base - self.model.predict_proba(X[self.features])[:, 1]
        fmt = lambda c, v: self.tld_name(v) if c == "tld_code" else (str(int(round(v))) if abs(v - round(v)) < 1e-9 else f"{v:.2f}")
        df = pd.DataFrame({"feature": self.features, "value": [fmt(c, x_row[c]) for c in self.features],
                           "typical benign": [fmt(c, self.reference[c]) for c in self.features],
                           "effect on score": [round(float(e), 3) for e in eff], "what it measures": [FEATURE_HELP[c] for c in self.features]})
        return df.reindex(df["effect on score"].abs().sort_values(ascending=False).index).reset_index(drop=True)


def load_url_model() -> UrlScorer:
    if not URL_MODEL_PATH.exists():
        raise SystemExit(f"{URL_MODEL_PATH} not found: run `python src/url_head.py` first")
    bundle = joblib.load(URL_MODEL_PATH)
    if "reference" not in bundle or "threshold_high" not in bundle:
        raise SystemExit("models/url_head.joblib is from an older url_head.py: rerun `python src/url_head.py`")
    return UrlScorer(bundle)


def url_notes(url):
    """Plain-language observations about one URL (some are not model features; the table below shows what the model used)."""
    host, reg = parse_url(url)
    toks = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    notes = []
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        notes.append("the host is a raw IP address")
    if "xn--" in host or any(ord(c) > 127 for c in host):
        notes.append("the host uses international characters (possible look-alike)")
    if re.match(r"^[a-z]+://[^/?#]*@", url, re.I):
        notes.append("an '@' before the host: everything left of it is decoration, the link goes to the host after it")
    brands = [b for b in BRANDS if b in toks and reg not in BRANDS[b]]
    if brands:
        notes.append(f"names {', '.join(brands)} but the registered domain is {reg}, which is not theirs")
    words = [w for w in SUSPICIOUS if w in host]
    if words:
        notes.append(f"host contains {', '.join(words)}")
    return notes


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


# ---------------------------------------------------------------- tactic tags
# Hand-written cue lists, English plus a few Hinglish / Hindi / Kannada words. The Hindi and Kannada ones are not yet checked by a
# native speaker (reports/spotcheck_*.csv is still open) and none of the lists was tuned on val or test.
_T = lambda *p: re.compile("|".join(p), re.I)
TACTICS = {
    "authority": _T(
        r"\b(?:rbi|reserve bank|sebi|npci|uidai|aadhaar|aadhar|income tax|cbi|enforcement directorate|police|cyber ?crime|customs|trai|"
        r"narcotics|court|ministry|government|govt|officer|department|customer care|kyc|fir|arrest(?:ed)?|warrant|legal action|"
        r"sbi|hdfc|icici|axis bank|kotak|paytm|phonepe|amazon|flipkart|microsoft|apple support|irctc|india post|bank)\b",
        r"पुलिस|सरकार|आधार|बैंक|ಪೊಲೀಸ್|ಸರ್ಕಾರ|ಬ್ಯಾಂಕ್"),
    "urgency": _T(
        r"\b(?:urgent(?:ly)?|immediately|asap|right now|at once|hurry|deadline|last (?:chance|day|date|warning)|final (?:notice|warning|reminder)|"
        r"act now|(?:pay|click|verify|update|call|claim|apply|login|register) (?:now|today)|today only|limited time|expires?(?: today| soon| in)?|"
        r"expir(?:ed|ing)|within \d+ ?(?:hours?|hrs?|mins?|minutes?|days?)|before midnight|do not delay|don'?t delay|"
        r"(?:will|be|get) (?:be )?(?:blocked|suspended|deactivated|disconnected|terminated|closed|locked|cancelled)|avoid (?:penalty|disconnection|suspension)|"
        r"turant|jaldi|abhi|aaj hi|jald se jald)\b",
        r"तुरंत|तत्काल|जल्दी|अभी|आज ही|ತಕ್ಷಣ|ಈಗಲೇ|ಬೇಗ"),
    "payment": _T(
        r"\b(?:pay(?:ment)?|transfer|send money|deposit|upi|gpay|google pay|phonepe|paytm|bhim|qr code|scan (?:the )?qr|collect request|"
        r"approve (?:the )?request|(?:upi )?pin|processing fee|registration fee|advance|refund|cashback|wire|western union|bitcoin|crypto|usdt|"
        r"gift card|recharge|challan|penalty|customs duty|account number|ifsc|cvv|otp|card number)\b",
        r"(?:\brs\.?|\binr|₹)\s?\d[\d,]*(?:\.\d+)?", r"<UPI_ID>|<ACCOUNT>", r"भुगतान|पैसे|रिफंड|ಪಾವತಿ|ಹಣ"),
    # always-on secrecy / control cues
    "isolation": _T(
        r"\btell (?:no ?one|nobody)\b", r"\bwithout (?:telling|informing)\b",
        r"\b(?:do not|don'?t|never) (?:hang up|disconnect)\b", r"\b(?:do not|don'?t) (?:contact|call|talk to) (?:your |any )?(?:family|bank|friends?|police|anyone)\b",
        r"\b(?:delete|erase|remove) (?:this|the|these|all) (?:message|msg|sms|chat|text|e-?mail|conversation|messages)\b",
        r"\bstay (?:on the )?(?:line|call|video)\b", r"\bremain on (?:the )?(?:call|video)\b", r"\bdigital arrest\b", r"\bnational security\b",
        r"\b(?:switch|move) to (?:whatsapp|telegram|signal)\b", r"\badd me on (?:whatsapp|telegram)\b",
        r"\bjoin (?:our |the )?(?:whatsapp|telegram) (?:group|channel)\b",
        # Hinglish / Hindi / Kannada (hand-written, unchecked by a native speaker; Indic text uses [^\s.,!?।]* because \w stops at combining marks)
        r"\bkisi ko (?:bhi )?(?:mat|nahi|na) (?:batana|batao|bataiye|batayein|bolna|kehna)\b", r"\b(?:ghar walon|family|bank|police) ko (?:mat|nahi|na) bata[a-z]*\b",
        r"\b(?:ye|yeh|is) message (?:ko )?delete kar[a-z]*\b", r"\bgopniya rakh[a-z]*\b",
        r"किसी को (?:भी )?(?:न|मत|नहीं) बता[^\s.,!?।]*", r"(?:परिवार|बैंक|घर वालों) को (?:न|मत|नहीं) बता[^\s.,!?।]*", r"गोपनीय रख[^\s.,!?।]*",
        r"(?:यह|ये|इस) (?:संदेश|मैसेज) (?:को )?(?:डिलीट|हटा|मिटा)[^\s.,!?।]*",
        r"ಯಾರಿಗೂ (?:ಹೇಳ|ತಿಳಿಸ)[^\s.,!?।]*", r"ಕುಟುಂಬ[^\s.,!?।]* ಹೇಳ[^\s.,!?।]*", r"ಗೌಪ್ಯ[^\s.,!?।]*",
        r"ಈ ಸಂದೇಶ[^\s.,!?।]* (?:ಅಳಿಸ|ಡಿಲೀಟ್)[^\s.,!?।]*"),
}
# Secrecy cues that genuine OTP alerts also use ("Do not share it with anyone", "Keep your OTP confidential"). They count only when the
# text isn't an OTP-style advisory: no credential word, or it actually asks for one (cred_requests below).
_SECRECY = _T(
    r"\b(?:do not|don'?t|never) (?:tell|inform|disclose|discuss|mention|share)\b[^.!?\n]{0,30}?\b(?:anyone|anybody|no ?one|family|friends|relatives|bank|police|colleagues|others|this|it)\b",
    r"\bkeep (?:this|it|the matter|everything|all this)?\s*(?:strictly )?(?:confidential|secret|private|between us|to yourself)\b",
    r"\bsecret(?:ly)?\b")
_CRED_WORD = re.compile(r"\b(?:otp|pin|cvv2?|cvc|password|passcode|verification code|security code)\b", re.I)
_DISCLAIMER = re.compile(r"intended recipient|in error|by mistake|received this (?:e-?mail|message)", re.I)   # 'please delete this message' footers

def tactic_tags(text, cred_hits=None):
    """tag -> up to 4 distinct matched phrases (empty list = tag absent). cred_hits: cred_requests(text), computed here if not given."""
    cred_hits = cred_requests(text) if cred_hits is None else cred_hits
    out = {}
    for tag, rx in TACTICS.items():
        rxs = [rx] + ([_SECRECY] if tag == "isolation" and (cred_hits or not _CRED_WORD.search(text)) else [])
        seen = []
        for r_ in rxs:
            for m in r_.finditer(text):
                s = m.group(0).strip().lower()
                if tag == "isolation" and _DISCLAIMER.search(text) and re.match(r"(?:delete|erase|remove)\b", s):
                    continue
                if s and s not in seen:
                    seen.append(s)
        out[tag] = seen[:4]
    return out


# ---------------------------------------------------------------- credential requests
# Hard rule: a request to send, share or forward an OTP, PIN or CVV is at least Suspicious whatever the models say, and is shown as its
# own red flag. Nothing legitimate asks for these. Genuine alerts only warn against sharing ("Do not share your OTP"), so a verb counts
# only when no negation sits directly in front of it (up to 3 words, no punctuation: "do not share", "never ask you to share"; or a comma-delimited
# aside: "do not, under any circumstances, share"; but "Don't worry, just share the OTP" is still a request). English plus a Hinglish "OTP bata do" form; the verb list leaves out text / message /
# confirm / enter, which genuine OTP SMS use ("Enter OTP 482913 to confirm"). Known false positive: a real delivery-OTP instruction
# ("share the OTP with the delivery partner"). 'pin code' is the postal code, not a PIN.
_CRED = (r"(?:otp|one[- ]?time[- ](?:password|pin|code)|verification code|security code|cvv2?|cvc|"
         r"(?:(?:upi|atm|card|debit|credit|net ?banking|m|t)[ -]?)?pin(?![ -]?code))")
_ASK_FIRST = re.compile(rf"\b(?:send|share|forward|give|provide|tell|read out|reply with|reply|submit|relay)\b[^.!?\n]{{0,40}}?\b{_CRED}\b", re.I)
_ASK_LAST = re.compile(rf"\b{_CRED}\b[^.!?\n]{{0,25}}?\b(?:bata(?:o|do|dena|iye|yein)?|bhej(?:o|do|dena|iye|ein)?|share kar(?:o|iye|ein|do|na)?)\b", re.I)
_NEG_BEFORE = re.compile(r"\b(?:do not|don'?t|dont|never|not|no one|nobody|avoid|cannot|can'?t|won'?t|will not|should not|shouldn'?t)\s+(?:[\w']+\s+){0,3}$", re.I)
# "do not, under any circumstances, share": the negation, a comma-delimited aside, then the verb. The aside must start right after the negation, so
# "Don't worry, just share the OTP" (the word 'worry' sits between them) is still a request.
_NEG_ASIDE = re.compile(r"\b(?:do not|don'?t|dont|never|not|should not|shouldn'?t|will not|won'?t|cannot|can'?t)\s*,\s*[^,.!?\n]{1,40},\s*$", re.I)
_NEG_INSIDE = re.compile(r"\b(?:no one|nobody|not|never|mat|nahi|na)\b", re.I)

def cred_requests(text):
    """Phrases that ask the reader to send / share / forward an OTP, PIN or CVV (empty list = none). Benign warnings are not requests."""
    hits = []
    for rx in (_ASK_FIRST, _ASK_LAST):
        for m in rx.finditer(text):
            before = text[max(0, m.start() - 60):m.start()]
            if _NEG_INSIDE.search(m.group(0)) or _NEG_BEFORE.search(before[-40:]) or _NEG_ASIDE.search(before):
                continue
            ph = m.group(0).strip().lower()
            if ph not in hits:
                hits.append(ph)
    return hits[:3]


# ---------------------------------------------------------------- analysis
def fuse(text_level, url_level):
    """Placeholder until the fusion model exists: the higher of the two heads' levels, and if both heads are at least Suspicious
    the evidence agrees, so Likely scam. Either head alone can raise a flag; neither can clear the other."""
    levels = [l for l in (text_level, url_level) if l is not None]
    if not levels:
        return None
    return 2 if len(levels) == 2 and min(levels) >= 1 else max(levels)

def analyse(text, text_model, url_model):
    text = (text or "")[:MAX_TEXT_CHARS]
    urls = extract_urls(text, MAX_URLS)
    prose_words = len(re.findall(r"\w+", replace_urls(text).replace(URL_TOKEN, " ")))
    cred = cred_requests(text)
    r = {"urls": urls, "cred_request": cred, "escalated": False, "tags": tactic_tags(mask_text(text), cred),   # masked, so a phone / UPI id / account number shows up as a payment cue
         "text_score": None, "text_level": None, "grams": [], "links": [], "top_score": None, "breakdown": None, "notes": []}
    if prose_words >= MIN_PROSE_WORDS:
        prepared = model_text(text, mask_pii=True)   # PII masks, URLs -> <URL>, first 2000 chars: what baseline.py trained on (textprep.py)
        r["text_thresholds"] = tuple(r3(t) for t in text_model.thresholds)
        r["text_score"] = r3(text_model.score(prepared))
        r["text_level"] = level_of(r["text_score"], *r["text_thresholds"])
        r["grams"] = text_model.explain(prepared, k=14)
        r["truncated"] = len(prepared) >= MAX_CHARS
    # one entry per link, in input order: shorteners and free hosting are assessed by rule, the rest go to the URL model
    r["links"] = [{"url": u, "host": parse_url(u)[0], "score": None, "level": None, "verdict": "", "note": "", "kind": "model",
                   **(assess_link(u) or {})} for u in urls]
    by_url = {l["url"]: l for l in r["links"] if l["kind"] == "model"}
    if by_url:
        scored, X = url_model.score_many(list(by_url))
        for row in scored.itertuples():
            l = by_url[row.url]
            l["score"], l["level"] = float(row.score), int(row.level)
            l["verdict"] = LEVELS[l["level"]] if l["level"] else "not flagged"
        if len(scored):
            top = int(scored["score"].idxmax())
            r["top_score"], r["top_url"] = float(scored.loc[top, "score"]), scored.loc[top, "url"]
            r["breakdown"] = url_model.breakdown(X.iloc[top])
            r["notes"] = url_notes(r["top_url"])
    levels = [l["level"] for l in r["links"] if l["level"] is not None]
    r["url_level"] = max(levels) if levels else None
    r["level"] = fuse(r["text_level"], r["url_level"])
    if cred and (r["level"] is None or r["level"] < 1):   # hard rule: at least Suspicious, whatever the scores say
        r["level"], r["escalated"] = 1, True
    return r


# ---------------------------------------------------------------- rendering
def banner_html(r, text_model, url_model):
    unjudged = [l for l in r["links"] if l["level"] is None]
    if r["level"] is None and unjudged:   # nothing the models can score, but there is a link we deliberately did not judge
        kinds = {l["kind"] for l in unjudged}
        head = CANT_VERIFY if kinds == {"shortener"} else CANT_JUDGE if kinds == {"free"} else "Can't judge the link"
        why = {"shortener": "A shortened link hides where it goes, and links are never followed here.",
               "free": "Anyone can publish a site on these platforms, so the domain says nothing about this one."}
        sub = " ".join(why[k] for k in ("shortener", "free") if k in kinds)
        return (f"<div style='background:#57606a;color:#fff;border-radius:10px;padding:14px 18px'>"
                f"<div style='font-size:1.6em;font-weight:700'>{head}</div><div style='font-size:.9em;opacity:.95'>{sub} No message text to score.</div></div>")
    if r["level"] is None:
        return "<p>Paste a message, email or link above, then press <b>Analyse</b>.</p>"
    parts = []
    if r["text_score"] is not None:
        parts.append(f"text score <b>{r['text_score']:.3f}</b> (Suspicious from {r['text_thresholds'][0]:.3f}, Likely scam from {r['text_thresholds'][1]:.3f})")
    else:
        parts.append("no message text to score" + (", link only" if r["links"] else ""))
    if r["top_score"] is not None:
        parts.append(f"link score <b>{r['top_score']:.3f}</b> (flagged from {url_model.t_flag:.3f}, Likely scam from {url_model.t_high:.3f})")
    n = lambda kind, judged: sum(l["kind"] == kind and (l["level"] is not None) == judged for l in r["links"])
    plural = lambda k, word: f"{k} {word}" + ("s" if k > 1 else "")
    if n("shortener", False):
        parts.append(f"{plural(n('shortener', False), 'shortened link')} can't be verified")
    if n("free", False):
        parts.append(f"{plural(n('free', False), 'free-hosted link')} can't be judged by domain")
    if n("free", True):
        parts.append("a free-hosted link has a brand or scam keyword in its subdomain (counts as Suspicious)")
    both = r["text_level"] is not None and r["url_level"] is not None and min(r["text_level"], r["url_level"]) >= 1
    if r["escalated"]:
        parts.append("raised to Suspicious by the OTP / PIN / CVV rule")
    sub = "; ".join(parts) + ("; both heads flagged it" if both else "")
    unjudged = any(l["level"] is None for l in r["links"])
    caveat = ("This only means no strong warning signs were found" + (" in what could be checked" if unjudged else "") +
              ". It is not a guarantee, so verify through the official app or number.") if r["level"] == 0 else ""
    return (f"<div style='background:{COLORS[r['level']]};color:#fff;border-radius:10px;padding:14px 18px'>"
            f"<div style='font-size:1.6em;font-weight:700'>{LEVELS[r['level']]}</div>"
            f"<div style='font-size:.9em;opacity:.95'>{sub}</div>"
            + (f"<div style='font-size:.9em;margin-top:4px'>{caveat}</div>" if caveat else "") + "</div>")

def flag_html(r):
    """The OTP / PIN / CVV request rule gets its own red box, separate from the tactic tags and from the level."""
    if not r["cred_request"]:
        return ""
    ev = ", ".join(f"&ldquo;{html.escape(h)}&rdquo;" for h in r["cred_request"])
    return ("<div style='border:2px solid #c62828;background:rgba(198,40,40,.14);border-radius:10px;padding:10px 14px'>"
            "<b style='color:#e5484d'>&#9873; Red flag: asks you to send or share an OTP, PIN or CVV</b> "
            f"<span style='opacity:.9'>{ev}</span><div style='font-size:.9em;margin-top:2px'>No bank, government office or delivery service needs "
            "these sent to them by message or call. The verdict is at least Suspicious whatever the scores say.</div></div>")

def tags_html(r):
    chips = []
    for tag, hits in r["tags"].items():
        if hits:
            ev = ", ".join(f"&ldquo;{html.escape(h)}&rdquo;" for h in hits)
            chips.append(f"<span style='border:1px solid rgba(198,40,40,.7);background:rgba(198,40,40,.14);border-radius:999px;padding:4px 12px'>"
                         f"<b>{tag}</b> <span style='opacity:.85;font-size:.9em'>{ev}</span></span>")
        else:
            chips.append(f"<span style='border:1px solid rgba(128,128,128,.4);border-radius:999px;padding:4px 12px;opacity:.55'>{tag}: none found</span>")
    return "<div style='display:flex;flex-wrap:wrap;gap:8px'>" + "".join(chips) + "</div>"

def grams_df(r):
    rows = [(g.replace(" ", "_"), "scam" if c > 0 else "safe", round(c, 3)) for g, c in sorted(r["grams"], key=lambda t: -abs(t[1]))]
    return pd.DataFrame(rows, columns=GRAM_COLS)

def urls_df(r):
    rows = [(l["url"], l["host"], "-" if l["score"] is None else f"{l['score']:.3f}", l["verdict"]) for l in r["links"]]
    return pd.DataFrame(rows, columns=URL_COLS)

def note_md(r):
    """Markdown under the URL table: why a link was or wasn't scored, then the model's reading of the highest-scoring link."""
    parts = []
    if r["breakdown"] is not None:
        parts.append(f"Breakdown for the highest-scoring scored link: `{r['top_url']}`" + "".join(f"\n- {n}" for n in r["notes"]))
    elif r["links"]:
        parts.append("The URL model scored none of these links.")
    else:
        parts.append("No link found in the input.")
    special = [l for l in r["links"] if l["kind"] != "model"]
    if special:
        parts.append("Not scored by the URL model:" + "".join(f"\n- `{l['url']}`: {l['note']}" for l in special))
    if r.get("truncated"):
        parts.append(f"The text head scored the first {MAX_CHARS} characters only.")
    return "\n\n".join(parts)

def run(text, text_model, url_model):
    r = analyse(text, text_model, url_model)
    no_feats = pd.DataFrame(columns=FEAT_COLS)
    if r["level"] is None and not r["links"]:
        msg = "<p>Nothing to score: no readable text or link found.</p>" if (text or "").strip() else banner_html(r, text_model, url_model)
        return msg, "", tags_html(r), grams_df(r), urls_df(r), no_feats, ""
    return (banner_html(r, text_model, url_model), flag_html(r), tags_html(r), grams_df(r), urls_df(r),
            r["breakdown"] if r["breakdown"] is not None else no_feats, note_md(r))


EXAMPLES = [
    ["Dear SBI customer, your account will be blocked within 24 hours. Complete KYC immediately: http://sbi-kyc-verify-now.xyz/login"],
    ["URGENT: This is Mumbai Police cyber crime. A parcel in your name contains illegal items. Stay on the call, do not tell anyone, and transfer Rs 25000 to clear your name."],
    ["HDFC Bank: Rs 3,200 spent on Card ending 4321 at RELIANCE RETAIL on 28-02-26. Avl Lmt: Rs 75,000. Not you? Call the number on the back of your card."],
    ["http://secure-paytm-wallet-update.top/refund"],
]

def build_ui(text_model, url_model):
    with gr.Blocks(title="Scam check (MVP)") as demo:
        gr.Markdown("# Scam check (MVP)\nPaste a message, email or link. Everything runs on this machine; links are read as text and never opened.")
        inp = gr.Textbox(label="Message, email or link", lines=8, placeholder="Paste here...")
        with gr.Row():
            go = gr.Button("Analyse", variant="primary")
            gr.ClearButton(inp, value="Clear")
        banner = gr.HTML()
        flag = gr.HTML()
        gr.Markdown("### Tactic tags\nHand-written word lists (authority, urgency, payment, isolation). They explain the message but do not change the score.")
        tags = gr.HTML()
        gr.Markdown(f"### Top contributing n-grams\nHow much each piece of text moved the score of the **{text_model.name}**.")
        grams = gr.Dataframe(headers=GRAM_COLS, interactive=False, wrap=True)
        gr.Markdown("### Links found\nShortened links can't be verified (the destination is hidden and never fetched). Free-hosting links (pages.dev, vercel.app, github.io ...) get no model verdict.")
        urls = gr.Dataframe(headers=URL_COLS, interactive=False, wrap=True)
        gr.Markdown("### URL feature breakdown\nHost-only model. *Effect on score* is how much the score drops if that feature took a typical benign value instead.")
        note = gr.Markdown()
        feats = gr.Dataframe(headers=FEAT_COLS, interactive=False, wrap=True)
        gr.Examples(EXAMPLES, inp, label="Examples (made-up; none is a real message)")
        gr.Markdown("**Limits.** Baseline models: scores are not calibrated probabilities and the cut-offs were picked on validation data. "
                    "The text model was trained mostly on English. Combining the two heads is a simple placeholder rule. "
                    "A 'No warning signs found' result only means no strong signal was found. See `reports/` for measured performance.")
        outs = [banner, flag, tags, grams, urls, feats, note]
        go.click(lambda t: run(t, text_model, url_model), inp, outs)
    return demo


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7860)
    a = ap.parse_args()
    build_ui(load_text_model(), load_url_model()).launch(server_name=a.host, server_port=a.port, share=False)
