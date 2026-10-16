import re
import joblib
import numpy as np, pandas as pd
from url_features import BRANDS, SUSPICIOUS, parse_url, host_row
from shield.config import URL_MODEL_PATH
from shield.core.verdict import r3, level_of

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
