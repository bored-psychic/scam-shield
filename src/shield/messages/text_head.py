from typing import Protocol
import joblib
import numpy as np
from textprep import URL_TOKEN
from shield.config import TEXT_MODEL_PATH

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
