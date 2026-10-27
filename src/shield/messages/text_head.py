import json, math, re, sys, threading
from typing import Protocol
import joblib
import numpy as np
from textprep import MAX_CHARS, URL_TOKEN
from shield import config
from shield.config import TEXT_MODEL_PATH

# ---------------------------------------------------------------- text head
class TextScorer(Protocol):
    """What the app needs from a text head. A MuRIL scorer replaces the baseline by implementing this and being returned
    from load_text_model(); nothing else in the app changes. Both methods receive text already passed through textprep.model_text (PII masked, links replaced by <URL>)."""
    name: str
    thresholds: tuple[float, float]   # (suspicious, likely scam): score cut-offs chosen on val
    meter_ends: tuple[float, float] | None   # scores at 0 and 100 of the risk meter (risk.curve, logit scale); None = D24's linear curve

    def score(self, text: str) -> float:
        """Scam score in [0, 1]."""

    def explain(self, text: str, k: int = 8) -> list[tuple[str, float]]:
        """The k strongest (token or n-gram, signed contribution) pairs; positive pushes toward scam."""


class TfidfLrScorer:
    name = "TF-IDF char n-grams + logistic regression (baseline)"
    meter_ends = None

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


class MurilScorer:
    """The fine-tuned MuRIL bundle (D27; reports/eval_muril_v2.md). score = sigmoid(logit / T): the softmax logit difference of the scam and
    benign classes, divided by the temperature T fitted on val (src/calibrate_text_head.py). Cut-offs and meter ends are the val-chosen ones in
    the bundle's shield_meta.json "calibration" block. Inputs are cut to the 128 tokens it was trained on."""
    name = "MuRIL (fine-tuned, temperature-scaled)"

    def __init__(self, run_dir, device="auto"):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        meta = json.loads((run_dir / "shield_meta.json").read_text(encoding="utf-8"))
        st, cal = meta.get("settings", {}), meta.get("calibration")
        problems = [m for m, bad in (
            ("a smoke run", st.get("smoke")), (f"a --limit {st.get('limit')} run", st.get("limit") is not None),
            (f"a leave-one-source-out fold (loso: true, held-out source {meta.get('exclude_source')}): it has no source it was not trained without, and no model/", meta.get("loso")),
            ("trained on another textprep", meta.get("textprep") != {"url_token": URL_TOKEN, "max_chars": MAX_CHARS}),
            ("not calibrated: run `python src/calibrate_text_head.py` first", not cal),
            ("calibrated on something other than val", cal and cal.get("fit_on") != "val")) if bad]
        if problems:
            raise SystemExit(f"{run_dir}: {'; '.join(problems)}")
        self.torch, self.max_len, self.T = torch, st["max_len"], cal["temperature"]
        self.thresholds = (cal["threshold_suspicious"], cal["threshold_likely"])
        self.meter_ends = (cal["meter_p0"], cal["meter_p100"])
        if device == "auto":
            device = "mps" if torch.backends.mps.is_available() else "cpu"
        self.device = device
        self.tok = AutoTokenizer.from_pretrained(run_dir / "model")
        self.model = AutoModelForSequenceClassification.from_pretrained(run_dir / "model").eval().to(device)
        self.lock = threading.Lock()   # the API serves requests from a thread pool; one forward pass at a time
        self.logits(["warm-up"])        # the first call on a device is slow: pay it at startup, not on the first request

    def logits(self, texts):
        """Scam-minus-benign logit per text, before the temperature."""
        enc = self.tok(list(texts), truncation=True, max_length=self.max_len, padding=True, return_tensors="pt").to(self.device)
        with self.lock, self.torch.no_grad():
            lg = self.model(**enc).logits.float()
        return (lg[:, 1] - lg[:, 0]).cpu().numpy()

    def score(self, text):
        return 1 / (1 + math.exp(-float(self.logits([text])[0]) / self.T))

    def explain(self, text, k=8, batch=32):
        """Leave-one-word-out: each word's contribution is how much the calibrated logit drops when that word is removed (positive pushes toward
        scam). Only the words inside the 128-token window can matter. A repeated word keeps its strongest occurrence."""
        words = re.findall(r"\S+", text)
        n = sum(1 for i in range(len(words)) if len(self.tok(" ".join(words[:i + 1]))["input_ids"]) <= self.max_len) if words else 0
        if not n:
            return []
        full = float(self.logits([" ".join(words)])[0])   # joined the same way as the variants, so only the removed word differs
        variants = [" ".join(words[:i] + words[i + 1:]) for i in range(n)]
        drops = np.concatenate([self.logits(variants[j:j + batch]) for j in range(0, n, batch)])
        best = {}
        for w, d in zip(words[:n], (full - drops) / self.T):
            # a saturated score (most confident scams) moves by ~0 whichever word goes: show nothing rather than a list of zeros (BUGS.md)
            if abs(d) >= 0.01 and abs(d) > abs(best.get(w, 0.0)):
                best[w] = float(d)
        return sorted(best.items(), key=lambda t: -abs(t[1]))[:k]


def load_baseline() -> TfidfLrScorer:
    if not TEXT_MODEL_PATH.exists():
        raise SystemExit(f"{TEXT_MODEL_PATH} not found: run `python src/baseline.py --save models/text_baseline.joblib` first")
    bundle = joblib.load(TEXT_MODEL_PATH)
    if bundle.get("textprep", {}).get("url_token") != URL_TOKEN:   # a model trained on raw URLs would see <URL> as an unknown token
        raise SystemExit("models/text_baseline.joblib predates the <URL> preprocessing: rerun `python src/baseline.py --save models/text_baseline.joblib`")
    return TfidfLrScorer(bundle)


def load_text_model() -> TextScorer:
    """The one place the text head is chosen: config.SHIELD_TEXT_HEAD (muril by default), falling back to the TF-IDF baseline with one line on
    stderr when the MuRIL bundle or torch / transformers is missing (config.text_head_choice)."""
    kind, _, fallback = config.text_head_choice()
    if fallback:
        print(fallback, file=sys.stderr, flush=True)
    if kind == config.MURIL_KIND:
        return MurilScorer(config.MURIL_DIR, config.TEXT_DEVICE)
    return load_baseline()
