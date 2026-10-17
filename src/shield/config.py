import hashlib, json
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEXT_MODEL_PATH, URL_MODEL_PATH = ROOT / "models" / "text_baseline.joblib", ROOT / "models" / "url_head.joblib"
# Gambling lookup files (git-ignored, built by src/gambling_lookup.py; decision G1)
GAMBLING_DOMAINS_PATH = ROOT / "data" / "final" / "gambling_domains.tsv"
GAMBLING_PLATFORM_HOSTS_PATH = ROOT / "data" / "final" / "gambling_platform_hosts.tsv"
GAMBLING_INDIA_PATH = ROOT / "data" / "final" / "gambling_india.json"

# Safety-advice cap (decision S1 once enabled; reports/otp_advisory.md): a message whose only reason for Suspicious is the text head, and which contains
# standard "never share your OTP" advice and none of the signs of a scam wrapped around it (router.safety_advice_cap), is shown as No warning signs.
# The default for the app and the API; analyse(..., safety_cap=True / False) overrides it per call (the tests run both).
SAFETY_ADVICE_CAP = False

# What kind of model sits behind each path above, for Report.meta.models. If load_text_model() is switched to another head (MuRIL),
# change TEXT_MODEL_PATH and this kind together.
TEXT_MODEL_KIND, URL_MODEL_KIND = "tfidf-lr", "hgb-host"   # TF-IDF char n-grams + logistic regression; host-only HistGradientBoosting


def _sha8(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()[:8]


@lru_cache(maxsize=1)
def model_versions() -> dict[str, str]:
    """Which models produced a Report: {"text": "<kind> <first 8 hex of the file's SHA-256>", "url": same, "gambling_lookup": "<snapshot date>"}.
    Read from the files the loaders load (TEXT_MODEL_PATH, URL_MODEL_PATH, GAMBLING_INDIA_PATH). Computed once per process, never per request
    (the API warms it at startup); callers must copy the dict. A missing file raises FileNotFoundError, as its loader would."""
    with open(GAMBLING_INDIA_PATH, encoding="utf-8") as f:
        snapshot = json.load(f)["snapshot"]
    return {"text": f"{TEXT_MODEL_KIND} {_sha8(TEXT_MODEL_PATH)}", "url": f"{URL_MODEL_KIND} {_sha8(URL_MODEL_PATH)}", "gambling_lookup": snapshot}
