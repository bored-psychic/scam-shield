import hashlib, json, os
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEXT_MODEL_PATH, URL_MODEL_PATH = ROOT / "models" / "text_baseline.joblib", ROOT / "models" / "url_head.joblib"
# Gambling lookup files (git-ignored, built by src/gambling_lookup.py; decision G1)
GAMBLING_DOMAINS_PATH = ROOT / "data" / "final" / "gambling_domains.tsv"
GAMBLING_PLATFORM_HOSTS_PATH = ROOT / "data" / "final" / "gambling_platform_hosts.tsv"
GAMBLING_INDIA_PATH = ROOT / "data" / "final" / "gambling_india.json"
# Link checks (D23). Downloaded lists (git-ignored; src/update_link_lists.py) and the tracked, curated reference files beside the code.
LINKLISTS_DIR = ROOT / "data" / "final" / "linklists"
_LINKS_DIR = ROOT / "src" / "shield" / "links"
BRAND_TLDS_PATH = _LINKS_DIR / "brand_tlds.json"           # verified by update_link_lists.py against ICANN gtlds.json + IANA root zone
BRANDS_INDIA_PATH = _LINKS_DIR / "brands_india.json"       # brand -> name tokens, registered domains it owns, its brand TLDs
RESTRICTED_ZONES_PATH = _LINKS_DIR / "restricted_zones.json"   # .bank.in (P1), .gov.in / .nic.in (display only)
ABUSE_TLDS_PATH = _LINKS_DIR / "abuse_tlds.json"           # cited high-abuse TLD names (display only)
# Live link checks (D23, D2: on by default). SHIELD_LIVE_CHECKS=0 turns every network check off ("not checked"); the offline checks still run.
# The Safe Browsing key is read from the environment at call time (shield.links.live), never stored here.
LIVE_CHECKS = os.environ.get("SHIELD_LIVE_CHECKS", "1") != "0"

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
