import hashlib, importlib.util, json, os
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
# The crt.sh certificate-age fallback (R8) is OFF by default: in the 2026-10-22 live evaluation crt.sh gave no usable answer for 93% of requests after two
# retries (66 of 68 failed on the first try: HTTP 429 or timeout) and R8 never fired, so it only added delay (decision C1, docs/decisions/README.md).
# SHIELD_CRTSH=1 turns it back on.
CRTSH_CHECK = os.environ.get("SHIELD_CRTSH", "0") == "1"
# Decision C2 (2026-10-23, variant b): the host-only URL model, with no link check agreeing, may raise a link to Suspicious at most; Likely scam needs
# link-check evidence (a red flag R1-R9). In the 2026-10-22 live evaluation the model alone fired on 27 of the 29 flagged benign domains, and 3 of them
# reached Likely scam. 2 = the old behaviour (the scripts/eval_live_links.py variant (a) sets it for the "before" rows). SHIELD_URL_ALONE_MAX=2 restores it.
URL_ALONE_MAX_LEVEL = int(os.environ.get("SHIELD_URL_ALONE_MAX", "1"))

# Safety-advice cap (decision S1 once enabled; reports/otp_advisory.md): a message whose only reason for Suspicious is the text head, and which contains
# standard "never share your OTP" advice and none of the signs of a scam wrapped around it (router.safety_advice_cap), is shown as No warning signs.
# The default for the app and the API; analyse(..., safety_cap=True / False) overrides it per call (the tests run both).
SAFETY_ADVICE_CAP = False

# What kind of model sits behind each path, for Report.meta.models.
TEXT_MODEL_KIND, URL_MODEL_KIND = "tfidf-lr", "hgb-host"   # TF-IDF char n-grams + logistic regression; host-only HistGradientBoosting
MURIL_KIND = "muril"

# The text head (D27). SHIELD_TEXT_HEAD=muril (default) loads the fine-tuned MuRIL bundle below; SHIELD_TEXT_HEAD=baseline loads the TF-IDF
# baseline (TEXT_MODEL_PATH). The bundle's weights are git-ignored (950 MB), so on a fresh clone, or without torch / transformers installed, the
# app falls back to the baseline and says so once at startup (text_head_choice()). The bundle's shield_meta.json carries the val-fitted
# temperature, cut-offs and meter ends (src/calibrate_text_head.py, reports/calibration_muril_v2.md).
TEXT_HEAD = os.environ.get("SHIELD_TEXT_HEAD") or "muril"   # unset or empty = the default
MURIL_DIR = ROOT / "models" / "finetune" / "muril_len128_20261021T135255Z"   # splits-v2, max_len 128, no aug (reports/eval_muril_v2.md)
# Where MuRIL runs: auto = the Mac GPU (MPS) if available, else CPU; or cpu / mps.
TEXT_DEVICE = os.environ.get("SHIELD_TEXT_DEVICE") or "auto"


@lru_cache(maxsize=1)
def text_head_choice() -> tuple[str, Path, str | None]:
    """(kind, weights file, fallback reason): which text head this process loads, decided once. The reason is None when the setting is honoured,
    otherwise the line load_text_model() prints. Only a MISSING bundle or missing packages fall back; a bundle that is there but fails its checks
    stops the app (load_text_model)."""
    if TEXT_HEAD not in ("muril", "baseline"):
        raise SystemExit(f"SHIELD_TEXT_HEAD={TEXT_HEAD!r}: use muril or baseline")
    if TEXT_HEAD == "baseline":
        return TEXT_MODEL_KIND, TEXT_MODEL_PATH, None
    weights = MURIL_DIR / "model" / "model.safetensors"
    missing = [m for m in ("torch", "transformers") if importlib.util.find_spec(m) is None]
    if missing:
        reason = f"{' and '.join(missing)} not installed"
    elif not weights.exists():
        reason = f"MuRIL bundle not found at {MURIL_DIR.relative_to(ROOT)}"
    else:
        return MURIL_KIND, weights, None
    return TEXT_MODEL_KIND, TEXT_MODEL_PATH, f"text head: {reason}; using the TF-IDF baseline ({TEXT_MODEL_PATH.relative_to(ROOT)})"


def _sha8(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()[:8]


@lru_cache(maxsize=1)
def model_versions() -> dict[str, str]:
    """Which models produced a Report: {"text": "<kind> <first 8 hex of the file's SHA-256>", "url": same, "gambling_lookup": "<snapshot date>"}.
    Read from the files the loaders load (text_head_choice()'s weights file, URL_MODEL_PATH, GAMBLING_INDIA_PATH). Computed once per process, never
    per request (the API warms it at startup); callers must copy the dict. A missing file raises FileNotFoundError, as its loader would."""
    with open(GAMBLING_INDIA_PATH, encoding="utf-8") as f:
        snapshot = json.load(f)["snapshot"]
    kind, path, _ = text_head_choice()
    return {"text": f"{kind} {_sha8(path)}", "url": f"{URL_MODEL_KIND} {_sha8(URL_MODEL_PATH)}", "gambling_lookup": snapshot}
