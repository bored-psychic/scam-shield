from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEXT_MODEL_PATH, URL_MODEL_PATH = ROOT / "models" / "text_baseline.joblib", ROOT / "models" / "url_head.joblib"
# Gambling lookup files (git-ignored, built by src/gambling_lookup.py; decision G1)
GAMBLING_DOMAINS_PATH = ROOT / "data" / "final" / "gambling_domains.tsv"
GAMBLING_PLATFORM_HOSTS_PATH = ROOT / "data" / "final" / "gambling_platform_hosts.tsv"
GAMBLING_INDIA_PATH = ROOT / "data" / "final" / "gambling_india.json"
