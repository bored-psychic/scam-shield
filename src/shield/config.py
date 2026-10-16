from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEXT_MODEL_PATH, URL_MODEL_PATH = ROOT / "models" / "text_baseline.joblib", ROOT / "models" / "url_head.joblib"
