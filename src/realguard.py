"""Tripwire for the real-message test set (CLAUDE.md, frozen hashes). Stdlib only, so the Kaggle and 2nd-laptop training scripts can import it.

Rule: data/real/real_test_v1.csv is TEST ONLY. Nothing may train, tune, calibrate or choose a threshold on it. Two checks, both raise
RealDataTripwire (a SystemExit, so the script stops with the message):
  1. refuse_real_paths: no input path lies under data/real/.
  2. guard_inputs: no row of an input frame has a text that is one of the real test rows (source_row_hash), matched by the same key
     (md5 of the lower-cased, whitespace-collapsed text, the key build_text.py uses for messages.csv text_hash).
The real-test hashes are read from REAL_TEST_PATH when it exists; with no file, only check 1 can fire.

The probe sets in data/probe/ (e.g. investment_v1.csv, docs/plans/investment_scams.md) are PROBE-ONLY, eval only, and get the same two checks:
no input path under data/probe/ (or the older git-ignored data/probes/), and no input row whose text key is a data/probe/ row's text key.
"""
import csv, hashlib, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REAL_DIR = ROOT / "data" / "real"
REAL_TEST_PATH = REAL_DIR / "real_test_v1.csv"
PROBE_DIR = ROOT / "data" / "probe"
# data/probes/: an older git-ignored investment probe (2026-10-22). Path check only: it copies rows of messages.csv, so its texts are not keys.
PROBE_DIRS = (PROBE_DIR, ROOT / "data" / "probes")


class RealDataTripwire(SystemExit):
    pass


def norm_key(text):
    """The row key: md5 of the lower-cased text with whitespace runs collapsed (build_text.py's text_hash, without strip)."""
    return hashlib.md5(re.sub(r"\s+", " ", str(text).lower()).encode()).hexdigest()


def real_hashes(path=None):
    path = Path(path or REAL_TEST_PATH)
    if not path.exists():
        return set()
    with open(path, encoding="utf-8", newline="") as f:
        return {r["source_row_hash"] for r in csv.DictReader(f)}


def probe_hashes(dirs=None):
    """The text keys of every row of every CSV with a 'text' column in data/probe/ (or the given folders)."""
    out = set()
    for d in dirs or (PROBE_DIR,):
        for f in sorted(Path(d).glob("*.csv")) if Path(d).is_dir() else ():
            with open(f, encoding="utf-8", newline="") as fh:
                out |= {norm_key(r["text"]) for r in csv.DictReader(fh) if r.get("text")}
    return out


def refuse_real_paths(paths):
    """Raise if any path (file or folder) is under data/real/ or a probe folder (data/probe/, data/probes/)."""
    for p in paths:
        q = Path(p)
        q = (ROOT / q if not q.is_absolute() else q).resolve()
        if q == REAL_DIR.resolve() or REAL_DIR.resolve() in q.parents:
            raise RealDataTripwire(f"refused: {p} is under data/real/, the real-message TEST set. It is never a training, tuning or calibration input.")
        for d in PROBE_DIRS:
            if q == d.resolve() or d.resolve() in q.parents:
                raise RealDataTripwire(f"refused: {p} is under {d.relative_to(ROOT)}/, a PROBE-ONLY set. It is never a training, tuning or calibration input.")


def guard_inputs(paths=(), frames=(), real_path=None, probe_dirs=None):
    """Both checks: the paths, then every frame (a pandas DataFrame or a list of dicts with a 'text' or 'text_hash' key), against the real
    test rows and the probe rows."""
    refuse_real_paths(paths)
    sets = [(real_hashes(real_path), "a real test row (data/real/real_test_v1.csv)"), (probe_hashes(probe_dirs), "a PROBE-ONLY row (data/probe/)")]
    sets = [(h, what) for h, what in sets if h]
    if not sets:
        return
    for name, df in frames:
        cols = set(df.columns) if hasattr(df, "columns") else set()
        keys = [norm_key(t) for t in df["text"]] if "text" in cols else []
        for hashes, what in sets:
            if "text_hash" in cols and set(map(str, df["text_hash"])) & hashes:
                raise RealDataTripwire(f"refused: {name} has text_hash values equal to {what}.")
            hit = sum(k in hashes for k in keys)
            if hit:
                raise RealDataTripwire(f"refused: {name} has {hit} rows whose text is {what}.")
