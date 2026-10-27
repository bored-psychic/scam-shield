import argparse, hashlib, json, subprocess, sys, tempfile
from pathlib import Path

import pandas as pd

# How many of the LOSO sources' val + test rows get a different model input under the current preprocessing than under the code the shipped bundle was trained
# with (commit 06f402e, shield_meta.json "git_commit")? Preprocessing only: no model, no score, no text printed. textprep.model_text depends on three files
# (textprep.py, pii.py, url_features.py), so all three are taken from the old commit, imported in a separate Python process (-I, the old files first on
# sys.path) and compared by SHA-256 of the output, row by row, with the current model_text. Counts per source go to reports/eval_preds/loso_muril/textprep_drift.json,
# which src/eval_loso.py states under the section 9 table. A fold trained on Kaggle runs the current code, the in-distribution numbers come from the old model
# scored on 06f402e's inputs, so a non-zero count is a (small) difference between the two columns that is not about the source.
#   .venv/bin/python src/textprep_drift.py [--old 06f402e]

ROOT = Path(__file__).resolve().parent.parent
FILES = ("textprep.py", "pii.py", "url_features.py")
OUT = ROOT / "reports/eval_preds/loso_muril/textprep_drift.json"
OLD_COMMIT = "06f402e"   # the shipped bundle's git_commit

CHILD = '''
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from textprep import model_text
texts = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
Path(sys.argv[2]).write_text(json.dumps([hashlib.sha256(model_text(t).encode("utf-8")).hexdigest() for t in texts]), encoding="utf-8")
'''


def git(*a):
    return subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def old_hashes(texts, ref, tmp):
    """SHA-256 of model_text(t) under the code of commit `ref`, one entry per text."""
    code = Path(tmp) / "old"
    code.mkdir()
    for f in FILES:
        (code / f).write_text(git("show", f"{ref}:src/{f}"), encoding="utf-8")
    (code / "child.py").write_text(CHILD, encoding="utf-8")
    (Path(tmp) / "in.json").write_text(json.dumps(list(texts)), encoding="utf-8")
    subprocess.run([sys.executable, "-I", str(code / "child.py"), str(Path(tmp) / "in.json"), str(Path(tmp) / "out.json")], check=True, cwd=tmp)
    return json.loads((Path(tmp) / "out.json").read_text(encoding="utf-8"))


def drift(df, sources, ref=OLD_COMMIT):
    """{source: {"rows": n, "changed": k}} over each source's val + test rows of `df` (messages.csv)."""
    sys.path.insert(0, str(ROOT / "src"))
    from textprep import model_text
    rows = df[df["source"].isin(sources) & df["split"].isin(["val", "test"])]
    with tempfile.TemporaryDirectory() as tmp:
        old = old_hashes(rows["text"], ref, tmp)
    new = [hashlib.sha256(model_text(t).encode("utf-8")).hexdigest() for t in rows["text"]]
    changed = pd.Series([a != b for a, b in zip(old, new)], index=rows.index)
    return {s: {"rows": int((rows["source"] == s).sum()), "changed": int(changed[rows["source"] == s].sum())} for s in sources}


def main():
    sys.path.insert(0, str(ROOT / "src"))
    from finetune import LOSO_FOLDS
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--old", default=OLD_COMMIT)
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args()
    df = pd.read_csv(ROOT / "data/final/messages.csv", low_memory=False, usecols=["text_hash", "text", "source", "split"])
    res = drift(df, LOSO_FOLDS, a.old)
    for s, r in res.items():
        print(f"{s}: {r['changed']} of {r['rows']} val + test rows get a different model_text under the current code than under {a.old}")
    new = git("rev-parse", "--short", "HEAD").strip()
    dirty = bool(git("status", "--porcelain", "--untracked-files=no", "--", *[f"src/{f}" for f in FILES]).strip())
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps({"old_commit": a.old, "new_commit": new + ("+uncommitted" if dirty else ""), "files": list(FILES), "sources": res}, indent=2), encoding="utf-8")
    print("wrote", a.out)


if __name__ == "__main__":
    main()
