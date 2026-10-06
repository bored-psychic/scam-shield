import argparse
import numpy as np, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, recall_score

# Smoke test: char n-gram TF-IDF + logistic regression on data/final/messages.csv.
# Per-source / per-language scores expose sources that are trivially separable; the adversarial
# test set (src/augment.py) shows how much simple obfuscation costs.
#   python src/baseline.py --max-len 500 --exclude-source fake_job_postings phishing_email
ap = argparse.ArgumentParser()
ap.add_argument("--max-len", type=int, help="drop messages longer than this (train and test)")
ap.add_argument("--exclude-source", nargs="*", default=[], help="sources to drop")
args = ap.parse_args()

df = pd.read_csv("data/final/messages.csv")
df = df[~df["source"].isin(args.exclude_source)]
if args.max_len:
    df = df[df["text"].str.len() <= args.max_len]
df["text"] = df["text"].str[:2000]
tr, te = df[df["split"] == "train"], df[df["split"] == "test"]
print(f"train {len(tr)}, test {len(te)}; excluded {args.exclude_source or 'none'}, max_len {args.max_len}")

# length-only model: how much of the score a shortcut alone gets
loglen = lambda d: np.log1p(d["text"].str.len()).to_frame()
lenclf = LogisticRegression(class_weight="balanced").fit(loglen(tr), tr["label"])
print(f"length-only F1 {f1_score(te['label'], lenclf.predict(loglen(te))):.3f}")

vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=3, max_features=200000, sublinear_tf=True)
clf = LogisticRegression(max_iter=2000, class_weight="balanced")
clf.fit(vec.fit_transform(tr["text"]), tr["label"])
te = te.assign(pred=clf.predict(vec.transform(te["text"])))

real = te[~te["is_synthetic"]]
print(f"test F1 {f1_score(te['label'], te['pred']):.3f} (n={len(te)}); "
      f"real-only F1 {f1_score(real['label'], real['pred']):.3f} (n={len(real)})")
for col in ("source", "language", "channel"):
    rows = []
    for k, g in te.groupby(col):
        acc = (g["label"] == g["pred"]).mean()
        rec = recall_score(g["label"], g["pred"], zero_division=0) if g["label"].any() else float("nan")
        rows.append({col: k, "n": len(g), "scam": int(g["label"].sum()), "acc": round(acc, 3), "scam_recall": round(rec, 3)})
    print("\n", pd.DataFrame(rows).to_string(index=False))

adv = pd.read_csv("data/final/messages_adv_test.csv")
adv = adv[adv["orig_id"].isin(te.index)]
adv["pred"] = clf.predict(vec.transform(adv["text"].str[:2000]))
orig = te.loc[te.index.isin(adv["orig_id"]), "pred"].mean()
print(f"\nscam recall on clean originals {orig:.3f}; on adversarial variants:")
print(adv.groupby("aug_method")["pred"].mean().round(3).to_string())
