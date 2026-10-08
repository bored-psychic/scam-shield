import argparse
import joblib
import numpy as np, pandas as pd
import neardup as nd
from textprep import model_text, URL_TOKEN, MAX_CHARS
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, recall_score

# Smoke test: char n-gram TF-IDF + logistic regression on data/final/messages.csv.
# Per-source / per-language scores expose sources that are trivially separable; the adversarial
# test set (src/augment.py) shows how much simple obfuscation costs.
#   python src/baseline.py --max-len 500 --exclude-source fake_job_postings phishing_email
#   python src/baseline.py --save models/text_baseline.joblib      (the model src/app.py loads)
ap = argparse.ArgumentParser()
ap.add_argument("--max-len", type=int, help="drop messages longer than this (train and test)")
ap.add_argument("--exclude-source", nargs="*", default=[], help="sources to drop")
ap.add_argument("--save", metavar="PATH", help="also save the fitted vectorizer + model + val-chosen thresholds (the app loads models/text_baseline.joblib)")
args = ap.parse_args()

df = pd.read_csv("data/final/messages.csv", low_memory=False)
df["has_train_twin"] = df.index.isin(nd.train_twin_rows(df))   # val/test rows with a train row at Jaccard >= 0.6; before any filtering, so positions match
df = df[~df["source"].isin(args.exclude_source)]
if args.max_len:
    df = df[df["text"].str.len() <= args.max_len]
df["text"] = df["text"].map(model_text)   # URLs -> <URL>, then the first 2000 characters (textprep.py); messages.csv and text hashes are untouched
tr, va, te = df[df["split"] == "train"], df[df["split"] == "val"], df[df["split"] == "test"]
print(f"train {len(tr)}, val {len(va)}, test {len(te)}; excluded {args.exclude_source or 'none'}, max_len {args.max_len}")

# length-only model: how much of the score a shortcut alone gets
loglen = lambda d: np.log1p(d["text"].str.len()).to_frame()
lenclf = LogisticRegression(class_weight="balanced").fit(loglen(tr), tr["label"])
print(f"length-only F1 {f1_score(te['label'], lenclf.predict(loglen(te))):.3f}")

vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=3, max_features=200000, sublinear_tf=True)
clf = LogisticRegression(max_iter=2000, class_weight="balanced")
clf.fit(vec.fit_transform(tr["text"]), tr["label"])
te = te.assign(pred=clf.predict(vec.transform(te["text"])))
va = va.assign(pred=clf.predict(vec.transform(va["text"])))

if args.save:
    # Thresholds for the app's three levels, both chosen on val only (never test): "likely" = max-F1 score threshold,
    # "suspicious" = highest score that still keeps val scam recall >= 0.95. Scores are uncalibrated LR probabilities
    # (class_weight=balanced), so they rank messages but are not true probabilities; calibration is a later step.
    sv = clf.predict_proba(vec.transform(va["text"]))[:, 1]
    grid = np.unique(np.quantile(sv, np.linspace(0.01, 0.99, 197)))
    t_likely = float(grid[int(np.argmax([f1_score(va["label"], sv >= t) for t in grid]))])
    t_susp = float(max(t for t in grid if recall_score(va["label"], sv >= t) >= 0.95))
    joblib.dump({"vectorizer": vec, "model": clf, "threshold_suspicious": min(t_susp, t_likely), "threshold_likely": t_likely,
                 "trained_on": f"train split, excluded {args.exclude_source or 'none'}, max_len {args.max_len}, textprep.model_text",
                 "textprep": {"url_token": URL_TOKEN, "max_chars": MAX_CHARS}}, args.save)   # app.py refuses a model without this key
    print(f"saved {args.save}: suspicious >= {min(t_susp, t_likely):.3f}, likely scam >= {t_likely:.3f} (val-chosen)")

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

# val/test rows with a near-duplicate train twin (>= 0.6 on either view) vs rows without
print("\nF1 by train-twin exposure (model fit on train only):")
rows = []
for name, d in (("val", va), ("test", te), ("val+test", pd.concat([va, te]))):
    for twin, g in d.groupby("has_train_twin"):
        rows.append({"split": name, "train_twin": twin, "n": len(g), "scam": int(g["label"].sum()),
                     "F1": round(f1_score(g["label"], g["pred"], zero_division=0), 3),
                     "scam_recall": round(recall_score(g["label"], g["pred"], zero_division=0), 3)})
print(pd.DataFrame(rows).to_string(index=False))

# adversarial variants join to their clean parent on parent_hash (stable if messages.csv is rebuilt), not row position
adv = pd.read_csv("data/final/messages_adv_test.csv")
parent = te.drop_duplicates("text_hash").set_index("text_hash")["pred"]
adv = adv[adv["parent_hash"].isin(parent.index)].copy()
adv["pred"] = clf.predict(vec.transform(adv["text"].map(model_text)))
adv["parent_pred"] = adv["parent_hash"].map(parent)
for name, a in (("all parents", adv), ("real parents only", adv[~adv["parent_is_synthetic"]])):
    print(f"\nadversarial scam recall, {name} ({len(a)} variants, {a['parent_hash'].nunique()} parents); "
          f"clean parents: {a.drop_duplicates('parent_hash')['parent_pred'].mean():.3f}")
    print(a.groupby("aug_method").agg(n=("pred", "size"), recall=("pred", "mean"), parent_recall=("parent_pred", "mean")).round(3).to_string())
