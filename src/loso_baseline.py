import argparse, json
from pathlib import Path

import numpy as np, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from textprep import model_text, URL_TOKEN, MAX_CHARS
from finetune import SPLIT_MAP_SHA256, LOSO_FOLDS, LOSO_RULE, load_data, split_loso, sha256

# The TF-IDF baseline's leave-one-source-out (LOSO) folds under the same rule as the MuRIL folds ("cluster-strict", finetune.LOSO_RULE): for each source in
# LOSO_FOLDS, train on the TRAIN rows that remain after split_loso (no row that shares a cluster_id with any row of the source, whatever its source or
# translation_of), then score the source's own val + test rows. The model and its settings are src/sanity_checks.py section 5's, line for line (char_wb 2-4
# grams, min_df 3, 200k features, sublinear tf, logistic regression with balanced class weights, vectorizer refit per fold, input = textprep.model_text);
# only the rows dropped from training differ. The old rule dropped just the source's own rows and kept the translations of its parents and other sources'
# near copies, so the old numbers in reports/sanity.md section 5 are the optimistic reference ("old rule").
#   .venv/bin/python src/loso_baseline.py        # 4 folds, CPU, a few minutes
# Output, committed like the other cached predictions: reports/eval_preds/loso_baseline_cluster_strict/<source>/{predictions_loso.csv, meta.json}.
# predictions_loso.csv: text_hash, split, label, score = the logistic regression's decision function (the 0.5-probability cut-off is score >= 0, as in
# sanity_checks.py). src/eval_loso.py computes F1 / AUROC / PR-AUC from it and puts the old rule's row from sanity.md beside it.

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data/final"
OUT = ROOT / "reports/eval_preds/loso_baseline_cluster_strict"
TFIDF = {"analyzer": "char_wb", "ngram_range": [2, 4], "min_df": 3, "max_features": 200000, "sublinear_tf": True}
LR = {"max_iter": 2000, "class_weight": "balanced"}


def fold(src, data=DATA):
    """(predictions DataFrame, meta dict) for one held-out source; trains on the fold's train rows only (val is not used, as in sanity_checks.py)."""
    df = load_data(data, False, False, src)[0]
    tr, va, held_va, held_te, counts = split_loso(df, src)
    held = pd.concat([held_va, held_te], ignore_index=True)
    vec = TfidfVectorizer(**{**TFIDF, "ngram_range": tuple(TFIDF["ngram_range"])})
    m = LogisticRegression(**LR).fit(vec.fit_transform(tr["text"].map(model_text)), tr["label"])
    score = m.decision_function(vec.transform(held["text"].map(model_text)))
    preds = pd.DataFrame({"text_hash": held["text_hash"].to_numpy(), "split": held["split"].to_numpy(), "label": held["label"].astype(int).to_numpy(), "score": score})
    meta = {"rule": LOSO_RULE, "exclude_source": src, "split_map_sha256": SPLIT_MAP_SHA256, "messages_sha256": sha256(data / "messages.csv"),
            "textprep": {"url_token": URL_TOKEN, "max_chars": MAX_CHARS}, "tfidf": TFIDF, "logistic_regression": LR, "trained_on": "train split only (as sanity_checks.py)",
            "rows": {"train": len(tr), "scored": len(held)}, "loso_dropped": counts, "score": "decision function; F1 at the 0.5-probability cut-off = score >= 0"}
    return preds, meta


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sources", nargs="*", default=LOSO_FOLDS, help=f"default {LOSO_FOLDS}")
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args()
    for src in a.sources:
        preds, meta = fold(src)
        d = a.out / src
        d.mkdir(parents=True, exist_ok=True)
        preds.to_csv(d / "predictions_loso.csv", index=False, encoding="utf-8")
        (d / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        print(f"{src}: trained on {meta['rows']['train']} rows, scored {meta['rows']['scored']}, dropped {meta['loso_dropped']} -> {d}", flush=True)


if __name__ == "__main__":
    main()
