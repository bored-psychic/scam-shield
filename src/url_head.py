import os, sys, time
import joblib
import numpy as np, pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score
from url_features import host_features, path_features   # shared with app.py

# URL head: gradient boosting on lexical features of data/final/urls.csv -> reports/url_head.md,
# data/final/url_preds.csv (scores for every row, for calibration / fusion), models/url_head.joblib.
#
# Population. Phishing vs benign, rows of `ealvaradob` (phishing + benign) and `tranco` (benign), with
# `domain_conflict` rows dropped (registered domains that carry both benign and bad rows, e.g. malware on github.io; the
# label is a property of the URL, not the domain, so a domain-level feature can't separate them). Never trained on:
#   openphish  300 phishing URLs from a different feed: the out-of-source test. Only recall can be measured (no benign
#              rows), so the false-positive rate is read from held-out benign. More pulls (src/pull_urls.py daily, then
#              build_urls.py) make it a "fresh" test: every row dated after the training pull is unseen by construction.
#   urlhaus    1000 malware URLs, a separate class (88% raw-IP hosts); recall only, never an input to the phishing task.
# Splits are the registered-domain splits in urls.csv (a domain never straddles splits); this script never re-splits.
#
# Features never used: scheme / https (build_urls.py: Tranco rows have https:// prepended, ealvaradob rows mostly have no
# scheme, so it is an artifact) and anything from `source`.
# Views: host-only (the main task, README: removes the has_path shortcut), host + TLD removed, full URL (adds path/query
# features), host-only + domain age. Shortcut-only models (length, has_ip + has_path, source) are the floor to beat.
#   python src/url_head.py
OUT, PRED_OUT, MODEL_OUT = "reports/url_head.md", "data/final/url_preds.csv", "models/url_head.joblib"
SEED = 0

def log(m):
    print(m, file=sys.stderr, flush=True)

df = pd.read_csv("data/final/urls.csv", low_memory=False)
n_total = len(df)
t0 = time.time()
H = pd.DataFrame([host_features(h, r) for h, r in zip(df["host"], df["reg_domain"])], index=df.index)
P = pd.DataFrame([path_features(u) for u in df["url_noscheme"]], index=df.index)
log(f"features: {time.time() - t0:.0f}s")

# ---- populations ----
# gambling_spam rows and the benign rows still waiting for the manual review (reports/gambling_manual_review.csv) are kept out of
# this binary phishing head until it is deliberately retrained on them (BUGS.md: subdomain-depth / TLD shortcuts of the new class)
df["task"] = np.select([df["label"] == "gambling_spam", df["provenance"] == "pending_review",
                        df["source"].isin(["ealvaradob", "tranco"]) & ~df["domain_conflict"], df["source"] == "openphish", df["source"] == "urlhaus"],
                       ["excluded_gambling_spam", "excluded_pending_review", "phishing_vs_benign", "openphish_heldout", "urlhaus_heldout"], "excluded_domain_conflict")
base = df["task"] == "phishing_vs_benign"
sp = df["split"].astype(str)
y = (df["label"] == "phishing").astype(int)   # urlhaus (malware) is only ever scored, never trained on
acct = pd.crosstab([df["task"], df["source"], df["label"]], df["split"])
acct["total"] = acct.sum(axis=1)

# TLD -> small categorical code: the 40 most frequent in train (base), everything else (and unseen) is 'other'
top_tld = H.loc[base & (sp == "train"), "tld"].value_counts().head(40).index.tolist()
H["tld_code"] = H["tld"].map({t: i for i, t in enumerate(top_tld)}).fillna(len(top_tld)).astype(int)
H["domain_age_days"] = df["domain_age_days"]   # NaN when not looked up; HistGradientBoosting handles NaN natively
H["noscheme_len_log"] = np.log1p(df["url_noscheme"].str.len())
H["has_path"] = df["has_path"].astype(int)

HOST = ["host_len", "n_labels", "subdomain_depth", "n_hyphens", "n_digits", "digit_ratio", "host_entropy", "reg_label_len",
        "reg_label_entropy", "longest_label", "has_ip", "punycode", "non_ascii", "n_suspicious_host", "brand_token_offsite",
        "brand_substr_offsite", "brand_min_dist", "tld_code"]
X = pd.concat([H, P], axis=1)
VIEWS = {  # name -> (features, categorical features)
    "host-only (main)": (HOST, ["tld_code"]),
    "host-only, no TLD": ([c for c in HOST if c != "tld_code"], []),
    "full URL (+ path/query)": (HOST + list(P.columns), ["tld_code"]),
    "host-only + domain age": (HOST + ["domain_age_days"], ["tld_code"]),
    "[shortcut] URL length only": (["noscheme_len_log"], []),
    "[shortcut] has_ip + has_path": (["has_ip", "has_path"], []),
}

# domain age is only usable once enrich_domains.py has covered the training rows: a column that is all-NaN in train can't be
# fit, and a sparsely covered one mostly learns "was looked up". Skip the view (and say so in the report) below this coverage.
MIN_AGE_COVERAGE = 0.5
age_cov = H.loc[base & (sp == "train"), "domain_age_days"].notna().mean()
if age_cov < MIN_AGE_COVERAGE:
    del VIEWS["host-only + domain age"]
    log(f"domain age covers {age_cov:.1%} of train rows: skipping the domain-age view")

def fit(cols, cats):
    m = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, max_leaf_nodes=31, l2_regularization=1.0, class_weight="balanced",
                                       early_stopping=False, categorical_features=[cols.index(c) for c in cats] or None, random_state=SEED)
    return m.fit(X.loc[base & (sp == "train"), cols], y[base & (sp == "train")])

def best_threshold(s, yy):
    ts = np.unique(np.quantile(s, np.linspace(0.01, 0.99, 197)))
    return ts[int(np.argmax([f1_score(yy, s >= t) for t in ts]))]

def rank_metrics(s, yy):
    return roc_auc_score(yy, s), average_precision_score(yy, s)

results, scores, models = [], pd.DataFrame(index=df.index), {}
for name, (cols, cats) in VIEWS.items():
    log(f"fit {name}")
    m = fit(cols, cats)
    models[name] = (m, cols, cats)
    s = pd.Series(m.predict_proba(X[cols])[:, 1], index=df.index)
    scores[name] = s
    vm, tm = base & (sp == "val"), base & (sp == "test")
    thr = best_threshold(s[vm], y[vm])
    eal = tm & (df["source"] == "ealvaradob")
    cross = tm & (((df["source"] == "tranco")) | ((df["source"] == "ealvaradob") & (y == 1)))
    op, uh = df["task"] == "openphish_heldout", df["task"] == "urlhaus_heldout"
    ben_t = tm & (y == 0)
    results.append({"view": name, "val AUROC": rank_metrics(s[vm], y[vm])[0], "test AUROC": rank_metrics(s[tm], y[tm])[0],
                    "test PR-AUC": rank_metrics(s[tm], y[tm])[1], "test F1 @val thr": f1_score(y[tm], s[tm] >= thr),
                    "ealvaradob-only AUROC": rank_metrics(s[eal], y[eal])[0],
                    "tranco-benign vs ealvaradob-phish AUROC": rank_metrics(s[cross], y[cross])[0],
                    "FPR tranco (test)": (s[tm & (df["source"] == "tranco")] >= thr).mean(),
                    "FPR ealvaradob benign (test)": (s[tm & (df["source"] == "ealvaradob") & (y == 0)] >= thr).mean(),
                    "recall ealvaradob phish (test)": (s[tm & (y == 1)] >= thr).mean(),
                    "recall openphish (all)": (s[op] >= thr).mean(),
                    "recall openphish (non-conflict)": (s[op & ~df["domain_conflict"]] >= thr).mean(),
                    "recall openphish (conflict)": (s[op & df["domain_conflict"]] >= thr).mean(),
                    "recall urlhaus": (s[uh] >= thr).mean(), "threshold": thr})
res = pd.DataFrame(results).set_index("view")

# ---- permutation importance of the main host-only model on val (which features carry it) ----
m, cols, cats = models["host-only (main)"]
vm = base & (sp == "val")
imp = permutation_importance(m, X.loc[vm, cols], y[vm], scoring="roc_auc", n_repeats=3, random_state=SEED, n_jobs=1)
imp = pd.DataFrame({"AUROC drop when shuffled": imp.importances_mean}, index=cols).sort_values("AUROC drop when shuffled", ascending=False)
imp.index.name = "feature"

# ---- domain age coverage ----
cov = df.assign(has_age=df["domain_age_days"].notna()).query("task == 'phishing_vs_benign'").groupby(["split", "label"], observed=True)["has_age"].agg(["size", "mean"])
cov.columns = ["rows", "share with domain age"]

# ---- the main model's errors on openphish, to read ----
mm, cols, _ = models["host-only (main)"]
op_rows = df.loc[df["task"] == "openphish_heldout", ["url", "domain_conflict"]].assign(score=scores["host-only (main)"])
thr_main = res.loc["host-only (main)", "threshold"]
missed = op_rows[op_rows["score"] < thr_main].sort_values("score").head(12)

def md(d, index=True):
    d = d.reset_index() if index else d
    cells = [[str(c) for c in d.columns]] + [[f"{v:.3f}" if isinstance(v, (float, np.floating)) and not pd.isna(v) else ("" if pd.isna(v) else str(v))
                                              for v in r] for r in d.itertuples(index=False)]
    lines = ["| " + " | ".join(r) + " |" for r in cells]
    lines.insert(1, "|" + "|".join(" --- " for _ in cells[0]) + "|")
    return "\n".join(lines)

out = ["# URL head\n",
       f"Generated by `src/url_head.py`. HistGradientBoosting (200 iters, lr 0.1, 31 leaves, l2 1.0, `class_weight=balanced`, no tuning), "
       f"fit on the train split of the phishing-vs-benign population only. Thresholds are chosen on val (max F1) and applied unchanged to test and to "
       f"the held-out feeds. Domain-grouped splits from `urls.csv`.\n",
       "## Row accounting\n\n" + f"{n_total} rows in `urls.csv`. `excluded_domain_conflict` rows (a registered domain with both benign and bad rows, from "
       "ealvaradob / tranco) are dropped from training and evaluation, and so are `excluded_gambling_spam` (the gambling category, see "
       "`reports/urls_gambling.md`) and `excluded_pending_review`; `openphish_heldout` and `urlhaus_heldout` are scored only.\n\n" + md(acct),
       "\n## Results\n\n`ealvaradob-only AUROC` is the fair within-source number (both labels from the same feed). "
       "`tranco-benign vs ealvaradob-phish AUROC` mixes sources (popular bare domains against the phishing feed): a high value there with a low "
       "ealvaradob-only value would mean the model learned the source. OpenPhish and URLhaus have no benign rows, so only recall is shown; read it "
       "next to the FPR columns. `[shortcut]` rows are the floor to beat.\n\n" + md(res),
       "\n## What carries the main model (permutation importance on val)\n\n" + md(imp.head(12)),
       "\n## Domain age coverage (phishing-vs-benign rows)\n\n" + (f"Train coverage is {age_cov:.1%}, below the {MIN_AGE_COVERAGE:.0%} minimum, so the `host-only + domain age` view was **not run**: "
       "`enrich_domains.py` has only looked up domains from the top of `urls.csv` (URLhaus / OpenPhish / conflict rows), none of the training rows. "
       "The comparison needs the batch job finished first (about 45k registered domains at 0.5 s each, roughly 6 hours). "
       if age_cov < MIN_AGE_COVERAGE else "") + "Coverage is also uneven by label, so missingness itself could become a shortcut.\n\n" + md(cov),
       "\n## OpenPhish URLs the main model misses (lowest scores)\n\nMalicious URLs, stored as strings only, never visited.\n\n" + md(missed, index=False)]
os.makedirs("reports", exist_ok=True)
open(OUT, "w").write("\n".join(out) + "\n")

pred = df[["url", "label", "source", "split", "task", "domain_conflict"]].copy()
for n in ("host-only (main)", "full URL (+ path/query)"):
    pred["score_" + ("host" if "host" in n else "full")] = scores[n].round(5)
pred.to_csv(PRED_OUT, index=False)
os.makedirs("models", exist_ok=True)
# reference = a typical benign host (train, phishing_vs_benign, label benign): median per feature, most frequent TLD code. app.py
# explains one URL by the score change when each feature is replaced by its reference value (occlusion; features are correlated,
# so single-feature effects understate shared signals).
ref_rows = X.loc[base & (sp == "train") & (y == 0), HOST]
reference = {c: float(ref_rows[c].median()) for c in HOST}
reference["tld_code"] = int(ref_rows["tld_code"].mode().iloc[0])
# second app level: the lowest val score at which val precision reaches 0.95 (val is 28% phishing, so this says little about
# precision on real traffic); "threshold" above stays the max-F1 level. inf if val never reaches it.
sv_main, yv_main = scores["host-only (main)"][base & (sp == "val")], y[base & (sp == "val")]
hi_grid = [t for t in np.unique(np.quantile(sv_main, np.linspace(0.01, 0.999, 300))) if (yv_main[sv_main >= t].mean() >= 0.95)]
thr_high = float(min(hi_grid)) if hi_grid else float("inf")
joblib.dump({"model": models["host-only (main)"][0], "features": HOST, "top_tld": top_tld, "threshold": float(thr_main),
             "threshold_high": thr_high, "reference": reference}, MODEL_OUT)
print(md(res)); print(md(imp.head(12)))
log(f"wrote {OUT}, {PRED_OUT}, {MODEL_OUT}")
