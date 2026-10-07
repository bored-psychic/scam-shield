import math, os, re, sys, time
from collections import Counter
from urllib.parse import urlsplit
import joblib
import numpy as np, pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score

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

# brand -> registered domains that genuinely own it. A brand token on any other domain is the lookalike signal.
BRANDS = {
    "sbi": ["onlinesbi.sbi", "sbi.co.in", "sbi.bank.in", "onlinesbi.com", "sbicard.com"], "onlinesbi": ["onlinesbi.sbi", "onlinesbi.com"],
    "hdfcbank": ["hdfcbank.com"], "icicibank": ["icicibank.com"], "axisbank": ["axisbank.com"], "kotak": ["kotak.com"],
    "paytm": ["paytm.com", "paytmbank.com"], "phonepe": ["phonepe.com"], "npci": ["npci.org.in"],
    "indiapost": ["indiapost.gov.in"], "irctc": ["irctc.co.in"], "incometax": ["incometax.gov.in", "incometaxindia.gov.in"],
    "uidai": ["uidai.gov.in"], "parivahan": ["parivahan.gov.in"], "flipkart": ["flipkart.com"], "cybercrime": ["cybercrime.gov.in"],
    "epfindia": ["epfindia.gov.in"], "amazon": ["amazon.in", "amazon.com", "amazon.co.uk", "amazon.de"], "google": ["google.com", "google.co.in"],
    "microsoft": ["microsoft.com", "live.com"], "apple": ["apple.com"], "paypal": ["paypal.com"], "facebook": ["facebook.com"],
    "instagram": ["instagram.com"], "whatsapp": ["whatsapp.com"], "netflix": ["netflix.com"],
}
SUSPICIOUS = ["login", "signin", "verify", "secure", "account", "update", "kyc", "bank", "wallet", "confirm", "support", "otp",
              "refund", "claim", "bonus", "prize", "free", "gift", "reward", "unlock", "suspend", "alert", "billing", "recover"]
EXEC_EXT = {".exe", ".apk", ".php", ".html", ".htm", ".zip", ".sh", ".js", ".asp", ".aspx"}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())

def lev(a, b, cap=3):
    """Levenshtein distance, capped (returns cap as soon as it can't be below it)."""
    if abs(len(a) - len(b)) >= cap:
        return cap
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) >= cap:
            return cap
        prev = cur
    return min(prev[-1], cap)

def host_features(host, reg):
    labels = host.split(".")
    reg_label = reg.split(".")[0]
    toks = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    is_ip = bool(IP_RE.match(host))
    f = {"host_len": len(host), "n_labels": len(labels), "subdomain_depth": 0 if is_ip else max(0, len(labels) - len(reg.split("."))),
         "n_hyphens": host.count("-"), "n_digits": sum(c.isdigit() for c in host), "host_entropy": entropy(host),
         "reg_label_len": len(reg_label), "reg_label_entropy": entropy(reg_label), "longest_label": max(map(len, labels)),
         "has_ip": int(is_ip), "punycode": int("xn--" in host), "non_ascii": sum(ord(c) > 127 for c in host),
         "n_suspicious_host": sum(k in host for k in SUSPICIOUS)}
    f["digit_ratio"] = f["n_digits"] / max(1, len(host))
    f["tld"] = reg.rsplit(".", 1)[-1] if "." in reg and not is_ip else ""
    # brand lookalikes: a brand as a whole token or long substring on a domain that doesn't own it, and the smallest edit
    # distance (cap 3) from a name token to a brand it isn't (exact matches on a legitimate domain score the cap)
    off_tok = off_sub = 0
    best = 3
    for b, legit in BRANDS.items():
        owns = reg in legit
        if not owns and b in toks:
            off_tok += 1
        if not owns and len(b) >= 5 and b in host:
            off_sub += 1
        if not owns and len(b) >= 4 and not is_ip:
            for t in {reg_label, *toks}:
                if len(t) >= 4 and t != b:
                    best = min(best, lev(t, b))
    f.update(brand_token_offsite=off_tok, brand_substr_offsite=off_sub, brand_min_dist=best)
    return f

def path_features(url):
    s = urlsplit(url if "://" in url else "http://" + url)
    path, q = s.path, s.query
    ext = os.path.splitext(path)[1].lower()
    return {"url_len": len(url), "path_len": len(path), "n_slashes": path.count("/"), "query_len": len(q),
            "n_params": q.count("&") + bool(q), "path_digits": sum(c.isdigit() for c in path + q), "path_entropy": entropy(path + q),
            "has_at": int("@" in url), "n_pct": url.count("%"), "double_slash_path": int("//" in path),
            "exec_ext": int(ext in EXEC_EXT), "n_suspicious_path": sum(k in (path + q).lower() for k in SUSPICIOUS)}

def log(m):
    print(m, file=sys.stderr, flush=True)

df = pd.read_csv("data/final/urls.csv", low_memory=False)
n_total = len(df)
t0 = time.time()
H = pd.DataFrame([host_features(h, r) for h, r in zip(df["host"], df["reg_domain"])], index=df.index)
P = pd.DataFrame([path_features(u) for u in df["url_noscheme"]], index=df.index)
log(f"features: {time.time() - t0:.0f}s")

# ---- populations ----
df["task"] = np.select([df["source"].isin(["ealvaradob", "tranco"]) & ~df["domain_conflict"], df["source"] == "openphish", df["source"] == "urlhaus"],
                       ["phishing_vs_benign", "openphish_heldout", "urlhaus_heldout"], "excluded_domain_conflict")
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
       "ealvaradob / tranco) are dropped from training and evaluation; `openphish_heldout` and `urlhaus_heldout` are scored only.\n\n" + md(acct),
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
joblib.dump({"model": models["host-only (main)"][0], "features": HOST, "top_tld": top_tld, "threshold": float(thr_main)}, MODEL_OUT)
print(md(res)); print(md(imp.head(12)))
log(f"wrote {OUT}, {PRED_OUT}, {MODEL_OUT}")
