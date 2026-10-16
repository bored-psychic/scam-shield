import argparse, ast, os, re, sys, time
from pathlib import Path
from urllib.parse import urlsplit
import joblib
import numpy as np, pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score
from url_features import host_features, path_features, normalise_host, parse_url, host_row, WWW_LABEL
from shield.core.verdict import r3, level_of   # the app's level rule: scores and cut-offs compared at 3 decimals

# URL head experiments: does stripping "www." help, are the brand features doing anything, and is the full-URL view worth its path
# shortcut? Candidates only: nothing here replaces models/url_head.joblib or touches src/shield (the app).
#   python src/url_experiments.py                              -> models/candidates/url_{A,B,C,D,E,F}.joblib, reports/url_experiments.md
#   python src/url_experiments.py --ref-current DIR --ref-old URLS_OLD DIR_OLD   also prove the harness reproduces url_head.py (below)
#   python src/url_experiments.py ... --check-only             only the reproduction checks, writes nothing
# Variants (all: train split of the phishing-vs-benign population, url_head.py's exact HGB settings and thresholds rule):
#   A host-only, host as-is   B host-only, one leading www label stripped   C = B without the brand_* features
#   D full URL (host + path / query features), www stripped from the host AND from the URL string the path features read
#   E = D trained on train + augment_benign    F = A trained on train + augment_benign   (experiment E/F, 2026-10-17)
# augment_benign: the Tranco benign TRAIN rows are bare registered domains with no www, no "/" and no path in 100% of rows (the corpus
# writes benign URLs one way), so every model that sees the host's www or a path can learn the writing, not the host. For each such
# row up to 3 variants are added to the TRAIN set only: https://www.<d>/ , https://<d>/ , http://<d> (source tranco_aug, is_synthetic
# True, never in val / test, asserted). Val and test are the unchanged real rows.
# Settings are read out of src/url_head.py with ast, not imported (importing it would run it and overwrite its outputs) and not
# copied (so the two cannot drift apart): HOST, SEED, the HGB keyword arguments, best_threshold, rank_metrics, md and the statements
# that define the population (task, base, sp, y). A is the url_head.py main model re-fit on the CURRENT urls.csv, NOT the deployed
# models/url_head.joblib (that one was fit on the 62,969-row file before gambling_spam / pending_review were excluded).
#
# Test discipline. Everything that selects (thresholds, the metric tables, importance, probes, the recommendation) sees train / val
# rows only. The test split is read in exactly one function, test_once(), called once after the recommendation is written.
# (--check-only, which exits before any selection, also scores the test rows to compare predictions with url_head.py's file; no label
# or metric is read from them.)
OUT, CAND_DIR = "reports/url_experiments.md", "models/candidates"
URLS = "data/final/urls.csv"
SCHEME_RX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")   # as build_urls.py makes url_noscheme
WWW_AT_START = re.compile(r"^([^/?#]*@)?(www[1-9]?\.)", re.I)

GENUINE = ["https://www.google.com/", "https://www.hdfcbank.com/", "https://netbanking.hdfcbank.com/netbanking/", "https://www.onlinesbi.sbi/",
           "https://www.irctc.co.in/nget/train-search", "https://www.amazon.in/gp/your-account", "https://paytm.com/", "https://www.icicibank.com/",
           "https://www.incometax.gov.in/iec/foportal/", "https://www.flipkart.com/account/orders", "https://uidai.gov.in/", "https://www.npci.org.in/",
           # 6 genuine deep links added for experiment E/F (strings only, never fetched)
           "https://www.irctc.co.in/nget/booking/train-list", "https://www.hdfcbank.com/personal/pay/cards/credit-cards", "https://www.amazon.in/dp/B0CHX1W1XY",
           "https://www.flipkart.com/search?q=shoes", "https://www.npci.org.in/what-we-do/upi/product-overview",
           "https://www.incometax.gov.in/iec/foportal/help/individual/return-applicable-1"]
FAKE = ["http://sbi-kyc-verify-now.xyz/login", "http://hdfc-netbanking-update.top/", "http://paytm-kyc.online/verify", "http://amaz0n-refund.in/claim",
        "http://www.sbi-rewards-points.co/redeem", "http://irctc-refund-status.info/", "http://incometax-refund.gov-in.site/"]   # strings only, never fetched

VARIANTS = {   # name -> host_norm, view, keep the brand_* features
    "A": dict(host_norm="none", view="host", brand=True, what="host-only, host as-is (url_head.py main, re-fit on the current file)"),
    "B": dict(host_norm="strip_www", view="host", brand=True, what="host-only, one leading www label stripped"),
    "C": dict(host_norm="strip_www", view="host", brand=False, what="B without the brand_* features"),
    "D": dict(host_norm="strip_www", view="full", brand=True, what="full URL (host + path / query), www stripped from host and URL"),
    "E": dict(host_norm="strip_www", view="full", brand=True, augment=True, what="D + train-only benign www / trailing-slash variants (augment_benign)"),
    "F": dict(host_norm="none", view="host", brand=True, augment=True, what="A + train-only benign www / trailing-slash variants (augment_benign)"),
}
RULE_SET = ["A", "B", "D", "E", "F"]   # the candidates the recommendation rule chooses among (C is the brand ablation, kept for the record)

def log(m):
    print(m, file=sys.stderr, flush=True)

# ---------------------------------------------------------------- url_head.py, read not imported
def read_url_head():
    """Namespace with SEED, HOST, best_threshold, rank_metrics, md, the HGB kwargs (HGB_KW) and `population(df)` from src/url_head.py."""
    tree = ast.parse(Path(__file__).with_name("url_head.py").read_text())
    ns = {"np": np, "pd": pd, "f1_score": f1_score, "roc_auc_score": roc_auc_score, "average_precision_score": average_precision_score}
    pop_stmts = []
    def key(node):
        t = node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1 else None
        if isinstance(t, ast.Name):
            return t.id
        if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and isinstance(t.slice, ast.Constant):
            return f"{t.value.id}[{t.slice.value!r}]"
    for node in tree.body:
        k = key(node)
        if k in ("SEED", "HOST"):
            exec(compile(ast.Module([node], []), "url_head.py", "exec"), ns)
        elif isinstance(node, ast.FunctionDef) and node.name in ("best_threshold", "rank_metrics", "md"):
            exec(compile(ast.Module([node], []), "url_head.py", "exec"), ns)
        elif k in ("df['task']", "base", "sp", "y"):
            pop_stmts.append(node)
    assert [key(n) for n in pop_stmts] == ["df['task']", "base", "sp", "y"], "url_head.py no longer defines task / base / sp / y at top level"
    fit = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "fit")
    call = next(n for n in ast.walk(fit) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "HistGradientBoostingClassifier")
    ns["HGB_KW"] = {k.arg: eval(compile(ast.Expression(k.value), "url_head.py", "eval"), ns) for k in call.keywords if k.arg != "categorical_features"}
    def population(df):
        loc = {"np": np, "pd": pd, "df": df}
        for node in pop_stmts:
            exec(compile(ast.Module([node], []), "url_head.py", "exec"), loc)
        return loc["base"], loc["sp"], loc["y"]
    ns["population"] = population
    return ns

UH = read_url_head()
HOST, SEED, HGB_KW = UH["HOST"], UH["SEED"], UH["HGB_KW"]
best_threshold, rank_metrics, md = UH["best_threshold"], UH["rank_metrics"], UH["md"]

def high_threshold(s, yy):
    """url_head.py's second level: the lowest score at which precision on `s` reaches 0.95 (inf if never)."""
    grid = [t for t in np.unique(np.quantile(s, np.linspace(0.01, 0.999, 300))) if yy[s >= t].mean() >= 0.95]
    return float(min(grid)) if grid else float("inf")

# ---------------------------------------------------------------- features
def url_with_norm(noscheme, host, reg, mode):
    """The URL string with the same leading www label removed that normalise_host removes from the host (so url_len and the other
    path features cannot carry the "www." the host features no longer see)."""
    if normalise_host(host, mode, reg) == host:
        return noscheme
    m = WWW_AT_START.match(noscheme)
    assert m, f"host {host!r} was normalised but the URL string has no leading www label: {noscheme!r}"
    return noscheme[:m.start(2)] + noscheme[m.end(2):]

def featurize(hosts, regs, urls, index):
    """Host and path features of URL rows under both host normalisations (a pure function of host, reg_domain, url_noscheme, so a row the
    normalisation does not change is the same row under both). Returns H0, H1 (host features, no tld_code yet), P0, P1 (path features;
    P1 reads the URL string with the same www label removed) and the Series of rows strip_www changes."""
    h0 = [host_features(h, r) for h, r in zip(hosts, regs)]
    norm = [normalise_host(h, "strip_www", r) for h, r in zip(hosts, regs)]
    ch = [n != h for n, h in zip(norm, hosts)]
    h1 = [host_features(n, r) if c else f for n, r, c, f in zip(norm, regs, ch, h0)]
    u1 = [url_with_norm(u, h, r, "strip_www") if c else u for u, h, r, c in zip(urls, hosts, regs, ch)]
    # the stripped URL string parses to the normalised host ("http://" added by hand: parse_url takes any "://" in a scheme-less
    # string as the scheme, which misreads the 12 rows with a redirect URL in the query; path_features has the same quirk on them)
    bad = sum(parse_url("http://" + u)[0] != n for u, n, c in zip(u1, norm, ch) if c)
    assert bad == 0, f"{bad} stripped URL strings do not parse to the normalised host"
    return (pd.DataFrame(h0, index=index), pd.DataFrame(h1, index=index), pd.DataFrame([path_features(u) for u in urls], index=index),
            pd.DataFrame([path_features(u) for u in u1], index=index), pd.Series(ch, index=index))

# ---------------------------------------------------------------- train-only augmentation of the benign rows
AUG_KINDS = [("www_slash", "https://www.{d}/"), ("bare_slash", "https://{d}/"), ("http_bare", "http://{d}")]

def augment_benign(df_train):
    """Experiment E/F. `df_train`: the Tranco benign TRAIN rows of urls.csv (bare registered domains, written 'https://<d>' by build_urls.py).
    For each row up to three variants are added: https://www.<d>/ , https://<d>/ , http://<d>. A variant is skipped when its string equals the
    original's, and the www one when the registered domain already starts with a www label (the label would be doubled). Variants inherit
    split 'train' and label 'benign'; source 'tranco_aug', is_synthetic True (CLAUDE.md rule 4: they never count as real and are never in
    val / test). Host, registered domain, scheme and has_path are derived from the variant URL with the same code as the real rows
    (url_features.parse_url, build_urls.py's has_path rule). Returns (aug frame in urls.csv's columns + parent bookkeeping, skip counts)."""
    assert (df_train["source"] == "tranco").all() and (df_train["label"] == "benign").all() and (df_train["split"] == "train").all(), \
        "augment_benign takes Tranco benign train rows only"
    assert (df_train["host"] == df_train["reg_domain"]).all(), "a Tranco row has a subdomain: the <domain> of the variants would be ambiguous"
    rows, skipped = [], {}
    def skip(kind, why):
        skipped[(kind, why)] = skipped.get((kind, why), 0) + 1
    for r in df_train.itertuples():
        for kind, tpl in AUG_KINDS:
            if kind == "www_slash" and WWW_LABEL.match(r.reg_domain):
                skip(kind, "registered domain starts with a www label")
                continue
            url = tpl.format(d=r.reg_domain)
            if url == r.url:
                skip(kind, "equal to the original")
                continue
            host, reg = parse_url(url)
            if reg != r.reg_domain:   # not in the brief's list: a parent that is itself a public suffix (sch.uk): www.sch.uk would be a new registered domain
                skip(kind, "registered domain of the variant differs from the parent's (parent is a public suffix)")
                continue
            sp_ = urlsplit(url)
            rows.append({"url": url, "label": "benign", "source": "tranco_aug", "scheme": sp_.scheme, "host": host, "reg_domain": reg,
                         "has_ip": False, "has_path": len(sp_.path) > 1 or bool(sp_.query), "url_noscheme": SCHEME_RX.sub("", url),
                         "split": "train", "is_synthetic": True, "provenance": "augmented", "aug_kind": kind,
                         "parent_url": r.url, "parent_reg_domain": r.reg_domain, "parent_index": r.Index})
    return pd.DataFrame(rows), skipped

def check_augmentation(aug, df, n_parents):
    """The split-crossing asserts of the brief. Raises AssertionError on the first failure; returns the lines for the report."""
    out = []
    def need(cond, text):
        assert cond, f"augmentation check failed: {text}"
        out.append(text)
    need((aug["split"] == "train").all() and (aug["label"] == "benign").all() and (aug["source"] == "tranco_aug").all() and aug["is_synthetic"].all(),
         f"all {len(aug)} variants: split train, label benign, source tranco_aug, is_synthetic True")
    need((aug["reg_domain"] == aug["parent_reg_domain"]).all(), "every variant's registered domain (re-derived from the variant URL) equals its parent's")
    reg_splits = df.groupby("reg_domain")["split"].agg(lambda x: set(x.astype(str)))
    need(all(reg_splits[r] == {"train"} for r in aug["reg_domain"].unique()),
         f"all {aug['reg_domain'].nunique()} registered domains of the variants have only train rows in urls.csv (any source, any label)")
    out_of_train = set(df.loc[df["split"].astype(str) != "train", "reg_domain"])
    need(not (set(aug["reg_domain"]) & out_of_train), "no variant's registered domain appears in any val / test row of urls.csv")
    need(aug.groupby("parent_index").size().le(len(AUG_KINDS)).all() and aug["parent_index"].nunique() <= n_parents, "at most 3 variants per parent row")
    return out

# ---------------------------------------------------------------- data
class Data:
    """urls.csv, the url_head.py population, and host / path features under both host normalisations. With augment=True also the train-only
    augmentation of the benign Tranco rows (self.aug, features in self.Xaug; never part of self.df, so every val / test table is on real rows)."""
    def __init__(self, path, augment=True):
        t0 = time.time()
        self.df = df = pd.read_csv(path, low_memory=False)
        self.base, self.sp, self.y = UH["population"](df)
        H0, H1, P0, P1, self.changed = featurize(df["host"].tolist(), df["reg_domain"].tolist(), df["url_noscheme"].tolist(), df.index)
        self.p_cols = list(P0.columns)
        # top_tld comes from the REAL train rows only: the variants copy existing TLDs, so adding them would only re-weight Tranco's TLDs,
        # and the code table must be the same for every variant and for url_head.py
        self.top_tld = H0.loc[self.base & (self.sp == "train"), "tld"].value_counts().head(40).index.tolist()
        code = {t: i for i, t in enumerate(self.top_tld)}
        for H in (H0, H1):
            H["tld_code"] = H["tld"].map(code).fillna(len(self.top_tld)).astype(int)
        self.X = {"none": pd.concat([H0, P0], axis=1), "strip_www": pd.concat([H1, P1], axis=1)}
        log(f"features for {len(df)} rows ({int(self.changed.sum())} changed by strip_www): {time.time() - t0:.0f}s")
        self.aug, self.aug_skipped, self.aug_checks, self.Xaug = None, None, None, None
        if augment:
            t1 = time.time()
            parents = df[self.base & (self.sp == "train") & (df["source"] == "tranco")]
            aug, self.aug_skipped = augment_benign(parents)
            aug.index = pd.RangeIndex(len(df), len(df) + len(aug))   # ids that cannot collide with a urls.csv row
            self.aug_checks = check_augmentation(aug, df, len(parents))
            self.n_aug_parents = len(parents)
            a0, a1, q0, q1, _ = featurize(aug["host"].tolist(), aug["reg_domain"].tolist(), aug["url_noscheme"].tolist(), aug.index)
            for H in (a0, a1):
                H["tld_code"] = H["tld"].map(code).fillna(len(self.top_tld)).astype(int)
            self.aug, self.Xaug = aug, {"none": pd.concat([a0, q0], axis=1), "strip_www": pd.concat([a1, q1], axis=1)}
            log(f"augmentation: {len(aug)} variants of {len(parents)} Tranco benign train rows: {time.time() - t1:.0f}s")

def variant_cols(v, p_cols):
    cols = [c for c in HOST if v["brand"] or not c.startswith("brand_")]
    return cols + (p_cols if v["view"] == "full" else [])

def train_variant(d, name):
    """Fit one variant on the train split (plus the train-only variants for E / F); thresholds on val only. Returns a dict with the model,
    columns, thresholds, reference and the scores of every row that is not in the test split (the test rows are scored in test_once)."""
    v = VARIANTS[name]
    cols, X = variant_cols(v, d.p_cols), d.X[v["host_norm"]]
    tr, val = d.base & (d.sp == "train"), d.base & (d.sp == "val")
    Xfit, yfit = X.loc[tr, cols], d.y[tr]
    if v.get("augment"):
        Xa = d.Xaug[v["host_norm"]][cols]
        Xfit, yfit = pd.concat([Xfit, Xa]), pd.concat([yfit, pd.Series(0, index=Xa.index)])
    m = HistGradientBoostingClassifier(**HGB_KW, categorical_features=[cols.index("tld_code")]).fit(Xfit, yfit)
    dev = d.sp.isin(["train", "val"])
    s = pd.Series(np.nan, index=d.df.index)
    s[dev] = m.predict_proba(X.loc[dev, cols])[:, 1]
    thr, thr_high = float(best_threshold(s[val], d.y[val])), high_threshold(s[val], d.y[val])
    ref_rows = Xfit[yfit == 0]   # the benign rows this model was fit on (for E / F including the variants)
    reference = {c: float(ref_rows[c].median()) for c in cols}
    reference["tld_code"] = int(ref_rows["tld_code"].mode().iloc[0])
    bundle = {"model": m, "features": cols, "top_tld": d.top_tld, "threshold": thr, "threshold_high": thr_high, "reference": reference,
              "host_norm": v["host_norm"], "view": v["view"], "augmented": bool(v.get("augment"))}
    return dict(name=name, bundle=bundle, cols=cols, X=X, scores=s, thr=thr, thr_high=thr_high,
                n_fit=len(yfit), n_fit_benign=int((yfit == 0).sum()), n_fit_phish=int((yfit == 1).sum()), n_aug=int(len(yfit) - tr.sum()))

# ---------------------------------------------------------------- reproduction of url_head.py
def reproduce(d, tv, ref_dir, label, ref_desc, with_test):
    """Compare variant A (harness) with the files an unmodified url_head.py run wrote into ref_dir (models/url_head.joblib,
    data/final/url_preds.csv). Predictions are compared on every row outside the test split (all rows when with_test, a run that
    only checks the harness and reports no metric). Returns (markdown lines, ok)."""
    ref_dir = Path(ref_dir)
    rb, rp = joblib.load(ref_dir / "models/url_head.joblib"), pd.read_csv(ref_dir / "data/final/url_preds.csv")
    assert len(rp) == len(d.df) and (rp["url"].values == d.df["url"].values).all(), f"{label}: reference preds are not for this urls.csv"
    rows = pd.Series(True, index=d.df.index) if with_test else d.sp.isin(["train", "val"])
    s = tv["scores"].copy()
    if with_test:
        te = d.sp == "test"
        s[te] = tv["bundle"]["model"].predict_proba(tv["X"].loc[te, tv["cols"]])[:, 1]
    val = d.base & (d.sp == "val")
    ref_s = rp["score_host"]
    diff = (s[rows] - ref_s[rows]).abs()
    checks = [("val AUROC (3 dp)", f"{rank_metrics(s[val], d.y[val])[0]:.3f}", f"{rank_metrics(ref_s[val], d.y[val])[0]:.3f}",
               round(rank_metrics(s[val], d.y[val])[0], 3) == round(rank_metrics(ref_s[val], d.y[val])[0], 3)),
              ("threshold (max F1 on val)", f"{tv['thr']:.10f}", f"{rb['threshold']:.10f}", abs(tv["thr"] - rb["threshold"]) < 1e-12),
              ("threshold_high", f"{tv['thr_high']:.10f}", f"{rb['threshold_high']:.10f}", abs(tv["thr_high"] - rb["threshold_high"]) < 1e-12),
              ("top_tld (40 codes, in order)", "equal" if d.top_tld == rb["top_tld"] else "differs", "", d.top_tld == rb["top_tld"]),
              ("reference benign host", "equal" if tv["bundle"]["reference"] == rb["reference"] else "differs", "", tv["bundle"]["reference"] == rb["reference"]),
              (f"scores, {int(rows.sum())} rows ({'all' if with_test else 'train + val'}): max abs diff vs the 5-dp preds", f"{diff.max():.2e}", "<= 5e-6", diff.max() <= 5.0001e-6)]
    lines = [f"**{label}** (urls.csv: {len(d.df)} rows; reference = {ref_desc})\n", "| check | harness A | url_head.py | ok |", "| --- | --- | --- | --- |"]
    lines += [f"| {n} | {a} | {b} | {'yes' if ok else '**NO**'} |" for n, a, b, ok in checks]
    return lines, all(ok for *_, ok in checks)

# ---------------------------------------------------------------- probes
def probe_scores(bundle, urls):
    """Score URL strings with a saved bundle alone (host_norm / view / features come from the bundle). Nothing is fetched."""
    rows = []
    for u in urls:
        f = host_row(u, bundle["top_tld"], bundle["host_norm"])
        if bundle["view"] == "full":
            host, reg = parse_url(u, "none")
            f.update(path_features(url_with_norm(SCHEME_RX.sub("", u), host, reg, bundle["host_norm"])))
        rows.append(f)
    X = pd.DataFrame(rows)[bundle["features"]]
    s = np.round(bundle["model"].predict_proba(X)[:, 1], 3)
    t, th = r3(bundle["threshold"]), r3(bundle["threshold_high"])
    return s, [level_of(r3(v), t, th) for v in s]

# ---------------------------------------------------------------- metrics (val only)
def val_table(d, tvs):
    sp, y, src, task = d.sp, d.y, d.df["source"], d.df["task"]
    val = d.base & (sp == "val")
    eal, tra = src == "ealvaradob", src == "tranco"
    heldout = sp.isin(["train", "val"])   # held-out feeds were never trained on, whatever their split: a supplementary, larger sample
    rows = []
    for name, tv in tvs.items():
        s, thr = tv["scores"], tv["thr"]
        flag = s >= thr
        r = {"variant": name, "features": len(tv["cols"]), "threshold": thr, "threshold_high": tv["thr_high"],
             "val AUROC": rank_metrics(s[val], y[val])[0], "val PR-AUC": rank_metrics(s[val], y[val])[1],
             "ealvaradob-only AUROC": rank_metrics(s[val & eal], y[val & eal])[0],
             "tranco-benign vs ealvaradob-phish AUROC": rank_metrics(s[val & (tra | (eal & (y == 1)))], y[val & (tra | (eal & (y == 1)))])[0],
             "FPR tranco": flag[val & tra].mean(), "FPR ealvaradob benign": flag[val & eal & (y == 0)].mean(),
             "recall ealvaradob phish": flag[val & (y == 1)].mean(), "F1 @thr": f1_score(y[val], flag[val]),
             "recall openphish (val)": flag[(task == "openphish_heldout") & (sp == "val")].mean(),
             "recall urlhaus (val)": flag[(task == "urlhaus_heldout") & (sp == "val")].mean(),
             "recall openphish (train+val)": flag[(task == "openphish_heldout") & heldout].mean(),
             "recall urlhaus (train+val)": flag[(task == "urlhaus_heldout") & heldout].mean()}
        rows.append(r)
    ns = {"openphish (val)": int(((task == "openphish_heldout") & (sp == "val")).sum()), "urlhaus (val)": int(((task == "urlhaus_heldout") & (sp == "val")).sum()),
          "openphish (train+val)": int(((task == "openphish_heldout") & heldout).sum()), "urlhaus (train+val)": int(((task == "urlhaus_heldout") & heldout).sum()),
          "val rows": int(val.sum()), "val tranco": int((val & tra).sum()), "val ealvaradob benign": int((val & eal & (y == 0)).sum()),
          "val ealvaradob phish": int((val & (y == 1)).sum())}
    return pd.DataFrame(rows).set_index("variant"), ns

def subdomain_table(d, tvs):
    """Flag rate of val benign (and recall of val phishing) by the host as the user sees it: no subdomain / any subdomain, and inside
    'any' the www-only hosts (one www label is the whole subdomain) against the rest. Same rows for every variant."""
    val = d.base & (d.sp == "val")
    raw, strip = d.X["none"]["subdomain_depth"], d.X["strip_www"]["subdomain_depth"]
    groups = {"no subdomain": raw == 0, "any subdomain": raw >= 1, "  of which www-only": (raw >= 1) & (strip == 0), "  of which other subdomain": strip >= 1}
    out = {}
    for lab, ymask in (("benign", d.y == 0), ("phishing", d.y == 1)):
        rows = []
        for g, gm in groups.items():
            m = val & ymask & gm
            r = {"group": g, "n": int(m.sum()), "n tranco": int((m & (d.df["source"] == "tranco")).sum()), "n ealvaradob": int((m & (d.df["source"] == "ealvaradob")).sum())}
            r.update({n: (tv["scores"][m] >= tv["thr"]).mean() for n, tv in tvs.items()})
            rows.append(r)
        out[lab] = pd.DataFrame(rows).set_index("group")
    return out

def importance(d, tv):
    val = d.base & (d.sp == "val")
    imp = permutation_importance(tv["bundle"]["model"], tv["X"].loc[val, tv["cols"]], d.y[val], scoring="roc_auc", n_repeats=3, random_state=SEED, n_jobs=1)
    return pd.Series(imp.importances_mean, index=tv["cols"]).sort_values(ascending=False)

def deployed_on_val(d):
    """models/url_head.joblib (host-only, fit on the 62,969-row file) scored on the CURRENT val set; its own threshold and top_tld."""
    b = joblib.load("models/url_head.joblib")
    X = d.X["none"].copy()
    X["tld_code"] = X["tld"].map({t: i for i, t in enumerate(b["top_tld"])}).fillna(len(b["top_tld"])).astype(int)
    val = d.base & (d.sp == "val")
    s = pd.Series(b["model"].predict_proba(X.loc[val, b["features"]])[:, 1], index=X.index[val])
    src, y = d.df["source"][val], d.y[val]
    flag = s >= b["threshold"]
    return {"threshold": b["threshold"], "val AUROC": roc_auc_score(y, s), "FPR tranco": flag[src == "tranco"].mean(),
            "FPR ealvaradob benign": flag[(src == "ealvaradob") & (y == 0)].mean(), "recall ealvaradob phish": flag[y == 1].mean()}

def matched_recall(d, tvs, target):
    """Supplementary, val only: each variant's threshold moved until it flags `target` of the val phishing (A's recall at its own threshold),
    then FPR on ealvaradob benign and on Tranco, and the www-only group (benign flagged / phishing recall). If a variant's FPRs here are no
    lower than A's, its lower FPR at its own val-chosen threshold came from the threshold, not from ranking the hosts better."""
    val, y, src = d.base & (d.sp == "val"), d.y, d.df["source"]
    raw, strip = d.X["none"]["subdomain_depth"], d.X["strip_www"]["subdomain_depth"]
    wo = val & (raw >= 1) & (strip == 0)
    rows = []
    for n, tv in tvs.items():
        s = tv["scores"]
        t = np.quantile(s[val & (y == 1)].values, 1 - target)
        rows.append({"variant": n, "threshold": t, "recall ealvaradob phish": (s[val & (y == 1)] >= t).mean(),
                     "FPR ealvaradob benign": (s[val & (src == "ealvaradob") & (y == 0)] >= t).mean(), "FPR tranco": (s[val & (src == "tranco")] >= t).mean(),
                     "www-only benign flagged": (s[wo & (y == 0)] >= t).mean(), "www-only phishing recall": (s[wo & (y == 1)] >= t).mean()})
    return pd.DataFrame(rows).set_index("variant")

def toggle_slash(u, with_slash):
    """The probe with a final '/' on the path (added if missing) or without it (removed if present). None for a URL with a query string:
    there a '/' would end the query value, not the path."""
    if "?" in u or "#" in u:
        return None
    return u.rstrip("/") + "/" if with_slash else u.rstrip("/")

def slash_table(bundles, names=("D", "E")):
    """Supplementary: every probe scored with and without a trailing '/' by the full-URL variants (Tranco training rows never have one;
    E / F were fit with 'd/' variants). The host-only variants ignore the path: their scores are asserted equal with and without it.
    Probes with a query string are left out (toggle_slash)."""
    probes = [u for u in GENUINE + FAKE if toggle_slash(u, True) is not None]
    wi, wo = [toggle_slash(u, True) for u in probes], [toggle_slash(u, False) for u in probes]
    for n, b in bundles.items():
        if b["view"] == "host":
            assert (probe_scores(b, wi)[0] == probe_scores(b, wo)[0]).all(), f"host-only variant {n} reads the trailing slash"
    rows = {"kind": ["genuine" if u in GENUINE else "fake" for u in probes], "url": [u.rstrip("/") for u in probes]}
    for n in names:
        (a, la), (c, lc) = probe_scores(bundles[n], wi), probe_scores(bundles[n], wo)
        rows[f"{n} with '/'"] = [f"{x:.3f} · L{l}" for x, l in zip(a, la)]
        rows[f"{n} without '/'"] = [f"{x:.3f} · L{l}" for x, l in zip(c, lc)]
    t = pd.DataFrame(rows)
    gen = t["kind"] == "genuine"
    summ = {"kind": "summary", "url": f"genuine probes at L0 (of {int(gen.sum())})"}
    for n in names:
        for lab in ("with", "without"):
            summ[f"{n} {lab} '/'"] = str(int(t.loc[gen, f"{n} {lab} '/'"].str.endswith("L0").sum()))
    return pd.concat([t, pd.DataFrame([summ])], ignore_index=True)

def path_share_table(d):
    """Share of rows with a path (urls.csv has_path: a path longer than '/' or a query) and with any '/' at all in the URL string, for the real
    train and val rows of the phishing-vs-benign population and for the train-only variants. The val rows are the unchanged real set."""
    def one(frame, label):
        g = frame.assign(any_slash=frame["url_noscheme"].str.contains("/", regex=False)).groupby(["source", "label"])
        out = g.agg(rows=("url", "size"), path=("has_path", "mean"), slash=("any_slash", "mean")).reset_index()
        out.insert(0, "set", label)
        return out
    df, tr, val = d.df, d.base & (d.sp == "train"), d.base & (d.sp == "val")
    parts = [one(df[tr], "train (real)")]
    if d.aug is not None:
        parts.append(one(d.aug, "train augmentation (E, F only)"))
    parts.append(one(df[val], "val (real, unchanged)"))
    t = pd.concat(parts, ignore_index=True)
    return t.rename(columns={"path": "share with a path", "slash": "share with any '/'"})

def path_fpr_table(d, tvs, names):
    """Val: flag rate (benign rows = false-positive rate, phishing rows = recall) with and without a path (urls.csv has_path), each variant at
    its own val threshold. Benign rows with a path are all ealvaradob (Tranco never has one), so the 'without a path' group is split by source."""
    val, y, src, hp = d.base & (d.sp == "val"), d.y, d.df["source"], d.df["has_path"]
    groups = [("benign WITH a path (FPR)", val & (y == 0) & hp), ("benign WITHOUT a path (FPR)", val & (y == 0) & ~hp),
              ("  of which ealvaradob", val & (y == 0) & ~hp & (src == "ealvaradob")), ("  of which tranco", val & (y == 0) & ~hp & (src == "tranco")),
              ("phishing WITH a path (recall)", val & (y == 1) & hp), ("phishing WITHOUT a path (recall)", val & (y == 1) & ~hp)]
    rows = []
    for g, m in groups:
        r = {"group": g, "n": int(m.sum())}
        r.update({n: (tvs[n]["scores"][m] >= tvs[n]["thr"]).mean() for n in names})
        rows.append(r)
    return pd.DataFrame(rows).set_index("group")

# ---------------------------------------------------------------- recommendation
def recommend(vt, probes, names):
    """The extended rule of experiment E/F, over `names` (A, B, D, E, F). Gate: val AUROC >= A's - 0.005, val Tranco FPR <= A's, recall of the
    never-trained OpenPhish rows (train+val, as in 950f157) >= A's - 0.02. Among the variants through the gate, those that flag all fake
    probes; then the most genuine probes below the threshold (of all genuine probes); ties -> higher val ealvaradob-only AUROC, then the
    earlier variant (so A, the unchanged model, wins an exact tie). No variant through both -> winner None (keep the deployed model)."""
    A = vt.loc["A"]
    g_auc, g_fpr = "AUROC gate (>= %.3f)" % (A["val AUROC"] - 0.005), "FPR gate (<= %.4f)" % A["FPR tranco"]
    g_op = "OpenPhish gate (>= %.3f)" % (A["recall openphish (train+val)"] - 0.02)
    gen_c, fake_c = "genuine below thr (of %d)" % len(GENUINE), "fakes at/above thr (of %d)" % len(FAKE)
    rows = []
    for n in names:
        rows.append({"variant": n, "val AUROC": vt.loc[n, "val AUROC"], "AUROC - A": f"{vt.loc[n, 'val AUROC'] - A['val AUROC']:+.4f}", g_auc: bool(vt.loc[n, "val AUROC"] >= A["val AUROC"] - 0.005),
                     "FPR tranco": vt.loc[n, "FPR tranco"], g_fpr: bool(vt.loc[n, "FPR tranco"] <= A["FPR tranco"]),
                     "recall openphish (train+val)": vt.loc[n, "recall openphish (train+val)"], g_op: bool(vt.loc[n, "recall openphish (train+val)"] >= A["recall openphish (train+val)"] - 0.02),
                     gen_c: probes[n]["genuine_below"], fake_c: probes[n]["fake_flagged"],
                     "all fakes flagged": probes[n]["fake_flagged"] == len(FAKE), "ealvaradob-only AUROC": vt.loc[n, "ealvaradob-only AUROC"]})
    t = pd.DataFrame(rows).set_index("variant")
    pool = t[t[g_auc] & t[g_fpr] & t[g_op] & t["all fakes flagged"]]
    if pool.empty:
        return t, None
    order = sorted(pool.index, key=lambda n: (-pool.loc[n, gen_c], -pool.loc[n, "ealvaradob-only AUROC"], list(names).index(n)))
    return t, order[0]

_TEST_CALLS = []
def test_once(d, tvs, names):
    """The only function that reads the test split; called once, after the recommendation. Thresholds are the val-chosen ones."""
    assert not _TEST_CALLS, "test split already evaluated"
    _TEST_CALLS.append(names)
    te = d.sp == "test"
    src, y = d.df["source"], d.y
    rows = []
    for n in names:
        tv = tvs[n]
        s = pd.Series(tv["bundle"]["model"].predict_proba(tv["X"].loc[d.base & te, tv["cols"]])[:, 1], index=d.df.index[d.base & te])
        m = d.base & te
        rows.append({"variant": n, "threshold (val)": tv["thr"], "test AUROC": roc_auc_score(y[m], s), "FPR tranco": (s[src[m] == "tranco"] >= tv["thr"]).mean(),
                     "FPR ealvaradob benign": (s[(src[m] == "ealvaradob") & (y[m] == 0)] >= tv["thr"]).mean(),
                     "n test tranco": int((src[m] == "tranco").sum()), "n test ealvaradob benign": int(((src[m] == "ealvaradob") & (y[m] == 0)).sum())})
    return pd.DataFrame(rows).set_index("variant")

# ---------------------------------------------------------------- augmentation summary
def aug_summary(d, tvs):
    """Rows added per variant type (all train), what was skipped, and how many added rows are feature-identical to their parent row in
    F's view (host-only, www kept) and in E's view (full URL, www stripped): an identical row adds weight, not information."""
    aug, rows = d.aug, []
    exact_dup = aug["url"].isin(set(d.df["url"]))
    for kind, tpl in AUG_KINDS + [(None, "all")]:
        a = aug if kind is None else aug[aug["aug_kind"] == kind]
        sk = {k: v for k, v in d.aug_skipped.items() if kind is None or k[0] == kind}
        r = {"variant": tpl.replace("{d}", "<domain>"), "added (all train)": len(a), "skipped": sum(sk.values()),
             "why skipped": "; ".join(f"{v} {w}" for (_, w), v in sk.items()) or "-", "same URL string as an existing urls.csv row": int(exact_dup[a.index].sum())}
        for vn in ("F", "E"):
            v = VARIANTS[vn]
            cols = variant_cols(v, d.p_cols)
            xa, xp = d.Xaug[v["host_norm"]].loc[a.index, cols].to_numpy(), d.X[v["host_norm"]].loc[a["parent_index"], cols].to_numpy()
            r[f"{vn}: same features as the parent row"] = int((xa == xp).all(axis=1).sum())
        rows.append(r)
    fit = pd.DataFrame([{"variant": n, "rows fit": tv["n_fit"], "benign": tv["n_fit_benign"], "phishing": tv["n_fit_phish"], "of which augmentation": tv["n_aug"]} for n, tv in tvs.items()])
    return pd.DataFrame(rows), fit

# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref-current", help="dir holding models/url_head.joblib + data/final/url_preds.csv from an unmodified url_head.py run on the CURRENT urls.csv")
    ap.add_argument("--ref-old", nargs=2, metavar=("URLS_OLD", "DIR_OLD"), help="pre-gambling urls.csv (62,969 rows, scratch) and the dir with the deployed url_head.py outputs")
    ap.add_argument("--check-only", action="store_true", help="run the reproduction checks and stop; writes nothing")
    args = ap.parse_args()
    t0 = time.time()
    d = Data(URLS, augment=not args.check_only)
    log(f"population: {d.df['task'].value_counts().to_dict()}")
    tvs = {"A": train_variant(d, "A")}
    checks, ok = [], True
    if args.ref_current:
        lines, good = reproduce(d, tvs["A"], args.ref_current, "A on the current urls.csv vs. an unmodified url_head.py run on it", "files written by an unmodified `url_head.py` run on this `urls.csv` in a scratch directory (not in the repo)", args.check_only)
        checks, ok = checks + lines + [""], ok and good
    if args.ref_old:
        d_old = Data(args.ref_old[0], augment=False)
        lines, good = reproduce(d_old, train_variant(d_old, "A"), args.ref_old[1], "A on the rebuilt pre-gambling urls.csv vs. the deployed model's own outputs (0.845 / 0.537)", "the repo's `models/url_head.joblib` and `data/final/url_preds.csv`; the 62,969-row file is `urls.csv` with the 127 relabelled / pending rows put back as benign and the 25,849 `ut1_blp_gambling` rows dropped (scratch copy, nothing written to the repo)", args.check_only)
        checks, ok = checks + lines + [""], ok and good
    print("\n".join(checks))
    if not ok:
        sys.exit("STOP: the harness does not reproduce url_head.py (see the table above); nothing was written")
    if args.check_only:
        return
    for n in ("B", "C", "D", "E", "F"):
        tvs[n] = train_variant(d, n)
        log(f"fit {n}: {time.time() - t0:.0f}s")
    names = list(tvs)

    # ---- selection, val only
    vt, ns = val_table(d, tvs)
    sub = subdomain_table(d, tvs)
    imps = {n: importance(d, tv) for n, tv in tvs.items()}
    dep = deployed_on_val(d)
    os.makedirs(CAND_DIR, exist_ok=True)
    for n, tv in tvs.items():
        joblib.dump(tv["bundle"], f"{CAND_DIR}/url_{n}.joblib")
    bundles = {n: joblib.load(f"{CAND_DIR}/url_{n}.joblib") for n in tvs}   # probes are scored from the saved files, not the in-memory models
    deployed = joblib.load("models/url_head.joblib")
    deployed.update(host_norm="none", view="host")
    pr = {n: probe_scores(b, GENUINE + FAKE) for n, b in {**bundles, "deployed": deployed}.items()}
    probes = {n: {"genuine_below": int(sum(l == 0 for l in pr[n][1][:len(GENUINE)])), "fake_flagged": int(sum(l >= 1 for l in pr[n][1][len(GENUINE):]))} for n in pr}
    rule, winner = recommend(vt, probes, RULE_SET)
    log(f"recommended {winner} (None = keep the deployed model): {time.time() - t0:.0f}s")
    mr = matched_recall(d, tvs, vt.loc["A", "recall ealvaradob phish"])
    slash = slash_table(bundles)
    pshare, pfpr = path_share_table(d), path_fpr_table(d, tvs, RULE_SET)
    aug_t, fit_t = aug_summary(d, tvs)

    # ---- the one test evaluation (after the recommendation)
    test = test_once(d, tvs, ["A"] if winner in (None, "A") else ["A", winner])

    # ---- report
    probe_rows = []
    for i, u in enumerate(GENUINE + FAKE):
        r = {"kind": "genuine" if i < len(GENUINE) else "fake", "url": u}
        for n in names + ["deployed"]:
            r[n] = f"{pr[n][0][i]:.3f} · L{pr[n][1][i]}"
        probe_rows.append(r)
    pt = pd.DataFrame(probe_rows)
    summ = [{"kind": "summary", "url": f"genuine below threshold (of {len(GENUINE)}) / fakes at or above (of {len(FAKE)})",
             **{n: f"{probes[n]['genuine_below']} / {probes[n]['fake_flagged']}" for n in names + ["deployed"]}}]
    pt = pd.concat([pt, pd.DataFrame(summ)], ignore_index=True)
    thr_line = ", ".join(f"{n} {r3(tv['thr']):.3f} / {r3(tv['thr_high']):.3f}" for n, tv in tvs.items()) + f", deployed {r3(deployed['threshold']):.3f} / {r3(deployed['threshold_high']):.3f}"
    imp_t = pd.DataFrame({n: [f"{f} ({v:.3f})" for f, v in imps[n].head(8).items()] for n in names}, index=range(1, 9))
    imp_t.index.name = "rank"
    brand_dropped = [c for c in HOST if c.startswith("brand_")]
    rule_cols = rule.reset_index()
    for c in rule_cols.columns:
        if rule_cols[c].dtype == bool:
            rule_cols[c] = rule_cols[c].map({True: "yes", False: "no"})
    A = vt.loc["A"]
    var_t = pd.DataFrame([{"variant": n, "host_norm": v["host_norm"], "view": v["view"], "features": len(tvs[n]["cols"]), "augmented": "yes" if v.get("augment") else "no",
                           "rows fit": tvs[n]["n_fit"], "what": v["what"]} for n, v in VARIANTS.items()])
    rep = ["# URL head experiments\n",
           "Generated by `src/url_experiments.py`. Candidates only: `models/url_head.joblib`, `src/url_head.py` and its outputs, `src/shield/**` (the app) are untouched. "
           "Strings only, nothing is fetched or resolved (CLAUDE.md rule 8). Every model is fit on the **train** split of the phishing-vs-benign population with "
           "`url_head.py`'s HGB settings (read out of its source, not copied) and its max-F1 threshold rule on **val**; E and F also see the train-only benign variants "
           "(`augment_benign`, below). All selection numbers are val, on the unchanged real rows; the test split is read once, in the last section.\n",
           "## Basis: read this first\n",
           f"**Variant A is the `url_head.py` main model re-fit on the current `urls.csv` ({len(d.df)} rows), not the deployed `models/url_head.joblib`.** "
           "`gambling_spam` and `pending_review` rows are excluded from training and evaluation here (127 benign rows fewer than the 62,969-row file the deployed model "
           "was fit on, measured on 2026-10-17 by rebuilding that file: train 94, val 14, test 19), so A's numbers (val AUROC "
           f"{A['val AUROC']:.3f}, threshold {A['threshold']:.3f}) differ from the deployed ones. What the app runs today, on the same current val set: "
           f"**deployed model: val AUROC {dep['val AUROC']:.3f}, FPR Tranco {dep['FPR tranco']:.3f}, FPR ealvaradob benign {dep['FPR ealvaradob benign']:.3f}, "
           f"recall ealvaradob phish {dep['recall ealvaradob phish']:.3f} at its own threshold {dep['threshold']:.3f}.**\n",
           "### Harness check (A reproduces `url_head.py`)\n"] + (checks if checks else ["Not run in this invocation (pass `--ref-current` / `--ref-old`).\n"]) + [
           "## Variants\n", md(var_t, index=False),
           f"\nVariant C drops these brand features: {', '.join('`%s`' % c for c in brand_dropped)} (every `brand_*` feature in url_head.py's host list). "
           f"Population on val: {ns['val rows']} rows = {ns['val tranco']} Tranco benign + {ns['val ealvaradob benign']} ealvaradob benign + {ns['val ealvaradob phish']} ealvaradob phishing. "
           "`strip_www` removes ONE leading `www` / `www1`..`www9` label (kept when it is part of the registered domain: 15 `urls.csv` hosts); it changes the host of "
           f"{int(d.changed.sum())} of {len(d.df)} rows, and the full-URL variants (D, E) strip the same label from the URL string their path features read (so `url_len` cannot carry the `www.`).\n",
           "## Augmentation for E and F (train only)\n",
           "Why: the Tranco benign train rows are bare registered domains with no `www.`, no `/` and no path in 100% of rows, so a model can learn how benign URLs are written in this "
           "corpus instead of what makes a host risky (shares in the table further down). `augment_benign` adds, for each Tranco benign **train** row, up to three variants: "
           "`https://www.<domain>/`, `https://<domain>/`, `http://<domain>`. Variants inherit split train and label benign, source `tranco_aug`, `is_synthetic` True (CLAUDE.md rule 4: "
           "never counted as real, never in val / test); they are held in a separate frame, so every val / test table is on the unchanged real rows. `top_tld` is taken from the real "
           f"train rows only (the variants copy existing TLDs). Parents: {d.n_aug_parents} Tranco benign train rows.\n",
           md(aug_t, index=False),
           "\n'Same features as the parent row' counts added rows whose feature vector is identical to the original's in that variant's view: such a row adds weight, not information "
           "(the scheme is not a feature, so `http://<domain>` is always one; in E the `www` is stripped, so the `www` and the bare `/` variants coincide; in F the path is not read, "
           "so only the `www` variant differs). Rows fit (HGB `class_weight=\"balanced\"` is recomputed on the larger benign class, thresholds are re-chosen on val):\n",
           md(fit_t, index=False),
           "\nSplit-crossing asserts (all passed, the run stops otherwise):\n\n" + "\n".join(f"- {t}" for t in d.aug_checks) + "\n",
           "## Selection metrics (val only)\n",
           "Thresholds: max F1 on val (`threshold`) and the lowest val score with precision >= 0.95 (`threshold_high`), as `url_head.py`. Held-out feeds are never trained on; "
           f"their val samples are tiny (openphish n={ns['openphish (val)']}, urlhaus n={ns['urlhaus (val)']}), so the `train+val` columns (n={ns['openphish (train+val)']} / {ns['urlhaus (train+val)']}, "
           "test-split rows excluded) are supplementary; the OpenPhish one is a gate of the recommendation rule.\n",
           md(vt.drop(columns=["recall openphish (train+val)", "recall urlhaus (train+val)"])),
           "\nRecall of the never-trained feeds, train+val rows: " + ", ".join(f"{n}: openphish {vt.loc[n, 'recall openphish (train+val)']:.3f}, urlhaus {vt.loc[n, 'recall urlhaus (train+val)']:.3f}" for n in names) + ".\n",
           "## Subdomain / www bias (val)\n",
           "Groups by the host as the user sees it (same rows for every variant). Cells = share flagged at each variant's own threshold. `www-only`: one `www` label is the whole subdomain. "
           "Tranco rows are all bare registered domains, so the subdomain groups are almost all ealvaradob rows: a gap here mixes `www` with source shape.\n\n"
           "**Benign (share flagged = false-positive rate)**\n\n" + md(sub["benign"]) + "\n\n**Phishing (share flagged = recall)**\n\n" + md(sub["phishing"]) + "\n",
           "## Path and trailing-slash shortcut (val, supplementary)\n",
           "Share of rows with a path (`has_path`: a path longer than `/`, or a query) and with any `/` in the URL string. The Tranco rows are the only benign rows without a `/`, and the "
           "augmentation gives them one (but never a path longer than `/`):\n\n" + md(pshare, index=False),
           "\nFlag rate on the real val rows with and without a path, at each variant's own threshold (benign = false-positive rate, phishing = recall). "
           "Benign rows with a path are all ealvaradob; a model that reads \"has a path\" as phishing shows a high FPR in the first row:\n\n" + md(pfpr),
           f"\n## Operating-point check (val, supplementary)\n\nEvery variant's threshold moved until it flags A's val recall ({vt.loc['A', 'recall ealvaradob phish']:.3f}). "
           "If a variant's FPR here is not lower than A's, its lower FPR at its own val-chosen threshold (main table) came from the threshold, not from ranking hosts better. "
           "Not part of the rule.\n\n" + md(mr) + "\n",
           "## What carries each model (permutation importance on val, AUROC drop)\n", md(imp_t),
           f"\n## Probes\n\nCell = score · level at that variant's own thresholds (L0 no warning, L1 Suspicious, L2 Likely scam; `r3` comparison as the app). Probes are not used to choose thresholds. "
           f"Thresholds (suspicious / likely): {thr_line}. The `deployed` column is `models/url_head.joblib`, shown for reference, not a candidate. "
           f"{len(GENUINE)} genuine probes (12 sites plus 6 deep links added for this experiment) and {len(FAKE)} fakes, strings only. "
           "The full-URL variants (D, E) read the probe URLs as given, including a trailing `/`.\n",
           md(pt, index=False),
           "\n### Trailing slash (supplementary)\n\nEach probe scored with and without a final `/` (the probe with a query string is left out: there a `/` would not end the path). "
           "Tranco training rows are bare domains with no `/` at all (`path_len` 0, `n_slashes` 0); E was also fit on `<domain>/` variants. The host-only variants (A, B, C, F) ignore the path "
           "(asserted: identical scores with and without it), so only D and E are shown.\n\n" + md(slash, index=False),
           "\n## Recommendation\n",
           "Rule (extended): among A, B, D, E, F (C is the brand ablation and is not a candidate), keep the variants whose val AUROC >= A's - 0.005, whose val Tranco FPR <= A's and whose recall "
           "of the never-trained OpenPhish rows (train+val) >= A's - 0.02; of those, the ones that flag all fake probes; pick the one with the most genuine probes below its threshold "
           f"(of {len(GENUINE)}); ties -> higher val ealvaradob-only AUROC, then the earlier variant. If none passes, keep the deployed model.\n", md(rule_cols, index=False)]
    if winner is None:
        rep.append("\n**Recommended: keep the deployed model.** No variant, A included, passes the gates and flags all fake probes (see the table).")
    elif winner == "A":
        others = []
        for n in RULE_SET[1:]:
            fails = [c for c in rule.columns if c.startswith(("AUROC gate", "FPR gate", "OpenPhish gate")) and not rule.loc[n, c]]
            if not rule.loc[n, "all fakes flagged"]:
                fails.append("all fakes flagged")
            others.append(f"{n}: " + (", ".join(f"fails the {c.split(' (')[0]}" if c.endswith(")") else f"fails: {c}" for c in fails) if fails else
                          f"passes every gate with {rule.loc[n, 'genuine below thr (of %d)' % len(GENUINE)]} genuine probes below the threshold against A's {rule.loc['A', 'genuine below thr (of %d)' % len(GENUINE)]}"))
        rep.append(f"\n**Recommended: variant A** (the unchanged host-only design, re-fit on the current file: keep the deployed model). No candidate beats it under the rule. Why not the others: " + "; ".join(others) + ".")
    else:
        rep.append(f"\n**Recommended: variant {winner}** ({VARIANTS[winner]['what']}).")
        W = vt.loc[winner]
        rep.append(f"\nAgainst A on val: AUROC {A['val AUROC']:.4f} -> {W['val AUROC']:.4f}, ealvaradob-only AUROC {A['ealvaradob-only AUROC']:.4f} -> {W['ealvaradob-only AUROC']:.4f}, "
                   f"recall of ealvaradob phishing {A['recall ealvaradob phish']:.3f} -> {W['recall ealvaradob phish']:.3f}; recall of the never-trained OpenPhish feed (train+val rows, "
                   f"n={ns['openphish (train+val)']}) {A['recall openphish (train+val)']:.3f} -> {W['recall openphish (train+val)']:.3f}. At A's recall (operating-point table): FPR ealvaradob benign "
                   f"{mr.loc['A', 'FPR ealvaradob benign']:.3f} -> {mr.loc[winner, 'FPR ealvaradob benign']:.3f}, FPR Tranco {mr.loc['A', 'FPR tranco']:.3f} -> {mr.loc[winner, 'FPR tranco']:.3f}, "
                   f"www-only benign flagged {mr.loc['A', 'www-only benign flagged']:.3f} -> {mr.loc[winner, 'www-only benign flagged']:.3f} with www-only phishing recall "
                   f"{mr.loc['A', 'www-only phishing recall']:.3f} -> {mr.loc[winner, 'www-only phishing recall']:.3f}.")
        if VARIANTS[winner]["view"] == "full":
            rep.append(f"\nPath-shortcut check for {winner} (val): tranco-benign vs ealvaradob-phish AUROC {vt.loc[winner, 'tranco-benign vs ealvaradob-phish AUROC']:.3f} against ealvaradob-only "
                       f"{vt.loc[winner, 'ealvaradob-only AUROC']:.3f}; FPR on benign rows with a path {pfpr.loc['benign WITH a path (FPR)', winner]:.3f} against "
                       f"{pfpr.loc['benign WITHOUT a path (FPR)', winner]:.3f} without.")
    rep += ["\n## Test split: reported once, not used for selection\n",
            "Evaluated after the recommendation above was computed, for the recommended variant and A only (A alone when the recommendation is A or to keep the deployed model), "
            "at the val-chosen thresholds. Disclosure: the previous run of this script (commit 950f157) already printed A's and B's test numbers; nothing here was chosen with them, "
            "and the rule above uses val only.\n", md(test),
            "\n## Limits\n",
            "- One seed (0), no tuning, one train/val/test split: differences of about 0.005 AUROC or one probe are within noise that this report does not measure.\n"
            f"- The probes are {len(GENUINE) + len(FAKE)} hand-picked strings ({len(GENUINE)} genuine, {len(FAKE)} fake); 'genuine' are all well-known Indian sites on their own domains, so they say little about unknown sites.\n"
            "- The augmentation only adds `www.` and a bare `/`. Tranco benign rows still have no path longer than `/`, no query and no subdomain other than `www`, so path-depth features can still "
            "learn the source; the deep-link probes and the with / without-a-path table are the check, not a fix.\n"
            "- Variants that are feature-identical to their parent (table above) re-weight the bare-domain rows instead of adding information; the HGB class weights and the val-chosen threshold "
            "move with them. This report does not separate the weight effect from the `www` / `/` information.\n"
            "- `subdomain` groups mix source and shape (Tranco is all bare domains).\n"
            "- A is a re-fit on the current file; the deployed model is a different (older) fit, see Basis.\n"
            "- 12 `urls.csv` rows carry a redirect URL inside the query; `path_features` takes the `://` there for the scheme and misreads them, exactly as `url_head.py`'s full-URL view does. "
            "It affects only the path features of D and E for those rows.\n"
            f"- Runtime {time.time() - t0:.0f}s.\n"]
    os.makedirs("reports", exist_ok=True)
    open(OUT, "w").write("\n".join(rep) + "\n")
    print(md(aug_t, index=False)); print(md(fit_t, index=False))
    print(md(vt)); print(md(pt, index=False)); print(md(rule_cols, index=False)); print(f"recommended: {winner}"); print(md(test))
    log(f"wrote {OUT}, {CAND_DIR}/url_[ABCDEF].joblib ({time.time() - t0:.0f}s)")

if __name__ == "__main__":
    main()
