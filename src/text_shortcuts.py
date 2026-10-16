"""Does the text baseline lean on amount and date formatting?  (VAL only: the test split is never read or scored.)

    python src/text_shortcuts.py          -> reports/text_shortcuts.md

Two TF-IDF + logistic regression models are trained on the train split with baseline.py's own settings: (i) the baseline input,
textprep.model_text(text); (ii) the same with amounts -> " <AMT> " and dates -> " <DATE> " applied after model_text. They are
compared on val. Nothing is saved except the report; textprep.py, baseline.py and models/ are untouched.

baseline.py is a flat script (no functions), and importing it would run it, test-split scoring included. So the estimator
constructors and the threshold rule are read out of its source with `ast` and only those statements are executed: the settings
cannot drift from baseline.py, and no test row is ever scored.

The "## Interpretation" section of the report is written by hand from the numbers; a rerun regenerates everything above it and keeps
that section (with a Stale warning if the numbers above it changed).
"""
import ast, hashlib, importlib.util, re, sys, time
from pathlib import Path
import joblib, numpy as np, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, recall_score, roc_auc_score
from textprep import model_text
from shield.messages.text_head import TfidfLrScorer

ROOT = Path(__file__).resolve().parent.parent
MESSAGES, SPLIT_MAP = ROOT / "data/final/messages.csv", ROOT / "data/final/split_map.csv"
BASELINE, SAVED, REPORT = ROOT / "src/baseline.py", ROOT / "models/text_baseline.joblib", ROOT / "reports/text_shortcuts.md"
USE = ["text_hash", "text", "label", "source", "language", "is_synthetic", "cluster_id", "split"]
LEVELS = ["No warning signs", "Suspicious", "Likely scam"]

# ------------------------------------------------------------------ the two patterns
# AMT: Rs / Rs. / INR / the rupee sign, optional spaces, then a number with comma groups and decimals ("Rs. 2,500.00", "INR9.50", "Rs500").
#      (?<![A-Za-z]) keeps "hrs 5", "Mrs 5" out. Not covered: "rupees 500", "$500", "5,000/-", "500 rs".
# DATE: (a) dd-mm-yy(yy), dd/mm/yy(yy), dd.mm.yy(yy) with the same separator twice; (b) "dd Mon" and "Mon dd" with a month name (full or
#      3-4 letter), optional separator (space, -, /), an optional "st/nd/rd/th" after the day and an optional trailing year, so "02-Mar-26",
#      "5 March", "March 5, 2026" match. "May" needs a capital M (lower-case "may" is the verb). Not covered: yyyy-mm-dd, mm/yy, "March 2026".
AMT_RE = re.compile(r"(?<![A-Za-z])(?:Rs\.?|INR|₹)\s*\d+(?:,\d+)*(?:\.\d+)?", re.I)
_MON = (r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|(?-i:May|MAY)|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)")
_DAY = r"(?:0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?"
_YEAR = r"(?:\d{4}|\d{2})(?!\d)"
DATE_RE = re.compile("|".join([
    r"(?<!\d)(?:0?[1-9]|[12]\d|3[01])(?P<sep>[-/.])(?:0?[1-9]|1[0-2])(?P=sep)" + _YEAR,                          # dd-mm-yy(yy)
    rf"(?<!\d){_DAY}[ \-/]?{_MON}\b(?:[ \-/,]*{_YEAR})?",                                                         # dd Mon [yy(yy)]
    rf"\b{_MON}\.?[ \-/]?{_DAY}(?!\d)(?:,?[ \-/]*{_YEAR})?",                                                       # Mon dd [, yy(yy)]
]), re.I)

def mask_amt_date(t):
    """Applied AFTER model_text, to what the model reads."""
    return DATE_RE.sub(" <DATE> ", AMT_RE.sub(" <AMT> ", t))

# ------------------------------------------------------------------ baseline.py's settings, read from its source
WANTED = ("vec", "clf", "sv", "grid", "t_likely", "t_susp")
def _baseline_stmts():
    found = {}
    for node in ast.walk(ast.parse(BASELINE.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in WANTED:
            found.setdefault(node.targets[0].id, []).append(node)
    assert all(len(found.get(n, [])) == 1 for n in WANTED), f"expected exactly one assignment of each of {WANTED} in baseline.py"
    return {n: v[0] for n, v in found.items()}
STMTS = _baseline_stmts() if BASELINE.exists() else {}

def _run(name, ns):
    exec(compile(ast.Module([STMTS[name]], type_ignores=[]), str(BASELINE), "exec"), ns)

def new_estimators():
    ns = {"TfidfVectorizer": TfidfVectorizer, "LogisticRegression": LogisticRegression}
    _run("vec", ns); _run("clf", ns)
    return ns["vec"], ns["clf"]

def val_thresholds(vec, clf, va_text, va_label):
    """baseline.py's --save rule, on val only: likely = max-F1 score cut-off, suspicious = highest cut-off keeping val scam recall >= 0.95,
    stored as min(suspicious, likely)."""
    ns = {"np": np, "f1_score": f1_score, "recall_score": recall_score, "vec": vec, "clf": clf,
          "va": pd.DataFrame({"text": list(va_text), "label": list(va_label)})}
    for n in ("sv", "grid", "t_likely", "t_susp"):
        _run(n, ns)
    return min(ns["t_susp"], ns["t_likely"]), ns["t_likely"]

# ------------------------------------------------------------------ data
def load_train_val():
    parts = []
    for chunk in pd.read_csv(MESSAGES, usecols=USE, chunksize=4000):
        parts.append(chunk[chunk["split"] != "test"])   # the test split is dropped here, chunk by chunk, before anything else touches the rows
    df = pd.concat(parts, ignore_index=True)
    assert set(df["split"]) == {"train", "val"}, set(df["split"])
    df["x"] = df["text"].map(model_text)                # exactly what baseline.py feeds the vectorizer
    df["xm"] = df["x"].map(mask_amt_date)               # variant (ii)
    df["amt"] = df["x"].map(lambda t: bool(AMT_RE.search(t)))
    df["date"] = df["x"].map(lambda t: bool(DATE_RE.search(t)))
    df["cluster"] = df["cluster_id"].fillna(df["text_hash"])
    return df

def fit_variant(tr_x, tr_y, va_x, va_y):
    vec, clf = new_estimators()
    clf.fit(vec.fit_transform(tr_x), tr_y)
    Xva = vec.transform(va_x)
    ts, tl = val_thresholds(vec, clf, va_x, va_y)
    return {"vec": vec, "clf": clf, "score": clf.predict_proba(Xva)[:, 1], "pred05": clf.predict(Xva), "t_susp": ts, "t_like": tl}

def level_of(s, ts, tl):
    return np.where(s >= tl, 2, np.where(s >= ts, 1, 0))

# ------------------------------------------------------------------ small helpers
def md(df):
    cols = [str(c) for c in df.columns]
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for _, r in df.iterrows():
        lines.append("| " + " | ".join(str(v).replace("|", "\\|") for v in r) + " |")
    return "\n".join(lines)

def auc(y, s):
    y = np.asarray(y)
    return roc_auc_score(y, s) if 0 < y.sum() < len(y) else float("nan")

def f3(v):
    return "n/a" if v != v else f"{v:.3f}"

def pct(a, b):
    return "-" if b == 0 else f"{100 * a / b:.1f}"

def paired_boot(y, s1, s2, clusters, B, seed=0):
    """95% interval of AUROC(s2) - AUROC(s1), resampling whole near-duplicate clusters (rows of one cluster are not independent)."""
    y, s1, s2 = np.asarray(y), np.asarray(s1), np.asarray(s2)
    groups = list(pd.Series(np.arange(len(y))).groupby(np.asarray(clusters)).indices.values())
    rng, d = np.random.default_rng(seed), []
    for _ in range(B):
        idx = np.concatenate([groups[i] for i in rng.integers(0, len(groups), len(groups))])
        if 0 < y[idx].sum() < len(idx):
            d.append(roc_auc_score(y[idx], s2[idx]) - roc_auc_score(y[idx], s1[idx]))
    return (np.percentile(d, 2.5), np.percentile(d, 97.5)) if len(d) > B // 2 else (float("nan"), float("nan"))

def literal(path, name):
    """A module-level literal (list / dict / string) read from a test file without importing it."""
    for node in ast.parse(Path(path).read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise KeyError(f"{name} not found in {path}")

def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

# ------------------------------------------------------------------ main
def main():
    t0 = time.time()
    df = load_train_val()
    tr, va = df[df["split"] == "train"], df[df["split"] == "val"].reset_index(drop=True)
    print(f"rows used: train {len(tr)}, val {len(va)}  (splits present: {sorted(set(df['split']))}; no test row was loaded into the table)")
    print(f"rows whose model input changes under the mask: train {int((tr['x'] != tr['xm']).sum())}, val {int((va['x'] != va['xm']).sum())}")

    m1 = fit_variant(tr["x"], tr["label"], va["x"], va["label"]); print(f"model (i) fitted  {time.time() - t0:.0f}s")
    m2 = fit_variant(tr["xm"], tr["label"], va["xm"], va["label"]); print(f"model (ii) fitted {time.time() - t0:.0f}s")
    y = va["label"].to_numpy()
    for m in (m1, m2):
        m["level"] = level_of(m["score"], m["t_susp"], m["t_like"])

    # ---- reproduction: model (i) against the baseline.py --save artifact, on val
    ref = joblib.load(SAVED)
    ref_s = ref["model"].predict_proba(ref["vectorizer"].transform(va["x"]))[:, 1]
    ref_row = {"AUROC": auc(y, ref_s), "F1@0.5": f1_score(y, ref["model"].predict(ref["vectorizer"].transform(va["x"]))),
               "F1@likely": f1_score(y, ref_s >= ref["threshold_likely"]), "susp": ref["threshold_suspicious"], "likely": ref["threshold_likely"]}
    m1_row = {"AUROC": auc(y, m1["score"]), "F1@0.5": f1_score(y, m1["pred05"]), "F1@likely": f1_score(y, m1["score"] >= m1["t_like"]),
              "susp": m1["t_susp"], "likely": m1["t_like"]}
    diff = {k: abs(m1_row[k] - ref_row[k]) for k in ref_row}
    print("reproduction (val):", {k: round(v, 6) for k, v in ref_row.items()}, "<- models/text_baseline.joblib")
    print("                   ", {k: round(v, 6) for k, v in m1_row.items()}, "<- model (i) retrained here")
    print("   abs diff        ", {k: float(f"{v:.2e}") for k, v in diff.items()})
    if max(diff.values()) > 1e-4:
        raise SystemExit("STOP: model (i) does not reproduce baseline.py's val numbers; report not written")

    out = ["# Text baseline: does it lean on amount and date formatting? (VAL only)", "",
           "Generated by `src/text_shortcuts.py`. **Only the train and val splits were read**; the test split is dropped while `messages.csv` is "
           "loaded and no test score exists in this report. Nothing was saved except this file (no model, no change to `textprep.py` / `baseline.py` / "
           "the splits). BUGS.md entry: *The text head leans on amount and date formatting*.", "",
           f"Rows used: train {len(tr):,}, val {len(va):,}. Model input = `textprep.model_text(text)` (CLAUDE.md rule 11). "
           f"`split_map.csv` SHA-256 `{sha256(SPLIT_MAP)}`.", "",
           "## 1. The two patterns", "",
           "Masking is applied **after** `model_text`, AMT first, then DATE: `AMT -> \" <AMT> \"`, `DATE -> \" <DATE> \"`. Regexes (case-insensitive):", "",
           "```", "AMT  = " + AMT_RE.pattern, "DATE = " + DATE_RE.pattern, "```", "",
           "- AMT: `Rs`, `Rs.`, `INR` or the rupee sign, optional spaces, then a number with comma groups and decimals (`Rs. 2,500.00`, `INR9.50`, `Rs500`). "
           "`hrs 5` / `Mrs 5` are excluded. **Not covered:** `rupees 500`, `$500`, `5,000/-`, `500 rs`.",
           "- DATE: `dd-mm-yy(yy)`, `dd/mm/yy(yy)`, `dd.mm.yy(yy)` (same separator twice, day 1-31, month 1-12), plus `dd Mon` and `Mon dd` with a month name, "
           "optional separator, optional `st/nd/rd/th`, optional year (`02-Mar-26`, `5 March`, `March 5, 2026`). Capital-M `May` only. "
           "**Not covered:** `yyyy-mm-dd`, `mm/yy`, `March 2026`, times.",
           "- Both are regexes on the text the model reads (after links became `<URL>` and the cut to 2,000 characters), so a row counts only if the pattern is inside what the model sees.",
           f"- Rows whose model input changes under the mask: train {int((tr['x'] != tr['xm']).sum()):,} of {len(tr):,}, val {int((va['x'] != va['xm']).sum()):,} of {len(va):,}.", ""]

    # ---- 2. data audit
    out += ["## 2. Data audit (counts only, no message text)", "",
            "Scam rate (%) of the rows that contain a pattern vs the rows that do not, within each source. The `all sources` row is confounded by the source mix "
            "(which sources have amounts at all); the per-source rows are the fair comparison.", ""]
    for name, d in (("train", tr), ("val", va)):
        rows = []
        for src, g in list(d.groupby("source")) + [("**all sources**", d)]:
            row = {"source": src, "n": len(g), "scam %": pct(g["label"].sum(), len(g))}
            for p, col in (("AMT", "amt"), ("DATE", "date")):
                a, b = g[g[col]], g[~g[col]]
                row.update({f"{p} rows": f"{len(a)} ({pct(len(a), len(g))}%)", f"{p}: scam % with": pct(a["label"].sum(), len(a)), f"{p}: scam % without": pct(b["label"].sum(), len(b))})
            rows.append(row)
        out += [f"### {name}", "", md(pd.DataFrame(rows)), ""]

    # ---- 3. ablation
    B = 1000
    lo, hi = paired_boot(y, m1["score"], m2["score"], va["cluster"], B)
    def metrics(m):
        return {"AUROC": f3(auc(y, m["score"])), "F1 @0.5": f3(f1_score(y, m["pred05"])),
                "likely cut-off": f"{m['t_like']:.3f}", "F1 @likely": f3(f1_score(y, m["score"] >= m["t_like"])),
                "suspicious cut-off": f"{m['t_susp']:.3f}", "F1 flagged (>= suspicious)": f3(f1_score(y, m["score"] >= m["t_susp"])),
                "scam recall flagged": f3(recall_score(y, m["score"] >= m["t_susp"]))}
    out += ["## 3. Ablation on val", "",
            "Both models use baseline.py's estimators, read from its source by `ast` (so they cannot drift) and executed here:", "", "```python",
            *[ast.unparse(STMTS[n]) for n in ("vec", "clf")], "```", "",
            "Cut-offs are chosen on val **by baseline.py's rule, separately for each model** (its `--save` block: `likely` = max-F1 cut-off, `suspicious` = highest cut-off "
            "keeping val scam recall >= 0.95), so F1 at those cut-offs is optimistic by construction, equally for both. AUROC needs no cut-off.", "",
            f"### Overall (val n={len(va):,}, scam {int(y.sum()):,})", "",
            md(pd.DataFrame([{"model": "(i) baseline input", **metrics(m1)}, {"model": "(ii) AMT/DATE masked", **metrics(m2)}])), "",
            f"Delta AUROC (ii) - (i) = **{auc(y, m2['score']) - auc(y, m1['score']):+.4f}**, 95% interval [{lo:+.4f}, {hi:+.4f}] "
            f"(paired bootstrap over near-duplicate clusters, B={B}, seed 0).", "",
            "### Reproduction check: model (i) vs the baseline.py artifact on val", "",
            md(pd.DataFrame([{"model": "`models/text_baseline.joblib` (`baseline.py --save`)", "AUROC": f"{ref_row['AUROC']:.6f}", "F1 @0.5": f"{ref_row['F1@0.5']:.6f}",
                              "F1 @likely": f"{ref_row['F1@likely']:.6f}", "suspicious cut-off": f"{ref_row['susp']:.6f}", "likely cut-off": f"{ref_row['likely']:.6f}"},
                             {"model": "(i) retrained in this script", "AUROC": f"{m1_row['AUROC']:.6f}", "F1 @0.5": f"{m1_row['F1@0.5']:.6f}",
                              "F1 @likely": f"{m1_row['F1@likely']:.6f}", "suspicious cut-off": f"{m1_row['susp']:.6f}", "likely cut-off": f"{m1_row['likely']:.6f}"},
                             {"model": "abs difference", **{k2: f"{diff[k1]:.1e}" for k1, k2 in (("AUROC", "AUROC"), ("F1@0.5", "F1 @0.5"), ("F1@likely", "F1 @likely"), ("susp", "suspicious cut-off"), ("likely", "likely cut-off"))}}])), "",
            "(baseline.py itself prints test metrics, so it was not run; its saved artifact is the same code on the same train split, "
            "trained 2026-10-09 on the current `textprep`.)", ""]

    def per_group(col, B2):
        rows = []
        for k, g in va.groupby(col):
            i = g.index.to_numpy()
            a1, a2 = auc(y[i], m1["score"][i]), auc(y[i], m2["score"][i])
            ci = "-"
            if a1 == a1 and len(i) >= 30:
                l2, h2 = paired_boot(y[i], m1["score"][i], m2["score"][i], g["cluster"], B2)
                ci = f"[{l2:+.3f}, {h2:+.3f}]"
            rows.append({col: k, "n": len(i), "scam": int(y[i].sum()), "AMT rows": int(g["amt"].sum()), "DATE rows": int(g["date"].sum()),
                         "AUROC (i)": f3(a1), "AUROC (ii)": f3(a2), "delta": "n/a" if a1 != a1 else f"{a2 - a1:+.3f}", "delta 95% interval": ci})
        return pd.DataFrame(rows).sort_values("n", ascending=False)
    out += ["### Per source (val)", "", md(per_group("source", 500)), "",
            "`n/a` = one class only in val. Intervals: paired cluster bootstrap, B=500, only for groups of >= 30 rows.", "",
            "### Per language (val)", "", md(per_group("language", 500)), "",
            "Languages with no val rows do not appear (CLAUDE.md: Hindi and Kannada have 0 val rows until `splits-v2`).", ""]

    # ---- 4. flips
    f1_, f2_ = m1["score"] >= m1["t_susp"], m2["score"] >= m2["t_susp"]
    lv2c = level_of(m2["score"], m1["t_susp"], m1["t_like"])   # model (ii) judged at model (i)'s cut-offs, to take the cut-off shift out
    pat = (va["amt"] | va["date"]).to_numpy()
    def flips(mask, fb=f2_, lb=m2["level"]):
        b, s = mask & (y == 0), mask & (y == 1)
        return {"benign: newly flagged": int((b & ~f1_ & fb).sum()), "benign: newly cleared": int((b & f1_ & ~fb).sum()),
                "scam: newly missed": int((s & f1_ & ~fb).sum()), "scam: newly caught": int((s & ~f1_ & fb).sum()),
                "any level change": int((mask & (m1["level"] != lb)).sum())}
    def cell(src_mask, key):
        return f"{flips(src_mask)[key]} ({flips(src_mask & pat)[key]})"
    keys = list(flips(np.ones(len(va), bool)))
    out += ["## 4. Rows that change level (val)", "",
            "Flagged = Suspicious or Likely scam (score >= the model's own suspicious cut-off). Each cell is `total (of which rows that contain an AMT/DATE pattern)`. "
            "Rows without a pattern have **identical input** in both models, so any change there is refit drift plus the cut-off moving, not the mask: that is the noise floor.", "",
            f"Cut-offs: (i) suspicious {m1['t_susp']:.3f} / likely {m1['t_like']:.3f}; (ii) suspicious {m2['t_susp']:.3f} / likely {m2['t_like']:.3f}.", "",
            "### All of val", "",
            md(pd.DataFrame([{"rows": r, "n": int(msk.sum()), **flips(msk)} for r, msk in (("with an AMT/DATE pattern", pat), ("without (identical input)", ~pat), ("all", np.ones(len(va), bool)))])), "",
            "### Same cut-offs for both models", "",
            "Model (ii) judged at model (i)'s cut-offs (suspicious "
            f"{m1['t_susp']:.3f} / likely {m1['t_like']:.3f}), so only the scores differ, not the thresholds:", "",
            md(pd.DataFrame([{"rows": r, "n": int(msk.sum()), **flips(msk, lv2c >= 1, lv2c)} for r, msk in (("with an AMT/DATE pattern", pat), ("without (identical input)", ~pat), ("all", np.ones(len(va), bool)))])), "",
            "### Which pattern, and how many independent clusters", "",
            "Own cut-offs. `clusters` = distinct near-duplicate clusters among the flipped rows (rows of one cluster are one template, not independent evidence). "
            "The four columns on the right split the flipped rows by which pattern they contain.", ""]
    ptype = np.where(va["amt"] & va["date"], "AMT+DATE", np.where(va["amt"], "AMT only", np.where(va["date"], "DATE only", "neither"))).astype(str)
    for title, scope in (("All of val", np.ones(len(va), bool)), ("`india_fraud_final` only", (va["source"] == "india_fraud_final").to_numpy())):
        rows = []
        for label, sel in (("benign: newly flagged", (y == 0) & ~f1_ & f2_), ("benign: newly cleared", (y == 0) & f1_ & ~f2_),
                           ("scam: newly missed", (y == 1) & f1_ & ~f2_), ("scam: newly caught", (y == 1) & ~f1_ & f2_)):
            sel = sel & scope
            rows.append({"flip": label, "rows": int(sel.sum()), "clusters": int(va["cluster"][sel].nunique()),
                         **{p: int((sel & (ptype == p)).sum()) for p in ("AMT only", "DATE only", "AMT+DATE", "neither")}})
        out += [f"**{title}**", "", md(pd.DataFrame(rows)), ""]
    out += ["### Per source", ""]
    rows = []
    for src, g in va.groupby("source"):
        msk = (va["source"] == src).to_numpy()
        rows.append({"source": src, "benign": int((y[msk] == 0).sum()), "scam": int((y[msk] == 1).sum()), "pattern rows": int(pat[msk].sum()), **{k: cell(msk, k) for k in keys}})
    out += [md(pd.DataFrame(rows).sort_values("benign", ascending=False)), ""]

    # ---- 5. genuine alerts
    scorers = [TfidfLrScorer({"vectorizer": m["vec"], "model": m["clf"], "threshold_suspicious": m["t_susp"], "threshold_likely": m["t_like"]}) for m in (m1, m2)]
    tricky = {e["id"]: e["text"] for e in literal(ROOT / "tests/tricky_inputs.py", "INPUTS")}
    alerts = [("`tests/test_contracts.py` EXTRA[1]: HDFC debit alert (amount, no date)", literal(ROOT / "tests/test_contracts.py", "EXTRA")[1]),
              ("`tests/tricky_inputs.py` `otp-disclose`: OTP SMS (amount, no date)", tricky["otp-disclose"]),
              ("`docs/design/prototype-globe.html:548`: HDFC debit alert (amount **and** date; the kind of message BUGS.md describes)",
               "Rs.2,500.00 debited from A/c XX4821 on 14-10-26 to VPA swiggy@ybl. Not you? Call 1800-XXX-XXXX. Never share your OTP with anyone. -HDFC Bank")]
    out += ["## 5. Genuine alerts", "",
            "The text as the app feeds it (`model_text(text, mask_pii=True)`), scored by each of the two models trained above (not saved). "
            "Top 5 n-grams = `TfidfLrScorer.explain` (the app's own explanation code): signed share of the logit, positive pushes toward scam; overlapping n-grams of one word are merged.", ""]
    for title, text in alerts:
        x1 = model_text(text, mask_pii=True); x2 = mask_amt_date(x1)
        res = []
        for sc, m, x in zip(scorers, (m1, m2), (x1, x2)):
            s = sc.score(x); lv = int(level_of(np.array([s]), m["t_susp"], m["t_like"])[0])
            res.append((s, lv, sc.explain(x, k=5)))
        out += [f"### {title}", "", f"- model input (i): `{x1}`", f"- model input (ii): `{x2}`", "",
                md(pd.DataFrame([{"model": "(i) baseline", "score": f"{res[0][0]:.3f}", "level": LEVELS[res[0][1]],
                                  "top 5 n-grams": ", ".join(f"`{g!r}` {c:+.3f}" for g, c in res[0][2])},
                                 {"model": "(ii) masked", "score": f"{res[1][0]:.3f}", "level": LEVELS[res[1][1]],
                                  "top 5 n-grams": ", ".join(f"`{g!r}` {c:+.3f}" for g, c in res[1][2])}])), ""]

    body = "\n".join(out)
    stamp = hashlib.sha256(body.encode()).hexdigest()[:12]
    old = REPORT.read_text(encoding="utf-8") if REPORT.exists() else ""
    m = re.search(r"\n## Interpretation\n(.*)\Z", old, re.S)
    interp = re.sub(r"\A(?:> \*\*Stale:\*\*[^\n]*\n\n)+", "", m.group(1).strip("\n")) if m else "(not yet written)"   # drop warnings from earlier reruns
    stale = re.search(r"<!-- numbers: ([0-9a-f]{12}) -->", interp)
    if m and interp != "(not yet written)" and (not stale or stale.group(1) != stamp):
        interp = "> **Stale:** the tables above changed after this section was written; re-read it before quoting it.\n\n" + interp
    REPORT.write_text(body + "\n\n## Interpretation\n" + interp + "\n", encoding="utf-8")
    print(f"wrote {REPORT.relative_to(ROOT)} (numbers stamp {stamp}); runtime {time.time() - t0:.0f}s")

if __name__ == "__main__":
    main()
