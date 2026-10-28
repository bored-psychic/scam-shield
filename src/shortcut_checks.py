import argparse, os, re, sys
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score
from textprep import model_text

# splits-v3 shortcut checks (docs/plans/splits_v3.md section 3, rule 3): what a model could score without reading the words. VAL ONLY: messages.csv is read in
# chunks that keep val rows (evaluated) and train rows (only to estimate a category's rate for the language / kw_bucket cues); a test row is never kept.
# Run through sanity_checks.py:
#   .venv/bin/python src/sanity_checks.py --v3-shortcuts [--data-dir data/final] [--out reports/sanity_shortcuts_v3.md]
#
# Every check is a cue-only AUROC: one cue (no text model) is the score, the label (or the "is a phones_pool row" flag) is the target. AUROC 0.5 = no signal. The report
# shows the oriented AUROC (cue up -> positive class); a flag uses the strength max(AUROC, 1 - AUROC), so a cue that points to genuine counts as much as one that points to scam.
#   label cues      token presence (mask tokens, as model_text() leaves them), message length, non-Latin letter share (script), language and kw_bucket (train-estimated rate of
#                   the category, as sanity_checks.py section 4 does), each on all val rows and per source;
#   POOL-origin     the same cues against "this val row is a phones_pool row", over all rows and, because the pool is ~97 % genuine, genuine rows only, overall and against
#                   each source: the shortcut the mask harmonisation (D-v3.5) exists to prevent;
#   length          label AUROC of message length on val with and without POOL (plan section 3);
#   synthetic/real  synth_upi_collect_v3 val rows against real collect-request val rows of the pool (both genuine), only if the family is on.
# kw_bucket is pool metadata and not a model input; "is a pool row" by kw_bucket is true by construction and is not reported as a flag.
#
# THRESHOLDS: section 3 of the plan names the cues but gives NO numbers, so the three below are chosen here, not taken from the plan. FLAG_STRENGTH is deliberately low
# (the English short-SMS reference of sanity.md, length alone 0.92, is far above it); the minimum counts keep a 3-row subset from flagging, and with ~150 per-source comparisons a 30-row group (SD of AUROC about 0.075) makes a chance flag at 0.70 rare. Change them here, one place.
FLAG_STRENGTH = 0.70        # a cue whose strength max(AUROC, 1 - AUROC) is at least this is flagged
MIN_CLASS = 30              # rows needed in each of the two compared groups (positives and negatives) before an AUROC is computed or flagged
MIN_SYNTH_REAL = 10         # same, for the small synthetic-family-vs-real-collect comparison
TOKENS = ["<OTP>", "<NAME>", "<ACCOUNT>", "<PHONE>", "<UPI_ID>", "<URL>", "<EMAIL>", "<UPI>"]   # the plan's six + the other two tokens pii.py writes
POOL_SOURCE, SYNTH_UPI_SOURCE = "phones_pool", "synth_upi_collect_v3"   # as gates_v3.py
COLLECT_RX = re.compile(r"collect request|request money|payment request", re.I)   # as gates_v3.py
LOAD_COLS = ["text", "label", "source", "language", "is_synthetic", "split", "kw_bucket", "real_group"]


def load(path):
    """(train, val) from a messages.csv, chunked; test rows are dropped inside the loop and never concatenated."""
    parts = []
    for chunk in pd.read_csv(path, chunksize=20000, keep_default_na=False, low_memory=False, usecols=lambda c: c in LOAD_COLS):
        parts.append(chunk[chunk["split"].isin(["train", "val"])])
    d = pd.concat(parts, ignore_index=True)
    for c in ("kw_bucket", "real_group"):
        if c not in d:
            d[c] = ""
    d["label"] = d["label"].astype(int)
    d["text"] = d["text"].map(model_text)   # the text models' input (rule 11): links -> <URL>, cut to 2000 characters
    return d[d["split"] == "train"].reset_index(drop=True), d[d["split"] == "val"].reset_index(drop=True)


def cue_frame(d):
    """Numeric cues of a frame, one column each: token presence, length, non-Latin letter share."""
    t = d["text"]
    X = {f"has {k}": t.str.contains(k, regex=False).astype(float) for k in TOKENS}
    X["length"] = t.str.len().astype(float)
    letters = t.map(lambda s: sum(c.isalpha() for c in s))
    nonlatin = t.map(lambda s: sum(c.isalpha() and ord(c) > 0x24F for c in s))
    X["non-Latin letter share"] = (nonlatin / letters.replace(0, np.nan)).fillna(0.0)
    return pd.DataFrame(X, index=d.index)


def category_cue(train, d, col, target):
    """A categorical cue as a score: the train rate of `target` (a 0/1 Series aligned with train) in each category of `col`; unseen categories get the train rate overall."""
    rate = target.groupby(train[col]).mean()
    return d[col].map(rate).fillna(float(target.mean())).astype(float)


def auroc_row(cue, y, name, scope, min_n):
    """One result row, or a 'too few rows' row. y is 0/1; cue the score."""
    y, cue = np.asarray(y), np.asarray(cue, dtype=float)
    n_pos, n_neg = int((y == 1).sum()), int((y == 0).sum())
    row = {"cue": name, "scope": scope, "n": len(y), "positives": n_pos, "AUROC": np.nan, "strength": np.nan, "flag": False, "note": ""}
    if min(n_pos, n_neg) < min_n:
        row["note"] = f"too few rows (need {min_n} per group)"
    elif np.ptp(cue) == 0:
        row["note"] = "cue is constant here"
    else:
        a = float(roc_auc_score(y, cue))
        row["AUROC"], row["strength"] = a, max(a, 1 - a)
        row["flag"] = row["strength"] >= FLAG_STRENGTH
    return row


def label_cues(train, val):
    """Section A: every cue against the label, all val rows and per source."""
    rows, X = [], cue_frame(val)
    cats = {"language": category_cue(train, val, "language", train["label"])}
    pool_tr = train[train["source"] == POOL_SOURCE]
    pool_va_idx = val.index[val["source"] == POOL_SOURCE]
    kw = pd.Series(np.nan, index=val.index)
    if len(pool_tr) and len(pool_va_idx):   # kw_bucket exists only for pool rows: scored inside the pool
        kw.loc[pool_va_idx] = category_cue(pool_tr, val.loc[pool_va_idx], "kw_bucket", pool_tr["label"]).to_numpy()
    scopes = [("all val", val.index)] + [(f"source {s}", val.index[val["source"] == s]) for s in sorted(val["source"].unique())]
    for scope, idx in scopes:
        for name in X.columns:
            rows.append(auroc_row(X.loc[idx, name], val.loc[idx, "label"], name, scope, MIN_CLASS))
        rows.append(auroc_row(cats["language"][idx], val.loc[idx, "label"], "language (train rate)", scope, MIN_CLASS))
    if len(pool_va_idx):
        rows.append(auroc_row(kw[pool_va_idx], val.loc[pool_va_idx, "label"], "kw_bucket (pool train rate)", f"source {POOL_SOURCE}", MIN_CLASS))
    return pd.DataFrame(rows)


def pool_origin_cues(train, val):
    """Section B: every cue against 'is a phones_pool row'. Scopes: all val rows, genuine rows only, and genuine rows of pool vs genuine rows of each other source."""
    is_pool = (val["source"] == POOL_SOURCE).to_numpy()
    if not is_pool.any():
        return pd.DataFrame(), "no phones_pool rows in val: not measurable"
    X = cue_frame(val)
    cue_cols = list(X.columns)
    lang = category_cue(train, val, "language", (train["source"] == POOL_SOURCE).astype(int))
    rows = []
    genuine = (val["label"] == 0).to_numpy()
    scopes = [("all val rows", np.ones(len(val), bool)), ("genuine rows only", genuine)]
    for s in sorted(val["source"].unique()):
        if s != POOL_SOURCE:
            scopes.append((f"genuine: pool vs {s}", genuine & ((val["source"] == s).to_numpy() | is_pool)))
    for scope, sel in scopes:
        for name in cue_cols:
            rows.append(auroc_row(X.loc[sel, name], is_pool[sel].astype(int), name, scope, MIN_CLASS))
        rows.append(auroc_row(lang[sel], is_pool[sel].astype(int), "language (train pool rate)", scope, MIN_CLASS))
    return pd.DataFrame(rows), ""


def length_with_without_pool(val):
    """Section D: label AUROC of message length on val with and without the pool rows, overall and real rows only."""
    L = val["text"].str.len().astype(float)
    nopool = val["source"] != POOL_SOURCE
    real = ~val["is_synthetic"].astype(str).str.lower().eq("true")
    rows = []
    for scope, sel in (("all val", slice(None)), ("all val, without POOL", nopool), ("real rows (is_synthetic = False)", real), ("real rows, without POOL", real & nopool)):
        rows.append(auroc_row(L[sel], val.loc[sel, "label"], "length", scope, MIN_CLASS))
    return pd.DataFrame(rows)


def synth_vs_real(val):
    """Section C: synth_upi_collect_v3 val rows (positive) against real collect-request val rows of the pool (negative), cues only. None if the family is off."""
    syn = val["source"] == SYNTH_UPI_SOURCE
    if not syn.any():
        return None, "the synthetic UPI collect family is not in this build: not checked"
    real = (val["source"] == POOL_SOURCE) & val["text"].str.contains(COLLECT_RX)
    sel = syn | real
    X = cue_frame(val)
    rows = [auroc_row(X.loc[sel, c], syn[sel].astype(int), c, "synthetic family vs real collect rows", MIN_SYNTH_REAL) for c in X.columns]
    return pd.DataFrame(rows), f"{int(syn.sum())} synthetic val rows, {int(real.sum())} real collect-request val rows"


def flag_lines(label_df, pool_df, synth_df):
    out = []
    def side(r, target):
        return f"cue up -> {target}" if r["AUROC"] >= 0.5 else f"cue down -> {target}"
    for _, r in label_df[label_df["flag"]].iterrows():
        out.append(f"RED FLAG [label cue] {r['cue']} | {r['scope']}: strength {r['strength']:.3f} (AUROC {r['AUROC']:.3f}, {side(r, 'scam')}), n={r['n']}, scam={r['positives']}, "
                   f"threshold {FLAG_STRENGTH}")
    if pool_df is not None and len(pool_df):
        for _, r in pool_df[pool_df["flag"]].iterrows():
            out.append(f"RED FLAG [POOL-origin cue] {r['cue']} | {r['scope']}: strength {r['strength']:.3f} (AUROC {r['AUROC']:.3f}, {side(r, 'pool row')}), n={r['n']}, "
                       f"pool rows={r['positives']}, threshold {FLAG_STRENGTH}")
    if synth_df is not None and len(synth_df):
        for _, r in synth_df[synth_df["flag"]].iterrows():
            out.append(f"RED FLAG [synthetic-vs-real cue] {r['cue']}: strength {r['strength']:.3f} (AUROC {r['AUROC']:.3f}, {side(r, 'synthetic')}), n={r['n']}, "
                       f"synthetic={r['positives']}, threshold {FLAG_STRENGTH}")
    return out


def md(df):
    cols = [c for c in df.columns if c != "flag"]
    cell = lambda v: "" if (isinstance(v, float) and np.isnan(v)) else (f"{v:.3f}" if isinstance(v, (float, np.floating)) else str(v))
    lines = ["| " + " | ".join(cols + ["flag"]) + " |", "|" + "|".join(" --- " for _ in cols + ["flag"]) + "|"]
    for _, r in df.iterrows():
        lines.append("| " + " | ".join(cell(r[c]) for c in cols) + f" | {'**RED FLAG**' if r['flag'] else ''} |")
    return "\n".join(lines)


def run(train, val, data_label=""):
    """Everything; returns (flag lines, report markdown). `val` and `train` need the LOAD_COLS columns and model_text()'d text."""
    lab = label_cues(train, val)
    pool_df, pool_note = pool_origin_cues(train, val)
    synth_df, synth_note = synth_vs_real(val)
    lens = length_with_without_pool(val)
    flags = flag_lines(lab, pool_df, synth_df)
    L = [f"# splits-v3 shortcut checks{(' (' + data_label + ')') if data_label else ''}", "",
         f"Val only ({len(val)} rows; {int((val['source'] == POOL_SOURCE).sum())} from `{POOL_SOURCE}`, {int((val['source'] == SYNTH_UPI_SOURCE).sum())} from `{SYNTH_UPI_SOURCE}`); "
         f"train rows ({len(train)}) only estimate the rate of a category for the language / kw_bucket cues; the test split is never read. Each row is a cue-only AUROC: one cue, no text model. "
         f"A row is flagged when its strength max(AUROC, 1 - AUROC) is at least **{FLAG_STRENGTH}** with at least {MIN_CLASS} rows in each compared group "
         f"({MIN_SYNTH_REAL} for the synthetic-family comparison). **These numbers are not from the plan** (section 3 names the cues, gives no thresholds); "
         "see `src/shortcut_checks.py`. A flag is a report, not a verdict: a flagged cue that is also a real label signal (length in short SMS) shows here too.", "",
         f"## Flags ({len(flags)})", ""] + ([f"- {f}" for f in flags] or ["- none"]) + ["", "## A. Cues against the label", "", md(lab), "",
         "## B. Cues against 'is a phones_pool row'", "", pool_note or "Genuine-only scopes are the like-for-like ones (the pool is ~97 % genuine). `kw_bucket` is true by construction (only pool rows carry it) and is not a model input.", ""]
    if len(pool_df):
        L += [md(pool_df), ""]
    L += ["## C. Synthetic UPI collect family against real collect-request rows", "", synth_note, ""]
    if synth_df is not None:
        L += [md(synth_df), ""]
    L += ["## D. Length-only label AUROC, with and without POOL", "", md(lens), ""]
    return flags, "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="splits-v3 shortcut checks (val only)")
    ap.add_argument("--data-dir", default="data/final", help="folder with messages.csv (default data/final; a scratch build folder works)")
    ap.add_argument("--out", default="reports/sanity_shortcuts_v3.md", help="report path")
    a = ap.parse_args(argv)
    path = os.path.join(a.data_dir, "messages.csv")
    train, val = load(path)
    flags, report = run(train, val, a.data_dir)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"{len(flags)} red flag(s); report: {a.out}")
    for f_ in flags:
        print(f_)
    return flags


if __name__ == "__main__":
    main()
