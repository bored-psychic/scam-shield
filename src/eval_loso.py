import argparse, json, shutil, sys
from pathlib import Path

import numpy as np, pandas as pd
from sklearn.metrics import average_precision_score, f1_score, recall_score, roc_auc_score

from textprep import URL_TOKEN, MAX_CHARS
from finetune import SPLIT_MAP_SHA256, LOSO_REFERENCE, LOSO_REFERENCE_PRECISION, LOSO_RULE, LOSO_FOLDS, sha256, split_loso

# Mac-side report for the MuRIL leave-one-source-out (LOSO) folds (src/finetune.py --exclude-source SRC --no-save-model, run on Kaggle by
# notebooks/kaggle_finetune.ipynb with LOSO_SOURCES set). One command after the fold folders are copied to models/finetune/:
#   .venv/bin/python src/eval_loso.py                       # finds models/finetune/muril_loso_*, skips *_smoke; or pass the folders
# It (1) checks every fold against the splits-v2 data (settings = the shipped bundle's, the right rows dropped, predictions_loso.csv holds exactly
# the held-out source's val + test rows and nothing else), (2) copies predictions_loso.csv + shield_meta.json + train_log.txt to
# reports/eval_preds/loso_muril/<source>/ (small, committed, like the other cached predictions), and (3) rewrites section 9 of the report in place
# (everything above it, including the hand-written block, is untouched). eval_text_head.py renders the same section from the cache, so
# regenerating that report keeps it. Nothing is scored here: a fold's scores were written on Kaggle; the in-distribution numbers come from the
# cached predictions of the shipped model (reports/eval_preds/muril_len128_20261021T135255Z), never from a new forward pass.
#
# Row definition = reports/sanity.md section 5 (the baseline's LOSO): the held-out source's val + test rows, F1 / recall / benign accuracy at the
# 0.5 cut-off. Rule = "cluster-strict" (finetune.LOSO_RULE): train and val lose every row in a cluster that holds a row of the source (its own rows, the
# translations of its parents, other sources' near copies). The baseline is refit under the same rule by src/loso_baseline.py (cached in
# reports/eval_preds/loso_baseline_cluster_strict/) and sits beside the old rule's row from sanity.md section 5 ("old rule", which only dropped the source's
# own rows). A fold must also have the shipped bundle's precision (fp16): --allow-precision-mismatch lets a fold from another GPU through, and the report says so.

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data/final"
PREDS = ROOT / "reports/eval_preds"
CACHE = PREDS / "loso_muril"
BASE_CACHE = PREDS / "loso_baseline_cluster_strict"   # src/loso_baseline.py
INDIST = PREDS / "muril_len128_20261021T135255Z"   # the shipped bundle's cached val + test predictions
SANITY = ROOT / "reports/sanity.md"
REPORT = ROOT / "reports/eval_muril_v2.md"
FOLDS_DIR = ROOT / "models/finetune"
HEADING = "## 9. Leave-one-source-out"
CACHED = ("predictions_loso.csv", "shield_meta.json", "train_log.txt")


def md_table(header, rows):
    return "\n".join(["| " + " | ".join(header) + " |", "|" + "---|" * len(header)] + ["| " + " | ".join(map(str, r)) + " |" for r in rows])


def fmt(x, nd=3):
    return "" if x is None or (isinstance(x, float) and np.isnan(x)) else (f"{x:.{nd}f}" if isinstance(x, float) else str(x))


def load_messages(data=DATA):
    got = sha256(data / "split_map.csv")
    assert got == SPLIT_MAP_SHA256, f"split_map.csv is {got[:16]}..., not splits-v2"
    frozen = pd.read_csv(data / "split_map.csv").set_index("text_hash")["split"]
    df = pd.read_csv(data / "messages.csv", low_memory=False)
    assert df["text_hash"].is_unique and (df["text_hash"].map(frozen) == df["split"]).all(), "messages.csv doesn't match split_map.csv"
    return df, sha256(data / "messages.csv")


# ---------------------------------------------------------------------------------------------------------------- checking a fold
def verify_fold(meta, preds, df, messages_sha, allow_precision_mismatch=False):
    """[(name, ok)] for one fold; the caller refuses to continue unless all are ok. `preds` = predictions_loso.csv."""
    src = meta.get("exclude_source")
    st = meta.get("settings", {})
    ref = {k: st.get(k) for k in ("epochs", "batch", "lr", "max_len", "seed", "warmup", "aug", "weight_decay", "grad_clip", "optimizer", "schedule")}
    want = {k: v for k, v in LOSO_REFERENCE.items() if k != "model"}
    checks = [
        ("loso: true and an exclude_source", bool(meta.get("loso")) and bool(src)),
        ("split_map SHA-256 = splits-v2", meta.get("split_map_sha256") == SPLIT_MAP_SHA256),
        ("messages.csv SHA-256 = local file", meta.get("data_sha256", {}).get("messages.csv") == messages_sha),
        ("textprep marker = this textprep", meta.get("textprep") == {"url_token": URL_TOKEN, "max_chars": MAX_CHARS}),
        ("model = google/muril-base-cased", meta.get("model_name") == "google/muril-base-cased"),
        ("settings = the shipped bundle's (3 epochs, batch 16, lr 2e-5, max-len 128, seed 42, warmup 0.06, no aug)", ref == want),
        ("not a smoke / --limit run", not st.get("smoke") and st.get("limit") is None),
        ("test not scored the usual way (score_held_out off)", not st.get("score_held_out")),
        ("git tree clean at training", meta.get("git_dirty") is False),
        (f"loso_rule = {LOSO_RULE} (train / val lose every cluster that holds a row of the source)", meta.get("loso_rule") == LOSO_RULE),
        (f"precision = {LOSO_REFERENCE_PRECISION} (the shipped bundle's)" + ("" if meta.get("precision") == LOSO_REFERENCE_PRECISION or not allow_precision_mismatch
                                                                           else f"; fold has {meta.get('precision')!r}, ALLOWED by --allow-precision-mismatch"),
         meta.get("precision") == LOSO_REFERENCE_PRECISION or allow_precision_mismatch),
    ]
    if src and src in set(df["source"]):
        tr, va, held_va, held_te, counts = split_loso(df, src)   # also asserts: no source row, no translation of its parents, in train / val
        held = pd.concat([held_va, held_te])
        got = preds.set_index("text_hash")
        checks += [
            ("dropped counts in shield_meta.json = recomputed from messages.csv", meta.get("loso_dropped") == counts),
            ("train / val rows in shield_meta.json = recomputed rows without the source", (meta["rows"]["train"], meta["rows"]["val"]) == (len(tr), len(va))),
            ("predictions_loso.csv: unique hashes, exactly the source's val + test rows", got.index.is_unique and set(got.index) == set(held["text_hash"])),
            ("predictions_loso.csv: split and label agree with messages.csv",
             bool((got["split"] == held.set_index("text_hash")["split"].reindex(got.index)).all()
                  and (got["label"] == held.set_index("text_hash")["label"].reindex(got.index)).all())),
            ("predictions_loso.csv: scores are probabilities", bool(got["score"].between(0, 1).all())),
        ]
    else:
        checks.append((f"exclude_source {src!r} is a source in messages.csv", False))
    return checks


def find_folds(paths):
    """{source: folder}; folders with a shield_meta.json that says loso, smoke folders skipped."""
    cands = [Path(p) for p in paths] if paths else sorted(FOLDS_DIR.glob("muril_loso_*"))
    found = {}
    for c in cands:
        if c.name.endswith("_smoke"):
            print(f"  skipping smoke fold {c.name}")
            continue
        meta = json.loads((c / "shield_meta.json").read_text(encoding="utf-8"))
        src = meta.get("exclude_source")
        if not meta.get("loso") or not src:
            raise SystemExit(f"{c} is not a LOSO fold (no loso: true / exclude_source in shield_meta.json)")
        if src in found:
            raise SystemExit(f"two folds for {src}: {found[src].name} and {c.name}; pass the folders you want explicitly")
        found[src] = c
    return found


def update_cache(folds, df, messages_sha, cache=CACHE, replace=False, allow_precision_mismatch=False):
    """Verify each fold folder and copy its small outputs to the cache. Returns the sources cached."""
    for src, folder in folds.items():
        meta = json.loads((folder / "shield_meta.json").read_text(encoding="utf-8"))
        preds = pd.read_csv(folder / "predictions_loso.csv")
        print(f"fold {src} ({folder.name}):")
        checks = verify_fold(meta, preds, df, messages_sha, allow_precision_mismatch)
        for name, ok in checks:
            print(f"  [{'ok' if ok else 'FAIL'}] {name}")
        assert meta["exclude_source"] == src and all(ok for _, ok in checks), f"fold check failed for {src}; nothing cached"
        dest = cache / src
        if dest.exists() and sha256(dest / "predictions_loso.csv") != sha256(folder / "predictions_loso.csv") and not replace:
            raise SystemExit(f"{dest} already holds different predictions for {src}; pass --replace to overwrite it deliberately")
        dest.mkdir(parents=True, exist_ok=True)
        for name in CACHED:
            shutil.copy2(folder / name, dest / name)
        print(f"  cached -> {dest.relative_to(ROOT) if dest.is_relative_to(ROOT) else dest}")
    return list(folds)


# ---------------------------------------------------------------------------------------------------------------- the baseline (cluster-strict)
def verify_baseline(meta, preds, df, messages_sha):
    """[(name, ok)] for one cached baseline fold (src/loso_baseline.py)."""
    src = meta.get("exclude_source")
    checks = [("rule = " + LOSO_RULE, meta.get("rule") == LOSO_RULE), ("split_map SHA-256 = splits-v2", meta.get("split_map_sha256") == SPLIT_MAP_SHA256),
              ("messages.csv SHA-256 = local file", meta.get("messages_sha256") == messages_sha),
              ("textprep marker = this textprep", meta.get("textprep") == {"url_token": URL_TOKEN, "max_chars": MAX_CHARS})]
    if src in set(df["source"]):
        tr, va, held_va, held_te, counts = split_loso(df, src)
        held = pd.concat([held_va, held_te]).set_index("text_hash")
        got = preds.set_index("text_hash")
        checks += [("dropped counts = recomputed from messages.csv", meta.get("loso_dropped") == counts),
                   ("train rows = recomputed rows without the source's clusters", meta.get("rows", {}).get("train") == len(tr)),
                   ("predictions: unique hashes, exactly the source's val + test rows", got.index.is_unique and set(got.index) == set(held.index)),
                   ("predictions: split and label agree with messages.csv", bool((got["split"] == held["split"].reindex(got.index)).all() and (got["label"] == held["label"].reindex(got.index)).all()))]
    else:
        checks.append((f"exclude_source {src!r} is a source in messages.csv", False))
    return checks


def load_baseline(df, messages_sha, base_cache=BASE_CACHE):
    """{source: (predictions, meta)} for LOSO_FOLDS from the cache, every fold verified; refuses (with the command to run) if one is missing or fails."""
    out = {}
    for src in LOSO_FOLDS:
        d = Path(base_cache) / src
        if not (d / "predictions_loso.csv").exists():
            raise SystemExit(f"no cached baseline fold for {src} in {base_cache}; run .venv/bin/python src/loso_baseline.py")
        meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
        preds = pd.read_csv(d / "predictions_loso.csv")
        bad = [n for n, ok in verify_baseline(meta, preds, df, messages_sha) if not ok]
        if bad or meta.get("exclude_source") != src:
            raise SystemExit(f"cached baseline fold {src} fails: {bad}; rerun src/loso_baseline.py")
        out[src] = (preds, meta)
    return out


def baseline_numbers(preds):
    y, s = preds["label"].to_numpy(), preds["score"].to_numpy()   # decision function: score >= 0 is the 0.5-probability cut-off
    return {"F1": f1_score(y, s >= 0, zero_division=0), "AUROC": roc_auc_score(y, s), "PR-AUC": average_precision_score(y, s),
            "scam recall": recall_score(y, s >= 0, zero_division=0), "benign acc": float((s[y == 0] < 0).mean())}


# ---------------------------------------------------------------------------------------------------------------- numbers
def baseline_table(sanity=SANITY):
    """sanity.md section 5 as a DataFrame keyed by held-out source (the baseline's LOSO, old rule), after checking it is on splits-v2."""
    san = Path(sanity).read_text(encoding="utf-8")
    assert SPLIT_MAP_SHA256[:16] in san.split("\n## ")[0], f"{sanity} is not on splits-v2"
    sec = san.split("## 5. Leave-one-source-out")[1].split("\n## ")[0]
    lines = [l for l in sec.splitlines() if l.startswith("|")]
    rows = [[c.strip() for c in l.strip().strip("|").split("|")] for l in lines]
    t = pd.DataFrame(rows[2:], columns=rows[0])
    t[t.columns[1:]] = t[t.columns[1:]].astype(float)
    return t.set_index("held-out source"), "\n".join(lines)


def fold_numbers(src, preds, meta, df, indist):
    """One row of metrics for one fold. `indist` = {'val': DataFrame, 'test': DataFrame} cached predictions of the shipped model."""
    y, s = preds["label"].to_numpy(), preds["score"].to_numpy()
    ids = set(preds["text_hash"])
    ind = pd.concat([indist["val"], indist["test"]])
    ind = ind[ind["text_hash"].isin(ids)]
    assert len(ind) == len(preds), f"{src}: the shipped model's cached predictions cover {len(ind)} of the fold's {len(preds)} rows"
    yi, si = ind["label"].to_numpy(), ind["score"].to_numpy()
    cut = meta["threshold_likely"]
    r = {"held-out source": src, "train rows left": meta["rows"]["train"], "val+test n": len(preds), "scam rate": float(y.mean()),
         "MuRIL in-dist F1@0.5": f1_score(yi, si >= 0.5, zero_division=0), "MuRIL in-dist AUROC": roc_auc_score(yi, si),
         "MuRIL LOSO F1@0.5": f1_score(y, s >= 0.5, zero_division=0), "MuRIL LOSO F1@likely": f1_score(y, s >= cut, zero_division=0),
         "MuRIL LOSO AUROC": roc_auc_score(y, s), "MuRIL LOSO PR-AUC": average_precision_score(y, s),
         "MuRIL LOSO scam recall": recall_score(y, s >= 0.5, zero_division=0),
         "MuRIL LOSO benign acc": float((s[y == 0] < 0.5).mean()), "likely cut-off": cut}
    r["MuRIL AUROC drop"] = r["MuRIL in-dist AUROC"] - r["MuRIL LOSO AUROC"]
    return r


def by_source(d):
    return ", ".join(f"{k} {v}" for k, v in d.items()) or "0"


def drift_text(path):
    """The sentence under the table about the preprocessing change since the shipped bundle (src/textprep_drift.py), or a pointer to run it."""
    path = Path(path)
    if not path.exists():
        return ("**Preprocessing drift not measured**: run `.venv/bin/python src/textprep_drift.py` to count how many of these rows get a different `model_text` than under the code "
                "the shipped bundle was trained with.\n")
    d = json.loads(path.read_text(encoding="utf-8"))
    rows = {s: r for s, r in d["sources"].items()}
    total, changed = sum(r["rows"] for r in rows.values()), sum(r["changed"] for r in rows.values())
    per = "; ".join(f"{s} {r['changed']} of {r['rows']}" for s, r in rows.items())
    if changed == 0:
        return (f"Preprocessing drift: `textprep.model_text` (with `pii.py`, `url_features.py`) gives the same input under the current code ({d['new_commit']}) as under {d['old_commit']}, "
                f"the commit the shipped bundle was trained with, for all {total} val + test rows scored here ({per}), so the in-distribution and LOSO columns see identical text.\n")
    return (f"**Preprocessing drift: {changed} of {total} val + test rows get a different model input** under the current code ({d['new_commit']}) than under {d['old_commit']}, the commit "
            f"the shipped bundle was trained with ({per}). The folds run the current code, the in-distribution column was scored on the old inputs, so those rows differ between the "
            "two columns for a reason that is not about the source.\n")


def section9_body(df, cache=CACHE, sanity=SANITY, indist_dir=INDIST, shipped=True, base_cache=BASE_CACHE, messages_sha=None):
    """Markdown for section 9 (without its heading), from the cached folds; the 'pending' text when there are none. shipped=False (a report on another
    bundle, e.g. the augmented run): the folds belong to the shipped plain MuRIL, so only the baseline table and a pointer are shown."""
    base_old, base_md = baseline_table(sanity)
    if not shipped:
        return ("**Not run for this model.** The MuRIL LOSO folds are for the shipped plain bundle (`reports/eval_muril_v2.md` section 9). The baseline's LOSO under the old rule, "
                "from `reports/sanity.md` section 5:\n\n" + base_md + "\n")
    folds = sorted(p.parent for p in Path(cache).glob("*/predictions_loso.csv")) if Path(cache).exists() else []
    messages_sha = messages_sha or sha256(DATA / "messages.csv")
    base = load_baseline(df, messages_sha, base_cache)
    bnum = {s: baseline_numbers(p) for s, (p, _) in base.items()}
    val_total = int((df["split"] == "val").sum())

    rule = (f"**Rule (`{LOSO_RULE}`).** For a held-out source, every row of train **and** val that sits in a near-duplicate cluster (`cluster_id`) holding a row of that source is dropped, "
            "whatever its source: the source's own rows, the translations of its parents (including the preview parents that were attached to one of its rows as a near twin, which "
            "`translation_of` alone does not find), and other sources' near copies (e.g. `ealvaradob_phishing` rows that repeat `uci_sms_spam` messages). Val is cleaned too because the "
            "best epoch and the cut-offs are chosen on it. The scored rows are the source's own val + test rows, as in `reports/sanity.md` section 5. Other sources' test rows are never "
            "loaded, so their twins there are not counted. Both the MuRIL fold and the baseline refit below use this rule; the \"old rule\" columns are `reports/sanity.md` section 5, "
            "which dropped only the source's own rows (and kept the translations and the other sources' twins), so they are the optimistic reference.\n")
    drops = [[s, m["loso_dropped"]["train"], m["loso_dropped"]["translations"], by_source(m["loso_dropped"]["other_sources"]["train"]), by_source(m["loso_dropped"]["other_sources"]["val"]),
              m["loso_dropped"]["val"], m["loso_dropped"]["test"], m["rows"]["train"], val_total - m["loso_dropped"]["val"] - sum(m["loso_dropped"]["other_sources"]["val"].values())]
             for s, (_, m) in base.items()]
    t_drops = md_table(["held-out source", "source's train rows dropped", "translations dropped", "other-source train rows dropped", "other-source val rows dropped",
                        "source's val rows (scored, out of val)", "source's test rows (scored)", "train rows left", "val rows left"], drops)
    cmp_rows = []
    for s in LOSO_FOLDS:
        o, n = base_old.loc[s], bnum[s]
        cmp_rows.append([s, int(o["val+test n"]), fmt(float(o["scam rate"])), int(o["train rows left"]), base[s][1]["rows"]["train"],
                         fmt(o["LOSO F1"]), fmt(n["F1"]), fmt(o["LOSO AUROC"]), fmt(n["AUROC"]), fmt(o["LOSO PR-AUC"]), fmt(n["PR-AUC"]), fmt(o["in-dist AUROC"])])
        assert int(o["val+test n"]) == len(base[s][0]), f"{s}: sanity.md has {int(o['val+test n'])} val+test rows, the cached baseline fold {len(base[s][0])}"
    t_cmp = md_table(["held-out source", "val+test n", "scam rate", "train rows left (old rule)", "train rows left (cluster-strict)", "baseline F1 old rule", "baseline F1 cluster-strict",
                      "AUROC old rule", "AUROC cluster-strict", "PR-AUC old rule", "PR-AUC cluster-strict", "baseline in-dist AUROC"], cmp_rows)
    base_text = ("The TF-IDF baseline refit under the same rule (`src/loso_baseline.py`, the settings of `sanity_checks.py` section 5, train split only; F1 at the 0.5-probability cut-off; "
                 "cached predictions in `reports/eval_preds/loso_baseline_cluster_strict/`) against the old rule:\n")
    head = [rule, "What the rule drops, per held-out source (counts from `messages.csv`, checked against every cached fold):\n", t_drops + "\n", base_text, t_cmp + "\n"]

    if not folds:
        return "\n".join(head + [
            "**MuRIL LOSO: code ready, runs pending** (`src/finetune.py --exclude-source`, `notebooks/kaggle_finetune.ipynb` with `LOSO_SOURCES`, then `src/eval_loso.py` fills the MuRIL "
            f"table here; {len(LOSO_FOLDS)} folds: {', '.join(LOSO_FOLDS)}).\n", drift_text(Path(cache) / "textprep_drift.json")])

    indist = {k: pd.read_csv(Path(indist_dir) / f"predictions_{k}.csv") for k in ("val", "test")}
    df_src = df.set_index("text_hash")
    rows, trained = [], []
    for fd in folds:
        src = fd.name
        meta = json.loads((fd / "shield_meta.json").read_text(encoding="utf-8"))
        preds = pd.read_csv(fd / "predictions_loso.csv")
        assert set(df_src.loc[preds["text_hash"], "source"]) == {src}, f"{fd}: predictions are not all {src} rows"
        n = fold_numbers(src, preds, meta, df, indist)
        o, b = base_old.loc[src], bnum[src]
        n.update({"baseline F1": b["F1"], "baseline AUROC": b["AUROC"], "baseline PR-AUC": b["PR-AUC"],
                  "baseline F1 old": o["LOSO F1"], "baseline AUROC old": o["LOSO AUROC"], "baseline PR-AUC old": o["LOSO PR-AUC"],
                  "baseline AUROC drop": o["in-dist AUROC"] - b["AUROC"], "baseline train rows left": base[src][1]["rows"]["train"]})
        assert n["val+test n"] == len(base[src][0]), f"{src}: the baseline fold scored {len(base[src][0])} rows, the MuRIL fold {n['val+test n']}"
        assert meta["rows"]["train"] == n["baseline train rows left"], f"{src}: MuRIL and baseline folds trained on different row counts"
        rows.append(n)
        trained.append([src, meta["rows"]["train"], meta["rows"]["val"], meta["best_epoch"], fmt(meta["threshold_likely"]), meta["training_seconds"], meta.get("precision", ""),
                        meta.get("gpu_name") or meta.get("device", "")])
    order = {s: i for i, s in enumerate(LOSO_FOLDS)}
    rows.sort(key=lambda r: order[r["held-out source"]])
    trained.sort(key=lambda r: order[r[0]])
    head2 = ["held-out source", "train rows left", "val+test n", "scam rate", "baseline F1 (cluster-strict)", "baseline AUROC", "baseline PR-AUC",
             "MuRIL in-dist F1@0.5", "MuRIL in-dist AUROC", "MuRIL LOSO F1@0.5", "MuRIL LOSO F1@likely", "MuRIL LOSO AUROC", "MuRIL LOSO PR-AUC",
             "MuRIL LOSO scam recall", "MuRIL LOSO benign acc", "MuRIL AUROC drop", "baseline AUROC drop", "baseline F1 old rule", "baseline AUROC old rule", "baseline PR-AUC old rule"]
    keys = ["held-out source", "train rows left", "val+test n", "scam rate", "baseline F1", "baseline AUROC", "baseline PR-AUC",
            "MuRIL in-dist F1@0.5", "MuRIL in-dist AUROC", "MuRIL LOSO F1@0.5", "MuRIL LOSO F1@likely", "MuRIL LOSO AUROC", "MuRIL LOSO PR-AUC",
            "MuRIL LOSO scam recall", "MuRIL LOSO benign acc", "MuRIL AUROC drop", "baseline AUROC drop", "baseline F1 old", "baseline AUROC old", "baseline PR-AUC old"]
    prec = sorted({r[6] for r in trained})
    out = [f"MuRIL leave-one-source-out, {len(rows)} folds ({', '.join(r['held-out source'] for r in rows)}), against the baseline refit under the same rule. "
           "Each fold is the shipped MuRIL (max-len 128, no augmentation, 3 epochs, batch 16, lr 2e-5, seed 42; `finetune.LOSO_REFERENCE`) trained without one source, under the "
           "rule above. `F1@0.5`, scam recall and benign accuracy are at the 0.5 cut-off (as the baseline's); `F1@likely` is at the fold's own val-chosen likely-scam "
           "cut-off (val without the source's clusters); `in-dist` = the shipped model, trained with the source, on the same rows (cached predictions, not re-scored); "
           "`AUROC drop` = in-dist AUROC minus LOSO AUROC (for the baseline: its in-distribution AUROC from `sanity.md`, minus the cluster-strict LOSO AUROC). The last three columns "
           "are the baseline under the old rule. Scam rate is what a random ranking scores on PR-AUC.\n",
           md_table(head2, [[fmt(r[k]) if k not in ("held-out source", "train rows left", "val+test n") else r[k] for k in keys] for r in rows]) + "\n",
           "AUROC measures only the ranking (how often a scam scores above a genuine message), so it needs no cut-off. F1, recall and benign accuracy are measured at a "
           "cut-off, so they also move if the model's scores shift on a new source. A high LOSO AUROC with a low LOSO F1@0.5 means the ranking survived and only the "
           "cut-off moved (F1@likely, with the fold's own val-chosen cut-off, shows how much of that a re-fitted cut-off would repair, though on a truly new source "
           "there is no val to fit it on). A low LOSO AUROC is a real failure: the model cannot tell scams from genuine messages in a source it has not seen. "
           "The held-out test rows were scored again here by a different model (one that never trained on that source), and nothing was tuned on them: the best epoch and "
           "both cut-offs come from val without the source's clusters.\n",
           "How each fold trained:\n",
           md_table(["held-out source", "MuRIL train rows left", "val rows left", "best epoch", "likely cut-off", "training s", "precision", "GPU"], trained) + "\n",
           (f"Every fold has the shipped bundle's precision ({LOSO_REFERENCE_PRECISION}).\n" if prec == [LOSO_REFERENCE_PRECISION] else
            f"**Precision differs from the shipped bundle's ({LOSO_REFERENCE_PRECISION}): folds have {prec}** (accepted with `--allow-precision-mismatch`); read the MuRIL columns with that in mind.\n"),
           drift_text(Path(cache) / "textprep_drift.json"),
           "Limits, same as the baseline's table: one seed per fold; the rule removes near copies inside train / val but not in other sources' test rows, and a looser paraphrase "
           "(below the 0.6 / 0.7 Jaccard rule) of a source's message can still be in another source; `synth_india` has no val rows, so its fold holds out test rows only; the in-dist column is "
           "the model that trained on the source's own train split, so the drop mixes 'source never seen' with 'source-specific shortcuts lost'. Per source "
           "the rows are few (428-1,032), so a difference of a few hundredths in F1 is inside the noise.\n"]
    return "\n".join(head + out)


def write_section(report, body):
    """Replace section 9 (the last section) of the report in place; everything above it is left byte for byte."""
    text = Path(report).read_text(encoding="utf-8")
    i = text.index(HEADING)
    if "\n## " in text[i + len(HEADING):]:
        raise SystemExit(f"{HEADING} is not the last section of {report}; refusing to cut anything after it")
    Path(report).write_text(text[:i] + HEADING + "\n\n" + body.rstrip("\n") + "\n\n", encoding="utf-8")   # ends like eval_text_head.py's report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("folds", nargs="*", help="fold folders (default: models/finetune/muril_loso_*, smoke folders skipped)")
    ap.add_argument("--report", type=Path, default=REPORT)
    ap.add_argument("--replace", action="store_true", help="overwrite cached predictions of a fold that already has different ones")
    ap.add_argument("--allow-precision-mismatch", action="store_true", help=f"accept folds whose precision is not the shipped bundle's ({LOSO_REFERENCE_PRECISION}); the report says so")
    a = ap.parse_args()
    df, messages_sha = load_messages()
    folds = find_folds(a.folds)
    if folds:
        update_cache(folds, df, messages_sha, replace=a.replace, allow_precision_mismatch=a.allow_precision_mismatch)
    write_section(a.report, section9_body(df, messages_sha=messages_sha))
    print(f"wrote section 9 of {a.report} from {len(list(CACHE.glob('*/predictions_loso.csv')))} cached MuRIL folds")


if __name__ == "__main__":
    main()
