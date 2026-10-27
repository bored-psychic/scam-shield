import argparse, hashlib, json, os, platform, re, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("HF_HUB_OFFLINE", "1")   # the bundle carries its tokenizer; nothing is downloaded
import joblib
import numpy as np, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

from textprep import model_text, URL_TOKEN, MAX_CHARS
from finetune import SPLIT_MAP_SHA256, sha256, thresholds   # the same splits-v2 hash and the same val cut-off rule as training
from eval_loso import section9_body   # section 9 (LOSO) is rendered from reports/eval_preds/loso_muril/, so a regenerated report keeps it

# Mac-side evaluation of a fine-tuned text head (src/finetune.py bundle) against the splits-v2 TF-IDF baseline. One command per model:
#   .venv-finetune/bin/python src/eval_text_head.py models/finetune/muril_len128_20261021T135255Z --report reports/eval_muril_v2.md \
#       --expect-commit 06f402e --expect-max-len 128 --expect-aug no
#
# Test is scored ONCE per model (CLAUDE.md rule 1 spirit: nothing is chosen on it). The first run writes
# reports/eval_preds/<model>/predictions_{test,adv_test}.csv + scored.json (when, where, which data); every later run reads those files and
# refuses to score again, so the report is always regenerated from the saved predictions. The baseline is refit on the splits-v2 train
# split with baseline.py's exact settings (NOT the app's models/text_baseline.joblib, which is the splits-v1 fit) and cached the same way
# under reports/eval_preds/baseline_splits_v2/. Cut-offs: each model's own, chosen on val (finetune.thresholds = baseline.py --save rule).
# Before a fine-tuned model touches test, val is re-scored on this Mac and must reproduce the bundle's predictions_val.csv.
#
# The report keeps everything between the HAND-WRITTEN markers when it is regenerated; --notes is a CSV (text_hash, why) whose guesses fill
# the "why" column of the worst-errors tables.

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data/final"
PREDS = ROOT / "reports/eval_preds"
BASELINE_KEY = "baseline_splits_v2"
BASELINE_FILE = ROOT / "models/eval/text_baseline_splits_v2.joblib"
LANGS = ("english", "hinglish", "hindi", "kannada")
HAND = ("<!-- HAND-WRITTEN START (kept when the report is regenerated) -->", "<!-- HAND-WRITTEN END -->")
SPEED_N, SPEED_WARMUP = 200, 10


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def git_head():
    return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()


# ---------------------------------------------------------------------------------------------------------------- data
def load_data():
    got = sha256(DATA / "split_map.csv")
    assert got == SPLIT_MAP_SHA256, f"split_map.csv is {got[:16]}..., not splits-v2"
    frozen = pd.read_csv(DATA / "split_map.csv").set_index("text_hash")["split"]
    df = pd.read_csv(DATA / "messages.csv", low_memory=False)
    assert df["text_hash"].is_unique and (df["text_hash"].map(frozen) == df["split"]).all(), "messages.csv doesn't match split_map.csv"
    adv = pd.read_csv(DATA / "messages_adv_test.csv", low_memory=False)
    assert (adv["parent_hash"].map(frozen) == "test").all(), "messages_adv_test.csv has parents outside test"
    adv["adv_row"] = np.arange(len(adv))
    files = {f: sha256(DATA / f) for f in ("split_map.csv", "messages.csv", "messages_adv_test.csv")}
    return df, adv, files


def write_once(out, preds, info):
    """Writes the val/test/adv prediction files of one model; refuses if test predictions already exist (test is scored once)."""
    out.mkdir(parents=True, exist_ok=True)
    assert not (out / "predictions_test.csv").exists(), f"{out} already has test predictions; they are read, never rewritten"
    for name, d in preds.items():
        d.to_csv(out / f"predictions_{name}.csv", index=False, encoding="utf-8")
    info["prediction_sha256"] = {f"predictions_{n}.csv": sha256(out / f"predictions_{n}.csv") for n in preds}
    (out / "scored.json").write_text(json.dumps(info, indent=2), encoding="utf-8")


def read_cached(out):
    info = json.loads((out / "scored.json").read_text(encoding="utf-8"))
    for f, h in info["prediction_sha256"].items():
        assert sha256(out / f) == h, f"{out / f} changed since it was written"
    return {n: pd.read_csv(out / f"predictions_{n}.csv") for n in ("val", "test", "adv_test")}, info


# ---------------------------------------------------------------------------------------------------------------- baseline
def baseline_vec_clf():
    # exactly baseline.py's model; keep in step with it
    return (TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=3, max_features=200000, sublinear_tf=True),
            LogisticRegression(max_iter=2000, class_weight="balanced"))


def baseline_preds(df, adv, files):
    out = PREDS / BASELINE_KEY
    if (out / "scored.json").exists():
        return read_cached(out)
    tr, va, te = (df[df["split"] == s] for s in ("train", "val", "test"))
    vec, clf = baseline_vec_clf()
    clf.fit(vec.fit_transform(tr["text"].map(model_text)), tr["label"])
    score = lambda texts: clf.predict_proba(vec.transform([model_text(t) for t in texts]))[:, 1]
    s_va = score(va["text"])
    t_susp, t_likely = thresholds(va["label"].to_numpy(), s_va)
    BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"vectorizer": vec, "model": clf, "threshold_suspicious": t_susp, "threshold_likely": t_likely,
                 "trained_on": "splits-v2 train split, textprep.model_text (eval_text_head.py; not the app's model)",
                 "textprep": {"url_token": URL_TOKEN, "max_chars": MAX_CHARS}}, BASELINE_FILE)
    print(f"baseline refit on splits-v2 train ({len(tr)} rows): val F1@0.5 {f1_score(va['label'], s_va >= 0.5):.3f}; "
          f"cut-offs suspicious {t_susp:.3f}, likely {t_likely:.3f} -> {BASELINE_FILE}")
    print("opening test for the baseline (scored once, cached)")
    preds = {"val": pd.DataFrame({"text_hash": va["text_hash"], "label": va["label"], "score": s_va}),
             "test": pd.DataFrame({"text_hash": te["text_hash"], "label": te["label"], "score": score(te["text"])}),
             "adv_test": pd.DataFrame({"adv_row": adv["adv_row"], "parent_hash": adv["parent_hash"], "aug_method": adv["aug_method"],
                                       "label": adv["label"], "score": score(adv["text"])})}
    info = {"model": "char TF-IDF (2-4, char_wb) + LR, class_weight balanced (baseline.py settings), refit on splits-v2 train",
            "threshold_suspicious": t_susp, "threshold_likely": t_likely, "test_scored_utc": now(), "device": "cpu",
            "git_head": git_head(), "data_sha256": files, "model_file": str(BASELINE_FILE.relative_to(ROOT))}
    write_once(out, preds, info)
    return read_cached(out)


# ---------------------------------------------------------------------------------------------------------------- fine-tuned bundle
def verify_bundle(run, args, files):
    meta = json.loads((run / "shield_meta.json").read_text(encoding="utf-8"))
    st = meta["settings"]
    checks = [
        ("split_map SHA-256 = splits-v2 = local file", meta["split_map_sha256"] == SPLIT_MAP_SHA256 == files["split_map.csv"]),
        ("messages.csv SHA-256 = local file", meta["data_sha256"]["messages.csv"] == files["messages.csv"]),
        ("textprep marker = this textprep", meta["textprep"] == {"url_token": URL_TOKEN, "max_chars": MAX_CHARS}),
        ("not a smoke / --limit run", not st["smoke"] and st["limit"] is None),
        ("not a leave-one-source-out fold (src/eval_loso.py reads those)", not meta.get("loso")),
        ("git tree clean at training", meta["git_dirty"] is False),
        ("test not scored during training", not st.get("score_held_out")),
        ("model/ present", (run / "model" / "model.safetensors").exists()),
    ]
    if args.expect_commit:
        checks.append((f"git commit {args.expect_commit}", meta["git_commit"].startswith(args.expect_commit)))
    if args.expect_max_len:
        checks.append((f"max_len {args.expect_max_len}", st["max_len"] == args.expect_max_len))
    if args.expect_aug:
        checks.append((f"aug {args.expect_aug}", st["aug"] == (args.expect_aug == "yes")))
    for name, ok in checks:
        print(f"  [{'ok' if ok else 'FAIL'}] {name}")
    assert all(ok for _, ok in checks), "bundle check failed; nothing scored"
    return meta, checks


def load_encoder(run):
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(run / "model")
    model = AutoModelForSequenceClassification.from_pretrained(run / "model").eval()
    return torch, tok, model


def encoder_scores(torch, tok, model, texts, max_len, device, batch=32):
    """P(scam) for each text (fp32), in input order; batches are length-sorted for speed."""
    model.to(device)
    X = [model_text(t) for t in texts]
    order = np.argsort([len(x) for x in X])
    out = np.zeros(len(X))
    with torch.no_grad():
        for i in range(0, len(X), batch):
            idx = order[i:i + batch]
            enc = tok([X[j] for j in idx], truncation=True, max_length=max_len, padding=True, return_tensors="pt").to(device)
            out[idx] = torch.softmax(model(**enc).logits.float(), dim=-1)[:, 1].cpu().numpy()
    return out


def encoder_preds(run, meta, df, adv, files):
    out = PREDS / run.name
    if (out / "scored.json").exists():
        return read_cached(out)
    torch, tok, model = load_encoder(run)
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    max_len = meta["settings"]["max_len"]
    va, te = df[df["split"] == "val"], df[df["split"] == "test"]

    # reproduce val first: the bundle's own val predictions (T4, fp16) vs this Mac (fp32). A gap means a wrong model or textprep.
    kaggle = pd.read_csv(run / "predictions_val.csv").set_index("text_hash")["score"]
    s_va = encoder_scores(torch, tok, model, va["text"], max_len, device)
    diff = np.abs(s_va - kaggle.loc[va["text_hash"]].to_numpy())
    y_va = va["label"].to_numpy()
    lo, hi = meta["threshold_suspicious"], meta["threshold_likely"]
    flips = int(((s_va >= hi) != (kaggle.loc[va["text_hash"]].to_numpy() >= hi)).sum())
    print(f"val re-scored on {device}: max |diff| {diff.max():.5f}, mean {diff.mean():.6f}, {flips} level flips at likely; "
          f"F1@likely {f1_score(y_va, s_va >= hi):.4f} (bundle {meta['val_overall']['f1_at_likely']})")
    assert diff.max() < 0.02, "Mac val scores don't reproduce the bundle's; test NOT opened"

    print(f"opening test for {run.name} (scored once, cached)")
    n_tok = lambda texts: [len(ids) for ids in tok([model_text(t) for t in texts], truncation=False)["input_ids"]]
    preds = {"val": pd.DataFrame({"text_hash": va["text_hash"], "label": y_va, "score": kaggle.loc[va["text_hash"]].to_numpy(), "score_mac": s_va}),
             "test": pd.DataFrame({"text_hash": te["text_hash"], "label": te["label"], "n_tokens": n_tok(te["text"]),
                                   "score": encoder_scores(torch, tok, model, te["text"], max_len, device)}),
             "adv_test": pd.DataFrame({"adv_row": adv["adv_row"], "parent_hash": adv["parent_hash"], "aug_method": adv["aug_method"],
                                       "label": adv["label"], "score": encoder_scores(torch, tok, model, adv["text"], max_len, device)})}
    import transformers
    info = {"model": f"{meta['model_name']} fine-tuned ({run.name})", "threshold_suspicious": lo, "threshold_likely": hi,
            "test_scored_utc": now(), "device": f"{device} fp32 ({platform.machine()})", "git_head": git_head(), "data_sha256": files,
            "val_reproduction": {"max_abs_diff": float(diff.max()), "mean_abs_diff": float(diff.mean()), "flips_at_likely": flips,
                                 "f1_at_likely_mac": float(f1_score(y_va, s_va >= hi))},
            "versions": {"torch": torch.__version__, "transformers": transformers.__version__},
            "note": "val 'score' = the bundle's predictions_val.csv (the scores the cut-offs were chosen on); 'score_mac' = this Mac's re-score"}
    write_once(out, preds, info)
    return read_cached(out)


# ---------------------------------------------------------------------------------------------------------------- speed
def timed(fn, items):
    for x in items[:SPEED_WARMUP]:
        fn(x)
    ms = []
    for x in items:
        t0 = time.perf_counter()
        fn(x)
        ms.append((time.perf_counter() - t0) * 1000)
    return {"median_ms": round(float(np.median(ms)), 2), "p95_ms": round(float(np.percentile(ms, 95)), 2), "n": len(ms)}


def speed(run, meta, df, retime):
    """Batch size 1, per message, on SPEED_N val messages (stratified, seed 0); never test rows. Includes model_text and tokenising."""
    path = PREDS / run.name / "speed.json"
    if path.exists() and not retime:
        return json.loads(path.read_text(encoding="utf-8"))
    va = df[df["split"] == "val"]
    texts = va.groupby("label", group_keys=False).sample(frac=SPEED_N / len(va), random_state=0)["text"].tolist()
    b = joblib.load(BASELINE_FILE)
    res = {"measured_utc": now(), "machine": f"{platform.machine()} {platform.mac_ver()[0]}", "n_messages": len(texts),
           "baseline_cpu": timed(lambda t: b["model"].predict_proba(b["vectorizer"].transform([model_text(t)]))[:, 1], texts)}
    torch, tok, model = load_encoder(run)
    res["torch_threads"] = torch.get_num_threads()
    max_len = meta["settings"]["max_len"]
    def one(dev):
        def f(t):
            with torch.no_grad():
                enc = tok([model_text(t)], truncation=True, max_length=max_len, return_tensors="pt").to(dev)
                p = torch.softmax(model(**enc).logits, dim=-1)[0, 1].item()   # .item() waits for the device
            return p
        return f
    model.to("cpu")
    res["encoder_cpu"] = timed(one("cpu"), texts)
    if torch.backends.mps.is_available():
        model.to("mps")
        res["encoder_mps"] = timed(one("mps"), texts)
    path.write_text(json.dumps(res, indent=2), encoding="utf-8")
    return res


# ---------------------------------------------------------------------------------------------------------------- metrics
def metrics(y, s, lo, hi):
    y, s = np.asarray(y).astype(int), np.asarray(s)
    pos, neg = y == 1, y == 0
    r = {"n": len(y), "scam": int(pos.sum())}
    if pos.any():
        r.update(f1=f1_score(y, s >= hi, zero_division=0), precision=precision_score(y, s >= hi, zero_division=0),
                 recall=(s[pos] >= hi).mean(), recall_susp=(s[pos] >= lo).mean())
    if neg.any():
        r.update(fp=int((s[neg] >= hi).sum()), fpr=(s[neg] >= hi).mean(), fp_susp=int((s[neg] >= lo).sum()), fpr_susp=(s[neg] >= lo).mean())
    if pos.any() and neg.any():
        r["auroc"] = roc_auc_score(y, s)
    return r


def f(x, nd=3):
    return "" if x is None or (isinstance(x, float) and np.isnan(x)) else (f"{x:.{nd}f}" if isinstance(x, float) else str(x))


def table(header, rows):
    return "\n".join(["| " + " | ".join(header) + " |", "|" + "---|" * len(header)] + ["| " + " | ".join(map(str, r)) + " |" for r in rows])


def side_by_side(groups, B, M, cb, cm):
    """rows of (label, n, scam, then baseline | model pairs for F1, precision, recall, recall@susp, FPR, AUROC)."""
    rows = []
    for name, idx in groups:
        b, m = metrics(B.loc[idx, "label"], B.loc[idx, "score"], *cb), metrics(M.loc[idx, "label"], M.loc[idx, "score"], *cm)
        cell = lambda k: f"{f(b.get(k))} / {f(m.get(k))}" if (k in b or k in m) else "–"
        rows.append([name, b["n"], b["scam"], cell("f1"), cell("precision"), cell("recall"), cell("recall_susp"), cell("fpr"), cell("auroc")])
    return table(["slice", "n", "scam", "F1", "precision", "recall", "recall @ suspicious", "benign FPR", "AUROC"], rows)


def brier(y, s):
    return float(np.mean((np.asarray(s) - np.asarray(y)) ** 2))


def logit(p, eps=1e-6):
    p = np.clip(np.asarray(p, dtype=float), eps, 1 - eps)
    return np.log(p / (1 - p))


def platt(val, test):
    """a*logit(s)+b fit on val (unregularised), applied to test: the calibration a later step could use; nothing is chosen on test."""
    lr = LogisticRegression(C=1e6, max_iter=1000).fit(logit(val["score"]).reshape(-1, 1), val["label"])
    return lr.predict_proba(logit(test["score"]).reshape(-1, 1))[:, 1], float(lr.coef_[0, 0]), float(lr.intercept_[0])


def meter_now(p, lo, hi):
    """src/shield/core/risk.py curve(): linear through (0,0), (lo,30), (hi,70), (1,100)."""
    p = np.clip(np.asarray(p, dtype=float), 0, 1)
    return np.where(p <= lo, 30 * p / lo, np.where(p <= hi, 30 + 40 * (p - lo) / (hi - lo), 70 + 30 * (p - hi) / (1 - hi)))


def meter_logit(p, lo, hi, a, z):
    """Proposal: the same anchors (lo -> 30, hi -> 70), interpolated on the logit scale, end points at logit a -> 0 and z -> 100."""
    x = np.clip(logit(p), a, z)
    la, lh = logit(lo), logit(hi)
    return np.where(x <= la, 30 * (x - a) / (la - a), np.where(x <= lh, 30 + 40 * (x - la) / (lh - la), 70 + 30 * (x - lh) / (z - lh)))


METER_BINS = [0, 10, 30, 50, 70, 90, 100.01]
METER_LABELS = ["0-9", "10-29", "30-49", "50-69", "70-89", "90-100"]


def meter_hist(v):
    c = pd.Series(pd.cut(np.floor(np.asarray(v) + 0.5), METER_BINS, right=False, labels=METER_LABELS)).value_counts(normalize=True).reindex(METER_LABELS)
    return [f"{x:.1%}" for x in c]


def esc(t, n=300):
    t = re.sub(r"\s+", " ", str(t)).strip()
    return (t[:n] + (" …" if len(t) > n else "")).replace("|", "\\|")


# ---------------------------------------------------------------------------------------------------------------- report
def report(path, run, meta, checks, df, adv_df, PB, IB, PM, IM, spd, notes):
    cb = (IB["threshold_suspicious"], IB["threshold_likely"])
    cm = (IM["threshold_suspicious"], IM["threshold_likely"])
    te = df[df["split"] == "test"].set_index("text_hash")
    B = PB["test"].set_index("text_hash").loc[te.index]
    M = PM["test"].set_index("text_hash").loc[te.index]
    assert (B["label"] == te["label"]).all() and (M["label"] == te["label"]).all() and len(te) == len(B) == len(M)
    name = run.name
    L = []
    w = L.append
    old = path.read_text(encoding="utf-8") if path.exists() else ""
    hand = old[old.index(HAND[0]): old.index(HAND[1]) + len(HAND[1])] if HAND[0] in old and HAND[1] in old else \
        f"{HAND[0]}\n\n_(summary and reading: not written yet)_\n\n{HAND[1]}"

    w(f"# Text head evaluation: `{name}` vs the splits-v2 TF-IDF baseline\n")
    w(f"Generated by `src/eval_text_head.py` from the saved prediction files in `reports/eval_preds/` (regenerating reads them, never re-scores). "
      f"Internal test split of splits-v2 (n={len(te):,}), **not** the final real-message test set. Each model uses its **own val-chosen cut-offs** "
      f"(likely = val max-F1; suspicious = highest with val scam recall >= 0.95). Nothing below was tuned on test. Cells read **baseline / {meta['short_name']}**.\n")
    w("## Test opened\n")
    w(table(["model", "test scored (first and only time)", "device", "repo HEAD then", "cut-offs suspicious / likely", "prediction files"], [
        [f"baseline (`{BASELINE_KEY}`)", IB["test_scored_utc"], IB["device"], IB["git_head"], f"{cb[0]:.3f} / {cb[1]:.3f}", f"`reports/eval_preds/{BASELINE_KEY}/`"],
        [f"`{name}`", IM["test_scored_utc"], IM["device"], IM["git_head"], f"{cm[0]:.3f} / {cm[1]:.3f}", f"`reports/eval_preds/{name}/`"]]))
    w(f"\nThe baseline's test split had been scored once before, at the splits-v2 rebuild (`reports/splits_v2.md`: test F1 0.900, same fit, same data); "
      f"this evaluation refits it deterministically and reads its own cached file. SHA-256 of every prediction file is in each folder's `scored.json`, "
      f"checked on every regeneration.\n")
    w(hand + "\n")

    w("## 1. Model checks\n")
    st = meta["settings"]
    w(f"Bundle `models/finetune/{name}/` (weights git-ignored): `{meta['model_name']}`, commit `{meta['git_commit'][:7]}`, max_len {st['max_len']}, "
      f"aug {st['aug']}, best epoch {meta['best_epoch']} of {st['epochs']}, trained on {meta['device']} ({meta['precision']}), "
      f"transformers {meta['versions']['transformers']} / torch {meta['versions']['torch']}.\n")
    w("\n".join(f"- {'ok' if ok else 'FAIL'}: {c}" for c, ok in checks))
    vr = IM["val_reproduction"]
    w(f"- val re-scored on this Mac ({IM['device']}, transformers {IM['versions']['transformers']}) before test was opened: max |score diff| "
      f"{vr['max_abs_diff']:.5f}, mean {vr['mean_abs_diff']:.6f} vs the bundle's T4 fp16 scores; {vr['flips_at_likely']} val rows change side of the likely "
      f"cut-off; val F1 at likely {vr['f1_at_likely_mac']:.4f} (bundle {meta['val_overall']['f1_at_likely']}). Test is scored on the Mac (fp32).\n")
    bv, mv = PB["val"], PM["val"]
    w(f"Val (where the cut-offs come from), at each model's likely cut-off: baseline F1 {f1_score(bv['label'], bv['score'] >= cb[1]):.3f} "
      f"(at 0.5: {f1_score(bv['label'], bv['score'] >= 0.5):.3f}, the number in splits_v2.md), {meta['short_name']} {f1_score(mv['label'], mv['score'] >= cm[1]):.3f}.\n")

    w("## 2. Overall test\n")
    real = te.index[~te["is_synthetic"].astype(bool)]
    w(side_by_side([("all test", te.index), ("real-only (is_synthetic = False)", real)], B, M, cb, cm))
    w(f"\nAt 0.5 instead of the val cut-offs: F1 {f1_score(B['label'], B['score'] >= 0.5):.3f} / {f1_score(M['label'], M['score'] >= 0.5):.3f}. "
      "`recall @ suspicious` = share of scams at least Suspicious; `benign FPR` = share of benign rows at Likely scam.\n")

    w("## 3. Per source\n")
    w("`synthetic` marks sources whose test rows are all synthetic. `cut at N` = share of test inputs longer than the fine-tuned model's token limit "
      "(it reads only the first N tokens of those).\n")
    rows_src = []
    for src, g in te.groupby("source"):
        syn = g["is_synthetic"].astype(bool)
        tag = " (synthetic)" if syn.all() else (f" ({syn.mean():.0%} synthetic)" if syn.any() else "")
        rows_src.append((f"{src}{tag}", g.index))
    w(side_by_side(rows_src, B, M, cb, cm))
    cut = (M["n_tokens"] > st["max_len"]).groupby(te["source"]).mean()
    w(f"\ncut at {st['max_len']} tokens: " + ", ".join(f"{k} {v:.0%}" for k, v in cut.items()) + "\n")

    w("## 4. Per language\n")
    w("**Hindi and Kannada test rows are all `synth_india` templates (synthetic; the real-looking Hindi / Kannada data are machine translations "
      "in train only), and val has none, so no cut-off saw either language.** Hinglish test mixes real benign chat (`cmu_hinglish_dog`) "
      "with synthetic chat and synth_india templates.\n")
    w(side_by_side([(l, te.index[te["language"] == l]) for l in LANGS], B, M, cb, cm))

    w("\n### False alarms on benign Hinglish\n")
    w("F1 is not meaningful here (the real Hinglish rows are all benign). Count and rate of benign Hinglish rows flagged, by source:\n")
    hb = te[(te["language"] == "hinglish") & (te["label"] == 0)]
    rows = []
    for name_, idx in [("all benign Hinglish", hb.index)] + [(f"{s}{' (synthetic)' if g['is_synthetic'].astype(bool).all() else ''}", g.index) for s, g in hb.groupby("source")]:
        rr = []
        for P, c in ((B, cb), (M, cm)):
            s = P.loc[idx, "score"]
            rr += [f"{int((s >= c[1]).sum())} ({(s >= c[1]).mean():.1%})", f"{int((s >= c[0]).sum())} ({(s >= c[0]).mean():.1%})"]
        rows.append([name_, len(idx), f"{rr[0]} / {rr[2]}", f"{rr[1]} / {rr[3]}"])
    w(table(["benign Hinglish", "n", "Likely scam: baseline / model", "at least Suspicious: baseline / model"], rows))

    w("\n## 5. Adversarial test (`messages_adv_test.csv`, held-out attacks on test scam parents)\n")
    w("Recall per attack type at each model's own cut-offs; `clean parent` = recall on the unattacked parents of the same variants. "
      "`url_obfuscate` is neutralised by `textprep.model_text` (defanged links become `<URL>`), so it does not measure robustness.\n")
    AB, AM = PB["adv_test"].set_index("adv_row").loc[adv_df["adv_row"]], PM["adv_test"].set_index("adv_row").loc[adv_df["adv_row"]]
    assert (AB["parent_hash"].to_numpy() == adv_df["parent_hash"].to_numpy()).all() and (AM["parent_hash"].to_numpy() == adv_df["parent_hash"].to_numpy()).all()
    rows = []
    for scope, a in (("all parents", adv_df), ("real parents", adv_df[~adv_df["parent_is_synthetic"].astype(bool)])):
        for meth, g in list(a.groupby("aug_method")) + [("all attacks", a)]:
            par = g["parent_hash"]
            cells = []
            for A, P, c in ((AB, B, cb), (AM, M, cm)):
                cells.append(((A.loc[g["adv_row"], "score"] >= c[1]).mean(), (A.loc[g["adv_row"], "score"] >= c[0]).mean(),
                              (P.loc[par, "score"] >= c[1]).mean()))
            rows.append([scope, meth, len(g), g["parent_hash"].nunique(), f"{f(cells[0][0])} / {f(cells[1][0])}",
                         f"{f(cells[0][1])} / {f(cells[1][1])}", f"{f(cells[0][2])} / {f(cells[1][2])}"])
    w(table(["parents", "attack", "variants", "parents n", "recall (Likely)", "recall (at least Suspicious)", "clean parent recall (Likely)"], rows))

    w("\n## 6. Calibration and score shape (test)\n")
    w("Reliability: 10 equal-width score bins; `scam rate` is the observed share of scams in the bin. Both models are trained with class-weighted "
      "loss (scam share in train 25%, weighted to 50/50), so both should over-state P(scam). Platt = `a*logit(score)+b` fit on **val**, applied to test.\n")
    rows = []
    edges = np.linspace(0, 1, 11)
    for i in range(10):
        r = [f"[{edges[i]:.1f}, {edges[i + 1]:.1f}{']' if i == 9 else ')'}"]
        for P in (B, M):
            sel = (P["score"] >= edges[i]) & ((P["score"] < edges[i + 1]) if i < 9 else (P["score"] <= 1))
            r += [int(sel.sum()), f(P.loc[sel, "score"].mean()) if sel.any() else "–", f(P.loc[sel, "label"].mean()) if sel.any() else "–"]
        rows.append(r)
    w(table(["score bin", "baseline n", "baseline mean score", "baseline scam rate", "model n", "model mean score", "model scam rate"], rows))
    rows = []
    for nm, P, V in (("baseline", B, PB["val"]), (meta["short_name"], M, PM["val"])):
        cal, a, b_ = platt(V, P.reset_index())
        ece = sum(abs(P.loc[sel, "score"].mean() - P.loc[sel, "label"].mean()) * sel.mean()
                  for sel in [(P["score"] >= edges[i]) & ((P["score"] < edges[i + 1]) if i < 9 else True) for i in range(10)] if sel.any())
        rows.append([nm, f(brier(P["label"], P["score"]), 4), f(ece, 4), f(brier(P["label"].to_numpy(), cal), 4), f"{a:.2f} / {b_:.2f}"])
    w("\n" + table(["model", "Brier (raw)", "ECE (10 bins)", "Brier after Platt (fit on val)", "Platt a / b"], rows))
    w(f"\nBrier of always predicting the test scam rate ({te['label'].mean():.3f}): {brier(te['label'], np.full(len(te), te['label'].mean())):.4f}.\n")
    w("Score shape on test (share of rows):\n")
    sb = [0, 0.01, 0.05, 0.2, 0.5, 0.8, 0.95, 0.99, 1.0001]
    lab = ["< 0.01", "0.01-0.05", "0.05-0.2", "0.2-0.5", "0.5-0.8", "0.8-0.95", "0.95-0.99", ">= 0.99"]
    w(table(["model"] + lab, [[nm] + [f"{x:.1%}" for x in pd.cut(P["score"], sb, right=False, labels=lab).value_counts(normalize=True).reindex(lab)]
                               for nm, P in (("baseline", B), (meta["short_name"], M))]))

    w("\n### Risk meter (D24): how the 0-100 scale would map onto these scores (proposal, not applied)\n")
    vm = PM["val"]
    a_, z_ = np.percentile(logit(vm["score"]), [1, 99])
    w(f"Today `risk.py` maps the score linearly through (0 -> 0, suspicious cut-off -> 30, likely cut-off -> 70, 1 -> 100). With {meta['short_name']}'s "
      f"cut-offs ({cm[0]:.3f} / {cm[1]:.3f}) the bands keep their meaning (the cut-offs still land on 30 / 70), but inside each band the number "
      f"is driven by a few hundredths of probability. The proposal keeps the same anchors and interpolates on the **logit** scale, with the ends at the "
      f"1st / 99th percentile of the model's **val** logits ({a_:.2f} -> 0, {z_:.2f} -> 100; p = {1 / (1 + np.exp(-a_)):.5f} / {1 / (1 + np.exp(-z_)):.5f}). "
      "Everything here is fit and shown on **val**; levels are unchanged by construction (only the number inside a band moves).\n")
    ps = [0.0005, 0.002, 0.01, cm[0], 0.1, 0.2, cm[1], 0.7, 0.9, 0.99, 0.999]
    w(table(["model score p"] + [f"{p:.4g}" for p in ps], [
        ["meter today (linear)"] + [f"{float(meter_now(p, *cm)):.0f}" for p in ps],
        ["meter proposed (logit)"] + [f"{float(meter_logit(p, *cm, a_, z_)):.0f}" for p in ps]]))
    w("\nShare of val messages per meter range (before the clamp into the final level's band):\n")
    vb = PB["val"]
    w(table(["mapping"] + METER_LABELS, [
        ["baseline, linear (today)"] + meter_hist(meter_now(vb["score"], *cb)),
        [f"{meta['short_name']}, linear (today's curve)"] + meter_hist(meter_now(vm["score"], *cm)),
        [f"{meta['short_name']}, logit (proposed)"] + meter_hist(meter_logit(vm["score"], *cm, a_, z_))]))

    w("\n## 7. Speed (batch size 1, this Mac)\n")
    w(f"{spd['n_messages']} val messages (stratified, never test), {SPEED_WARMUP} warm-up calls first; time includes `model_text` and tokenising, "
      f"not loading. Machine: {spd['machine']}, torch threads {spd['torch_threads']}; measured {spd['measured_utc']}.\n")
    rows = [["baseline (TF-IDF + LR)", "CPU", spd["baseline_cpu"]["median_ms"], spd["baseline_cpu"]["p95_ms"]],
            [meta["short_name"], "CPU (fp32)", spd["encoder_cpu"]["median_ms"], spd["encoder_cpu"]["p95_ms"]]]
    if "encoder_mps" in spd:
        rows.append([meta["short_name"], "GPU (MPS, fp32)", spd["encoder_mps"]["median_ms"], spd["encoder_mps"]["p95_ms"]])
    w(table(["model", "device", "median ms / message", "p95 ms / message"], rows))
    w(f"\nModel size on disk: {meta['short_name']} {(run / 'model' / 'model.safetensors').stat().st_size / 1e6:.0f} MB; baseline "
      f"{BASELINE_FILE.stat().st_size / 1e6:.0f} MB.\n")

    w("## 8. The 20 worst {} errors on test\n".format(meta["short_name"]))
    miss, fa = M[(M["label"] == 1) & (M["score"] < cm[1])], M[(M["label"] == 0) & (M["score"] >= cm[1])]
    w(f"At the likely cut-off {meta['short_name']} misses {len(miss)} test scams (" + ", ".join(f"{k} {v}" for k, v in te.loc[miss.index, "source"].value_counts().items())
      + f") and raises {len(fa)} false alarms (" + ", ".join(f"{k} {v}" for k, v in te.loc[fa.index, "source"].value_counts().items()) + "). "
      "The literal worst rows are ties from a few templates (the same company's job posts, one synth_india template in several languages), so each "
      "table keeps the **worst row per group** (synth_india `template_family`, else near-duplicate `cluster_id`); `group rows` = how many of that "
      "group's test rows make the same error. Masked text (`messages.csv`), whitespace collapsed, first 300 characters. `why` is a guess from "
      "reading the text, not a measured cause.\n")
    grp = te["template_family"].fillna("").astype(str).where(te["template_family"].notna(), "c:" + te["cluster_id"].astype(str))
    for title, err, asc in (("10 missed scams (lowest score among scams)", miss, True), ("10 false alarms (highest score among benign)", fa, False)):
        e = err.assign(_g=grp.loc[err.index]).sort_values("score", ascending=asc)
        size = e["_g"].value_counts()
        rows = []
        for i, (h, r) in enumerate(e.drop_duplicates("_g").head(10).iterrows(), 1):
            t = te.loc[h]
            rows.append([i, f"`{h[:8]}`", t["source"] + (" (syn)" if bool(t["is_synthetic"]) else ""), t["language"], f(r["score"], 4),
                         f(B.loc[h, "score"], 4), size[r["_g"]], esc(t["text"]), esc(notes.get(h, "(not reviewed)"), 400)])
        w(f"### {title}\n")
        w(table(["#", "hash", "source", "language", "model", "baseline", "group rows", "text", "why (guess)"], rows) + "\n")

    w("## 9. Leave-one-source-out\n")
    w(section9_body(df, shipped=run.name == "muril_len128_20261021T135255Z"))   # src/eval_loso.py: the cached MuRIL folds, or the "runs pending" text with the baseline's LOSO

    path.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"wrote {path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run", help="fine-tuned bundle folder (models/finetune/<run>)")
    ap.add_argument("--report", required=True, help="markdown report to (re)write, e.g. reports/eval_muril_v2.md")
    ap.add_argument("--notes", help="CSV text_hash,why for the worst-errors tables")
    ap.add_argument("--expect-commit"), ap.add_argument("--expect-max-len", type=int), ap.add_argument("--expect-aug", choices=["yes", "no"])
    ap.add_argument("--retime", action="store_true", help="measure speed again (otherwise speed.json is reused)")
    args = ap.parse_args()
    run = Path(args.run).resolve()
    df, adv, files = load_data()
    print(f"bundle {run.name}:")
    meta, checks = verify_bundle(run, args, files)
    PB, IB = baseline_preds(df, adv, files)
    PM, IM = encoder_preds(run, meta, df, adv, files)
    spd = speed(run, meta, df, args.retime)
    notes = pd.read_csv(args.notes).set_index("text_hash")["why"].to_dict() if args.notes and Path(args.notes).exists() else {}
    report(Path(args.report), run, meta, checks, df, adv, PB, IB, PM, IM, spd, notes)


if __name__ == "__main__":
    main()
