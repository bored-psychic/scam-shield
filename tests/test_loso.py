import json, os, shutil, string, subprocess, sys, tempfile
from argparse import Namespace
from pathlib import Path

HERE = Path(os.path.abspath(globals().get("__file__", "tests/test_loso.py"))).parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "src")]
PY = sys.executable

import numpy as np, pandas as pd
import eval_loso
import finetune
from textprep import MAX_CHARS, URL_TOKEN

# python tests/test_loso.py   (from the project root). Leave-one-source-out folds of the MuRIL text head (finetune.py --exclude-source, eval_loso.py).
# Everything runs on the real splits-v2 files in data/final/ but never on the real-message test set, and none of it needs a GPU.
#   L1  the data path of a fold (load_data + split_loso, the code main() runs) for all four folds, rule cluster-strict: 0 train / val rows share a cluster_id with any row of
#       the source (recomputed here from messages.csv, not by finetune's own helper), the held-out rows are exactly the source's val + test rows (1,032 / 660 / 428 / 821),
#       the translations dropped are 6 / 84 / 70 / 0, every row is accounted for; the checker itself fails on a translation of a near-twin parent left in train
#   L2  finetune.LOSO_REFERENCE and LOSO_REFERENCE_PRECISION equal the shipped bundle's shield_meta.json (checked whenever the bundle is on disk)
#   L3  refusals, before anything is created: --score-held-out, --aug, any other setting, an unknown source, a source with one class, --no-save-model alone
#   L4  a CPU dry run (--smoke --limit 40 --no-save-model, MuRIL from the local Hugging Face cache; skipped without it): writes predictions_loso.csv holding
#       only source rows, no model/ and no epoch_*/, shield_meta.json with loso: true / loso_rule / exclude_source / non-zero drop counts, and refuses nothing it should not
#   L5  the app (MurilScorer) refuses a bundle with loso: true, and says why
#   L6  eval_loso on invented folds (random scores): the checks pass on a good fold and fail on a changed setting, an extra row, a missing row, a wrong label, a missing
#       loso_rule, a precision other than fp16 (unless --allow-precision-mismatch); the cache is written once and a different prediction file is refused; section 9 is
#       rendered from the cache, replaced in place in a copy of the report (everything above it byte for byte, the hand-written block kept), and a report whose
#       section 9 is not last is refused; the textprep-drift sentence follows the drift file
#   L7  the best epoch is restored with --no-save-model: a 2-epoch CPU run of a tiny invented model on the real fold data, with epoch 2 wrecked by a huge learning rate,
#       must pick epoch 1 and the restored model's val AUROC must equal epoch 1's logged value (and differ from epoch 2's)
#   L8  src/textprep_drift.py sees a change that is there (a UPI id after a dotted name, 06f402e read it as a link) and none that is not; the committed drift file
#       covers the four sources
#   L9  the committed baseline folds (src/loso_baseline.py, cluster-strict) verify against messages.csv, and a tampered copy is refused
FOLDS = ["uci_sms_spam", "india_fraud_final", "scam_ham_india", "synth_india"]
EXPECTED = {"uci_sms_spam": (1032, 6), "india_fraud_final": (660, 84), "scam_ham_india": (428, 70), "synth_india": (821, 0)}   # scored rows, translations dropped
BUNDLE = ROOT / "models/finetune/muril_len128_20261021T135255Z"
DATA = ROOT / "data/final"
_C = {}


def messages():
    if "df" not in _C:
        _C["df"], _C["sha"] = eval_loso.load_messages()
    return _C["df"], _C["sha"]


def l1(tmp):
    bad = []
    df, _ = messages()
    cid = df["cluster_id"].astype(str)
    for src in FOLDS:
        got, aug, adv, files, test_hashes = finetune.load_data(DATA, False, False, src)
        te_src = set(got.loc[got["split"] == "test", "source"])
        if te_src != {src}:
            bad.append(f"{src}: load_data kept test rows of {te_src}")
        tr, va, hv, ht, c = finetune.split_loso(got, src)
        # the cluster rule, recomputed from messages.csv: no train / val row shares a cluster_id with any row of the source
        clusters = set(cid[df["source"] == src])
        for name, d in (("train", tr), ("val", va)):
            n = int(d["cluster_id"].astype(str).isin(clusters).sum())
            print(f"      {src}: {name} rows sharing a cluster_id with an {src} row: {n}")
            if n or (d["source"] == src).any():
                bad.append(f"{src}: {name} still holds {n} rows that share a cluster with the source (or source rows)")
        should_be_out = df[cid.isin(clusters) & df["split"].isin(["train", "val"])]
        if set(should_be_out["text_hash"]) & (set(tr["text_hash"]) | set(va["text_hash"])):
            bad.append(f"{src}: a train / val row in a source cluster was kept")
        if len(ht) != int(((df["source"] == src) & (df["split"] == "test")).sum()) or set(ht["text_hash"]) - test_hashes:
            bad.append(f"{src}: the held-out test rows are not the source's test rows")
        if set(hv["text_hash"]) & test_hashes or not set(hv["split"]) <= {"val"}:
            bad.append(f"{src}: held-out val rows are not the source's val rows")
        if (len(hv) + len(ht), c["translations"]) != EXPECTED[src]:
            bad.append(f"{src}: scored rows / translations dropped {(len(hv) + len(ht), c['translations'])}, expected {EXPECTED[src]}")
        full_tr, full_va = (int((df["split"] == s).sum()) for s in ("train", "val"))
        o = c["other_sources"]
        if len(tr) + c["train"] + c["translations"] + sum(o["train"].values()) != full_tr or len(va) + c["val"] + sum(o["val"].values()) != full_va:
            bad.append(f"{src}: rows not accounted for: train {len(tr)}+{c['train']}+{c['translations']}+{sum(o['train'].values())} vs {full_tr}, val {len(va)}+{c['val']}+{sum(o['val'].values())} vs {full_va}")
        if not (c["train"] > 0 and c["test"] > 0):
            bad.append(f"{src}: expected rows in train and test, got {c}")
        if src != "synth_india" and c["val"] == 0:
            bad.append(f"{src}: no val rows dropped")
        if src == "synth_india" and c["val"] != 0:
            bad.append("synth_india has val rows now; the report's note that its fold holds out test rows only is stale")
        print(f"      {src}: dropped train {c['train']}, translations {c['translations']}, other sources {o}, val {c['val']}; held out test {c['test']}; train left {len(tr)}, val left {len(va)}")
    # a non-LOSO load drops every test row, as before
    plain = finetune.load_data(DATA, False, False)[0]
    if (plain["split"] == "test").any():
        bad.append("a normal load_data kept test rows")
    # the checker must see what the old translation_of test missed: scam_ham_india's 12 translations of preview parents attached to its rows as near twins
    got = finetune.load_data(DATA, False, False, "scam_ham_india")[0]
    tr, va, hv, ht, c = finetune.split_loso(got, "scam_ham_india")
    src_rows = got[got["source"] == "scam_ham_india"]
    hashes = set(src_rows["text_hash"])
    missed = got[(got["source"] == "translated_indic") & ~got["translation_of"].isin(hashes) & got["cluster_id"].astype(str).isin(set(src_rows["cluster_id"].astype(str)))]
    if len(missed) != 12:
        bad.append(f"expected 12 translations of near-twin parents in scam_ham_india clusters, found {len(missed)}")
    elif refuses(finetune.assert_loso_clean, pd.concat([tr, missed]), va, hv, ht, "scam_ham_india", src_rows) is None:
        bad.append("assert_loso_clean accepted a train set that keeps a translation of a near-twin parent")
    other = got[(got["source"] == "uci_sms_spam") & got["cluster_id"].astype(str).isin(set(src_rows["cluster_id"].astype(str)))]
    if len(other) != 1 or refuses(finetune.assert_loso_clean, pd.concat([tr, other]), va, hv, ht, "scam_ham_india", src_rows) is None:
        bad.append("assert_loso_clean accepted a train set that keeps another source's near copy")
    return bad


def l2(tmp):
    if not BUNDLE.exists():
        print("      shipped bundle not on disk: skipped")
        return []
    st = json.loads((BUNDLE / "shield_meta.json").read_text(encoding="utf-8"))["settings"]
    ref = {k: v for k, v in finetune.LOSO_REFERENCE.items() if k != "model"}
    bad = [f"LOSO_REFERENCE {k}={v!r}, bundle {st.get(k)!r}" for k, v in ref.items() if st.get(k) != v]
    prec = json.loads((BUNDLE / "shield_meta.json").read_text(encoding="utf-8")).get("precision")
    if prec != finetune.LOSO_REFERENCE_PRECISION:
        bad.append(f"LOSO_REFERENCE_PRECISION {finetune.LOSO_REFERENCE_PRECISION!r}, bundle {prec!r}")
    return bad


def args(**kw):
    base = dict(model="muril", epochs=3, batch=16, lr=2e-5, max_len=128, seed=42, warmup=0.06, aug=False, score_held_out=False, smoke=False)
    return Namespace(**{**base, **kw})


def refuses(fn, *a):
    """The SystemExit message if fn exits, "" if it fails some other way after its checks passed (e.g. the control bundle has no weights), None if it returns."""
    try:
        fn(*a)
    except SystemExit as e:
        return str(e)
    except Exception:
        return ""
    return None


def l3(tmp):
    bad = []
    if refuses(finetune.check_loso_args, args()) is not None:
        bad.append("the shipped settings were refused")
    if refuses(finetune.check_loso_args, args(smoke=True)) is not None:
        bad.append("--smoke (1 epoch by definition) was refused")
    for what, kw in (("--score-held-out", dict(score_held_out=True)), ("--aug", dict(aug=True)), ("--max-len 256", dict(max_len=256)), ("--lr", dict(lr=3e-5)),
                     ("--batch", dict(batch=32)), ("--seed", dict(seed=1)), ("--epochs", dict(epochs=4)), ("--warmup", dict(warmup=0.1)), ("--model", dict(model="mdeberta"))):
        if not refuses(finetune.check_loso_args, args(**kw)):
            bad.append(f"{what} was not refused")
    for what, extra in (("unknown source", ["--exclude-source", "no_such_source"]), ("--score-held-out", ["--exclude-source", "uci_sms_spam", "--score-held-out"]),
                        ("one-class source", ["--exclude-source", "web_scams"]), ("no val/test rows", ["--exclude-source", "translated_indic"]),
                        ("--no-save-model alone", ["--no-save-model"])):
        out = tmp / ("refuse_" + what.replace(" ", "_").replace("/", "_").replace("-", "_"))
        r = subprocess.run([PY, str(ROOT / "src/finetune.py"), *extra, "--limit", "10", "--device", "cpu", "--out", str(out)], capture_output=True, text=True, cwd=ROOT)
        if r.returncode == 0 or out.exists():
            bad.append(f"{what}: exit {r.returncode}, out dir created: {out.exists()}")
    return bad


def l4(tmp):
    cache = Path.home() / ".cache/huggingface/hub/models--google--muril-base-cased"
    if not cache.exists():
        print("      MuRIL not in the local Hugging Face cache: skipped")
        return []
    bad = []
    df, _ = messages()
    out = tmp / "dry"
    r = subprocess.run([PY, str(ROOT / "src/finetune.py"), "--exclude-source", "uci_sms_spam", "--smoke", "--limit", "40", "--no-save-model", "--device", "cpu", "--out", str(out)],
                       capture_output=True, text=True, cwd=ROOT, env={**os.environ, "HF_HUB_OFFLINE": "1"})
    if r.returncode != 0:
        return [f"dry run failed: {(r.stdout + r.stderr)[-600:]}"]
    names = {p.name for p in out.iterdir()}
    if names & {"model"} or any(n.startswith("epoch_") for n in names):
        bad.append(f"--no-save-model wrote {sorted(names)}")
    p = pd.read_csv(out / "predictions_loso.csv")
    src = df.set_index("text_hash").loc[p["text_hash"], ["source", "split"]]
    if len(p) == 0 or set(src["source"]) != {"uci_sms_spam"} or not set(src["split"]) <= {"val", "test"}:
        bad.append(f"predictions_loso.csv is not only uci_sms_spam val/test rows: {sorted(set(src['source']))}")
    if not (out / "predictions_val.csv").exists() or (out / "predictions_test.csv").exists():
        bad.append("expected predictions_val.csv and no predictions_test.csv")
    meta = json.loads((out / "shield_meta.json").read_text(encoding="utf-8"))
    d = meta.get("loso_dropped", {})
    if not (meta.get("loso") is True and meta.get("exclude_source") == "uci_sms_spam" and meta.get("loso_rule") == finetune.LOSO_RULE and d.get("train", 0) > 0 and d.get("val", 0) > 0
            and d.get("translations") == 6 and d.get("other_sources", {}).get("train", {}).get("ealvaradob_phishing") == 191 and d["other_sources"]["val"].get("ealvaradob_phishing") == 30):
        bad.append(f"shield_meta.json loso fields: {meta.get('loso')}, {meta.get('loso_rule')}, {meta.get('exclude_source')}, {d}")
    if meta["settings"]["score_held_out"] or meta["rows"]["test"] is not None:
        bad.append("the dry run recorded a held-out test score")
    vm = pd.read_csv(out / "val_metrics.csv")
    if "uci_sms_spam" in set(vm.loc[vm["slice"] == "source", "key"]):
        bad.append("val_metrics.csv has uci_sms_spam rows: it was in val")
    print(f"      dry run: {len(p)} held-out rows scored, dropped {d}")
    return bad


def l5(tmp):
    from shield.messages.text_head import MurilScorer
    meta = {"settings": {"smoke": False, "limit": None, "max_len": 128}, "textprep": {"url_token": URL_TOKEN, "max_chars": MAX_CHARS},
            "calibration": {"fit_on": "val", "temperature": 1.0, "threshold_suspicious": 0.1, "threshold_likely": 0.4, "meter_p0": -3.0, "meter_p100": 3.0}}
    bad = []
    for loso in (True, False):
        d = tmp / f"bundle_{loso}"
        d.mkdir()
        (d / "shield_meta.json").write_text(json.dumps({**meta, **({"loso": True, "exclude_source": "uci_sms_spam"} if loso else {})}), encoding="utf-8")
        msg = refuses(MurilScorer, d, "cpu")
        if loso and not (msg and "leave-one-source-out" in msg and "uci_sms_spam" in msg):
            bad.append(f"a loso: true bundle was not refused for that reason: {msg!r}")
        if not loso and msg and "leave-one-source-out" in msg:
            bad.append("a normal bundle was refused as a fold")
    return bad


def fake_fold(tmp, src, df, sha, name=None):
    """An invented fold folder: a real fold's shape and meta, random scores correlated with the label."""
    tr, va, hv, ht, c = finetune.split_loso(df, src)
    held = pd.concat([hv, ht])
    rng = np.random.default_rng(0)
    y = held["label"].astype(int).to_numpy()
    score = np.clip(0.5 + (y - 0.5) * 0.6 + rng.normal(0, 0.25, len(y)), 0.001, 0.999)
    d = tmp / (name or f"muril_loso_{src}_20261101T000000Z")
    d.mkdir(parents=True)
    pd.DataFrame({"text_hash": held["text_hash"].to_numpy(), "split": held["split"].to_numpy(), "label": y, "score": score}).to_csv(d / "predictions_loso.csv", index=False)
    meta = {"model_name": "google/muril-base-cased", "short_name": "muril", "textprep": {"url_token": URL_TOKEN, "max_chars": MAX_CHARS},
            "split_map_sha256": finetune.SPLIT_MAP_SHA256, "data_sha256": {"messages.csv": sha}, "git_dirty": False, "loso": True, "loso_rule": finetune.LOSO_RULE, "exclude_source": src,
            "settings": {"epochs": 3, "batch": 16, "lr": 2e-5, "max_len": 128, "seed": 42, "warmup": 0.06, "weight_decay": 0.01, "grad_clip": 1.0, "optimizer": "AdamW",
                         "schedule": "linear warmup + linear decay", "aug": False, "smoke": False, "limit": None, "score_held_out": False},
            "rows": {"train": len(tr), "val": len(va)}, "loso_dropped": c, "loso_held_out_rows": {"val": len(hv), "test": len(ht)}, "best_epoch": 2,
            "threshold_likely": 0.45, "training_seconds": 1000, "precision": "fp16"}
    (d / "shield_meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (d / "train_log.txt").write_text("log\n", encoding="utf-8")
    return d, meta


def l6(tmp):
    bad = []
    df, sha = messages()
    d, meta = fake_fold(tmp / "good", "scam_ham_india", df, sha)
    preds = pd.read_csv(d / "predictions_loso.csv")
    fails = lambda m, p: [n for n, ok in eval_loso.verify_fold(m, p, df, sha) if not ok]
    if fails(meta, preds):
        bad.append(f"a good fold failed: {fails(meta, preds)}")
    other = df[(df["source"] == "uci_sms_spam") & (df["split"] == "val")].iloc[0]
    cases = {"changed lr": (json.loads(json.dumps({**meta, "settings": {**meta["settings"], "lr": 3e-5}})), preds),
             "aug on": ({**meta, "settings": {**meta["settings"], "aug": True}}, preds),
             "smoke": ({**meta, "settings": {**meta["settings"], "smoke": True}}, preds),
             "wrong split map": ({**meta, "split_map_sha256": "0" * 64}, preds),
             "wrong drop counts": ({**meta, "loso_dropped": {**meta["loso_dropped"], "translations": 999}}, preds),
             "extra row from another source": (meta, pd.concat([preds, pd.DataFrame([{"text_hash": other["text_hash"], "split": "val", "label": int(other["label"]), "score": 0.5}])])),
             "missing row": (meta, preds.iloc[1:]),
             "wrong label": (meta, preds.assign(label=[1 - preds["label"].iloc[0]] + list(preds["label"].iloc[1:]))),
             "score above 1": (meta, preds.assign(score=[1.5] + list(preds["score"].iloc[1:]))),
             "no loso_rule (the old rule)": ({k: v for k, v in meta.items() if k != "loso_rule"}, preds),
             "another rule": ({**meta, "loso_rule": "translation-of-v0"}, preds),
             "bf16": ({**meta, "precision": "bf16"}, preds),
             "no precision": ({k: v for k, v in meta.items() if k != "precision"}, preds)}
    for what, (m, p) in cases.items():
        if not fails(m, p):
            bad.append(f"verify_fold passed a fold with {what}")
    bf16 = {**meta, "precision": "bf16"}
    if [n for n, ok in eval_loso.verify_fold(bf16, preds, df, sha, allow_precision_mismatch=True) if not ok]:
        bad.append("--allow-precision-mismatch did not let a bf16 fold through")
    if not any("ALLOWED" in n for n, ok in eval_loso.verify_fold(bf16, preds, df, sha, allow_precision_mismatch=True)):
        bad.append("an allowed precision mismatch is not named in the check list")
    bf_dir, bf_meta = fake_fold(tmp / "bf", "scam_ham_india", df, sha, name="muril_loso_scam_ham_india_20261103T000000Z")
    (bf_dir / "shield_meta.json").write_text(json.dumps({**bf_meta, "precision": "bf16"}), encoding="utf-8")
    if refuses(eval_loso.update_cache, {"scam_ham_india": bf_dir}, df, sha, tmp / "bfc") is None:
        bad.append("update_cache accepted a bf16 fold without --allow-precision-mismatch")
    if (tmp / "bfc").exists():
        bad.append("a refused bf16 fold was cached")
    if refuses(eval_loso.update_cache, {"scam_ham_india": bf_dir}, df, sha, tmp / "bfc", False, True) is not None or not (tmp / "bfc/scam_ham_india/predictions_loso.csv").exists():
        bad.append("update_cache with allow_precision_mismatch did not cache the bf16 fold")

    # cache + section 9
    folds = {}
    for src in ("scam_ham_india", "uci_sms_spam"):
        folds[src] = fake_fold(tmp / "folds", src, df, sha)[0]
    cache = tmp / "cache"
    eval_loso.update_cache(folds, df, sha, cache=cache)
    if not all((cache / s / n).exists() for s in folds for n in eval_loso.CACHED):
        bad.append("cache incomplete")
    eval_loso.update_cache(folds, df, sha, cache=cache)   # the same files again: fine
    shutil.copy2(folds["uci_sms_spam"] / "predictions_loso.csv", tmp / "orig.csv")
    p = pd.read_csv(folds["uci_sms_spam"] / "predictions_loso.csv")
    p["score"] = 1 - p["score"]
    p.to_csv(folds["uci_sms_spam"] / "predictions_loso.csv", index=False)
    if refuses(eval_loso.update_cache, folds, df, sha, cache) is None:
        bad.append("a different prediction file for a cached fold was not refused")
    body = eval_loso.section9_body(df, cache=cache, messages_sha=sha)
    for src in folds:
        if f"| {src} |" not in body:
            bad.append(f"section 9 has no row for {src}")
    if "pending" in body or "Limits, same as the baseline" not in body or "A high LOSO AUROC with a low LOSO F1@0.5" not in body:
        bad.append("section 9 lacks the folds table / the plain-language paragraph")
    # an independent recomputation of one number: scam_ham_india LOSO AUROC from the cached file
    from sklearn.metrics import roc_auc_score
    cp = pd.read_csv(cache / "scam_ham_india" / "predictions_loso.csv")
    auc = f"{roc_auc_score(cp['label'], cp['score']):.3f}"
    row = [l for l in body.splitlines() if l.startswith("| scam_ham_india |") and l.count(" | ") == 19][0].split(" | ")   # the 20-column MuRIL table (not the drop / comparison / training ones)
    if auc not in row:
        bad.append(f"scam_ham_india LOSO AUROC {auc} not in its row: {row}")
    if "not measured" not in body:
        bad.append("section 9 without a drift file does not say the drift is not measured")
    (cache / "textprep_drift.json").write_text(json.dumps({"old_commit": "06f402e", "new_commit": "abc1234", "sources": {s: {"rows": 100, "changed": 0 if s != "uci_sms_spam" else 3} for s in FOLDS}}), encoding="utf-8")
    drift_body = eval_loso.section9_body(df, cache=cache, messages_sha=sha)
    if "Preprocessing drift: 3 of 400" not in drift_body:
        bad.append("section 9 does not state the textprep drift count from the drift file")
    (cache / "textprep_drift.json").write_text(json.dumps({"old_commit": "06f402e", "new_commit": "abc1234", "sources": {s: {"rows": 100, "changed": 0} for s in FOLDS}}), encoding="utf-8")
    if "the same input under the current code" not in eval_loso.section9_body(df, cache=cache, messages_sha=sha):
        bad.append("section 9 does not say the preprocessing is unchanged when the count is 0")
    prec_body = eval_loso.section9_body(df, cache=cache, messages_sha=sha)
    if f"Every fold has the shipped bundle's precision ({finetune.LOSO_REFERENCE_PRECISION})" not in prec_body:
        bad.append("section 9 does not state that the precision matches")
    pending = eval_loso.section9_body(df, cache=tmp / "nothing", messages_sha=sha)
    if "runs pending" not in pending or "| uci_sms_spam |" not in pending:
        bad.append("the pending text lacks the baseline table")
    if "Not run for this model" not in eval_loso.section9_body(df, cache=cache, shipped=False, messages_sha=sha):
        bad.append("shipped=False did not give the pointer text")

    # in-place replacement
    rep = tmp / "report.md"
    rep.write_text("# T\n\n<!-- HAND-WRITTEN START -->\nmy words\n<!-- HAND-WRITTEN END -->\n\n## 8. x\n\ntext\n\n## 9. Leave-one-source-out\n\nold\n", encoding="utf-8")
    above = rep.read_text(encoding="utf-8").split("## 9.")[0]
    eval_loso.write_section(rep, body)
    new = rep.read_text(encoding="utf-8")
    if not new.startswith(above) or "old\n" in new or "my words" not in new or new.count("## 9. Leave-one-source-out") != 1:
        bad.append("write_section did not replace section 9 in place")
    eval_loso.write_section(rep, body)
    if rep.read_text(encoding="utf-8") != new:
        bad.append("write_section is not idempotent")
    rep.write_text(new + "\n## 10. later\n\nx\n", encoding="utf-8")
    if refuses(eval_loso.write_section, rep, body) is None:
        bad.append("write_section cut a section that follows section 9")
    # duplicate fold sources
    d2 = fake_fold(tmp / "dup", "scam_ham_india", df, sha, name="muril_loso_scam_ham_india_20261102T000000Z")[0]
    if refuses(eval_loso.find_folds, [str(d), str(d2)]) is None:
        bad.append("two folds for one source were not refused")
    if eval_loso.find_folds([str(fake_fold(tmp / "sm", "synth_india", df, sha, name="muril_loso_synth_india_20261101T000000Z_smoke")[0])]):
        bad.append("a smoke fold was not skipped")
    return bad


def l7(tmp):
    """finetune.main() with a tiny invented BERT (no download), 2 epochs, the learning rate multiplied by 1e4 from epoch 2 on: epoch 2 is wrecked, so the best epoch must be 1,
    and with --no-save-model the model that scores val after training must be the one saved in memory at epoch 1."""
    import torch
    from unittest import mock
    from transformers import BertConfig, BertForSequenceClassification, BertTokenizer
    chars = sorted({c for c in string.printable if c.strip()})
    vocab = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"] + chars + ["##" + c for c in chars]
    (tmp / "vocab.txt").write_text("\n".join(vocab), encoding="utf-8")
    tok = BertTokenizer(str(tmp / "vocab.txt"), do_lower_case=False)
    cfg = BertConfig(vocab_size=len(vocab), hidden_size=32, num_hidden_layers=1, num_attention_heads=2, intermediate_size=64, max_position_embeddings=130, num_labels=2)

    def wrecking_schedule(opt, warmup_steps, total_steps):   # lr x1 in epoch 1, x1e4 after: a model that trains for one epoch and then falls apart
        return torch.optim.lr_scheduler.LambdaLR(opt, lambda step: 1.0 if step < total_steps // 2 else 1e4)

    tried = []
    for init_seed in range(6):   # the premise (epoch 2 not better than epoch 1 on val F1) depends on the invented model's init; take the first seed that has it
        torch.manual_seed(init_seed)
        model = BertForSequenceClassification(cfg)
        out = tmp / f"run{init_seed}"
        argv = ["finetune.py", "--exclude-source", "uci_sms_spam", "--no-save-model", "--epochs", "2", "--limit", "60", "--device", "cpu", "--out", str(out)]
        with mock.patch.object(sys, "argv", argv), mock.patch.dict(finetune.LOSO_REFERENCE, {"epochs": 2}), \
                mock.patch.object(finetune.AutoTokenizer, "from_pretrained", return_value=tok), \
                mock.patch.object(finetune.AutoModelForSequenceClassification, "from_pretrained", return_value=model), \
                mock.patch.object(finetune, "get_linear_schedule_with_warmup", wrecking_schedule):
            finetune.main()
        meta = json.loads((out / "shield_meta.json").read_text(encoding="utf-8"))
        h = meta["history"]
        tried.append((init_seed, meta["best_epoch"], [r["val_f1_at_0.5"] for r in h], [r["val_auroc"] for r in h]))
        if meta["best_epoch"] != 1 or h[1]["val_auroc"] == h[0]["val_auroc"]:
            continue
        print(f"      init seed {init_seed}: val F1@0.5 {[r['val_f1_at_0.5'] for r in h]}, val AUROC {[r['val_auroc'] for r in h]}, best epoch {meta['best_epoch']}, "
              f"restored model's val AUROC {meta['val_overall']['auroc']}")
        bad = []
        if meta["val_overall"]["auroc"] != h[0]["val_auroc"]:
            bad.append(f"restored val AUROC {meta['val_overall']['auroc']} != epoch 1's logged {h[0]['val_auroc']} (epoch 2's was {h[1]['val_auroc']}): the last epoch's weights were scored")
        if any(p.name == "model" or p.name.startswith("epoch_") for p in out.iterdir()):
            bad.append("--no-save-model wrote a checkpoint")
        return bad
    return [f"could not make epoch 1 the best epoch with a different epoch 2 on any of 6 init seeds: {tried}"]


def l8(tmp):
    bad = []
    import textprep_drift
    df = pd.DataFrame({"text": ["hello world, your OTP is <OTP>", "pay to rajesh.trade88@ybl now", "visit bit.ly/abc today", "invest via ravi.trade@upi account"],
                       "source": ["a", "a", "b", "b"], "split": "val"})
    got = textprep_drift.drift(df, ["a", "b"])   # the old code (06f402e) read 'rajesh.trade' and 'ravi.trade' as links; the current code does not
    if got != {"a": {"rows": 2, "changed": 1}, "b": {"rows": 2, "changed": 1}}:
        bad.append(f"textprep_drift on texts with a known change: {got}")
    if textprep_drift.drift(df.iloc[[0, 2]], ["a", "b"]) != {"a": {"rows": 1, "changed": 0}, "b": {"rows": 1, "changed": 0}}:
        bad.append("textprep_drift reported a change on texts that are the same under both versions")
    f = ROOT / "reports/eval_preds/loso_muril/textprep_drift.json"
    if not f.exists():
        return bad + [f"{f} is missing: run src/textprep_drift.py"]
    d = json.loads(f.read_text(encoding="utf-8"))
    if {s: r["rows"] for s, r in d["sources"].items()} != {s: n for s, (n, _) in EXPECTED.items()} or d["old_commit"] != "06f402e":
        bad.append(f"textprep_drift.json does not cover the four sources' val + test rows: {d}")
    return bad


def l9(tmp):
    bad = []
    df, sha = messages()
    base = eval_loso.load_baseline(df, sha)
    if set(base) != set(FOLDS):
        bad.append(f"committed baseline folds: {sorted(base)}")
    shutil.copytree(eval_loso.BASE_CACHE, tmp / "b")
    p = pd.read_csv(tmp / "b/scam_ham_india/predictions_loso.csv")
    p.iloc[1:].to_csv(tmp / "b/scam_ham_india/predictions_loso.csv", index=False)
    if refuses(eval_loso.load_baseline, df, sha, tmp / "b") is None:
        bad.append("a baseline fold with a missing row was accepted")
    shutil.copy2(eval_loso.BASE_CACHE / "scam_ham_india/predictions_loso.csv", tmp / "b/scam_ham_india/predictions_loso.csv")
    m = json.loads((tmp / "b/uci_sms_spam/meta.json").read_text(encoding="utf-8"))
    (tmp / "b/uci_sms_spam/meta.json").write_text(json.dumps({**m, "rule": "translation-of-v0"}), encoding="utf-8")
    if refuses(eval_loso.load_baseline, df, sha, tmp / "b") is None:
        bad.append("a baseline fold from another rule was accepted")
    if refuses(eval_loso.load_baseline, df, sha, tmp / "nothing") is None:
        bad.append("a missing baseline cache was accepted")
    for src, (preds, meta) in base.items():
        a = eval_loso.baseline_numbers(preds)
        if not (0.5 < a["AUROC"] <= 1 and 0 <= a["F1"] <= 1) or len(preds) != EXPECTED[src][0]:
            bad.append(f"{src}: implausible baseline numbers {a}")
    return bad


CHECKS = [("L1", "fold data path (cluster-strict): 0 train / val rows share a cluster with the source, held-out = source val + test, every row accounted for", l1),
          ("L2", "LOSO_REFERENCE (+ precision) = the shipped bundle's", l2),
          ("L3", "refusals before anything is created", l3),
          ("L4", "CPU dry run: only source rows in predictions_loso.csv, no model saved, loso fields", l4),
          ("L5", "the app refuses a loso: true bundle", l5),
          ("L6", "eval_loso: fold checks (rule, precision), cache, section 9 in place", l6),
          ("L7", "--no-save-model restores the best epoch (epoch 1 of 2, epoch 2 wrecked)", l7),
          ("L8", "textprep_drift sees a real change and none that is not; the committed drift file", l8),
          ("L9", "the committed cluster-strict baseline folds verify; tampered copies are refused", l9)]


def run():
    out = []
    with tempfile.TemporaryDirectory() as d:
        for cid, title, fn in CHECKS:
            sub = Path(d) / cid
            sub.mkdir()
            try:
                bad = fn(sub)
            except BaseException as e:   # SystemExit included: a script that stops is a failed check
                bad = [f"{type(e).__name__}: {str(e)[:400]}"]
            out.append((cid, title, bad))
    return out


def test_loso():
    bad = [f"{cid}: {b}" for cid, _, bs in run() for b in bs]
    assert not bad, "\n".join(bad)


if __name__ == "__main__":
    res = run()
    for cid, title, bad in res:
        print(("PASS" if not bad else "FAIL"), cid, title)
        for b in bad:
            print("    ", b)
    print(f"\n{sum(not b for _, _, b in res)}/{len(res)} passed")
    sys.exit(any(b for _, _, b in res))
