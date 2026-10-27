import json, os, shutil, subprocess, sys, tempfile
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
#   L1  the data path of a fold (load_data + split_loso, the code main() runs) for all four folds: 0 source rows and 0 translations of the source's parents
#       in train and val; the held-out rows are exactly the source's val + test rows; no other test row is loaded; every row of train / val is accounted for
#   L2  finetune.LOSO_REFERENCE equals the shipped bundle's shield_meta.json settings (checked whenever the bundle is on disk)
#   L3  refusals, before anything is created: --score-held-out, --aug, any other setting, an unknown source, a source with one class, --no-save-model alone
#   L4  a CPU dry run (--smoke --limit 40 --no-save-model, MuRIL from the local Hugging Face cache; skipped without it): writes predictions_loso.csv holding
#       only source rows, no model/ and no epoch_*/, shield_meta.json with loso: true / exclude_source / non-zero drop counts, and refuses nothing it should not
#   L5  the app (MurilScorer) refuses a bundle with loso: true, and says why
#   L6  eval_loso on invented folds (random scores): the checks pass on a good fold and fail on a changed setting, an extra row, a missing row, a wrong
#       label; the cache is written once and a different prediction file is refused; section 9 is rendered from the cache, replaced in place in a copy of
#       the report (everything above it byte for byte, the hand-written block kept), and a report whose section 9 is not last is refused
FOLDS = ["uci_sms_spam", "india_fraud_final", "scam_ham_india", "synth_india"]
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
    for src in FOLDS:
        got, aug, adv, files, test_hashes = finetune.load_data(DATA, False, False, src)
        te_src = set(got.loc[got["split"] == "test", "source"])
        if te_src != {src}:
            bad.append(f"{src}: load_data kept test rows of {te_src}")
        tr, va, hv, ht, c = finetune.split_loso(got, src)
        hashes = set(df.loc[df["source"] == src, "text_hash"])
        for name, d in (("train", tr), ("val", va)):
            if (d["source"] == src).any() or d["translation_of"].isin(hashes).any():
                bad.append(f"{src}: {name} still holds source rows or translations of its parents")
        if len(ht) != int(((df["source"] == src) & (df["split"] == "test")).sum()) or set(ht["text_hash"]) - test_hashes:
            bad.append(f"{src}: the held-out test rows are not the source's test rows")
        if set(hv["text_hash"]) & test_hashes or not set(hv["split"]) <= {"val"}:
            bad.append(f"{src}: held-out val rows are not the source's val rows")
        full_tr, full_va = (int((df["split"] == s).sum()) for s in ("train", "val"))
        if len(tr) + c["train"] + c["translations"] != full_tr or len(va) + c["val"] != full_va:
            bad.append(f"{src}: rows not accounted for: train {len(tr)}+{c['train']}+{c['translations']} vs {full_tr}, val {len(va)}+{c['val']} vs {full_va}")
        if not (c["train"] > 0 and c["test"] > 0):
            bad.append(f"{src}: expected rows in train and test, got {c}")
        if src != "synth_india" and c["val"] == 0:
            bad.append(f"{src}: no val rows dropped")
        if src == "synth_india" and c["val"] != 0:
            bad.append("synth_india has val rows now; the report's note that its fold holds out test rows only is stale")
        print(f"      {src}: dropped train {c['train']}, translations {c['translations']}, val {c['val']}; held out test {c['test']}; train left {len(tr)}, val left {len(va)}")
    # a non-LOSO load drops every test row, as before
    plain = finetune.load_data(DATA, False, False)[0]
    if (plain["split"] == "test").any():
        bad.append("a normal load_data kept test rows")
    return bad


def l2(tmp):
    if not BUNDLE.exists():
        print("      shipped bundle not on disk: skipped")
        return []
    st = json.loads((BUNDLE / "shield_meta.json").read_text(encoding="utf-8"))["settings"]
    ref = {k: v for k, v in finetune.LOSO_REFERENCE.items() if k != "model"}
    return [f"LOSO_REFERENCE {k}={v!r}, bundle {st.get(k)!r}" for k, v in ref.items() if st.get(k) != v]


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
    if not (meta.get("loso") is True and meta.get("exclude_source") == "uci_sms_spam" and d.get("train", 0) > 0 and d.get("val", 0) > 0 and d.get("translations", 0) >= 0):
        bad.append(f"shield_meta.json loso fields: {meta.get('loso')}, {meta.get('exclude_source')}, {d}")
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
            "split_map_sha256": finetune.SPLIT_MAP_SHA256, "data_sha256": {"messages.csv": sha}, "git_dirty": False, "loso": True, "exclude_source": src,
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
             "score above 1": (meta, preds.assign(score=[1.5] + list(preds["score"].iloc[1:])))}
    for what, (m, p) in cases.items():
        if not fails(m, p):
            bad.append(f"verify_fold passed a fold with {what}")

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
    body = eval_loso.section9_body(df, cache=cache)
    for src in folds:
        if f"| {src} |" not in body:
            bad.append(f"section 9 has no row for {src}")
    if "pending" in body or "Limits, same as the baseline" not in body or "A high LOSO AUROC with a low LOSO F1@0.5" not in body:
        bad.append("section 9 lacks the folds table / the plain-language paragraph")
    # an independent recomputation of one number: scam_ham_india LOSO AUROC from the cached file
    from sklearn.metrics import roc_auc_score
    cp = pd.read_csv(cache / "scam_ham_india" / "predictions_loso.csv")
    auc = f"{roc_auc_score(cp['label'], cp['score']):.3f}"
    row = [l for l in body.splitlines() if l.startswith("| scam_ham_india |")][0].split(" | ")
    if auc not in row:
        bad.append(f"scam_ham_india LOSO AUROC {auc} not in its row: {row}")
    pending = eval_loso.section9_body(df, cache=tmp / "nothing")
    if "runs pending" not in pending or "| uci_sms_spam |" not in pending:
        bad.append("the pending text lacks the baseline table")
    if "Not run for this model" not in eval_loso.section9_body(df, cache=cache, shipped=False):
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


CHECKS = [("L1", "fold data path: 0 source rows / 0 translations in train and val, held-out = source val + test, every row accounted for", l1),
          ("L2", "LOSO_REFERENCE = the shipped bundle's settings", l2),
          ("L3", "refusals before anything is created", l3),
          ("L4", "CPU dry run: only source rows in predictions_loso.csv, no model saved, loso fields", l4),
          ("L5", "the app refuses a loso: true bundle", l5),
          ("L6", "eval_loso: fold checks, cache, section 9 in place", l6)]


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
