import argparse, hashlib, json, platform, random, shutil, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np, pandas as pd
import torch
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup

from textprep import model_text, URL_TOKEN, MAX_CHARS

# Fine-tunes a multilingual encoder (MuRIL by default) as the text head. Runs on the 2nd laptop (RTX 5050, 8 GB, Windows)
# or on Kaggle (P100 / T4, notebooks/kaggle_finetune.ipynb); both only `git pull` and run this, they never edit code.
# Everything it writes goes back to the Mac, where all evaluation runs (per-source, per-language, LOSO, adversarial,
# calibration).
#   python src/finetune.py --smoke                     # 1 epoch on 2,000 train rows: checks the setup end to end
#   python src/finetune.py                             # MuRIL, 3 epochs, the settings below
#   python src/finetune.py --model mdeberta            # comparison runs: mdeberta, xlmr, or any HF model id
#   python src/finetune.py --aug                       # also train on messages_aug.csv (homoglyph / leet / zero-width, train parents)
#   python src/finetune.py --limit 50 --device cpu     # Mac dry run: 50 rows per split, no GPU
#   python src/finetune.py --data-dir /kaggle/input/scam-shield-data --out /kaggle/working/models/muril_run1   # the notebook finds the folder
#   python src/finetune.py --score-held-out            # also score test + adv_test at the end (off by default: that happens on the Mac)
#
# Precision (--precision, default auto): bf16 autocast on GPUs with compute capability >= 8.0 (RTX 5050, A100), fp16 autocast
# + GradScaler below that (T4 7.5, P100 6.0), fp32 on CPU. Weights and optimizer state stay fp32 in every mode; the loss and
# the softmax are computed in fp32.
#
# What it guarantees (CLAUDE.md rules 1, 2, 11):
#   - split_map.csv is the frozen splits-v2 file (SHA-256 below) and messages.csv agrees with it row for row;
#   - no cluster / template family / company / translation group straddles splits (the cheap half of neardup.assert_no_leakage; the LSH half was
#     run by split_audit.py on exactly this split_map, 0 violations);
#   - weights are fit on train rows only; the best epoch and both cut-offs are chosen on val; test rows are read only for the
#     integrity checks above and then dropped: by default they are never tokenised, fed to the model or scored (asserted in
#     assert_no_test_rows); --score-held-out is the one switch that scores test + adv_test, after the best epoch is chosen;
#   - every input goes through textprep.model_text (links -> <URL>, first 2000 chars), the same function the baseline and the
#     app use; the tokenizer then keeps the first --max-len tokens.
# Output (--out): model/ (best epoch, HF format) + shield_meta.json is the bundle a MurilScorer loads; epoch_<k>/ are the
# per-epoch checkpoints; predictions_val.csv, val_metrics.csv (overall / per source / per language) and, with --score-held-out,
# predictions_{test,adv_test}.csv are copied to the Mac for evaluation.

SPLIT_MAP_SHA256 = "8263df1c304de7154290f57f648387ddc396cab303630753aa40200619bd4e6c"   # splits-v2 (2026-10-21); keep in step with CLAUDE.md
MODELS = {"muril": "google/muril-base-cased", "mdeberta": "microsoft/mdeberta-v3-base", "xlmr": "FacebookAI/xlm-roberta-base"}
GROUP_KEYS = ("cluster_id", "template_family", "company_key", "translation_of")   # rows sharing any of these must share a split


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def git_state():
    """(commit, dirty) of the repo this file lives in, whatever the working directory; ("unknown", None) without git."""
    repo = Path(__file__).resolve().parent
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=repo, capture_output=True, text=True).stdout.strip())
        return commit, dirty
    except (OSError, subprocess.CalledProcessError):
        return "unknown", None


def pick_precision(requested, device):
    """auto: bf16 on compute capability >= 8.0, else fp16; fp32 on CPU. Refuses combinations the hardware can't run."""
    if device.type != "cuda":
        if requested not in ("auto", "fp32"):
            raise SystemExit(f"--precision {requested} needs a CUDA GPU; on CPU use fp32 (or auto)")
        return "fp32"
    cap = torch.cuda.get_device_capability(device)
    if requested == "auto":
        return "bf16" if cap >= (8, 0) else "fp16"
    if requested == "bf16" and cap < (8, 0):
        raise SystemExit(f"--precision bf16 needs compute capability >= 8.0; this GPU is {cap[0]}.{cap[1]} (use fp16 or auto)")
    return requested


def load_data(data_dir, use_aug, held_out):
    """messages.csv (+ messages_aug.csv) after the split checks; raises before anything is trained if a check fails.
    Test rows are in messages.csv, so they are read here for the checks; unless held_out they are dropped before returning
    and messages_adv_test.csv (test parents only) is not opened at all."""
    sm_path = data_dir / "split_map.csv"
    got = sha256(sm_path)
    if got != SPLIT_MAP_SHA256:
        raise SystemExit(f"{sm_path} SHA-256 is {got[:16]}..., expected {SPLIT_MAP_SHA256[:16]}... (splits-v2). "
                         "Pull the repo / copy the right data, or update SPLIT_MAP_SHA256 together with CLAUDE.md.")
    frozen = pd.read_csv(sm_path).set_index("text_hash")["split"]
    df = pd.read_csv(data_dir / "messages.csv", low_memory=False)
    mapped = df["text_hash"].map(frozen)
    assert mapped.notna().all(), f"{mapped.isna().sum()} messages.csv rows are missing from split_map.csv"
    assert (df["split"] == mapped).all(), "messages.csv doesn't match split_map.csv; rerun build_text.py on the Mac"
    for key in GROUP_KEYS:
        k = df[key].fillna("").astype(str)
        n = df["split"][k != ""].groupby(k[k != ""]).nunique()
        assert not (n > 1).any(), f"{key}: {(n > 1).sum()} groups straddle splits, e.g. {list(n[n > 1].index[:3])}"
    test_hashes = set(frozen.index[frozen == "test"])
    if not held_out:
        df = df[df["split"] != "test"]
    df = df.reset_index(drop=True)

    aug = None
    if use_aug:
        aug = pd.read_csv(data_dir / "messages_aug.csv", low_memory=False)
        train_clusters = set(df.loc[df["split"] == "train", "cluster_id"].astype(str))
        assert (aug["parent_hash"].map(frozen) == "train").all(), "messages_aug.csv has parents outside train; rerun augment.py on the Mac"
        assert aug["cluster_id"].astype(str).isin(train_clusters).all(), "messages_aug.csv has clusters outside train"
        assert (aug["split"] == "train").all()
        assert not set(aug["parent_hash"]) & test_hashes, "messages_aug.csv has a test parent"
    adv = None
    if held_out:
        adv = pd.read_csv(data_dir / "messages_adv_test.csv", low_memory=False)
        assert (adv["parent_hash"].map(frozen) == "test").all(), "messages_adv_test.csv has parents outside test"
    files = {f: sha256(data_dir / f) for f in ("messages.csv",) + (("messages_adv_test.csv",) if held_out else ()) + (("messages_aug.csv",) if use_aug else ())}
    return df, aug, adv, files, test_hashes


def assert_no_test_rows(tr, va, test_hashes):
    """Everything that will be tokenised for training or selection is train / val, and no text in it is a test row."""
    assert set(tr["split"]) == {"train"}, f"training rows from splits {set(tr['split'])}"
    assert set(va["split"]) == {"val"}, f"validation rows from splits {set(va['split'])}"
    seen = set(tr["text_hash"].dropna()) | set(va["text_hash"].dropna())
    assert not seen & test_hashes, f"{len(seen & test_hashes)} train/val rows carry a test text_hash"
    if "parent_hash" in tr:
        assert not set(tr["parent_hash"].dropna()) & test_hashes, "an augmented training row has a test parent"


def val_report(va, score, t_susp, t_likely):
    """Overall / per-source / per-language val metrics of the best epoch, at 0.5 and at the val-chosen likely cut-off."""
    d = va.assign(_s=score, _y=va["label"].astype(int))
    rows = []
    def add(kind, key, g):
        y, sc = g["_y"].to_numpy(), g["_s"].to_numpy()
        two = len(set(y)) == 2
        rows.append({"slice": kind, "key": key, "n": len(g), "scam": int(y.sum()),
                     "f1_at_0.5": round(f1_score(y, sc >= 0.5, zero_division=0), 4),
                     "f1_at_likely": round(f1_score(y, sc >= t_likely, zero_division=0), 4),
                     "precision_at_likely": round(precision_score(y, sc >= t_likely, zero_division=0), 4),
                     "recall_at_likely": round(recall_score(y, sc >= t_likely, zero_division=0), 4),
                     "recall_at_suspicious": round(recall_score(y, sc >= t_susp, zero_division=0), 4) if y.sum() else None,
                     "auroc": round(roc_auc_score(y, sc), 4) if two else None})
    add("overall", "all", d)
    for col, kind in (("source", "source"), ("language", "language")):
        for key, g in d.groupby(col):
            add(kind, key, g)
    present = set(d["language"])
    for lang in ("hindi", "kannada"):   # the translations are train-only; val should have none, and the log says so either way
        if lang not in present:
            rows.append({"slice": "language", "key": lang, "n": 0, "scam": 0})
    return pd.DataFrame(rows)


def sample(d, n, seed):
    """Up to n rows, stratified by label, original order kept."""
    if n is None or len(d) <= n:
        return d
    frac = n / len(d)
    return d.groupby("label", group_keys=False).sample(frac=frac, random_state=seed).sort_index()


def seed_everything(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.benchmark = False


class Batcher:
    """Tokenises a batch at a time (dynamic padding to the longest row in the batch, cut at max_len tokens)."""
    def __init__(self, tok, max_len):
        self.tok, self.max_len = tok, max_len

    def __call__(self, rows):
        texts, labels = zip(*rows)
        enc = self.tok(list(texts), truncation=True, max_length=self.max_len, padding=True, return_tensors="pt")
        enc["labels"] = torch.tensor(labels, dtype=torch.long)
        return enc


def loader(texts, labels, batcher, batch, shuffle, seed):
    g = torch.Generator()
    g.manual_seed(seed)
    return torch.utils.data.DataLoader(list(zip(texts, labels)), batch_size=batch, shuffle=shuffle, generator=g,
                                       collate_fn=batcher, num_workers=0)   # workers 0: Windows spawns processes, and tokenising is not the bottleneck


@torch.no_grad()
def predict(model, texts, batcher, batch, device, amp_dtype):
    """P(scam) for each text, in order."""
    model.eval()
    out = []
    for enc in loader(texts, [0] * len(texts), batcher, batch * 2, False, 0):
        enc.pop("labels")
        enc = {k: v.to(device) for k, v in enc.items()}
        with torch.autocast(device.type, dtype=amp_dtype or torch.float32, enabled=amp_dtype is not None):
            logits = model(**enc).logits
        out.append(torch.softmax(logits.float(), dim=-1)[:, 1].cpu().numpy())
    return np.concatenate(out) if out else np.zeros(0)


def thresholds(y, s):
    """The app's two cut-offs, chosen on val exactly as baseline.py --save does: likely = max-F1 threshold,
    suspicious = highest threshold that keeps val scam recall >= 0.95 (never above likely)."""
    grid = np.unique(np.quantile(s, np.linspace(0.01, 0.99, 197)))
    t_likely = float(grid[int(np.argmax([f1_score(y, s >= t, zero_division=0) for t in grid]))])
    ok = [t for t in grid if recall_score(y, s >= t, zero_division=0) >= 0.95]
    t_susp = float(max(ok)) if ok else float(grid[0])
    return min(t_susp, t_likely), t_likely


def dir_mb(p):
    return round(sum(f.stat().st_size for f in Path(p).rglob("*") if f.is_file()) / 1e6, 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="muril", help=f"one of {list(MODELS)} or a Hugging Face model id")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--max-len", type=int, default=128, help="tokens kept per message")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--warmup", type=float, default=0.06, help="fraction of steps with a rising learning rate")
    ap.add_argument("--aug", action="store_true", help="also train on messages_aug.csv (off by default: like-for-like with baseline.py)")
    ap.add_argument("--score-held-out", action="store_true", help="also score test + adv_test after the best epoch is chosen "
                    "(off: the test split is never tokenised or scored; evaluation happens on the Mac)")
    ap.add_argument("--smoke", action="store_true", help="1 epoch, 2,000 train rows, val/test/adv capped at 500: a setup check, not a model")
    ap.add_argument("--limit", type=int, help="at most N rows per split (Mac dry run)")
    ap.add_argument("--device", choices=["auto", "cuda", "cpu"], default="auto")
    ap.add_argument("--precision", choices=["auto", "bf16", "fp16", "fp32"], default="auto",
                    help="auto: bf16 if the GPU's compute capability >= 8.0, else fp16 (with GradScaler); fp32 on CPU")
    ap.add_argument("--data-dir", default="data/final", help="folder with split_map.csv, messages.csv, messages_adv_test.csv "
                    "(+ messages_aug.csv); relative to the working directory, or absolute (the Kaggle notebook finds it by file name)")
    ap.add_argument("--out", help="run directory, created if missing, must be empty; relative or absolute "
                    "(e.g. /kaggle/working/models/muril_run1). Default models/finetune/<model>_<UTC time>[_smoke]")
    args = ap.parse_args()

    model_id = MODELS.get(args.model, args.model)
    short = args.model if args.model in MODELS else model_id.split("/")[-1]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.out or f"models/finetune/{short}_{stamp}{'_smoke' if args.smoke else ''}").expanduser().resolve()
    data_dir = Path(args.data_dir).expanduser().resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"{out} exists and is not empty; pick another --out")
    out.mkdir(parents=True, exist_ok=True)
    log_f = open(out / "train_log.txt", "w", encoding="utf-8")
    def log(msg):
        print(msg, flush=True)
        log_f.write(msg + "\n")
        log_f.flush()

    device = torch.device("cuda" if args.device == "cuda" or (args.device == "auto" and torch.cuda.is_available()) else "cpu")
    if device.type == "cuda" and not torch.cuda.is_available():
        raise SystemExit("--device cuda but torch.cuda.is_available() is False (check the torch build: it needs a CUDA wheel)")
    precision = pick_precision(args.precision, device)
    amp_dtype = {"bf16": torch.bfloat16, "fp16": torch.float16, "fp32": None}[precision]   # autocast dtype; weights stay fp32
    scaler = torch.amp.GradScaler("cuda") if precision == "fp16" else None   # fp16 only: bf16 has fp32's exponent range, fp32 needs none
    gpu = torch.cuda.get_device_name(device) if device.type == "cuda" else None
    cap = ".".join(map(str, torch.cuda.get_device_capability(device))) if device.type == "cuda" else None
    epochs = 1 if args.smoke else args.epochs
    seed_everything(args.seed)

    # ---------------------------------------------------------------- data
    df, aug, adv, data_files, test_hashes = load_data(data_dir, args.aug, args.score_held_out)
    log(f"device {device}{f' ({gpu}, compute capability {cap})' if gpu else ''}; precision {precision} "
        f"(requested {args.precision}){'; fp16 GradScaler on' if scaler else ''}")
    log(f"data {data_dir} -> run {out}")
    log(f"split_map.csv SHA-256 ok (splits-v2); messages.csv matches it row for row; no {'/'.join(GROUP_KEYS)} straddles splits")
    tr, va, te = (df[df["split"] == s] for s in ("train", "val", "test"))   # te is empty unless --score-held-out
    if aug is not None:
        tr = pd.concat([tr, aug[["text", "label", "source", "split"]].assign(text_hash=None)], ignore_index=True)
    caps = {"train": 2000, "val": 500, "test": 500, "adv": 500} if args.smoke else {}
    if args.limit:
        caps = {k: min(caps.get(k, args.limit), args.limit) for k in ("train", "val", "test", "adv")}
    tr, va, te = sample(tr, caps.get("train"), args.seed), sample(va, caps.get("val"), args.seed), sample(te, caps.get("test"), args.seed)
    assert_no_test_rows(tr, va, test_hashes)
    sets = {"train": tr, "val": va}
    if args.score_held_out:
        adv = sample(adv, caps.get("adv"), args.seed)
        sets.update(test=te, adv=adv)
    else:
        assert len(te) == 0 and adv is None
    log(f"train {len(tr)} ({int(tr['label'].sum())} scam = {tr['label'].mean():.1%}{', incl. aug' if aug is not None else ''}), val {len(va)} "
        f"({int(va['label'].sum())} scam = {va['label'].mean():.1%})"
        + (f", test {len(te)}, adv_test {len(adv)}" if args.score_held_out else "; test and adv_test rows: not loaded, not scored"))
    log("val rows by language: " + ", ".join(f"{k} {v}" for k, v in va["language"].value_counts().items())
        + ("" if {"hindi", "kannada"} & set(va["language"]) else "  (no hindi / kannada rows in val, as expected)"))

    X = {k: [model_text(t) for t in d["text"]] for k, d in sets.items()}   # rule 11

    tok = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id, num_labels=2).to(device)
    batcher = Batcher(tok, args.max_len)

    # how much of each input survives the token cut (long job posts and emails lose most of their text at 128 tokens)
    n_tok = np.array([len(ids) for ids in tok(X["train"], truncation=False)["input_ids"]])
    trunc = pd.Series(n_tok > args.max_len, index=tr.index).groupby(tr["source"]).mean().round(3).to_dict()
    log(f"train inputs longer than {args.max_len} tokens: {(n_tok > args.max_len).mean():.1%} (median {int(np.median(n_tok))} tokens)")

    # class-balanced loss, as class_weight="balanced" in baseline.py: n / (2 * n_c), on the rows actually trained on
    y_tr = tr["label"].astype(int).to_numpy()
    counts = np.bincount(y_tr, minlength=2)
    weights = len(y_tr) / (2 * np.maximum(counts, 1))
    loss_fn = torch.nn.CrossEntropyLoss(weight=torch.tensor(weights, dtype=torch.float, device=device))

    train_dl = loader(X["train"], y_tr.tolist(), batcher, args.batch, True, args.seed)
    steps = epochs * len(train_dl)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    sched = get_linear_schedule_with_warmup(opt, int(args.warmup * steps), steps)
    y_va = va["label"].astype(int).to_numpy()

    # ---------------------------------------------------------------- train
    history, best = [], None
    t_train = time.time()
    for ep in range(1, epochs + 1):
        model.train()
        t0, total, n = time.time(), 0.0, 0
        for i, enc in enumerate(train_dl, 1):
            labels = enc.pop("labels").to(device)
            enc = {k: v.to(device) for k, v in enc.items()}
            with torch.autocast(device.type, dtype=amp_dtype or torch.float32, enabled=amp_dtype is not None):
                logits = model(**enc).logits
            loss = loss_fn(logits.float(), labels)
            opt.zero_grad(set_to_none=True)
            if scaler is None:   # bf16 / fp32
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
            else:                # fp16: scale the loss so small gradients don't underflow, unscale before clipping
                scaler.scale(loss).backward()
                scaler.unscale_(opt)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                scaler.step(opt)   # skipped if the gradients hold inf/NaN; the scale then shrinks
                scaler.update()
            sched.step()
            total, n = total + loss.item() * len(labels), n + len(labels)
            if i % 200 == 0:
                log(f"  epoch {ep} step {i}/{len(train_dl)} loss {total / n:.4f} ({time.time() - t0:.0f} s)")
        s_va = predict(model, X["val"], batcher, args.batch, device, amp_dtype)
        rec = {"epoch": ep, "train_loss": round(total / max(n, 1), 4), "val_f1_at_0.5": round(f1_score(y_va, s_va >= 0.5, zero_division=0), 4),
               "val_auroc": round(roc_auc_score(y_va, s_va), 4) if len(set(y_va)) == 2 else None, "seconds": round(time.time() - t0)}
        history.append(rec)
        ck = out / f"epoch_{ep}"
        model.save_pretrained(ck)
        tok.save_pretrained(ck)
        log(f"epoch {ep}: train loss {rec['train_loss']}, val F1@0.5 {rec['val_f1_at_0.5']}, val AUROC {rec['val_auroc']}, "
            f"{rec['seconds']} s -> {ck}")
        if best is None or rec["val_f1_at_0.5"] > best["val_f1_at_0.5"]:   # ties keep the earlier epoch
            best = rec

    train_seconds = round(time.time() - t_train)

    # ---------------------------------------------------------------- best epoch -> model/, cut-offs on val, predictions
    shutil.copytree(out / f"epoch_{best['epoch']}", out / "model")
    model = AutoModelForSequenceClassification.from_pretrained(out / "model").to(device)
    s = {k: predict(model, X[k], batcher, args.batch, device, amp_dtype) for k in X if k != "train"}   # val, + test / adv with --score-held-out
    t_susp, t_likely = thresholds(y_va, s["val"])
    log(f"best epoch {best['epoch']} (val F1@0.5 {best['val_f1_at_0.5']}); val-chosen cut-offs: suspicious >= {t_susp:.3f}, likely scam >= {t_likely:.3f}; "
        f"training time {train_seconds} s ({train_seconds / 60:.1f} min)")

    rep_val = val_report(va, s["val"], t_susp, t_likely)
    rep_val.to_csv(out / "val_metrics.csv", index=False, encoding="utf-8")
    log("val metrics of the best epoch (f1@likely = F1 at the val-chosen max-F1 cut-off, the number comparable with baseline.py's val F1):\n"
        + rep_val.fillna("").to_string(index=False))

    pd.DataFrame({"text_hash": va["text_hash"].to_numpy(), "split": "val", "label": y_va, "score": s["val"]}).to_csv(
        out / "predictions_val.csv", index=False, encoding="utf-8")
    if args.score_held_out:
        pd.DataFrame({"text_hash": te["text_hash"].to_numpy(), "split": "test", "label": te["label"].astype(int).to_numpy(),
                      "score": s["test"]}).to_csv(out / "predictions_test.csv", index=False, encoding="utf-8")
        pd.DataFrame({"parent_hash": adv["parent_hash"].to_numpy(), "aug_method": adv["aug_method"].to_numpy(),
                      "label": adv["label"].astype(int).to_numpy(), "score": s["adv"]}).to_csv(out / "predictions_adv_test.csv", index=False, encoding="utf-8")

    commit, dirty = git_state()
    import transformers, tokenizers, sklearn, tldextract
    meta = {
        "model_name": model_id, "short_name": short,
        "textprep": {"url_token": URL_TOKEN, "max_chars": MAX_CHARS},   # the same key app.py checks on the baseline bundle
        "split_map_sha256": SPLIT_MAP_SHA256, "data_sha256": data_files,
        "git_commit": commit, "git_dirty": dirty,
        "threshold_suspicious": t_susp, "threshold_likely": t_likely,
        "thresholds_chosen_on": "val (likely = max F1; suspicious = highest with scam recall >= 0.95)",
        "score": "softmax P(scam) of the best epoch; uncalibrated (class-weighted loss)",
        "best_epoch": best["epoch"], "selected_by": "val F1 at 0.5", "history": history,
        "settings": {"epochs": epochs, "batch": args.batch, "lr": args.lr, "max_len": args.max_len, "seed": args.seed,
                     "warmup": args.warmup, "weight_decay": 0.01, "grad_clip": 1.0, "optimizer": "AdamW",
                     "schedule": "linear warmup + linear decay", "aug": args.aug, "smoke": args.smoke, "limit": args.limit,
                     "score_held_out": args.score_held_out},
        "rows": {"train": len(tr), "train_scam": int(counts[1]), "val": len(va), "val_scam": int(y_va.sum()),
                 "test": len(te) if args.score_held_out else None, "adv_test": len(adv) if args.score_held_out else None},
        "training_seconds": train_seconds,
        "val_overall": rep_val[rep_val["slice"] == "overall"].iloc[0].dropna().to_dict(),
        "class_weights": [round(float(w), 4) for w in weights],
        "train_truncated_share_by_source": trunc,
        "device": gpu or platform.processor() or "cpu", "gpu_name": gpu, "gpu_compute_capability": cap,
        "precision": precision, "precision_requested": args.precision,
        "dtype": {"bf16": "bf16 autocast, fp32 weights", "fp16": "fp16 autocast + GradScaler, fp32 weights", "fp32": "fp32"}[precision],
        "fp16_final_loss_scale": float(scaler.get_scale()) if scaler else None,
        "versions": {"python": platform.python_version(), "torch": torch.__version__, "cuda": torch.version.cuda,
                     "transformers": transformers.__version__, "tokenizers": tokenizers.__version__,
                     "tldextract": tldextract.__version__, "scikit-learn": sklearn.__version__, "pandas": pd.__version__, "numpy": np.__version__},
        "checkpoint_mb": {p.name: dir_mb(p) for p in sorted(out.glob("epoch_*"))},
        "created_utc": stamp, "command": " ".join(sys.argv),
    }
    (out / "shield_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    log(f"wrote {out / 'model'}, shield_meta.json, val_metrics.csv, predictions_val.csv{', predictions_test/adv_test.csv' if args.score_held_out else ''}; copy {out} back to the Mac")
    if dirty:
        log("WARNING: the git tree had uncommitted changes; the laptop should only `git pull`")
    log_f.close()


if __name__ == "__main__":
    main()
