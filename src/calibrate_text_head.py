import argparse, json, math
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np, pandas as pd
from scipy.optimize import minimize_scalar

from textprep import model_text
from finetune import SPLIT_MAP_SHA256, sha256, thresholds   # the same splits-v2 hash and the same val cut-off rule as training
from shield.core.risk import curve
from shield.core.verdict import r3

# Calibrates the app's MuRIL text head (decision D27) from its CACHED predictions; nothing is re-scored and no model is loaded.
#   .venv/bin/python src/calibrate_text_head.py            # -> the "calibration" block in the bundle's shield_meta.json + reports/calibration_muril_v2.md
#                                                          #    + the tracked backup models/calibration/<run>.json
#   .venv/bin/python src/calibrate_text_head.py --export   # write that backup from the bundle's current block (no fit)
#   .venv/bin/python src/calibrate_text_head.py --apply models/calibration/<run>.json [--run <fresh copy of the bundle>]
#                                                          # put the saved block into a fresh copy's shield_meta.json, no refit; refuses if the
#                                                          # weights' SHA-256 or the split map differ from the ones the block was fitted for
#
# Every choice is made on VAL (5,267 rows, the bundle's predictions_val.csv, column `score`: the T4 scores the cut-offs were chosen on):
#   1. temperature T: one parameter, calibrated score = sigmoid(logit(score) / T), T minimises val log-loss. The head is a 2-class softmax, so
#      logit(score) is exactly the logit difference the model produced.
#   2. cut-offs: finetune.thresholds (the rule every text head uses) on the calibrated val scores; the val levels must be identical to the raw
#      scores' levels under the raw cut-offs (T only rescales, so the order is kept), also after the app's 3-decimal rounding.
#   3. Suspicious flag policy (user, 2026-10-21): MuRIL may not flag more val benign messages at Suspicious-or-above than the app's TF-IDF
#      baseline (models/text_baseline.joblib, its own cut-offs) does. If it would, its suspicious cut-off is raised to match that rate.
#   4. meter ends (risk.curve, logit scale): the 1st / 99th percentile of the calibrated val scores -> 0 / 100.
# Test is read from the cache (reports/eval_preds/<run>/predictions_test.csv, SHA-256 checked against scored.json) ONLY to report its Brier and
# reliability before / after T. No number from test feeds any choice.

ROOT = Path(__file__).resolve().parent.parent
RUN = ROOT / "models/finetune/muril_len128_20261021T135255Z"
REPORT = ROOT / "reports/calibration_muril_v2.md"
BACKUP_DIR = ROOT / "models/calibration"   # tracked (.gitignore re-includes it): models/ itself is not
BASELINE = ROOT / "models/text_baseline.joblib"
BINS = np.linspace(0, 1, 11)


def logit(p):
    p = np.clip(np.asarray(p, dtype=float), 1e-12, 1 - 1e-12)
    return np.log(p / (1 - p))


def sigmoid(x):
    return 1 / (1 + np.exp(-x))


def nll(y, p):
    p = np.clip(p, 1e-12, 1 - 1e-12)
    return float(-np.mean(y * np.log(p) + (1 - y) * np.log(1 - p)))


def brier(y, p):
    return float(np.mean((p - y) ** 2))


def reliability(y, p):
    """10 equal-width bins: (bin, n, mean score, scam rate); and the ECE."""
    idx = np.clip(np.digitize(p, BINS[1:-1]), 0, 9)
    rows, ece = [], 0.0
    for b in range(10):
        m = idx == b
        if m.any():
            ece += m.mean() * abs(p[m].mean() - y[m].mean())
        rows.append((f"[{BINS[b]:.1f}, {BINS[b + 1]:.1f}{']' if b == 9 else ')'}", int(m.sum()),
                     f"{p[m].mean():.3f}" if m.any() else "-", f"{y[m].mean():.3f}" if m.any() else "-"))
    return rows, float(ece)


def levels(s, lo, hi):
    return (s >= lo).astype(int) + (s >= hi).astype(int)


def table(head, rows):
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows])


def app_baseline_val(df):
    """The app's TF-IDF baseline on the val messages, with its own cut-offs."""
    b = joblib.load(BASELINE)
    val = df[df["split"] == "val"]
    s = b["model"].predict_proba(b["vectorizer"].transform(val["text"].map(model_text)))[:, 1]
    return val["label"].to_numpy(), s, (b["threshold_suspicious"], b["threshold_likely"])


def flag_stats(y, s, lo):
    return float((s[y == 0] >= lo).mean()), int((s[y == 0] >= lo).sum()), float((s[y == 1] >= lo).mean())


def export_backup(run, meta):
    """Save the bundle's calibration block, with the SHA-256 of the weights it was fitted for, as a small tracked file."""
    out = BACKUP_DIR / f"{run.name}.json"
    BACKUP_DIR.mkdir(exist_ok=True)
    data = {"run": run.name, "model_safetensors_sha256": sha256(run / "model/model.safetensors"), "split_map_sha256": meta["split_map_sha256"],
            "calibration": meta["calibration"]}
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return out


def apply_backup(run, backup):
    """Re-apply a saved calibration block to a fresh copy of the bundle. Nothing is fitted or re-scored."""
    data = json.loads(backup.read_text(encoding="utf-8"))
    meta_path = run / "shield_meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    w = sha256(run / "model/model.safetensors")
    assert w == data["model_safetensors_sha256"], f"{run}: the weights are not the ones this calibration was fitted for ({w} != {data['model_safetensors_sha256']})"
    assert meta["split_map_sha256"] == data["split_map_sha256"], "the bundle was trained on a different split map"
    meta["calibration"] = data["calibration"]
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    c = data["calibration"]
    print(f"applied {backup.relative_to(ROOT) if backup.is_relative_to(ROOT) else backup} to {run}: weights sha256 {w[:12]} match; "
          f"T {c['temperature']:.4f}, cut-offs {c['threshold_suspicious']:.4f} / {c['threshold_likely']:.4f}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run", type=Path, default=RUN)
    ap.add_argument("--report", type=Path, default=REPORT)
    ap.add_argument("--export", action="store_true", help="write models/calibration/<run>.json from the bundle's current block; no fit")
    ap.add_argument("--apply", type=Path, help="re-apply a saved calibration file to --run; no fit")
    a = ap.parse_args()
    meta_path = a.run / "shield_meta.json"
    if a.apply:
        return apply_backup(a.run, a.apply)
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if a.export:
        assert "calibration" in meta, "the bundle has no calibration block to export"
        print("wrote", export_backup(a.run, meta).relative_to(ROOT))
        return
    assert meta["split_map_sha256"] == SPLIT_MAP_SHA256 == sha256(ROOT / "data/final/split_map.csv"), "not splits-v2"
    assert not meta["settings"]["aug"] and not meta["settings"]["smoke"] and meta["settings"]["limit"] is None

    # ---- val
    v = pd.read_csv(a.run / "predictions_val.csv")
    y, raw = v["label"].to_numpy(), v["score"].to_numpy(dtype=float)
    z = logit(raw)
    res = minimize_scalar(lambda t: nll(y, sigmoid(z / t)), bounds=(0.05, 20), method="bounded", options={"xatol": 1e-6})
    T = float(res.x)
    cal = sigmoid(z / T)
    raw_t = (meta["threshold_suspicious"], meta["threshold_likely"])
    assert thresholds(y, raw) == raw_t or np.allclose(thresholds(y, raw), raw_t), "the bundle's cut-offs don't reproduce on its val scores"
    cal_t = thresholds(y, cal)
    same = levels(raw, *raw_t) == levels(cal, *cal_t)
    same_r3 = levels(raw, *raw_t) == levels(np.round(cal, 3), *(r3(t) for t in cal_t))
    assert same.all() and same_r3.all(), f"T changed {int((~same).sum())} val levels ({int((~same_r3).sum())} after rounding)"

    # ---- Suspicious flag policy (val)
    df = pd.read_csv(ROOT / "data/final/messages.csv", usecols=["text_hash", "text", "label", "split"], low_memory=False)
    assert set(df.loc[df["split"] == "val", "text_hash"]) == set(v["text_hash"]), "val rows differ from the bundle's predictions"
    by, bs, b_t = app_baseline_val(df)
    b_rate, b_n, b_rec = flag_stats(by, bs, b_t[0])
    m_rate, m_n, m_rec = flag_stats(y, cal, cal_t[0])
    t_susp, policy = cal_t[0], "not needed: MuRIL already flags fewer val benign messages than the baseline; the rule's cut-off is kept"
    if m_rate > b_rate:
        ben = np.sort(cal[y == 0])[::-1]
        k = int(math.floor(b_rate * len(ben)))   # flag at most k benign messages: the cut-off sits between the k-th and (k+1)-th highest benign score
        t_susp = min(float((ben[k - 1] + ben[k]) / 2) if k else float(ben[0]) + 1e-9, cal_t[1])
        policy = f"applied: suspicious cut-off raised from {cal_t[0]:.4f} to {t_susp:.4f}"
    cal_t = (t_susp, cal_t[1])
    p_rate, p_n, p_rec = flag_stats(y, cal, cal_t[0])

    # ---- meter (val, as the app computes it: 3-decimal score and cut-offs)
    zc = z / T
    p0, p100 = float(sigmoid(np.percentile(zc, 1))), float(sigmoid(np.percentile(zc, 99)))
    lo3, hi3 = r3(cal_t[0]), r3(cal_t[1])
    meter = np.array([math.floor(curve(r3(p), lo3, hi3, (p0, p100)) + 0.5) for p in cal])
    bands = [int((meter <= 29).sum()), int(((meter >= 30) & (meter <= 69)).sum()), int((meter >= 70).sum())]
    tens = np.histogram(meter, bins=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 101])[0]

    # ---- test, reported only
    cache = ROOT / "reports/eval_preds" / a.run.name
    scored = json.loads((cache / "scored.json").read_text(encoding="utf-8"))
    assert sha256(cache / "predictions_test.csv") == scored["prediction_sha256"]["predictions_test.csv"], "cached test predictions changed"
    te = pd.read_csv(cache / "predictions_test.csv")
    ty, traw = te["label"].to_numpy(), te["score"].to_numpy(dtype=float)
    tcal = sigmoid(logit(traw) / T)

    # ---- write the calibration block (existing keys untouched) and the report
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    meta["calibration"] = {
        "fit_on": "val", "method": "temperature scaling, score = sigmoid(logit(softmax P(scam)) / T), T minimises val log-loss",
        "temperature": T, "threshold_suspicious": cal_t[0], "threshold_likely": cal_t[1],
        "thresholds_rule": "finetune.thresholds on the calibrated val scores; suspicious capped so val benign flags <= the app baseline's",
        "suspicious_policy": policy, "meter_p0": p0, "meter_p100": p100, "meter_ends_rule": "1st / 99th percentile of the calibrated val scores",
        "val_rows": int(len(y)), "fitted_utc": when, "report": str(a.report.relative_to(ROOT))}
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    export_backup(a.run, meta)

    rv0, e0 = reliability(y, raw)
    rv1, e1 = reliability(y, cal)
    rt0, f0 = reliability(ty, traw)
    rt1, f1 = reliability(ty, tcal)
    L = ["# MuRIL text head: calibration, cut-offs and meter (D27)", "",
         f"Generated by `python src/calibrate_text_head.py` on {when} from the cached predictions of `{a.run.relative_to(ROOT)}` (splits-v2, max_len 128, "
         "no aug). **Every choice below is made on val** (5,267 rows, the bundle's `predictions_val.csv`, the scores the original cut-offs were chosen on). "
         "Test is read from `reports/eval_preds/` (SHA-256 checked) only for the last section, after every choice was fixed; nothing was re-scored.", "",
         "## 1. Temperature", "",
         f"One parameter: calibrated score = sigmoid(logit(score) / T). **T = {T:.4f}** (val log-loss minimised). T > 1 pulls the scores away from 0 and 1: "
         "the model was over-confident.", "",
         table(["val", "log-loss", "Brier", "ECE (10 bins)"],
               [("raw", f"{nll(y, raw):.4f}", f"{brier(y, raw):.4f}", f"{e0:.4f}"), ("calibrated", f"{nll(y, cal):.4f}", f"{brier(y, cal):.4f}", f"{e1:.4f}")]), "",
         "Reliability on val, 10 equal-width bins (`scam rate` = observed share of scams in the bin):", "",
         table(["bin", "raw n", "raw mean score", "raw scam rate", "calibrated n", "calibrated mean score", "calibrated scam rate"],
               [r0 + r1[1:] for r0, r1 in zip(rv0, rv1)]), "",
         "A single temperature cannot fix the class-weighted training's shift in base rate (val is 21.9% scam); the bins with few rows are noise.", "",
         "## 2. Cut-offs", "",
         table(["", "Suspicious from", "Likely scam from"],
               [("raw (bundle, val rule)", f"{raw_t[0]:.4f}", f"{raw_t[1]:.4f}"),
                ("calibrated (same rule on calibrated val)", f"{thresholds(y, cal)[0]:.4f}", f"{thresholds(y, cal)[1]:.4f}"),
                ("**used by the app**", f"**{cal_t[0]:.4f}**", f"**{cal_t[1]:.4f}**")]), "",
         f"Val levels that differ between raw scores + raw cut-offs and calibrated scores + calibrated cut-offs: **{int((~same).sum())}** "
         f"(after the app's 3-decimal rounding: {int((~same_r3).sum())}). Asserted.", "",
         "### Suspicious flag policy", "",
         "Fixed in advance (user, 2026-10-21): *MuRIL may not raise more Suspicious flags on normal messages than the old model did.* Text head alone, on val:", "",
         table(["text head (its cut-offs)", "val benign flagged at Suspicious or above", "val scam recall at Suspicious"],
               [(f"app TF-IDF baseline (`text_baseline.joblib`, {b_t[0]:.3f} / {b_t[1]:.3f})", f"{b_rate:.2%} ({b_n} of {int((by == 0).sum())})", f"{b_rec:.4f}"),
                (f"MuRIL, calibrated rule cut-offs ({thresholds(y, cal)[0]:.3f} / {thresholds(y, cal)[1]:.3f})", f"{m_rate:.2%} ({m_n} of {int((y == 0).sum())})", f"{m_rec:.4f}"),
                (f"MuRIL, used ({cal_t[0]:.3f} / {cal_t[1]:.3f})", f"{p_rate:.2%} ({p_n})", f"{p_rec:.4f}")]), "",
         f"Policy: **{policy}**. Recall cost at Suspicious: {m_rec - p_rec:+.4f}.", "",
         "## 3. Risk meter (risk.curve, logit scale)", "",
         f"Anchors: Suspicious cut-off -> 30, Likely-scam cut-off -> 70; ends at the 1st / 99th percentile of the calibrated val scores: p = {p0:.5f} -> 0, "
         f"p = {p100:.5f} -> 100 (flat beyond). With ends set by percentiles the meter does not depend on T (dividing every logit by T moves the "
         "anchors and the scores together); T changes the score shown in Details and the Brier, not the number on the meter.", "",
         "Val messages per meter range, text score only (before the clamp into the final level's band, which lifts a rule- or link-raised message to 30 / 70):", "",
         table(["0-29", "30-69", "70-100"], [[f"{n} ({n / len(y):.1%})" for n in bands]]), "",
         table(["0-9", "10-19", "20-29", "30-39", "40-49", "50-59", "60-69", "70-79", "80-89", "90-100"], [[int(n) for n in tens]]), "",
         "Most messages still read 0-9 or 90-100: the model's scores are bimodal, and only the messages it is unsure of land in the middle.", "",
         table(["calibrated p"] + [f"{p:g}" for p in (0.01, 0.03, 0.06, 0.1, 0.2, 0.3, 0.44, 0.6, 0.8, 0.95, 0.99)],
               [["meter"] + [math.floor(curve(p, lo3, hi3, (p0, p100)) + 0.5) for p in (0.01, 0.03, 0.06, 0.1, 0.2, 0.3, 0.44, 0.6, 0.8, 0.95, 0.99)]]), "",
         "## 4. Test (reported only; T fixed on val)", "",
         f"Cached predictions `{(cache / 'predictions_test.csv').relative_to(ROOT)}` (scored once on {scored['test_scored_utc']}), calibrated with the val T.", "",
         table(["test", "Brier", "ECE (10 bins)", "log-loss"],
               [("raw", f"{brier(ty, traw):.4f}", f"{f0:.4f}", f"{nll(ty, traw):.4f}"), ("calibrated", f"{brier(ty, tcal):.4f}", f"{f1:.4f}", f"{nll(ty, tcal):.4f}")]), "",
         table(["bin", "raw n", "raw mean score", "raw scam rate", "calibrated n", "calibrated mean score", "calibrated scam rate"],
               [r0 + r1[1:] for r0, r1 in zip(rt0, rt1)]), ""]
    a.report.write_text("\n".join(L), encoding="utf-8")
    print(f"T {T:.4f}; cut-offs {cal_t[0]:.4f} / {cal_t[1]:.4f}; policy {policy}; meter ends {p0:.5f} / {p100:.5f}; bands {bands}; -> {a.report.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
