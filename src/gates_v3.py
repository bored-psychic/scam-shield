import argparse, json, math, re
from pathlib import Path

import numpy as np, pandas as pd
from sklearn.metrics import f1_score, roc_auc_score

# splits-v3 success gates G1-G5 (docs/plans/splits_v3.md section 4), pre-registered before any v3 model exists. VAL ONLY: every prediction file and every row used
# must have split == "val"; a test row anywhere is an error, and messages.csv is read in chunks that keep val rows only, so no test row is ever held. Run on the Mac on
# 3 Nov after calibrate_text_head.py (v3 val) and the re-score of the shipped bundle on v3 val; writes reports/gates_v3.md with pass / fail / not measurable per gate.
#
#   .venv/bin/python src/gates_v3.py --v3-preds P --v3-meta M --shipped-preds P --shipped-meta M --baseline-preds P --baseline-meta M [--loso-val CSV]
#
# Inputs, per model: predictions_val.csv (text_hash, split, label, score; raw scores) and a JSON with the cut-offs: a shield_meta.json (its "calibration" block: temperature,
# threshold_suspicious, threshold_likely; the score is calibrated as sigmoid(logit(score) / T)) or a flat {"threshold_suspicious", "threshold_likely"[, "temperature"]} (the baseline).
# The LOSO input of G4 is the val-only CSV written by `eval_loso.py --val-only` (the fold's test rows never get here).
#
# Group counting (the plan says "per group"): a group is a real_group (the intake's template group) for real rows and a template_family for the synthetic UPI family; a group
# is flagged at a level if ANY of its rows has a calibrated score at or above that level's cut-off (= its maximum score does), the conservative reading: a template the
# model flags once is a false alarm.
# Not built here (plan section 4 "Also reported"): the shortcut checks (<OTP> cue AUROC, length-only AUROC with and without POOL) are sanity_checks.py's job; G-inv exists
# only if Phase B is "go" on 1 Nov and is listed as not applicable.

G1_MIN_GROUPS, G1_SUSP_MAX, G1_LIKELY_MAX = 39, 0.10, 0.02          # section 4: n >= 39 groups (+-15 points), D5 ship gate 10 %, Likely 2 %
D5_TARGETS = (0.05, 0.01)                                           # D5 section 1.4, reported beside the gate
G2_TOLERANCE, G2_SHIPPED_V2_F1 = 0.005, 0.9514                      # the D27 rule's tolerance; shipped on v2 text (reports/eval_muril_v2.md section 1)
G3_MIN_GROUPS, G3_LIKELY_MAX = 5, 0.10
G4_GENUINE_ACC, G4_AUROC = 0.30, 0.828                              # v2 fold, same 350 val rows: 0.149 / 0.961 recall / 0.828
G4_V2_REFERENCE = {"genuine_accuracy": 0.149, "scam_recall": 0.961, "auroc": 0.828, "n_genuine": 195, "n_scam": 155}
ALERT_BUCKETS = ("kyc-bank", "delivery")
COLLECT_RX = re.compile(r"collect request|request money|payment request", re.I)
POOL_SOURCE, SYNTH_UPI_SOURCE = "phones_pool", "synth_upi_collect_v3"
PASS, FAIL, NOT_MEASURABLE = "pass", "fail", "not measurable"
VAL_COLS = ["text_hash", "text", "label", "source", "language", "is_synthetic", "template_family", "split"]


class GateError(SystemExit):
    pass


def logit(p):
    p = np.clip(np.asarray(p, dtype=float), 1e-12, 1 - 1e-12)   # the clip calibrate_text_head.py uses
    return np.log(p / (1 - p))


def sigmoid(x):
    return 1 / (1 + np.exp(-x))


def wilson_upper(k, n, z=1.96):
    """Upper end of the Wilson 95 % interval for k of n."""
    if n == 0:
        return float("nan")
    p = k / n
    d = 1 + z * z / n
    return float((p + z * z / (2 * n) + z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d)


def require_val(df, name):
    """Every gate input is val only: a row of any other split, or a missing split column, is an error before anything is computed."""
    if "split" not in df.columns:
        raise GateError(f"{name}: no split column; refusing to use rows whose split is unknown")
    bad = df["split"].astype(str) != "val"
    if bad.any():
        raise GateError(f"{name}: {int(bad.sum())} rows have split != 'val' ({sorted(set(df.loc[bad, 'split'].astype(str)))}); the gates read validation predictions only")
    return df


def load_val_messages(path):
    """messages.csv rows with split == val, read in chunks so that no test row is ever held in memory. Needs the columns of VAL_COLS plus (with a pool) real_group, kw_bucket."""
    parts = []
    for chunk in pd.read_csv(path, chunksize=20000, keep_default_na=False, low_memory=False):
        parts.append(chunk[chunk["split"] == "val"].drop(columns=[c for c in chunk.columns if c not in VAL_COLS + ["real_group", "kw_bucket"]]))
    val = pd.concat(parts, ignore_index=True)
    for c in ("real_group", "kw_bucket"):
        if c not in val:
            val[c] = ""
    val["label"] = val["label"].astype(int)
    val["is_synthetic"] = val["is_synthetic"].astype(str).str.lower().eq("true")
    return require_val(val, "messages.csv (val rows)")


def load_cutoffs(path):
    j = json.loads(Path(path).read_text(encoding="utf-8"))
    c = j.get("calibration") or j
    try:
        return {"temperature": float(c.get("temperature", 1.0)), "susp": float(c["threshold_suspicious"]), "likely": float(c["threshold_likely"]), "source": str(path)}
    except KeyError as e:
        raise GateError(f"{path}: no {e} (expected a shield_meta.json with a calibration block, or a flat cut-off file)")


class Model:
    """One model's val scores, calibrated, and its two cut-offs."""

    def __init__(self, name, preds, cutoffs, val):
        require_val(preds, f"{name} predictions")
        if preds["text_hash"].duplicated().any():
            raise GateError(f"{name}: duplicate text_hash in the predictions")
        want, got = set(val["text_hash"]), set(preds["text_hash"])
        if want != got:
            raise GateError(f"{name}: predictions do not cover exactly the val rows of messages.csv ({len(want - got)} missing, {len(got - want)} extra)")
        lab = preds.set_index("text_hash")["label"].astype(int).reindex(val["text_hash"]).to_numpy()
        if not (lab == val["label"].to_numpy()).all():
            raise GateError(f"{name}: predictions' labels disagree with messages.csv")
        self.name, self.cut = name, cutoffs
        raw = preds.set_index("text_hash")["score"].astype(float).reindex(val["text_hash"]).to_numpy()
        self.score = pd.Series(sigmoid(logit(raw) / cutoffs["temperature"]), index=val.index)   # calibrated, aligned with val's index

    def susp(self):
        return self.score >= self.cut["susp"]

    def likely(self):
        return self.score >= self.cut["likely"]


def group_rate(flag, groups):
    """(flagged groups, groups) when a group is flagged if any of its rows is."""
    g = flag.groupby(groups).any()
    return int(g.sum()), int(len(g))


def level_text(k, n):
    return f"{k}/{n} = {k / n:.1%} (Wilson 95 % upper {wilson_upper(k, n):.1%})" if n else "n/a"


def gate_g1(val, models):
    """G1 Indian genuine alerts: POOL-val genuine rows with kw_bucket kyc-bank / delivery, per real_group, at each model's own cut-offs."""
    rows = (val["source"] == POOL_SOURCE) & (val["label"] == 0) & val["kw_bucket"].isin(ALERT_BUCKETS)
    groups = val.loc[rows, "real_group"]
    n = groups.nunique()
    out = {"gate": "G1", "name": "Indian genuine alerts", "blocking": True, "n_groups": int(n), "models": {}}
    for m in models:
        ks, n_ = group_rate(m.susp()[rows], groups)
        kl, _ = group_rate(m.likely()[rows], groups)
        out["models"][m.name] = {"susp": ks, "likely": kl, "n": n_}
    v3 = out["models"].get("v3")
    if n < G1_MIN_GROUPS or v3 is None:
        out["status"] = NOT_MEASURABLE
        out["why"] = f"{n} POOL-val alert groups, fewer than the {G1_MIN_GROUPS} the gate needs (+-15 points)"
        return out
    ok = v3["susp"] / n <= G1_SUSP_MAX and v3["likely"] / n <= G1_LIKELY_MAX
    out["status"] = PASS if ok else FAIL
    out["why"] = (f"v3: at least Suspicious {level_text(v3['susp'], n)} (pass if <= {G1_SUSP_MAX:.0%}), Likely scam {level_text(v3['likely'], n)} (pass if <= {G1_LIKELY_MAX:.0%}); "
                  f"D5 targets {D5_TARGETS[0]:.0%} / {D5_TARGETS[1]:.0%}: " + ("met" if v3["susp"] / n <= D5_TARGETS[0] and v3["likely"] / n <= D5_TARGETS[1] else "not met"))
    return out


def gate_g2(val, models):
    """G2 no regression: v2-core val (every val row that is not a pool row or the synthetic UPI family), F1 at each model's own Likely cut-off."""
    core = ~val["source"].isin([POOL_SOURCE, SYNTH_UPI_SOURCE])
    y = val.loc[core, "label"].to_numpy()
    f1 = {m.name: float(f1_score(y, m.likely()[core].to_numpy())) for m in models}
    out = {"gate": "G2", "name": "no regression", "blocking": True, "n_core_val": int(core.sum()), "f1": f1}
    if "v3" not in f1 or "shipped" not in f1:
        out["status"], out["why"] = NOT_MEASURABLE, "needs both the v3 and the re-scored shipped predictions"
        return out
    ok = f1["v3"] >= f1["shipped"] - G2_TOLERANCE
    out["status"] = PASS if ok else FAIL
    out["why"] = (f"v3 F1 {f1['v3']:.4f} vs shipped re-scored {f1['shipped']:.4f} - {G2_TOLERANCE} = {f1['shipped'] - G2_TOLERANCE:.4f} (n {int(core.sum())}); "
                  f"shipped on v2 text {G2_SHIPPED_V2_F1}")
    return out


def gate_g3(val, models):
    """G3 UPI collect: genuine collect-request groups, Likely scam <= 10 % of groups, for the real proxy (POOL-val, regex) and the synthetic family, each if it has >= 5 groups."""
    real_rows = (val["source"] == POOL_SOURCE) & (val["label"] == 0) & val["text"].map(lambda t: bool(COLLECT_RX.search(str(t))))
    syn_rows = val["source"] == SYNTH_UPI_SOURCE
    proxies = {"real (POOL-val collect-request alerts)": (real_rows, val["real_group"]), "synthetic (synth_upi_collect_v3 families)": (syn_rows, val["template_family"])}
    out = {"gate": "G3", "name": "UPI collect", "blocking": True, "proxies": {}}
    existing = []
    for pname, (rows, groups) in proxies.items():
        n = groups[rows].nunique()
        res = {"n_groups": int(n), "models": {}}
        for m in models:
            k, n_ = group_rate(m.likely()[rows], groups[rows])
            res["models"][m.name] = {"likely": k, "n": n_}
        out["proxies"][pname] = res
        if n >= G3_MIN_GROUPS:
            existing.append(pname)
    v3_ok = lambda p: "v3" in out["proxies"][p]["models"] and out["proxies"][p]["models"]["v3"]["likely"] / out["proxies"][p]["n_groups"] <= G3_LIKELY_MAX
    if not existing:
        out["status"] = NOT_MEASURABLE
        out["why"] = "neither proxy has >= %d groups (%s); the gate blocks" % (G3_MIN_GROUPS, ", ".join(f"{p.split(' (')[0]} {out['proxies'][p]['n_groups']}" for p in out["proxies"]))
        return out
    bad = [p for p in existing if not v3_ok(p)]
    out["status"] = FAIL if bad else PASS
    out["why"] = "; ".join(f"{p.split(' (')[0]}: v3 Likely scam {level_text(out['proxies'][p]['models']['v3']['likely'], out['proxies'][p]['n_groups'])} (pass if <= {G3_LIKELY_MAX:.0%})" for p in existing)
    skipped = [p.split(' (')[0] for p in out["proxies"] if p not in existing]
    if skipped:
        out["why"] += f"; {', '.join(skipped)} has < {G3_MIN_GROUPS} groups and is not gated"
    return out


def g4_numbers(loso_val):
    """Genuine accuracy at 0.5, scam recall at 0.5 and AUROC of the LOSO fold's val rows (raw scores, as eval_loso.py's section 9)."""
    require_val(loso_val, "LOSO val-only predictions")
    y, s = loso_val["label"].astype(int).to_numpy(), loso_val["score"].astype(float).to_numpy()
    pos = s >= 0.5
    n0, n1 = int((y == 0).sum()), int((y == 1).sum())
    return {"genuine_accuracy": float(((~pos) & (y == 0)).sum() / n0) if n0 else float("nan"), "scam_recall": float((pos & (y == 1)).sum() / n1) if n1 else float("nan"),
            "auroc": float(roc_auc_score(y, s)) if n0 and n1 else float("nan"), "n_genuine": n0, "n_scam": n1}


def gate_g4(loso_val):
    out = {"gate": "G4", "name": "LOSO india_fraud_final (val rows only)", "blocking": False, "v2_reference": G4_V2_REFERENCE}
    if loso_val is None:
        out["status"], out["why"] = NOT_MEASURABLE, "no --loso-val file (run eval_loso.py --val-only on the v3 fold)"
        return out
    r = g4_numbers(loso_val)
    out["v3"] = r
    if r["n_genuine"] == 0 or r["n_scam"] == 0:
        out["status"], out["why"] = NOT_MEASURABLE, f"the fold's val rows hold {r['n_genuine']} genuine and {r['n_scam']} scam rows"
        return out
    ok = r["genuine_accuracy"] >= G4_GENUINE_ACC and r["auroc"] >= G4_AUROC
    out["status"] = PASS if ok else FAIL
    out["why"] = (f"genuine accuracy at 0.5 {r['genuine_accuracy']:.3f} (improved if >= {G4_GENUINE_ACC}; v2 fold {G4_V2_REFERENCE['genuine_accuracy']}), val AUROC {r['auroc']:.3f} "
                  f"(>= {G4_AUROC}; v2 {G4_V2_REFERENCE['auroc']}), scam recall {r['scam_recall']:.3f} (v2 {G4_V2_REFERENCE['scam_recall']}); n {r['n_genuine']} genuine / {r['n_scam']} scam. "
                  "Report-only, not blocking (decided 2026-10-27)")
    return out


def gate_g5(val, models):
    """G5 flag policy: v2-core val genuine rows flagged at least Suspicious, v3 MuRIL <= the v3 TF-IDF baseline refit."""
    core = ~val["source"].isin([POOL_SOURCE, SYNTH_UPI_SOURCE]) & (val["label"] == 0)
    n = int(core.sum())
    rates = {m.name: int(m.susp()[core].sum()) for m in models}
    out = {"gate": "G5", "name": "flag policy", "blocking": True, "n_genuine": n, "flagged": rates}
    if "v3" not in rates or "baseline" not in rates:
        out["status"], out["why"] = NOT_MEASURABLE, "needs the v3 and the v3 baseline refit predictions"
        return out
    out["status"] = PASS if rates["v3"] <= rates["baseline"] else FAIL
    out["why"] = f"v2-core val genuine (n {n}) at least Suspicious: v3 MuRIL {rates['v3']} ({rates['v3'] / n:.2%}), v3 baseline refit {rates['baseline']} ({rates['baseline'] / n:.2%})" + \
        (f", shipped re-scored {rates['shipped']} ({rates['shipped'] / n:.2%}); shipped on v2 text 1.56 % vs baseline 4.06 % (D27)" if "shipped" in rates else "")
    return out


def extras(val, models):
    """Reported, not gated: overall and real-only F1 / AUROC on all v3 val at each model's Likely cut-off, POOL-val scam groups caught, Kannada / Hindi POOL-val genuine false alarms."""
    lines = []
    y = val["label"].to_numpy()
    real = ~val["is_synthetic"].to_numpy()
    for m in models:
        s = m.score.to_numpy()
        f1 = float(f1_score(y, m.likely().to_numpy()))
        auc = float(roc_auc_score(y, s))
        f1r = float(f1_score(y[real], m.likely().to_numpy()[real])) if real.any() and len(set(y[real])) > 1 else float("nan")
        lines.append(f"- {m.name}: all val (n {len(val)}) F1 {f1:.4f}, AUROC {auc:.4f}; real-only (is_synthetic False, n {int(real.sum())}) F1 {f1r:.4f}")
    pool = val["source"] == POOL_SOURCE
    sc = pool & (val["label"] == 1)
    for m in models:
        k, n = group_rate(m.likely()[sc], val.loc[sc, "real_group"]) if sc.any() else (0, 0)
        lines.append(f"- {m.name}: POOL-val scam groups caught at Likely: {k}/{n} (a count, not a rate)")
    for lang in ("kannada", "hindi"):
        rows = pool & (val["label"] == 0) & (val["language"] == lang)
        if rows.any():
            for m in models:
                k, n = group_rate(m.susp()[rows], val.loc[rows, "real_group"])
                lines.append(f"- {m.name}: POOL-val {lang} genuine groups flagged at least Suspicious: {k}/{n}")
        else:
            lines.append(f"- POOL-val {lang} genuine groups: none")
    return lines


def run_gates(val, models, loso_val=None):
    by = {m.name: m for m in models}
    order = [by[n] for n in ("v3", "shipped", "baseline") if n in by]
    gates = [gate_g1(val, order), gate_g2(val, order), gate_g3(val, order), gate_g4(loso_val), gate_g5(val, order)]
    return gates, extras(val, order)


def verdict(gates):
    blocking = [g for g in gates if g["blocking"]]
    if all(g["status"] == PASS for g in blocking):
        return "ALL BLOCKING GATES PASS: the test read (once) may follow (plan section 4)."
    bad = [f"{g['gate']} {g['status']}" for g in blocking if g["status"] != PASS]
    return "BLOCKING GATES NOT MET (" + ", ".join(bad) + "): the shipped MuRIL (muril_len128_20261021T135255Z) stays in the app; no test read."


def render(gates, extra_lines, models, val):
    L = ["# splits-v3 gates G1-G5 (validation rows only)", "",
         "Pre-registered in `docs/plans/splits_v3.md` section 4. **Every input row has split == val (asserted); no test row was read.** One v3 training run; no gate was changed after the model existed.", "",
         f"**{verdict(gates)}**", "", "| gate | measured on | result | blocking | numbers |", "|---|---|---|---|---|"]
    for g in gates:
        L.append(f"| {g['gate']} {g['name']} | val | **{g['status']}** | {'yes' if g['blocking'] else 'no (report-only)'} | {g['why'].replace('|', '/')} |")
    L.append("| G-inv investment | val | not applicable | only if Phase B is go on 1 Nov | not built here |")
    L += ["", "## Cut-offs used", ""]
    for m in models:
        L.append(f"- {m.name}: temperature {m.cut['temperature']:.4f}, Suspicious {m.cut['susp']:.4f}, Likely {m.cut['likely']:.4f} (from `{m.cut['source']}`)")
    L += ["", "## Per model", ""]
    g1 = gates[0]
    L.append(f"G1 ({g1['n_groups']} POOL-val alert groups; a group is flagged if any of its rows is):")
    for name, r in g1["models"].items():
        L.append(f"- {name}: at least Suspicious {level_text(r['susp'], r['n'])}; Likely scam {level_text(r['likely'], r['n'])}")
    L += ["", "G2 (F1 on v2-core val at each model's own Likely cut-off):"]
    for name, f in gates[1]["f1"].items():
        L.append(f"- {name}: {f:.4f}")
    L += ["", "G3 (Likely scam among genuine collect-request groups):"]
    for pname, r in gates[2]["proxies"].items():
        L.append(f"- {pname}, {r['n_groups']} groups: " + "; ".join(f"{n} {level_text(x['likely'], x['n'])}" for n, x in r["models"].items()))
    L += ["", "G5 (v2-core val genuine flagged at least Suspicious):"]
    for name, k in gates[4]["flagged"].items():
        L.append(f"- {name}: {k}/{gates[4]['n_genuine']} = {k / gates[4]['n_genuine']:.2%}")
    L += ["", "## Also reported on val, not gated", ""] + extra_lines
    L += ["", "Shortcut checks of section 3 (`<OTP>` cue AUROC, length-only AUROC with and without POOL) are `sanity_checks.py`'s job and are not part of this file.", ""]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0] if __doc__ else None)
    ap.add_argument("--messages", default="data/final/messages.csv")
    for m in ("v3", "shipped", "baseline"):
        ap.add_argument(f"--{m}-preds", help=f"predictions_val.csv of the {m} model, scored on the v3 val rows")
        ap.add_argument(f"--{m}-meta", help=f"shield_meta.json (calibration block) or flat cut-off JSON of the {m} model")
    ap.add_argument("--loso-val", help="val-only CSV from eval_loso.py --val-only (G4)")
    ap.add_argument("--out", default="reports/gates_v3.md")
    a = ap.parse_args()
    val = load_val_messages(a.messages)
    models = []
    for m in ("v3", "shipped", "baseline"):
        p, c = getattr(a, f"{m}_preds"), getattr(a, f"{m}_meta")
        if p or c:
            if not (p and c):
                raise GateError(f"--{m}-preds and --{m}-meta go together")
            models.append(Model(m, pd.read_csv(p), load_cutoffs(c), val))
    loso = pd.read_csv(a.loso_val) if a.loso_val else None
    gates, extra_lines = run_gates(val, models, loso)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(render(gates, extra_lines, models, val), encoding="utf-8")
    print(verdict(gates))
    for g in gates:
        print(f"  {g['gate']} {g['name']}: {g['status']}")
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
