"""Genuine OTP / PIN / delivery-code messages under the MuRIL text head (D27) vs the old TF-IDF head.   Measurement only: nothing in the app changes.

    .venv/bin/python src/otp_muril.py          -> reports/otp_advisory_muril.md        (about 8 minutes: every val row through analyse() twice)

1. The tricky-input fixture (frontend/src/lib/__fixtures__/reports.json, 83 entries): every one whose level moved between the TF-IDF and MuRIL heads,
   old vs new verdict, and the driver (text head or a hard OTP / PIN rule). Both heads are run here and checked against the committed fixture (new) and
   against the previous commit's fixture (old).
2. VAL (the only split any choice is made on): benign / scam messages that mention OTP, a PIN, a code, or a credential word, by level, MuRIL vs TF-IDF.
3. TEST: the same groups, REPORTED ONLY, from the cached predictions (reports/eval_preds/, SHA-256 checked). Text head alone plus the OTP / PIN hard floor;
   links are ignored. No choice depends on it.
4. What three candidate fixes would do on val and on the fixture (simulated after analyse(); the app is not changed).

Val rows are picked by text_hash from split_map.csv and asserted to be val. No val message text is written to the report (counts only); the fixture
texts are the hand-written inputs of tests/tricky_inputs.py.
"""
import hashlib, json, re, subprocess, sys, time
from pathlib import Path
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
from shield import config
from shield.core.router import analyse, safety_advice_cap
from shield.core.verdict import r3
from shield.links.lexical import load_url_model
from shield.links.gambling import load_gambling
from shield.messages.rules import advisory_phrases, cred_requests, has_indian_mobile, pin_to_receive, _CRED_WORD
from shield.messages.text_head import MurilScorer, load_baseline

FIXTURE = ROOT / "frontend/src/lib/__fixtures__/reports.json"
SPLIT_MAP, MESSAGES = ROOT / "data/final/split_map.csv", ROOT / "data/final/messages.csv"
CAL = ROOT / "models/calibration/muril_len128_20261021T135255Z.json"
CACHE = ROOT / "reports/eval_preds/muril_len128_20261021T135255Z"
BASE_CACHE = ROOT / "reports/eval_preds/baseline_splits_v2"
REPORT = ROOT / "reports/otp_advisory_muril.md"
LEVEL = {"no_warning_signs": 0, "suspicious": 1, "likely_scam": 2}
NAME = ["No warning signs", "Suspicious", "Likely scam"]

OTP_RX = re.compile(r"\botp\b|one[- ]?time[- ]pass", re.I)
PIN_RX = re.compile(r"\bpin\b", re.I)
CODE_RX = re.compile(r"\b(?:verification|security|delivery|confirmation|login) code\b", re.I)
DELIV_RX = re.compile(r"deliver|parcel|order|courier|shipment|shipping|package|dispatch", re.I)
# Candidate C: the OTP rule's delivery-PIN family ("Share PIN 1234 only at delivery", "Give PIN 5566 to the agent only if you receive the order").
DELIV_PIN_RX = re.compile(r"\bat (?:the )?delivery\b|\b(?:to|with) the (?:delivery )?(?:agent|executive|partner|boy|person)\b|only if you receive the (?:order|parcel|package)", re.I)
GROUPS = [("mention OTP / one-time password", OTP_RX), ("mention a PIN", PIN_RX), ("mention a verification / delivery / login code", CODE_RX),
          ("delivery / order / courier wording AND (OTP, PIN or code)", None), ("any credential word (rules._CRED_WORD)", None),
          ("ADVISORY (rules.advisory_phrases)", None)]


def md(rows, cols):
    return "\n".join(["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)] + ["| " + " | ".join(str(r[c]).replace("|", "\\|") for c in cols) + " |" for r in rows])


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def group_masks(texts):
    s = pd.Series(list(texts))
    otp, pin, code = s.map(lambda t: bool(OTP_RX.search(t))), s.map(lambda t: bool(PIN_RX.search(t))), s.map(lambda t: bool(CODE_RX.search(t)))
    deliv = s.map(lambda t: bool(DELIV_RX.search(t)))
    cred = s.map(lambda t: bool(_CRED_WORD.search(t)))
    adv = s.map(lambda t: bool(advisory_phrases(t)))
    return [otp, pin, code, deliv & (otp | pin | code), cred, adv]


def driver(r):
    """Why the final level is what it is, for a Report built by analyse()."""
    if r["level"] is None:
        return "can't judge"
    if r["escalated"]:
        return "rule floor (OTP / PIN rule; the text head said " + (NAME[r["text_level"]] if r["text_level"] is not None else "nothing") + ")"
    if r["text_level"] == r["level"]:
        return "text head"
    return "link / other"


def main():
    t0 = time.time()
    um = load_url_model(); load_gambling()
    base = load_baseline()
    cal = json.loads(CAL.read_text(encoding="utf-8"))["calibration"]
    mur = MurilScorer(config.MURIL_DIR, config.TEXT_DEVICE)
    assert abs(mur.thresholds[0] - cal["threshold_suspicious"]) < 1e-9 and abs(mur.thresholds[1] - cal["threshold_likely"]) < 1e-9, "the app's MuRIL is not the saved calibration"
    heads = {"MuRIL": mur, "TF-IDF": base}
    out = ["# Genuine OTP / PIN / delivery-code messages: MuRIL vs the TF-IDF head  (VAL for numbers, test reported only)", "",
           f"Generated by `python src/otp_muril.py`. Text head MuRIL `{config.MURIL_DIR.name}` (T {cal['temperature']:.3f}, Suspicious from {r3(mur.thresholds[0]):.3f}, Likely scam from {r3(mur.thresholds[1]):.3f}); "
           f"TF-IDF head `models/text_baseline.joblib` (the app's splits-v1 fit; Suspicious from {r3(base.thresholds[0]):.3f}, Likely scam from {r3(base.thresholds[1]):.3f}); "
           f"`split_map.csv` SHA-256 `{sha(SPLIT_MAP)}`. Nothing in the app, the model or the calibration was changed. `analyse()` runs with the safety-advice cap at its configured value "
           f"(`config.SAFETY_ADVICE_CAP` = {config.SAFETY_ADVICE_CAP}) unless a section says otherwise.", ""]

    # ---------------------------------------------------------------- 1. fixture
    new_fx = json.loads(FIXTURE.read_text(encoding="utf-8"))
    old_fx = json.loads(subprocess.run(["git", "show", "HEAD~1:frontend/src/lib/__fixtures__/reports.json"], cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    old_by = {x["label"]: x for x in old_fx}
    fx_rows, fx_r = [], {}
    for x in new_fx:
        lab, text = x["label"], x["text"]
        a_new, a_old = analyse(text, mur, um, safety_cap=False), analyse(text, base, um, safety_cap=False)
        fx_r[lab] = (text, a_old, a_new)
        # the fixture was made by to_report(); its level strings must agree with these runs (Can't judge / Promotional are outside the 0-2 scale)
        if x["report"]["level"] in LEVEL:
            assert LEVEL[x["report"]["level"]] == a_new["level"], f"{lab}: fixture (new) {x['report']['level']} != rerun {a_new['level']}"
        o = old_by[lab]["report"]["level"]
        if o in LEVEL:
            assert LEVEL[o] == a_old["level"], f"{lab}: fixture (old) {o} != rerun {a_old['level']}"
    moved = [lab for lab, (t, o, n) in fx_r.items() if o["level"] != n["level"]]
    for lab in moved:
        t, o, n = fx_r[lab]
        fx_rows.append({"id": f"`{lab}`", "text": t, "old (TF-IDF)": f"{NAME[o['level']]} (text {o['text_score']:.3f})",
                        "new (MuRIL)": f"{NAME[n['level']]} (text {n['text_score']:.3f})", "new driver": driver(n), "old driver": driver(o)})
    out += [f"## 1. Fixture: the {len(moved)} of {len(new_fx)} entries whose level moved", "",
            "Both heads were rerun here, `analyse(..., safety_cap=False)`, and agree with the committed fixture (new) and the previous commit's fixture (old) on every entry. "
            "**Driver** = what sets the final level: `text head` (the text level is the final level), `rule floor` (the OTP / PIN-to-receive rule lifted a message the text head had "
            "at a lower level), `link / other`. The texts are the hand-written, illustrative inputs of `tests/tricky_inputs.py` (no real messages); whether each is genuine or a scam "
            "is the label its author gave it there (`why` field), summarised in the last column.", ""]
    from tricky_inputs import INPUTS
    why = {x["id"]: x["why"] for x in INPUTS}
    for r_ in fx_rows:
        r_["what it is (tricky_inputs `why`)"] = why.get(r_["id"].strip("`"), "(demo / extra input)")
    out += [md(fx_rows, ["id", "text", "old (TF-IDF)", "new (MuRIL)", "new driver", "what it is (tricky_inputs `why`)"]), ""]
    ups = [lab for lab in moved if fx_r[lab][2]["level"] > fx_r[lab][1]["level"]]
    dns = [lab for lab in moved if fx_r[lab][2]["level"] < fx_r[lab][1]["level"]]
    out += [f"Raised: {len(ups)} ({', '.join('`' + u + '`' for u in ups)}). Lowered: {len(dns)} ({', '.join('`' + u + '`' for u in dns)}).", ""]

    # ---------------------------------------------------------------- 2. val
    sm = pd.read_csv(SPLIT_MAP, usecols=["text_hash", "split"])
    vh = set(sm.loc[sm["split"] == "val", "text_hash"])
    val = pd.concat([c[c["text_hash"].isin(vh)] for c in pd.read_csv(MESSAGES, usecols=["text_hash", "text", "label", "source"], chunksize=4000)], ignore_index=True)
    assert len(val) == len(vh) == 5267 and set(val["text_hash"]) == vh
    assert set(sm.set_index("text_hash").loc[val["text_hash"], "split"]) == {"val"}
    masks = group_masks(val["text"])
    anyg = np.logical_or.reduce([m.to_numpy() for m in masks])
    recs = {}
    for hn, h in heads.items():
        print(f"val, {hn} head ...", flush=True)
        rows = []
        for i, (t, lab) in enumerate(zip(val["text"], val["label"])):
            r = analyse(t, h, um, safety_cap=False)
            row = {"level": -1 if r["level"] is None else r["level"], "text_level": -1 if r["text_level"] is None else r["text_level"], "escalated": r["escalated"],
                   "cred": bool(r["cred_request"]), "pinr": bool(r["pin_to_receive"])}
            if anyg[i]:
                row["r"] = r
            rows.append(row)
        recs[hn] = rows
    D = {hn: pd.DataFrame([{k: v for k, v in row.items() if k != "r"} for row in rows]) for hn, rows in recs.items()}
    lab = val["label"].to_numpy()

    def cnt(d, mask, label):
        s = d[(lab == label) & mask]
        return [int((s["level"] == k).sum()) for k in range(3)]

    tab = []
    allmask = np.ones(len(val), bool)
    for gname, m in [("**all val messages**", pd.Series(allmask))] + list(zip([g[0] for g in GROUPS], masks)):
        m = m.to_numpy()
        row = {"group": gname, "benign n": int(((lab == 0) & m).sum()), "scam n": int(((lab == 1) & m).sum())}
        for hn in heads:
            b, s = cnt(D[hn], m, 0), cnt(D[hn], m, 1)
            row[f"{hn}: benign L0 / L1 / L2"] = " / ".join(map(str, b))
            row[f"{hn}: scam L0 / L1 / L2"] = " / ".join(map(str, s))
        tab.append(row)
    cols = ["group", "benign n", "scam n"] + [f"{hn}: {k} L0 / L1 / L2" for hn in heads for k in ("benign", "scam")]
    out += ["## 2. Val: the groups, by label and final level", "",
            "5,267 val messages. L0 = No warning signs, L1 = Suspicious, L2 = Likely scam; the final level of `analyse()` (text head + URL head + the OTP / PIN rule floors). "
            "The groups overlap. 24 messages are 'Can't judge' (too little text) in both heads and are in no L column.", "", md(tab, cols), ""]

    # why the benign messages in the groups are flagged
    anyc = np.logical_or.reduce([m.to_numpy() for m in masks[:5]])
    why_rows = []
    for hn in heads:
        d = D[hn]
        s = d[(lab == 0) & anyc & (d["level"] >= 1)]
        why_rows.append({"head": hn, "benign credential-group messages at L1 or L2": len(s),
                         "... set by the OTP / PIN rule floor (text head said No warning)": int(s["escalated"].sum()),
                         "... set by the text head": int((~s["escalated"] & (s["text_level"] == s["level"])).sum()),
                         "... of those at L2": int((s["level"] == 2).sum())})
    out += ["### Who flags the benign messages of the groups", "", md(why_rows, list(why_rows[0])), ""]
    fam = lambda t: re.sub(r"\d+", "#", t[:60])
    s = val[(lab == 0) & anyc & (D["MuRIL"]["level"] >= 1).to_numpy()]
    out += [f"The {len(s)} benign group messages that MuRIL flags are {s['text'].map(fam).nunique()} distinct openings (first 60 characters, digits folded), "
            f"{int(s['source'].eq('india_fraud_final').sum())} of them from `india_fraud_final` (templated, near-duplicate rows), "
            f"{int(s['source'].eq('phishing_email').sum())} from `phishing_email` (long e-mails that merely contain the word PIN, OTP or password).", ""]

    # ---------------------------------------------------------------- 3. test, cache only
    print("test (cache) ...", flush=True)
    sc = json.loads((CACHE / "scored.json").read_text(encoding="utf-8"))
    assert sha(CACHE / "predictions_test.csv") == sc["prediction_sha256"]["predictions_test.csv"]
    bsc = json.loads((BASE_CACHE / "scored.json").read_text(encoding="utf-8"))
    assert sha(BASE_CACHE / "predictions_test.csv") == bsc["prediction_sha256"]["predictions_test.csv"]
    th = set(sm.loc[sm["split"] == "test", "text_hash"])
    te = pd.concat([c[c["text_hash"].isin(th)] for c in pd.read_csv(MESSAGES, usecols=["text_hash", "text"], chunksize=4000)], ignore_index=True)
    pm, pb = pd.read_csv(CACHE / "predictions_test.csv"), pd.read_csv(BASE_CACHE / "predictions_test.csv")
    te = te.merge(pm[["text_hash", "label", "score"]], on="text_hash").merge(pb[["text_hash", "score"]].rename(columns={"score": "bscore"}), on="text_hash")
    assert len(te) == len(th)
    z = np.log(np.clip(te["score"], 1e-12, 1 - 1e-12) / (1 - np.clip(te["score"], 1e-12, 1 - 1e-12))) / cal["temperature"]
    te["mp"] = (1 / (1 + np.exp(-z))).round(3)
    from textprep import model_text   # noqa: F401  (the cached scores were made on model_text(); nothing is re-scored)
    te["rule"] = te["text"].map(lambda t: bool(cred_requests(t)) or bool(pin_to_receive(t)))
    lo, hi = r3(cal["threshold_suspicious"]), r3(cal["threshold_likely"])
    te["m_lvl"] = (te["mp"] >= lo).astype(int) + (te["mp"] >= hi).astype(int)
    te["b_lvl"] = (te["bscore"] >= bsc["threshold_suspicious"]).astype(int) + (te["bscore"] >= bsc["threshold_likely"]).astype(int)
    te["m_fin"], te["b_fin"] = np.where(te["rule"], np.maximum(te["m_lvl"], 1), te["m_lvl"]), np.where(te["rule"], np.maximum(te["b_lvl"], 1), te["b_lvl"])
    tm_ = group_masks(te["text"])
    trows = []
    for gname, m in [("**all test messages**", pd.Series(np.ones(len(te), bool)))] + list(zip([g[0] for g in GROUPS], tm_)):
        m = m.to_numpy()
        row = {"group": gname, "benign n": int(((te["label"] == 0) & m).sum()), "scam n": int(((te["label"] == 1) & m).sum())}
        for nm, c in (("MuRIL", "m_fin"), ("TF-IDF (splits-v2 refit)", "b_fin")):
            for k, l in (("benign", 0), ("scam", 1)):
                s = te[(te["label"] == l) & m]
                row[f"{nm}: {k} L0 / L1 / L2"] = " / ".join(str(int((s[c] == j).sum())) for j in range(3))
        trows.append(row)
    out += ["## 3. Test: the same groups (REPORTED ONLY; no choice depends on it)", "",
            f"From the cached test predictions (`reports/eval_preds/`, scored once, SHA-256 checked; MuRIL calibrated with the val T). Level = the text head's level, lifted to "
            f"Suspicious where the OTP / PIN rule fires (`rule floor`); links, the URL head and the other floors are not applied, so these are not full Reports. The TF-IDF column is "
            f"the splits-v2 refit that `eval_text_head.py` scored (cut-offs {bsc['threshold_suspicious']:.3f} / {bsc['threshold_likely']:.3f}), not the app's older splits-v1 file. "
            "Test is real held-out data of the same sources; its benign class has one templated source (`india_fraud_final`) too.", "",
            md(trows, ["group", "benign n", "scam n"] + [f"{nm}: {k} L0 / L1 / L2" for nm in ("MuRIL", "TF-IDF (splits-v2 refit)") for k in ("benign", "scam")]), ""]

    # ---------------------------------------------------------------- 4. candidate fixes, simulated
    print("candidate fixes ...", flush=True)
    def genuine_guard(text, r):
        """A: a Likely scam that only the text head produced, with a credential / code word and nothing else around it that looks like a scam, goes to Suspicious (never lower)."""
        if r["level"] != 2 or r["text_level"] != 2 or r["escalated"] or r["cred_request"] or r["pin_to_receive"]:
            return False
        if r["links"] or has_indian_mobile(text) or r["tags"]["isolation"] or r["tags"]["urgency"]:
            return False
        return bool(OTP_RX.search(text) or PIN_RX.search(text) or CODE_RX.search(text) or _CRED_WORD.search(text))

    def deliv_exempt(text, r):
        """B: the OTP rule's hit is in a delivery-PIN sentence ("only at delivery", "to the delivery agent"): do not floor to Suspicious. Only when the text head says No warning signs."""
        return bool(r["escalated"] and r["cred_request"] and not r["pin_to_receive"] and r["text_level"] == 0 and DELIV_PIN_RX.search(text) and not r["links"]
                    and not has_indian_mobile(text) and not r["tags"]["isolation"] and not r["tags"]["urgency"])

    def adv_cap(text, r):
        """C: the existing safety-advice cap switched on (Suspicious -> No warning signs for 'never share your OTP' advice)."""
        return not safety_advice_cap(text, r)[1] and r["level"] == 1

    OPTS = [("A. genuine-format guard: Likely scam from the text head alone -> Suspicious", genuine_guard, 1),
            ("B. delivery-PIN exemption: OTP-rule floor not applied to 'share PIN only at delivery' sentences", deliv_exempt, 0),
            ("C. the existing safety-advice cap switched on (`SAFETY_ADVICE_CAP`)", adv_cap, 0)]
    mr = recs["MuRIL"]
    orows = []
    for oname, fn, to in OPTS:
        hit_b, hit_s = [], []
        for i, row in enumerate(mr):
            if "r" not in row:
                continue
            if fn(val["text"].iat[i], row["r"]):
                (hit_b if lab[i] == 0 else hit_s).append(i)
        ben_before = pd.Series([mr[i]["level"] for i in hit_b], dtype=int)
        scam_before = pd.Series([mr[i]["level"] for i in hit_s], dtype=int)
        nb = len(hit_b)
        # fixture
        fx_hit = [l for l, (t, o, n) in fx_r.items() if fn(t, n)]
        orows.append({"candidate": oname, "val benign it changes": nb, "val scam it changes": len(hit_s),
                      "... of those, scam that loses a flag": int((scam_before >= (2 if to == 1 else 1)).sum()),
                      "fixture entries it changes": ", ".join(f"`{l}`" for l in fx_hit) or "(none)"})
    # val totals before / after
    d = D["MuRIL"]
    tot = {"benign Suspicious or above": int((d.loc[lab == 0, "level"] >= 1).sum()), "benign Likely scam": int((d.loc[lab == 0, "level"] == 2).sum()),
           "scam Likely scam": int((d.loc[lab == 1, "level"] == 2).sum()), "scam Suspicious or above": int((d.loc[lab == 1, "level"] >= 1).sum())}
    out += ["## 4. What the candidate fixes would do (simulated after `analyse()`; the app is unchanged)", "",
            f"Val totals now (MuRIL): benign flagged at Suspicious or above {tot['benign Suspicious or above']} of {int((lab == 0).sum())}, benign at Likely scam {tot['benign Likely scam']}; "
            f"scam at Likely scam {tot['scam Likely scam']} of {int((lab == 1).sum())}, scam at Suspicious or above {tot['scam Suspicious or above']}.", "",
            md(orows, list(orows[0].keys())), ""]
    # which val scam the guard would lower, and what the same two conditions would touch on test (cached scores; reported only, not used to choose)
    a_scam_src = [val["source"].iat[i] for i, row in enumerate(mr) if "r" in row and lab[i] == 1 and genuine_guard(val["text"].iat[i], row["r"])]
    from pii import mask_text
    from textprep import extract_urls
    from shield.messages.tactics import tactic_tags

    def quiet(t, rule):
        tg = tactic_tags(mask_text(t), cred_requests(t))
        return not extract_urls(t) and not has_indian_mobile(t) and not tg["isolation"] and not tg["urgency"]

    wordy = te["text"].map(lambda t: bool(OTP_RX.search(t) or PIN_RX.search(t) or CODE_RX.search(t) or _CRED_WORD.search(t)))
    qa = te["text"].map(lambda t: quiet(t, False))
    a_te = (te["m_lvl"] == 2) & ~te["rule"] & wordy & qa
    b_te = (te["m_lvl"] == 0) & te["rule"] & te["text"].map(lambda t: bool(DELIV_PIN_RX.search(t))) & qa & te["text"].map(lambda t: bool(cred_requests(t))) & ~te["text"].map(lambda t: bool(pin_to_receive(t)))
    out += ["### Reported only: the same conditions on test (cached text scores; no choice depends on it)", "",
            md([{"candidate": "A (text level Likely scam, no rule, credential / code word, no link / mobile / isolation / urgency)", "test benign it would change": int((a_te & (te["label"] == 0)).sum()),
                 "test scam it would change": int((a_te & (te["label"] == 1)).sum())},
                {"candidate": "B (OTP rule fires on a delivery-PIN sentence, text level No warning, same quiet conditions)", "test benign it would change": int((b_te & (te["label"] == 0)).sum()),
                 "test scam it would change": int((b_te & (te["label"] == 1)).sum())}], ["candidate", "test benign it would change", "test scam it would change"]), "",
            f"Val scam that A would lower: {len(a_scam_src)} ({', '.join(a_scam_src) or '-'}).", ""]
    out += [f"_Runtime {time.time() - t0:.0f} s._", ""]
    REPORT.write_text("\n".join(out), encoding="utf-8")
    print("wrote", REPORT.relative_to(ROOT), f"({time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()
