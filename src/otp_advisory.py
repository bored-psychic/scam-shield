"""Genuine "never share your OTP" messages that come out Suspicious: why, and does a capped rule fix it safely?   (VAL only: the test split is never read or scored.)

    python src/otp_advisory.py          -> reports/otp_advisory.md

1. The 8 genuine OTP advisories of tests/tricky_inputs.py (the ones the OTP rule rightly ignores): text score, level, the strongest n-grams, and what the
   head does when only the negation is removed.
2. ADVISORY on val: the messages that warn against sharing an OTP / PIN / CVV (rules.advisory_phrases), by label, level and source. Counts only, no message text.
3. The safety-advice cap (router.safety_advice_cap, flag config.SAFETY_ADVICE_CAP) on val, with the real models: benign messages moved from Suspicious
   to No warning signs, scam messages moved the same way (newly missed), per source; which conditions stop the cap; and what happens when a scammer pastes
   the warning sentence onto a scam that is already flagged (a synthetic probe built from val scam rows in memory, nothing is saved).
4. The gate (CLAUDE.md-style, set by the user): the cap is enabled by default only if it misses no scam on val, clears at least 4 of the 5 flagged advisories,
   and tests/test_tricky_inputs.py and tests/test_contracts.py pass with the cap on and off.

Nothing is saved except the report. models/, data/, textprep.py, baseline.py and the split map are only read. The test split is not loaded: val rows are picked
by text_hash from split_map.csv, and an assertion checks that every row used is a val row.

The "## Interpretation" section of the report is written by hand from the numbers; a rerun regenerates everything above it and keeps that section
(with a Stale warning if the numbers above it changed).
"""
import hashlib, re, sys, time
from pathlib import Path
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
from textprep import model_text
from shield import config
from shield.core.router import analyse, safety_advice_cap
from shield.core.verdict import r3
from shield.links.lexical import load_url_model
from shield.links.gambling import load_gambling
from shield.messages.rules import advisory_phrases, _CRED_WORD
from shield.messages.text_head import load_text_model
import test_contracts, test_tricky_inputs
from tricky_inputs import INPUTS

MESSAGES, SPLIT_MAP, REPORT = ROOT / "data/final/messages.csv", ROOT / "data/final/split_map.csv", ROOT / "reports/otp_advisory.md"
LEVELS = ["No warning signs", "Suspicious", "Likely scam"]
# The 8 genuine OTP advisories of tests/tricky_inputs.py whose OTP-rule verdict is "not a request" (BUGS.md: 5 of them came out Suspicious).
ADVISORIES = ["otp-alert-do-not-share", "otp-advisory-never", "otp-bank-will-never-ask", "otp-disclose", "otp-enter-to-confirm", "otp-keep-confidential",
              "otp-negation-aside", "otp-negation-aside-short"]
NEGATION_HOLES = ["Don't hesitate to share your OTP.", "Please do not worry and send the OTP to our agent",
                  "Do not hesitate to share your OTP with our executive to complete KYC.", "Don't delay and share your OTP now"]
STAY_FLAGGED = [("advice-with-mobile-number", "has a mobile number"), ("advice-with-link", "has a link"), ("advice-with-urgency", "urgency cue")]
# Pure negation removals (nothing else changes): does the head notice the negation?
TWINS = [("Never share your OTP, PIN or CVV with anyone, including bank staff.", "Share your OTP, PIN or CVV with anyone, including bank staff."),
         ("Bank will never ask you to share your OTP or PIN. Beware of fraud.", "Bank will ask you to share your OTP or PIN. Beware of fraud."),
         ("Please do not share your OTP with anyone. Enter OTP 482913 to confirm your login.", "Please share your OTP with anyone. Enter OTP 482913 to confirm your login."),
         ("Do not, under any circumstances, share your OTP with anyone.", "Under any circumstances, share your OTP with anyone.")]
# What a scammer could paste onto a scam to get it capped.
SHORT = 300   # characters: an SMS-sized message (the length of the original val scam, before the sentence is appended)
APPENDS = [" Never share your OTP with anyone.", " Bank will never ask you to share your OTP or PIN."]


def md(df):
    if df.empty:
        return "(none)"
    cols = [str(c) for c in df.columns]
    rows = [cols, ["---"] * len(cols)] + [[str(v).replace("|", "\\|") for v in row] for row in df.itertuples(index=False)]
    return "\n".join("| " + " | ".join(r) + " |" for r in rows)

def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def load_val():
    """The val rows only: picked by text_hash from split_map.csv, chunk by chunk, so no test row is ever kept."""
    sm = pd.read_csv(SPLIT_MAP, usecols=["text_hash", "split"])
    val_hashes = set(sm.loc[sm["split"] == "val", "text_hash"])
    parts = [c[c["text_hash"].isin(val_hashes)] for c in pd.read_csv(MESSAGES, usecols=["text_hash", "text", "label", "source"], chunksize=4000)]
    val = pd.concat(parts, ignore_index=True)
    assert len(val) == len(val_hashes) and set(val["text_hash"]) == val_hashes, "val rows do not match the split map"
    assert set(sm.set_index("text_hash").loc[val["text_hash"], "split"]) == {"val"}
    return val

def contribs(tm, prepared):
    x = tm.vec.transform([prepared])
    return x.data * tm.coef[x.indices]

def ngram_cell(tm, prepared):
    return ", ".join(f"`{g!r}` {c:+.3f}" for g, c in tm.explain(prepared, k=8))

def counts(df, col):
    """label x level counts for a frame, as the columns benign L0..L2, scam L0..L2."""
    out = {}
    for lab, name in ((0, "benign"), (1, "scam")):
        sub = df[df["label"] == lab]
        for lv in range(3):
            out[f"{name} L{lv}"] = int((sub[col] == lv).sum())
    return out


def main():
    t0 = time.time()
    tm, um = load_text_model(), load_url_model()
    load_gambling()
    val = load_val()
    out = [f"# OTP safety advice: why genuine warnings come out Suspicious, and a gated cap  (VAL only)", "",
           "Generated by `src/otp_advisory.py`. **Only the val split was read**: the test split is not loaded (val rows are picked by `text_hash` from `split_map.csv` and "
           f"asserted to be val). `split_map.csv` SHA-256 `{sha256(SPLIT_MAP)}`; text head file `{config.model_versions()['text']}`, URL head `{config.model_versions()['url']}`; "
           f"Suspicious from {r3(tm.thresholds[0]):.3f}, Likely scam from {r3(tm.thresholds[1]):.3f}. Nothing was saved except this file. "
           "No val message text appears below (counts only); the messages quoted in sections 1 and 3 are test inputs written in `tests/tricky_inputs.py`.", "",
           "**ADVISORY** = `rules.advisory_phrases(text)` is non-empty: a send / share / forward / give / provide / tell / disclose / reveal / ask-for verb next to OTP, PIN or CVV in the "
           "same sentence, under a negation (the request rule's own negation test, `rules._negated`). Not ADVISORY, on purpose: the pronoun form (\"Your OTP is 482913. Do not share it with anyone.\") and "
           "the affirmative \"Keep your OTP confidential\".", "",
           "**The cap** (`router.safety_advice_cap`, lowers Suspicious to No warning signs) applies only if ALL hold: an ADVISORY phrase; no OTP / PIN / CVV request; text level is Suspicious "
           "(never Likely scam) and so is the verdict; no link at all; no Indian mobile number (toll-free 1800 numbers are fine); no isolation cue; no urgency cue; no gambling hit.", ""]

    # ------------------------------------------------------------------ 1. the 8 advisories
    by_id = {x["id"]: x for x in INPUTS}
    rows, flagged_ids, lowered = [], [], []
    for i in ADVISORIES:
        text = by_id[i]["text"]
        off, on = analyse(text, tm, um, safety_cap=False), analyse(text, tm, um, safety_cap=True)
        prepared = model_text(text, mask_pii=True)
        _, blockers = safety_advice_cap(text, off)
        c = contribs(tm, prepared)
        if off["level"] == 1:
            flagged_ids.append(i)
            if on["level"] == 0:
                lowered.append(i)
        rows.append({"id": f"`{i}`", "text": text, "score": f"{off['text_score']:.3f}", "level": LEVELS[off["level"]], "with cap": LEVELS[on["level"]],
                     "blocked by": ", ".join(blockers) or "(none: cap applies)",
                     "intercept / sum of + / sum of -": f"{tm.clf.intercept_[0]:+.2f} / {c[c > 0].sum():+.2f} / {c[c < 0].sum():+.2f}",
                     "top 8 n-grams (contribution to the logit)": ngram_cell(tm, prepared)})
    out += ["## 1. The 8 genuine OTP advisories", "",
            f"{len(flagged_ids)} of the 8 are Suspicious with the cap off (`{'`, `'.join(flagged_ids)}`). The head is TF-IDF over character 2-4-grams inside words (`char_wb`) + logistic regression; "
            "a contribution is the n-gram's TF-IDF weight times its coefficient, and the logit is the intercept plus the sum of them (`TfidfLrScorer.explain`).", "",
            md(pd.DataFrame(rows)), "",
            "### Does the head see the negation?", "",
            "The same sentences with only the negation taken out (a request instead of a warning). If the head understood \"never\", the request would score clearly higher.", ""]
    tw = []
    for a, b in TWINS:
        sa, sb = tm.score(model_text(a, mask_pii=True)), tm.score(model_text(b, mask_pii=True))
        tw.append({"warning": a, "score": f"{sa:.3f}", "same sentence without the negation": b, "score ": f"{sb:.3f}", "request minus warning": f"{sb - sa:+.3f}"})
    out += [md(pd.DataFrame(tw)), ""]

    # ------------------------------------------------------------------ 2. + 3. val, cap off and on
    print(f"analysing {len(val)} val rows twice (cap off, cap on) ...", flush=True)
    recs = []
    for text, lab, src in zip(val["text"], val["label"], val["source"]):
        off = analyse(text, tm, um, safety_cap=False)
        on = analyse(text, tm, um, safety_cap=True)
        phrases, blockers = safety_advice_cap(text, off)
        recs.append({"label": int(lab), "source": src, "advisory": bool(advisory_phrases(text)), "cred_word": bool(_CRED_WORD.search(text)),
                     "off": off["level"], "on": on["level"], "fired": bool(on.get("safety_advice")), "blockers": blockers,
                     "cant_judge": off["level"] is None})
    d = pd.DataFrame(recs)
    assert (d["off"].isna() == d["on"].isna()).all()
    d["off"], d["on"] = d["off"].fillna(-1).astype(int), d["on"].fillna(-1).astype(int)   # -1 = Can't judge (too little text)
    changed = d[d["off"] != d["on"]]
    integrity = (len(changed) == int(d["fired"].sum()) and bool(((changed["off"] == 1) & (changed["on"] == 0)).all())
                 and bool((d.loc[d["fired"], "off"] == 1).all()) and bool(((d["on"] == 0) & (d["off"] == 1)).sum() == d["fired"].sum())
                 and bool(d.loc[d["fired"], "blockers"].map(len).eq(0).all()) and bool(d.loc[~d["fired"], "blockers"].map(len).gt(0).all()))
    assert integrity, "cap-on levels differ from cap-off levels by something other than the cap firing, or analyse() and safety_advice_cap() disagree"

    adv = d[d["advisory"]]
    tab = []
    for src, g in list(d.groupby("source")) + [("**all val**", d)]:
        ga = g[g["advisory"]]
        row = {"source": src, "val rows": len(g), "ADVISORY rows": len(ga)}
        row.update(counts(ga, "off"))
        if len(ga) or src == "**all val**":
            tab.append(row)
    omitted = sorted(set(d["source"]) - {r["source"] for r in tab})
    out += ["## 2. ADVISORY messages on val, by label and level (cap off)", "",
            "Level = the verdict of `analyse()` with the cap off. L0 = No warning signs, L1 = Suspicious, L2 = Likely scam (Can't judge rows, if any, are in no column).", "",
            md(pd.DataFrame(tab)), "",
            f"Sources with no ADVISORY row: {', '.join(omitted) or '(none)'}.", ""]
    gap = []
    for src, g in list(d.groupby("source")) + [("**all val**", d)]:
        b1 = g[(g["label"] == 0) & (g["off"] == 1)]
        if len(b1):
            gap.append({"source": src, "benign, Suspicious": len(b1), "... of them ADVISORY": int(b1["advisory"].sum()),
                        "... mention OTP / PIN / CVV / password but are not ADVISORY": int((b1["cred_word"] & ~b1["advisory"]).sum()),
                        "... no credential word": int((~b1["cred_word"]).sum())})
    out += ["### How much of the benign-Suspicious problem is this?", "",
            "Benign val messages that come out Suspicious, split by whether the warning pattern is there. Only the first column of counts can be touched by the cap.", "",
            md(pd.DataFrame(gap)), ""]

    fired = d[d["fired"]]
    per = []
    for src, g in list(d.groupby("source")) + [("**all val**", d)]:
        e = g[(g["advisory"]) & (g["off"] == 1)]
        f = g[g["fired"]]
        per.append({"source": src, "ADVISORY and Suspicious: benign": int((e["label"] == 0).sum()), "ADVISORY and Suspicious: scam": int((e["label"] == 1).sum()),
                    "cap fired: benign fixed (1 -> 0)": int((f["label"] == 0).sum()), "cap fired: scam newly missed (1 -> 0)": int((f["label"] == 1).sum())})
    per = [p for p in per if p["source"] == "**all val**" or p["ADVISORY and Suspicious: benign"] or p["ADVISORY and Suspicious: scam"]]
    n_fixed, n_missed = int((fired["label"] == 0).sum()), int((fired["label"] == 1).sum())
    out += ["## 3. The cap on val, with the real models", "",
            f"Every val row ({len(d)}) was analysed with the cap off and on. The only difference is the {len(fired)} rows where the cap fired, all Suspicious -> No warning signs "
            "(asserted; `analyse()` and `safety_advice_cap()` agree on every row).", "",
            md(pd.DataFrame(per)), "",
            "### What stops the cap on the ADVISORY + Suspicious rows", "",
            "A row can be stopped by several conditions at once, so the columns do not add up to the row count.", ""]
    e = adv[adv["off"] == 1]
    names = ["credential request", "has a link", "has a mobile number", "isolation cue", "urgency cue", "gambling hit"]
    bl = [{"condition": n, "benign": int(e[e["label"] == 0]["blockers"].map(lambda b: n in b).sum()), "scam": int(e[e["label"] == 1]["blockers"].map(lambda b: n in b).sum())} for n in names]
    bl.append({"condition": "(none) -> the cap fires", "benign": n_fixed, "scam": n_missed})
    out += [md(pd.DataFrame(bl)), ""]

    # ---- the paste-the-warning probe
    scams = val[(val["label"] == 1)].reset_index(drop=True)
    sd = d[d["label"] == 1].reset_index(drop=True)
    flagged = scams[sd["off"] >= 1].reset_index(drop=True)
    print(f"append probe on {len(flagged)} flagged val scams ...", flush=True)
    probe = []
    for ap in APPENDS:
        res = []
        for text, src in zip(flagged["text"], flagged["source"]):
            t2 = text + ap
            r = analyse(t2, tm, um, safety_cap=False)
            _, b = safety_advice_cap(t2, r)
            res.append({"source": src, "off": r["level"], "capped": r["level"] == 1 and not b, "long": bool(r.get("truncated")), "short": len(text) <= SHORT})
        res = pd.DataFrame(res)
        probe.append({"pasted sentence": f"`{ap.strip()}`", "flagged val scams": len(res), "still flagged without the cap": int((res["off"] >= 1).sum()),
                      "cleared by the cap (Suspicious -> No warning)": int(res["capped"].sum()),
                      "... of them longer than the head reads (the pasted sentence is past the cut)": int((res["capped"] & res["long"]).sum()),
                      f"flagged scams of {SHORT} characters or fewer (SMS length): cleared / all": f"{int((res['capped'] & res['short']).sum())} / {int(res['short'].sum())}",
                      "where": ", ".join(f"{s} {n}" for s, n in res[res["capped"]]["source"].value_counts().items()) or "-"})
    out += ["### A scammer pastes the warning onto a scam (synthetic probe)", "",
            f"The {len(flagged)} val scam messages that are Suspicious or Likely scam with the cap off, each with one warning sentence appended. The probe is built in memory from val rows; "
            "nothing is saved. \"Cleared by the cap\" counts rows that the head alone would still have flagged.", "",
            md(pd.DataFrame(probe)), ""]

    # ---- requests the negation test reads as warnings
    ph = []
    for text in NEGATION_HOLES:
        off = analyse(text, tm, um, safety_cap=False)
        _, b = safety_advice_cap(text, off)
        ph.append({"text": text, "OTP rule fires": "yes" if off["cred_request"] else "NO", "ADVISORY": "yes" if advisory_phrases(text) else "no",
                   "text score": f"{off['text_score']:.3f}", "level, cap off": LEVELS[off["level"]], "level, cap on": LEVELS[analyse(text, tm, um, safety_cap=True)["level"]],
                   "blocked by": ", ".join(b) or "(none: cap applies)"})
    out += ["### Requests that the negation test reads as warnings", "",
            "`rules._NEG_BEFORE` accepts a negation up to three words before the verb, so \"do not hesitate to share your OTP\" counts as negated. That is a gap in the OTP rule itself "
            "(rows marked NO are requests it misses) and it makes such a request look like ADVISORY. Today none of these is Suspicious, so the cap does not touch them; "
            "one that the head put at Suspicious, with nothing else suspicious around it, would be lowered.", "",
            md(pd.DataFrame(ph)), ""]

    # ---- the three entries that must stay flagged
    st = []
    for i, want in STAY_FLAGGED:
        text = by_id[i]["text"]
        r = analyse(text, tm, um, safety_cap=False)
        _, b = safety_advice_cap(text, r)
        r_on = analyse(text, tm, um, safety_cap=True)
        st.append({"id": f"`{i}`", "text": text, "level, cap off": LEVELS[r["level"]], "level, cap on": LEVELS[r_on["level"]], "blocked by": ", ".join(b)})
    out += ["### The three entries that must stay flagged", "", md(pd.DataFrame(st)), ""]

    # ------------------------------------------------------------------ 4. gate
    print("running the tricky-input and contract checks ...", flush=True)
    tm_, um_ = tm, um
    tricky_bad = {x["id"]: b for x in INPUTS if (b := test_tricky_inputs.check(x, tm_, um_))}
    contract_bad = {}
    for cap in (False, True):
        _, fails, _ = test_contracts.run(cap)
        contract_bad[cap] = {a: len(m) for a, m in fails.items() if m}
    c1 = n_missed == 0
    c2 = len(lowered) >= 4
    c3 = not tricky_bad
    c4 = not any(contract_bad.values())
    ok = c1 and c2 and c3 and c4
    gate = [{"condition": "scam messages newly missed on val (cap fired on a scam)", "required": "0", "value": n_missed, "met": "yes" if c1 else "NO"},
            {"condition": f"of the {len(flagged_ids)} flagged advisories, how many go to No warning signs", "required": ">= 4", "value": f"{len(lowered)} of {len(flagged_ids)}", "met": "yes" if c2 else "NO"},
            {"condition": "tests/test_tricky_inputs.py, every entry, cap off and on", "required": "all pass", "value": f"{len(INPUTS) - len(tricky_bad)}/{len(INPUTS)}" + (f" (fail: {', '.join(tricky_bad)})" if tricky_bad else ""), "met": "yes" if c3 else "NO"},
            {"condition": "tests/test_contracts.py A1-A15, cap off and on", "required": "0 failures", "value": "0 failures" if c4 else f"failures: {contract_bad}", "met": "yes" if c4 else "NO"}]
    out += ["## 4. The gate", "",
            md(pd.DataFrame(gate)), "",
            f"**Gate: {'PASSED' if ok else 'NOT PASSED'}.** `config.SAFETY_ADVICE_CAP` is currently **{'ON' if config.SAFETY_ADVICE_CAP else 'OFF'}** (this report does not change it; `analyse()` runs above force the cap on or off). "
            f"On val the cap fixed {n_fixed} benign and missed {n_missed} scam messages of {len(d)}.", ""]
    n_elig = int(((d["advisory"]) & (d["off"] == 1)).sum())
    if len(fired) < 10:
        out += [f"**The val check has almost no power.** The cap fired on {len(fired)} of {len(d)} rows: {len(adv)} val rows are ADVISORY, {n_elig} of them Suspicious. "
                "\"0 scams newly missed\" is therefore true but would also be true of a rule that does nothing; it says nothing about how the cap behaves on scams. "
                "The paste probe in section 3 is the measurement that can show it, and the benefit side rests on the hand-written inputs of section 1.", ""]

    body = "\n".join(out)
    stamp = hashlib.sha256(body.encode()).hexdigest()[:12]
    old = REPORT.read_text(encoding="utf-8") if REPORT.exists() else ""
    m = re.search(r"\n## Interpretation\n(.*)\Z", old, re.S)
    interp = re.sub(r"\A(?:> \*\*Stale:\*\*[^\n]*\n\n)+", "", m.group(1).strip("\n")) if m else "(not yet written)"   # drop warnings from earlier reruns
    stale = re.search(r"<!-- numbers: ([0-9a-f]{12}) -->", interp)
    if m and interp != "(not yet written)" and (not stale or stale.group(1) != stamp):
        interp = "> **Stale:** the tables above changed after this section was written; re-read it before quoting it.\n\n" + interp
    REPORT.write_text(body + "\n\n## Interpretation\n" + interp + "\n", encoding="utf-8")
    print(f"wrote {REPORT.relative_to(ROOT)} (numbers stamp {stamp}); gate {'PASSED' if ok else 'NOT PASSED'}; runtime {time.time() - t0:.0f}s")

if __name__ == "__main__":
    main()
