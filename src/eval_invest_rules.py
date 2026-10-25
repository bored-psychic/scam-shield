"""Evaluation of the investment-scam rules A1-A12 (docs/plans/investment_scams.md Phase A) -> reports/investment_rules_v1.md.

    .venv/bin/python src/eval_invest_rules.py            # both heads, the full router (live=False: no network)

1. Probe v1 (data/probe/investment_v1.csv, PROBE-ONLY): the app with the rules off vs on, both text heads, plus what the rules catch alone, per rule.
   UPPER BOUND: the rules were written after reading this probe, and most of its rows were written by us. It is not a held-out score.
2. Val, every row of the val split (all sources, 4,115 genuine / 1,152 scam): how often each rule fires, each genuine hit listed. Val text is PII-masked,
   so A1 (a UPI id) is run with the stored tokens <UPI_ID> / <EMAIL> read as a non-@valid handle (a proxy; no stored row has a @valid id). The first
   version of several rules fired on 15 genuine val rows (long-form emails and job posts); the guards in invest_rules.py were added for them, so
   "0 genuine hits on val" is by construction, not an independent check. The train split's genuine hits are counted too (regex only, same proxy).
3. Val, the whole app (router.analyse, MuRIL and the TF-IDF baseline, rules off vs on): F1, precision and recall of "flagged" (Suspicious or Likely
   scam), and every row whose level changed.
No test-split row is read: messages.csv is streamed and a row whose split is not val / train is skipped before its text is used (CLAUDE.md rule 1).
"""
import csv, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]
csv.field_size_limit(sys.maxsize)

from shield.messages.invest_rules import RULES, invest_rule_hits

MESSAGES = ROOT / "data" / "final" / "messages.csv"
PROBE = ROOT / "data" / "probe" / "investment_v1.csv"
REPORT = ROOT / "reports" / "investment_rules_v1.md"
CODES = [r[0] for r in RULES]
NAME = {r[0]: r[4] for r in RULES}


def rows_of(split):
    with open(MESSAGES, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["split"] != split:   # test rows are skipped here, before anything else of them is used
                continue
            yield r


def proxy(text):
    """Stored text has <UPI_ID> / <EMAIL> where a handle was: read them as a plain non-@valid UPI handle so A1 can be counted at all."""
    return re.sub(r"<(?:UPI_ID|EMAIL)>", "x@ybl", text)[:20000]


def frac(k, n):
    return f"{k}/{n} ({k / n:.0%})" if n else "0/0"


def f1(tp, fp, fn):
    return 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else float("nan")


class Cached:
    """A text head that remembers its scores, so running the router twice (rules off, rules on) scores each message once."""
    def __init__(self, head):
        self._h, self._c = head, {}
    def score(self, text):
        if text not in self._c:
            self._c[text] = self._h.score(text)
        return self._c[text]
    def __getattr__(self, name):
        return getattr(self._h, name)


def heads():
    from shield import config
    from shield.messages.text_head import MurilScorer, load_baseline
    return {"MuRIL (the app)": Cached(MurilScorer(config.MURIL_DIR, config.TEXT_DEVICE)), "TF-IDF baseline": Cached(load_baseline())}


def levels(texts, head, um, rules):
    from shield.core.router import analyse
    return [analyse(t, head, um, invest_rules=rules)["level"] for t in texts]


def flagged(lv):
    return [l is not None and l >= 1 for l in lv]


def main():
    from shield.links.gambling import load_gambling
    from shield.links.lexical import load_url_model
    from shield.links.lists import warm
    load_gambling()
    warm()
    um = load_url_model()
    hs = heads()
    L = ["# Investment-scam rules A1-A12: evaluation", "",
         "`src/eval_invest_rules.py`, offline (`live=False`), 2026-10-25. Rules: `src/shield/messages/invest_rules.py`. Plan: `docs/plans/investment_scams.md`. "
         "No test-split row was read.", ""]

    # ---------------------------------------------------------------- 1. probe
    probe = list(csv.DictReader(open(PROBE, encoding="utf-8", newline="")))
    S = [r for r in probe if r["label"] == "1"]
    G = [r for r in probe if r["label"] == "0"]
    texts = [r["text"] for r in probe]
    L += ["## 1. Probe v1 (PROBE-ONLY): the app without and with the rules", "",
          "**Upper bound: the rules were written after reading the probe, and 45 of its 54 scam rows and all 48 genuine rows were written by us from cited "
          "descriptions.** Flagged = Suspicious or Likely scam. 'Without' = `analyse(..., invest_rules=False)` with the current masks (the @valid mask fix "
          "is in both columns).", "",
          "| head | rules | scams flagged | scams at Likely scam | genuine flagged (false alarms) | genuine at Likely scam |", "|---|---|---|---|---|---|"]
    probe_lv = {}
    for hname, head in hs.items():
        for rules in (False, True):
            lv = levels(texts, head, um, rules)
            probe_lv[(hname, rules)] = lv
            ls = [l or 0 for l, r in zip(lv, probe) if r["label"] == "1"]
            lg = [l or 0 for l, r in zip(lv, probe) if r["label"] == "0"]
            L.append(f"| {hname} | {'on' if rules else 'off'} | {frac(sum(x >= 1 for x in ls), len(ls))} | {sum(x == 2 for x in ls)} | "
                     f"{frac(sum(x >= 1 for x in lg), len(lg))} | {sum(x == 2 for x in lg)} |")
    m_off, m_on = probe_lv[("MuRIL (the app)", False)], probe_lv[("MuRIL (the app)", True)]
    gained = [r["id"] for r, a, b in zip(probe, m_off, m_on) if r["label"] == "1" and (a or 0) < 1 <= (b or 0)]
    up = [r["id"] for r, a, b in zip(probe, m_off, m_on) if r["label"] == "1" and (a or 0) == 1 and b == 2]
    newfa = [r["id"] for r, a, b in zip(probe, m_off, m_on) if r["label"] == "0" and (b or 0) > (a or 0)]
    L += ["", f"MuRIL + rules: scams newly flagged: {len(gained)} ({' '.join(gained)}); raised from Suspicious to Likely scam: {len(up)} ({' '.join(up)}); "
          f"genuine rows raised: {len(newfa)} ({' '.join(newfa) or 'none'}).", ""]
    sebi = [r["id"] for r in G if r["kind"] == "valid_upi_template"]
    L += [f"SEBI's own @valid templates ({' '.join(sebi)}): rules fire on {sum(bool(invest_rule_hits(r['text'])) for r in G if r['id'] in sebi)} of {len(sebi)} "
          "(the templates are still Likely scam from MuRIL itself; that is a text-head problem, Phase B).", ""]
    L += ["What the rules catch alone:", "", "| rule | name | scams caught /54 | genuine fired /48 | new on top of MuRIL (scams MuRIL left unflagged) |", "|---|---|---|---|---|"]
    hits = {r["id"]: {h["code"] for h in invest_rule_hits(r["text"])} for r in probe}
    off_lv = dict(zip((r["id"] for r in probe), m_off))
    union_s = set()
    for c in CODES:
        cs = [r["id"] for r in S if c in hits[r["id"]]]
        cg = [r["id"] for r in G if c in hits[r["id"]]]
        new = [i for i in cs if (off_lv[i] or 0) < 1]
        union_s |= set(cs)
        L.append(f"| {c} | {NAME[c]} | {len(cs)} | {len(cg)}{' (' + ' '.join(cg) + ')' if cg else ''} | {len(new)} {' '.join(new)} |")
    L += [f"| any | | {len(union_s)} | {sum(bool(hits[r['id']]) for r in G)} | |", ""]
    missed = [r["id"] for r in S if not hits[r["id"]]]
    L += [f"Scams no rule catches ({len(missed)}): {' '.join(missed)}. Among them the first-stage messages that ask for nothing (s52, s53) and the fake testimonial (s51): "
          "nothing in the text to catch.", ""]

    # ---------------------------------------------------------------- 2. val / train fire counts
    def fire_table(split, title):
        fires = {c: {"0": [], "1": []} for c in CODES}
        n = Counter()
        for r in rows_of(split):
            n[r["label"]] += 1
            for h in invest_rule_hits(proxy(r["text"])):
                fires[h["code"]][r["label"]].append((r["source"], r["text_hash"][:8], h["quote"][:70]))
        out = [f"### {title}: {n['0']} genuine, {n['1']} scam rows", "", "| rule | name | genuine fired | scam fired |", "|---|---|---|---|"]
        for c in CODES:
            out.append(f"| {c} | {NAME[c]} | {len(fires[c]['0'])} | {len(fires[c]['1'])} |")
        listed = [(c, x) for c in CODES for x in fires[c]["0"]]
        out += ["", "Genuine rows a rule fires on: " + ("none." if not listed else "")]
        out += [f"- {c} {src} `{h}`: \"{q}\"" for c, (src, h, q) in listed]
        return out + [""]
    L += ["## 2. Fire counts on the whole val split (every source)", ""]
    L += fire_table("val", "val")
    L += ["For information, the train split (regex only; its genuine hits were also read when the guards were written):", ""]
    L += fire_table("train", "train")

    # ---------------------------------------------------------------- 3. val, the whole app
    val = list(rows_of("val"))
    vt = [r["text"][:20000] for r in val]
    y = [int(r["label"]) for r in val]
    L += ["## 3. Val F1 of the whole app, rules off vs on", "",
          f"All {len(val)} val rows through `router.analyse` (offline). Val text is stored masked, so A1 cannot fire on it (a UPI id is `<UPI_ID>`); the A1 "
          "proxy is only in section 2. The 'off' column equals the app before this change (no stored row has a @valid id, so the mask fix changes nothing).", "",
          "| head | rules | precision | recall | F1 | flagged | at Likely scam |", "|---|---|---|---|---|---|---|"]
    changed = {}
    for hname, head in hs.items():
        res = {}
        for rules in (False, True):
            lv = levels(vt, head, um, rules)
            res[rules] = lv
            fl = flagged(lv)
            tp = sum(a and b == 1 for a, b in zip(fl, y)); fp = sum(a and b == 0 for a, b in zip(fl, y)); fn = sum((not a) and b == 1 for a, b in zip(fl, y))
            L.append(f"| {hname} | {'on' if rules else 'off'} | {tp / (tp + fp):.4f} | {tp / (tp + fn):.4f} | {f1(tp, fp, fn):.4f} | {sum(fl)} | {sum((l or 0) == 2 for l in lv)} |")
        changed[hname] = [(r, a, b) for r, a, b in zip(val, res[False], res[True]) if (a or 0) != (b or 0) or (a is None) != (b is None)]
    L.append("")
    for hname, ch in changed.items():
        L.append(f"{hname}: {len(ch)} of {len(val)} val rows change level with the rules. " + (
            "; ".join(f"{r['source']} {r['text_hash'][:8]} label {r['label']} {a}->{b}" for r, a, b in ch) if ch else ""))
    L.append("")
    REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
