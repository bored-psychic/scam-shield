import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import pandas as pd
import app
from shield.contracts import Effect, Level, LEVEL_RANK, Report
from shield.core.report import to_report
from tricky_inputs import INPUTS

# python tests/test_contracts.py   (from the project root; needs both models). For every tricky input, every app.EXAMPLES entry and 300 val rows
# (messages.csv rows whose split_map split is "val", sample random_state=0; never test rows): r = analyse(...), rep = to_report(text, r), then
#   A1 JSON round-trip   A2 level mapping   A3 child levels   A4 reasons   A5 quotes are exact substrings   A6 DANGER -> flagged
#   A7 NO_WARNING_SIGNS -> no DANGER / CAUTION   A8 top level >= judged children
#   A9 text[span] == quote (code points)   A10 every Evidence has a tag of 1-24 characters   A11 tactic titles are the neutral ones exactly when the level is NO_WARNING_SIGNS
# Two "extra" inputs are appended: an emoji before the quote (A9 with astral characters) and a genuine bank alert (A11).
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
FLAGGED = (Level.SUSPICIOUS, Level.LIKELY_SCAM)
NEUTRAL_TITLES = {"Mentions a bank, government body or company", "Uses time words (common in genuine alerts too)",
                  "Mentions money or payments (normal in genuine bank alerts)", "Mentions keeping something private"}
EXTRA = ["\U0001F600 Dear customer \U0001F600, share your OTP now to avoid account block: http://sbi-kyc-verify.xyz/login",
         "Rs. 2,500 debited from A/c XX1234. Never share your OTP with anyone. -HDFC Bank"]
LEVEL_OF_INT = {None: Level.CANT_JUDGE, 0: Level.NO_WARNING_SIGNS, 1: Level.SUSPICIOUS, 2: Level.LIKELY_SCAM}

def all_evidence(rep):
    return list(rep.evidence) + [e for c in rep.children for e in c.evidence]

def check(text, r, rep):
    """assertion id -> message, for each assertion that fails."""
    bad, ev = {}, all_evidence(rep)
    if Report.model_validate_json(rep.model_dump_json()) != rep:
        bad["A1"] = "round-trip changed the Report"
    if rep.level != LEVEL_OF_INT[r["level"]]:
        bad["A2"] = f"level {rep.level.value}, analyse() level {r['level']}"
    got, want = [c.level.value for c in rep.children], [LEVEL_OF_INT[l["level"]].value for l in r["links"]]
    if got != want:
        bad["A3"] = f"child levels {got}, links {want}"
    titles = {e.title for e in ev}
    stray = [x for x in rep.reasons if x not in titles and x != "Too little text to judge"]
    if len(rep.reasons) > 3 or stray:
        bad["A4"] = f"{len(rep.reasons)} reasons, not the title of any evidence: {stray}"
    quotes = [e.quote for e in ev if e.quote is not None]
    if any(q not in text for q in quotes):
        bad["A5"] = f"quotes not in the input: {[q for q in quotes if q not in text]}"
    if any(e.effect == Effect.DANGER for e in ev) and rep.level not in FLAGGED:
        bad["A6"] = f"DANGER evidence {[e.id for e in ev if e.effect == Effect.DANGER]} at level {rep.level.value}"
    if rep.level == Level.NO_WARNING_SIGNS and any(e.effect in (Effect.DANGER, Effect.CAUTION) for e in ev):
        bad["A7"] = f"no-warning verdict with {[e.id for e in ev if e.effect in (Effect.DANGER, Effect.CAUTION)]}"
    ranks = [LEVEL_RANK[c.level] for c in rep.children if c.level in LEVEL_RANK]
    if ranks and rep.level in LEVEL_RANK and LEVEL_RANK[rep.level] < max(ranks):
        bad["A8"] = f"top level {rep.level.value} below a child at rank {max(ranks)}"
    if any(e.span is not None and text[e.span[0]:e.span[1]] != e.quote for e in ev):
        bad["A9"] = f"span does not slice back to the quote: {[(e.id, e.span, e.quote, text[e.span[0]:e.span[1]]) for e in ev if e.span is not None and text[e.span[0]:e.span[1]] != e.quote]}"
    if any(not e.tag or len(e.tag) > 24 for e in ev):
        bad["A10"] = f"bad tag on {[e.id for e in ev if not e.tag or len(e.tag) > 24]}"
    tactic_titles = [e.title for e in ev if e.id.startswith("tactic.")]
    if rep.level == Level.NO_WARNING_SIGNS and any(x not in NEUTRAL_TITLES for x in tactic_titles):
        bad["A11"] = f"no-warning verdict with a non-neutral tactic title: {[x for x in tactic_titles if x not in NEUTRAL_TITLES]}"
    if rep.level in FLAGGED and any(x in NEUTRAL_TITLES for x in tactic_titles):
        bad["A11"] = f"flagged verdict ({rep.level.value}) with a neutral tactic title: {[x for x in tactic_titles if x in NEUTRAL_TITLES]}"
    return bad

def inputs():
    msgs = pd.read_csv(os.path.join(ROOT, "data", "final", "messages.csv"), usecols=["text", "text_hash"])
    sm = pd.read_csv(os.path.join(ROOT, "data", "final", "split_map.csv"))
    val = msgs.merge(sm, on="text_hash")
    val = val[val["split"] == "val"]
    assert set(val["split"]) == {"val"}
    val = val.sample(300, random_state=0)
    out = [("tricky", x["id"], x["text"]) for x in INPUTS] + [("example", f"example-{i}", e[0]) for i, e in enumerate(app.EXAMPLES)]
    out += [("val", f"val-{h[:8]}", t) for h, t in zip(val["text_hash"], val["text"])]
    return out + [("extra", f"extra-{i}", x) for i, x in enumerate(EXTRA)]

def run():
    tm, um = app.load_text_model(), app.load_url_model()
    items = inputs()
    fails = {f"A{i}": [] for i in range(1, 12)}
    dist = {}
    for kind, name, text in items:
        r = app.analyse(text, tm, um)
        rep = to_report(text, r)
        dist[(kind, rep.level)] = dist.get((kind, rep.level), 0) + 1
        for a, msg in check(text, r, rep).items():
            fails[a].append(f"{kind} {name}: {msg}")
    return items, fails, dist

def test_contracts():
    items, fails, _ = run()
    assert not any(fails.values()), "\n".join(f"{a}: {m}" for a, ms in fails.items() for m in ms)

if __name__ == "__main__":
    items, fails, dist = run()
    print(f"inputs: {len(items)}")
    for a, ms in fails.items():
        print(f"{a}: {len(ms)} failures")
        for m in ms[:10]:
            print("    " + m.encode("ascii", "backslashreplace").decode()[:300])
    kinds = ["tricky", "example", "val", "extra"]
    print(f"\n{'level':<18}" + "".join(f"{k:>9}" for k in kinds) + f"{'all':>9}")
    for lv in Level:
        row = [dist.get((k, lv), 0) for k in kinds]
        print(f"{lv.value:<18}" + "".join(f"{n:>9}" for n in row) + f"{sum(row):>9}")
    sys.exit(1 if any(fails.values()) else 0)
