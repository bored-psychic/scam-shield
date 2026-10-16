import os, re, sys
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_contracts.py")))   # exec()-ed from the project root there is no __file__: tests/ relative to the cwd
sys.path[:0] = [os.path.join(HERE, "..", "src"), HERE]
import hashlib, json
import pandas as pd
from shield import config
from shield.contracts import Effect, Level, LEVEL_RANK, Report
from shield.core.advice import ADVICE, GAMBLING_ADVICE
from shield.core.report import to_report
from shield.core.router import analyse
from shield.examples import EXAMPLES
from shield.links.lexical import load_url_model
from shield.messages.text_head import load_text_model
from tricky_inputs import INPUTS

# python tests/test_contracts.py   (from the project root; needs both models; needs no Gradio: everything comes from shield.*). For every tricky input, every shield.examples.EXAMPLES entry and 300 val rows
# (messages.csv rows whose split_map split is "val", sample random_state=0; never test rows): r = analyse(...), rep = to_report(text, r), then
#   A1 JSON round-trip   A2 level mapping   A3 child levels   A4 reasons   A5 quotes are exact substrings   A6 DANGER -> flagged
#   A7 NO_WARNING_SIGNS -> no DANGER / CAUTION   A8 top level >= judged children
#   A9 text[span] == quote (code points)   A10 every Evidence has a tag of 1-24 characters   A11 tactic titles are the neutral ones exactly when the level is NO_WARNING_SIGNS
#   A12 a rule.* / tactic.* span does not start or end inside a word (the cue "pin" must not point into "shipping"; re \w semantics)
#   A13 advice: a top-level Report has 1-5 non-empty items, == ADVICE[level] with GAMBLING_ADVICE first iff category == "gambling"; children have none
#   A14 meta.models has text, url, gambling_lookup; text / url end in 8 hex chars that match the SHA-256 of the model files, the same dict in every Report,
#       and model_versions() was computed once (cache misses == 1)
# Three "extra" inputs are appended: an emoji before the quote (A9 with astral characters), a genuine bank alert (A11) and a message where
# "shipping" comes before the real "PIN" (A12). They are the only inputs counted in the level table.
# Two probes are checked for A13 / A14 but not counted in the table: a betting promo (category "gambling", so the gambling advice line is exercised)
# and a one-word message (Can't judge).
ROOT = os.path.join(HERE, "..")
FLAGGED = (Level.SUSPICIOUS, Level.LIKELY_SCAM)
NEUTRAL_TITLES = {"Mentions a bank, government body or company", "Uses time words (common in genuine alerts too)",
                  "Mentions money or payments (normal in genuine bank alerts)", "Mentions keeping something private"}
EXTRA = ["\U0001F600 Dear customer \U0001F600, share your OTP now to avoid account block: http://sbi-kyc-verify.xyz/login",
         "Rs. 2,500 debited from A/c XX1234. Never share your OTP with anyone. -HDFC Bank",
         "Your shipping update: share the PIN 4821 with our agent to confirm delivery today."]
PROBES = [("gambling", "Big IPL offer! Deposit Rs 500 and play now: https://bet365.com/promo"), ("cant-judge", "ok")]
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
    inside = []
    for e in ev:
        if e.span is None or not e.id.startswith(("rule.", "tactic.")):
            continue
        (s, t), q = e.span, e.quote
        if (re.match(r"\w", q[0]) and s > 0 and re.match(r"\w", text[s - 1])) or (re.match(r"\w", q[-1]) and t < len(text) and re.match(r"\w", text[t])):
            inside.append((e.id, e.quote, repr(text[max(0, s - 3):t + 3])))
    if inside:
        bad["A12"] = f"span starts or ends inside a word: {inside}"
    return bad

def expected_advice(rep):
    return ([GAMBLING_ADVICE] if rep.category == "gambling" else []) + ADVICE[rep.level]

def check_advice(rep):
    """A13."""
    bad = []
    if not 1 <= len(rep.advice) <= 5 or any(not isinstance(a, str) or not a.strip() for a in rep.advice):
        bad.append(f"{len(rep.advice)} items, or an empty one: {rep.advice}")
    if rep.advice != expected_advice(rep):
        bad.append(f"advice for {rep.level.value} / category {rep.category!r} is not ADVICE[level] (+ gambling line first): {rep.advice}")
    if (GAMBLING_ADVICE in rep.advice) != (rep.category == "gambling"):
        bad.append(f"gambling line present = {GAMBLING_ADVICE in rep.advice}, category {rep.category!r}")
    if any(c.advice != [] for c in rep.children):
        bad.append(f"a child Report has advice: {[c.advice for c in rep.children]}")
    return bad

def inputs():
    msgs = pd.read_csv(os.path.join(ROOT, "data", "final", "messages.csv"), usecols=["text", "text_hash"])
    sm = pd.read_csv(os.path.join(ROOT, "data", "final", "split_map.csv"))
    val = msgs.merge(sm, on="text_hash")
    val = val[val["split"] == "val"]
    assert set(val["split"]) == {"val"}
    val = val.sample(300, random_state=0)
    out = [("tricky", x["id"], x["text"]) for x in INPUTS] + [("example", f"example-{i}", e[0]) for i, e in enumerate(EXAMPLES)]
    out += [("val", f"val-{h[:8]}", t) for h, t in zip(val["text_hash"], val["text"])]
    return out + [("extra", f"extra-{i}", x) for i, x in enumerate(EXTRA)]

def sha8(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()[:8]

def check_models(reps):
    """A14, over every Report made in this run."""
    bad = []
    first = reps[0].meta.models
    snapshot = json.load(open(config.GAMBLING_INDIA_PATH))["snapshot"]
    want = {"text": f"{config.TEXT_MODEL_KIND} {sha8(config.TEXT_MODEL_PATH)}", "url": f"{config.URL_MODEL_KIND} {sha8(config.URL_MODEL_PATH)}", "gambling_lookup": snapshot}
    if first != want:
        bad.append(f"meta.models {first}, wanted {want} (hashes recomputed here from the model files)")
    if set(first) != {"text", "url", "gambling_lookup"} or not all(re.fullmatch(r"\S+ [0-9a-f]{8}", first[k]) for k in ("text", "url")):
        bad.append(f"meta.models has the wrong keys or value shape: {first}")
    different = sum(r.meta.models != first for r in reps)
    if different:
        bad.append(f"{different} of {len(reps)} Reports have a different meta.models")
    misses = config.model_versions.cache_info().misses
    if misses != 1:
        bad.append(f"model_versions() was computed {misses} times, not once")
    return bad

def run():
    tm, um = load_text_model(), load_url_model()
    items = inputs()
    fails = {f"A{i}": [] for i in range(1, 15)}
    dist, reps = {}, []
    for kind, name, text in items:
        r = analyse(text, tm, um)
        rep = to_report(text, r)
        reps.append(rep)
        dist[(kind, rep.level)] = dist.get((kind, rep.level), 0) + 1
        for a, msg in check(text, r, rep).items():
            fails[a].append(f"{kind} {name}: {msg}")
        fails["A13"] += [f"{kind} {name}: {m}" for m in check_advice(rep)]
    for name, text in PROBES:   # not in the level table
        rep = to_report(text, analyse(text, tm, um))
        reps.append(rep)
        fails["A13"] += [f"probe {name}: {m}" for m in check_advice(rep)]
        exercised = (rep.category == "gambling" and rep.level in FLAGGED) if name == "gambling" else rep.level == Level.CANT_JUDGE
        if not exercised:
            fails["A13"].append(f"probe {name}: category {rep.category!r}, level {rep.level.value}: the probe no longer exercises its branch")
    fails["A14"] += [f"{m}" for m in check_models(reps)]
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
