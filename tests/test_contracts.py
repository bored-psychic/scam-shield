import os, re, sys
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_contracts.py")))   # exec()-ed from the project root there is no __file__: tests/ relative to the cwd
sys.path[:0] = [os.path.join(HERE, "..", "src"), HERE]
import copy, hashlib, json, socket
import pandas as pd
from pydantic import ValidationError
from shield import config
from shield.contracts import (DETAILS_OF_MODULE, MODULE_OF_INPUT, SCHEMA_VERSION, Details, Effect, InputKind, Level, LEVEL_RANK, Report)
from shield.core.advice import (ADVICE, APP_ADVICE, APP_WARNING_ADVICE, EMAIL_ADVICE, GAMBLING_ADVICE, INVESTMENT_ADVICE, MAX_ADVICE, PAYMENT_ADVICE,
                               PAYMENT_PROOF_ADVICE, advice_for)
from shield.core.risk import BANDS, risk_score
from shield.core.report import to_report
from shield.core.router import analyse, assess_links
from shield.core.sender_rule import apply_sender, hard_risks
from shield.examples import EXAMPLES
from shield.links.lexical import load_url_model
from shield.messages.sender import parse_sender
from shield.messages.text_head import load_text_model
from tricky_inputs import INPUTS

# python tests/test_contracts.py   (from the project root; needs both models; needs no Gradio: everything comes from shield.*). For every tricky input, every shield.examples.EXAMPLES entry and 300 val rows
# (messages.csv rows whose split_map split is "val", sample random_state=0; never test rows): r = analyse(...), rep = to_report(text, r), then
#   A1 JSON round-trip   A2 level mapping   A3 child levels   A4 reasons   A5 quotes are exact substrings   A6 DANGER -> flagged
#   A7 NO_WARNING_SIGNS -> no DANGER / CAUTION   A8 top level >= judged children
#   A9 text[span] == quote (code points)   A10 every Evidence has a tag of 1-24 characters   A11 tactic titles are the neutral ones exactly when the level is NO_WARNING_SIGNS
#   A12 a rule.* / tactic.* span does not start or end inside a word (the cue "pin" must not point into "shipping"; re \w semantics)
#   A13 advice: a top-level Report has 1-5 non-empty items, == ADVICE[level] with GAMBLING_ADVICE first iff category == "gambling" and INVESTMENT_ADVICE next iff a
#       rule.invest_* evidence exists (Phase A, 2026-10-25); children have none
#   A14 meta.models has text, url, gambling_lookup; text / url end in 8 hex chars that match the SHA-256 of the model files, the same dict in every Report,
#       and model_versions() was computed once (cache misses == 1)
#   A15 the safety-advice cap: a Report has a rule.safety_advice evidence exactly when analyse() set r["safety_advice"]; then the level is no_warning_signs,
#       every such evidence is reassuring, and there is no link (no children), no credential request (r["cred_request"], rule.otp_request), no PIN-to-receive request
#       (r["pin_to_receive"], rule.pin_to_receive) and no caution / danger evidence
# D22 (the sender, schema "3"): A2 knows the level promotional; A7 a promotional Report has no danger evidence and no caution on the message itself (a link the
# URL model rates Suspicious may still be caution: only its scam level is a hard-risk signal); A8 promotional has no rank, and never has a Likely-scam child, a
# gambling category or an OTP / PIN-to-receive rule hit; A11 tactic titles are the neutral ones on promotional too; A15 allows promotional when a P sender set it.
#   A16 empty sender: analyse(..., sender="   ") gives exactly the Report of a call without a sender argument, and Report.sender is None (None and "" take the
#       same path after strip(); tests/test_sender.py E1 runs all three on the demo set, the session's HEAD comparison is in docs/decisions/README.md D22)
#   A17 every input x SENDERS (P, S, T, G, no suffix, bare, mobile, other): the D22 table holds (see sender_rule.py), A1-A15 hold on the variant Report, the
#       sender block echoes a header only for dlt / dlt_bare and never the mobile number, and the reasons are the no-sender ones unchanged plus the sender
#       reason only in a free place (first on promotional), so no warning is ever pushed out.
#       The variants apply sender_rule.apply_sender() to a copy of the no-sender result (the router does exactly that, last); for the tricky inputs the full
#       analyse(..., sender=...) path is run too and must give the same Report.
# Schema "6" (2026-11-04, D29 / W1, docs/plans/multi_input.md 7.5), `python tests/test_contracts.py` prints them after A1-A17:
#   CT01 v6 fields: SCHEMA_VERSION "6", Report.input / details exist and default to None, a "5" payload and an unknown field are rejected, JSON round-trips
#   CT02 the InputKind literal is the nine kinds of the plan; each validates with its module; anything else is rejected
#   CT03 module follows input and details.kind follows module (every wrong pair is rejected)
#   CT04 child (link) Reports have input and details null; a parent with a child that has an input is rejected
#   CT05 inputs without a text score get the band floor (70 / 30 / 0) and the contract rejects any other number outside the band
#   CT06 Can't judge has no score, for every input kind
#   CT07 extra="forbid" on the new request bodies (CheckRequest, AnalyseRequest), on Details and on Report
#   CT08 the refactor (reasons_from, assess_links, advice_for(input=)) changes nothing: for every contract input (tricky + examples + 300 val + extras + probes) the
#        SHA-256 of (level, reasons, advice, risk_score) equals the one the schema-5 code gave (tests/fixtures/ct08_v5_digests.json, made by golden_w1.py run before on
#        master; hashes only, one entry per text hash, per text head)
#   CT09 (W1 extra) assess_links(..., offline_only=True) makes no network call, marks nothing pending, and agrees with analyse() on the offline parts
#   CT10 (W1 extra) advice_for(input=None / "message" / "link") is the old list for every level x category x investment; the per-input lines go where 2.4 says
# Everything runs twice, with the cap forced OFF and ON (analyse(..., safety_cap=...)), so the contract holds whichever way config.SAFETY_ADVICE_CAP is set;
# the level table is printed for each. With the cap OFF A15 is only the "no evidence without the cap" half.
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
LEVEL_OF_INT = {None: Level.CANT_JUDGE, 0: Level.NO_WARNING_SIGNS, 1: Level.SUSPICIOUS, 2: Level.LIKELY_SCAM, "promotional": Level.PROMOTIONAL}
SENDERS = ["JM-JIOCPN-P", "KA-ZOMATO-S", "VM-HDFCBK-T", "XY-GOVTIN-G", "AD-SBIINB", "JIOCPN", "+91 98765 43210", "Jio"]
QUIET = (Level.NO_WARNING_SIGNS, Level.PROMOTIONAL)   # verdicts without a warning: tactic titles are the neutral ones

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
    if rep.level == Level.PROMOTIONAL and (any(e.effect == Effect.DANGER for e in ev) or any(e.effect == Effect.CAUTION for e in rep.evidence)):
        bad["A7"] = f"promotional verdict with {[(e.id, e.effect.value) for e in ev if e.effect in (Effect.DANGER, Effect.CAUTION)]}"
    ranks = [LEVEL_RANK[c.level] for c in rep.children if c.level in LEVEL_RANK]
    if ranks and rep.level in LEVEL_RANK and LEVEL_RANK[rep.level] < max(ranks):
        bad["A8"] = f"top level {rep.level.value} below a child at rank {max(ranks)}"
    if rep.level == Level.PROMOTIONAL and (any(c.level == Level.LIKELY_SCAM for c in rep.children) or rep.category == "gambling"
                                           or any(e.id in ("rule.otp_request", "rule.pin_to_receive") or e.id.startswith("rule.invest_") for e in rep.evidence)):
        bad["A8"] = f"promotional with a Likely-scam child, a gambling category or a rule hit: {[c.level.value for c in rep.children]}, {rep.category}"
    if any(e.span is not None and text[e.span[0]:e.span[1]] != e.quote for e in ev):
        bad["A9"] = f"span does not slice back to the quote: {[(e.id, e.span, e.quote, text[e.span[0]:e.span[1]]) for e in ev if e.span is not None and text[e.span[0]:e.span[1]] != e.quote]}"
    if any(not e.tag or len(e.tag) > 24 for e in ev):
        bad["A10"] = f"bad tag on {[e.id for e in ev if not e.tag or len(e.tag) > 24]}"
    tactic_titles = [e.title for e in ev if e.id.startswith("tactic.")]
    if rep.level in QUIET and any(x not in NEUTRAL_TITLES for x in tactic_titles):
        bad["A11"] = f"{rep.level.value} verdict with a non-neutral tactic title: {[x for x in tactic_titles if x not in NEUTRAL_TITLES]}"
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
    sa = [e for e in rep.evidence if e.id == "rule.safety_advice"]
    a15 = []
    if bool(sa) != bool(r.get("safety_advice")):
        a15.append(f"{len(sa)} rule.safety_advice evidence, analyse() safety_advice {r.get('safety_advice')}")
    if sa:
        promoted = rep.level == Level.PROMOTIONAL and (r.get("sender") or {}).get("rule") == "promotional"   # D22 runs after the cap
        if rep.level != Level.NO_WARNING_SIGNS and not promoted:
            a15.append(f"level {rep.level.value}, not no_warning_signs")
        if any(e.effect != Effect.REASSURING for e in sa):
            a15.append(f"effect {[e.effect.value for e in sa]}, not reassuring")
        if rep.children or r["links"]:
            a15.append(f"with {len(r['links'])} link(s)")
        if r["cred_request"] or any(e.id == "rule.otp_request" for e in rep.evidence):
            a15.append("with a credential request")
        if r["pin_to_receive"] or any(e.id == "rule.pin_to_receive" for e in rep.evidence):
            a15.append("with a PIN-to-receive request")
        if any(e.effect in (Effect.DANGER, Effect.CAUTION) for e in ev):
            a15.append("with caution / danger evidence")
    if a15:
        bad["A15"] = "; ".join(a15)
    return bad

def expected_advice(rep):
    investment = any(e.id.startswith("rule.invest_") for e in rep.evidence)   # Phase A: the SEBI line, right after the gambling line
    return ([GAMBLING_ADVICE] if rep.category == "gambling" else []) + ([INVESTMENT_ADVICE] if investment else []) + ADVICE[rep.level]

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
    kind, text_file, _ = config.text_head_choice()   # the head this process loaded (D27: MuRIL, or the TF-IDF baseline)
    want = {"text": f"{kind} {sha8(text_file)}", "url": f"{config.URL_MODEL_KIND} {sha8(config.URL_MODEL_PATH)}", "gambling_lookup": snapshot}
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

SENDER_TITLE = {"sender.registered", "sender.registered_misused", "sender.mobile"}

def check_sender(text, r0, rep0, s, r, rep):
    """A17 for one input and one sender: r0 / rep0 = the result and Report without a sender, r / rep = with sender s."""
    bad, sid = [], parse_sender(s)
    base, risks, level = LEVEL_OF_INT[r0["level"]], hard_risks(text, r0), rep.level
    flagged_base = base in (Level.SUSPICIOUS, Level.LIKELY_SCAM)
    sev = [e for e in rep.evidence if e.id in SENDER_TITLE]
    if sid.kind in ("mobile", "other"):
        if level != base:
            bad.append(f"{sid.kind} changed the level {base.value} -> {level.value}")
        want = ["sender.mobile"] if sid.kind == "mobile" and flagged_base else []
        if [e.id for e in sev] != want:
            bad.append(f"{sid.kind} at {base.value}: sender evidence {[e.id for e in sev]}, wanted {want}")
    elif risks:
        if level != base or [e.id for e in sev] != ["sender.registered_misused"]:
            bad.append(f"hard-risk {risks}: level {base.value} -> {level.value}, sender evidence {[e.id for e in sev]}")
    else:
        want = Level.PROMOTIONAL if sid.kind == "dlt" and sid.suffix == "P" else Level.SUSPICIOUS if base == Level.LIKELY_SCAM else base
        if level != want or [(e.id, e.effect) for e in sev] != [("sender.registered", Effect.REASSURING)]:
            bad.append(f"no hard-risk, {sid.kind} {sid.suffix}: level {base.value} -> {level.value} (wanted {want.value}), sender evidence {[e.id for e in sev]}")
    if level == Level.PROMOTIONAL:
        if rep.reasons[:1] != [sev[0].title]:
            bad.append(f"promotional, but the first reason is {rep.reasons[:1]}")
    else:   # the sender reason never pushes a warning out: the no-sender reasons stay, and it fills a free place only
        want = rep0.reasons + ([sev[0].title] if sev and len(rep0.reasons) < 3 else [])
        if rep.reasons != want:
            bad.append(f"reasons {rep.reasons}, wanted {want}")
    sb = rep.sender
    if sb is None or sb.kind != sid.kind or (sb.header is not None) != (sid.kind in ("dlt", "dlt_bare")) or sb.header != sid.header or sb.suffix != sid.suffix:
        bad.append(f"sender block {sb} for {sid}")
    if "98765" in rep.model_dump_json():
        bad.append("the mobile number is in the Report")
    if any(c.sender is not None for c in rep.children):
        bad.append("a child Report has a sender block")
    return bad

def run(cap):
    tm, um = load_text_model(), load_url_model()
    items = inputs()
    fails = {f"A{i}": [] for i in range(1, 18)}
    dist, reps = {}, []
    for kind, name, text in items:
        r = analyse(text, tm, um, safety_cap=cap)
        rep = to_report(text, r)
        reps.append(rep)
        dist[(kind, rep.level)] = dist.get((kind, rep.level), 0) + 1
        for a, msg in check(text, r, rep).items():
            fails[a].append(f"{kind} {name}: {msg}")
        fails["A13"] += [f"{kind} {name}: {m}" for m in check_advice(rep)]
        # A16: an empty sender is no sender
        blank = to_report(text, analyse(text, tm, um, safety_cap=cap, sender="   "))
        if rep.sender is not None or r["sender"] is not None or blank != rep:
            fails["A16"].append(f"{kind} {name}: sender '   ' changes the Report (or sender is set without one)")
        # A17: the D22 table, on a copy of the no-sender result (what the router does last); the full router path too for the tricky inputs
        for s in SENDERS:
            rs = apply_sender(copy.deepcopy(r), parse_sender(s), text)
            rep_s = to_report(text, rs)
            fails["A17"] += [f"{kind} {name} + {s}: {m}" for m in check_sender(text, r, rep, s, rs, rep_s)]
            fails["A17"] += [f"{kind} {name} + {s}: {a} {m}" for a, m in check(text, rs, rep_s).items()]
            fails["A17"] += [f"{kind} {name} + {s}: A13 {m}" for m in check_advice(rep_s)]
            if not cap and kind == "tricky" and to_report(text, analyse(text, tm, um, safety_cap=cap, sender=s)) != rep_s:
                fails["A17"].append(f"{kind} {name} + {s}: analyse(..., sender=...) differs from apply_sender() on the no-sender result")
    for name, text in PROBES:   # not in the level table
        rep = to_report(text, analyse(text, tm, um, safety_cap=cap))
        reps.append(rep)
        fails["A13"] += [f"probe {name}: {m}" for m in check_advice(rep)]
        exercised = (rep.category == "gambling" and rep.level in FLAGGED) if name == "gambling" else rep.level == Level.CANT_JUDGE
        if not exercised:
            fails["A13"].append(f"probe {name}: category {rep.category!r}, level {rep.level.value}: the probe no longer exercises its branch")
    fails["A14"] += [f"{m}" for m in check_models(reps)]
    return items, fails, dist

# ---------------------------------------------------------------- schema "6" (W1)
CT_KINDS = ["message", "link", "email", "upi_id", "payment_request", "qr", "payment_proof", "app", "apk"]   # the plan's order (2.2)
CT08_PATH = os.path.join(HERE, "fixtures", "ct08_v5_digests.json")

def rejects(fn):
    try:
        fn()
    except (ValidationError, ValueError):
        return True
    return False

def mini(module="messages", **kw):
    return Report(module=module, level=kw.pop("level", Level.CANT_JUDGE), **kw)

def ct01():
    bad = []
    if SCHEMA_VERSION != "6" or Report(module="messages", level=Level.CANT_JUDGE).schema_version != "6":
        bad.append(f"SCHEMA_VERSION {SCHEMA_VERSION}")
    rep = mini()
    j = rep.model_dump(mode="json")
    if "input" not in j or "details" not in j or j["input"] is not None or j["details"] is not None:
        bad.append(f"input / details missing from the JSON or not null by default: {[j.get('input', 'MISSING'), j.get('details', 'MISSING')]}")
    if not rejects(lambda: Report.model_validate({**j, "schema_version": "5"})):
        bad.append("a schema_version 5 payload is accepted")
    if not rejects(lambda: Report.model_validate({**j, "extra_field": 1})):
        bad.append("an unknown field is accepted")
    if Report.model_validate_json(mini(input="email").model_dump_json()).input != "email":
        bad.append("input does not round-trip")
    return bad

def ct02():
    bad = []
    import typing
    if list(typing.get_args(InputKind)) != CT_KINDS:
        bad.append(f"InputKind is {list(typing.get_args(InputKind))}")
    for k in CT_KINDS:
        if rejects(lambda: mini(MODULE_OF_INPUT[k], input=k)):
            bad.append(f"{k} with module {MODULE_OF_INPUT[k]} is rejected")
    for k in ("bogus", "Message", "payment", "", "text"):
        if not rejects(lambda: mini(input=k)):
            bad.append(f"input {k!r} is accepted")
    return bad

def ct03():
    bad = []
    modules = ["messages", "links", "transactions", "apps"]
    for k in CT_KINDS:
        for m in modules:
            if (m != MODULE_OF_INPUT[k]) != rejects(lambda: mini(m, input=k)):
                bad.append(f"input {k} + module {m}: {'accepted' if m != MODULE_OF_INPUT[k] else 'rejected'}")
    for m in modules:
        for kind in ("payment", "app", "email"):
            ok = DETAILS_OF_MODULE.get(m) == kind
            if ok == rejects(lambda: mini(m, details=Details(kind=kind, title="Details"))):
                bad.append(f"details kind {kind} + module {m}: {'rejected' if ok else 'accepted'}")
    if rejects(lambda: mini("transactions", input="upi_id", details=Details(kind="payment", title="Payment details", note="n"))):
        bad.append("a consistent payment Report is rejected")
    if not rejects(lambda: Details(kind="payment", title="")) or not rejects(lambda: Details(kind="payment", title="x" * 41)) or not rejects(lambda: Details(kind="other", title="x")):
        bad.append("Details accepts an empty / over-long title or an unknown kind")
    return bad

def ct04(tm, um):
    bad = []
    for text in ("Dear customer, share your OTP now: http://sbi-kyc-verify.xyz/login and https://bit.ly/3xYz", "Click https://example.com/login to continue please now"):
        rep = to_report(text, analyse(text, tm, um), input="message")
        if not rep.children or rep.input != "message":
            bad.append(f"{text[:30]!r}: {len(rep.children)} children, input {rep.input}")
        if any(c.input is not None or c.details is not None or c.module != "links" for c in rep.children):
            bad.append(f"{text[:30]!r}: a child has input / details, or is not a links Report")
    child = mini("links", level=Level.NO_WARNING_SIGNS)
    if rejects(lambda: mini(children=[child])):
        bad.append("a parent with a plain link child is rejected")
    if not rejects(lambda: mini(children=[mini("messages", input="message")])):
        bad.append("a parent with a child that has an input is accepted")
    if not rejects(lambda: mini("links", input="link")):
        bad.append("a links-module Report with an input is accepted")
    return bad

def ct05(tm, um):
    bad = []
    for level, (lo, hi) in ((Level.LIKELY_SCAM, (70, 100)), (Level.SUSPICIOUS, (30, 69)), (Level.NO_WARNING_SIGNS, (0, 29))):
        if risk_score(level, None, None) != lo:
            bad.append(f"risk_score({level.value}, no text score) = {risk_score(level, None, None)}, wanted the floor {lo}")
        for k in CT_KINDS:
            m = MODULE_OF_INPUT[k]
            if rejects(lambda: mini(m, input=k, level=level, risk_score=lo)) or rejects(lambda: mini(m, input=k, level=level, risk_score=hi)):
                bad.append(f"{k} at {level.value}: the band floor / ceiling {lo} / {hi} is rejected")
            if not rejects(lambda: mini(m, input=k, level=level, risk_score=lo - 1 if lo else hi + 1)):
                bad.append(f"{k} at {level.value}: a score outside the band is accepted")
    seen = set()
    for text in ("https://sbi-kyc-update.top/login", "http://bit.ly/3xYz", "https://www.google.com/search", "www.example.com/a", "http://192.168.0.1/login.php"):
        r = analyse(text, tm, um)
        rep = to_report(text, r, input="link")
        if r["text_score"] is not None:
            bad.append(f"{text}: expected a bare link with no text score")
        want = None if rep.level == Level.CANT_JUDGE else BANDS[rep.level][0]
        if rep.risk_score != want:
            bad.append(f"bare link {text}: level {rep.level.value}, risk_score {rep.risk_score}, wanted {want}")
        seen.add(rep.level)
    if not seen - {Level.CANT_JUDGE}:
        bad.append("no bare link reached a scored level, so the floor was never exercised")
    return bad

def ct06(tm, um):
    bad = []
    if risk_score(Level.CANT_JUDGE, None, None) is not None or risk_score(Level.CANT_JUDGE, 0.9, (0.1, 0.4)) is not None:
        bad.append("risk_score(CANT_JUDGE) is not None")
    for k in CT_KINDS:
        if not rejects(lambda: mini(MODULE_OF_INPUT[k], input=k, level=Level.CANT_JUDGE, risk_score=0)):
            bad.append(f"{k}: a Can't judge Report with a score is accepted")
    rep = to_report("ok", analyse("ok", tm, um), input="message")
    if rep.level != Level.CANT_JUDGE or rep.risk_score is not None:
        bad.append(f"'ok': level {rep.level.value}, risk_score {rep.risk_score}")
    return bad

def ct07():
    from shield.api.main import AnalyseRequest, CheckRequest
    bad = []
    for cls, ok in ((CheckRequest, {"kind": "auto", "text": "hi"}), (AnalyseRequest, {"text": "hi"})):
        cls(**ok)
        if not rejects(lambda: cls(**ok, unknown=1)):
            bad.append(f"{cls.__name__} accepts an unknown field")
    if not rejects(lambda: CheckRequest(text="hi")):
        bad.append("CheckRequest accepts a missing kind")
    if not rejects(lambda: CheckRequest(kind="bogus")):
        bad.append("CheckRequest accepts an unknown kind")
    if not rejects(lambda: Details(kind="app", title="t", extra=1)):
        bad.append("Details accepts an unknown field")
    for k in ("auto", "message", "link", "email", "upi_id", "payment_request", "qr", "payment_proof", "app", "apk"):
        CheckRequest(kind=k)
    return bad

def ct08(tm, um):
    kind = config.text_head_choice()[0]
    digests = json.load(open(CT08_PATH)).get(kind)
    if digests is None:
        return [f"no schema-5 digests for the {kind} head in {os.path.relpath(CT08_PATH, ROOT)}"]
    bad, n = [], 0
    for _, name, text in inputs() + [("probe", n_, t) for n_, t in PROBES]:
        rep = to_report(text, analyse(text, tm, um)).model_dump(mode="json")
        got = hashlib.sha256(json.dumps([rep["level"], rep["reasons"], rep["advice"], rep["risk_score"]], ensure_ascii=False).encode("utf-8")).hexdigest()
        want = digests.get(hashlib.sha256(text.encode("utf-8")).hexdigest())
        n += 1
        if want is None:
            bad.append(f"{name}: no schema-5 digest for this text (the input set changed? regenerate with golden_w1.py run before on master)")
        elif got != want:
            bad.append(f"{name}: level / reasons / advice / risk_score differ from the schema-5 code")
    if n < 300:
        bad.append(f"only {n} contract inputs were compared")
    return bad[:20]

def ct09(tm, um):
    bad, attempts = [], []
    urls = ["https://sbi-kyc-update.top/login", "https://bit.ly/3xYz", "https://www.google.com/search", "http://192.168.0.1/login.php"]
    names = ("connect", "connect_ex")
    saved_methods = {n: socket.socket.__dict__.get(n) for n in names}
    saved_funcs = {n: getattr(socket, n) for n in ("create_connection", "getaddrinfo", "gethostbyname")}
    def refuse(name):
        def f(*a, **k):
            attempts.append(name)
            raise OSError(f"CT09: outbound network call blocked ({name})")
        return f
    try:
        for n in names:
            setattr(socket.socket, n, refuse(n))
        for n in saved_funcs:
            setattr(socket, n, refuse(n))
        off = assess_links(urls, um, live=True, expand=(urls[1],), offline_only=True)   # live=True is asked for and must be ignored
        base = assess_links(urls, um, live=False)
    finally:
        for n, f in saved_methods.items():
            delattr(socket.socket, n) if f is None else setattr(socket.socket, n, f)
        for n, f in saved_funcs.items():
            setattr(socket, n, f)
    if attempts:
        bad.append(f"network attempts: {attempts}")
    if set(off) < {"links", "url_level", "top_score", "breakdown", "notes"} or len(off["links"]) != len(urls):
        bad.append(f"result keys {sorted(off)}, {len(off['links'])} links")
    for l in off["links"]:
        c = l["checks"]
        if c and (c["pending"] or c["sent"]):
            bad.append(f"{l['url']}: pending {c['pending']}, sent {c['sent']}")
    for a, b in zip(off["links"], base["links"]):   # the same link, the same URL-model and gambling answers; only the network-dependent parts differ
        if (a["url"], a["kind"], a["score"], a["model_level"], a["gambling"]) != (b["url"], b["kind"], b["score"], b["model_level"], b["gambling"]):
            bad.append(f"{a['url']}: offline_only changes the URL model / gambling answer")
    text = " ".join(urls)
    r = analyse(text, tm, um)
    if [l["url"] for l in r["links"]] != [l["url"] for l in base["links"]] or r["url_level"] != base["url_level"]:
        bad.append("analyse() and assess_links() disagree on the links")
    return bad

def ct10():
    bad = []
    for level in Level:
        for cat in (None, "gambling"):
            for inv in (False, True):
                want = ([GAMBLING_ADVICE] if cat == "gambling" else []) + ([INVESTMENT_ADVICE] if inv else []) + ADVICE[level]
                for inp in (None, "message", "link"):
                    if advice_for(level, cat, investment=inv, input=inp) != want:
                        bad.append(f"{level.value}/{cat}/{inv}/{inp}: not the old list")
                if advice_for(level, cat, investment=inv) != want:
                    bad.append(f"{level.value}/{cat}/{inv}: default input changed the list")
                flagged = level in (Level.SUSPICIOUS, Level.LIKELY_SCAM)
                front = ([GAMBLING_ADVICE] if cat == "gambling" else []) + ([INVESTMENT_ADVICE] if inv else [])
                for inp, own in (("email", [EMAIL_ADVICE] if flagged else []), ("upi_id", [PAYMENT_ADVICE]), ("payment_request", [PAYMENT_ADVICE]), ("qr", [PAYMENT_ADVICE]),
                                 ("app", [APP_ADVICE] + ([APP_WARNING_ADVICE] if flagged else [])), ("apk", [APP_ADVICE] + ([APP_WARNING_ADVICE] if flagged else []))):
                    got = advice_for(level, cat, investment=inv, input=inp)
                    if got != (front + own + ADVICE[level])[:MAX_ADVICE] or not 1 <= len(got) <= MAX_ADVICE or got[len(front)] != (own or ADVICE[level])[0]:
                        bad.append(f"{level.value}/{cat}/{inv}/{inp}: {got}")
                if advice_for(level, cat, investment=inv, input="payment_proof") != PAYMENT_PROOF_ADVICE:
                    bad.append(f"{level.value}: payment_proof advice")
    return bad

def run_v6():
    tm, um = load_text_model(), load_url_model()
    out = [("CT01", "v6 fields, version, round-trip", ct01()), ("CT02", "InputKind literal", ct02()), ("CT03", "module <-> input, details.kind <-> module", ct03()),
           ("CT04", "child Reports have no input", ct04(tm, um)), ("CT05", "band floors without a text score", ct05(tm, um)), ("CT06", "Can't judge has no score", ct06(tm, um)),
           ("CT07", "extra=forbid on the new request bodies", ct07()), ("CT08", "refactor changes nothing: digests of the schema-5 results", ct08(tm, um)),
           ("CT09", "assess_links offline_only: no network, nothing pending", ct09(tm, um)), ("CT10", "advice_for(input=): old list unchanged, per-input lines", ct10())]
    return out

def test_contract_v6():
    bad = [f"{cid}: {b}" for cid, _, bs in run_v6() for b in bs]
    assert not bad, "\n".join(bad)


def test_contracts():
    for cap in (False, True):
        items, fails, _ = run(cap)
        assert not any(fails.values()), "\n".join(f"cap {cap}: {a}: {m}" for a, ms in fails.items() for m in ms)

if __name__ == "__main__":
    bad_run = False
    print("==== schema 6 (W1)")
    for cid, what, bs in run_v6():
        print(f"{'FAIL' if bs else 'PASS'} {cid} {what}")
        for b in bs[:10]:
            print("    " + b.encode("ascii", "backslashreplace").decode()[:300])
        bad_run |= bool(bs)
    print()
    for cap in (False, True):
        items, fails, dist = run(cap)
        print(f"==== safety-advice cap {'ON' if cap else 'OFF'}   inputs: {len(items)}")
        for a, ms in fails.items():
            print(f"{a}: {len(ms)} failures")
            for m in ms[:10]:
                print("    " + m.encode("ascii", "backslashreplace").decode()[:300])
        kinds = ["tricky", "example", "val", "extra"]
        print(f"\n{'level':<18}" + "".join(f"{k:>9}" for k in kinds) + f"{'all':>9}")
        for lv in Level:
            row = [dist.get((k, lv), 0) for k in kinds]
            print(f"{lv.value:<18}" + "".join(f"{n:>9}" for n in row) + f"{sum(row):>9}")
        print()
        bad_run |= any(fails.values())
    sys.exit(1 if bad_run else 0)
