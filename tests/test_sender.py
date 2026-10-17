import json, os, sys
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_sender.py")))   # exec()-ed from the project root there is no __file__
sys.path[:0] = [os.path.join(HERE, "..", "src"), HERE]
from demo_check import load_demo
from shield.contracts import Effect, Level, LEVEL_RANK
from shield.core.advice import ADVICE
from shield.core.report import to_report
from shield.core.router import analyse
from shield.core.sender_rule import PAYMENT_DEMAND_CUES, hard_risks, payment_demands
from shield.links.lexical import load_url_model
from shield.messages.sender import SenderID, parse_sender
from shield.messages.tactics import tactic_tags
from shield.messages.text_head import load_text_model
from tricky_inputs import INPUTS

# python tests/test_sender.py   (from the project root; needs both models). The sender input (decision D22, docs/decisions/README.md):
#   P1  parse_sender(): every case of the D22 request and its addendum, plus the edge cases the regex comments name
#   D1-D13  the decision table, one check per row and per named case, each through the full analyse() + to_report() path (the API's path)
#   H1  each hard-risk signal on its own blocks softening by a P sender (and is the one the misuse reason names)
#   H2  a payment-demand cue is found even when the payment tactic already listed 4 cues before it (tactic_tags() keeps only 4)
#   E1  the 14 demo messages with sender None, "" and "   " give exactly the Report of a call without a sender (sender null)
# test_contracts.py A16 / A17 run the empty-sender identity and the table's invariants over all 363 contract inputs; test_api.py T10-T13 the HTTP side.
JIO = "Dear User,\nYou've earned Lifetime Free\nKiwi UPI Credit Card (CC:\nJIOKIWI) on JioRecharge.\nClaim now:\nhttps://t.jio/JIOCPN/x48NuN\nT&C*\nJioCoupons"   # tests/test_ocr.py JIO_TEXT: the real Jio promo, typed
MOBILE = "+91 98765 43210"
DEMO = {e["id"]: e["text"] for e in load_demo()}
TRICKY = {x["id"]: x["text"] for x in INPUTS}
P_TITLE, MOBILE_TITLE = "Sent from a registered business ID (promotional)", "Sent from a personal mobile number; businesses use registered IDs like JM-JIOCPN-P"
MISUSED = lambda thing: f"Registered sender, but {thing}. Registered IDs can still be misused."

# (raw, kind, prefix, header, suffix)
PARSER_CASES = [
    ("JM-JIOCPN-P", "dlt", "JM", "JIOCPN", "P"), ("jm-jiocpn-p", "dlt", "JM", "JIOCPN", "P"), ("VM-HDFCBK-T", "dlt", "VM", "HDFCBK", "T"),
    ("AD-SBIINB", "dlt", "AD", "SBIINB", None), ("KA-ZOMATO-S", "dlt", "KA", "ZOMATO", "S"), ("XY-GOVTIN-G", "dlt", "XY", "GOVTIN", "G"),
    ("  JM-JIOCPN-P  ", "dlt", "JM", "JIOCPN", "P"), ("JM - JIOCPN - P", "dlt", "JM", "JIOCPN", "P"), ("JM–JIOCPN–P", "dlt", "JM", "JIOCPN", "P"),
    ("VM-612345", "dlt", "VM", "612345", None), ("JM-JIOCPN-X", "other", None, None, None), ("JM-JIOCP-P", "other", None, None, None),
    ("J-JIOCPN-P", "other", None, None, None), ("JM-JIOCPN-PP", "other", None, None, None),
    ("JIOCPN", "dlt_bare", None, "JIOCPN", None), ("HDFCBK", "dlt_bare", None, "HDFCBK", None), ("SBIINB", "dlt_bare", None, "SBIINB", None),
    ("JIO123", "dlt_bare", None, "JIO123", None), (" HDFCBK ", "dlt_bare", None, "HDFCBK", None),
    ("Jio", "other", None, None, None), ("Amazon", "other", None, None, None), ("jiocpn", "other", None, None, None), ("JioCpn", "other", None, None, None),
    ("123456", "other", None, None, None), ("JIOCP", "other", None, None, None), ("JIOCPNX", "other", None, None, None), ("JIO CPN", "other", None, None, None),
    ("+91 98765 43210", "mobile", None, None, None), ("09876543210", "mobile", None, None, None), ("98765-43210", "mobile", None, None, None),
    ("9876543210", "mobile", None, None, None), ("919876543210", "mobile", None, None, None), ("+91-98765-43210", "mobile", None, None, None),
    ("+91 58765 43210", "other", None, None, None), ("98765 4321", "other", None, None, None), ("३८७६५४३२१०", "other", None, None, None),
    ("56767", "other", None, None, None), ("1800-123-4567", "other", None, None, None), ("alerts@hdfcbank.net", "other", None, None, None),
    ("", "none", None, None, None), ("   ", "none", None, None, None), (None, "none", None, None, None),
    ("JM-JIOCPN-P" + " x" * 15, "other", None, None, None), ("A" * 41, "other", None, None, None), ("!!@@##$$", "other", None, None, None),
    ("ЈM-JIOCPN-P", "other", None, None, None),   # a Cyrillic J: lookalike letters never pass for a header
]


def p1():
    bad = []
    for raw, kind, prefix, header, suffix in PARSER_CASES:
        got = parse_sender(raw)
        if got != SenderID(kind, prefix, header, suffix):
            bad.append(f"{raw!r}: {got}, wanted {SenderID(kind, prefix, header, suffix)}")
    return bad


_cache = {}
def run(text, sender=None):
    if not _cache:
        _cache["models"] = (load_text_model(), load_url_model())
    tm, um = _cache["models"]
    r = analyse(text, tm, um, sender=sender)
    return r, to_report(text, r)

def titles(rep):
    return [e.title for e in rep.evidence]

def sender_ev(rep):
    return [e for e in rep.evidence if e.id.startswith("sender.")]

def expect(bad, cond, msg):
    if not cond:
        bad.append(msg)


def d1():
    """Jio fixture + JM-JIOCPN-P -> Promotional, the P reason first, Promotional advice, no warning evidence on the message itself."""
    _, rep = run(JIO, "JM-JIOCPN-P")
    bad = []
    expect(bad, rep.level == Level.PROMOTIONAL, f"level {rep.level.value}")
    expect(bad, rep.reasons[:1] == [P_TITLE], f"reasons {rep.reasons}")
    expect(bad, rep.advice == ADVICE[Level.PROMOTIONAL], f"advice {rep.advice}")
    expect(bad, not any(e.effect in (Effect.DANGER, Effect.CAUTION) for e in rep.evidence), f"warning evidence {[(e.id, e.effect.value) for e in rep.evidence]}")
    expect(bad, rep.sender and (rep.sender.kind, rep.sender.suffix, rep.sender.header, rep.sender.label) == ("dlt", "P", "JIOCPN", "Registered business · Promotional"),
           f"sender {rep.sender}")
    return bad

def d2():
    """Jio fixture + a personal mobile number -> the level without a sender (Likely scam), plus the mobile reason; the number is not echoed."""
    _, base = run(JIO)
    _, rep = run(JIO, MOBILE)
    bad = []
    expect(bad, rep.level == base.level == Level.LIKELY_SCAM, f"level {rep.level.value}, without a sender {base.level.value}")
    expect(bad, MOBILE_TITLE in rep.reasons, f"reasons {rep.reasons}")
    expect(bad, [e.effect for e in sender_ev(rep)] == [Effect.CAUTION], f"sender evidence {sender_ev(rep)}")
    dumped = rep.model_dump_json()
    expect(bad, "98765" not in dumped and "43210" not in dumped, "the mobile number appears in the Report")
    expect(bad, rep.sender and (rep.sender.kind, rep.sender.header, rep.sender.suffix, rep.sender.label) == ("mobile", None, None, "Personal mobile number"),
           f"sender {rep.sender}")
    return bad

def d3():
    """the demo OTP scam (d02) + a P sender -> still Likely scam, with the misuse reason naming the OTP request."""
    _, rep = run(DEMO["d02"], "JM-JIOCPN-P")
    bad = []
    expect(bad, rep.level == Level.LIKELY_SCAM, f"level {rep.level.value}")
    expect(bad, MISUSED("it asks for your OTP, PIN or CVV") in rep.reasons, f"reasons {rep.reasons}")
    return bad

def d4():
    """a gambling-link text (d10) + a P sender -> not softened (same level as without a sender), gambling category, misuse reason naming gambling."""
    _, base = run(DEMO["d10"])
    _, rep = run(DEMO["d10"], "JM-JIOCPN-P")
    bad = []
    expect(bad, rep.level == base.level and rep.level != Level.PROMOTIONAL, f"level {rep.level.value}, without a sender {base.level.value}")
    expect(bad, rep.category == "gambling", f"category {rep.category}")
    expect(bad, MISUSED("it links to a gambling or betting site") in rep.reasons, f"reasons {rep.reasons}")
    return bad

def d5():
    """the bank-alert demo (g01) + VM-HDFCBK-T -> at most Suspicious, with the positive (transactional) reason."""
    _, rep = run(DEMO["g01"], "VM-HDFCBK-T")
    bad = []
    expect(bad, rep.level in LEVEL_RANK and LEVEL_RANK[rep.level] <= 1, f"level {rep.level.value}")
    want = "Sent from a registered business ID (transactional)"
    expect(bad, want in rep.reasons, f"reasons {rep.reasons}")
    expect(bad, [e.effect for e in sender_ev(rep)] == [Effect.REASSURING], f"sender evidence {sender_ev(rep)}")
    return bad

def d6():
    """Jio fixture + the bare header JIOCPN -> Suspicious (capped from Likely scam) + the positive reason; not Promotional (that needs suffix P)."""
    _, rep = run(JIO, "JIOCPN")
    bad = []
    expect(bad, rep.level == Level.SUSPICIOUS, f"level {rep.level.value}")
    expect(bad, "Sent from a registered business ID (type unknown)" in rep.reasons, f"reasons {rep.reasons}")
    expect(bad, rep.sender and (rep.sender.kind, rep.sender.label) == ("dlt_bare", "Registered business · type unknown"), f"sender {rep.sender}")
    return bad

def d7():
    """'Jio' and 'Amazon' -> other: the Report without a sender, except the sender block (kind other, label 'Not recognised', nothing echoed)."""
    _, base = run(JIO)
    bad = []
    for s in ("Jio", "Amazon"):
        _, rep = run(JIO, s)
        expect(bad, rep.sender and (rep.sender.kind, rep.sender.header, rep.sender.label) == ("other", None, "Not recognised"), f"{s}: sender {rep.sender}")
        expect(bad, rep.model_dump(exclude={"sender"}) == base.model_dump(exclude={"sender"}), f"{s}: the Report differs from the one without a sender")
    return bad

def d8():
    """the demo OTP scam (d02) + the bare header HDFCBK -> still Likely scam, misuse reason."""
    _, rep = run(DEMO["d02"], "HDFCBK")
    bad = []
    expect(bad, rep.level == Level.LIKELY_SCAM, f"level {rep.level.value}")
    expect(bad, MISUSED("it asks for your OTP, PIN or CVV") in rep.reasons, f"reasons {rep.reasons}")
    return bad

def d9():
    """row 'dlt with S / T / G / no suffix + no hard-risk -> capped at Suspicious + positive reason', on the Jio text (Likely scam without a sender)."""
    bad = []
    for s, word in (("KA-JIOCPN-S", "Sent from a registered business ID (service)"), ("VM-JIOCPN-T", "Sent from a registered business ID (transactional)"),
                    ("XY-GOVTIN-G", "Sent from a registered government sender ID"), ("AD-JIOCPN", "Sent from a registered business ID (type unknown)")):
        _, rep = run(JIO, s)
        expect(bad, rep.level == Level.SUSPICIOUS, f"{s}: level {rep.level.value}")
        expect(bad, word in rep.reasons, f"{s}: reasons {rep.reasons}")
    return bad

def d10():
    """the cap never lowers below Suspicious and never raises: a Suspicious message stays Suspicious, a no-warning one stays no-warning."""
    bad = []
    for text, want in ((TRICKY["otp-enter-to-confirm"], Level.SUSPICIOUS), (DEMO["g04"], Level.NO_WARNING_SIGNS)):
        r0, base = run(text)
        _, rep = run(text, "VM-HDFCBK-T")
        expect(bad, not hard_risks(text, r0), f"{text[:30]!r}: has hard-risk signals, so it no longer tests the cap")
        expect(bad, base.level == rep.level == want, f"{text[:30]!r}: level {rep.level.value}, without a sender {base.level.value}, wanted {want.value}")
    return bad

def d11():
    """mobile below Suspicious -> no change at all except the sender block (no reason: the level is not flagged)."""
    _, base = run(DEMO["g04"])
    _, rep = run(DEMO["g04"], MOBILE)
    bad = []
    expect(bad, not sender_ev(rep), f"sender evidence {sender_ev(rep)}")
    expect(bad, rep.model_dump(exclude={"sender"}) == base.model_dump(exclude={"sender"}), "the Report differs from the one without a sender")
    return bad

def d12():
    """mobile never raises: on every demo message the level with a mobile sender equals the level without one."""
    bad = []
    for i, t in DEMO.items():
        _, base = run(t)
        _, rep = run(t, MOBILE)
        expect(bad, rep.level == base.level, f"{i}: level {rep.level.value}, without a sender {base.level.value}")
        expect(bad, (MOBILE_TITLE in rep.reasons) == (base.level in (Level.SUSPICIOUS, Level.LIKELY_SCAM)), f"{i}: mobile reason {rep.reasons}")
    return bad

def d13():
    """row 'dlt P + no hard-risk -> Promotional' holds whatever the text level: a no-warning text and a too-short one become Promotional too."""
    bad = []
    for text in (DEMO["g03"], "ok"):
        _, rep = run(text, "JM-JIOCPN-P")
        expect(bad, rep.level == Level.PROMOTIONAL and rep.reasons[:1] == [P_TITLE], f"{text[:30]!r}: level {rep.level.value}, reasons {rep.reasons}")
    return bad


# one input per signal whose ONLY hard-risk signal is that one (checked), and the risky thing the misuse reason must name
SINGLE_RISK = [("otp_request", TRICKY["otp-forward"], "it asks for your OTP, PIN or CVV"),
               ("pin_to_receive", TRICKY["pin-receive-cashback"], "it asks for your UPI PIN to receive money"),
               ("phishing_link", DEMO["d06"], "its link looks like a phishing link"),
               ("lookalike_link", TRICKY["free-hosting-brand"], "its link is a lookalike site on free hosting"),
               ("gambling", DEMO["d10"], "it links to a gambling or betting site"),
               ("payment_demand", DEMO["d08"], "it asks for a payment or fee")]

def h1():
    bad = []
    for key, text, thing in SINGLE_RISK:
        r0, base = run(text)
        if hard_risks(text, r0) != [key]:
            bad.append(f"{key}: the input's signals are {hard_risks(text, r0)}, not just [{key!r}]")
            continue
        for s in ("JM-JIOCPN-P", "VM-HDFCBK-T", "HDFCBK"):
            r, rep = run(text, s)
            expect(bad, rep.level == base.level, f"{key} + {s}: level {rep.level.value}, without a sender {base.level.value}")
            expect(bad, r["sender"]["rule"] == "misuse" and MISUSED(thing) in titles(rep), f"{key} + {s}: rule {r['sender']['rule']}, evidence {titles(rep)}")
    return bad

def h2():
    text = "Win Rs 5000 cashback on UPI, pay via Paytm or PhonePe today. A processing fee of Rs 99 applies."
    cues = tactic_tags(text)["payment"]
    bad = []
    expect(bad, len(cues) == 4 and "processing fee" not in cues, f"the payment tactic lists {cues}: the input no longer puts the demand cue past the 4th place")
    expect(bad, payment_demands(text) == ["processing fee"], f"payment_demands {payment_demands(text)}")
    _, rep = run(text, "JM-JIOCPN-P")
    expect(bad, rep.level != Level.PROMOTIONAL and MISUSED("it asks for a payment or fee") in titles(rep), f"level {rep.level.value}, evidence {titles(rep)}")
    expect(bad, PAYMENT_DEMAND_CUES >= set(payment_demands(DEMO["d04"]) + payment_demands(DEMO["d08"])) and payment_demands(DEMO["g01"]) == [],
           "the demo fee scams must carry a demand cue and the bank alert none")
    return bad

def e1():
    bad = []
    for i, t in DEMO.items():
        r0, base = run(t)
        want = base.model_dump(mode="json")
        expect(bad, r0["sender"] is None and base.sender is None, f"{i}: sender not None without a sender argument")
        for s in (None, "", "   "):
            _, rep = run(t, s)
            expect(bad, rep.model_dump(mode="json") == want, f"{i}: sender {s!r} changes the Report")
    return bad


CHECKS = [("P1", f"parse_sender() on {len(PARSER_CASES)} cases", p1),
          ("D1", "Jio + JM-JIOCPN-P -> Promotional", d1), ("D2", "Jio + mobile -> unchanged level + mobile reason, number not echoed", d2),
          ("D3", "OTP scam d02 + P -> still Likely scam, misuse reason", d3), ("D4", "gambling d10 + P -> not softened", d4),
          ("D5", "bank alert g01 + VM-HDFCBK-T -> at most Suspicious + positive reason", d5), ("D6", "Jio + JIOCPN -> Suspicious + positive reason", d6),
          ("D7", "'Jio' / 'Amazon' -> other, no change", d7), ("D8", "OTP scam d02 + HDFCBK -> still Likely scam", d8),
          ("D9", "S / T / G / no-suffix headers cap the Jio text at Suspicious", d9), ("D10", "the cap neither lowers below Suspicious nor raises", d10),
          ("D11", "mobile below Suspicious -> no change", d11), ("D12", "mobile never changes a level (14 demo messages)", d12),
          ("D13", "P + no hard-risk -> Promotional at any text level", d13),
          ("H1", "each hard-risk signal alone blocks softening (P, T, bare)", h1), ("H2", "a 5th-place payment-demand cue still counts", h2),
          ("E1", "demo set: sender None / '' / '   ' == no sender argument", e1)]

def results():
    return [(cid, what, fn()) for cid, what, fn in CHECKS]

def test_sender():
    bad = [f"{cid}: {b}" for cid, _, bs in results() for b in bs]
    assert not bad, "\n".join(bad)

if __name__ == "__main__":
    res = results()
    for cid, what, bad in res:
        print(f"{'FAIL' if bad else 'PASS'} {cid} {what}")
        for b in bad[:10]:
            print("    " + b.encode("ascii", "backslashreplace").decode()[:300])
    print(f"\n{sum(not b for _, _, b in res)}/{len(res)} passed")
    sys.exit(1 if any(b for _, _, b in res) else 0)
