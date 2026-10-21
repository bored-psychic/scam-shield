import json, os, sys
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_sender.py")))   # exec()-ed from the project root there is no __file__
sys.path[:0] = [os.path.join(HERE, "..", "src"), HERE]
from demo_check import load_demo
from shield import config
from shield.contracts import Effect, Level, LEVEL_RANK
from shield.core.advice import ADVICE
from shield.core.report import to_report
from shield.core.router import analyse
from shield.core.sender_rule import PAYMENT_DEMAND_CUES, hard_risks, payment_demands
from shield.links.lexical import load_url_model
from shield.messages.sender import SenderID, parse_sender
from shield.messages.tactics import tactic_tags
from shield.messages.text_head import load_text_model
from shield.messages.threats import fear_cues
from pii import mask_text
from tricky_inputs import INPUTS

# python tests/test_sender.py   (from the project root; needs both models). The sender input (decision D22, docs/decisions/README.md):
#   P1  parse_sender(): every case of the D22 request and its addendum, plus the edge cases the regex comments name
#   D1-D13  the decision table, one check per row and per named case, each through the full analyse() + to_report() path (the API's path)
#   H1  each hard-risk signal on its own blocks softening by a P sender (and is the one the misuse reason names)
#   H2  a payment-demand cue is found even when the payment tactic already listed 4 cues before it (tactic_tags() keeps only 4)
#   E1  the 14 demo messages with sender None, "" and "   " give exactly the Report of a call without a sender (sender null)
# Tightening B (2026-10-18): the fear-cue families (shield.messages.threats) are hard-risk signals too, and the sender reason never pushes a warning out.
#   F1  d01 (digital arrest), d05 (electricity), d07 (investment) + a P, a T and a bare header -> not softened, the misuse evidence names the family
#   F2  each family: synthetic messages that must hit it, and negated / after-the-fact / advice forms that must not
#   F3  promotional wording (offer, cashback, coupon, free, claim now, T&C, limited period, a WhatsApp channel, a 'secret sale') is never a hard-risk signal,
#       and those texts with a P header are Promotional
#   F4  a password request is caught by the OTP rule and shown with its own title; a one-time password keeps the OTP title
#   R1  reason slots: over the demo and tricky inputs x 8 senders, the reasons without a sender come first and unchanged (so the wording model's "very
#       similar to known scam messages" is never pushed out); the sender reason is added only into a free place, or first on Promotional
# test_contracts.py A16 / A17 run the empty-sender identity and the table's invariants over all 363 contract inputs; test_api.py T10-T13 the HTTP side.
JIO = "Dear User,\nYou've earned Lifetime Free\nKiwi UPI Credit Card (CC:\nJIOKIWI) on JioRecharge.\nClaim now:\nhttps://t.jio/JIOCPN/x48NuN\nT&C*\nJioCoupons"   # tests/test_ocr.py JIO_TEXT: the real Jio promo, typed
MOBILE = "+91 98765 43210"
DEMO = {e["id"]: e["text"] for e in load_demo()}
TRICKY = {x["id"]: x["text"] for x in INPUTS}
P_TITLE, MOBILE_TITLE = "Sent from a registered business ID (promotional)", "Sent from a personal mobile number; businesses use registered IDs like JM-JIOCPN-P"
OTP_THING = "it asks for your OTP, PIN, CVV or password"
SENDERS = ["JM-JIOCPN-P", "KA-ZOMATO-S", "VM-HDFCBK-T", "XY-GOVTIN-G", "AD-SBIINB", "JIOCPN", "+91 98765 43210", "Jio"]
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
    """Jio fixture + a personal mobile number -> the level without a sender, plus the mobile reason; the number is not echoed. The level is Suspicious
    since D23 (was Likely scam): t.jio is on Jio's own .brand TLD and nothing in the message is a hard-risk signal, so P1 caps it."""
    _, base = run(JIO)
    _, rep = run(JIO, MOBILE)
    bad = []
    expect(bad, rep.level == base.level == Level.SUSPICIOUS, f"level {rep.level.value}, without a sender {base.level.value}")
    expect(bad, MOBILE_TITLE in titles(rep) and rep.reasons == base.reasons, f"reasons {rep.reasons} (three warnings: the mobile reason is evidence, not a reason)")
    expect(bad, [e.effect for e in sender_ev(rep)] == [Effect.CAUTION], f"sender evidence {sender_ev(rep)}")
    dumped = rep.model_dump_json()
    expect(bad, "98765" not in dumped and "43210" not in dumped, "the mobile number appears in the Report")
    expect(bad, rep.sender and (rep.sender.kind, rep.sender.header, rep.sender.suffix, rep.sender.label) == ("mobile", None, None, "Personal mobile number"),
           f"sender {rep.sender}")
    return bad

def d3():
    """the demo OTP scam (d02) + a P sender -> still Likely scam, with the misuse evidence naming the OTP request (three warnings fill the reasons)."""
    _, rep = run(DEMO["d02"], "JM-JIOCPN-P")
    bad = []
    expect(bad, rep.level == Level.LIKELY_SCAM, f"level {rep.level.value}")
    expect(bad, MISUSED(OTP_THING) in titles(rep), f"evidence {titles(rep)}")
    return bad

def d4():
    """a gambling-link text (d10) + a P sender -> not softened (same level as without a sender), gambling category, misuse reason naming gambling."""
    _, base = run(DEMO["d10"])
    _, rep = run(DEMO["d10"], "JM-JIOCPN-P")
    bad = []
    expect(bad, rep.level == base.level and rep.level != Level.PROMOTIONAL, f"level {rep.level.value}, without a sender {base.level.value}")
    expect(bad, rep.category == "gambling", f"category {rep.category}")
    expect(bad, MISUSED("it links to a gambling or betting site") in titles(rep), f"evidence {titles(rep)}")
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
    """Jio fixture + the bare header JIOCPN -> Suspicious (capped from Likely scam) + the positive evidence; not Promotional (that needs suffix P).
    The Jio text has three warnings, so the positive reason is evidence only (the page showed it under the sender chip, removed 2026-10-18), and the three reasons are the ones without a sender."""
    _, base = run(JIO)
    _, rep = run(JIO, "JIOCPN")
    bad = []
    expect(bad, rep.level == Level.SUSPICIOUS, f"level {rep.level.value}")
    expect(bad, "Sent from a registered business ID (type unknown)" in titles(rep), f"evidence {titles(rep)}")
    expect(bad, rep.reasons == base.reasons and "The wording is very similar to known scam messages" in rep.reasons, f"reasons {rep.reasons}")
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
    expect(bad, MISUSED(OTP_THING) in titles(rep), f"evidence {titles(rep)}")
    return bad

def d9():
    """row 'dlt with S / T / G / no suffix + no hard-risk -> capped at Suspicious + positive reason', on the Jio text (Likely scam without a sender)."""
    bad = []
    for s, word in (("KA-JIOCPN-S", "Sent from a registered business ID (service)"), ("VM-JIOCPN-T", "Sent from a registered business ID (transactional)"),
                    ("XY-GOVTIN-G", "Sent from a registered government sender ID"), ("AD-JIOCPN", "Sent from a registered business ID (type unknown)")):
        _, rep = run(JIO, s)
        expect(bad, rep.level == Level.SUSPICIOUS, f"{s}: level {rep.level.value}")
        expect(bad, word in titles(rep), f"{s}: evidence {titles(rep)}")
    return bad

def d10():
    """the cap never lowers below Suspicious and never raises: a Suspicious message stays Suspicious, a no-warning one stays no-warning."""
    bad = []
    # the Suspicious example has to be Suspicious from the text head alone, so it depends on the head (D27): MuRIL scores the OTP-login text Likely scam
    suspicious = {config.TEXT_MODEL_KIND: TRICKY["otp-enter-to-confirm"], config.MURIL_KIND: DEMO["g03"]}[config.text_head_choice()[0]]
    for text, want in ((suspicious, Level.SUSPICIOUS), (DEMO["g04"], Level.NO_WARNING_SIGNS)):
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
        expect(bad, (MOBILE_TITLE in titles(rep)) == (base.level in (Level.SUSPICIOUS, Level.LIKELY_SCAM)), f"{i}: mobile evidence {titles(rep)}")
    return bad

def d13():
    """row 'dlt P + no hard-risk -> Promotional' holds whatever the text level: a no-warning text and a too-short one become Promotional too."""
    bad = []
    for text in (DEMO["g03"], "ok"):
        _, rep = run(text, "JM-JIOCPN-P")
        expect(bad, rep.level == Level.PROMOTIONAL and rep.reasons[:1] == [P_TITLE], f"{text[:30]!r}: level {rep.level.value}, reasons {rep.reasons}")
    return bad


# one input per signal whose ONLY hard-risk signal is that one (checked), and the risky thing the misuse reason must name.
# D23: demo d06's link (indiapost-redelivery.top) now also has a brand lookalike flag (link_red_flag), so phishing_link uses a link the URL model rates
# at its scam level with no D23 red flag, and link_red_flag a lookalike the model only rates Suspicious.
PHISH_ONLY = "Your parcel is waiting at the depot. Track it here: http://parcel-redelivery-fee.top/pay"
RED_FLAG_ONLY = "Your parcel is waiting at the depot. Track it here: http://paytm-refund.in/claim"
SINGLE_RISK = [("otp_request", TRICKY["otp-forward"], OTP_THING),
               ("pin_to_receive", TRICKY["pin-receive-cashback"], "it asks for your UPI PIN to receive money"),
               ("phishing_link", PHISH_ONLY, "its link looks like a phishing link"),
               ("link_red_flag", RED_FLAG_ONLY, "its link has a red flag (see the link panel)"),
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


FEAR_THING = {"legal_threat": "it threatens arrest or legal action", "secrecy": "it tells you to keep it secret",
              "cutoff_threat": "it threatens to block or cut off a service", "earning_promise": "it promises guaranteed or easy earnings"}

def f1():
    bad = []
    for i, fam in (("d01", "legal_threat"), ("d05", "cutoff_threat"), ("d07", "earning_promise")):
        r0, base = run(DEMO[i])
        expect(bad, fam in hard_risks(DEMO[i], r0), f"{i}: hard-risk signals {hard_risks(DEMO[i], r0)}, wanted {fam} among them")
        for s in ("JM-JIOCPN-P", "VM-HDFCBK-T", "JIOCPN"):
            r, rep = run(DEMO[i], s)
            expect(bad, rep.level == base.level and rep.level != Level.PROMOTIONAL, f"{i} + {s}: level {rep.level.value}, without a sender {base.level.value}")
            first = r["sender"]["hard_risks"][0] if r["sender"]["hard_risks"] else None
            expect(bad, first == fam and MISUSED(FEAR_THING[fam]) in titles(rep), f"{i} + {s}: first signal {first}, evidence {titles(rep)}")
    return bad

# (family, must hit, must not hit): all synthetic
FAMILY_CASES = [
    ("legal_threat", ["A case has been registered against your Aadhaar. You will be arrested today.", "You are under digital arrest. Stay on the video call.",
                      "Your parcel with illegal items was seized by customs.", "Act immediately to avoid legal consequences."],
                     ["You will not be arrested; this is only a reminder to update your address.", "Report fraud to the cyber crime police at 1930.",
                      "Our court booking for Saturday badminton is confirmed."]),
    ("secrecy", ["Do not tell anyone about this call.", "Keep this confidential and do not inform your bank.", "Do not disconnect this call."],
                ["There is no need to keep this confidential.", "Your OTP is 482913. Do not share it with anyone.", "Join our WhatsApp channel for updates.",
                 "Our secret sale is live! Up to 70% off."]),
    ("cutoff_threat", ["Your SIM will be blocked within 2 hours. Call now.", "Dear consumer, your electricity connection will be disconnected tonight.",
                       "Your account has been blocked. Update your PAN here: http://x.top", "Your KYC is pending. Update today or your account stops.",
                       "Failure to respond will result in account suspension.", "Your account is being blocked. Update your PAN card now."],
                      ["Your card will not be blocked.", "Your card has been blocked after 3 wrong PIN attempts. To unblock, call 1800-180-1234.",
                       "Your KYC is complete. Thank you.", "Your order will be cancelled if not picked up in 3 days.", "Your Airtel pack will expire soon! Recharge now."]),
    ("earning_promise", ["Guaranteed 20% returns every month. Join our stock tips group.", "Earn Rs 3,000 per day working from home, just like videos.",
                         "VIP Task: send Rs 1000 and get Rs 1500 within 10 minutes.", "Double your money in 30 days."],
                        ["Mutual funds are subject to market risk; returns are not guaranteed.", "We never promise guaranteed returns.",
                         "Earn 10X reward points on every purchase this Diwali. T&C apply."]),
]

def f2():
    bad = []
    for fam, hits, misses in FAMILY_CASES:
        for t in hits:
            got = fear_cues(mask_text(t))
            expect(bad, bool(got[fam]), f"{fam}: no hit on {t!r} ({got})")
        for t in misses:
            got = fear_cues(mask_text(t))
            expect(bad, not got[fam], f"{fam}: hit {got[fam]} on {t!r}")
    return bad

PROMOS = [JIO, "Flat 50% off on all shoes! Use coupon SAVE50. Limited period offer. T&C apply.",
          "Get Rs 100 cashback on your first UPI payment. Claim now: https://example-shop.in/c", "FREE 2GB data for 7 days on recharge of Rs 299. Claim now. T&C*",
          "Limited period: free delivery on every order this weekend. Shop now.", "Join our WhatsApp channel for exclusive offers and early access to sales.",
          "Our secret sale is live! Up to 70% off for members only.", "Earn 10X reward points on every purchase this Diwali. T&C apply.",
          "Your free trial of Premium ends in 3 days. Upgrade now and get 20% off.", "Double data offer: get 2X data on all plans this month. Recharge now.",
          "Invest in our Fixed Deposit at 7.5% p.a. Book now in the app.", "Lifetime FREE credit card + 5% unlimited cashback. Limited period offer! Apply now."]

def f3():
    bad = []
    for t in PROMOS:
        r0, _ = run(t)
        expect(bad, not hard_risks(t, r0), f"hard-risk signals {hard_risks(t, r0)} on the promo {t[:50]!r}")
        _, rep = run(t, "JM-JIOCPN-P")
        expect(bad, rep.level == Level.PROMOTIONAL, f"{t[:50]!r} + P: level {rep.level.value}")
    return bad

def f4():
    bad = []
    _, rep = run("Dear customer, send your net banking password to verify your account today.")
    ev = [e for e in rep.evidence if e.id == "rule.otp_request"]
    expect(bad, [(e.title, e.tag, e.quote) for e in ev] == [("Asks you to share a password", "Password request", "send your net banking password")],
           f"password evidence {[(e.title, e.tag, e.quote) for e in ev]}")
    expect(bad, rep.level in (Level.SUSPICIOUS, Level.LIKELY_SCAM), f"level {rep.level.value}")
    _, rep = run("Please share the one-time password sent to your phone.")
    expect(bad, [e.title for e in rep.evidence if e.id == "rule.otp_request"] == ["Asks you to share an OTP, PIN or CVV"], "a one-time password is an OTP")
    return bad

def r1():
    bad = []
    texts = list(DEMO.items()) + [(f"tricky {k}", v) for k, v in TRICKY.items()]
    for i, t in texts:
        _, base = run(t)
        for s in SENDERS:
            _, rep = run(t, s)
            sev = sender_ev(rep)
            if rep.level == Level.PROMOTIONAL:
                expect(bad, rep.reasons[:1] == [sev[0].title], f"{i} + {s}: promotional, reasons {rep.reasons}")
                continue
            want = base.reasons + ([sev[0].title] if sev and len(base.reasons) < 3 else [])
            expect(bad, rep.reasons == want, f"{i} + {s}: reasons {rep.reasons}, wanted {want}")
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
          ("E1", "demo set: sender None / '' / '   ' == no sender argument", e1),
          ("F1", "d01 / d05 / d07 + P, T, bare -> not softened, misuse names the family", f1),
          ("F2", f"fear-cue families on {sum(len(h) + len(m) for _, h, m in FAMILY_CASES)} synthetic hit / miss cases", f2),
          ("F3", f"{len(PROMOS)} promotional texts: no hard-risk signal, Promotional with a P header", f3),
          ("F4", "a password request has its own title; a one-time password keeps the OTP title", f4),
          ("R1", "reason slots: the no-sender reasons come first, unchanged (demo + tricky x 8 senders)", r1)]

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
