import os, re, sys
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_invest_rules.py")))
sys.path[:0] = [os.path.join(HERE, "..", "src"), HERE]
import csv

# python tests/test_invest_rules.py   (from the project root; pytest runs the same checks). The investment-scam rules A1-A12 (Phase A of
# docs/plans/investment_scams.md; src/shield/messages/invest_rules.py) and the @valid UPI mask (src/pii.py, 2026-10-25).
#   I1 pii: SEBI @valid ids mask as <UPI_ID>; personal handles, e-mail addresses and dotless hosts keep their masks
#   I2 every rule has a message it fires on and a look-alike it stays quiet on (the look-alikes are the genuine forms the val / train sweeps found)
#   I3 SEBI's own @valid templates and ids fire nothing, and a personal UPI id in the same message fires A1
#   I4 raise-only, through the router: with the rules the level is never below the level without them; a hook rule alone gives at least Suspicious,
#      a money rule alone gives Likely scam; a rule hit never makes a level lower (checked on the 102 probe rows and the A-rule examples)
#   I5 the Report: one rule.invest_* evidence per hit with a quote that is text[span], a tag of <= 24 characters, danger for money / caution for hook rules,
#      the SEBI advice line right after the gambling line iff a rule fired; every Report validates
#   I6 a registered promotional sender does not soften a message the rules fired on (the hard-risk signal 'investment_rule')
#   I7 the probe (data/probe/investment_v1.csv, PROBE-ONLY): the rules fire on no genuine row; they fire on at least 41 of the 54 scam rows
#   I8 the frontend's English strings are the backend's (reasons, advice, tags are not translated twice differently)
#   I9 a UPI id or an e-mail address is not a link: 'pay to rajesh.trade88@ybl' yields no link, no link report and no live lookup (live checks patched to record calls)
ROOT = os.path.join(HERE, "..")
PROBE = os.path.join(ROOT, "data", "probe", "investment_v1.csv")

# code -> (a message the rule fires on, a look-alike it stays quiet on)
CASES = {
    "A1": ("Pay Rs 25,000 to rajesh.trade88@ybl to activate your trading account.", "Pay Rs 25,000 to examplebroker.brk@validhdfc for your trading account."),
    "A2": ("We are SEBI registered advisers. Join for daily stock tips.", "Research call: BUY EXAMPLE 412. SEBI RA Reg. No. INH000012345. Investments are subject to market risks."),
    "A3": ("Guaranteed returns of 30% every month on your investment.", "No one can promise guaranteed returns in the stock market."),
    "A4": ("To withdraw your profit you must first pay 20% tax.", "Do not pay any fee to withdraw your funds; there is none."),
    "A5": ("Join our VIP group for daily stock tips.", "Join our WhatsApp group for exam updates and notes."),
    "A6": ("Share your login and password and we handle your trading account.", "Never share your login or password with anyone, including us."),
    "A7": ("Part-time job: like videos and earn Rs 3000 per day.", "Full time role, salary Rs 25,000 per month, paid daily on attendance."),
    "A8": ("Higher level tasks are prepaid: deposit Rs 5,000 to unlock them.", "Prepaid mobile recharge of Rs 299 was successful."),
    "A9": ("Download our trading app from https://x.example.top/app.apk to get stock tips.", "Use the official broker app for stock trading; we never ask you to install apps from links."),
    "A10": ("Get IPO pre-allotment through our institutional account.", "Your IPO application was submitted. A UPI mandate request has been sent."),
    "A11": ("Nirmala Sitharaman launched a scheme: invest Rs 22,000 and earn Rs 20 lakh a month.", "The Finance Minister presented the budget in Parliament today."),
    "A12": ("Deposit 100 USDT to start earning on the platform.", "Our cryptography course starts Monday; pay the fee online."),
}
HOOK, MONEY = {"A2", "A3", "A5", "A6", "A7", "A9", "A10", "A11"}, {"A1", "A4", "A8", "A12"}
SEBI_TEMPLATES = ["We have a validated UPI ID for payment, please pay us at examplebroker.brk@validhdfc.",
                  "To make your payments secure, we got a validated UPI handle examplebroker.brk@validicici.",
                  "The market now has new validated and exclusive UPI IDs, visit our website to know more.",
                  "To add funds to your trading account, pay by UPI only to examplebroker.brk@validhdfc and check the green thumbs-up icon before entering your PIN. Never pay to any personal account."]


def codes(text):
    from shield.messages.invest_rules import invest_rule_hits
    return [h["code"] for h in invest_rule_hits(text)]


def i1():
    from pii import mask_text
    bad = []
    for raw, want in (("pay examplebroker.brk@validhdfc now", "pay <UPI_ID> now"), ("xyz.mf@validicici", "<UPI_ID>"), ("Name.RA@VALIDAXIS", "<UPI_ID>"),
                      ("rajesh@ybl", "<UPI_ID>"), ("x@gmail.com", "<EMAIL>"), ("root@localhost", "<EMAIL>"), ("a.b@validbank.co.in", "<EMAIL>"),
                      ("class=x>@Valid SignupForm", "class=x>@Valid SignupForm")):
        if mask_text(raw) != want:
            bad.append(f"mask_text({raw!r}) = {mask_text(raw)!r}, wanted {want!r}")
    return bad


def i2():
    bad = []
    for code, (fires, quiet) in CASES.items():
        if code not in codes(fires):
            bad.append(f"{code} did not fire on {fires!r}: {codes(fires)}")
        if code in codes(quiet):
            bad.append(f"{code} fired on the look-alike {quiet!r}")
    return bad


def i3():
    bad = [f"a rule fired on SEBI's own template {t!r}: {codes(t)}" for t in SEBI_TEMPLATES if codes(t)]
    mixed = SEBI_TEMPLATES[3] + " Or pay Rs 25,000 to rajesh.trade88@ybl for VIP stock tips."
    if "A1" not in codes(mixed):
        bad.append(f"A1 missed a personal UPI id next to a @valid id: {codes(mixed)}")
    return bad


def models():
    from shield.links.lexical import load_url_model
    from shield.messages.text_head import load_text_model
    return load_text_model(), load_url_model()


def i4():
    from shield.core.router import analyse
    tm, um = models()
    bad = []
    texts = [v[0] for v in CASES.values()] + SEBI_TEMPLATES + [r["text"] for r in csv.DictReader(open(PROBE, encoding="utf-8", newline=""))]
    for code, (fires, _) in CASES.items():
        on, off = analyse(fires, tm, um, invest_rules=True), analyse(fires, tm, um, invest_rules=False)
        floor = 2 if code in MONEY else 1
        if on["level"] is None or on["level"] < floor:
            bad.append(f"{code}: level {on['level']} with the rule, wanted >= {floor}")
        if off["invest_rules"] != []:
            bad.append(f"{code}: invest_rules=False still produced hits")
    for t in texts:
        on, off = analyse(t, tm, um, invest_rules=True), analyse(t, tm, um, invest_rules=False)
        a, b = on["level"], off["level"]
        if (b or 0) > (a or 0) or (b is not None and a is None):
            bad.append(f"a rule lowered the level {b} -> {a} on {t[:60]!r}")
        if on["invest_rules"] and (a or 0) < max(h["floor"] for h in on["invest_rules"]):
            bad.append(f"level {a} below the rule floor on {t[:60]!r}")
        if not on["invest_rules"] and a != b:
            bad.append(f"no hit but the level changed {b} -> {a} on {t[:60]!r}")
    return bad


def i5():
    from shield.contracts import Effect, Report
    from shield.core.advice import GAMBLING_ADVICE, INVESTMENT_ADVICE
    from shield.core.report import to_report
    from shield.core.router import analyse
    tm, um = models()
    bad = []
    t = "Join our VIP group for stock tips. Guaranteed returns! Pay Rs 25,000 to rajesh.trade88@ybl to activate."
    rep = to_report(t, analyse(t, tm, um))
    inv = [e for e in rep.evidence if e.id.startswith("rule.invest_")]
    if {e.id for e in inv} != {"rule.invest_upi", "rule.invest_guaranteed", "rule.invest_vip_group"}:
        bad.append(f"evidence ids {[e.id for e in inv]}")
    for e in inv:
        if e.quote is None or t[e.span[0]:e.span[1]] != e.quote or len(e.tag) > 24 or not re.match(r"^rule\.invest_[a-z_]+$", e.id):
            bad.append(f"bad evidence {e.id}: {e.quote!r} {e.span} {e.tag!r}")
    eff = {e.id: e.effect for e in inv}
    if eff.get("rule.invest_upi") != Effect.DANGER or eff.get("rule.invest_guaranteed") != Effect.CAUTION:
        bad.append(f"effects {eff}")
    if rep.advice[0] != INVESTMENT_ADVICE or "@valid" not in rep.advice[0] or "sebi.gov.in" not in rep.advice[0]:
        bad.append(f"advice {rep.advice}")
    if Report.model_validate_json(rep.model_dump_json()) != rep or len(rep.reasons) > 3 or not set(rep.reasons) <= {e.title for e in rep.evidence}:
        bad.append("Report does not round-trip, or reasons are not evidence titles")
    if rep.reasons[0] != "Asks for investment money to a UPI ID that is not a SEBI @valid ID.":
        bad.append(f"first reason {rep.reasons[0]!r}")
    # no rule: no investment line, and the gambling line still comes first when both apply
    plain = to_report("Your OTP is 482913. Do not share it with anyone. -SBI", analyse("Your OTP is 482913. Do not share it with anyone. -SBI", tm, um))
    if INVESTMENT_ADVICE in plain.advice:
        bad.append("investment line on a message with no rule")
    g = "Big IPL offer! Deposit Rs 500 and play now: https://bet365.com/promo. Join our VIP group for stock tips with guaranteed returns."
    rg = to_report(g, analyse(g, tm, um))
    if rg.category == "gambling" and rg.advice[:2] != [GAMBLING_ADVICE, INVESTMENT_ADVICE]:
        bad.append(f"gambling + investment advice order: {rg.advice[:2]}")
    return bad


def i6():
    from shield.core.report import to_report
    from shield.core.router import analyse
    tm, um = models()
    t = "Dear user, join our VIP group for stock tips. Guaranteed returns every month."
    r = analyse(t, tm, um, sender="JM-JIOCPN-P")
    bad = []
    if r["level"] == "promotional" or "investment_rule" not in r["sender"]["hard_risks"]:
        bad.append(f"a P sender softened an investment-rule message: level {r['level']}, risks {r['sender']['hard_risks']}")
    to_report(t, r)
    return bad


def i7():
    rows = list(csv.DictReader(open(PROBE, encoding="utf-8", newline="")))
    bad = [f"fired on genuine probe row {r['id']}: {codes(r['text'])}" for r in rows if r["label"] == "0" and codes(r["text"])]
    caught = sum(bool(codes(r["text"])) for r in rows if r["label"] == "1")
    if caught < 41:
        bad.append(f"only {caught} of 54 probe scams caught")
    return bad


def i8():
    ts = open(os.path.join(ROOT, "frontend", "src", "lib", "investment.ts"), encoding="utf-8").read()
    from shield.messages.invest_rules import RULES, SEBI_ADVICE
    bad = [f"{id_}: English title or tag not in frontend/src/lib/investment.ts" for _, id_, _, _, tag, title in RULES if title not in ts or id_ not in ts or tag not in ts]
    if SEBI_ADVICE not in ts:
        bad.append("English SEBI advice not in frontend/src/lib/investment.ts")
    return bad


def i9():
    from shield import config
    from shield.core import router
    from shield.core.report import to_report
    from textprep import extract_urls, model_text, replace_urls
    tm, um = models()
    bad = []
    for t in ("pay to rajesh.trade88@ybl", "pay to rajesh.trade88@ybl.", "Pay Rs 25,000 to rajesh.trade88@ybl to activate your VIP trading account.", "mail user.name@gmail.com now"):
        if extract_urls(t) or "<URL>" in replace_urls(t) or "<URL>" in model_text(t, mask_pii=True):
            bad.append(f"a link was found in {t!r}: {extract_urls(t)}")
    calls, real = [], router.live_checks.run
    router.live_checks.run = lambda urls, *a, **k: (calls.append(list(urls)) or {})
    saved = config.LIVE_CHECKS
    config.LIVE_CHECKS = True
    try:
        r = router.analyse("pay to rajesh.trade88@ybl", tm, um, live=True)
        rep = to_report("pay to rajesh.trade88@ybl", r)
        if r["links"] or rep.children:
            bad.append(f"a link report for a UPI id: {[l['url'] for l in r['links']]}")
        if calls:
            bad.append(f"a live lookup was made for {calls}")
        control = router.analyse("pay to example.com", tm, um, live=True)   # the same code path does look a real link up (the patched run records it)
        if not control["links"] or not calls:
            bad.append("control: a plain domain was not looked up, so this check proves nothing")
    finally:
        router.live_checks.run, config.LIVE_CHECKS = real, saved
    return bad


CHECKS = [("I1", "@valid ids mask as <UPI_ID>", i1), ("I2", "each rule fires on its message and not on its look-alike", i2),
          ("I3", "SEBI's own @valid templates fire nothing; a personal UPI id still fires A1", i3), ("I4", "raise-only through the router", i4),
          ("I5", "Report evidence, reasons and the SEBI advice line", i5), ("I6", "a registered promotional sender does not soften a rule hit", i6),
          ("I7", "probe v1: 0 genuine fires, >= 41 of 54 scams", i7), ("I8", "frontend English strings equal the backend's", i8),
          ("I9", "a UPI id / e-mail address is not a link: no link, no live lookup", i9)]


def run():
    out = []
    for cid, title, fn in CHECKS:
        try:
            bad = fn()
        except BaseException as e:
            bad = [f"{type(e).__name__}: {str(e)[:300]}"]
        out.append((cid, title, bad))
    return out


def test_invest_rules():
    bad = [f"{cid}: {b}" for cid, _, bs in run() for b in bs]
    assert not bad, "\n".join(bad)


if __name__ == "__main__":
    res = run()
    for cid, title, bad in res:
        print(("PASS" if not bad else "FAIL"), cid, title)
        for b in bad:
            print("    ", b)
    print(f"\n{sum(not b for _, _, b in res)}/{len(res)} passed")
    sys.exit(any(b for _, _, b in res))
