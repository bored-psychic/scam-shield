import json, os, sys
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_risk.py")))   # exec()-ed from the project root there is no __file__
sys.path[:0] = [os.path.join(HERE, "..", "src"), HERE]
from demo_check import load_demo
from shield import config
from shield.contracts import Level, Report
from shield.core.report import to_report
from shield.core.risk import BANDS, curve, risk_score
from shield.core.router import analyse, apply_positives
from shield.core.verdict import fuse
from shield.links.lexical import load_url_model
from shield.messages.text_head import load_text_model
import test_contracts as tc

# python tests/test_risk.py   (from the project root; needs both models). Decision D24 (docs/decisions/README.md): the 0-100 risk score and the
# "Lowered from ..." note. Neither changes a level, a threshold, a model or a split.
#   K1  the curve passes through (0,0), (Suspicious cut-off,30), (Likely cut-off,70), (1,100), with the model's real cut-offs; for a head with meter ends
#       (MuRIL, D27) through (p0,0), (Suspicious,30), (Likely,70), (p100,100) on the logit scale, flat beyond the ends. The cut-offs are locked per head
#   K2  for every level, risk_score() over p = 0 .. 1 (step 0.001) stays in the level's band and never decreases as p grows
#   K3  all 363 contract inputs + the 14 demo messages: the score lies in its level's band; None exactly for Can't judge
#   K4  on those real Reports, within one level the score never decreases as the text model's score increases
#   K5  the contract refuses a score outside the band of its level, or any score on Can't judge
#   K6  Lowered: shown for the Jio promo; not for Jio + a mobile number, Jio + an OTP request, any demo message; wherever set it is Suspicious,
#       from Likely scam, with a P1 link in the evidence
#   K7  who lowered it (hand-built results): a P1 link lowering by re-fusion -> note; P2 alone -> none; P1 and P2 together but P2 alone is enough -> none;
#       P1 firing with no change -> none
#   K8  Promotional (dormant, API-only) stays in 0-29 even with a high text score
#   K9  the same text twice gives the same Report (score included)
JIO = "Dear User,\nYou've earned Lifetime Free\nKiwi UPI Credit Card (CC:\nJIOKIWI) on JioRecharge.\nClaim now:\nhttps://t.jio/JIOCPN/x48NuN\nT&C*\nJioCoupons"
JIO_NOTE = "Lowered from Likely scam: the link belongs to Jio (only Reliance can register .jio addresses)."
_M = {}

def models():
    if not _M:
        _M["t"], _M["u"] = load_text_model(), load_url_model()
    return _M["t"], _M["u"]

def run(text, sender=None):
    tm, um = models()
    r = analyse(text, tm, um, sender=sender)
    return r, to_report(text, r)

_ALL = []
def all_reports():
    """(label, text, r, report) for the 363 contract inputs and the 14 demo messages, computed once."""
    if not _ALL:
        for kind, i, t in tc.inputs():
            _ALL.append((f"{kind}:{i}", t, *run(t)))
        for d in load_demo():
            _ALL.append((f"demo:{d['id']}", d["text"], *run(d["text"])))
    return _ALL

CUT_OFFS = {config.TEXT_MODEL_KIND: ((0.423, 0.656), "the D24 text"), config.MURIL_KIND: ((0.103, 0.436), "D27 (reports/calibration_muril_v2.md)")}

def k1():
    tm = models()[0]
    (lo, hi), ends = tm.thresholds, tm.meter_ends
    pts = [(0, 0), (lo, 30), (hi, 70), (1, 100)] if ends is None else [(0, 0), (ends[0] / 2, 0), (ends[0], 0), (lo, 30), (hi, 70), (ends[1], 100), (1, 100)]
    bad = [f"curve({p}) = {curve(p, lo, hi, ends)}, wanted {w}" for p, w in pts if abs(curve(p, lo, hi, ends) - w) > 1e-9]
    want, where = CUT_OFFS[config.text_head_choice()[0]]
    return bad + ([] if (round(lo, 3), round(hi, 3)) == want else [f"cut-offs are {lo:.3f} / {hi:.3f}, {where} says {want[0]} / {want[1]}"])

def k2():
    (lo, hi), ends = models()[0].thresholds, models()[0].meter_ends
    bad = []
    for level, (a, b) in BANDS.items():
        prev = -1
        for i in range(1001):
            s = risk_score(level, i / 1000, (lo, hi), ends)
            if not a <= s <= b:
                bad.append(f"{level.value} p={i / 1000}: {s} outside {a}-{b}")
            if s < prev:
                bad.append(f"{level.value} p={i / 1000}: {s} < {prev}")
            prev = s
        if risk_score(level, None, (lo, hi), ends) != a:
            bad.append(f"{level.value}: no text score should give the band floor {a}")
    return bad[:20]

def k3():
    bad, n_none = [], 0
    for label, t, r, rep in all_reports():
        s = rep.risk_score
        n_none += s is None
        if rep.level == Level.CANT_JUDGE:
            if s is not None:
                bad.append(f"{label}: Can't judge has score {s}")
        elif s is None or not BANDS[rep.level][0] <= s <= BANDS[rep.level][1]:
            bad.append(f"{label}: {rep.level.value} with score {s}")
        if any(c.risk_score is not None or c.lowered is not None for c in rep.children):
            bad.append(f"{label}: a child Report carries a score or a lowered note")
    if n_none == 0:
        bad.append("no Can't judge input in the set: the null case is untested here")
    return bad[:20]

def k4():
    bad = []
    for level in (Level.NO_WARNING_SIGNS, Level.SUSPICIOUS, Level.LIKELY_SCAM):
        rows = sorted((r["text_score"], rep.risk_score, label) for label, t, r, rep in all_reports() if rep.level == level and r["text_score"] is not None)
        if len(rows) < 5:
            bad.append(f"{level.value}: only {len(rows)} rows")
        bad += [f"{level.value}: p={a[0]} -> {a[1]} ({a[2]}) then p={b[0]} -> {b[1]} ({b[2]})" for a, b in zip(rows, rows[1:]) if b[1] < a[1]]
    return bad[:20]

def k5():
    bad = []
    for level, score, ok in ((Level.SUSPICIOUS, 80, False), (Level.SUSPICIOUS, 29, False), (Level.LIKELY_SCAM, 69, False), (Level.NO_WARNING_SIGNS, 30, False),
                             (Level.CANT_JUDGE, 0, False), (Level.CANT_JUDGE, None, True), (Level.SUSPICIOUS, 30, True), (Level.SUSPICIOUS, 69, True),
                             (Level.LIKELY_SCAM, 70, True), (Level.LIKELY_SCAM, 100, True), (Level.NO_WARNING_SIGNS, 0, True), (Level.NO_WARNING_SIGNS, 101, False)):
        try:
            Report(module="messages", level=level, risk_score=score)
            made = True
        except ValueError:
            made = False
        if made != ok:
            bad.append(f"{level.value} score {score}: accepted={made}, wanted {ok}")
    return bad

def k6():
    bad = []
    r, rep = run(JIO)
    if rep.level != Level.SUSPICIOUS or rep.lowered is None or rep.lowered.text != JIO_NOTE or rep.lowered.from_level != Level.LIKELY_SCAM:
        bad.append(f"Jio: level {rep.level.value}, lowered {rep.lowered}")
    if rep.risk_score is None or not 30 <= rep.risk_score <= 69:
        bad.append(f"Jio: score {rep.risk_score}")
    for name, text in (("mobile", JIO + "\nCall 9876543210 to activate"), ("otp", JIO + "\nShare the OTP sent to you to claim.")):
        r, rep = run(text)
        if rep.lowered is not None or rep.level != Level.LIKELY_SCAM:
            bad.append(f"Jio + {name}: level {rep.level.value}, lowered {rep.lowered}")
    for label, t, r, rep in all_reports():
        if label.startswith("demo:") and rep.lowered is not None:
            bad.append(f"{label}: lowered note on a demo message")
        if rep.lowered is not None:
            has_p1 = any(e.id in ("link.brand_owned", "link.bank_in") for c in rep.children for e in c.evidence)
            if rep.level != Level.SUSPICIOUS or rep.lowered.from_level != Level.LIKELY_SCAM or not has_p1:
                bad.append(f"{label}: lowered {rep.lowered} at {rep.level.value}, P1 evidence {has_p1}")
    return bad

def link(risk, positive, lowered=None):
    return {"url": "https://x.test/", "kind": "model", "base_level": risk, "risk_level": risk, "level": risk, "positive": positive, "flags": [], "gambling": None,
            "checks": {"positive": {"title": "Belongs to X", **({"lowered": lowered} if lowered else {})}}}

def result(text_level, links, level=None):
    ul = [l["risk_level"] for l in links if l["risk_level"] is not None]
    return {"cred_request": [], "pin_to_receive": [], "links": links, "text_level": text_level, "url_level": max(ul) if ul else None,
            "level": fuse(text_level, max(ul) if ul else None) if level is None else level}

def k7():
    bad, T = [], "hello there, a plain note"
    P1 = "{} belongs to X (only X can register .x addresses)"
    cases = [
        ("P1 lowers by re-fusion (text Suspicious, link rated Likely)", 1, [link(2, "p1", P1)], "Lowered from Likely scam: the link belongs to X (only X can register .x addresses)."),
        ("P1 cap (text Likely scam, no phone number in the text)", 2, [link(0, "p1", P1)], "Lowered from Likely scam: the link belongs to X (only X can register .x addresses)."),
        ("P2 alone lowers", 1, [link(2, "p2")], None),
        ("P1 present but P2 alone is enough", 1, [link(0, "p1", P1), link(2, "p2")], None),
        ("P1 fired, level unchanged (text Likely scam, MOBILE in the text)", 2, [link(0, "p1", P1)], None),
    ]
    for name, tl, links, want in cases:
        text = T + (" call 9876543210" if "MOBILE" in name else "")
        r = result(tl, links)
        before = r["level"]
        apply_positives(text, r)
        got = r["lowered"] and r["lowered"]["text"]
        if got != want:
            bad.append(f"{name}: lowered {got!r}, wanted {want!r} (level {before} -> {r['level']})")
        if want and r["lowered"]["from"] != before:
            bad.append(f"{name}: from {r['lowered']['from']}, wanted {before}")
    return bad

def k8():
    bad = []
    for text in (JIO, "Hello, your order has shipped"):
        r, rep = run(text, sender="JM-JIOCPN-P")
        if rep.level != Level.PROMOTIONAL:
            bad.append(f"{text[:20]!r} + P header: level {rep.level.value}")
        elif rep.risk_score is None or not 0 <= rep.risk_score <= 29:
            bad.append(f"{text[:20]!r}: Promotional score {rep.risk_score} (text score {r['text_score']})")
    return bad

def k9():
    return [f"{t[:30]!r}: {a.risk_score} / {b.risk_score}" for t in (JIO, "Your OTP is 123456. Do not share it.") for (_, a), (_, b) in [(run(t), run(t))]
            if a.model_dump(mode="json") != b.model_dump(mode="json")]

CHECKS = [("K1", "the curve passes through the four anchor points (real cut-offs)", k1),
          ("K2", "every level: score in its band and non-decreasing in p (0..1, step 0.001)", k2),
          ("K3", "363 contract inputs + 14 demo messages: score in the level's band, None only for Can't judge", k3),
          ("K4", "within a level the score never decreases as the text score grows (real Reports)", k4),
          ("K5", "the contract refuses a score outside its level's band", k5),
          ("K6", "Lowered note: Jio yes; Jio + mobile, Jio + OTP, the demo set no; only Suspicious from Likely scam with P1 evidence", k6),
          ("K7", "who lowered it: P1 yes, P2 alone no, P1 with no change no (hand-built results)", k7),
          ("K8", "Promotional stays in 0-29", k8),
          ("K9", "deterministic: the same text gives the same Report", k9)]

def results():
    return [(cid, what, fn()) for cid, what, fn in CHECKS]

def test_risk():
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
