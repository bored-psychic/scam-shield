import os, sys
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_fold.py")))   # exec()-ed from the project root there is no __file__
sys.path[:0] = [os.path.join(HERE, "..", "src"), HERE]
from pii import mask_text
from shield.contracts import Level
from shield.core.fold import FOLD_LINE, FOLD_NEEDS_REVIEW, fold
from shield.core.report import to_report
from shield.core.router import analyse
from shield.links.lexical import load_url_model
from shield.messages.invest_rules import invest_rule_hits
from shield.messages.rules import cred_requests, pin_to_receive
from shield.messages.tactics import tactic_tags

# python tests/test_fold.py   (from the project root; needs the URL model; the end-to-end checks use a stub text head with a fixed low score, so only the rules
# can raise a level and the result does not depend on which head is active). D11: the rules match on a folded view of the raw text.
#   F1  fold() undoes Cyrillic / Greek / fullwidth / mathematical / small-capital look-alikes, zero-width characters and leet (table of cases)
#   F2  fold() leaves amounts, OTP codes, phone numbers, UPI ids, e-mail addresses, quantities, times, links and Hindi / Kannada text exactly as they are
#   F3  the FoldMap: a span of the folded text maps back to the original characters (zero-width characters inside or beside the match, fullwidth, ligature)
#   F4  every rule family fires on the disguised variants of its phrase: OTP, PIN, R2 PIN-to-receive, investment A1-A12 (all 12), tactic tags
#   F5  the disguised phrase gets the same level as the plain phrase, the evidence quotes the user's own text (span slices back to the quote), and the reason
#       line "Hidden or look-alike characters ..." is there; the plain phrase has no such line and the fold is raise-only for this set
#   F6  genuine messages and advisories (no disguise) get an identical Report with fold on and off; a "Do not share your OTP" advisory in disguise stays an advisory
#   F7  the reason line: EN / HI / KN, HI / KN needs-review; fold=False restores the old behaviour (the disguised phrase is missed)

class Stub:
    name, thresholds = "stub", (0.1, 0.4)
    def score(self, prepared): return 0.02
    def explain(self, prepared, k=14): return []

_URL = []
def um():
    if not _URL:
        _URL.append(load_url_model())
    return _URL[0]

def run(text, **kw):
    r = analyse(text, Stub(), um(), **kw)
    return r, to_report(text, r)

CYR = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "i": "і", "y": "у", "s": "ѕ"}
def cyr(t):
    return "".join(CYR.get(c, c) for c in t)
def zw(t):
    return "​".join(t)   # a zero-width space between every character
def zw_some(t):
    return "".join(c + "​" if c.isalpha() and i % 3 == 0 else c for i, c in enumerate(t))
def full(t):
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in t)
def math_bold(t):
    return "".join(chr(0x1D5D4 + ord(c) - 65) if "A" <= c <= "Z" else chr(0x1D5EE + ord(c) - 97) if "a" <= c <= "z" else c for c in t)
GREEK = {"A": "Α", "B": "Β", "E": "Ε", "I": "Ι", "K": "Κ", "M": "Μ", "N": "Ν", "O": "Ο", "P": "Ρ", "T": "Τ", "Y": "Υ", "X": "Χ"}
def greek(t):
    return "".join(GREEK.get(c, c) for c in t)
def _per_word(t, fn):
    """fn on every space-separated word except a UPI id / e-mail address (an attacker who garbles the id breaks the payment) and a link."""
    return " ".join(w if "@" in w or "." in w and "/" in w else fn(w) for w in t.split(" "))
def _alternate(w, table):
    """Swap every other occurrence of the letters in table (the first, third ...), the way a partial leet attack does."""
    seen, out = 0, []
    for c in w:
        if c in table:
            out.append(table[c] if seen % 2 == 0 else c)
            seen += 1
        else:
            out.append(c)
    return "".join(out)
def leet(t):
    return _per_word(t, lambda w: _alternate(w, {"o": "0", "O": "0", "e": "3", "a": "4", "s": "5", "i": "1"}))
def leet_sym(t):
    return _per_word(t, lambda w: _alternate(w, {"a": "@", "s": "$"}))
def leet_all(t):
    return _per_word(t, lambda w: w.replace("a", "@").replace("s", "$"))

# F1: (disguised, what fold must give, comparing case-insensitively)
F1 = [("Shаre your OTP", "Share your OTP"), ("O​TP is the code", "OTP is the code"), ("ＳＨＡＲＥ ｏｔｐ", "SHARE otp"),
      (math_bold("Share your OTP"), "Share your OTP"), ("ꜱʜᴀʀᴇ ᴏᴛᴘ", "share otp"), ("Τhε ΟΤΡ", "The OTP"),
      ("sh4re y0ur 0TP", "share your oTP"), ("send your P1N", "send your PiN"), ("v3r1fy 1nvest tr4d1ng", "verify invest trading"), ("sh@re your p@ssword", "share your password"),
      ("pa$$word and $hare", "password and share"), ("café ñ", "cafe n"), ("éclair", "eclair"), ("a‍‌b", "ab"), ("a­b﻿c⁠d", "abcd"),
      ("ﬁnal", "final"), ("① ②", "1 2")]
# F2: unchanged
F2 = ["Rs 5,000 credited to A/c XX1234 on 12-10-2026. Ref 482913.", "Your OTP is 482913. Valid for 10 min.", "Call 9876543210 or +91 98765 43210 now", "pay rajesh.trade88@ybl 9876543210",
      "raj3sh@okaxis and name.brk@validhdfc and john3@gmail.com", "Rs5000 Rs5 within 4hrs on the 3rd, 1st, 2nd at 10am 5k 3pm 2x", "24x7 2FA T20 5G 4B H2O", "OTP 482913 PIN 1234 CVV 456",
      "https://bit.ly/3xYz9 and www.sbi-kyc.xyz/a1b2c3", "आपका OTP किसी को न बताएं क़ क्ष",
      "ನಿಮ್ಮ OTP ಹಂಚಿಕೊಳ್ಳಬೇಡಿ", "क्ष‍न ನ‌ಿ", "@john is $5", "GA MART Rs 151OFF Rs 5", "Message-ID: <007e01c1515d$bb255940$x@ybl> CB1 2DH EH1 SB1 RB1", "Rs 5000 and seat R5, @telegram @amazon @john", "order #4521, call 1800 123 456"]

def f1():
    bad = []
    for dis, want in F1:
        got, _ = fold(dis)
        if got != want:
            bad.append(f"fold({dis!r}) = {got!r}, wanted {want!r}")
    return bad

def f2():
    return [f"fold changed {t!r} -> {fold(t)[0]!r}" for t in F2 if fold(t)[0] != t]

def f3():
    bad = []
    t = "Plеase sh​аre yоur O​TP ①"
    f, m = fold(t)
    i = f.index("share")
    s, e = m.span(i, i + 5)
    if t[s:e] != "sh​аre":
        bad.append(f"share -> {t[s:e]!r}")
    i = f.index("OTP")
    s, e = m.span(i, i + 3)
    if t[s:e] != "O​TP":
        bad.append(f"OTP -> {t[s:e]!r}")
    f, m = fold("x ﬁnal y")   # the ligature becomes two characters, both mapped to it
    i = f.index("final")
    s, e = m.span(i, i + 5)
    if "x ﬁnal y"[s:e] != "ﬁnal":
        bad.append(f"ligature span {s, e}")
    f, m = fold("ab​")
    if m.span(2, 2) != (3, 3) or len(f) != 2:
        bad.append(f"end span {m.span(2, 2)}")
    return bad

# F4: the plain phrase of each rule (it must fire), then it is disguised in every way
PLAIN = {
    "OTP": ["Please share your OTP with the agent", "Kindly send your CVV and card number", "Share your net banking password now"],
    "PIN": ["Tell me your UPI PIN", "Give us your ATM PIN to proceed", "OTP bata do"],
    "R2": ["Enter your UPI PIN to receive the refund", "Put your MPIN to get the cashback"],
    "A1": ["Invest in stocks, pay Rs 5000 to rajesh.trade@ybl for the trading tips"],
    "A2": ["We are SEBI registered advisers for stocks"],
    "A3": ["Guaranteed returns on your investment, 5% daily"],
    "A4": ["To withdraw your profits you must first pay a 15% tax"],
    "A5": ["Join our VIP stock tips group on telegram now"],
    "A6": ["Share your trading login and we will handle your account"],
    "A7": ["Earn Rs 5000 daily by liking videos, part time work"],
    "A8": ["Prepaid task deposit needed: Rs 3000 to unlock the next level"],
    "A9": ["Download our trading app, install the .apk for stock signals"],
    "A10": ["IPO pre-allotment through our institutional account"],
    "A11": ["Nirmala Sitharaman invest scheme gives returns"],
    "A12": ["Deposit USDT to start earning returns"],
    "tactic": ["URGENT: your account will be blocked, the police and the RBI officer will act immediately, tell no one"],
}
def disguises(t):
    return {"cyrillic": cyr(t), "zero-width": zw_some(t), "zero-width everywhere": zw(t), "fullwidth": full(t), "math bold": math_bold(t), "greek": greek(t),
            "leet digits": leet(t), "leet symbols": leet_sym(t), "leet symbols (all)": leet_all(t)}

def rule_codes(text, fold_on):
    """Every rule family that fires on the text, the way analyse() reads it."""
    import shield.config as config
    r, _ = run(text, fold=fold_on)
    codes = set()
    if r["cred_request"]: codes.add("OTP")
    if r["pin_to_receive"]: codes.add("R2")
    codes |= {h["code"] for h in r["invest_rules"]}
    if any(r["tags"].values()): codes.add("tactic")
    return codes

def f4():
    bad, table = [], {}
    for fam, plains in PLAIN.items():
        for p in plains:
            want = {"OTP": "OTP", "PIN": "OTP", "R2": "R2", "tactic": "tactic"}.get(fam, fam)
            if want not in rule_codes(p, True):
                bad.append(f"[{fam}] the plain phrase {p!r} does not fire (fix the case)")
                continue
            for name, d in disguises(p).items():
                # a digit-for-letter swap can only be undone for the letters the swap touches in a token that has letters: the phrase must still fire
                got = want in rule_codes(d, True)
                table.setdefault((fam, name), []).append(got)
                if not got:
                    bad.append(f"[{fam}] {name}: {d!r} does not fire {want}")
    f4.table = {k: f"{sum(v)}/{len(v)}" for k, v in table.items()}
    return bad

def f5():
    bad = []
    for fam in ("OTP", "R2", "A3", "A5", "A12"):
        p = PLAIN[fam][0]
        r0, rep0 = run(p)
        for name, d in disguises(p).items():
            if d == p:
                continue
            r1, rep1 = run(d)
            if rep1.level != rep0.level:
                bad.append(f"[{fam}] {name}: level {rep1.level.value}, the plain phrase gets {rep0.level.value}")
            # the line is there exactly when the rule needed the fold: if the raw view of the disguised text still fires it, there is nothing to report
            needed = r1["fold_hits"] != []
            if needed != (FOLD_LINE["en"] in rep1.reasons) or needed != any(e.id == "fold.hidden" for e in rep1.evidence):
                bad.append(f"[{fam}] {name}: fold_hits {r1['fold_hits']}, reasons {rep1.reasons}")
            if not needed and name not in ("greek", "fullwidth", "leet symbols", "leet symbols (all)", "leet digits", "math bold", "cyrillic"):
                bad.append(f"[{fam}] {name}: the fold was not needed for the rule")
            if any(e.id == "fold.hidden" for e in rep0.evidence):
                bad.append(f"[{fam}] the plain phrase has a fold.hidden evidence")
            for e in rep1.evidence:
                if e.span is not None and d[e.span[0]:e.span[1]] != e.quote:
                    bad.append(f"[{fam}] {name}: {e.id} span {e.span} does not slice back to {e.quote!r}")
            rule_ev = [e for e in rep1.evidence if e.id.startswith("rule.")]
            if not rule_ev or not all(e.quote for e in rule_ev):
                bad.append(f"[{fam}] {name}: rule evidence without a quote {[e.id for e in rule_ev]}")
            if len(rep1.reasons) > 3:
                bad.append(f"[{fam}] {name}: {len(rep1.reasons)} reasons")
    return bad

GENUINE = ["Rs 5,000 credited to A/c XX1234 on 12-10-2026. Do not share your OTP with anyone.", "Your OTP is 482913. Never share it. Valid for 10 min.",
           "Your order will be delivered by 3pm on the 4th. Track at the app.", "Hi, are we meeting at 5? Call me on 9876543210",
           "आपका OTP किसी को न बताएं।", "SEBI cautions investors: no one can promise guaranteed returns.",
           "Your electricity bill of Rs 1,250 is due on the 5th. Pay at the counter."]

def f6():
    bad = []
    for t in GENUINE:
        a, b = run(t, fold=False)[1], run(t, fold=True)[1]
        if a.model_dump() != b.model_dump():
            bad.append(f"fold changes the Report of {t!r}")
    adv = "Do not share your OTP with anyone."
    for name, d in disguises(adv).items():
        r, rep = run(d)
        if r["cred_request"]:
            bad.append(f"the disguised advisory ({name}) {d!r} is read as a request: {r['cred_request']}")
    return bad

def f7():
    bad = []
    if set(FOLD_LINE) != {"en", "hi", "kn"} or FOLD_NEEDS_REVIEW != {"en": False, "hi": True, "kn": True}:
        bad.append(f"line languages {sorted(FOLD_LINE)} / {FOLD_NEEDS_REVIEW}")
    if not any("ऀ" <= c <= "ॿ" for c in FOLD_LINE["hi"]) or not any("ಀ" <= c <= "೿" for c in FOLD_LINE["kn"]):
        bad.append("the Hindi / Kannada lines are not in their scripts")
    d = cyr(PLAIN["OTP"][0])
    r, rep = run(d, fold=False)
    if r["cred_request"] or r["fold_hits"] or r["fold_map"] is not None or r["folded"] != d:
        bad.append("fold=False does not restore the old behaviour")
    return bad

CHECKS = [("F1", f"fold() undoes {len(F1)} disguises (Cyrillic, Greek, fullwidth, mathematical, small capitals, zero-width, soft hyphen, accents, leet)", f1),
          ("F2", f"fold() leaves {len(F2)} amounts / codes / numbers / ids / links / hi / kn strings exactly as they are", f2),
          ("F3", "the FoldMap maps folded spans back to the original characters", f3),
          ("F4", "every rule family fires on the 9 disguises of its phrases (OTP, PIN, R2, A1-A12, tactics)", f4),
          ("F5", "disguised = same level as plain, quotes are the user's own text, the reason line is there", f5),
          ("F6", f"{len(GENUINE)} genuine messages: identical Report with fold on / off; a disguised advisory stays an advisory", f6),
          ("F7", "the reason line (EN / HI / KN, needs-review) and fold=False", f7)]

def results():
    return [(cid, what, fn()) for cid, what, fn in CHECKS]

def test_fold():
    bad = [f"{cid}: {b}" for cid, _, bs in results() for b in bs]
    assert not bad, "\n".join(bad)

if __name__ == "__main__":
    res = results()
    for cid, what, bad in res:
        print(f"{'FAIL' if bad else 'PASS'} {cid} {what}")
        for b in bad[:12]:
            print("    " + b.encode("ascii", "backslashreplace").decode()[:300])
    print(f"\nF4 fired / tried, per family x disguise: {getattr(f4, 'table', None)}")
    print(f"{sum(not b for _, _, b in res)}/{len(res)} passed")
    sys.exit(1 if any(b for _, _, b in res) else 0)
