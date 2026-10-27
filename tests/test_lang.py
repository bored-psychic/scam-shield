import contextlib, os, sys
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_lang.py")))   # exec()-ed from the project root there is no __file__
sys.path[:0] = [os.path.join(HERE, "..", "src"), HERE]
from demo_check import load_demo
from shield.contracts import Level, Report
from shield.core import router
from shield.core.lang import LANG_CAP_LINE, LANG_CAP_NEEDS_REVIEW, detect_lang
from shield.core.report import to_report
from shield.core.router import analyse, apply_language_cap
from shield.links.lexical import load_url_model
from shield.links.lists import LinkLists
from shield.messages.text_head import load_text_model
import test_contracts as tc
from test_links_live import FIXTURES, NOW

# python tests/test_lang.py   (from the project root; needs the URL model; the end-to-end checks use a stub text head with a fixed score, so they do not
# depend on which head is active; Z7 uses the active head). D5 section 6 + D6: in Hindi, Kannada and Hinglish the text model alone reaches at most Suspicious.
#   Z1  detect_lang on en / hi / kn / Hinglish / mixed / emoji-only / numbers-only / link-only / other-script / empty
#   Z2  the cap line: English wording, Hindi and Kannada in their scripts, hi / kn marked needs-review
#   Z3  a kn, hi or Hinglish message the text head scores Likely scam is shown Suspicious, with the reason line last, meta.lang set, score in the band;
#       the same score in English stays Likely scam; lang_cap=False and a Suspicious text score change nothing
#   Z4  not capped: a kn message with a blocklisted link stays Likely scam; an OTP request still forces at least Suspicious (rules are not lowered)
#   Z5  apply_language_cap on hand-built results: only "text Likely, no link rated Suspicious or higher, no Likely-floor investment rule" is capped
#   Z6  Report.meta.lang is set on every Report, a valid label
#   Z7  contract inputs + demo set with the active head: the cap changes only Likely scam -> Suspicious, only in a capped language; the 14 demo messages are unchanged

class Stub:
    """A text head with a fixed score (the router only reads thresholds, score and explain)."""
    name, thresholds = "stub", (0.1, 0.4)
    def __init__(self, score): self.s = score
    def score(self, prepared): return self.s
    def explain(self, prepared, k=14): return []

_URL = []
def url_model():
    if not _URL:
        _URL.append(load_url_model())
    return _URL[0]

def run(text, score, **kw):
    r = analyse(text, Stub(score), url_model(), **kw)
    return r, to_report(text, r)

@contextlib.contextmanager
def fixture_lists():
    saved = router.load_lists
    router.load_lists = lambda: LinkLists(root=FIXTURES, now=NOW)
    try:
        yield
    finally:
        router.load_lists = saved

KN_SCAM = "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆ ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ. ಈಗಲೇ KYC ನವೀಕರಿಸಿ ಮತ್ತು ಬಹುಮಾನ ಪಡೆಯಿರಿ"
HI_SCAM = "आपका बैंक खाता बंद हो जाएगा। अभी KYC अपडेट करें और इनाम पाएं"
HG_SCAM = "Aapka khata band ho jayega, kripya turant KYC update karein aur inaam paayein"
EN_SCAM = "Your bank account will be blocked. Update KYC now and claim your prize"

DETECT = [
    ("English sentence", "Your account is blocked. Click here to verify now", "en"),
    ("English greeting that contains 'hi'", "hi, how are you? ok see you at the bank", "en"),
    ("English with one Hindi word", "Please share the prize money, ji", "en"),
    ("Hindi", "आपका खाता बंद हो जाएगा, कृपया अपडेट करें", "hi"),
    ("Hindi with English brand and KYC", "आपका SBI खाता बंद हो जाएगा, कृपया KYC अपडेट करें", "hi"),
    ("Hindi with digits and danda", "आपका OTP 123456 है। किसी को न बताएं।", "hi"),
    ("Kannada", "ನಿಮ್ಮ ಖಾತೆ ಬಂದ್ ಆಗುತ್ತದೆ, ದಯವಿಟ್ಟು ನವೀಕರಿಸಿ", "kn"),
    ("Kannada with English brand", "ನಿಮ್ಮ SBI ಖಾತೆ ಬಂದ್ ಆಗುತ್ತದೆ, KYC ನವೀಕರಿಸಿ", "kn"),
    ("Hinglish (Latin Hindi)", "Aapka account band ho jayega, kripya turant KYC update karein", "hinglish"),
    ("Hinglish short", "Aapka khata band hai", "hinglish"),
    ("Hinglish with a link", "Aapka khata band hai, abhi update karein https://sbi-kyc.example.top/x", "hinglish"),
    ("mixed Hindi + Kannada, Kannada larger", "आपका ನಿಮ್ಮ ಖಾತೆ ಬಂದ್ ಆಗುತ್ತದೆ ನವೀಕರಿಸಿ", "kn"),
    ("mixed English + a little Hindi (under the share)", "Dear customer your SBI account KYC is pending, please update today to avoid closure of the account खाता", "en"),
    ("emoji only", "😀😀🎉", "unknown"),
    ("numbers only", "12345 6789 0", "unknown"),
    ("link only", "https://example.com/a?b=1", "unknown"),
    ("mask tokens only", "<URL> <PHONE> <UPI_ID>", "unknown"),
    ("another script (Tamil)", "உங்கள் கணக்கு மூடப்படும்", "unknown"),
    ("empty", "", "unknown"),
    ("spaces and punctuation", "  ...  !! ", "unknown"),
]

def z1():
    bad = [f"{name}: {detect_lang(t)!r}, wanted {want!r}" for name, t, want in DETECT if detect_lang(t) != want]
    if detect_lang(None) != "unknown":
        bad.append("None did not give 'unknown'")
    return bad

def z2():
    bad = []
    if set(LANG_CAP_LINE) != {"en", "hi", "kn"} or set(LANG_CAP_NEEDS_REVIEW) != {"en", "hi", "kn"}:
        return ["keys must be en, hi, kn"]
    if "less tested" not in LANG_CAP_LINE["en"] or "warning" not in LANG_CAP_LINE["en"] or "verdict" not in LANG_CAP_LINE["en"]:
        bad.append(f"English line: {LANG_CAP_LINE['en']!r}")
    if detect_lang(LANG_CAP_LINE["hi"]) != "hi" or detect_lang(LANG_CAP_LINE["kn"]) != "kn":
        bad.append("the Hindi / Kannada lines are not written in their scripts")
    if LANG_CAP_NEEDS_REVIEW != {"en": False, "hi": True, "kn": True}:
        bad.append(f"needs-review flags: {LANG_CAP_NEEDS_REVIEW}")
    if len(LANG_CAP_LINE["en"]) > 120:
        bad.append("the English line is longer than an Evidence title may be")
    return bad

def z3():
    bad = []
    for name, text, lang in (("kn", KN_SCAM, "kn"), ("hi", HI_SCAM, "hi"), ("hinglish", HG_SCAM, "hinglish")):
        r, rep = run(text, 0.99)
        if r["lang"] != lang or rep.meta.lang != lang:
            bad.append(f"{name}: lang {r['lang']} / {rep.meta.lang}")
        if rep.level != Level.SUSPICIOUS or not r["lang_cap"]:
            bad.append(f"{name}: level {rep.level.value}, lang_cap {r['lang_cap']} (wanted Suspicious, capped)")
        if not rep.reasons or rep.reasons[-1] != LANG_CAP_LINE["en"] or len(rep.reasons) > 3:
            bad.append(f"{name}: reasons {rep.reasons}")
        ids = [e.id for e in rep.evidence]
        if "lang.cap" not in ids or "model.text" not in ids:
            bad.append(f"{name}: evidence ids {ids}")
        if rep.risk_score is None or not 30 <= rep.risk_score <= 69:
            bad.append(f"{name}: risk score {rep.risk_score}")
        if rep.advice != to_report(text, analyse(text, Stub(0.2), url_model())).advice:
            bad.append(f"{name}: the advice is not the Suspicious advice")
        r0, rep0 = run(text, 0.99, lang_cap=False)
        if rep0.level != Level.LIKELY_SCAM or "lang.cap" in [e.id for e in rep0.evidence]:
            bad.append(f"{name}: lang_cap=False gave {rep0.level.value}")
        r1, rep1 = run(text, 0.2)
        if rep1.level != Level.SUSPICIOUS or r1["lang_cap"] or LANG_CAP_LINE["en"] in rep1.reasons:
            bad.append(f"{name}: a Suspicious text score changed: {rep1.level.value}, reasons {rep1.reasons}")
    r, rep = run(EN_SCAM, 0.99)
    if rep.level != Level.LIKELY_SCAM or r["lang_cap"] or rep.meta.lang != "en":
        bad.append(f"English: level {rep.level.value}, capped {r['lang_cap']}, lang {rep.meta.lang}")
    return bad

def z4():
    bad = []
    with fixture_lists():
        text = KN_SCAM + " http://zqxj-listed-phish.top/login"
        r, rep = run(text, 0.99)
        if rep.level != Level.LIKELY_SCAM or r["lang_cap"]:
            bad.append(f"kn + OpenPhish link (fixture): level {rep.level.value}, capped {r['lang_cap']}")
        r, rep = run(text, 0.2)
        if rep.level != Level.LIKELY_SCAM or r["lang_cap"]:
            bad.append(f"kn + OpenPhish link, text Suspicious: level {rep.level.value}")
    otp = "Aapka khata band ho jayega, turant apna OTP share karein"
    r, rep = run(otp, 0.0)
    if not r["cred_request"] or rep.level != Level.SUSPICIOUS or not r["escalated"] or r["lang"] != "hinglish":
        bad.append(f"Hinglish OTP request, text score 0: level {rep.level.value}, cred {r['cred_request']}, lang {r['lang']}")
    r, rep = run(otp, 0.99)
    if rep.level != Level.SUSPICIOUS or not r["lang_cap"]:
        bad.append(f"Hinglish OTP request, text Likely: level {rep.level.value}, capped {r['lang_cap']}")
    return bad

def z5():
    bad = []
    def res(level, text_level, url_level, lang, invest=()):
        return {"level": level, "text_level": text_level, "url_level": url_level, "lang": lang, "invest_rules": [{"floor": f} for f in invest]}
    cases = [("text alone, kn", res(2, 2, None, "kn"), True), ("text alone, links all 0", res(2, 2, 0, "hi"), True), ("hook invest rule (floor 1) only", res(2, 2, None, "hinglish", (1,)), True),
             ("English", res(2, 2, None, "en"), False), ("unknown", res(2, 2, None, "unknown"), False),
             ("a link rated Suspicious beside a Likely text", res(2, 2, 1, "kn"), False), ("a link rated Likely scam", res(2, 2, 2, "kn"), False),
             ("text Suspicious + link Suspicious fused to Likely", res(2, 1, 1, "kn"), False), ("a money-floor investment rule", res(2, 2, None, "hi", (2,)), False),
             ("level already Suspicious", res(1, 2, None, "kn"), False), ("no text score (a bare link)", res(2, None, 2, "kn"), False)]
    for name, r, want in cases:
        apply_language_cap(r)
        got = bool(r.get("lang_cap"))
        if got != want or (want and r["level"] != 1) or (not want and r["level"] != {"level already Suspicious": 1}.get(name, 2)):
            bad.append(f"{name}: capped {got} (wanted {want}), level {r['level']}")
    return bad

def z6():
    bad = []
    for text in (KN_SCAM, EN_SCAM, "😀", "12345", "https://example.com/x"):
        rep = to_report(text, analyse(text, Stub(0.5), url_model()))
        if rep.meta.lang not in ("en", "hi", "kn", "hinglish", "unknown"):
            bad.append(f"{text[:20]!r}: meta.lang {rep.meta.lang!r}")
        Report.model_validate(rep.model_dump(mode="json"))
    return bad

_HEAD = []
def head():
    if not _HEAD:
        _HEAD.append(load_text_model())
    return _HEAD[0]

def z7():
    bad, rows = [], [(f"{kind}:{i}", t) for kind, i, t in tc.inputs()] + [(f"demo:{d['id']}", d["text"]) for d in load_demo()]
    changed = []
    for label, t in rows:
        a = analyse(t, head(), url_model(), lang_cap=False)["level"]
        b = analyse(t, head(), url_model(), lang_cap=True)
        if a != b["level"]:
            changed.append(label)
            if (a, b["level"]) != (2, 1) or b["lang"] not in ("hi", "kn", "hinglish"):
                bad.append(f"{label}: level {a} -> {b['level']} in {b['lang']}")
    if any(c.startswith("demo:") for c in changed):
        bad.append(f"demo messages changed: {[c for c in changed if c.startswith('demo:')]}")
    z7.changed = changed
    return bad

CHECKS = [("Z1", f"detect_lang on {len(DETECT)} cases (en, hi, kn, Hinglish, mixed, emoji-only, numbers-only, link-only, other script, empty)", z1),
          ("Z2", "the cap line: EN wording, HI / KN in their scripts, hi / kn needs-review", z2),
          ("Z3", "kn / hi / Hinglish text-Likely -> Suspicious + reason line; English, lang_cap=False and a Suspicious score unchanged", z3),
          ("Z4", "not capped: a listed link stays Likely scam; an OTP request still forces Suspicious", z4),
          ("Z5", "apply_language_cap on hand-built results (11 cases)", z5),
          ("Z6", "meta.lang is set and valid on every Report", z6),
          ("Z7", "contract inputs + demo set, active head: only Likely -> Suspicious in hi / kn / Hinglish; demo unchanged", z7)]

def results():
    return [(cid, what, fn()) for cid, what, fn in CHECKS]

def test_lang():
    bad = [f"{cid}: {b}" for cid, _, bs in results() for b in bs]
    assert not bad, "\n".join(bad)

if __name__ == "__main__":
    res = results()
    for cid, what, bad in res:
        print(f"{'FAIL' if bad else 'PASS'} {cid} {what}")
        for b in bad[:10]:
            print("    " + b.encode("ascii", "backslashreplace").decode()[:300])
    print(f"\nZ7 changed: {getattr(z7, 'changed', None)}")
    print(f"{sum(not b for _, _, b in res)}/{len(res)} passed")
    sys.exit(1 if any(b for _, _, b in res) else 0)
