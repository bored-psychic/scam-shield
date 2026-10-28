import hashlib, json, os, re, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_masks.py")))   # exec()-ed from the project root there is no __file__
ROOT = os.path.join(HERE, "..")
sys.path[:0] = [os.path.join(ROOT, "src"), HERE]
import pii

# python tests/test_masks.py   (from the project root). splits-v3 B0a (docs/plans/splits_v3.md D-v3.5): versioned PII masks. Nothing here writes under data/.
#   M1  MASKS_V2 is today's pii.py, frozen: pattern digest, 140 golden strings (made with the pre-B0a code), mask_text() default, MASKS is MASKS_V2.patterns, mask_version strings
#   M2  MASKS_V2 on every row of data/final/messages.csv gives byte-identical text to the pre-B0a pii.py (one digest over md5 of each output; texts are not printed).
#       Valid while messages.csv is the splits-v2 file (49,931 rows, split_map SHA-256 8263df1c...); after the splits-v3 rebuild this check says so and skips
#   M3  MASKS_INTAKE_V1 is intake_real's masking, frozen: the same 140 strings with and without name_rx, intake_real.mask is the pinned function, the
#       intake patterns and word lists have the frozen digest
#   M4  MASKS_V3 cases: greeting names, ALL-CAPS payers on SMS-type channels only, glued account numbers, OTP / card / tails; and what must NOT be masked
#       (brands, months, places that are also words, "MS Office", "hi how are you", job-post headings, ordinary numbers)
#   M5  MASKS_V3 properties on the golden strings: idempotent (v3(v3(x)) == v3(x), also on intake-masked text); hides at least what v2 hid; changes intake-masked text only by a name or OTP rule
#   M6  the app follows the bundle: model_text and router.analyse use the head's mask_version (missing = v2), an unknown one is refused, the shipped heads declare v2
#   M7  build_text.py takes --mask-version (v2 / v3 only) and --out-dir; a bad version stops before anything is built or written
#   M8  eval_real.py (and the router under it) applies the bundle's mask set on top of the intake-masked real-message text: a v3 head sees the English OTP the intake left, a v2 head does not

V2_PATTERN_DIGEST = "04da81e6fb42b362e1ef30db57cc10891fc003b942154b98944d71c7d29b73c7"
INTAKE_DIGEST = "be3a9ca0e6428695774932628d04b245e18fc39f461c459dd5a7aa546857dd52"
MESSAGES_V2_ROWS, SPLIT_MAP_V2_SHA = 49931, "8263df1c304de7154290f57f648387ddc396cab303630753aa40200619bd4e6c"
MESSAGES_V2_OUTPUT_DIGEST = "f8c5e89e70941509e048319a3533e04cca940391882e717bdeb22f36f53dac47"   # sha256 over md5(pre-B0a mask_text(text)) of all rows, in file order

GOLDEN = json.load(open(os.path.join(HERE, "fixtures", "mask_golden.json"), encoding="utf-8"))   # made with the pre-B0a pii.py / intake_real.py
sha = lambda *parts: hashlib.sha256(json.dumps(parts, sort_keys=True, default=list).encode()).hexdigest()

def m1():
    bad = []
    if sha(pii.MASKS_V2.patterns) != V2_PATTERN_DIGEST:
        bad.append("the v2 pattern list changed: a mask set is frozen once a model is trained on it; add a new version instead")
    bad += [f"v2 differs on golden string {i}" for i, (a, b) in enumerate(GOLDEN["pii_v2"]) if pii.MASKS_V2(a) != b or pii.mask_text(a) != b or pii.mask_text(a, version="v2") != b]
    if pii.MASKS is not pii.MASKS_V2.patterns:
        bad.append("pii.MASKS must stay the v2 pattern list")
    if (pii.MASKS_V2.mask_version, pii.MASKS_INTAKE_V1.mask_version, pii.MASKS_V3.mask_version) != ("v2", "intake-v1", "v3"):
        bad.append("mask_version strings")
    if pii.MASK_VERSIONS != ("v2", "v3"):
        bad.append(f"MASK_VERSIONS {pii.MASK_VERSIONS}: intake-v1 is the intake's own, not a bundle's")
    return bad

def m2():
    import pandas as pd
    path = os.path.join(ROOT, "data", "final", "messages.csv")
    smap = os.path.join(ROOT, "data", "final", "split_map.csv")
    if not (os.path.exists(path) and os.path.exists(smap)):
        m2.note = "skipped: data/final/messages.csv not on this machine"
        return []
    if hashlib.sha256(open(smap, "rb").read()).hexdigest() != SPLIT_MAP_V2_SHA:
        m2.note = "skipped: split_map.csv is no longer splits-v2 (messages.csv was rebuilt); the v2 byte-identity was checked before the rebuild"
        return []
    d = pd.read_csv(path, usecols=["text"], keep_default_na=False)
    h = hashlib.sha256()
    for t in d["text"]:
        h.update(hashlib.md5(pii.MASKS_V2(t).encode()).digest())
    m2.note = f"{len(d)} rows"
    bad = []
    if len(d) != MESSAGES_V2_ROWS:
        bad.append(f"{len(d)} rows, expected {MESSAGES_V2_ROWS}")
    if h.hexdigest() != MESSAGES_V2_OUTPUT_DIGEST:
        bad.append("MASKS_V2 output on messages.csv differs from the pre-B0a pii.py")
    return bad

def m3():
    import intake_real
    bad = []
    nrx = re.compile(GOLDEN["names_rx"], re.I)
    bad += [f"intake-v1 differs on golden string {i}" for i, (a, b) in enumerate(GOLDEN["intake_v1"]) if pii.MASKS_INTAKE_V1(a) != b or intake_real.mask(a) != b]
    bad += [f"intake-v1 with names differs on golden string {i}" for i, (a, b) in enumerate(GOLDEN["intake_v1_names"]) if pii.MASKS_INTAKE_V1(a, name_rx=nrx) != b or intake_real.mask(a, nrx) != b]
    rx = (pii.URL_RX, pii.CARD_RX, pii.OTP_RX, pii.OTP_BEFORE_RX, pii.LONG_RX, pii.URL_PHONE_RX, pii.URL_MOBILE_RX, pii.ACCT_TAIL_RX, pii.XX_TAIL_RX, pii.GREETING_NAME_RX, pii.CAPS_NAME_RX)
    if sha([pii.ADDRESS_MASKS, pii.NUMBER_MASKS], [r.pattern for r in rx], sorted(pii.COMMON), sorted(pii.NOT_NAMES), sorted(pii.ACRONYMS)) != INTAKE_DIGEST:
        bad.append("the intake's patterns or name word lists changed: intake_real is pinned to MASKS_INTAKE_V1 (its group keys are built on the masked text)")
    for name in ("URL_RX", "CARD_RX", "OTP_RX", "OTP_BEFORE_RX", "LONG_RX", "URL_PHONE_RX", "URL_MOBILE_RX", "ACCT_TAIL_RX", "XX_TAIL_RX", "GREETING_NAME_RX", "CAPS_NAME_RX", "NOT_NAMES", "COMMON"):
        if getattr(intake_real, name) is not getattr(pii, name):
            bad.append(f"intake_real.{name} is not pii.{name}")
    return bad

V3 = pii.MASKS_V3
# (text, channel, expected)
V3_CASES = [
    # greeting names: any source, any channel
    ("Hey Rahul, your order is out", "sms", "Hey <NAME>, your order is out"),
    ("Dear Priya Sharma, your account", "email", "Dear <NAME> Sharma, your account"),
    ("hello PRAJVAL kindly pay", "job_post", "hello <NAME> kindly pay"),
    ("Namaste Suresh ji", "chat", "Namaste <NAME> ji"),
    ("Mr Sharma has called", "call", "Mr <NAME> has called"),
    ("Ms Priya will call", "sms", "Ms <NAME> will call"),
    # ALL-CAPS payers: SMS-type channels, and the app (no channel); not mail, calls, job posts
    ("Received Rs 500 from SURESH on 12 Jan", "sms", "Received Rs 500 from <NAME> on 12 Jan"),
    ("paid to RENU KUMAR today.", "whatsapp", "paid to <NAME> today."),
    ("Credited by RENU R KUMAR on 12 Mar", "sms", "Credited by <NAME> on 12 Mar"),   # one run, initials included
    ("Paid to K SURESH KUMAR via UPI", "sms", "Paid to <NAME> via UPI"),
    ("Rs 10 from A. B. RAO SHETTY today", "sms", "Rs 10 from <NAME> today"),
    ("received from AMIT I will pay", "sms", "received from <NAME> I will pay"),   # an initial without a dot may not end the run; "I" / "A" are words
    ("from A TO Z", "sms", "from A TO Z"),
    ("sent to AMIT TO PAY", "sms", "sent to <NAME> TO PAY"),   # a 2-letter token ends the run
    ("from RENU R KUMAR PAYTM", "sms", "from RENU R KUMAR PAYTM"),   # a stoplisted word in the run leaves the run alone
    ("credited by RAMESH.", None, "credited by <NAME>."),
    ("Received Rs 500 from SURESH on 12 Jan", "email", "Received Rs 500 from SURESH on 12 Jan"),
    ("Received Rs 500 from SURESH on 12 Jan", "email_or_sms", "Received Rs 500 from SURESH on 12 Jan"),   # copies of mail rows must mask like the mail rows (dedupe)
    ("Received Rs 500 from SURESH on 12 Jan", "job_post", "Received Rs 500 from SURESH on 12 Jan"),
    ("Received Rs 500 from SURESH on 12 Jan", "call", "Received Rs 500 from SURESH on 12 Jan"),
    # numbers: the intake's, glued ones included
    ("Your OTP is 482913. 123456 is your verification code", "sms", "Your OTP is <OTP>. <OTP> is your verification code"),
    ("Your OTP for Grapevine is 919157", "sms", "Your OTP for Grapevine is <OTP>"),   # the keyword with the number further on (v3 only)
    ("Your OTP for txn of Rs.500.00 at AMAZON PAY INDIA is 123456. Do not share", "sms", "Your OTP for txn of Rs.500.00 at AMAZON PAY INDIA is <OTP>. Do not share"),
    ("One time password for login is 887766", "sms", "One time password for login is <OTP>"),
    ("verification code : 998877 expires soon", "sms", "verification code : <OTP> expires soon"),
    ("OTP: 4521 valid. Ref is 123456", "sms", "OTP: <OTP> valid. Ref is 123456"),   # the gap stops at a sentence end
    ("OTP will expire in 10 min. Balance is 123456", "sms", "OTP will expire in 10 min. Balance is 123456"),
    ("Your OTP is shared by nobody, total is 1500.50", "sms", "Your OTP is shared by nobody, total is 1500.50"),   # not a 4-8 digit run on its own (decimal)
    ("A/c XX1234 debited. Card ending 4455. a/c no. 12345", "sms", "A/c XX<ACCOUNT> debited. Card ending <ACCOUNT>. a/c no. <ACCOUNT>"),
    ("card 1234 5678 9012 3456 used", "sms", "card <ACCOUNT> used"),
    ("txn FMPIB1234567890 done", "sms", "txn FMPIB<ACCOUNT> done"),
    ("ref 12345678901234567890", "job_post", "ref <ACCOUNT>"),
    ("call 9876543210 or mail a@b.com or pay xy@ybl", "sms", "call <PHONE> or mail <EMAIL> or pay <UPI_ID>"),
    ("open https://x.example.com/pay?phone=919876543210&id=1", "sms", "open https://x.example.com/pay?phone=<PHONE>&id=1"),
    ("UPI id <UPI> kept as <UPI_ID>", "sms", "UPI id <UPI_ID> kept as <UPI_ID>"),
    # must NOT be masked
    ("Hi how are you doing", "chat", "Hi how are you doing"),
    ("hello there, hi all, Dear Customer, Dear Sir", "sms", "hello there, hi all, Dear Customer, Dear Sir"),
    ("Dear taxpayer, file now. Hello everyone", "email", "Dear taxpayer, file now. Hello everyone"),
    ("Experience with MS Office and MS SQL required", "job_post", "Experience with MS Office and MS SQL required"),
    ("Pay via HDFC Bank on 12 March in Mumbai from SBI", "sms", "Pay via HDFC Bank on 12 March in Mumbai from SBI"),
    ("Order from AMAZON PAY delivered to MUMBAI HOME", "sms", "Order from AMAZON PAY delivered to MUMBAI HOME"),
    ("Hi Jan, Hi March, Hi Airtel", "sms", "Hi Jan, Hi March, Hi Airtel"),
    ("CLICK HERE to VERIFY YOUR ACCOUNT now", "sms", "CLICK HERE to VERIFY YOUR ACCOUNT now"),
    ("Rs 1500 due on 15/03/2026, amount 100000, 2 items, ph 1800 123 4567", "sms", "Rs 1500 due on 15/03/2026, amount 100000, 2 items, ph 1800 123 4567"),
    ("", "sms", ""), ("   ", None, "   "), ("नमस्ते ಕನ್ನಡ no digits", "sms", "नमस्ते ಕನ್ನಡ no digits"),
]

def m4():
    bad = []
    for text, ch, want in V3_CASES:
        got = V3(text, channel=ch)
        if got != want:
            bad.append(f"{ch}: {text!r} -> {got!r}, expected {want!r}")
    if pii.mask_text("Hey Rahul", version="v3") != "Hey <NAME>" or pii.mask_text("Hey Rahul") != "Hey Rahul":
        bad.append("mask_text(version=...) does not pick the set; the default must stay v2")
    return bad

def m5():
    bad = []
    for key in ("pii_v2", "intake_v1"):
        for i, (a, b) in enumerate(GOLDEN[key]):
            for ch in ("sms", "email", None):
                once = V3(a, channel=ch)
                if V3(once, channel=ch) != once:
                    bad.append(f"v3 is not idempotent on {key}[{i}] ({ch})")
                if pii.MASKS_V2(once) != once:
                    bad.append(f"v3 hides less than v2 on {key}[{i}] ({ch}): the v2 masks still change its output")
    for i, (a, b) in enumerate(GOLDEN["intake_v1"]):   # b = intake_real.mask(a), i.e. POOL text: v3 is idempotent on it, and changes it only by a name rule or the widened OTP rule
        k = set()
        out = V3(b, channel="sms", kinds=k)
        if V3(out, channel="sms") != out:
            bad.append(f"v3 is not idempotent on intake-masked golden string {i}")
        if out != b.replace("<UPI>", "<UPI_ID>") and not k & {"greeting_name", "caps_name", "otp"}:   # (v2 and v3 unify web_scams' <UPI> tag; the intake does not)
            bad.append(f"v3 changes intake-masked golden string {i} without a name or OTP rule")
    return bad

class Head:
    """A text head that records what the router hands it."""
    name, thresholds = "stub", (0.1, 0.4)
    def __init__(self, mask_version=None):
        if mask_version is not None:
            self.mask_version = mask_version
        self.seen = []
    def score(self, prepared):
        self.seen.append(prepared)
        return 0.2
    def explain(self, prepared, k=14): return []

def m6():
    from textprep import model_text
    from shield.core.router import analyse
    from shield.links.lexical import load_url_model
    from shield.messages import text_head
    bad = []
    text = "Hey Rahul, your OTP is 482913 for the transfer of Rs 500 to account 123456789012345 now, please check it."
    v2, v3 = model_text(text, mask_pii=True), model_text(text, mask_pii=True, mask_version="v3")
    if v2 != model_text(text, mask_pii=True, mask_version="v2") or "<NAME>" in v2 or "<OTP>" in v2:
        bad.append(f"model_text default must be v2: {v2!r}")
    if "<NAME>" not in v3 or "<OTP>" not in v3:
        bad.append(f"model_text(mask_version='v3') did not apply the v3 masks: {v3!r}")
    um = load_url_model()
    heads = {"declares v3": Head("v3"), "declares v2": Head("v2"), "declares nothing": Head()}
    for h in heads.values():
        analyse(text, h, um)
    want = {"declares v3": v3, "declares v2": v2, "declares nothing": v2}
    for k, h in heads.items():
        if h.seen != [want[k]]:
            bad.append(f"router fed a head that {k}: {h.seen!r}")
    if text_head.bundle_mask_version({}, "x") != "v2":
        bad.append("a bundle without mask_version must read as v2")
    if text_head.bundle_mask_version({"mask_version": "v3"}, "x") != "v3":
        bad.append("a v3 bundle must read as v3")
    for junk in ("v9", "intake-v1", "", None, 3):
        try:
            text_head.bundle_mask_version({"mask_version": junk}, "x")
            bad.append(f"mask_version {junk!r} was accepted")
        except SystemExit:
            pass
    try:
        pii.mask_text("x", version="v9")
        bad.append("mask_text accepted an unknown version")
    except ValueError:
        pass
    head = text_head.load_text_model()
    if head.mask_version != "v2":
        bad.append(f"the shipped head ({head.name}) must declare v2, it says {head.mask_version!r}")
    return bad

def m7():
    bad = []
    run = lambda *a: subprocess.run([sys.executable, os.path.join(ROOT, "src", "build_text.py"), *a], cwd=ROOT, capture_output=True, text=True, timeout=120)
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "o")
        r = run("--mask-version", "v9", "--out-dir", out)
        if r.returncode != 2 or "invalid choice" not in r.stderr or os.path.exists(out):
            bad.append(f"--mask-version v9: exit {r.returncode}, out dir created {os.path.exists(out)}")
        r = run("--mask-version", "intake-v1", "--out-dir", out)
        if r.returncode != 2 or os.path.exists(out):
            bad.append(f"--mask-version intake-v1 must be refused (it is not a bundle's set): exit {r.returncode}")
        r = run("--help")
        if r.returncode != 0 or "--mask-version" not in r.stdout or "--out-dir" not in r.stdout:
            bad.append("--help does not list the flags")
    return bad

def m8():
    """splits-v3 D-v3.5: real_test_v1 / POOL text is intake-masked; a v3 bundle must see it with the v3 masks on top (a v2 bundle exactly as it is)."""
    import eval_real
    from intake_real import mask as intake_mask
    bad = []
    raw = "Hey Rahul, your OTP for Grapevine is 919157. Received Rs 500 from RENU R KUMAR, a/c no. 123456789012."
    pool = intake_mask(raw)   # what a POOL / TEST row holds
    if "<OTP>" in pool or "919157" not in pool:
        bad.append(f"fixture is wrong: the intake now masks the English OTP form: {pool!r}")
    rows = [{"text": pool}]
    heads = {"v3": Head("v3"), "v2": Head("v2"), "none": Head()}
    eval_real.score_rows(rows, False, heads=heads)
    from textprep import model_text
    for k, h in heads.items():
        want = model_text(pool, mask_pii=True, mask_version="v3" if k == "v3" else "v2")
        if len(h.seen) != 1 or h.seen[0] != want:
            bad.append(f"eval_real fed the {k} head {h.seen!r}, expected the {k} masks on top of the intake text")
        if k == "v3" and h.seen and ("919157" in h.seen[0] or "<OTP>" not in h.seen[0]):
            bad.append(f"the v3 head still sees the OTP: {h.seen[0]!r}")
        if k != "v3" and h.seen and "919157" not in h.seen[0]:
            bad.append(f"the {k} head must see the text as the v2 masks leave it: {h.seen[0]!r}")
    return bad

CHECKS = [("M1", "MASKS_V2 frozen: pattern digest, 140 golden strings, defaults, mask_version strings", m1),
          ("M2", "MASKS_V2 byte-identical to the pre-B0a pii.py on every row of messages.csv (digest only)", m2),
          ("M3", "MASKS_INTAKE_V1 frozen and pinned: golden strings with / without names, digest, intake_real aliases", m3),
          ("M4", f"MASKS_V3 cases ({len(V3_CASES)}): names, ALL-CAPS payers by channel, glued numbers; brands, months, MS Office, hi how are you not masked", m4),
          ("M5", "MASKS_V3 properties: idempotent (also on intake text), hides at least what v2 hid, changes intake text only by a name or OTP rule", m5),
          ("M6", "the app masks input by the head's mask_version (missing = v2); unknown refused; shipped head is v2", m6),
          ("M7", "build_text.py --mask-version / --out-dir: v2 / v3 only, a bad version stops first", m7),
          ("M8", "eval_real applies the head's mask set on top of intake-masked text (v3 head sees the English OTP masked, v2 head does not)", m8)]

def results():
    return [(cid, what, fn()) for cid, what, fn in CHECKS]

def test_masks():
    bad = [f"{cid}: {b}" for cid, _, bs in results() for b in bs]
    assert not bad, "\n".join(bad)

if __name__ == "__main__":
    res = results()
    for cid, what, bad in res:
        print(f"{'FAIL' if bad else 'PASS'} {cid} {what}" + (f"  [{m2.note}]" if cid == "M2" and hasattr(m2, "note") else ""))
        for b in bad[:10]:
            print("    " + b.encode("ascii", "backslashreplace").decode()[:300])
    print(f"\n{sum(not b for _, _, b in res)}/{len(res)} passed")
    sys.exit(1 if any(b for _, _, b in res) else 0)
