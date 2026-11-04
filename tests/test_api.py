import contextlib, io, logging, os, socket, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from fastapi.testclient import TestClient
from shield.api.main import app
from shield.contracts import Level, Report, SCHEMA_VERSION
from shield.core.advice import ADVICE, EMAIL_ADVICE, GAMBLING_ADVICE
from shield.core.intake import classify
from shield.core.report import to_report
from shield.core.router import analyse
from shield.links.lexical import load_url_model
from shield.messages.text_head import load_text_model
from textprep import extract_urls
from tricky_inputs import INPUTS

# python tests/test_api.py   (from the project root; needs both models; no pytest required, but pytest collects test_api() too)
# Runs the app in-process (TestClient inside `with`, so the lifespan loads the models once) and checks, each printed PASS / FAIL:
#   T1 GET /api/health   T2 every tricky input over HTTP == to_report(analyse(...), input=...) except meta.ms   T3 response validates as a Report (schema "6", ms rounded)
#   T4 empty / whitespace-only text -> 422   T5 over 20,000 characters -> 422 (20,000 is still fine)   T6 wrong method -> 405
#   T7 no network: sockets patched to record + refuse every connection / lookup, link-bearing inputs still answer 200 with 0 attempts
#   T8 unknown body field -> 422
#   T9 an SBI / OTP-request message: the response advice == ADVICE[level] (gambling line first iff category == "gambling"), the same rule as A13 in test_contracts.py
#   T10 the sender field (D22) absent, null, "" and "   ": the same response (except meta.ms), "sender": null, for every tricky input
#   T11 the Jio promo with "JM-JIOCPN-P" -> promotional, sender block {dlt, P, JIOCPN}; with a mobile number -> kind "mobile" only, the digits nowhere in the
#       response; a non-string sender -> 422
#   T12 nothing the user typed reaches a log: every logging record (root, uvicorn, fastapi, at DEBUG) and everything written to stdout / stderr while
#       requests with a marked text and sender are answered (including a failing analysis) is captured, and neither marker appears in it
# W1 (2026-11-04, schema "6", /api/check; docs/plans/multi_input.md 7.5 ST rows that apply):
#   T13 /api/check status table: auto / message / link / email answer 200 with the right Report.input; upi_id, payment_request, qr, payment_proof, app, apk -> 501 with
#       the fixed message; an unknown kind or a missing kind -> 422
#   T14 extra="forbid": an unknown field on /api/check (and a non-string subject / body) -> 422
#   T15 /api/check auto and message give the /api/analyse response (except meta.ms) for every tricky input; link with a single link equals /api/analyse; email gives
#       router.analyse(subject + "\n\n" + body) with input "email", details null, children / reasons as the engine's
#   T16 /api/check error cases: link with prose, an empty text, an over-long text, an incomplete or over-long email -> 422 with a fixed message that carries nothing
#       the user sent; expand needs live
#   T17 zero network: T7's gate on /api/check for message, link and email (offline path), 0 attempts
#   T18 nothing the user typed (text, subject, body, sender) reaches a log or stdout / stderr on /api/check, including a failing analysis and a 501
#   T19 /api/analyse labels a bare link input "link", any other text (and a UPI ID, which has no engine yet) "message"; a Report has details null for message / link / email
EMPTY = {"detail": "Paste a message to check."}
TOO_LONG = {"detail": "Message is too long (max 20,000 characters)."}
SBI_OTP = "Dear customer, share your OTP now to avoid account block: http://sbi-kyc-verify.xyz/login"
LINK_IDS = ["shortener-keywords", "free-hosting-brand", "userinfo-trick"]   # one link of each kind: shortener, free hosting, URL model
JIO = "Dear User,\nYou've earned Lifetime Free\nKiwi UPI Credit Card (CC:\nJIOKIWI) on JioRecharge.\nClaim now:\nhttps://t.jio/JIOCPN/x48NuN\nT&C*\nJioCoupons"


def post(c, text, **extra):
    return c.post("/api/analyse", json={"text": text, **extra})

def without_ms(d):
    d = dict(d, meta=dict(d["meta"]))
    d["meta"].pop("ms")
    return d

def input_of(text):
    """What /api/analyse puts into Report.input: a bare link is a link, everything else a message (there is no payments engine yet)."""
    return "link" if classify(text) == "link" else "message"

def t1(c, ref):
    r = c.get("/api/health")
    return [] if (r.status_code, r.json()) == (200, {"status": "ok", "schema_version": "6"}) and SCHEMA_VERSION == "6" else [f"{r.status_code} {r.text}"]

def t2(c, ref):
    tm, um = ref
    bad = []
    for x in INPUTS:
        r = post(c, x["text"])
        want = to_report(x["text"], analyse(x["text"], tm, um), input=input_of(x["text"])).model_dump(mode="json")
        if r.status_code != 200:
            bad.append(f"{x['id']}: status {r.status_code}")
        elif without_ms(r.json()) != without_ms(want):
            bad.append(f"{x['id']}: response differs from to_report(analyse(...))")
    return bad

def t3(c, ref):
    bad = []
    for x in INPUTS:
        j = post(c, x["text"]).json()
        rep = Report.model_validate(j)
        ms = j["meta"]["ms"]
        if rep.schema_version != "6" or j["schema_version"] != "6":
            bad.append(f"{x['id']}: schema_version {j['schema_version']}")
        if not isinstance(ms, float) or ms < 0 or round(ms, 1) != ms:
            bad.append(f"{x['id']}: meta.ms {ms!r} is not a non-negative number rounded to 1 decimal")
    return bad

def t4(c, ref):
    return [f"{text!r}: {r.status_code} {r.text}" for text in ("", "   \n\t  ") if (r := post(c, text)).status_code != 422 or r.json() != EMPTY]

def t5(c, ref):
    bad = [f"20001 chars: {r.status_code} {r.text}" for r in [post(c, "a" * 20001)] if r.status_code != 422 or r.json() != TOO_LONG]
    bad += [f"20000 chars: {r.status_code}" for r in [post(c, "a" * 20000)] if r.status_code != 200]
    return bad

def t6(c, ref):
    return [f"{m} {p}: {r.status_code}" for m, p in (("GET", "/api/analyse"), ("POST", "/api/health")) if (r := c.request(m, p)).status_code != 405]

@contextlib.contextmanager
def network_gate():
    """Sockets patched to record and refuse every connection and lookup. Yields the list of attempts; the gate itself is probed first (a connect must raise and
    is then not counted), so an empty list at the end means the code under test never reached for the network."""
    attempts, names = [], ("connect", "connect_ex")
    saved_methods = {n: socket.socket.__dict__.get(n) for n in names}   # None = inherited from the C base class
    saved_funcs = {n: getattr(socket, n) for n in ("create_connection", "getaddrinfo", "gethostbyname")}
    def refuse(name):
        def f(*a, **k):
            attempts.append(name)
            raise OSError(f"T7: outbound network call blocked ({name})")
        return f
    try:
        for n in names:
            setattr(socket.socket, n, refuse(n))
        for n in saved_funcs:
            setattr(socket, n, refuse(n))
        try:
            socket.create_connection(("127.0.0.1", 9))
            raise AssertionError("the guard is not live: create_connection did not raise")
        except OSError:
            pass
        attempts.clear()   # the line above was the probe
        yield attempts
    finally:
        for n, f in saved_methods.items():
            delattr(socket.socket, n) if f is None else setattr(socket.socket, n, f)
        for n, f in saved_funcs.items():
            setattr(socket, n, f)

def t7(c, ref):
    texts = {x["id"]: x["text"] for x in INPUTS}
    assert all(extract_urls(texts[i]) for i in LINK_IDS), "T7 inputs must contain links"
    with network_gate() as attempts:
        bad = []
        for i in LINK_IDS:
            r = post(c, texts[i], sender="JM-JIOCPN-P")   # with a sender too: parsing it is string work only (D22)
            if r.status_code != 200:
                bad.append(f"{i}: status {r.status_code}")
            elif not r.json()["children"]:
                bad.append(f"{i}: no link was analysed")
        if attempts:
            bad.append(f"outbound attempts during analysis: {attempts}")
        return bad

def t8(c, ref):
    r = c.post("/api/analyse", json={"text": "hi", "x": 1})
    return [] if r.status_code == 422 else [f"{r.status_code} {r.text}"]

def t9(c, ref):
    r = post(c, SBI_OTP)
    if r.status_code != 200:
        return [f"status {r.status_code}"]
    j = r.json()
    want = ([GAMBLING_ADVICE] if j["category"] == "gambling" else []) + ADVICE[Level(j["level"])]
    bad = [] if j["advice"] == want else [f"advice {j['advice']}, wanted {want}"]
    if j["level"] not in ("suspicious", "likely_scam") or not j["advice"]:
        bad.append(f"expected a flagged level with advice, got {j['level']} / {j['advice']}")   # the input must keep exercising a warning branch
    bad += [f"a child has advice: {ch['advice']}" for ch in j["children"] if ch["advice"]]
    return bad

def t10(c, ref):
    bad = []
    for x in INPUTS:
        plain = without_ms(post(c, x["text"]).json())
        if plain["sender"] is not None:
            bad.append(f"{x['id']}: sender {plain['sender']} without a sender field")
        for extra in ({"sender": None}, {"sender": ""}, {"sender": "   "}):
            r = post(c, x["text"], **extra)
            if r.status_code != 200 or without_ms(r.json()) != plain:
                bad.append(f"{x['id']}: {extra} gives a different response ({r.status_code})")
    return bad

def t11(c, ref):
    bad = []
    j = post(c, JIO, sender="JM-JIOCPN-P").json()
    if j["level"] != "promotional" or j["sender"] != {"kind": "dlt", "suffix": "P", "header": "JIOCPN", "label": "Registered business · Promotional"}:
        bad.append(f"Jio + JM-JIOCPN-P: level {j['level']}, sender {j['sender']}")
    r = post(c, JIO, sender="+91 98765 43210")
    if r.json()["sender"] != {"kind": "mobile", "suffix": None, "header": None, "label": "Personal mobile number"} or "98765" in r.text or "43210" in r.text:
        bad.append(f"mobile sender: {r.json()['sender']}, digits in the response: {'98765' in r.text or '43210' in r.text}")
    r = post(c, JIO, sender=12345)
    if r.status_code != 422:
        bad.append(f"a non-string sender: {r.status_code}")
    return bad

def t12(c, ref):
    marker_text, marker_sender = "ZQXJ-TEXT-MARKER share your OTP now", "ZQ-XJMKR-P"
    records, buf = [], io.StringIO()
    class Keep(logging.Handler):
        def emit(self, record):
            records.append(self.format(record))
    h = Keep(level=logging.DEBUG)
    loggers = [logging.getLogger(n) for n in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "fastapi", "starlette")]
    saved = [(lg, lg.level) for lg in loggers]
    import shield.api.main as api
    real_analyse = api.analyse
    def boom(text, *a, **k):   # a failing analysis whose exception carries the input, as a pydantic error would
        raise ValueError(f"cannot read {text!r} from {k.get('sender')!r}")
    try:
        for lg in loggers:
            lg.addHandler(h)
            lg.setLevel(logging.DEBUG)
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            codes = [post(c, marker_text, sender=marker_sender).status_code, post(c, marker_text, sender="+91 98765 43210").status_code]
            api.analyse = boom
            codes.append(post(c, marker_text, sender=marker_sender).status_code)
    finally:
        api.analyse = real_analyse
        for lg, lvl in saved:
            lg.removeHandler(h)
            lg.setLevel(lvl)
    seen = "\n".join(records) + buf.getvalue()
    bad = [] if codes == [200, 200, 500] else [f"status codes {codes}, wanted [200, 200, 500]"]
    bad += [f"{name} found in the captured logs / output" for name, m in (("text", "ZQXJ"), ("sender", "XJMKR"), ("mobile", "98765")) if m in seen]
    return bad

# ---------------------------------------------------------------- W1: /api/check (schema "6")
KINDS_501 = ["upi_id", "payment_request", "qr", "payment_proof", "app", "apk"]
NOT_AVAILABLE = {"detail": "This check is not available yet."}
NOT_A_LINK = {"detail": "Paste a single link to check."}
EMAIL_INCOMPLETE = {"detail": "Add the subject and the body of the email to check."}
EMAIL_TOO_LONG = {"detail": "Paste the part with the request and the links (at most 20,000 characters)."}
BARE_LINKS = ["https://sbi-kyc-update.top/login", "see http://bit.ly/3xYz", "www.example.com/a"]
FLAGGED = ("suspicious", "likely_scam")

def check(c, kind, **fields):
    return c.post("/api/check", json={"kind": kind, **fields})

def t13(c, ref):
    bad = []
    for kind, want in (("auto", "message"), ("message", "message")):
        r = check(c, kind, text=SBI_OTP)
        if r.status_code != 200 or r.json()["input"] != want:
            bad.append(f"{kind}: {r.status_code} input {r.json().get('input') if r.status_code == 200 else r.text}")
    r = check(c, "link", text="https://example.com/login")
    if r.status_code != 200 or r.json()["input"] != "link":
        bad.append(f"link: {r.status_code} {r.text[:100]}")
    r = check(c, "email", subject="Account blocked", body=SBI_OTP)
    if r.status_code != 200 or r.json()["input"] != "email":
        bad.append(f"email: {r.status_code} {r.text[:100]}")
    for k in KINDS_501:
        for fields in ({}, {"text": "rajesh@ybl"}):
            r = check(c, k, **fields)
            if (r.status_code, r.json()) != (501, NOT_AVAILABLE):
                bad.append(f"{k} {sorted(fields)}: {r.status_code} {r.text}")
    for body in ({"kind": "bogus", "text": "hi there friend"}, {"text": "hi there friend"}, {}):
        r = c.post("/api/check", json=body)
        if r.status_code != 422:
            bad.append(f"{sorted(body)}: {r.status_code}, wanted 422")
    r = c.request("GET", "/api/check")
    if r.status_code != 405:
        bad.append(f"GET /api/check: {r.status_code}")
    return bad

def t14(c, ref):
    bad = []
    for kind in ("auto", "message", "link", "email", "qr", "app"):
        r = check(c, kind, text="hello there friend", x=1)
        if r.status_code != 422:
            bad.append(f"{kind} + unknown field: {r.status_code}")
    for fields in ({"text": 5}, {"subject": 5}, {"body": ["a"]}, {"sender": 12345}, {"live": "maybe"}, {"expand": "x"}):
        r = check(c, "auto", **fields)
        if r.status_code != 422:
            bad.append(f"{fields}: {r.status_code}")
    return bad

def t15(c, ref):
    bad = []
    for n, x in enumerate(INPUTS):
        want = without_ms(post(c, x["text"]).json())
        for kind in (("auto", "message") if n % 5 == 0 else ("auto",)):
            r = check(c, kind, text=x["text"])
            if r.status_code != 200 or without_ms(r.json()) != want:
                bad.append(f"{x['id']} {kind}: differs from /api/analyse ({r.status_code})")
    for t in BARE_LINKS:
        a, k = post(c, t).json(), check(c, "link", text=t)
        if k.status_code != 200 or without_ms(k.json()) != without_ms(a) or a["input"] != "link":
            bad.append(f"link {t!r}: differs from /api/analyse, or input {a.get('input')!r}")
    tm, um = ref
    for x in INPUTS[:12]:
        subject = "Re: your account"
        r = check(c, "email", subject=subject, body=x["text"])
        text = subject + "\n\n" + x["text"]
        want = to_report(text, analyse(text, tm, um), input="email").model_dump(mode="json")
        j = r.json()
        if r.status_code != 200 or without_ms(j) != without_ms(want):
            bad.append(f"email {x['id']}: differs from router.analyse(subject + body)")
            continue
        if j["details"] is not None or j["input"] != "email" or j["module"] != "messages":
            bad.append(f"email {x['id']}: details {j['details']}, input {j['input']}, module {j['module']}")
        if (EMAIL_ADVICE in j["advice"]) != (j["level"] in FLAGGED) or (j["advice"] and j["level"] in FLAGGED and j["advice"].count(EMAIL_ADVICE) != 1):
            bad.append(f"email {x['id']}: level {j['level']}, email advice present = {EMAIL_ADVICE in j['advice']}")
        if len(j["advice"]) > 5:
            bad.append(f"email {x['id']}: {len(j['advice'])} advice items")
    return bad

def t16(c, ref):
    bad = []
    def want(r, status, detail, what):
        if (r.status_code, r.json()) != (status, detail):
            bad.append(f"{what}: {r.status_code} {r.text[:120]}")
    want(check(c, "link", text="Please click this link to verify your account now"), 422, NOT_A_LINK, "link with prose")
    want(check(c, "link", text="http://a.com http://b.com"), 422, NOT_A_LINK, "two links")
    want(check(c, "link", text="rajesh@ybl"), 422, NOT_A_LINK, "link kind with a UPI ID")
    want(check(c, "link", text=""), 422, EMPTY, "link, empty")
    want(check(c, "link"), 422, EMPTY, "link, no text")
    want(check(c, "auto", text="   \n"), 422, EMPTY, "auto, blank")
    want(check(c, "message", text="a" * 20001), 422, TOO_LONG, "message, 20,001 chars")
    want(check(c, "email", subject="", body="hello"), 422, EMAIL_INCOMPLETE, "email, empty subject")
    want(check(c, "email", subject="hello", body="  "), 422, EMAIL_INCOMPLETE, "email, blank body")
    want(check(c, "email", body="hello there friend"), 422, EMAIL_INCOMPLETE, "email, no subject")
    want(check(c, "email", subject="hello"), 422, EMAIL_INCOMPLETE, "email, no body")
    want(check(c, "email", subject="s", body="a" * 20000), 422, EMAIL_TOO_LONG, "email over the cap")
    if check(c, "email", subject="s", body="a" * 19990).status_code != 200:
        bad.append("an email just under the cap is refused")
    ex = {"detail": "Only a short link from this message can be revealed."}
    want(check(c, "auto", text="see https://bit.ly/3xYz", expand=["https://bit.ly/3xYz"]), 422, ex, "expand without live")
    want(check(c, "email", subject="s", body="see https://bit.ly/3xYz now please", expand=["https://bit.ly/3xYz"]), 422, ex, "email: expand without live")
    return bad

def t17(c, ref):
    cases = [("auto", {"text": SBI_OTP}), ("message", {"text": "Pay at https://sbi-kyc-update.top/login or https://bit.ly/3xYz right now"}),
             ("link", {"text": "https://sbi-kyc-update.top/login"}), ("link", {"text": "https://bit.ly/3xYz"}),
             ("email", {"subject": "KYC", "body": "Your SBI account is blocked. Verify at http://sbi-kyc-verify.xyz/login or https://bit.ly/3xYz"})]
    bad = []
    with network_gate() as attempts:
        for kind, fields in cases:
            r = check(c, kind, **fields)
            if r.status_code != 200:
                bad.append(f"{kind}: status {r.status_code}")
            elif not r.json()["children"]:
                bad.append(f"{kind}: no link was analysed")
        for k in KINDS_501 + ["bogus"]:
            check(c, k, text="https://sbi-kyc-update.top/login")
        if attempts:
            bad.append(f"outbound attempts on /api/check: {attempts}")
    return bad

def t18(c, ref):
    m_text, m_subject, m_body, m_sender = "ZQXJ-TEXT-MARKER", "QWVB-SUBJECT-MARKER", "PLMK-BODY-MARKER", "ZQ-XJMKR-P"
    records, buf = [], io.StringIO()
    class Keep(logging.Handler):
        def emit(self, record):
            records.append(self.format(record))
    h = Keep(level=logging.DEBUG)
    loggers = [logging.getLogger(n) for n in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "fastapi", "starlette")]
    saved = [(lg, lg.level) for lg in loggers]
    import shield.api.main as api
    real_analyse = api.analyse
    def boom(text, *a, **k):
        raise ValueError(f"cannot read {text!r} from {k.get('sender')!r}")
    codes = []
    try:
        for lg in loggers:
            lg.addHandler(h)
            lg.setLevel(logging.DEBUG)
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            codes.append(check(c, "auto", text=m_text + " share your OTP now", sender=m_sender).status_code)
            codes.append(check(c, "link", text=m_text + " this is not a single link at all").status_code)
            codes.append(check(c, "email", subject=m_subject, body=m_body + " share your OTP now", sender=m_sender).status_code)
            codes.append(check(c, "email", subject=m_subject, body="").status_code)
            codes.append(check(c, "qr", text=m_text, sender=m_sender).status_code)
            codes.append(c.post("/api/check", json={"kind": "auto", "text": m_text, "bogus": m_body}).status_code)
            api.analyse = boom
            codes.append(check(c, "auto", text=m_text + " share your OTP now", sender=m_sender).status_code)
            codes.append(check(c, "email", subject=m_subject, body=m_body, sender=m_sender).status_code)
            codes.append(check(c, "link", text="https://zqxj-text-marker.example/x").status_code)
    finally:
        api.analyse = real_analyse
        for lg, lvl in saved:
            lg.removeHandler(h)
            lg.setLevel(lvl)
    seen = "\n".join(records) + buf.getvalue()
    want = [200, 422, 200, 422, 501, 422, 500, 500, 500]
    bad = [] if codes == want else [f"status codes {codes}, wanted {want}"]
    bad += [f"{name} found in the captured logs / output" for name, m in (("text", "ZQXJ"), ("subject", "QWVB"), ("body", "PLMK"), ("sender", "XJMKR"), ("link", "zqxj-text")) if m.lower() in seen.lower()]
    return bad

def t19(c, ref):
    bad = []
    for t, want in (("https://sbi-kyc-update.top/login", "link"), ("see http://bit.ly/3xYz", "link"), (SBI_OTP, "message"), ("rajesh@ybl", "message"),
                    ("upi://pay?pa=shop@ybl&pn=Shop&am=100", "message"), ("ok", "message"), ("rajesh@ybl is requesting Rs 500. Approve to receive.", "message")):
        j = post(c, t).json()
        if j["input"] != want or j["details"] is not None or j["module"] != "messages":
            bad.append(f"{t[:40]!r}: input {j['input']!r} (wanted {want!r}), details {j['details']}, module {j['module']}")
    for x in INPUTS:
        j = post(c, x["text"]).json()
        if j["input"] not in ("message", "link") or j["details"] is not None or any(ch["input"] is not None or ch["details"] is not None for ch in j["children"]):
            bad.append(f"{x['id']}: input {j['input']!r}, details {j['details']}, or a child with input / details")
    return bad

CHECKS = [("T1", "GET /api/health", t1), ("T2", "every tricky input over HTTP == to_report(analyse(...)), ignoring meta.ms", t2),
          ("T3", "responses validate as Report v6, meta.ms rounded", t3), ("T4", "empty and whitespace-only text -> 422", t4),
          ("T5", "20,001 characters -> 422 (20,000 -> 200)", t5), ("T6", "wrong method -> 405", t6),
          ("T7", "no outbound network during analysis", t7), ("T8", "unknown body field -> 422", t8),
          ("T9", "SBI / OTP message: response advice == ADVICE[level]", t9),
          ("T10", "sender absent / null / '' / '   ' -> the same response, sender null", t10),
          ("T11", "Jio + JM-JIOCPN-P -> promotional; a mobile number is never echoed; non-string sender -> 422", t11),
          ("T12", "no text or sender in any log record or on stdout / stderr, even when the analysis fails", t12),
          ("T13", "/api/check: auto / message / link / email -> 200 with the right input; the other kinds -> 501 with the fixed message; unknown / missing kind -> 422", t13),
          ("T14", "/api/check: unknown field or wrong type -> 422 (extra=forbid)", t14),
          ("T15", "/api/check: auto / message == /api/analyse; link == /api/analyse; email == router.analyse(subject + body) with input email, email advice on a warning", t15),
          ("T16", "/api/check: fixed 422 messages (link with prose, empty, too long, incomplete email, expand without live)", t16),
          ("T17", "/api/check: no outbound network on the offline path (message, link, email, 501 kinds)", t17),
          ("T18", "/api/check: no text, subject, body, sender or link in any log record or on stdout / stderr, even when the analysis fails", t18),
          ("T19", "/api/analyse: input is link for a bare link and message otherwise; details null; children have no input", t19)]

def run():
    ref = (load_text_model(), load_url_model())   # a second, independent copy of the models: the HTTP layer must not change a result
    out = []
    with TestClient(app) as c:
        for tid, what, fn in CHECKS:
            out.append((tid, what, fn(c, ref)))
    return out

def test_api():
    bad = [f"{tid}: {b}" for tid, _, bs in run() for b in bs]
    assert not bad, "\n".join(bad)

if __name__ == "__main__":
    results = run()
    for tid, what, bad in results:
        print(f"{'FAIL' if bad else 'PASS'} {tid} {what}")
        for b in bad[:10]:
            print("    " + b.encode("ascii", "backslashreplace").decode()[:300])
    print(f"\n{sum(not b for _, _, b in results)}/{len(results)} passed")
    sys.exit(1 if any(b for _, _, b in results) else 0)
