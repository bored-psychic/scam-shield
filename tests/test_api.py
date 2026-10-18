import contextlib, io, logging, os, socket, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from fastapi.testclient import TestClient
from shield.api.main import app
from shield.contracts import Level, Report, SCHEMA_VERSION
from shield.core.advice import ADVICE, GAMBLING_ADVICE
from shield.core.report import to_report
from shield.core.router import analyse
from shield.links.lexical import load_url_model
from shield.messages.text_head import load_text_model
from textprep import extract_urls
from tricky_inputs import INPUTS

# python tests/test_api.py   (from the project root; needs both models; no pytest required, but pytest collects test_api() too)
# Runs the app in-process (TestClient inside `with`, so the lifespan loads the models once) and checks, each printed PASS / FAIL:
#   T1 GET /api/health   T2 every tricky input over HTTP == to_report(analyse(...)) except meta.ms   T3 response validates as a Report (schema "5", ms rounded)
#   T4 empty / whitespace-only text -> 422   T5 over 20,000 characters -> 422 (20,000 is still fine)   T6 wrong method -> 405
#   T7 no network: sockets patched to record + refuse every connection / lookup, link-bearing inputs still answer 200 with 0 attempts
#   T8 unknown body field -> 422
#   T9 an SBI / OTP-request message: the response advice == ADVICE[level] (gambling line first iff category == "gambling"), the same rule as A13 in test_contracts.py
#   T10 the sender field (D22) absent, null, "" and "   ": the same response (except meta.ms), "sender": null, for every tricky input
#   T11 the Jio promo with "JM-JIOCPN-P" -> promotional, sender block {dlt, P, JIOCPN}; with a mobile number -> kind "mobile" only, the digits nowhere in the
#       response; a non-string sender -> 422
#   T12 nothing the user typed reaches a log: every logging record (root, uvicorn, fastapi, at DEBUG) and everything written to stdout / stderr while
#       requests with a marked text and sender are answered (including a failing analysis) is captured, and neither marker appears in it
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

def t1(c, ref):
    r = c.get("/api/health")
    return [] if (r.status_code, r.json()) == (200, {"status": "ok", "schema_version": "5"}) and SCHEMA_VERSION == "5" else [f"{r.status_code} {r.text}"]

def t2(c, ref):
    tm, um = ref
    bad = []
    for x in INPUTS:
        r = post(c, x["text"])
        want = to_report(x["text"], analyse(x["text"], tm, um)).model_dump(mode="json")
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
        if rep.schema_version != "5" or j["schema_version"] != "5":
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

def t7(c, ref):
    texts = {x["id"]: x["text"] for x in INPUTS}
    assert all(extract_urls(texts[i]) for i in LINK_IDS), "T7 inputs must contain links"
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
            return ["the guard is not live: create_connection did not raise"]
        except OSError:
            pass
        attempts.clear()   # the line above was the probe
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
    finally:
        for n, f in saved_methods.items():
            delattr(socket.socket, n) if f is None else setattr(socket.socket, n, f)
        for n, f in saved_funcs.items():
            setattr(socket, n, f)

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

CHECKS = [("T1", "GET /api/health", t1), ("T2", "every tricky input over HTTP == to_report(analyse(...)), ignoring meta.ms", t2),
          ("T3", "responses validate as Report v4, meta.ms rounded", t3), ("T4", "empty and whitespace-only text -> 422", t4),
          ("T5", "20,001 characters -> 422 (20,000 -> 200)", t5), ("T6", "wrong method -> 405", t6),
          ("T7", "no outbound network during analysis", t7), ("T8", "unknown body field -> 422", t8),
          ("T9", "SBI / OTP message: response advice == ADVICE[level]", t9),
          ("T10", "sender absent / null / '' / '   ' -> the same response, sender null", t10),
          ("T11", "Jio + JM-JIOCPN-P -> promotional; a mobile number is never echoed; non-string sender -> 422", t11),
          ("T12", "no text or sender in any log record or on stdout / stderr, even when the analysis fails", t12)]

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
