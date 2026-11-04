import os, socket, sys
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_intake.py")))   # exec()-ed from the project root there is no __file__
sys.path[:0] = [os.path.join(HERE, "..", "src"), HERE]
from shield.core.intake import classify
from shield.core.router import MAX_TEXT_CHARS, MIN_PROSE_WORDS, prose_word_count
from tricky_inputs import INPUTS

# python tests/test_intake.py   (from the project root; also collected by pytest). shield.core.intake.classify (docs/plans/multi_input.md 2.1, W1): string work
# only, no model, no network. Checks, each printed PASS / FAIL:
#   I1 a single link (scheme, hxxp / [.] forms, www., bare domain with a path, with up to 2 words around it) -> "link"
#   I2 a single UPI ID, alone (spaces and newlines around it do not matter; NPCI handles, SEBI @valid ids, any case) -> "upi_id"
#   I3 a upi:// string with no whitespace -> "qr"; the same with a space in it stays "message"
#   I4 three or more prose words -> "message", whatever else the text holds (links, UPI IDs)
#   I5 request-shaped text ("x@ybl is requesting Rs 500", "pay x@ybl", collect-request wording) stays "message" (rule 12: the real test set could hold it)
#   I6 empty, whitespace-only and None -> "message"; two links or a link and an e-mail address -> "message"; the literal "<UPI_ID>" is not an ID
#   I7 every tricky input with >= MIN_PROSE_WORDS prose words is "message"; every answer is one of the four classes; classify never raises
#   I8 no outbound network: sockets patched to refuse every connection, none is attempted; a text longer than MAX_TEXT_CHARS is cut like analyse() cuts it
LINK = ["https://example.com/login", "  http://bit.ly/3xYz  ", "see http://bit.ly/3xYz", "hxxps://evil[.]com/verify", "www.sbi-kyc-update.top", "http://a.com rajesh@ybl",   # the last: 2 prose words, one link = the router's bare link
        "sbi-kyc-update.top/login", "click https://example.com/a now", "https://example.com/a\n"]
UPI_ID = ["rajesh@ybl", "  rajesh.kumar@oksbi \n", "name.brk@validhdfc", "SHOP@OKAXIS", "9876543210@paytm", "dunzo.payu@axisbank"]
QR = ["upi://pay?pa=shop@ybl&pn=Shop&am=100", "UPI://PAY?pa=x@ybl", "  upi://pay?pa=shop@oksbi&cu=INR\n"]
QR_NOT = ["upi://pay?pa=shop@ybl&pn=My Shop&am=100", "scan upi://pay?pa=shop@ybl to receive"]
MESSAGE = ["Your account is blocked, click http://sbi-kyc.xyz/login now",   # I4: three or more prose words
           "Dear customer, share your OTP: http://sbi-kyc-verify.xyz/login",
           "ok", "hello", "Urgent: pay rajesh@ybl today",
           "rajesh@ybl is requesting Rs 500 on UPI. Approve to receive your refund.",   # I5: request-shaped
           "Collect request from rajesh@ybl for Rs 5000. Enter your UPI PIN to receive the money.",
           "pay rajesh@ybl", "rajesh@ybl requesting 500", "Rs 500 requested by rajesh@ybl",
           "", "   ", "\n\t", "http://a.com http://b.com", "rajesh@gmail.com", "user@unknownbank", "<UPI_ID>", "<UPI>"]


def i1():
    return [f"{t!r}: {classify(t)}" for t in LINK if classify(t) != "link"]

def i2():
    return [f"{t!r}: {classify(t)}" for t in UPI_ID if classify(t) != "upi_id"]

def i3():
    return ([f"{t!r}: {classify(t)}" for t in QR if classify(t) != "qr"] + [f"{t!r}: {classify(t)}, wanted message" for t in QR_NOT if classify(t) != "message"])

def i4():
    texts = ["Your account is blocked, click http://sbi-kyc.xyz/login now", "see this link now http://x.com", "rajesh@ybl sent you money today"]
    return [f"{t!r}: {prose_word_count(t)} words, {classify(t)}" for t in texts if prose_word_count(t) < MIN_PROSE_WORDS or classify(t) != "message"]

def i5():
    return [f"{t!r}: {classify(t)}" for t in MESSAGE if classify(t) != "message"]

def i6():
    bad = [f"None: {classify(None)}"] if classify(None) != "message" else []
    bad += [f"{t!r}: {classify(t)}" for t in ("", "   ", "\n\t", "http://a.com http://b.com", "<UPI_ID>", "<UPI>", "rajesh@gmail.com")
            if classify(t) != "message"]
    return bad

def i7():
    bad = []
    for x in INPUTS:
        try:
            c = classify(x["text"])
        except Exception as e:   # pragma: no cover
            bad.append(f"{x['id']}: raised {type(e).__name__}")
            continue
        if c not in ("message", "link", "upi_id", "qr"):
            bad.append(f"{x['id']}: unknown class {c!r}")
        if prose_word_count(x["text"]) >= MIN_PROSE_WORDS and c != "message":
            bad.append(f"{x['id']}: {prose_word_count(x['text'])} prose words but classified {c}")
    return bad

def i8():
    attempts = []
    names = ("connect", "connect_ex")
    saved_methods = {n: socket.socket.__dict__.get(n) for n in names}
    saved_funcs = {n: getattr(socket, n) for n in ("create_connection", "getaddrinfo", "gethostbyname")}
    def refuse(name):
        def f(*a, **k):
            attempts.append(name)
            raise OSError(f"I8: outbound network call blocked ({name})")
        return f
    bad = []
    try:
        for n in names:
            setattr(socket.socket, n, refuse(n))
        for n in saved_funcs:
            setattr(socket, n, refuse(n))
        for t in LINK + UPI_ID + QR + MESSAGE:
            classify(t)
        if attempts:
            bad.append(f"outbound attempts: {attempts}")
    finally:
        for n, f in saved_methods.items():
            delattr(socket.socket, n) if f is None else setattr(socket.socket, n, f)
        for n, f in saved_funcs.items():
            setattr(socket, n, f)
    long_link = "https://example.com/x " + "a" * (MAX_TEXT_CHARS + 50)
    cut = long_link[:MAX_TEXT_CHARS]
    if classify(long_link) != classify(cut):
        bad.append("a text over MAX_TEXT_CHARS is not classified like its cut")
    return bad

CHECKS = [("I1", "a single link -> link", i1), ("I2", "a single UPI ID -> upi_id", i2), ("I3", "a upi:// string -> qr (a space in it -> message)", i3),
          ("I4", "3+ prose words -> message", i4), ("I5", "request-shaped and other texts stay message", i5),
          ("I6", "empty / None / two links / e-mail / mask token -> message", i6), ("I7", "tricky inputs: only the four classes, 3+ words -> message", i7),
          ("I8", "no network; over-long text cut like analyse()", i8)]

def test_intake():
    bad = [f"{cid}: {b}" for cid, _, fn in CHECKS for b in fn()]
    assert not bad, "\n".join(bad)

if __name__ == "__main__":
    results = [(cid, what, fn()) for cid, what, fn in CHECKS]
    for cid, what, bad in results:
        print(f"{'FAIL' if bad else 'PASS'} {cid} {what}")
        for b in bad[:10]:
            print("    " + b.encode("ascii", "backslashreplace").decode()[:300])
    print(f"\n{sum(not b for _, _, b in results)}/{len(results)} passed")
    sys.exit(1 if any(b for _, _, b in results) else 0)
