import re
from collections import Counter

# Spans that must survive translation verbatim (numbers, amounts, dates, URLs, the pii.py mask tokens, and a short list of terms the
# synth_india rows also keep in Latin script: OTP, UPI, KYC, bank and app names) are swapped for markers before the model sees the
# text and swapped back afterwards. A marker the model drops, duplicates or invents makes the row fail (status != "ok") instead of
# silently corrupting a number, so the failure rate is measurable.
#   protected, spans = protect(text)          markers are <ID51>, <ID52> ... in order of appearance
#   text_out, status = restore(model_out, spans)
# Why <ID51>: IndicTransToolkit wraps emails / URLs / numerals in <ID1>, <ID2> ... itself and restores them in postprocess_batch; our
# markers start at 51 so the two numberings can never collide (tested through the toolkit for hin_Deva and kan_Knda). Findings from
# that test that shape the code below: the toolkit drops a "/" between two adjacent markers ("<ID51>/<ID52>" -> "<ID51> <ID52>") and
# splits a plural off a marker ("<ID52>s" -> "<ID52> s"), so spans separated by one punctuation character are merged into one marker
# and plurals (OTPs) are part of the vocabulary patterns.
FIRST = 51

_MONTH = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*"
_TLD = r"(?:com|in|co|org|net|gov|io|ly|cc|top|vip|xyz|me|info|app|link|ai|it|im|fm|ws|ink|bank|page|site|online|club|shop|store)"
_VOCAB = [r"OTPs?", r"UPI", r"e-?KYC", r"Re-KYC", r"KYC", r"PINs?", r"CVV", r"PAN", r"NEFT", r"IMPS", r"RTGS", r"ATM", r"SMS", r"EMI", r"SIM", r"GST",
          r"FASTag", r"[aA]/[cC]", r"Acct", r"Avl", r"Avbl", r"Bal", r"Rs", r"INR", r"PNR", r"AWB", r"IFSC", r"BHIM", r"GPay", r"PhonePe", r"Paytm",
          r"Google Pay", r"Amazon Pay", r"YONO", r"SBI", r"HDFC", r"ICICI", r"Axis", r"Kotak", r"Canara", r"PNB", r"BoB", r"IDFC", r"RBL", r"AMEX",
          r"Amazon", r"Flipkart", r"Swiggy", r"Instamart", r"Zomato", r"Myntra", r"Jio", r"Airtel", r"Vi", r"BSNL", r"FedEx", r"DHL", r"BlueDart",
          r"IRCTC", r"LIC", r"WhatsApp", r"Telegram", r"YouTube", r"Instagram", r"Google"]
PATTERNS = [
    ("mask", re.compile(r"<(?:EMAIL|UPI_ID|PHONE|ACCOUNT)>")),
    ("url", re.compile(rf"(?:https?://|www\.)[^\s<>\"']+|\b(?:[A-Za-z0-9-]+\.)+{_TLD}\b(?:/[^\s<>\"']*)?", re.I)),
    ("date", re.compile(rf"\b\d{{1,2}}[-/. ]{_MONTH}[-/., ]+\d{{2,4}}\b|\b\d{{1,2}}[-/.]\d{{1,2}}[-/.]\d{{2,4}}\b|\b\d{{4}}-\d{{2}}-\d{{2}}\b", re.I)),
    ("time", re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?(?:\s?(?:AM|PM|Hrs|IST))?", re.I)),
    ("money", re.compile(r"(?:Rs\.?|INR|₹)\s?\d[\d,]*(?:\.\d+)?(?:/-)?", re.I)),
    ("card", re.compile(r"(?:[Xx]{2,}|\*{2,})[.…]{0,3}[\w*]*")),
    ("code", re.compile(r"(?<![\w])[A-Za-z*#]{0,4}\d[\w*]*(?:[.,/-]\d[\w*]*)*")),
    ("vocab", re.compile(r"\b(?:" + "|".join(sorted(_VOCAB, key=len, reverse=True)) + r")\b", re.I)),
]
_TRAIL = ".,;:!?)'\"]"

def spans_of(text):
    """Non-overlapping (start, end) spans to protect: leftmost, then longest; spans split by a single / - : (or touching) are merged."""
    cand = []
    for kind, rx in PATTERNS:
        for m in rx.finditer(text):
            a, b = m.span()
            if kind == "url":
                while b > a and text[b - 1] in _TRAIL:
                    b -= 1
            if b > a:
                cand.append((a, b))
    cand.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    kept, last = [], 0
    for a, b in cand:
        if a >= last:
            kept.append([a, b])
            last = b
    merged = []
    for a, b in kept:
        if merged and (a == merged[-1][1] or (a - merged[-1][1] == 1 and text[merged[-1][1]] in "/-:")):
            merged[-1][1] = b
        else:
            merged.append([a, b])
    return [tuple(x) for x in merged]

def protect(text):
    spans, out, pos = [], [], 0
    for k, (a, b) in enumerate(spans_of(text)):
        out.append(text[pos:a] + f"<ID{FIRST + k}>")
        spans.append(text[a:b])
        pos = b
    out.append(text[pos:])
    return "".join(out), spans

_MARKER = re.compile(r"[<\[]\s*ID\s*(\d+)\s*[>\]]", re.I)

def restore(out, spans):
    """-> (text, "ok") or (None, reason). The model may respace or re-bracket a marker (< ID51 >, [ID51]); those are accepted. Each expected
    marker must appear exactly once and no other marker may appear."""
    canon = _MARKER.sub(lambda m: f"<ID{int(m.group(1))}>", out)
    seen = Counter(int(i) for i in re.findall(r"<ID(\d+)>", canon))
    expect = range(FIRST, FIRST + len(spans))
    if any(seen[i] == 0 for i in expect):
        return None, "marker_missing"
    if any(seen[i] > 1 for i in expect):
        return None, "marker_duplicated"
    if set(seen) - set(expect):
        return None, "stray_marker"
    for k, sp in enumerate(spans):
        canon = canon.replace(f"<ID{FIRST + k}>", sp)
    return canon, "ok"
