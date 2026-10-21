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
    # bounded on both sides (2026-10-21): without it an OTP like "1:363094" was cut into the time "1:36" and a loose "3094"; now a longer
    # number falls through to the code pattern and the whole token is one span
    ("time", re.compile(r"(?<![\d:])\b\d{1,2}:\d{2}(?::\d{2})?(?![\d:])(?:\s?(?:AM|PM|Hrs|IST))?", re.I)),
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
# When the model translates the marker instead of copying it, "ID" comes back transliterated: <ID51> -> <ಐಡಿ51>, <आई. डी. 51>. These spellings (the toolkit's own list
# of Hindi failure cases plus the Kannada one seen in the 50-sentence test) are accepted only under the strict rule in restore().
_ID_SPELL = r"(?:ID|आ[ईयइ]\s*\.?\s*डी\s*\.?|ऐ[टड]ि|आइडि|आयडी|ಐ\s*ಡಿ)"
_TOLERANT = re.compile(r"[<\[]\s*" + _ID_SPELL + r"\s*(\d+)\s*[>\]]", re.I)
_LEFTOVER = re.compile(_ID_SPELL + r"\s*\.?\s*\d|[<\[]\s*" + _ID_SPELL, re.I)

def restore(out, spans):
    """-> (text, "ok"), (text, "ok_tolerant") or (None, reason).
    Exact path: markers spelled <ID51> (a model-added space or [ ] bracket is fine). Each expected marker must appear exactly once and no other
    marker may appear; their order may change, because Hindi / Kannada word order differs from English.
    Tolerant path, only when the exact path failed: markers whose "ID" came back transliterated are recovered ONLY if every marker is matched exactly
    once, in the original order (51, 52, ...), nothing else that looks like a marker is left in the text, and nothing extra was matched. Anything
    ambiguous keeps the exact path's failure reason."""
    canon = _MARKER.sub(lambda m: f"<ID{int(m.group(1))}>", out)
    seen = Counter(int(i) for i in re.findall(r"<ID(\d+)>", canon))
    expect = list(range(FIRST, FIRST + len(spans)))
    if all(seen[i] == 1 for i in expect) and not set(seen) - set(expect):
        for k, sp in enumerate(spans):
            canon = canon.replace(f"<ID{FIRST + k}>", sp)
        return canon, "ok"
    reason = ("marker_missing" if any(seen[i] == 0 for i in expect) else "marker_duplicated" if any(seen[i] > 1 for i in expect) else "stray_marker")
    found = list(_TOLERANT.finditer(out))
    if not spans or [int(m.group(1)) for m in found] != expect:
        return None, reason
    rest = _TOLERANT.sub(" ", out)
    if _LEFTOVER.search(rest):
        return None, reason
    pieces, pos = [], 0
    for m, sp in zip(found, spans):
        pieces += [out[pos:m.start()], sp]
        pos = m.end()
    pieces.append(out[pos:])
    return "".join(pieces), "ok_tolerant"

def strip_markers(out):
    """Model output with every marker token (exact or transliterated spelling) replaced by a space: the text OUTSIDE the protected spans.
    finalise uses it to measure script share on the words the model actually translated, not on numbers, amounts and bank names."""
    return _TOLERANT.sub(" ", _MARKER.sub(" ", out))
