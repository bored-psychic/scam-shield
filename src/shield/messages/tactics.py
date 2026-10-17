import re
from shield.messages.rules import _CRED_WORD, _DISCLAIMER, cred_requests

# ---------------------------------------------------------------- tactic tags
# Hand-written cue lists, English plus a few Hinglish / Hindi / Kannada words. The Hindi and Kannada ones are not yet checked by a
# native speaker (reports/spotcheck_*.csv is still open) and none of the lists was tuned on val or test.
_T = lambda *p: re.compile("|".join(p), re.I)
TACTICS = {
    "authority": _T(
        r"\b(?:rbi|reserve bank|sebi|npci|uidai|aadhaar|aadhar|income tax|cbi|enforcement directorate|police|cyber ?crime|customs|trai|"
        r"narcotics|court|ministry|government|govt|officer|department|customer care|kyc|fir|arrest(?:ed)?|warrant|legal action|"
        r"sbi|hdfc|icici|axis bank|kotak|paytm|phonepe|amazon|flipkart|microsoft|apple support|irctc|india post|bank)\b",
        r"पुलिस|सरकार|आधार|बैंक|ಪೊಲೀಸ್|ಸರ್ಕಾರ|ಬ್ಯಾಂಕ್"),
    "urgency": _T(
        r"\b(?:urgent(?:ly)?|immediately|asap|right now|at once|hurry|deadline|last (?:chance|day|date|warning)|final (?:notice|warning|reminder)|"
        r"act now|(?:pay|click|verify|update|call|claim|apply|login|register) (?:now|today)|today only|limited time|expires?(?: today| soon| in)?|"
        r"expir(?:ed|ing)|within \d+ ?(?:hours?|hrs?|mins?|minutes?|days?)|before midnight|do not delay|don'?t delay|"
        r"(?:will|be|get) (?:be )?(?:blocked|suspended|deactivated|disconnected|terminated|closed|locked|cancelled)|avoid (?:penalty|disconnection|suspension)|"
        r"turant|jaldi|abhi|aaj hi|jald se jald)\b",
        r"तुरंत|तत्काल|जल्दी|अभी|आज ही|ತಕ್ಷಣ|ಈಗಲೇ|ಬೇಗ"),
    "payment": _T(
        r"\b(?:pay(?:ment)?|transfer|send money|deposit|upi|gpay|google pay|phonepe|paytm|bhim|qr code|scan (?:the )?qr|collect request|"
        r"approve (?:the )?request|(?:upi )?pin|processing fee|registration fee|advance|refund|cashback|wire|western union|bitcoin|crypto|usdt|"
        r"gift card|recharge|challan|penalty|customs duty|account number|ifsc|cvv|otp|card number)\b",
        r"(?:\brs\.?|\binr|₹)\s?\d[\d,]*(?:\.\d+)?", r"<UPI_ID>|<ACCOUNT>", r"भुगतान|पैसे|रिफंड|ಪಾವತಿ|ಹಣ"),
    # always-on secrecy / control cues
    "isolation": _T(
        r"\btell (?:no ?one|nobody)\b", r"\bwithout (?:telling|informing)\b",
        r"\b(?:do not|don'?t|never) (?:hang up|disconnect)\b", r"\b(?:do not|don'?t) (?:contact|call|talk to) (?:your |any )?(?:family|bank|friends?|police|anyone)\b",
        r"\b(?:delete|erase|remove) (?:this|the|these|all) (?:message|msg|sms|chat|text|e-?mail|conversation|messages)\b",
        r"\bstay (?:on the )?(?:line|call|video)\b", r"\bremain on (?:the )?(?:call|video)\b", r"\bdigital arrest\b", r"\bnational security\b",
        r"\b(?:switch|move) to (?:whatsapp|telegram|signal)\b", r"\badd me on (?:whatsapp|telegram)\b",
        r"\bjoin (?:our |the )?(?:whatsapp|telegram) (?:group|channel)\b",
        # Hinglish / Hindi / Kannada (hand-written, unchecked by a native speaker; Indic text uses [^\s.,!?।]* because \w stops at combining marks)
        r"\bkisi ko (?:bhi )?(?:mat|nahi|na) (?:batana|batao|bataiye|batayein|bolna|kehna)\b", r"\b(?:ghar walon|family|bank|police) ko (?:mat|nahi|na) bata[a-z]*\b",
        r"\b(?:ye|yeh|is) message (?:ko )?delete kar[a-z]*\b", r"\bgopniya rakh[a-z]*\b",
        r"किसी को (?:भी )?(?:न|मत|नहीं) बता[^\s.,!?।]*", r"(?:परिवार|बैंक|घर वालों) को (?:न|मत|नहीं) बता[^\s.,!?।]*", r"गोपनीय रख[^\s.,!?।]*",
        r"(?:यह|ये|इस) (?:संदेश|मैसेज) (?:को )?(?:डिलीट|हटा|मिटा)[^\s.,!?।]*",
        r"ಯಾರಿಗೂ (?:ಹೇಳ|ತಿಳಿಸ)[^\s.,!?।]*", r"ಕುಟುಂಬ[^\s.,!?।]* ಹೇಳ[^\s.,!?।]*", r"ಗೌಪ್ಯ[^\s.,!?।]*",
        r"ಈ ಸಂದೇಶ[^\s.,!?।]* (?:ಅಳಿಸ|ಡಿಲೀಟ್)[^\s.,!?।]*"),
}
# Secrecy cues that genuine OTP alerts also use ("Do not share it with anyone", "Keep your OTP confidential"). They count only when the
# text isn't an OTP-style advisory: no credential word, or it actually asks for one (cred_requests below).
_SECRECY = _T(
    r"\b(?:do not|don'?t|never) (?:tell|inform|disclose|discuss|mention|share)\b[^.!?\n]{0,30}?\b(?:anyone|anybody|no ?one|family|friends|relatives|bank|police|colleagues|others|this|it)\b",
    r"\bkeep (?:this|it|the matter|everything|all this)?\s*(?:strictly )?(?:confidential|secret|private|between us|to yourself)\b",
    r"\bsecret(?:ly)?\b")

def tactic_matches(text, tag, cred_hits):
    """The matches (re.Match, with positions) that tactic_tags() counts for one tag, in its order, before de-duplication and the cap of 4: the
    secrecy cues only when the text isn't an OTP-style advisory, and no 'delete this message' in an email disclaimer. shield.messages.threats reuses
    the isolation ones as its secrecy family."""
    rxs = [TACTICS[tag]] + ([_SECRECY] if tag == "isolation" and (cred_hits or not _CRED_WORD.search(text)) else [])
    for r_ in rxs:
        for m in r_.finditer(text):
            s = m.group(0).strip().lower()
            if tag == "isolation" and _DISCLAIMER.search(text) and re.match(r"(?:delete|erase|remove)\b", s):
                continue
            if s:
                yield m

def tactic_tags(text, cred_hits=None):
    """tag -> up to 4 distinct matched phrases (empty list = tag absent). cred_hits: cred_requests(text), computed here if not given."""
    cred_hits = cred_requests(text) if cred_hits is None else cred_hits
    out = {}
    for tag in TACTICS:
        seen = []
        for m in tactic_matches(text, tag, cred_hits):
            s = m.group(0).strip().lower()
            if s not in seen:
                seen.append(s)
        out[tag] = seen[:4]
    return out
