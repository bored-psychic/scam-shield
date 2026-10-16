import re

_CRED_WORD = re.compile(r"\b(?:otp|pin|cvv2?|cvc|password|passcode|verification code|security code)\b", re.I)
_DISCLAIMER = re.compile(r"intended recipient|in error|by mistake|received this (?:e-?mail|message)", re.I)   # 'please delete this message' footers


# ---------------------------------------------------------------- credential requests
# Hard rule: a request to send, share or forward an OTP, PIN or CVV is at least Suspicious whatever the models say, and is shown as its
# own red flag. Nothing legitimate asks for these. Genuine alerts only warn against sharing ("Do not share your OTP"), so a verb counts
# only when no negation sits directly in front of it (up to 3 words, no punctuation: "do not share", "never ask you to share"; or a comma-delimited
# aside: "do not, under any circumstances, share"; but "Don't worry, just share the OTP" is still a request). English plus a Hinglish "OTP bata do" form; the verb list leaves out text / message /
# confirm / enter, which genuine OTP SMS use ("Enter OTP 482913 to confirm"). Known false positive: a real delivery-OTP instruction
# ("share the OTP with the delivery partner"). 'pin code' is the postal code, not a PIN.
_CRED = (r"(?:otp|one[- ]?time[- ](?:password|pin|code)|verification code|security code|cvv2?|cvc|"
         r"(?:(?:upi|atm|card|debit|credit|net ?banking|m|t)[ -]?)?pin(?![ -]?code))")
_ASK_FIRST = re.compile(rf"\b(?:send|share|forward|give|provide|tell|read out|reply with|reply|submit|relay)\b[^.!?\n]{{0,40}}?\b{_CRED}\b", re.I)
_ASK_LAST = re.compile(rf"\b{_CRED}\b[^.!?\n]{{0,25}}?\b(?:bata(?:o|do|dena|iye|yein)?|bhej(?:o|do|dena|iye|ein)?|share kar(?:o|iye|ein|do|na)?)\b", re.I)
_NEG_BEFORE = re.compile(r"\b(?:do not|don'?t|dont|never|not|no one|nobody|avoid|cannot|can'?t|won'?t|will not|should not|shouldn'?t)\s+(?:[\w']+\s+){0,3}$", re.I)
# "do not, under any circumstances, share": the negation, a comma-delimited aside, then the verb. The aside must start right after the negation, so
# "Don't worry, just share the OTP" (the word 'worry' sits between them) is still a request.
_NEG_ASIDE = re.compile(r"\b(?:do not|don'?t|dont|never|not|should not|shouldn'?t|will not|won'?t|cannot|can'?t)\s*,\s*[^,.!?\n]{1,40},\s*$", re.I)
_NEG_INSIDE = re.compile(r"\b(?:no one|nobody|not|never|mat|nahi|na)\b", re.I)

def cred_requests(text):
    """Phrases that ask the reader to send / share / forward an OTP, PIN or CVV (empty list = none). Benign warnings are not requests."""
    hits = []
    for rx in (_ASK_FIRST, _ASK_LAST):
        for m in rx.finditer(text):
            before = text[max(0, m.start() - 60):m.start()]
            if _NEG_INSIDE.search(m.group(0)) or _NEG_BEFORE.search(before[-40:]) or _NEG_ASIDE.search(before):
                continue
            ph = m.group(0).strip().lower()
            if ph not in hits:
                hits.append(ph)
    return hits[:3]
