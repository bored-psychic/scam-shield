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
_ASK_VERBS = r"send|share|forward|give|provide|tell|read out|reply with|reply|submit|relay"
_ASK_FIRST = re.compile(rf"\b(?:{_ASK_VERBS})\b[^.!?\n]{{0,40}}?\b{_CRED}\b", re.I)
_ASK_LAST = re.compile(rf"\b{_CRED}\b[^.!?\n]{{0,25}}?\b(?:bata(?:o|do|dena|iye|yein)?|bhej(?:o|do|dena|iye|ein)?|share kar(?:o|iye|ein|do|na)?)\b", re.I)
_NEG_BEFORE = re.compile(r"\b(?:do not|don'?t|dont|never|not|no one|nobody|avoid|cannot|can'?t|won'?t|will not|should not|shouldn'?t)\s+(?:[\w']+\s+){0,3}$", re.I)
# "do not, under any circumstances, share": the negation, a comma-delimited aside, then the verb. The aside must start right after the negation, so
# "Don't worry, just share the OTP" (the word 'worry' sits between them) is still a request.
_NEG_ASIDE = re.compile(r"\b(?:do not|don'?t|dont|never|not|should not|shouldn'?t|will not|won'?t|cannot|can'?t)\s*,\s*[^,.!?\n]{1,40},\s*$", re.I)
_NEG_INSIDE = re.compile(r"\b(?:no one|nobody|not|never|mat|nahi|na)\b", re.I)

def _negated(text, m):
    """Whether the match m of a request pattern sits under a negation (the three tests described above). The one copy, used by cred_requests
    (negated = skipped) and advisory_phrases (negated = kept), so the two can never disagree about what is negated."""
    before = text[max(0, m.start() - 60):m.start()]
    return bool(_NEG_INSIDE.search(m.group(0)) or _NEG_BEFORE.search(before[-40:]) or _NEG_ASIDE.search(before))

def cred_requests(text):
    """Phrases that ask the reader to send / share / forward an OTP, PIN or CVV (empty list = none). Benign warnings are not requests."""
    hits = []
    for rx in (_ASK_FIRST, _ASK_LAST):
        for m in rx.finditer(text):
            if _negated(text, m):
                continue
            ph = m.group(0).strip().lower()
            if ph not in hits:
                hits.append(ph)
    return hits[:3]


# ---------------------------------------------------------------- safety advice (the mirror image of a request)
# "Never share your OTP", "Bank will never ask you to share your OTP or PIN", "Do not, under any circumstances, share your OTP": the same
# patterns as the request rule, found where _negated() is true. The verb list adds disclose / reveal / divulge / ask, which a warning uses
# and a request does not ("ask" is only ever the bank's verb in a warning). Same-sentence only. Not covered, on purpose: the pronoun form
# ("Your OTP is 482913. Do not share it with anyone."), which names no credential in the clause, and the affirmative "Keep your OTP confidential".
# This function only finds the phrase; whether a message may be treated as safe because of it is decided in router.safety_advice_cap().
_ADVISE_FIRST = re.compile(rf"\b(?:{_ASK_VERBS}|disclose|reveal|divulge|asks?|asked|asking)\b[^.!?\n]{{0,40}}?\b{_CRED}\b", re.I)

def advisory_phrases(text):
    """Phrases that warn the reader NOT to send / share / disclose / tell / ask for an OTP, PIN or CVV (empty list = none), lower-cased, at most 3,
    in the same form as cred_requests() so the Report can quote and underline them. A message can have both (a request wrapped in a warning);
    the caller decides what that means."""
    hits = []
    for rx in (_ADVISE_FIRST, _ASK_LAST):
        for m in rx.finditer(text):
            if not _negated(text, m):
                continue
            ph = m.group(0).strip().lower()
            if ph not in hits:
                hits.append(ph)
    return hits[:3]


# ---------------------------------------------------------------- a phone number to call
# An Indian mobile number: 10 digits starting 6-9, optionally written 5+5 / with single spaces, dots or dashes between digits, optionally behind
# +91 / 91 / 0. Deliberately wider than the PII mask (which needs a 5+5 split): a miss here lets the safety-advice cap fire on a message that
# tells the reader to call someone, a false hit only keeps a warning. A digit directly in front rules the match out, and so does a lone '1' and a
# separator (1-800-...), so toll-free 1800 numbers and longer digit strings (account, card numbers) are not mobile numbers.
_MOBILE = re.compile(r"(?<!\d)(?<!\b1[ .-])(?:(?:\+|00)?91[ .-]?|0)?[6-9](?:[ .-]?\d){9}(?!\d)")

def has_indian_mobile(text):
    return _MOBILE.search(text) is not None
