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
# A negation only cancels a request when it is attached to the request verb itself. "Don't hesitate to share your OTP", "Please do not worry and
# send the OTP", "Never forget to share your OTP", "Do not think twice, send the PIN" negate hesitating / worrying / forgetting, not sharing: they are
# requests (see _NOT_THE_VERB).
_CRED = (r"(?:otp|one[- ]?time[- ](?:password|pin|code)|verification code|security code|cvv2?|cvc|"
         r"(?:(?:upi|atm|card|debit|credit|net ?banking|m|t)[ -]?)?pin(?![ -]?code))")
_ASK_VERBS = r"send|share|forward|give|provide|tell|read out|reply with|reply|submit|relay"
_ASK_FIRST = re.compile(rf"\b(?:{_ASK_VERBS})\b[^.!?\n]{{0,40}}?\b{_CRED}\b", re.I)
_ASK_LAST = re.compile(rf"\b{_CRED}\b[^.!?\n]{{0,25}}?\b(?:bata(?:o|do|dena|iye|yein)?|bhej(?:o|do|dena|iye|ein)?|share kar(?:o|iye|ein|do|na)?)\b", re.I)
# One candidate per negation in the 40 characters before the verb; 'between' (group 2, inside a lookahead so the candidates can overlap) is the up to
# three words from the negation to the verb. A candidate counts only if _NOT_THE_VERB finds nothing in 'between'.
_NEG_BEFORE = re.compile(r"\b(do not|don'?t|dont|never|not|no one|nobody|avoid|cannot|can'?t|won'?t|will not|should not|shouldn'?t)\s+(?=((?:[\w']+\s+){0,3})$)", re.I)
# "do not, under any circumstances, share": the negation, a comma-delimited aside, then the verb. The aside must start right after the negation, so
# "Don't worry, just share the OTP" (the word 'worry' sits between them) is still a request.
_NEG_ASIDE = re.compile(r"\b(?:do not|don'?t|dont|never|not|should not|shouldn'?t|will not|won'?t|cannot|can'?t)\s*,\s*([^,.!?\n]{1,40}),\s*$", re.I)
# The words a negation is attached to when it is not attached to the request verb: hesitate, worry, delay, wait, panic, fear / be afraid / be scared /
# be shy, forget, think twice (all inflections). "No need to panic, just send your PIN" is the same case, and needs no entry: 'no need' is not a
# negation word above, so it never cancels anything ("There is no need to share your OTP" therefore still fires, as before).
_NOT_THE_VERB = re.compile(r"\b(?:hesitat\w*|worr\w*|delay\w*|wait\w*|panic\w*|fear\w*|afraid|scared|shy|forget\w*|forgot\w*|(?:think\w*|thought)\s+twice)\b", re.I)
_NEG_INSIDE = re.compile(r"\b(?:no one|nobody|not|never|mat|nahi|na)\b", re.I)

def _negated(text, m):
    """Whether the match m of a request pattern sits under a negation (the three tests described above). The one copy, used by cred_requests
    (negated = skipped) and advisory_phrases (negated = kept), so the two can never disagree about what is negated."""
    before = text[max(0, m.start() - 60):m.start()]
    if _NEG_INSIDE.search(m.group(0)):
        return True
    if any(not _NOT_THE_VERB.search(c.group(2)) for c in _NEG_BEFORE.finditer(before[-40:])):
        return True
    a = _NEG_ASIDE.search(before)
    return bool(a and not _NOT_THE_VERB.search(a.group(1)))

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


# ---------------------------------------------------------------- a UPI PIN asked for in order to RECEIVE money (rule R2)
# Receiving money on UPI never needs a PIN: the PIN is entered only to PAY. "Enter your UPI PIN to receive the refund", "accept the collect request and
# put your MPIN to get the cashback" is therefore a scam whatever the sender calls it (the collect-request / "sent by mistake" script). cred_requests()
# leaves 'enter' out of its verbs on purpose (genuine OTP SMS say "Enter OTP 482913 to confirm"), so it misses this; here the PIN is the credential, and
# the other half is a receive-money cue near it. 'PIN code' is the postal code. Negation is _negated(), the same copy as the OTP rule ("You never need to
# enter your UPI PIN to receive money" is silent); like the OTP rule it does not know "no need to enter ..." (BUGS.md).
# The verbs are the spec's (enter / type / put / give / share / approve) plus the OTP rule's request verbs, so a message that both rules see gets both pieces
# of evidence; the level was already forced by cred_requests there. Hinglish: only the "UPI PIN daal ke" form (unchecked by a native speaker).
# 'Near' = in the same sentence, or within 12 words either side (the window crosses a full stop): a sentence that only talks about paying ("Enter your UPI PIN
# to pay Rs 499. You will receive 5% cashback.") is therefore a known false positive. 'received' is not a cue (it also describes a delivery); 'receive' is.
_PIN = r"(?:upi[ -]?)?(?:m-?pin|pin)(?![ -]?code)"
_PIN_VERBS = (r"enter(?:ing)?|typ(?:e|ing)|put(?:ting)?|giv(?:e|ing)|shar(?:e|ing)|approv(?:e|ing)|key(?:ing)? in|input(?:ting)?|provid(?:e|ing)|submit(?:ting)?|"
              r"send(?:ing)?|tell(?:ing)?|forward(?:ing)?|reply(?:ing)? with|read out|relay(?:ing)?")
_PIN_FIRST = re.compile(rf"\b(?:{_PIN_VERBS})\b[^.!?\n]{{0,40}}?\b{_PIN}\b", re.I)
_PIN_LAST = re.compile(rf"\b{_PIN}\b[^.!?\n]{{0,25}}?\b(?:daal\w*|dal(?:o|na|ein|iye|ke|kar)\b|(?:enter|type|approve) kar\w*)", re.I)
_RECEIVE = re.compile(r"\breceiv(?:e|ing)\b|\bget(?:ting)?\b(?:\s+\w+){0,3}?\s+(?:money|amount|refund|cash ?back|prize|payment)\b|\brefund\w*|\bcash ?back\b|"
                      r"\bcredit(?:ed)?\s+(?:to|in(?:to)?)\s+(?:you|your)\b|\bcollect (?:request|money)\b|\baccept(?:ing)?\s+(?:the |this |your |a )?(?:payment|request|money)\b", re.I)
_SENTENCE_END = re.compile(r"[.!?]+(?=\s|$)|\n")
_WINDOW_WORDS = 12

def _near(text, start, end):
    """(lo, hi): the sentence around text[start:end], widened to 12 words before and after it if that reaches further (the union of the two readings)."""
    ends = [m.end() for m in _SENTENCE_END.finditer(text)]
    lo = max([e for e in ends if e <= start], default=0)
    hi = min([e for e in ends if e >= end], default=len(text))
    words = [m.span() for m in re.finditer(r"\S+", text)]
    first = next((i for i, (_, b) in enumerate(words) if b > start), len(words))
    last = max((i for i, (a, _) in enumerate(words) if a < end), default=first)
    return (min(lo, words[max(0, first - _WINDOW_WORDS)][0]) if words else lo,
            max(hi, words[min(len(words) - 1, last + _WINDOW_WORDS)][1]) if words else hi)

def pin_to_receive(text):
    """Phrases that ask for a UPI PIN / MPIN in order to receive money (empty list = none), lower-cased, at most 3, each the stretch of the text from the
    PIN request to the receive cue (or the cue to the request), so the Report can quote and underline it."""
    hits = []
    for rx in (_PIN_FIRST, _PIN_LAST):
        for m in rx.finditer(text):
            if _negated(text, m):
                continue
            lo, hi = _near(text, m.start(), m.end())
            cues = [c for c in _RECEIVE.finditer(text, lo, hi) if c.end() <= hi]
            if not cues:
                continue
            c = min(cues, key=lambda c: max(c.start() - m.end(), m.start() - c.end(), 0))   # the cue nearest to the request: the shortest quote
            ph = text[min(m.start(), c.start()):max(m.end(), c.end())].strip().lower()
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
