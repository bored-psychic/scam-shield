import re
from shield.messages.rules import _negated_before
from shield.messages.tactics import tactic_matches

# ---------------------------------------------------------------- fear-cue families (decision D22, tightening B, 2026-10-18)
# Four families of pressure a scam uses and a genuine offer does not: a legal / arrest threat, secrecy, a cut-off / block threat, an investment or
# earning promise. They are hard-risk signals for the sender rule only (shield.core.sender_rule): a message carrying one is never softened by a
# registered sender ID. They do NOT change a verdict and are not tactic tags, so a message checked without a sender gets exactly the Report it got
# before. Run on the PII-masked text, as the tactics are.
#
# Negation: every match goes through rules._negated_before(), the same 'no need to' / three-word / comma-aside tests as the OTP rule ("You will not
# be arrested", "There is no need to keep this confidential" stay quiet). The 'inside the match' test of rules._negated() is NOT used: a secrecy cue
# carries its own negation ("do not tell anyone"), and the KYC cue's "not updated" is the threat, not a negation of it.
#
# Promotional wording is never a cue: offer, cashback, coupon, free, claim now, T&C, "limited period" are in no pattern below, a bare "secret"
# ("secret sale") and the WhatsApp / Telegram cues of the isolation tactic ("join our WhatsApp channel") are left out of secrecy, and a cut-off
# threat needs a service it threatens (account, SIM, card, connection ...). tests/test_sender.py F3 runs promotional texts through all four.

# legal / arrest threat. Reused: the isolation tactic's "digital arrest" and "national security"; the authority tactic's law-enforcement words as the
# agencies. New: the threat itself. A bare agency name never counts ("Report fraud to the cyber crime police at 1930" is advice): it has to come with
# a threat word in the same sentence. ED is matched only in capitals (as an agency it is always written so).
# "avoid" is in the shared negation list (it negates a request: "avoid sharing your OTP"), but in "to avoid legal consequences" it is part of the threat,
# so the avoid-forms are matched whole and the negation test then looks only at what comes before "avoid".
_LEGAL_CORE = re.compile(
    r"\bavoid\s+(?:being\s+)?(?:arrest(?:ed)?|legal (?:action|proceedings?|consequences?|trouble)|(?:a\s+)?(?:court case|fir|case))\b|"
    r"\bdigital arrest\b|\barrest(?:ed|ing)?\b|\b(?:arrest |non[- ]bailable )?warrants?\b|\bfir\b|\blegal (?:action|proceedings?|notice|consequences?|trouble)\b|"
    r"\bcourt (?:notice|summons?|case|order|hearing)\b|\bsummons\b|\bcase (?:has been |is |was |will be )?(?:registered|filed|booked|lodged)\b|"
    r"\bmoney laundering\b|\bnational security\b", re.I)
_AGENCY = re.compile(r"\b(?:police|cbi|ncb|enforcement directorate|narcotics|customs|cyber ?crime|crime branch|court|magistrate|interpol)\b", re.I)
_AGENCY_ED = re.compile(r"\bED\b")
_AGENCY_THREAT = re.compile(r"\b(?:seiz\w*|confiscat\w*|intercept\w*|complaint (?:against|registered|filed)|investigation|illegal|drugs?|contraband)\b", re.I)
_PARCEL = re.compile(r"\b(?:parcel|package|courier|shipment|consignment)\b", re.I)

# secrecy. Reused, unchanged: the isolation tactic (tactics.TACTICS["isolation"] + tactics._SECRECY) through tactics.tactic_matches(), so it keeps that
# tag's own exemptions (an OTP advisory's "Do not share it with anyone"; "delete this message" in an email disclaimer). Left out: the WhatsApp /
# Telegram cues, which genuine brands use ("join our WhatsApp channel"), a bare "secret(ly)" ("secret sale"), and "digital arrest" / "national
# security", which are legal threats above.
_NOT_SECRECY = re.compile(r"whatsapp|telegram|\bsignal\b|digital arrest|national security|^secret(?:ly)?$", re.I)

# cut-off / block threat. Adapted from the urgency tactic's "(will|be|get) (be) blocked / suspended / deactivated / disconnected ..." and
# "avoid (penalty|disconnection|suspension)": a threat about to happen ("will be blocked", "is being blocked"), and it must name the service threatened,
# within the same sentence and 80 characters before it. A block that has already happened ("has been blocked", "has now been put on hold") is a genuine
# alert just as often (a card blocked after three wrong PINs), so it counts only when the message also demands an update / verification / KYC / PAN /
# a click to undo it ("To unblock, call 1800 ..." does not). Plus "... will result in account suspension" and a KYC expiry with a deadline anywhere in
# the message. New: the service list, the after-the-fact rule, the 'result in' form and the KYC rule. "cancelled" was dropped from the verbs (orders
# and bookings get cancelled).
_CUT_VERBS = r"(?:blocked|suspended|deactivated|disconnected|terminated|frozen|locked|barred|cut off|cut|discontinued|closed|put on hold)"
_CUT_CORE = re.compile(
    rf"\b(?:(?:will|shall|would|may|is going to|are going to|going to|about to)\s+(?:be|get)|(?:is|are)\s+being)\s+(?:permanently\s+|temporarily\s+)?{_CUT_VERBS}\b", re.I)
_CUT_DONE = re.compile(rf"\b(?:has|have)\s+(?:now\s+)?been\s+(?:permanently\s+|temporarily\s+)?{_CUT_VERBS}\b", re.I)
_UNDO_DEMAND = re.compile(r"\b(?:update\w*|verify|verification|re-?kyc|kyc|pan|click|restore access|re-?activate)\b", re.I)
_CUT_OF = re.compile(r"\b(?:disconnection|suspension|deactivation|termination|blocking|closure)\s+of\s+(?:your\s+)?"
                     r"(?:account|a/c|sim|card|connection|electricity|power|services?|number|mobile|wallet|upi|bank account|net ?banking)\b|"
                     r"\b(?:result(?:s|ing)? in|lead(?:s|ing)? to)\s+(?:the\s+)?(?:permanent\s+)?(?:(?:account|sim|card|service|number|connection)\s+)?"
                     r"(?:suspension|deactivation|disconnection|blocking|termination|closure)\b|"
                     r"\bavoid\s+(?:penalty|disconnection|suspension|deactivation|blocking)\b", re.I)
_SERVICE = re.compile(r"\b(?:account|a/c|sim|card|connection|electricity|power|light|services?|number|mobile|wallet|upi|kyc|pan|aadhaa?r|"
                      r"net ?banking|internet|broadband|gas|meter|line|id)\b", re.I)
_KYC = re.compile(r"\bkyc\b[^.!?\n]{0,50}?\b(?:expir\w*|pending|incomplete|not (?:been )?(?:updated|completed|verified|done)|suspend\w*|block\w*)\b|"
                  r"\b(?:expir\w*|pending|incomplete)\b[^.!?\n]{0,20}?\bkyc\b", re.I)
_DEADLINE = re.compile(r"\b(?:today|tonight|immediately|asap|within\s+\d+\s*(?:hours?|hrs?|days?|mins?|minutes?)|\d+\s*(?:hours?|hrs?)\b|"
                       r"before\s+(?:\d|midnight|tomorrow)|by\s+(?:\d|tomorrow|tonight|midnight))", re.I)

# investment / earning promise. All new: no tactic covers it. Guaranteed or fixed-rate returns, doubling money, a stock / trading tips group, task-based
# earning (a "VIP task", pay per like / review / video), work from home or a part-time job with earnings, a stated daily or hourly income.
_EARN = re.compile(
    r"\bguaranteed\s+(?:\d+(?:\.\d+)?\s*%\s+)?(?:returns?|profits?|income|earnings?|payouts?)\b|"
    r"\b\d+(?:\.\d+)?\s*%\s+(?:returns?|profits?)\s+(?:every|per|a|each)\s+(?:day|week|month)\b|"
    r"\b(?:double|triple)\s+your\s+(?:money|investment|amount|deposit|capital)\b|"
    r"\b(?:stock|share|trading|crypto|forex|ipo|intraday)\s+(?:market\s+)?(?:tips?|signals?|calls?)\b[^.!?\n]{0,30}?\b(?:group|channel|community)\b|"
    r"\btask[- ]based\b|\bvip\s+tasks?\b|\b(?:simple|daily|easy|online)\s+tasks?\b[^.!?\n]{0,40}?\b(?:earn\w*|income|paid|commission)\b|"
    r"\bearn\w*\b[^.!?\n]{0,40}?\bper\s+(?:task|like|review|rating|video|post)\b|"
    r"\b(?:lik(?:e|ing)|subscrib(?:e|ing)|rat(?:e|ing)|review(?:ing)?)\s+(?:\w+\s+){0,2}(?:videos?|posts?|hotels?|products?|channels?|reels?)\b"
    r"[^.!?\n]{0,40}?\b(?:earn\w*|income|commission|paid)\b|"
    r"\bearn\w*\b[^.!?\n]{0,50}?\b(?:lik(?:e|ing)|subscrib(?:e|ing)|rat(?:e|ing))\s+(?:\w+\s+){0,2}(?:videos?|posts?|hotels?|products?|channels?|reels?)\b|"
    r"\b(?:work|jobs?)\s+from\s+home\b[^.!?\n]{0,60}?\b(?:earn\w*|income|salary)\b|\bearn\w*\b[^.!?\n]{0,60}?\b(?:work|jobs?)\s+from\s+home\b|"
    r"\bpart[- ]time\s+(?:job|work)\b[^.!?\n]{0,60}?\b(?:earn\w*|income|salary|per\s+day|daily)\b|"
    r"\bearn\w*\s+(?:up\s+to\s+)?(?:rs\.?\s?|inr\s?|₹\s?)\d[\d,]*(?:\.\d+)?\s*(?:/-)?\s*(?:per|a|every|/)\s*(?:day|hour|hr)\b", re.I)

FAMILIES = ("legal_threat", "secrecy", "cutoff_threat", "earning_promise")
_SENTENCE_END = re.compile(r"[.!?]+(?=\s|$)|\n")


def _sentence(text, start, end):
    """(lo, hi) of the sentence around text[start:end]."""
    lo = max((m.end() for m in _SENTENCE_END.finditer(text, 0, start)), default=0)
    m = _SENTENCE_END.search(text, end)
    return lo, (m.start() if m else len(text))

def _legal(text):
    out = [m for m in _LEGAL_CORE.finditer(text)]
    for m in _AGENCY_THREAT.finditer(text):   # a threat word counts only with an agency (or, for a seizure, a parcel) in the same sentence
        lo, hi = _sentence(text, m.start(), m.end())
        s = text[lo:hi]
        if _AGENCY.search(s) or _AGENCY_ED.search(s) or (re.match(r"(?i)seiz|confiscat|intercept", m.group(0)) and _PARCEL.search(s)):
            out.append(m)
    return out

def _secrecy(text, cred_hits):
    return [m for m in tactic_matches(text, "isolation", cred_hits) if not _NOT_SECRECY.search(m.group(0).strip())]

def _cutoff(text):
    out = list(_CUT_OF.finditer(text))
    undo = bool(_UNDO_DEMAND.search(text))
    for rx, needs_undo in ((_CUT_CORE, False), (_CUT_DONE, True)):
        for m in rx.finditer(text):   # the threatened service must be named in the same sentence, at most 80 characters before the threat
            lo, _ = _sentence(text, m.start(), m.end())
            if _SERVICE.search(text, max(lo, m.start() - 80), m.start()) and (undo or not needs_undo):
                out.append(m)
    if _DEADLINE.search(text):
        out += list(_KYC.finditer(text))
    return out

def fear_cues(masked_text, cred_hits=()):
    """family -> the matched phrases (lower-cased, at most 3, in order of appearance; [] = family absent), on PII-masked text. cred_hits: the
    message's cred_requests() hits, which the secrecy family needs for the isolation tactic's OTP-advisory exemption."""
    found = {"legal_threat": _legal(masked_text), "secrecy": _secrecy(masked_text, cred_hits), "cutoff_threat": _cutoff(masked_text),
             "earning_promise": list(_EARN.finditer(masked_text))}
    out = {}
    for fam in FAMILIES:
        kept = sorted((m for m in found[fam] if not _negated_before(masked_text, m.start())), key=lambda m: m.start())
        out[fam] = list(dict.fromkeys(m.group(0).strip().lower() for m in kept))[:3]
    return out
