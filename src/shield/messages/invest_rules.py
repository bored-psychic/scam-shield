"""Investment / trading / task-scam rules A1-A12 (Phase A of docs/plans/investment_scams.md, audit 2026-10-24).

Raise-only: a hit never lowers a level, and none of them reads a model score. They run on the RAW message (before PII masking: A1 needs the real UPI
id, and `pii.mask_text` turns `abc.brk@validhdfc` into `<UPI_ID>`), in shield.core.router.analyse().

  floor 1 (hook rules: raise to Suspicious, never to Likely scam on their own)   A2 A3 A5 A6 A7 A9 A10 A11
  floor 2 (money rules: the message asks for money or a deposit; Likely scam)     A1 A4 A8 A12

Why these rules exist: on the probe set (data/probe/investment_v1.csv) MuRIL caught the payment step of these scams and missed the hook (a VIP / IPO /
tips group that asks for nothing yet). The regexes began as the ones in src/audit_investment.py; after the first run on the whole val split (every
source, 5,267 rows) several were tightened (guards below), each time to remove a genuine val hit or a clear false-fire pattern. The numbers, the probe
results (an upper bound: the rules were written after reading the probe) and the val fire counts are in reports/investment_rules_v1.md.

Every title is one plain sentence, shown to the user as the reason (Report.reasons); the Hindi and Kannada versions are in
frontend/src/lib/investment.ts (needs-review, like the helpline strings). Changing a title here means changing it there, tests/test_invest_rules.py
and frontend/src/lib/investment.test.ts check that they agree.
"""
import re

F = re.I

# What counts as an investment context (A1, A9). Narrow on purpose: 'group', 'fund' and 'profit' alone are in many genuine messages.
_INVEST = (r"(?:trad(?:e|es|ing|er|ers)|stocks?|shares\b|share (?:market|price|tips?)|ipos?|invest\w*|demat|brokers?|broking|nifty|sensex|sebi|mutual funds?|"
           r"returns?|portfolio|securities|signals?|tips|vip|forex|crypto\w*|bitcoin|usdt)")
_PAY_VERB = r"(?:pay|send|transfer|deposit|remit|add funds|invest|recharge)\w*"

# A warning sentence ("NSE cautions investors not to ... assured or guaranteed returns", "Deal only with SEBI registered intermediaries") quotes the scam's
# words in order to warn against them. A scammer can paste such a sentence, so this only silences the two hook rules that quote (A2, A3), and only for
# the sentence it is in; the money rules ignore it.
_WARN = re.compile(r"\b(?:caution\w*|beware|warn\w*|prohibited|illegal|unlawful|no one can|nobody can|cannot promise|can't promise|never promise|"
                   r"do not (?:subscribe|invest|trust|believe|fall|pay|share|deal)|not to (?:subscribe|invest|trust|believe)|"
                   r"(?:deal|invest|trade|transact)\w* (?:only )?(?:with|through)|check (?:if|whether|that)|verify|ensure)\b", F)
_NEG = re.compile(r"\b(?:no|not|never|nobody|cannot|can't|don't|do not|without|nor|neither)\b[\w\s'-]{0,24}$", F)   # directly in front, same clause (no comma between)


def _sentence(text, start, end):
    lo = max(text.rfind(c, 0, start) for c in ".!?\n") + 1
    hi = min([i for i in (text.find(c, end) for c in ".!?\n") if i >= 0], default=len(text))
    return text[lo:hi]


def _warned(text, m):
    return bool(_WARN.search(_sentence(text, m.start(), m.end())))


def _negated_at(text, pos):
    return bool(_NEG.search(text[max(0, pos - 40):pos]))


def _negated(text, m):
    return _negated_at(text, m.start())


def _first(rx, text, ok=None):
    """The first match of rx in text for which ok(match) is true (or any), or None."""
    for m in rx.finditer(text):
        if ok is None or ok(m):
            return m
    return None


# ---------------------------------------------------------------- the rules: text -> a match (with .start() / .end()) or None
_UPI_ID = re.compile(r"(?<![\w./:@-])[\w.-]{2,}@(?!valid)[a-z][a-z0-9]+\b(?![.\w-]*\.[a-z])", F)   # name@handle: no dot after (an e-mail), no URL userinfo
_INVEST_CTX = re.compile(rf"\b{_INVEST}\b", F)
_PAY_CTX = re.compile(rf"\b{_PAY_VERB}\b", F)

def a1_non_valid_upi(t):
    """Money to a UPI id that is not @valid, in an investment message. SEBI's @valid ids (name.brk@validhdfc) are exempt; so is a message with no ask."""
    m = _first(_UPI_ID, t)
    return m if m and _INVEST_CTX.search(t) and _PAY_CTX.search(t) else None


_SEBI_CLAIM = re.compile(r"\bsebi[- ]?(?:registered|certified|approved|regd|licen[sc]ed)\b|\b(?:registered|certified|authori[sz]ed) (?:with|by) sebi\b|"
                         r"\bsebi (?:registration|certificate)\b", F)
_SEBI_NUMBER = re.compile(r"\bIN[AHZPMB]\d{9}\b|\bIN-DP-\d+", re.I)

def a2_sebi_claim_no_number(t):
    """'SEBI registered / certified' with no registration number anywhere in the message, outside a warning sentence."""
    return None if _SEBI_NUMBER.search(t) else _first(_SEBI_CLAIM, t, lambda m: not _warned(t, m))


_GUARANTEE = re.compile(
    r"\b(?:guarantee\w*|assured|sure[- ]?shot|pakka|zero risk|no risk|100% (?:safe|guaranteed))\b(?:[\s,'%-]+\w+){0,4}?[\s,'%-]+(?:returns?|profits?|income|payouts?|allotment|target)\b"   # one sentence
    r"|\b(?:returns?|profits?|income|target)\b(?:[\s,'%-]+\w+){0,3}?[\s,'%-]+(?:guaranteed|assured|pakka)\b"
    r"|\bfixed (?:monthly |daily |weekly )(?:returns?|profits?|payouts?)\b"                                      # 'fixed income' (a bond term) and 'a fixed price' are not promises
    r"|\b(?:earn|get|receive|promis\w*|offer\w*)\W+(?:\w+\W+){0,2}fixed (?:returns?|profits?|payouts?)\b", F)

def a3_guaranteed_returns(t):
    """Guaranteed / assured / fixed / sure-shot returns, unless negated in front ('not a guaranteed return') or in a warning sentence."""
    return _first(_GUARANTEE, t, lambda m: not _negated(t, m) and not _warned(t, m))


_WITHDRAW = r"(?:withdraw\w*|release[d]?|unfreeze|unlock\w*|unblock\w*|receive (?:your )?(?:funds|money|profits?)|get (?:your )?(?:funds|money|profits?))"
_PAY_NOUN = r"(?:fees?|tax(?:es)?|charges?|penalty|commission|clearance|deposit|amount|money|\d+\s?%)"
_PAY_V = re.compile(r"\b(?:pay|deposit)\b", F)
_A4 = [re.compile(p, F) for p in (
    rf"\b(?:pay|deposit)\b[^.!?]{{0,80}}\b(?:to|before|for|and then|so that|in order to)\b[^.!?]{{0,30}}\b{_WITHDRAW}\b",   # pay X to withdraw / pay them to release your withdrawal
    rf"\b{_WITHDRAW}\b[^.!?]{{0,80}}\b(?:must|need(?:s)? to|have to|required to|first|only after)\b[^.!?]{{0,40}}\b(?:pay|deposit)\b",   # to withdraw you must first pay
    rf"\b{_WITHDRAW}\b[^.!?]{{0,80}}\b(?:by|after|once|upon) (?:you )?(?:pay|paying|deposit|depositing)\b",   # withdraw later by paying 15% tax
    rf"\b{_PAY_NOUN}\b[^.!?]{{0,30}}\b(?:must|need to|have to|should) be (?:paid|deposited|cleared)\b[^.!?]{{0,40}}\b(?:unfreeze|release|withdraw\w*|unlock)\b",   # fees must be paid to unfreeze
    rf"\b(?:unlock|unfreeze|release|unblock)\w*\b[^.!?]{{0,60}}[,;]?\s*(?:please\s+|kindly\s+)?(?:deposit|pay)\b",   # to unlock your earnings, please deposit 30%
    rf"\b(?:funds?|account|money|profits?|balance|earnings|withdrawal)\b[^.!?]{{0,40}}\b(?:frozen|locked|on hold|blocked)\b[^.!?]{{0,120}}\b(?:pay|deposit|fees?|tax|charges?|clearance)\b",   # funds frozen ... pay the charges
)]

def a4_pay_to_withdraw(t):
    """A fee, tax or deposit demanded before money can be withdrawn, released or unfrozen. A negated pay verb ('do not pay') does not count."""
    def asked(m):
        v = _PAY_V.search(t, m.start(), m.end())
        return not _negated_at(t, v.start() if v else m.start())
    for rx in _A4:
        m = _first(rx, t, asked)
        if m:
            return m
    return None


_GROUP = re.compile(r"\b(?:join|joining|add(?:ed)?|upgraded?|welcome)\b[^.!?]{0,50}\b(?:(?:trading|stock|share|investment|investors?|tips?|signals?|research|intraday|ipo|forex|crypto\w*)\s+"
                    r"(?:group|channel|club|academy|community)|(?:telegram|whatsapp)\s+(?:group|channel))\b"
                    r"|\b(?:join|joining|upgraded?)\b[^.!?]{0,50}\b(?:vip|premium)\b", F)   # a bare 'VIP' needs join / upgrade: 'welcome letter to VIP' is a job post
_TIPS_CTX = re.compile(r"\b(?:stocks?|signals?|tips?|trad\w*|ipo|returns?|profit|nifty|invest\w*)\b", F)

def a5_vip_group(t):
    """An invitation to join (or an upgrade to) a VIP / tips group, channel or club, in an investment message."""
    m = _first(_GROUP, t)
    return m if m and _TIPS_CTX.search(t) else None


_LOGIN = re.compile(r"\bshare (?:your )?(?:login|password|user ?id|credentials)\b|\bhandle (?:your )?(?:trading )?account\b|\baccount handling\b", F)

_TRADING = re.compile(r"\b(?:trad\w*|stocks?|nifty|intraday|demat|invest\w*|returns?)\b", F)

def a6_credentials_or_handling(t):
    """Asking for a trading login, or offering to run the account ('account handling' is also a job-posting phrase: it needs a trading word nearby).
    'Never share your login' is a warning, not a request."""
    return _first(_LOGIN, t, lambda m: not _negated(t, m) and not _warned(t, m) and (m.group(0)[:5].lower() != "accou" or _TRADING.search(t)))


_TASK_PAY = re.compile(r"(?:\b(?:rs\.?|inr|rupees)|₹)\s?\d[\d,]*(?:\s?-\s?\d[\d,]*)?\+?\s*(?:/-)?\s*(?:daily|per day|a day|every day|roz)\b"
                       r"|\b\d[\d,]*(?:\s?-\s?\d[\d,]*)?\+?\s*(?:rs|rupees|€|usdt)\s*(?:/-)?\s*(?:daily|per day|a day|every day|roz)\b"
                       r"|\b(?:daily|roz) (?:rs\.?|₹)\s?\d", F)   # a currency marker: a bare '800 per day' or a date '2010, Daily' in a job post is not a promise
_TASK_WORDS = re.compile(r"\b(?:part[- ]?time|tasks?|likes?|rating|reviews?|videos?|subscribe|ghar baithe|work from home|kamai)\b", F)

def a7_task_pay(t):
    """A daily amount promised for part-time work, ratings, likes or videos."""
    m = _first(_TASK_PAY, t)
    return m if m and m.group(0).strip() and _TASK_WORDS.search(t) else None


_A8 = [re.compile(p, F) for p in (
    r"\bprepaid\s+tasks?\b|\btask\s+deposit\b|\btasks?\s+amount\b",
    r"\b(?:tasks?|vip|tier|level)\b[^.!?]{0,40}\b(?:needs?|requires?|must have|prepaid)\b[^.!?]{0,40}(?:\brs\.?|₹|usdt)",
    r"\b(?:deposit|pay|keep)\b[^.!?]{0,50}\b(?:to|for)\s+(?:unlock|access|start|activate|complete|continue)\w*[^.!?]{0,40}\b(?:tasks?|vip|tier|level|orders?)\b",
    r"\b(?:deposit|pay)\b[^.!?]{0,40}\b(?:for|to)\b[^.!?]{0,20}\btasks?\b",
    r"\bgrab\s+orders?\b[^.!?]{0,80}\b(?:deposit|pay|keep|maintain)\b",
    r"\b(?:higher|next|upper) (?:level|tier)\b[^.!?]{0,30}\b(?:prepaid|pay|deposit)\b",
)]

def a8_prepaid_task(t):
    """A deposit demanded for a task, a tier or a level."""
    for rx in _A8:
        m = _first(rx, t)
        if m:
            return m
    return None


_APP = re.compile(r"\.apk\b|\b(?:download|install)\w*\s+(?:our|the|this)\s+[\w ]{0,20}app\b", F)
_APP_OK = re.compile(r"official (?:broker )?app|we never ask you to install", F)

def a9_install_app(t):
    """Install an app (an .apk or 'download our ... app') next to an investment word (within 150 characters); 'use the official app' is the genuine form."""
    m = _first(_APP, t, lambda m: _INVEST_CTX.search(t[max(0, m.start() - 150):m.end() + 150]))
    return m if m and not _APP_OK.search(t) else None


_IPO = re.compile(r"\bpre-?allot\w*|\binstitutional (?:trading )?account\b|\bfii channel\b|\b(?:allotment|allocation) is guaranteed\b|"
                  r"\bpriority allotment\b|\bvip allocation\b|"
                  r"\b(?:buy|discount|members?|vip|join|apply|subscribe)\b[^.!?]{0,60}\bblock (?:trades?|deals?)\b|"   # 'block trade' is also market news: it needs an offer around it
                  r"\bblock (?:trades?|deals?)\b[^.!?]{0,80}\b(?:buy|discount|members?|vip|join|apply|subscribe)\b", F)

def a10_ipo_allotment(t):
    """IPO pre-allotment, an institutional account, block trades or an FII channel offered in a message."""
    return _first(_IPO, t)


_PERSON = r"(?:sitharaman|sudha murthy|murthy|ambani|ratan tata|finance minister)"
_SCHEME = r"(?:invest|scheme|earn|returns?|income|trading)"
_CELEB = re.compile(rf"\b{_PERSON}\b[^.!?]{{0,120}}\b{_SCHEME}\w*|\b{_SCHEME}\w*[^.!?]{{0,120}}\b{_PERSON}\b", F)

def a11_celebrity_scheme(t):
    """A minister's or celebrity's name next to an investment scheme."""
    return _first(_CELEB, t)


_CRYPTO = r"(?:usdt|crypto(?:currency|currencies)?|bitcoin|btc)"   # not 'cryptography'
_A12 = [re.compile(p, F) for p in (
    rf"\b(?:deposit|pay|send|transfer)(?:ing)?\b[^.!?]{{0,40}}\b{_CRYPTO}\b",
    rf"\b(?:usdt|bitcoin|btc)\b[^.!?]{{0,40}}\b(?:deposit|payment|to (?:start|unlock|withdraw|activate))\b",
    r"\bit takes \d[\d,]*\s*usdt\b",
    r"\bopen your (?:bitcoin|crypto\w*) (?:trading )?account\b",
)]

def a12_crypto_deposit(t):
    """Pay or deposit in crypto (USDT / Bitcoin) to start, unlock or earn."""
    for rx in _A12:
        m = _first(rx, t, lambda m: not _negated(t, m))
        if m:
            return m
    return None


# ---------------------------------------------------------------- the table
# (code, evidence id, rule function, floor level, radar tag (<= 24 characters), title shown to the user (<= 120 characters))
RULES = [
    ("A1", "rule.invest_upi", a1_non_valid_upi, 2, "Non-@valid UPI",
     "Asks for investment money to a UPI ID that is not a SEBI @valid ID."),
    ("A2", "rule.invest_sebi_claim", a2_sebi_claim_no_number, 1, "SEBI claim",
     "Claims to be SEBI registered but gives no registration number."),
    ("A3", "rule.invest_guaranteed", a3_guaranteed_returns, 1, "Guaranteed returns",
     "Promises guaranteed returns. No real investment can guarantee returns."),
    ("A4", "rule.invest_pay_to_withdraw", a4_pay_to_withdraw, 2, "Pay to withdraw",
     "Asks you to pay a fee or tax before you can withdraw your money."),
    ("A5", "rule.invest_vip_group", a5_vip_group, 1, "VIP tips group",
     "Invites you to a paid or VIP tips group."),
    ("A6", "rule.invest_credentials", a6_credentials_or_handling, 1, "Login sharing",
     "Asks for your trading login or offers to run your account."),
    ("A7", "rule.invest_task_pay", a7_task_pay, 1, "Task pay promise",
     "Promises daily pay for simple online tasks."),
    ("A8", "rule.invest_task_prepaid", a8_prepaid_task, 2, "Prepaid task",
     "Asks for a deposit to unlock tasks or higher levels."),
    ("A9", "rule.invest_app", a9_install_app, 1, "Install app",
     "Asks you to install a trading app from a link."),
    ("A10", "rule.invest_ipo_allotment", a10_ipo_allotment, 1, "IPO allotment",
     "Offers IPO pre-allotment or an institutional account through a group or app."),
    ("A11", "rule.invest_celebrity", a11_celebrity_scheme, 1, "Celebrity scheme",
     "Uses a minister's or celebrity's name to promote an investment."),
    ("A12", "rule.invest_crypto", a12_crypto_deposit, 2, "Crypto deposit",
     "Asks you to deposit or pay in crypto to earn or trade."),
]
BY_ID = {r[1]: r for r in RULES}
assert all(len(r[4]) <= 24 and len(r[5]) <= 120 for r in RULES), "tag <= 24 characters (contract), title <= 120"
assert len({r[0] for r in RULES}) == len({r[1] for r in RULES}) == 12

# The advice line added to What to do now whenever any of these rules fires (shield.core.advice). The frontend shows it as the "investment card" and
# has its Hindi and Kannada versions (frontend/src/lib/investment.ts), matched by this exact string.
SEBI_ADVICE = ("SEBI-registered brokers and advisers collect UPI payments only through IDs with the @valid handle (for example name.brk@validhdfc), "
               "and never promise guaranteed returns. Check any adviser at sebi.gov.in before paying.")


def invest_rule_hits(text):
    """The rules that fire on this raw text, in table order: [{"code", "id", "floor", "tag", "title", "quote", "span"}], quote = text[span[0]:span[1]]
    (code points), trimmed of surrounding spaces and punctuation so a span starts and ends on a word. Empty list = none."""
    out = []
    for code, id_, fn, floor, tag, title in RULES:
        m = fn(text)
        if not m:
            continue
        s, e = m.start(), m.end()
        while s < e and not (text[s].isalnum() or text[s] in "₹."):
            s += 1
        while e > s and not (text[e - 1].isalnum() or text[e - 1] in "/-"):
            e -= 1
        if s < e:
            out.append({"code": code, "id": id_, "floor": floor, "tag": tag, "title": title, "quote": text[s:e], "span": (s, e)})
    return out
