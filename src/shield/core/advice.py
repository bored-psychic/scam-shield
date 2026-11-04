from shield.contracts import InputKind, Level
from shield.messages.invest_rules import SEBI_ADVICE

# What to do next, per verdict level: the one place for this wording (the frontend shows Report.advice and owns no "what to do" copy).
# Plain, calm, no jargon. A level with no warning still gets the OTP reminder: it only means nothing strong was found.
ADVICE: dict[Level, list[str]] = {
    Level.LIKELY_SCAM: ["Don't reply, click the link or call back.",
                        "Never share an OTP, PIN or CVV. No bank, police or company will ask for it.",
                        "If you paid or shared details, call 1930 now."],
    Level.SUSPICIOUS: ["Don't click the link or share any code yet.",
                       "Contact the company through its official app or the number on your card, not the one in the message.",
                       "If you're unsure, ask someone you trust before acting."],
    Level.NO_WARNING_SIGNS: ["Still never share an OTP, PIN or CVV, even with senders that look genuine.",
                             "If something feels off later, check it again."],
    Level.CANT_JUDGE: ["Paste the whole message, including any link.",
                       "If you're unsure, verify with the sender through an official channel."],
    # D22: a registered promotional sender and no hard-risk signal. Genuine marketing is likely, not certain: the ID may be mistyped or misused.
    Level.PROMOTIONAL: ["This is likely genuine marketing from a registered business.",
                        "Only click the link if you expected this offer.",
                        "Never share an OTP or PIN, even with a registered sender."],
}
# Added as the FIRST item when the message links to a gambling or betting site (Report.category == "gambling").
GAMBLING_ADVICE = "Don't deposit money or share payment details with betting sites or apps promoted by message."

# Added right after the gambling line when any investment-scam rule (shield.messages.invest_rules) fired. Same wording as invest_rules.SEBI_ADVICE.
INVESTMENT_ADVICE = SEBI_ADVICE

# Per-input lines (docs/plans/multi_input.md 2.4, W1). The frontend shows the first line as a card and matches it by exact string, like the SEBI card, so
# these strings are the contract: change one and the card copy in the frontend moves with it. Only EMAIL_ADVICE is reachable in W1 (/api/check kind
# "email"); the payment and app lines are used by the engines of W3 / W6, and advice_for() already knows where they go.
PAYMENT_ADVICE = "Before you pay, check the registered name your payment app shows. Receiving money never needs your UPI PIN, a QR scan or an approved request."
PAYMENT_PROOF_ADVICE = ["A screenshot cannot prove a payment. Check your own bank or UPI app before you hand over anything.",
                        "Do not send back 'extra' money someone says they sent. Ask your bank instead."]
APP_ADVICE = "Install apps only from the Play Store, and check the publisher's name before you install."
APP_WARNING_ADVICE = "Do not install this file. If you already did, disconnect from the internet, uninstall it and call your bank and 1930."
EMAIL_ADVICE = "Do not open attachments or links you were not expecting. Contact the company through its official website or app."
PAYMENT_INPUTS = ("upi_id", "payment_request", "qr")
APP_INPUTS = ("app", "apk")

MAX_ADVICE = 5
assert set(ADVICE) == set(Level), "every Level needs advice"
assert all(1 <= len(v) <= MAX_ADVICE - 1 for v in ADVICE.values()), f"advice is at most {MAX_ADVICE} items, one of them the gambling line"


def advice_for(level: Level, category: str | None, investment: bool = False, input: InputKind | None = None) -> list[str]:
    """A fresh list: ADVICE[level], with GAMBLING_ADVICE in front when category == "gambling", and INVESTMENT_ADVICE after it when an investment rule fired
    (investment is only ever true on a Suspicious or Likely scam level: the rules raise to at least Suspicious).
    input (W1): None, "message" and "link" give exactly the list above (byte-identical to before schema 6). The other kinds put their own line(s) after those
    and before ADVICE[level]: payments (upi_id, payment_request, qr) PAYMENT_ADVICE at every level; apps APP_ADVICE at every level, then APP_WARNING_ADVICE on a
    warning; email EMAIL_ADVICE on a warning; payment_proof is the fixed answer PAYMENT_PROOF_ADVICE and nothing else. The list is cut at MAX_ADVICE from the
    end, so the level's own last line gives way before a specific one does."""
    flagged = level in (Level.SUSPICIOUS, Level.LIKELY_SCAM)
    if input == "payment_proof":
        return list(PAYMENT_PROOF_ADVICE)
    own = []
    if input in PAYMENT_INPUTS:
        own = [PAYMENT_ADVICE]
    elif input in APP_INPUTS:
        own = [APP_ADVICE] + ([APP_WARNING_ADVICE] if flagged else [])
    elif input == "email" and flagged:
        own = [EMAIL_ADVICE]
    out = ([GAMBLING_ADVICE] if category == "gambling" else []) + ([INVESTMENT_ADVICE] if investment else []) + own + ADVICE[level]
    out = out[:MAX_ADVICE]
    assert 1 <= len(out) <= MAX_ADVICE
    return out
