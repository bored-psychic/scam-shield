from shield.contracts import Level

# What to do next, per verdict level: the one place for this wording (the frontend shows Report.advice and owns no "what to do" copy).
# Plain, calm, no jargon. A level with no warning still gets the OTP reminder: it only means nothing strong was found.
ADVICE: dict[Level, list[str]] = {
    Level.LIKELY_SCAM: ["Don't reply, click the link or call back.",
                        "Never share an OTP, PIN or CVV. No bank, police or company will ask for it.",
                        "If you paid or shared details, use Get help below.",
                        "Report it at cybercrime.gov.in."],
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

MAX_ADVICE = 5
assert set(ADVICE) == set(Level), "every Level needs advice"
assert all(1 <= len(v) <= MAX_ADVICE - 1 for v in ADVICE.values()), f"advice is at most {MAX_ADVICE} items, one of them the gambling line"


def advice_for(level: Level, category: str | None) -> list[str]:
    """A fresh list: ADVICE[level], with GAMBLING_ADVICE in front when category == "gambling"."""
    out = ([GAMBLING_ADVICE] if category == "gambling" else []) + ADVICE[level]
    assert 1 <= len(out) <= MAX_ADVICE
    return out
