from pii import mask_text
from shield.core.verdict import PROMOTIONAL
from shield.messages.sender import SenderID
from shield.messages.tactics import TACTICS
from shield.messages.threats import FAMILIES, fear_cues

# ---------------------------------------------------------------- the sender rule layer (decision D22, docs/decisions/README.md)
# Runs after everything else in router.analyse() (models, hard rules, gambling floor, safety-advice cap), on the sender the user typed; the models
# and their thresholds are untouched. A registered header is a strong hint, not proof (a registered ID can be misused, and the user may mistype
# it), so it only ever softens a message that shows none of the hard-risk signals below, and a personal mobile number never raises a level
# (that effect has not been measured). With no sender (None, "" or only spaces) analyse() returns exactly what it returned before D22.
#
#   sender                         | hard-risk signal | level                                           | reason added
#   dlt with suffix P              | none             | Promotional                                      | "Sent from a registered business ID (promotional)" (first)
#   dlt with S / T / G / no suffix | none             | capped at Suspicious (Likely scam -> Suspicious;  | "Sent from a registered business ID (...)"
#   dlt_bare (header alone)        |                  |  Suspicious, No warning signs, Can't judge stay) |
#   dlt or dlt_bare                | any              | unchanged                                        | "Registered sender, but <the risky thing>. Registered IDs can still be misused."
#   mobile                         | (not checked)    | unchanged                                        | "Sent from a personal mobile number; ..." only at Suspicious or Likely scam
#   other / none                   | (not checked)    | unchanged                                        | none

# Payment / fee DEMAND cues: the matches of the payment tactic (tactics.TACTICS["payment"], lower-cased as tactic_tags() returns them) that ask the
# reader to pay a fee, to move money outside a normal checkout, or to approve a UPI pull. The rest of that tactic (pay, payment, transfer, deposit,
# upi, gpay / phonepe / paytm / bhim, refund, cashback, recharge, (upi) pin, otp, cvv, card number, account number, ifsc, a masked UPI ID or account,
# an amount) is left out: genuine promotions and bank alerts mention them all the time (val, SMS-length rows: otp 45 benign / 0 scam, a masked
# account 8 / 53, pay 14 / 45, cashback 10 / 14; the demo bank alert g01 has a masked UPI ID and "otp"), and a mention is not a demand. Kept:
# processing fee 0 / 5, gift card 0 / 2, challan 5 / 7 (a fine to pay: genuine e-challan SMS get the misuse reason too, which is true of them).
# The whole tactic is searched again here, without tactic_tags()' cap of 4 cues per tag, so a demand cue listed fifth is not lost.
PAYMENT_DEMAND_CUES = frozenset({"processing fee", "registration fee", "customs duty", "challan", "penalty",
                                 "send money", "wire", "western union", "gift card", "bitcoin", "crypto", "usdt",
                                 "collect request", "approve request", "approve the request", "scan qr", "scan the qr"})

# The hard-risk signals, most severe first, each with what the misuse reason says the message does. All existing signals of analyse()'s result:
#   otp_request     r["cred_request"]      the OTP / PIN / CVV / password request rule (rules.cred_requests; plain passwords since 2026-10-18)
#   pin_to_receive  r["pin_to_receive"]    rule R2 (rules.pin_to_receive)
#   phishing_link   a link the URL model rates at its scam level: kind "model", base_level 2 (Likely scam, the model's threshold_high); since D23
#                   not a link with a positive background check (P1 / P2: its known owner overrides the model's guess from the host string)
#                   read from l["model_level"], the model's own level before the C2 cap (2026-10-23: the URL model alone now stops at Suspicious in the
#                   verdict), so a P-sender message with such a link is still not softened, as before C2
#   link_red_flag   D23: a link with a red flag R1-R9 (on a phishing list, Safe Browsing, look-alike letters, a brand lookalike name, a raw IP,
#                   a server shared with listed scam hosts, registered < 30 days ago, a first certificate < 7 days old)
#   lookalike_link  a free-hosted link with a brand or scam word in its name: kind "free", base_level 1 (platforms.assess_link). Free-hosted links
#                   never reach the URL model, so without this a phishing page on a free host could be softened; added beyond the D22 request
#   gambling        a G1 gambling match on any link (l["gambling"])
#   legal_threat, secrecy, cutoff_threat, earning_promise   the fear-cue families (shield.messages.threats; tightening B, 2026-10-18): a legal / arrest
#                   threat, secrecy, a cut-off / block threat, an investment or earning promise
#   payment_demand  a PAYMENT_DEMAND_CUES match in the masked text
RISKY_THING = {"otp_request": "it asks for your OTP, PIN, CVV or password",
               "pin_to_receive": "it asks for your UPI PIN to receive money",
               "phishing_link": "its link looks like a phishing link",
               "link_red_flag": "its link has a red flag (see the link panel)",
               "lookalike_link": "its link is a lookalike site on free hosting",
               "gambling": "it links to a gambling or betting site",
               "legal_threat": "it threatens arrest or legal action",
               "secrecy": "it tells you to keep it secret",
               "cutoff_threat": "it threatens to block or cut off a service",
               "earning_promise": "it promises guaranteed or easy earnings",
               "payment_demand": "it asks for a payment or fee",
               "investment_rule": "it matches an investment-scam pattern"}


def payment_demands(text):
    """The PAYMENT_DEMAND_CUES in text (masked as tactic_tags() reads it), in order of appearance, each once."""
    found = [m.group(0).strip().lower() for m in TACTICS["payment"].finditer(mask_text(text))]
    return list(dict.fromkeys(c for c in found if c in PAYMENT_DEMAND_CUES))


def hard_risks(text, r):
    """The hard-risk signals (RISKY_THING keys, most severe first) in analyse()'s result r for this text."""
    links, fear = r["links"], fear_cues(mask_text(text), r["cred_request"])
    return [key for key, hit in (
        ("otp_request", bool(r["cred_request"])),
        ("pin_to_receive", bool(r["pin_to_receive"])),
        ("phishing_link", any(l["kind"] == "model" and l.get("model_level", l["base_level"]) == 2 and l.get("positive") not in ("p1", "p2") for l in links)),
        ("link_red_flag", any(l.get("flags") for l in links)),
        ("lookalike_link", any(l["kind"] == "free" and l["base_level"] == 1 for l in links)),
        ("gambling", any(l["gambling"] for l in links)),
        *((fam, bool(fear[fam])) for fam in FAMILIES),
        ("payment_demand", bool(payment_demands(text))),
        ("investment_rule", bool(r.get("invest_rules")))) if hit]   # last: the investment rules (Phase A) are the least specific signal, so an existing signal stays the first one named


def apply_sender(r, sid: SenderID, text):
    """The D22 table above, on analyse()'s result r (changed in place and returned). Sets r["sender"]: None for kind "none", else
    {"id": sid, "rule": "promotional" | "registered" | "misuse" | "mobile" | None, "level_before": the level without the sender, "hard_risks": [...]}.
    The raw sender string is not stored: sid holds only kind, prefix, header and suffix (a mobile number is never kept)."""
    if sid.kind == "none":
        r["sender"] = None
        return r
    before, risks, rule = r["level"], [], None
    if sid.kind in ("dlt", "dlt_bare"):
        risks = hard_risks(text, r)
        if risks:
            rule = "misuse"                                   # no softening
        elif sid.kind == "dlt" and sid.suffix == "P":
            rule, r["level"] = "promotional", PROMOTIONAL
        else:
            rule = "registered"
            if before is not None and before > 1:             # cap at Suspicious; never lower than that
                r["level"] = 1
    elif sid.kind == "mobile" and before is not None and before >= 1:
        rule = "mobile"                                       # a reason only: unmeasured, so the level is not raised
    r["sender"] = {"id": sid, "rule": rule, "level_before": before, "hard_risks": risks}
    return r
