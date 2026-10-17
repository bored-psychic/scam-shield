import re
from dataclasses import dataclass

# ---------------------------------------------------------------- the sender the user typed (decision D22, docs/decisions/README.md)
# What the user's phone showed as the sender, classified as a string. Nothing is looked up, logged or stored: like the message text, the raw value
# lives only in memory for the length of one analysis, and only kind / prefix / header / suffix leave this function (a mobile number never does).
#
#   dlt       a TRAI DLT business header: 2-letter operator + circle prefix, a 6-character header, and since the TCCCPR 2025 amendment
#             (on phones from 6 May 2025) a type suffix: P promotional, S service, T transactional, G government. "JM-JIOCPN-P", "VM-HDFCBK-T";
#             the older form without a suffix ("AD-SBIINB") is dlt with suffix None. Case-insensitive.
#   dlt_bare  the 6-character header alone, as some Android phones show it ("JIOCPN", "HDFCBK"): registered business, type unknown.
#   mobile    an Indian mobile number: 10 digits starting 6-9, optionally behind +91 / 91 / 0, spaces or dashes allowed.
#   other     anything else that is not empty: a shortcode ("56767"), a name ("Jio", "Amazon"), an email, garbage, or more than 40 characters.
#   none      empty or only whitespace.
#
# The regexes, and why each is exactly this:
#   _DLT     [A-Z]{2} - [A-Z0-9]{6} ( - [PSTG] )?   on the upper-cased string. The prefix is always two letters; DLT headers are 6 characters
#            (letters for service / transactional, 6 digits for the older promotional headers, so digits are allowed here, where the prefix and
#            the dash already make the shape unambiguous); only the four TRAI suffix letters count, so "JM-JIOCPN-X" is other. A space either
#            side of a dash is tolerated because people retype what they see.
#   _BARE    [A-Z0-9]{6} with at least one letter, CASE-SENSITIVE (upper case only), no spaces or dashes. Phones print headers in capitals, while a
#            person typing a brand name types "Amazon" or "Jio", so case is what separates a header from a word: "Amazon" (6 letters) stays other.
#            At least one letter, because six bare digits are as likely a shortcode or an OTP as an old numeric header. Known overlap: a brand
#            typed in capitals ("AMAZON") counts as a bare header, which is also how a phone shows AX-AMAZON-S.
#   _MOBILE  (\+91|91|0)? [6-9][0-9]{9}   on the string with its spaces and dashes removed, so "+91 98765 43210", "09876543210" and
#            "98765-43210" all match; the 6-9 start is the Indian mobile range, which 5-digit shortcodes and 1800 numbers are not in.
# Before matching: strip; more than 40 characters is other; Unicode dashes become "-" and any run of whitespace one space; then anything that is
# still not ASCII is other (so a lookalike letter or a Devanagari digit never passes for a header or a number).
MAX_LEN = 40
_DLT = re.compile(r"([A-Z]{2}) ?- ?([A-Z0-9]{6})(?: ?- ?([PSTG]))?", re.ASCII)
_BARE = re.compile(r"(?=[0-9]*[A-Z])[A-Z0-9]{6}", re.ASCII)
_MOBILE = re.compile(r"(?:\+91|91|0)?[6-9][0-9]{9}", re.ASCII)
_DASHES = re.compile(r"[‐-―−]")   # hyphen, non-breaking hyphen, figure dash, en / em dash, horizontal bar, minus sign

SUFFIX_NAME = {"P": "promotional", "S": "service", "T": "transactional", "G": "government"}


@dataclass(frozen=True)
class SenderID:
    kind: str                  # "dlt" | "dlt_bare" | "mobile" | "other" | "none"
    prefix: str | None = None  # dlt only, upper case, e.g. "JM"
    header: str | None = None  # dlt / dlt_bare only, upper case, e.g. "JIOCPN": a business ID, not personal data
    suffix: str | None = None  # dlt only: "P" | "S" | "T" | "G", or None for the older format without one


def parse_sender(raw: str | None) -> SenderID:
    """Classify what the user typed as the sender. Pure: no I/O, and the raw string is not kept."""
    s = (raw or "").strip()
    if not s:
        return SenderID("none")
    if len(s) > MAX_LEN:
        return SenderID("other")
    s = re.sub(r"\s+", " ", _DASHES.sub("-", s))
    if not s.isascii():
        return SenderID("other")
    if m := _DLT.fullmatch(s.upper()):
        return SenderID("dlt", prefix=m[1], header=m[2], suffix=m[3])
    if _BARE.fullmatch(s):
        return SenderID("dlt_bare", header=s)
    if _MOBILE.fullmatch(s.replace(" ", "").replace("-", "")):
        return SenderID("mobile")
    return SenderID("other")
