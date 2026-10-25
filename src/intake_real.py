"""Real-message intake -> data/real/real_test_v1.csv, a masked TEST-ONLY set (CLAUDE.md rule 12). No network.
Run on the Mac:

    .venv/bin/python src/intake_real.py                  # every file under data/real/raw/, recursively
    .venv/bin/python src/intake_real.py --freeze         # also writes the frozen hash into CLAUDE.md

Three kinds of input are read (folder names with spaces are fine; other file types are listed in the report and skipped):
  *.xml  SMS Backup & Restore export. Only <sms type="1"> (received) is read: body is the text; address becomes a sender_kind
         (dlt_header = an alphanumeric sender id like AX-HDFCBK, short_code, mobile_number, other) and is then discarded; date, contact
         name and every other attribute are never read into a row. The phone label (phone_1, phone_2, ...) comes from "phone_N" in the
         file name, else from the file's position in sorted order. <mms> elements are counted, not read.
  *.txt  WhatsApp chat export (Android and iOS line formats). Sender names and timestamps are dropped, system / media / deleted lines
         too, and only messages longer than 20 characters are kept. Each export is one source (wa_1, wa_2, ...).
  *.csv  The Google Form export: headers text (or message), label (scam / not_scam / unsure), language, source; collected_by, script,
         date_received, notes are dropped before anything else. unsure is excluded and counted. Older header sets still map by regex.
Then, for all of them: (1) PII masks (src/pii.py + card, OTP, account-tail patterns; every phone number and contact / sender name seen in
the input is masked wherever it appears and checked again in every output before it is written); (2) template groups: near-duplicates by
src/neardup.py on the masked text with digits collapsed (so OTPs and amounts with different digits fall into one group), group_id is a hash
of the group's smallest key, so it is the same on every run; (3) data/real/label_me.csv: one row per group that still has unlabelled
messages, biggest first, two examples (links defanged), blank label column (scam / genuine / skip). No model score is ever written there;
(4) a rerun reads your filled label_me.csv and gives every message of a group its label (labels you filled in are never overwritten);
(5) the test set keeps at most --cap (3) messages per group, exact duplicates once, and stores group_id and group_size so eval can report
per message and per group; (6) names are NOT masked automatically: rows with likely names go to data/real/review_names.csv, your edits
(replace_with "<NAME>" masks the token, "DROP" drops the row, "ok" marks a reviewed non-name) are applied on rerun; --freeze needs none left blank; (7) overlap: each kept row against the TRAIN split of
data/final/messages.csv with the same near-duplicate rule (overlap True/False, rows are never dropped for it).
Tripwire: realguard.py. The output's source_row_hash is the key training scripts refuse on. Report: reports/real_intake_v1.md (no text).
"""
import argparse, csv, datetime as dt, hashlib, io, re, sys, unicodedata
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]
import pandas as pd
import pii
import realguard
from audit_investment import CRYPTO_RX, INVEST_RX, TASK_RX
from neardup import CLUSTER_SEED, near_dup_pairs_any, shingle_sets
from textprep import _urls, model_text, replace_urls

RAW_DIR = ROOT / "data" / "real" / "raw"
OUT = ROOT / "data" / "real" / "real_test_v1.csv"
REVIEW = ROOT / "data" / "real" / "review_names.csv"
LABEL_ME = ROOT / "data" / "real" / "label_me.csv"
REPORT = ROOT / "reports" / "real_intake_v1.md"
MESSAGES = ROOT / "data" / "final" / "messages.csv"
CLAUDE = ROOT / "CLAUDE.md"
MIN_CHARS = 10          # SMS and Form rows
WA_MIN_CHARS = 20       # WhatsApp: kept only when LONGER than this
CAP = 3                 # messages kept per template group
OUT_COLS = ["id", "text", "label", "language", "category", "overlap", "source_row_hash", "source", "source_type", "sender_kind", "group_id", "group_size"]
LABEL_COLS = ["group_id", "size", "example_1", "example_2", "example_similarity", "sender_kind_mix", "sources", "label"]
SHEET_CHARS = 500
MAX_DF = 5              # a capitalised word in more than this many different message texts is a brand or a word, not a person: not a name candidate

# Form header rules. Known headers (normalised: lower case, _ and - read as spaces) map exactly; any other header goes through the older
# regex rules below, which stop on anything unexpected.
FORM_DROP = {"collected by", "script", "date received", "notes"}
FORM_ROLES = {"text": "text", "message": "text", "label": "label", "language": "language", "source": "source", "category": "category"}
DROP_RX = re.compile(r"timestamp|time stamp|^time$|e-?mail|name|contact|phone|mobile|whatsapp|username|user id|consent|address")
ROLE_RX = [
    ("category", re.compile(r"categor|type of scam|scam type|kind of scam")),
    ("language", re.compile(r"language")),
    ("label", re.compile(r"scam or genuine|genuine or scam|is (this|it) a scam|label|genuine|legit|scam\?")),
    ("text", re.compile(r"message|sms|text|paste|content")),
]
REQUIRED = ("text", "label", "language")
LANG = {"english": "en", "en": "en", "hindi": "hi", "hi": "hi", "kannada": "kn", "kn": "kn", "hinglish": "hinglish", "mixed": "mixed"}
UNSURE = ("unsure", "not sure", "unclear", "unknown")
FORM_SOURCES = {"sms", "whatsapp", "email", "call", "telegram", "instagram", "facebook", "x", "twitter", "web", "other"}   # anything else -> form_other

# capitalised words that are not names (sentence starts, brands, banks, money, common nouns). Used only to decide what goes to the review file.
COMMON = set("""Dear Your You Yours The This That These Please Click Call Dial Share Pay Paid Send Get Win Won Congratulations Congrats Offer Now Today
Use Visit Download Thank Thanks Hello Hi Hey Sir Madam Customer Customers Kindly Ensure Urgent Alert Notice Update Verify Login Free Prize Reward
Cashback Refund Tax Limited Ltd Pvt India Indian Government Police Court Income Department Team Support Helpline Official Website Link Account Bank
Card Credit Debit Balance Amount Rs INR Monday Tuesday Wednesday Thursday Friday Saturday Sunday January February March April May June July
August September October November December Click Here More Also Dont Don Do Not With For From Any All Your Our We Are Was Will Can Could Would
Should Have Has Had Please Note Warning Important Final Last Bonus Loan Job Work Order Delivery Parcel Package Courier Service Services Insurance
Policy Bill Payment Transfer Money Cash Gift Lottery Winner Winners Lucky Selected Account Blocked Suspended Expired Expiry Activate Activated
Kyc Aadhaar Aadhar Pan Mobile Number Otp Upi Sbi Hdfc Icici Axis Kotak Jio Airtel Vi Bsnl Amazon Flipkart Netflix Paytm Phonepe Gpay Google
Whatsapp Telegram Facebook Instagram Youtube Apple Microsoft Income Tax Epfo Uidai Irctc Fedex Dhl Bluedart Dtdc
Jan Feb Mar Apr Jun Jul Aug Sep Sept Oct Nov Dec Mon Tue Wed Thu Fri Sat Sun Namaste Namaskara Namaskar Dhanyavad""".split())
GREETING_RX = re.compile(r"(?i)\b(hi|hello|hey|dear|mr|mrs|ms|miss|shri|smt|sir|madam|mam|by|from|regards|thanks|thank you)\.?\s+$")
TOKEN_RX = re.compile(r"\b[A-Z][a-z]{2,}\b")
URL_RX = re.compile(r"https?://\S+|www\.\S+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|net|org|co|io|ly|me|info|xyz|top|site|online|link|store|app|gov|edu|bank|shop|live)\b(?:/\S*)?", re.I)
CARD_RX = re.compile(r"\b(?:\d{4}[ -]){3}\d{4}\b")
OTP_RX = re.compile(r"(?i)\b(otp|code|pin|password)\b(?:\W{0,3}\b(?:is|was|number|no|code)\b){0,2}\W{0,5}(\d{4,8})\b")
# the code before its keyword: "482913 is your OTP", "123456 is the verification code", "Use 5566 as your login code"
OTP_BEFORE_RX = re.compile(r"(?i)\b\d{4,8}\b(?=\s*(?:is|as|are|was)\s+(?:your|the|an?|ur|my)?\s*[^.\d]{0,30}?\b(?:otp|code|pin|passcode|password)\b)")
# any run of 9+ digits left after the other masks, glued to letters or inside a link included: the pii.py masks need word boundaries and stop at
# 18 digits, so a 21-digit transaction id and order / tracking ids like FMPIB1234567890 got through
LONG_RX = re.compile(r"\d{9,}")
# links are kept for the link checks, but a number inside one can be a person's: click-to-chat links (wa.me/91..., ?phone=91...) and any
# standalone Indian mobile number in a path or query (?id=98..., /bill-98...)
URL_PHONE_RX = re.compile(r"(?i)(wa\.me/|[?&]phone=)\+?\d{10,15}")
URL_MOBILE_RX = re.compile(r"(?<!\w)(?:\+?91)?[6-9]\d{9}(?!\w)")
# a word right after a greeting is usually the recipient's name, in any case ("Hey prajval", "Dear PRAJVAL"); an ALL-CAPS run after from / to / by is a
# UPI payer or payee
GREETING_NAME_RX = re.compile(r"(?i)\b(?:hey|hi|hello|dear|namaste|namaskara|mr|mrs|ms|miss|shri|smt)\b\.?,?\s+([a-z]{3,15})\b")
CAPS_NAME_RX = re.compile(r"\b(?i:from|to|by|paid to|sent to|received from|credited by|beneficiary|payee)\s+([A-Z]{3,}\.{0,2}(?:\s+[A-Z]{3,}\.{0,2}){0,2})(?![A-Za-z])")
NOT_NAMES = {w.lower() for w in COMMON} | set("""user valued there all team friend friends guest member applicant subscriber everyone folks sirji mam mama customer
passenger cardholder holder student parent donor investor policyholder beneficiary resident owner partner candidate aap aapka aapke hai ji sahab bhai didi
who you your are the and for with this that dost sahib""".split())
ACRONYMS = {"UPI", "SBI", "OTP", "ATM", "NEFT", "IMPS", "RTGS", "KYC", "PAN", "EMI", "IRCTC", "HDFC", "ICICI", "AXIS", "BANK", "NPCI", "LIC", "EPFO", "FASTAG", "AMAZON", "PAYTM"}
NAMES_FILE = ROOT / "data" / "real" / "mask_names.txt"
# the last digits of an account or card: "A/c XX1234", "card ending 4455", "a/c no. 12345", and a bare XX1234 / ****1234
ACCT_TAIL_RX = re.compile(r"(?i)\b((?:a/c|acct?|account|card)\b(?:\s+(?:no\.?|number|ending(?:\s+(?:with|in))?|last\s+\d\s+digits(?:\s+are)?))?[\s.:#*x-]{0,12}?)(\d{3,6})\b")
XX_TAIL_RX = re.compile(r"(?i)\b(?:x{2,}|\*{2,})\d{3,8}\b")
# pii.MASKS split by what they produce, not by position (the list gains entries): the address masks run first, the phone / account masks after the
# links are set aside
ADDRESS_MASKS = [m for m in pii.MASKS if m[1] in ("<EMAIL>", "<UPI_ID>")]
NUMBER_MASKS = [m for m in pii.MASKS if m[1] not in ("<EMAIL>", "<UPI_ID>")]
WA_MENTION_IOS_RX = re.compile("@⁨[^⁩\n]{0,80}⁩")
WA_MENTION_NUM_RX = re.compile(r"@\+?\d[\d ]{7,14}\d")
MARKS_RX = re.compile("[​-‏‪-‮⁦-⁩﻿]")

WA_HEAD = re.compile(
    "^[‎‏‪-‮]*\\[?(?P<date>\\d{1,4}[/.-]\\d{1,2}[/.-]\\d{1,4}),?\\s+"
    r"(?P<time>\d{1,2}[:.]\d{2}(?:[:.]\d{2})?(?:\s*[AaPp]\.?[Mm]\.?)?)(?:\]\s*|\s+-\s+)(?P<rest>.*)$")
WA_SENDER = re.compile(r"^(?P<sender>[^:]{1,100}?):\s(?P<body>.*)$")
WA_SKIP_RX = re.compile(r"(?i)^(?:<media omitted>|<attached:[^>]*>|(?:image|video|audio|sticker|gif|document|contact card|voice call|video call)(?: omitted)?|"
                        r"this message was deleted|you deleted this message|missed (?:voice|video) call.*|waiting for this message.*|null)$")
WA_NOTICE_RX = re.compile(r"(?i)^messages and calls are end-to-end encrypted")   # iOS puts the chat's name in front of this notice
WA_FILE_LINE = re.compile(r"(?i)^\S+ \(file attached\)$")
PHONE_LABEL = re.compile(r"(?i)(?<![a-z])phone[\s_-]*(\d+)(?!\d)")
WA_LABEL = re.compile(r"(?i)(?<![a-z])(?:wa|whatsapp)[\s_-]*(\d+)(?!\d)")
LABEL_WORDS = {"scam": "scam", "1": "scam", "yes": "scam", "genuine": "genuine", "not_scam": "genuine", "not scam": "genuine", "ham": "genuine", "legit": "genuine",
               "0": "genuine", "no": "genuine", "skip": "skip", "": None}


class Stop(SystemExit):
    pass


def stop(msg):
    raise Stop(f"STOP: {msg}")


# ---------------------------------------------------------------------------------------------------------------- what must not leak

class Sensitive:
    """Phone numbers and names seen in the input (SMS addresses and contact names of person-like senders, WhatsApp sender names and the
    names in chat file names). Held in memory only: used to mask them wherever they appear in a message and to check every output."""
    def __init__(self):
        self.phones, self.names = set(), set()

    def add_phone(self, s):
        d = re.sub(r"\D", "", str(s or ""))
        if len(d) >= 10:
            self.phones.add(d[-10:])

    def add_name(self, s, min_len=4):
        s = unicodedata.normalize("NFC", MARKS_RX.sub("", str(s or ""))).strip(" ~")
        if len(re.sub(r"\D", "", s)) >= 10:   # a sender shown as a number
            self.add_phone(s)
        elif len(s) >= min_len and any(c.isalpha() for c in s) and s.lower() not in {"null", "(unknown)", "unknown", "you"} and s.title() not in COMMON:
            self.names.add(s)

    def drop_names(self, vetoed):
        self.names = {n for n in self.names if n.lower() not in vetoed}

    def name_rx(self):
        if not self.names:
            return None
        return re.compile(r"(?<!\w)(?:" + "|".join(re.escape(n) for n in sorted(self.names, key=len, reverse=True)) + r")(?!\w)", re.I)

    def leaks(self, value):
        """What survives in one output string: counts only, never the string itself."""
        found = []
        digits = re.sub(r"\D", "", value)
        found += ["a phone number"] * sum(p in digits for p in self.phones)
        rx = self.name_rx()
        if rx and rx.search(value):
            found.append("a contact / sender name")
        return found


def scan_outputs(sens, outputs):
    """outputs: {file name: iterable of strings}. Stop (naming the file and kind, never the value) if anything from `sens` is in one."""
    for name, values in outputs.items():
        for v in values:
            hit = sens.leaks(str(v))
            if hit:
                stop(f"{hit[0]} from the input survived into {name}; nothing was written. Masking missed it: tell the maintainer.")


# ---------------------------------------------------------------------------------------------------------------- Form CSV

def norm_header(h):
    return re.sub(r"[\s_-]+", " ", h.strip().lower())


def map_headers(headers):
    """{role: header} for text, label, language (required), category and source (optional), and the list of dropped headers. Stops on
    anything unexpected."""
    roles, dropped, unexpected = {}, [], []
    for h in headers:
        low = norm_header(h)
        if low in FORM_DROP:
            dropped.append(h)
            continue
        if low in FORM_ROLES:
            hits = [FORM_ROLES[low]]
        elif DROP_RX.search(low):
            dropped.append(h)
            continue
        else:
            hits = [role for role, rx in ROLE_RX if rx.search(low)]
        if len(hits) > 1:
            stop(f"header {h!r} matches more than one role ({', '.join(hits)}); rename it in the Form export or tell the script which it is")
        if not hits:
            unexpected.append(h)
            continue
        if hits[0] in roles:
            stop(f"two headers map to {hits[0]!r}: {roles[hits[0]]!r} and {h!r}")
        roles[hits[0]] = h
    missing = [r for r in REQUIRED if r not in roles]
    if missing or unexpected:
        lines = [f"headers found: {list(headers)}"]
        if missing:
            lines.append(f"missing: {missing}")
        if unexpected:
            lines.append(f"unexpected (not mapped, not dropped): {unexpected}")
        stop("; ".join(lines))
    return roles, dropped


def label_of(v):
    """1 scam, 0 genuine, "unsure" (excluded, counted), None (not recognised)."""
    s = re.sub(r"[\s_-]+", " ", str(v).strip().lower())
    if not s:
        return None
    if s in UNSURE:
        return "unsure"
    if s in ("1", "yes", "scam", "spam", "fraud", "phishing", "scam message") or s.startswith("scam") or s.startswith("spam") or s.startswith("fraud"):
        return 1
    if s.startswith("not scam") or s.startswith("not a scam") or s in ("0", "no", "genuine", "legit", "legitimate", "real", "ham", "not scam"):
        return 0
    if s.startswith("genuine") or s.startswith("legit"):
        return 0
    return None


def language_of(v):
    s = str(v).strip().lower()
    return LANG.get(s, s or "unknown")


def clean(text):
    t = unicodedata.normalize("NFC", MARKS_RX.sub("", str(text or ""))).strip()
    return re.sub(r"\s+", " ", t)


def script_language(text):
    """Language from the script alone: Devanagari -> hi, Kannada -> kn, a mixture -> mixed, Latin -> en. Latin-script Hindi (Hinglish) cannot
    be told from English this way and counts as en."""
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return "en"
    dev = sum("ऀ" <= c <= "ॿ" for c in letters)
    kn = sum("ಀ" <= c <= "೿" for c in letters)
    if dev / len(letters) >= 0.3:
        return "hi"
    if kn / len(letters) >= 0.3:
        return "kn"
    return "mixed" if dev + kn else "en"


def read_form(path, drops, read):
    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        headers = next(reader)
        raw_rows = list(reader)
    roles, dropped_cols = map_headers(headers)
    idx = {r: headers.index(h) for r, h in roles.items()}
    print(f"form file: mapped {{{', '.join(f'{r}: {headers[i]!r}' for r, i in idx.items())}}}; dropped before anything else: {dropped_cols}")
    get = lambda rr, role: rr[idx[role]] if role in idx and len(rr) > idx[role] else ""
    recs = []
    for rr in raw_rows:
        src = "form"
        if "source" in idx:
            v = re.sub(r"[^a-z]+", "", get(rr, "source").lower())
            src = f"form_{v}" if v in FORM_SOURCES else "form_other"
        read[src] += 1
        text = clean(get(rr, "text"))
        if len(text) < MIN_CHARS:
            drops[(src, f"shorter than {MIN_CHARS} characters")] += 1
            continue
        label = label_of(get(rr, "label"))
        if label == "unsure":
            drops[(src, "label unsure (excluded)")] += 1
            continue
        if label is None:
            drops[(src, "label not recognised")] += 1
            continue
        recs.append({"text": text, "label": label, "language": language_of(get(rr, "language")), "category": clean(get(rr, "category")) or "unspecified",
                     "source": src, "source_type": "form", "sender_kind": "n/a"})
    return recs, roles, dropped_cols


# ---------------------------------------------------------------------------------------------------------------- SMS Backup & Restore XML

def sender_kind(address):
    """dlt_header (alphanumeric sender id, with or without the operator prefix and the -S / -P / -T / -G suffix), short_code (3-8 digits),
    mobile_number (an Indian 10-digit mobile, with 91 / 0 in front or not, or any number written with a leading +), other (toll-free,
    telemarketing and anything else). The address itself is never kept."""
    a = (address or "").strip()
    digits = re.sub(r"[\s().-]", "", a)
    if re.fullmatch(r"\+?\d+", digits):
        d = digits.lstrip("+")
        if re.fullmatch(r"(?:91|0)?[6-9]\d{9}", d) or (digits.startswith("+") and 10 <= len(d) <= 15):
            return "mobile_number"
        return "short_code" if re.fullmatch(r"\d{3,8}", d) else "other"
    if sum(c.isalpha() for c in a) >= 2 and re.fullmatch(r"[A-Za-z0-9&._ -]{3,15}", a):
        return "dlt_header"
    return "other"


def _xml_char(cp):
    return cp in (0x9, 0xA, 0xD) or 0x20 <= cp <= 0xD7FF or 0xE000 <= cp <= 0xFFFD or 0x10000 <= cp <= 0x10FFFF


def sanitize_xml(raw):
    """SMS Backup & Restore writes an emoji as two numeric references (a UTF-16 surrogate pair), which an XML parser rejects. Join each pair
    into one character and drop any other reference to a character XML forbids."""
    s = raw.decode("utf-8", errors="replace")
    ref = re.compile(r"&#(?:x([0-9a-fA-F]+)|(\d+));")
    out, pos = [], 0
    ms = list(ref.finditer(s))
    k = 0
    cp_of = lambda m: int(m.group(1), 16) if m.group(1) else int(m.group(2))
    while k < len(ms):
        m = ms[k]
        cp = cp_of(m)
        out.append(s[pos:m.start()])
        pos = m.end()
        if 0xD800 <= cp <= 0xDBFF and k + 1 < len(ms) and ms[k + 1].start() == m.end() and 0xDC00 <= cp_of(ms[k + 1]) <= 0xDFFF:
            out.append(chr(0x10000 + ((cp - 0xD800) << 10) + (cp_of(ms[k + 1]) - 0xDC00)))
            pos = ms[k + 1].end()
            k += 2
            continue
        out.append(m.group(0) if _xml_char(cp) else "")
        k += 1
    out.append(s[pos:])
    s = re.sub("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]", "", "".join(out))
    return s.encode("utf-8")


def read_sms(path, source, drops, read, sens):
    raw = path.read_bytes()
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        root = ET.fromstring(sanitize_xml(raw))
    if root.tag != "smses":
        stop(f"a .xml file is not an SMS Backup & Restore export (root element <{root.tag}>); move it out of data/real/raw/")
    recs, n_elements = [], 0
    for el in root:
        if el.tag not in ("sms", "mms"):
            continue
        n_elements += 1
        read[source] += 1
        if el.tag == "mms":
            drops[(source, "MMS element (only <sms> is read)")] += 1
            continue
        if el.get("type") != "1":
            drops[(source, "not a received message (type != 1)")] += 1
            continue
        body = el.get("body")
        kind = sender_kind(el.get("address"))
        if kind == "mobile_number":   # a person: the number and the saved name must not survive in any message or output
            sens.add_phone(el.get("address"))
            sens.add_name(el.get("contact_name"))
        text = clean("" if body in (None, "null") else body)
        if not text:
            drops[(source, "empty body")] += 1
            continue
        if len(text) < MIN_CHARS:
            drops[(source, f"shorter than {MIN_CHARS} characters")] += 1
            continue
        recs.append({"text": text, "label": None, "language": script_language(text), "category": "unspecified", "source": source, "source_type": "sms", "sender_kind": kind})
    declared = root.get("count")
    if declared and declared.isdigit() and int(declared) != n_elements:
        print(f"note: {source}: the file says count={declared}, {n_elements} <sms> / <mms> elements were found")
    return recs


# ---------------------------------------------------------------------------------------------------------------- WhatsApp .txt

def parse_whatsapp(text):
    """[(sender or None, body)] from an Android ("12/03/2024, 10:15 - Name: text") or iOS ("[12/03/24, 10:15:30 PM] Name: text") export.
    A line without a date header continues the message before it. Sender-less lines are WhatsApp's own notices."""
    entries = []
    for line in text.splitlines():
        m = WA_HEAD.match(line)
        if m:
            sm = WA_SENDER.match(m.group("rest"))
            entries.append([sm.group("sender") if sm else None, sm.group("body") if sm else m.group("rest")])
        elif entries:
            entries[-1][1] += "\n" + line
    return [tuple(e) for e in entries]


def read_whatsapp(path, source, drops, read, sens):
    named = re.match(r"(?i)^(?:whatsapp )?chat (?:with|-)\s*(.+)$", path.stem)   # "WhatsApp Chat with <a person>.txt": that name must not survive anywhere
    if named:
        sens.add_name(named.group(1))
    entries = parse_whatsapp(path.read_text(encoding="utf-8-sig", errors="replace"))
    if not entries:
        stop(f"{path.name} has no WhatsApp message lines (dated lines like '12/03/2024, 10:15 - Name: text'); if it is not a chat export, move it out of data/real/raw/")
    recs = []
    for sender, body in entries:
        read[source] += 1
        if sender is None:
            drops[(source, "system, media or deleted line")] += 1
            continue
        sens.add_name(sender)
        body = WA_MENTION_NUM_RX.sub("<PHONE>", WA_MENTION_IOS_RX.sub("<NAME>", body))
        lines = [l for l in (clean(x) for x in body.split("\n")) if l]
        if lines and WA_FILE_LINE.match(lines[0]):
            lines = lines[1:]
        text = clean(" ".join(lines))
        if not text or WA_SKIP_RX.match(text) or WA_NOTICE_RX.match(text):
            drops[(source, "system, media or deleted line")] += 1
            continue
        if len(text) <= WA_MIN_CHARS:
            drops[(source, f"{WA_MIN_CHARS} characters or fewer")] += 1
            continue
        recs.append({"text": text, "label": None, "language": script_language(text), "category": "unspecified", "source": source, "source_type": "whatsapp", "sender_kind": "n/a"})
    return recs


# ---------------------------------------------------------------------------------------------------------------- finding and labelling the files

def discover(inputs):
    """{kind: [paths]} for csv / xml / txt under the given files and folders (recursive, sorted), plus 'other' for the rest. Hidden and
    macOS resource files (._x, .DS_Store) are ignored."""
    found = {"csv": [], "xml": [], "txt": [], "other": []}
    for p in inputs:
        p = Path(p)
        files = sorted(q for q in p.rglob("*") if q.is_file()) if p.is_dir() else [p]
        for q in files:
            if any(part.startswith(".") for part in (q.relative_to(p).parts if p.is_dir() else (q.name,))):
                continue
            kind = q.suffix.lower().lstrip(".")
            found[kind if kind in ("csv", "xml", "txt") else "other"].append(q)
    return {k: sorted(set(v)) for k, v in found.items()}


def assign_labels(paths, prefix, rx):
    """{path: prefix_N}. N comes from the file name when it holds one (phone_2.xml), else the smallest unused number in sorted order."""
    out, used = {}, set()
    for p in paths:
        m = rx.search(p.stem)
        if m:
            n = int(m.group(1))
            if n in used:
                stop(f"two {prefix} files claim the number {n} in their names")
            used.add(n)
            out[p] = f"{prefix}_{n}"
    n = 0
    for p in paths:
        if p not in out:
            n += 1
            while n in used:
                n += 1
            used.add(n)
            out[p] = f"{prefix}_{n}"
    return out


def check_input_path(p):
    """The intake is the one script allowed to read data/real/ (it makes it); the PROBE-ONLY sets are not intake inputs."""
    q = Path(p)
    q = (ROOT / q if not q.is_absolute() else q).resolve()
    for d in realguard.PROBE_DIRS:
        if q == d.resolve() or d.resolve() in q.parents:
            stop(f"{p} is under {d.name}/, a PROBE-ONLY folder; it is not an intake input")


# ---------------------------------------------------------------------------------------------------------------- masking, names

def protect_urls(text):
    urls = []
    def keep(m):
        urls.append(m.group(0))
        return f"\x00{len(urls) - 1}\x00"
    return URL_RX.sub(keep, text), urls

def restore_urls(text, urls):
    return re.sub(r"\x00(\d+)\x00", lambda m: urls[int(m.group(1))], text)

def mask(text, name_rx=None):
    """src/pii.py masks (emails and UPI ids first, then phones and accounts) with URLs kept, plus card, OTP, account-tail and long digit
    runs, and every contact / sender name seen in the input (name_rx) as <NAME>."""
    t = text
    for pat, tok in ADDRESS_MASKS:
        t = re.sub(pat, tok, t)
    t, urls = protect_urls(t)
    if name_rx is not None:
        t = name_rx.sub("<NAME>", t)
    t = CARD_RX.sub("<ACCOUNT>", t)
    t = OTP_RX.sub(lambda m: m.group(0)[: m.start(2) - m.start(0)] + "<OTP>", t)
    t = OTP_BEFORE_RX.sub("<OTP>", t)
    t = ACCT_TAIL_RX.sub(lambda m: m.group(1) + "<ACCOUNT>", t)
    t = XX_TAIL_RX.sub("<ACCOUNT>", t)
    for pat, tok in NUMBER_MASKS:
        t = re.sub(pat, tok, t)
    t = URL_PHONE_RX.sub(lambda m: m.group(1) + "<PHONE>", restore_urls(t, urls))
    return LONG_RX.sub("<ACCOUNT>", URL_MOBILE_RX.sub("<PHONE>", t))

def defang(text):
    """Every link in a text made unclickable (hxxp, [.]) so a spreadsheet cannot turn it into a hyperlink (CLAUDE.md rule 8)."""
    out, pos = [], 0
    for a, b, core in _urls(text):
        out += [text[pos:a], re.sub(r"(?i)^http", "hxxp", core).replace(".", "[.]")]
        pos = b
    out.append(text[pos:])
    return "".join(out)

def defang_span(s):
    return re.sub(r"https?://\S+|www\.\S+", lambda m: m.group(0).replace("http", "hxxp").replace(".", "[.]"), s)

def sheet_text(text):
    """A message as one spreadsheet cell: links defanged, cut to SHEET_CHARS, and never starting with a formula character."""
    t = defang(text)
    t = t[:SHEET_CHARS] + ("..." if len(t) > SHEET_CHARS else "")
    return " " + t if t[:1] in "=+-@" else t

def vocab_stats(recs):
    """(in how many different message texts each word occurs, the words seen in lower case): what separates a name from a brand or an ordinary
    word. Links are taken out first, so 'Swiggy' is not 'seen in lower case' only because of swiggy.in."""
    seen, df, lower = set(), Counter(), set()
    for r in recs:
        if r["gkey"] in seen:
            continue
        seen.add(r["gkey"])
        words = re.findall(r"[^\W\d_]{3,}", replace_urls(r["masked"]))
        df.update(set(words))
        lower.update(w for w in words if w.islower())
    return df, lower

def name_tokens(masked, vocab=None):
    """Capitalised words that may be a person's name. A word at the start of a sentence is only a candidate when another capitalised word follows
    it ("Ramesh Kumar") or a greeting precedes it; otherwise it is the sentence's first word (Reply, Track, Dinner). With `vocab` (vocab_stats),
    a word that also occurs in lower case, or in more than MAX_DF different message texts, is dropped (Recharge, Swiggy). Greeting names and
    ALL-CAPS payer / payee phrases are always candidates."""
    out = set()
    for m in TOKEN_RX.finditer(masked):
        tok = m.group(0)
        if tok in COMMON:
            continue
        if vocab is not None and (tok.lower() in vocab[1] or vocab[0][tok] > MAX_DF):
            continue
        before = masked[:m.start()]
        starts = not before.strip() or before.rstrip()[-1] in ".!?:;\n\"'("
        followed = re.match(r"\s+[A-Z][a-z]{2,}\b", masked[m.end():]) is not None
        if starts and not followed and not GREETING_RX.search(before):
            continue
        out.add(tok)
    for m in GREETING_NAME_RX.finditer(masked):
        if m.group(1).lower() not in NOT_NAMES:
            out.add(m.group(1))
    for m in CAPS_NAME_RX.finditer(masked):
        phrase = m.group(1).rstrip(".").strip()
        if phrase.title() not in COMMON and not set(phrase.split()) & ACRONYMS:
            out.add(phrase)
    return sorted(out)

def auto_names(recs, min_templates=3, min_share=0.5):
    """Words that follow a greeting in at least `min_templates` different message texts and, of all the texts that hold the word, in at least
    `min_share` of them: almost always the phone owner's own name ("Hey prajval, your order ..."), or a name that keeps coming back. These are
    masked everywhere, whatever the case. 'aap' (Hinglish) follows 'Namaste' too, but is a word everywhere else, so the share test keeps it."""
    keys = [group_key(r["masked"]) for r in recs]
    after, anywhere = defaultdict(set), defaultdict(set)
    for r, key in zip(recs, keys):
        for m in GREETING_NAME_RX.finditer(r["masked"]):
            if m.group(1).lower() not in NOT_NAMES:
                after[m.group(1).lower()].add(key)
    if not after:
        return []
    rx = re.compile(r"(?<!\w)(" + "|".join(map(re.escape, after)) + r")(?!\w)", re.I)
    for r, key in zip(recs, keys):
        for w in set(x.lower() for x in rx.findall(r["masked"])):
            anywhere[w].add(key)
    return sorted(w for w, ks in after.items() if len(ks) >= min_templates and len(ks) / len(anywhere[w]) >= min_share)

def read_names_file(path):
    """(names to mask, names to leave alone) from data/real/mask_names.txt: one name per line, '#' comments, a leading '-' vetoes a name that
    was auto-detected from greetings. Missing file = nothing."""
    add, veto = [], set()
    if path and Path(path).exists():
        for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            (veto.add(line[1:].strip().lower()) if line.startswith("-") else add.append(line))
    return add, veto

def contexts(masked, token, width=30):
    out = []
    for m in re.finditer(rf"(?<!\w){re.escape(token)}(?!\w)", masked):
        a, b = max(0, m.start() - width), min(len(masked), m.end() + width)
        out.append(defang_span(masked[a:m.start()]) + f"[[{token}]]" + defang_span(masked[m.end():b]))
    return out


def read_review(path):
    if not path.exists():
        return {}
    with open(path, encoding="utf-8", newline="") as f:
        return {(r["id"], r["token"]): r for r in csv.DictReader(f)}

def csv_text(fields, rows):
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=fields, lineterminator="\r\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in fields})
    return buf.getvalue()

def write_review(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(csv_text(["id", "token", "context", "replace_with"], sorted(rows, key=lambda r: (r["id"], r["token"]))), encoding="utf-8", newline="")


def overlap_flags(texts, messages=MESSAGES):
    """True for each text with a TRAIN row of data/final/messages.csv at near-duplicate similarity (the splits' rule, both views)."""
    m = pd.read_csv(messages, usecols=["text", "split"], low_memory=False, keep_default_na=False)
    train = [model_text(t) for t in m.loc[m["split"] == "train", "text"]]
    n_tr = len(train)
    prep = [model_text(t, mask_pii=True) for t in texts]
    allt = train + prep
    flags = [False] * len(prep)
    for i, j, _, _ in near_dup_pairs_any(allt, ["x"] * len(allt), CLUSTER_SEED, skip=lambda i, j: (i < n_tr) == (j < n_tr),
                                          queries=range(n_tr, len(allt))):
        if i >= n_tr and j < n_tr:
            flags[i - n_tr] = True
        elif j >= n_tr and i < n_tr:
            flags[j - n_tr] = True
    return flags


# ---------------------------------------------------------------------------------------------------------------- template groups, label_me.csv

def group_key(masked):
    """What two messages of one template share: links -> <URL>, lower case, every digit run -> 0 (OTPs, amounts, dates, reference numbers)."""
    return re.sub(r"\d+", "0", model_text(masked).lower()).strip()


def make_groups(recs):
    """Sets rec['gkey'] and rec['group'] (a hash of the group's smallest key, so it does not depend on the order of the files). Two keys join
    one group when src/neardup.py calls them near-duplicates (exact Jaccard >= 0.7 on char 5-grams, raw or normalised view)."""
    keys = sorted({group_key(r["masked"]) for r in recs})
    pos = {k: i for i, k in enumerate(keys)}
    parent = list(range(len(keys)))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    if len(keys) > 1:
        for i, j, _, _ in near_dup_pairs_any(keys, ["real"] * len(keys), CLUSTER_SEED):
            a, b = find(i), find(j)
            parent[max(a, b)] = min(a, b)
    roots = [i for i in range(len(keys)) if find(i) == i]
    gid = {k: "G" + hashlib.md5(keys[find(i)].encode()).hexdigest()[:8] for k, i in pos.items()}
    if len({gid[keys[i]] for i in roots}) != len(roots):
        stop("two template groups got the same group_id (hash collision)")
    groups = defaultdict(list)
    for r in recs:
        r["gkey"] = group_key(r["masked"])
        r["group"] = gid[r["gkey"]]
        groups[r["group"]].append(r)
    return groups


def _jac(a, b):
    inter = len(a & b)
    return inter / (len(a) + len(b) - inter) if (a or b) else 1.0

def pick_examples(members):
    """(example 1, example 2, similarity): the most common text of the group and the text least like it (digits collapsed, links kept, so
    a link that differs shows up). example 2 is empty when the group is a single text."""
    cnt = Counter(r["masked"] for r in members)
    texts = sorted(cnt, key=lambda t: (-cnt[t], realguard.norm_key(t)))
    if len(texts) == 1:
        return texts[0], "", ""
    shs = shingle_sets([re.sub(r"\d+", "0", t.lower())[:2000] for t in texts])
    sims = [_jac(shs[0], s) for s in shs[1:]]
    k = min(range(len(sims)), key=lambda i: (sims[i], realguard.norm_key(texts[i + 1])))
    return texts[0], texts[k + 1], f"{sims[k]:.2f}"


def mix(counter):
    return "; ".join(f"{k}:{v}" for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))


def read_label_file(path):
    """({group_id: scam | genuine | skip}, {group_id: row}) from the label sheet. Stops on a label that is not one of the three words."""
    if not path.exists():
        return {}, {}
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if rows and ("group_id" not in rows[0] or "label" not in rows[0]):
        stop(f"{path.name} has no group_id / label columns (columns: {list(rows[0])})")
    labels, by_id, bad = {}, {}, []
    for r in rows:
        gid = r["group_id"].strip()
        if gid in by_id:
            stop(f"{path.name}: group_id {gid} appears twice")
        by_id[gid] = r
        v = r["label"].strip().lower()
        if v not in LABEL_WORDS:
            bad.append(gid)
        elif LABEL_WORDS[v]:
            labels[gid] = LABEL_WORDS[v]
    if bad:
        stop(f"{path.name}: label must be scam, genuine, skip or empty; wrong value for group_id {', '.join(bad[:10])}{' ...' if len(bad) > 10 else ''}")
    return labels, by_id


def label_rows(groups, need, old_rows):
    """One row per group that still has an unlabelled message, biggest first. Rows already in the file keep their label; a labelled row whose
    group no longer exists is kept at the end (orphan), never dropped."""
    rows = []
    for gid in need:
        members = groups[gid]
        e1, e2, sim = pick_examples(members)
        rows.append({"group_id": gid, "size": len(members), "example_1": sheet_text(e1), "example_2": sheet_text(e2) if e2 else "", "example_similarity": sim,
                     "sender_kind_mix": mix(Counter(r["sender_kind"] for r in members)), "sources": mix(Counter(r["source"] for r in members)),
                     "label": (old_rows.get(gid, {}).get("label") or "").strip()})
    rows.sort(key=lambda r: (-r["size"], r["group_id"]))
    listed = {x["group_id"] for x in rows}
    orphans = [r for gid, r in old_rows.items() if gid not in listed and (r.get("label") or "").strip()]
    return rows, [{k: o.get(k, "") for k in LABEL_COLS} for o in orphans]


# ---------------------------------------------------------------------------------------------------------------- the run

def run(inputs=None, out=OUT, review=REVIEW, report=REPORT, freeze=False, messages=MESSAGES, label_file=LABEL_ME, cap=CAP, allow_unlabelled=False, names_file=NAMES_FILE,
        allow_open_names=False):
    inputs = [RAW_DIR] if inputs is None else ([inputs] if isinstance(inputs, (str, Path)) else list(inputs))
    for p in inputs:
        if not Path(p).exists():
            stop(f"{p} does not exist (the exports go in data/real/raw/; the folder is git-ignored)")
        check_input_path(p)
    files = discover(inputs)
    if not (files["csv"] or files["xml"] or files["txt"]):
        stop(f"no .csv, .xml or .txt file under {', '.join(str(Path(p)) for p in inputs)}")
    sens, drops, read = Sensitive(), Counter(), Counter()
    recs, form_info = [], []
    for p in files["csv"]:
        r, roles, dropped_cols = read_form(p, drops, read)
        recs += r
        form_info.append((roles, dropped_cols))
    for p, src in assign_labels(files["xml"], "phone", PHONE_LABEL).items():
        recs += read_sms(p, src, drops, read, sens)
    for p, src in assign_labels(files["txt"], "wa", WA_LABEL).items():
        recs += read_whatsapp(p, src, drops, read, sens)
    print(f"read {sum(read.values())} rows from {len(files['csv'])} Form file(s), {len(files['xml'])} SMS file(s), {len(files['txt'])} WhatsApp file(s)"
          + (f"; {len(files['other'])} other file(s) not read" if files["other"] else ""))

    for r in recs:
        r["masked"] = mask(r["text"])
    extra, vetoed = read_names_file(names_file)
    auto = [w for w in auto_names(recs) if w not in vetoed]
    for w in auto:
        sens.add_name(w, min_len=3)
    for w in extra:
        sens.add_name(w, min_len=2)
    sens.drop_names(vetoed)
    nrx = sens.name_rx()
    if nrx:
        for r in recs:
            r["masked"] = mask(r["text"], nrx)
    if auto:
        print(f"names masked everywhere because they follow a greeting in many messages (a wrong one: add '-word' to {names_file}): {', '.join(auto)}")
    groups = make_groups(recs)

    # exact duplicates once, at most `cap` messages per group (a stable pseudo-random pick: the md5 order of the masked text)
    cands = []
    for gid, members in groups.items():
        seen, kept = set(), []
        for r in sorted(members, key=lambda r: (r["label"] is None, realguard.norm_key(r["masked"]), r["source"])):
            k = realguard.norm_key(r["masked"])
            if k in seen:
                drops[(r["source"], "exact duplicate")] += 1
            elif len(kept) >= cap:
                drops[(r["source"], f"over the {cap}-per-group cap")] += 1
            else:
                kept.append(r)
            seen.add(k)
        for r in kept:
            r["id"] = "R" + realguard.norm_key(r["masked"])[:10]
            r["group_size"] = len(members)
        cands += kept
    if len({r["id"] for r in cands}) != len(cands):
        stop("two kept messages got the same row id (hash collision)")

    labels, old_rows = read_label_file(label_file)
    need = [gid for gid, m in groups.items() if any(r["label"] is None for r in m)]
    final_pre = []
    for r in cands:
        if r["label"] is None:
            v = labels.get(r["group"])
            if v is None:
                drops[(r["source"], "group not labelled yet")] += 1
                continue
            if v == "skip":
                drops[(r["source"], "group marked skip")] += 1
                continue
            r["label"] = 1 if v == "scam" else 0
        final_pre.append(r)
    unlabelled_groups = [gid for gid in need if gid not in labels]
    sheet, orphans = label_rows(groups, need, old_rows)
    stale = [gid for gid in labels if gid not in groups]

    # names: candidates to review for the rows that are kept; edits from the review file are applied
    review_rows = read_review(review)
    current = {}
    vocab = vocab_stats(recs)
    for r in final_pre:
        for tok in name_tokens(r["masked"], vocab):
            ctx = contexts(r["masked"], tok)
            if ctx:
                current[(r["id"], tok)] = {"id": r["id"], "token": tok, "context": ctx[0], "replace_with": ""}
    new_rows = [v for k, v in current.items() if k not in review_rows]
    merged = {**review_rows, **{k: v for k, v in current.items() if k not in review_rows}}
    open_names = sum(1 for k, v in merged.items() if k in current and not v["replace_with"].strip())   # blank = not looked at yet
    applied, final = Counter(), []
    for r in final_pre:
        edits = [v for (rid, tok), v in review_rows.items() if rid == r["id"]]
        if any(e["replace_with"].strip().upper() == "DROP" for e in edits):
            drops[(r["source"], "review: marked DROP")] += 1
            continue
        t = r["masked"]
        for e in edits:
            rep = e["replace_with"].strip()
            if rep and rep.upper() not in ("DROP", "OK", "KEEP") and e["token"]:
                t, n = re.subn(rf"(?<!\w){re.escape(e['token'])}(?!\w)", rep, t)
                applied[rep] += n
        r["final"] = t
        final.append(r)

    # overlap with TRAIN for every candidate (the report counts unlabelled groups too); rows are never dropped for it
    flags = overlap_flags([r["masked"] for r in cands], messages) if cands else []
    for r, o in zip(cands, flags):
        r["overlap"] = bool(o)
    for r in final:
        r["hash"] = realguard.norm_key(r["final"])
    final.sort(key=lambda r: (-r["group_size"], r["group"], r["hash"]))

    if sum(read.values()) != len(final) + sum(drops.values()):
        stop(f"row accounting does not balance: read {sum(read.values())}, kept {len(final)}, dropped {sum(drops.values())}")
    inv = {"investment": INVEST_RX, "crypto": CRYPTO_RX, "task": TASK_RX}
    inv_groups = {k: sum(any(rx.search(r["masked"]) for r in m) for m in groups.values()) for k, rx in inv.items()}
    inv_groups["any"] = sum(any(rx.search(r["masked"]) for rx in inv.values() for r in m) for m in groups.values())

    out_rows = [{"id": r["id"], "text": r["final"], "label": r["label"], "language": r["language"], "category": r["category"], "overlap": r["overlap"],
                 "source_row_hash": r["hash"], "source": r["source"], "source_type": r["source_type"], "sender_kind": r["sender_kind"],
                 "group_id": r["group"], "group_size": r["group_size"]} for r in final]
    out_text = csv_text(OUT_COLS, out_rows)
    sheet_text_csv = csv_text(LABEL_COLS, sheet + orphans)
    review_rows_out = list(merged.values())
    summary = summarise(files, read, drops, groups, need, labels, unlabelled_groups, stale, orphans, cands, final, inv_groups, current, review_rows, new_rows, applied,
                        form_info, open_names, sens_counts=(len(sens.phones), len(sens.names), len(auto), len(extra)))
    sha = hashlib.sha256(out_text.encode("utf-8")).hexdigest() if final else None
    report_text = write_summary(summary, sha, out)

    # nothing is written until every output has been checked for the phone numbers and names that were in the input
    scan_outputs(sens, {out.name: [r["text"] for r in out_rows], label_file.name: [r[c] for r in sheet + orphans for c in ("example_1", "example_2")],
                        review.name: [r["context"] for r in review_rows_out], report.name: report_text.splitlines()})
    frozen_now = frozen_hash()
    if frozen_now and out.exists() and hashlib.sha256(out.read_bytes()).hexdigest() == frozen_now and (not final or sha != frozen_now):
        stop(f"{out.name} is the frozen test set (CLAUDE.md); a rerun would replace it. Move it aside deliberately if that is what you want")
    label_file.parent.mkdir(parents=True, exist_ok=True)
    label_file.write_text(sheet_text_csv, encoding="utf-8", newline="")
    write_review(review, review_rows_out)
    if final:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(out_text, encoding="utf-8", newline="")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(report_text, encoding="utf-8")
    shown = lambda p: p.relative_to(ROOT) if p.is_relative_to(ROOT) else p
    print(f"{len(cands)} candidate messages in {len(groups)} template groups; {len(need)} groups need a label ({len(unlabelled_groups)} still blank) -> {shown(label_file)}")
    if final:
        print(f"kept {len(final)} labelled rows -> {shown(out)}\nsha256 {sha}")
    else:
        print(f"no group is labelled yet, so {shown(out)} was not written")
    if freeze:
        if not final:
            stop("--freeze needs at least one labelled row")
        if unlabelled_groups and not allow_unlabelled:
            stop(f"--freeze: {len(unlabelled_groups)} groups in {label_file.name} still have no label (scam / genuine / skip). Label them, or pass --allow-unlabelled "
                 "to freeze without them (their messages are then left out, which favours the templates you did label)")
        if open_names and not allow_open_names:
            stop(f"--freeze: {open_names} name candidates in {review.name} are still blank. Write <NAME> to mask a token, DROP to drop its row, or ok when it is not a name "
                 "(fill the column with ok, then fix the real names); or pass --allow-open-names to freeze with them as written")
        freeze_hash(sha, len(final))
    return sha, final


def summarise(files, read, drops, groups, need, labels, unlabelled_groups, stale, orphans, cands, final, inv_groups, current, review_rows, new_rows, applied, form_info, open_names, sens_counts):
    return dict(files=files, read=read, drops=drops, groups=groups, need=need, labels=labels, unlabelled_groups=unlabelled_groups, stale=stale, orphans=orphans,
                cands=cands, final=final, inv=inv_groups, current=current, review_rows=review_rows, new_rows=new_rows, applied=applied, form_info=form_info, open_names=open_names, sens=sens_counts)


def write_summary(s, sha, out):
    final, cands, groups, drops, read = s["final"], s["cands"], s["groups"], s["drops"], s["read"]
    L = ["# Real-message intake v1\n",
         f"*Generated by `src/intake_real.py` on {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC. No message text, no file name, no number and no name "
         "in this report: texts are in `data/real/real_test_v1.csv` and `data/real/label_me.csv` (git-ignored).*\n",
         f"Files read: {len(s['files']['csv'])} Form CSV, {len(s['files']['xml'])} SMS Backup & Restore XML, {len(s['files']['txt'])} WhatsApp text. "
         f"Not read (other file types): {len(s['files']['other'])}.\n"]
    for roles, dropped_cols in s["form_info"]:
        L.append(f"Form columns mapped: {', '.join(f'{r} <- {c!r}' for r, c in roles.items())}. Dropped before anything else: {', '.join(repr(c) for c in dropped_cols) or 'none'}.\n")
    L.append("## Rows read per source\n")
    kept = Counter(r["source"] for r in final)
    dropped = Counter()
    for (src, _), n in drops.items():
        dropped[src] += n
    L += ["| source | type | read | kept | dropped |", "|---|---|---:|---:|---:|"]
    for src in sorted(read):
        L.append(f"| {src} | {'sms' if src.startswith('phone_') else 'whatsapp' if src.startswith('wa_') else 'form'} | {read[src]} | {kept[src]} | {dropped[src]} |")
    L.append(f"| **all** | | {sum(read.values())} | {len(final)} | {sum(drops.values())} |\n")
    L.append("## Kept vs dropped, and why\n")
    L.append(f"- Read {sum(read.values())}. **Kept {len(final)}** in the test set. Dropped {sum(drops.values())} (read = kept + dropped).")
    by_reason = defaultdict(Counter)
    for (src, reason), n in drops.items():
        by_reason[reason][src] += n
    for reason, c in sorted(by_reason.items(), key=lambda kv: -sum(kv[1].values())):
        L.append(f"  - {reason}: {sum(c.values())} ({mix(c)})")
    L.append("")
    L.append("## Template groups\n")
    sizes = sorted((len(m) for m in groups.values()), reverse=True)
    bins = [("1", lambda n: n == 1), ("2-3", lambda n: 2 <= n <= 3), ("4-10", lambda n: 4 <= n <= 10), ("11-50", lambda n: 11 <= n <= 50), ("over 50", lambda n: n > 50)]
    L.append(f"- Groups: **{len(groups)}** for {sum(sizes)} messages that passed the first filters (group = near-duplicates after masking, digits collapsed). "
             f"Largest 10 group sizes: {', '.join(map(str, sizes[:10])) or 'none'}.")
    L.append("- Groups by size: " + "; ".join(f"{name}: {sum(fn(n) for n in sizes)}" for name, fn in bins) + ".")
    if sizes:
        L.append("- Labelling the biggest groups first covers: " + "; ".join(f"{n} groups = {100 * sum(sizes[:n]) / sum(sizes):.0f}% of messages" for n in (25, 50, 100, 200, 400) if n < len(sizes))
                 + f"; all {len(sizes)} groups = 100%.")
    L.append(f"- The test set keeps at most {CAP} messages per group (exact duplicates once): {len(final)} rows from {len({r['group'] for r in final})} groups; "
             f"`group_size` in the file is the whole group, so eval can report per message and per group.")
    L.append(f"- Groups with a message to label: {len(s['need'])}. Labelled in `label_me.csv`: {sum(g in s['labels'] for g in s['need'])} "
             f"(skip: {sum(s['labels'].get(g) == 'skip' for g in s['need'])}), still blank: **{len(s['unlabelled_groups'])}**. "
             f"Labels in the file that match no group: {len(s['stale'])} (kept at the end of the file: {len(s['orphans'])}).")
    L.append(f"- Phone numbers and names seen in the input and masked wherever they appear: {s['sens'][0]} numbers, {s['sens'][1]} names "
             f"({s['sens'][2]} found after greetings, {s['sens'][3]} from `mask_names.txt`; values are not written anywhere).\n")
    L.append("## Label counts: language x sender_kind\n")
    L += ["| language | sender_kind | scam | genuine | not labelled yet (candidates) |", "|---|---|---:|---:|---:|"]
    c = Counter((r["language"], r["sender_kind"], r["label"]) for r in final)
    open_groups = set(s["unlabelled_groups"])
    pending = Counter((r["language"], r["sender_kind"]) for r in cands if r["group"] in open_groups and r["label"] is None)
    keys = sorted({(k[0], k[1]) for k in c} | set(pending))
    for lang, kind in keys:
        L.append(f"| {lang} | {kind} | {c[(lang, kind, 1)]} | {c[(lang, kind, 0)]} | {pending[(lang, kind)]} |")
    L.append("")
    L.append("Language for SMS and WhatsApp comes from the script only (Devanagari -> hi, Kannada -> kn, mixture -> mixed, Latin -> en), so Hinglish counts as en. "
             "Form rows keep the language the contributor gave.\n")
    L.append("## Overlap with the TRAIN split\n")
    ov_groups = len({r["group"] for r in cands if r["overlap"]})
    L.append(f"- Candidate messages with a near-duplicate in TRAIN (the splits' rule): {sum(r['overlap'] for r in cands)} of {len(cands)}; "
             f"groups with at least one such message: {ov_groups} of {len(groups)}. Kept rows with overlap=True: {sum(r['overlap'] for r in final)} of {len(final)}. "
             "Rows are kept; `eval_real.py` reports with and without them.\n")
    L.append("## Investment / trading / task-like groups (keyword count only)\n")
    L.append(f"- Groups with at least one message matching the keyword lists of `src/audit_investment.py` (INVEST_RX, CRYPTO_RX, TASK_RX): **{s['inv']['any']}** of {len(groups)} "
             f"(investment {s['inv']['investment']}, crypto {s['inv']['crypto']}, task {s['inv']['task']}; a group can match more than one). A keyword hit is not a label.\n")
    L.append("## Names\n")
    ids = {r["id"] for r in final}
    L.append(f"- Kept rows with a likely name (capitalised word not in the common-word list): {len({k[0] for k in s['current']})}. Candidate tokens: {len(s['current'])}.")
    L.append(f"- Edits applied from `review_names.csv`: masks {sum(s['applied'].values())} (replacement values are not written here).")
    L.append(f"- Candidates still blank (not looked at; blank is kept as written, `ok` marks a reviewed non-name): {s['open_names']}; new since last run: {len(s['new_rows'])}; "
             f"entries for rows no longer in the set: {sum(1 for k in s['review_rows'] if k[0] not in ids)}.\n")
    L.append("## Output\n")
    L.append(f"- `{out.name}`: {len(final)} rows" + (f", SHA-256 `{sha}`." if sha else " (not written: no labelled group yet)."))
    return "\n".join(L) + "\n"


FREEZE_HEAD = "## Frozen hashes (real-message test set)"

def frozen_hash():
    if not CLAUDE.exists() or FREEZE_HEAD not in CLAUDE.read_text(encoding="utf-8"):
        return None
    m = re.search(r"SHA-256 `([0-9a-f]{64})`", CLAUDE.read_text(encoding="utf-8").split(FREEZE_HEAD, 1)[1])
    return m.group(1) if m else None

def freeze_hash(sha, n):
    """Write (or replace) the frozen-hashes section of CLAUDE.md. Refuses to replace a different hash: that needs a human decision."""
    text = CLAUDE.read_text(encoding="utf-8")
    line = f"- `data/real/real_test_v1.csv`: {n} rows, SHA-256 `{sha}` (frozen {dt.date.today().isoformat()}). TEST ONLY: never a training, tuning or calibration input (src/realguard.py)."
    if FREEZE_HEAD in text:
        block = text.split(FREEZE_HEAD, 1)[1]
        old = re.search(r"SHA-256 `([0-9a-f]{64})`", block)
        if old and old.group(1) != sha:
            stop("CLAUDE.md already freezes a different real_test_v1.csv hash; this needs a decision, not a rewrite")
        if old and old.group(1) == sha:
            return
        text = re.sub(r"(?m)^Not frozen yet:.*\n?", "", text).replace(FREEZE_HEAD, FREEZE_HEAD + "\n\n" + line, 1)
    else:
        text = text.rstrip("\n") + f"\n\n{FREEZE_HEAD}\n\n{line}\n"
    CLAUDE.write_text(text, encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, nargs="+", help="files and / or folders (default: data/real/raw/, searched recursively)")
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--review", type=Path, default=REVIEW)
    ap.add_argument("--report", type=Path, default=REPORT)
    ap.add_argument("--label-file", type=Path, default=LABEL_ME, help="the sheet you label (written on every run; your labels are kept)")
    ap.add_argument("--cap", type=int, default=CAP, help="messages kept per template group")
    ap.add_argument("--names-file", type=Path, default=NAMES_FILE, help="optional: names to mask everywhere, one per line; '-word' keeps an auto-detected word")
    ap.add_argument("--messages", type=Path, default=MESSAGES, help="the training corpus for the overlap check (tests pass a tiny file)")
    ap.add_argument("--freeze", action="store_true", help="write the SHA-256 into CLAUDE.md's frozen-hashes section (needs every group labelled)")
    ap.add_argument("--allow-unlabelled", action="store_true", help="with --freeze: freeze although some groups have no label (their messages are left out)")
    ap.add_argument("--allow-open-names", action="store_true", help="with --freeze: freeze although name candidates in review_names.csv are still blank")
    a = ap.parse_args()
    run(a.input, a.out, a.review, a.report, a.freeze, a.messages, a.label_file, a.cap, a.allow_unlabelled, a.names_file, a.allow_open_names)


if __name__ == "__main__":
    try:
        main()
    except Stop as e:
        print(e, file=sys.stderr)
        sys.exit(2)
