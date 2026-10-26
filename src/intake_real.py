"""Real-message intake -> data/real/real_test_v1.csv, a masked TEST-ONLY set (CLAUDE.md rule 12). No network.
Run on the Mac:

    .venv/bin/python src/intake_real.py                  # every file under data/real/raw/, recursively
    .venv/bin/python src/label_real.py                   # label the template groups in the terminal (s / g / k / b / q), bucket by bucket
    .venv/bin/python src/intake_real.py --freeze --allow-unlabelled   # ONCE: grouped 50/50 split, TEST frozen (hash in CLAUDE.md), POOL for training

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
src/neardup.py on the masked text with digits collapsed (so OTPs and amounts with different digits fall into one group), a new group's id is a
hash of its smallest key, and the registry in (8) keeps it on every later run; (3) data/real/label_me.csv: one row per group that still has unlabelled
messages, bucket by bucket (8), biggest first, two examples (links defanged), blank label column (scam / genuine / skip). No model score is ever written there;
(4) a rerun reads your filled label_me.csv (or the one src/label_real.py fills) and gives every message of a group its label (labels you filled in
are never overwritten); (5) each group keeps at most --cap (3) messages, exact duplicates once, with group_id and group_size so eval can report per
message and per group; (6) names are NOT masked automatically: rows with likely names go to data/real/review_names.csv, your edits (replace_with
"<NAME>" masks the token, "DROP" drops the row, "ok" marks a reviewed non-name) are applied on rerun; --freeze needs none left blank; greeting names
seen in many templates are masked everywhere and listed in data/real/auto_names.txt (never printed); (7) overlap: each candidate against the TRAIN
split of data/final/messages.csv with the same near-duplicate rule (overlap True/False, rows are never dropped for it); (8) label_priority: every
group in label_me.csv gets a bucket (1 = the 150 largest, 2 = every other group with a mobile_number sender, scam-enriched by design, 3 = a random
150 of the rest, 4 = the rest), fixed by a seed and stored in label_me_state.json with the group registry (key hashes -> group_id): a rerun or a
new phone file never renames, merges or re-buckets a group that exists; new groups are bucketed on arrival; src/label_real.py walks the buckets in
order. Before the freeze the labelled rows go to data/real/labelled_preview.csv; real_test_v1.csv does not exist yet. (9) --freeze, once: the
labelled groups are split 50/50 by template group (groups with a near-duplicate pair between any of their messages move together), stratified by
label x keyword bucket (investment / task / loan / kyc-bank / delivery / other), and checked again with an independent seed. TEST half ->
data/real/real_test_v1.csv (frozen, hash in CLAUDE.md, realguard-protected, at most 3 messages per group with group_size); POOL half ->
data/collected/phones/pool.csv (group ids, source = phone_N; allowed for training / validation in splits-v3); data/real/freeze_manifest.json holds
the split. --allow-unlabelled leaves out bucket 4 only. A second --freeze is refused. After the freeze a rerun never touches the test file: new
phone files and new labels go to the pool; a message of a TEST group, or a near-duplicate of any TEST message, is dropped and counted.
Tripwire: realguard.py. The output's source_row_hash is the key training scripts refuse on. Report: reports/real_intake_v1.md (no text).
"""
import argparse, csv, datetime as dt, functools, hashlib, io, json, os, random, re, sys, unicodedata
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]
import pandas as pd
import pii
import realguard
from audit_investment import CRYPTO_RX, INVEST_RX, TASK_RX
from neardup import CHECK_SEED, CLUSTER_SEED, near_dup_pairs_any, shingle_sets
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
POOL_DIR = ROOT / "data" / "collected" / "phones"   # the POOL half of the freeze split: training / validation material, not guarded by realguard
MANIFEST_NAME = "freeze_manifest.json"             # next to the test file: the split (seeds, TEST / POOL group ids, TEST key hashes); its presence means "frozen"
PREVIEW_NAME = "labelled_preview.csv"              # before the freeze the labelled rows go here, never to real_test_v1.csv
AUTO_NAMES_NAME = "auto_names.txt"                 # the greeting names masked everywhere (names: never printed or reported)
NOT_RECEIVED, MMS_DROP = "not a received message (type != 1)", "MMS element (only <sms> is read)"
TEST_GROUP_DROP, TEST_NEAR_DROP = "group is in the frozen TEST half", "near-duplicate of a TEST message"
OUT_COLS = ["id", "text", "label", "language", "category", "overlap", "source_row_hash", "source", "source_type", "sender_kind", "group_id", "group_size",
            "label_priority", "kw_bucket"]
POOL_COLS = OUT_COLS + ["provenance", "is_synthetic"]
LABEL_COLS = ["group_id", "size", "label_priority", "example_1", "example_2", "example_similarity", "sender_kind_mix", "sources", "label"]
PRIORITY_SEED = 20261025   # label_priority bucket 3 is the PRIORITY_N3 groups with the smallest md5(seed|group_id); written to the report
PRIORITY_N1, PRIORITY_N3 = 150, 150
SPLIT_SEED = 20261026      # freeze split: which half of each (label x keyword) stratum a group goes to; written to the manifest and the report
KW_BUCKETS = ["investment", "task", "loan", "kyc-bank", "delivery", "other"]   # first match wins, in this order
LOAN_RX = re.compile(r"(?i)\b(?:loans?|emi|pre-?approved|instant cash|cibil|credit score|credit limit|borrow\w*|disburs\w*|interest rate)\b")
KYC_BANK_RX = re.compile(r"(?i)\b(?:kyc|a/c|acct?|account|debited|credited|upi|neft|imps|rtgs|bank|atm|net ?banking|ifsc|pan|aadhaar|aadhar|otp|balance|withdraw\w*|"
                         r"transaction|txn|statement|card)\b|<ACCOUNT>|<OTP>|<UPI_ID>")
DELIVERY_RX = re.compile(r"(?i)\b(?:deliver\w*|parcel|courier|shipment|shipped|dispatch\w*|order|tracking|awb|consignment|package|pick-?up)\b")
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


def flat(obj):
    """Every key and leaf value of a JSON-like object, as strings (each one scanned on its own: hex ids glued together are not a number)."""
    if isinstance(obj, dict):
        return [x for k, v in obj.items() for x in [str(k)] + flat(v)]
    if isinstance(obj, (list, tuple, set)):
        return [x for v in obj for x in flat(v)]
    return [str(obj)]


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
            drops[(source, MMS_DROP)] += 1
            continue
        if el.get("type") != "1":
            drops[(source, NOT_RECEIVED)] += 1
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

@functools.lru_cache(maxsize=4)
def in_link_rx(name_rx):
    """name_rx for the inside of a link: a name ends at any non-letter there (/u/Name123/, ?ref=Name_2), not only at a non-word character."""
    return re.compile(name_rx.pattern.replace(r"(?<!\w)", r"(?<![^\W\d_])").replace(r"(?!\w)", r"(?![^\W\d_])"), name_rx.flags)

def mask(text, name_rx=None):
    """src/pii.py masks (emails and UPI ids first, then phones and accounts) with URLs kept, plus card, OTP, account-tail and long digit
    runs, and every contact / sender name seen in the input (name_rx) as <NAME>, inside links too (a link keeps its host and shape, never a
    name: /u/<NAME>/orders)."""
    t = text
    for pat, tok in ADDRESS_MASKS:
        t = re.sub(pat, tok, t)
    t, urls = protect_urls(t)
    if name_rx is not None:
        t = name_rx.sub("<NAME>", t)
        urls = [in_link_rx(name_rx).sub("<NAME>", u) for u in urls]
    t = CARD_RX.sub("<ACCOUNT>", t)
    t = OTP_RX.sub(lambda m: m.group(0)[: m.start(2) - m.start(0)] + "<OTP>", t)
    t = OTP_BEFORE_RX.sub("<OTP>", t)
    t = ACCT_TAIL_RX.sub(lambda m: m.group(1) + "<ACCOUNT>", t)
    t = XX_TAIL_RX.sub("<ACCOUNT>", t)
    for pat, tok in NUMBER_MASKS:
        t = re.sub(pat, tok, t)
    t = URL_PHONE_RX.sub(lambda m: m.group(1) + "<PHONE>", restore_urls(t, urls))
    if name_rx is not None:
        t = name_rx.sub("<NAME>", t)   # once more over the whole text: nothing the link protection kept back may hold a name
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


def key_hash(key):
    """What the group registry stores for one template key: md5 of the key, 16 hex. Never the key itself."""
    return hashlib.md5(key.encode()).hexdigest()[:16]


def make_groups(recs, registry=None, stats=None):
    """Sets rec['gkey'] and rec['group']. Two keys join one group when src/neardup.py calls them near-duplicates (exact Jaccard >= 0.7 on char
    5-grams, raw or normalised view). registry ({key hash: group_id}, kept in label_me_state.json and updated in place) keeps a group fixed once
    it exists: a key seen before stays in its group, two existing groups never merge (a new message like both joins the one it is most like:
    pairs are taken from the most similar down), and only a group made of new keys gets a new id, a hash of its smallest key. On the first run
    every group is new, so the ids do not depend on the order of the files. A new phone file therefore never renames, merges or splits a group
    that has a label, a bucket or a side of the freeze split.
    -> groups. stats (a dict, optional) gets new_keys, joined_existing, new_groups and kept_apart (pairs of existing groups a new message is like both of)."""
    registry = {} if registry is None else registry
    keys = sorted({group_key(r["masked"]) for r in recs})
    hashes = [key_hash(k) for k in keys]
    parent = list(range(len(keys)))
    tag = {i: registry[h] for i, h in enumerate(hashes) if h in registry}   # root -> the existing group it belongs to
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a, b):
        a, b = find(a), find(b)
        if a == b:
            return True
        ta, tb = tag.get(a), tag.get(b)
        if ta is not None and tb is not None and ta != tb:
            return False
        r, o = min(a, b), max(a, b)
        parent[o] = r
        tag.pop(o, None)
        if (ta if ta is not None else tb) is not None:
            tag[r] = ta if ta is not None else tb
        return True
    first = {}
    for i in sorted(tag):   # the keys of one existing group stay together even when the message that linked them is gone
        g = tag[i]
        if g in first:
            union(first[g], i)
        else:
            first[g] = i
    best = {}
    if len(keys) > 1:
        for i, j, jac, _ in near_dup_pairs_any(keys, ["real"] * len(keys), CLUSTER_SEED):
            p = (min(i, j), max(i, j))
            best[p] = max(best.get(p, 0.0), jac)
    kept_apart = set()
    for (i, j), _ in sorted(best.items(), key=lambda kv: (-kv[1], kv[0])):
        if not union(i, j):
            kept_apart.add(frozenset((tag[find(i)], tag[find(j)])))
    used, new_ids, gid_of = set(registry.values()), set(), {}
    for root in sorted({find(i) for i in range(len(keys))}):
        if root in tag:
            gid_of[root] = tag[root]
            continue
        g = "G" + hashlib.md5(keys[root].encode()).hexdigest()[:8]
        if g in used or g in new_ids:
            stop("two template groups got the same group_id (hash collision)")
        new_ids.add(g)
        gid_of[root] = g
    new_keys = [i for i, h in enumerate(hashes) if h not in registry]
    if stats is not None:
        stats.update(new_keys=len(new_keys), joined_existing=sum(find(i) in tag for i in new_keys), new_groups=len(new_ids), kept_apart=len(kept_apart))
    gid = {}
    for i, (k, h) in enumerate(zip(keys, hashes)):
        gid[k] = registry[h] = gid_of[find(i)]
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


def top_text(members):
    """The most common masked text of a group (the same pick_examples makes for example 1)."""
    cnt = Counter(r["masked"] for r in members)
    return min(cnt, key=lambda t: (-cnt[t], realguard.norm_key(t)))


def kw_bucket(text):
    """Keyword bucket of one message text: investment (INVEST_RX / CRYPTO_RX), task, loan, kyc-bank, delivery, else other. Used only to
    stratify the freeze split; a keyword hit is not a label."""
    if INVEST_RX.search(text) or CRYPTO_RX.search(text):
        return "investment"
    for name, rx in (("task", TASK_RX), ("loan", LOAN_RX), ("kyc-bank", KYC_BANK_RX), ("delivery", DELIVERY_RX)):
        if rx.search(text):
            return name
    return "other"


def hkey(gid):
    """A fixed pseudo-random number in [0, 1) per group (md5 of seed and id): the random draw behind label_priority 3."""
    return int(hashlib.md5(f"{PRIORITY_SEED}|{gid}".encode()).hexdigest()[:12], 16) / 16 ** 12


def load_state(path):
    """The labelling state next to the label sheet (label_me_state.json): the bucket of every group ("assigned"), the thresholds new groups are
    bucketed by, and the group registry ("keys": key hash -> group_id, make_groups). Ids, hashes and numbers only, no text."""
    if path.exists():
        st = json.loads(path.read_text(encoding="utf-8"))
        made = (st.get("seed"), st.get("n_largest"), st.get("n_random"))
        if made != (PRIORITY_SEED, PRIORITY_N1, PRIORITY_N3):
            stop(f"{path.name} was made with seed / sizes {made}, this script uses {(PRIORITY_SEED, PRIORITY_N1, PRIORITY_N3)}; changing them would reshuffle the buckets")
        st.setdefault("keys", {})
        return st
    return {"seed": PRIORITY_SEED, "n_largest": PRIORITY_N1, "n_random": PRIORITY_N3, "b1_min_size": None, "b3_max_key": None, "assigned": {}, "keys": {}}


def atomic_write(path, text):
    """Write next to the file and rename over it: a reader (src/label_real.py, a crash) sees the old file or the new one, never half of one."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def assign_priorities(infos, state, old_rows):
    """label_priority per group: 1 = the PRIORITY_N1 largest groups; 2 = every remaining group with a mobile_number sender (scam-enriched by
    design); 3 = a random PRIORITY_N3 of the rest (smallest hkey); 4 = the rest. infos: {group_id: (size, has_mobile_sender)}.
    The first call assigns by that exact rule. Every later call keeps what is in `state` (or in the label sheet's own label_priority column
    when the state file is gone) and puts only the groups it has not seen before into a bucket, by the thresholds the first call left: size
    above the smallest bucket-1 group -> 1, mobile sender -> 2, hkey up to the largest bucket-3 key -> 3, else 4 (a bucket that was not full
    yet is filled first). So a new phone file never moves an existing group. -> ({group_id: priority}, number of groups newly bucketed)."""
    assigned = state["assigned"]
    for gid, r in old_rows.items():
        v = (r.get("label_priority") or "").strip()
        if gid not in assigned and v in ("1", "2", "3", "4"):
            assigned[gid] = int(v)
    new = sorted((g for g in infos if g not in assigned), key=lambda g: (-infos[g][0], g))
    if new and not assigned:
        top = new[:PRIORITY_N1]
        for g in top:
            assigned[g] = 1
        state["b1_min_size"] = infos[top[-1]][0]
        rest = new[PRIORITY_N1:]
        for g in rest:
            if infos[g][1]:
                assigned[g] = 2
        pool = sorted((g for g in rest if not infos[g][1]), key=hkey)
        b3 = pool[:PRIORITY_N3]
        for g in b3:
            assigned[g] = 3
        for g in pool[PRIORITY_N3:]:
            assigned[g] = 4
        state["b3_max_key"] = hkey(b3[-1]) if b3 else -1.0
    else:
        n1 = sum(v == 1 for v in assigned.values())
        n3 = sum(v == 3 for v in assigned.values())
        for g in new:
            size, mobile = infos[g]
            if n1 < PRIORITY_N1 or size > (state["b1_min_size"] or 0):
                assigned[g] = 1
                n1 += 1
                state["b1_min_size"] = size if state["b1_min_size"] is None else min(state["b1_min_size"], size)
            elif mobile:
                assigned[g] = 2
            elif n3 < PRIORITY_N3 or hkey(g) <= (state["b3_max_key"] if state["b3_max_key"] is not None else -1.0):
                assigned[g] = 3
                n3 += 1
                state["b3_max_key"] = max(hkey(g), state["b3_max_key"] if state["b3_max_key"] is not None else -1.0)
            else:
                assigned[g] = 4
    return {g: assigned[g] for g in infos}, len(new)


def label_rows(groups, need, old_rows, prio=None):
    """One row per group that still has an unlabelled message, bucket by bucket (label_priority), biggest first inside a bucket. Rows already in
    the file keep their label; a labelled row whose group no longer exists is kept at the end (orphan), never dropped."""
    prio = prio or {}
    rows = []
    for gid in need:
        members = groups[gid]
        e1, e2, sim = pick_examples(members)
        rows.append({"group_id": gid, "size": len(members), "label_priority": prio.get(gid, 4), "example_1": sheet_text(e1), "example_2": sheet_text(e2) if e2 else "",
                     "example_similarity": sim, "sender_kind_mix": mix(Counter(r["sender_kind"] for r in members)), "sources": mix(Counter(r["source"] for r in members)),
                     "label": (old_rows.get(gid, {}).get("label") or "").strip()})
    rows.sort(key=lambda r: (r["label_priority"], -r["size"], r["group_id"]))
    listed = {x["group_id"] for x in rows}
    orphans = [r for gid, r in old_rows.items() if gid not in listed and (r.get("label") or "").strip()]
    return rows, [{k: o.get(k, "") for k in LABEL_COLS} for o in orphans]


# ---------------------------------------------------------------------------------------------------------------- the freeze split

def text_pairs(texts, owners, seeds):
    """{(i, j)}: index pairs of texts with different owners (template groups, or the two sides of the split) that src/neardup.py calls
    near-duplicates under any of `seeds`, on two views: the text with links as <URL> (textprep.model_text) and the digit-collapsed group key."""
    out = set()
    if len(texts) < 2:
        return out
    for view in (model_text, group_key):
        vt = [view(t) for t in texts]
        for seed in seeds:
            for i, j, _, _ in near_dup_pairs_any(vt, ["real"] * len(vt), seed, skip=lambda i, j: owners[i] == owners[j]):
                out.add((min(i, j), max(i, j)))
    return out


def grouped_split(final, keys_by_group, seed=SPLIT_SEED):
    """Split the labelled groups 50/50 into TEST and POOL. The unit is the template group, and groups with a near-duplicate pair between them are
    one unit: every message of every labelled group is looked at (its digit-collapsed key, keys_by_group), not only the <= 3 stored rows, under
    the grouping seed and an independent one (CHECK_SEED). Groups can be near-duplicates of each other when a later phone file brought a message
    like two existing groups (make_groups keeps them apart). Units are stratified by label x keyword bucket: inside a stratum they are sorted by
    size, taken in pairs, and a seeded coin decides which of the pair goes to TEST (an odd one out is a coin flip too).
    -> {"test": group ids, "pool": group ids, "strata": {(label, kw): [test units, pool units]}, "merged_units": n, "mixed_units": n}."""
    gids = sorted({r["group"] for r in final})
    parent = {g: g for g in gids}
    def find(g):
        while parent[g] != g:
            parent[g] = parent[parent[g]]
            g = parent[g]
        return g
    texts = [r["final"] for r in final] + [k for g in gids for k in sorted(keys_by_group[g])]
    owners = [r["group"] for r in final] + [g for g in gids for _ in keys_by_group[g]]
    for i, j in sorted(text_pairs(texts, owners, (CLUSTER_SEED, CHECK_SEED))):
        a, b = find(owners[i]), find(owners[j])
        if a != b:
            parent[max(a, b)] = min(a, b)
    units = defaultdict(list)
    for g in gids:
        units[find(g)].append(g)
    by_group = defaultdict(list)
    for r in final:
        by_group[r["group"]].append(r)
    size_of = lambda g: by_group[g][0]["group_size"]
    strata, mixed = defaultdict(list), 0
    for u, gs in units.items():
        lab = Counter(r["label"] for g in gs for r in by_group[g])
        if len(lab) > 1:
            mixed += 1
        label = max(lab, key=lambda l: (lab[l], l))
        big = max(gs, key=lambda g: (size_of(g), g))
        strata[(label, by_group[big][0]["kw_bucket"])].append((u, sum(size_of(g) for g in gs)))
    test, pool, counts = set(), set(), {}
    for key in sorted(strata, key=str):
        us = sorted(strata[key], key=lambda x: (-x[1], x[0]))
        rng = random.Random(f"{seed}|{key[0]}|{key[1]}")
        t = p = 0
        for k in range(0, len(us), 2):
            pair = [x[0] for x in us[k:k + 2]]
            if len(pair) == 2:
                rng.shuffle(pair)
                to_test, to_pool = [pair[0]], [pair[1]]
            else:
                to_test, to_pool = ([pair[0]], []) if rng.random() < 0.5 else ([], [pair[0]])
            for u in to_test:
                test.update(units[u]); t += 1
            for u in to_pool:
                pool.update(units[u]); p += 1
        counts[key] = [t, p]
    return {"test": test, "pool": pool, "strata": counts, "merged_units": len(gids) - len(units), "mixed_units": mixed}


def verify_disjoint(test_rows, pool_rows, keys_by_group):
    """(groups on both sides, near-duplicate pairs across the two sides), by an independent look: a seed neither the grouping nor the split used,
    over the stored rows and every message key of the groups on each side."""
    tg, pg = {r["group"] for r in test_rows}, {r["group"] for r in pool_rows}
    texts = [r["final"] for r in test_rows] + [k for g in sorted(tg) for k in sorted(keys_by_group[g])]
    owners = ["test"] * len(texts)
    texts += [r["final"] for r in pool_rows] + [k for g in sorted(pg) for k in sorted(keys_by_group[g])]
    owners += ["pool"] * (len(texts) - len(owners))
    return len(tg & pg), len(text_pairs(texts, owners, (CHECK_SEED + 1,)))


def near_test_flags(texts, test_texts):
    """True for each text that is a near-duplicate of a TEST text (raw and digit-collapsed views, the grouping seed and the independent one)."""
    flags = [False] * len(texts)
    if not texts or not test_texts:
        return flags
    n0 = len(test_texts)
    for view in (model_text, group_key):
        allt = [view(t) for t in test_texts + texts]
        for seed in (CLUSTER_SEED, CHECK_SEED):
            for i, j, _, _ in near_dup_pairs_any(allt, ["real"] * len(allt), seed, skip=lambda i, j: (i < n0) == (j < n0), queries=range(n0, len(allt))):
                flags[max(i, j) - n0] = True
    return flags


def read_rows(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


# ---------------------------------------------------------------------------------------------------------------- the run

def run(inputs=None, out=OUT, review=REVIEW, report=REPORT, freeze=False, messages=MESSAGES, label_file=LABEL_ME, cap=CAP, allow_unlabelled=False, names_file=NAMES_FILE,
        allow_open_names=False, pool_dir=None):
    """Three modes. preview (before the freeze): the labelled rows go to labelled_preview.csv next to `out`, nothing is split and `out` is not
    written. freeze (freeze=True, once): the labelled groups are split 50/50 (grouped_split); freeze_manifest.json (next to `out`) records the
    split, the TEST half goes to `out` and its SHA-256 into CLAUDE.md, the POOL half to pool_dir/pool.csv. post (a manifest exists): `out` is never
    touched; labelled messages go to the pool, except a message of a TEST group or a near-duplicate of any TEST message (dropped and counted), and
    a row with a name candidate not reviewed yet (held back until review_names.csv has an answer). A second freeze is refused.
    -> (SHA-256 of the file written for the test side: the preview, the new test file, or the frozen one; the rows kept)."""
    inputs = [RAW_DIR] if inputs is None else ([inputs] if isinstance(inputs, (str, Path)) else list(inputs))
    for p in inputs:
        if not Path(p).exists():
            stop(f"{p} does not exist (the exports go in data/real/raw/; the folder is git-ignored)")
        check_input_path(p)
    out = Path(out)
    real_target = out.resolve() == OUT.resolve()
    claude_is_real = Path(CLAUDE).resolve() == (ROOT / "CLAUDE.md").resolve()
    if freeze and not real_target and claude_is_real:
        stop(f"a freeze of {out} (not data/real/real_test_v1.csv) would write its hash into the project's CLAUDE.md; point intake_real.CLAUDE at a copy first")
    claude_hash = frozen_hash() if (real_target or not claude_is_real) else None
    manifest_path = out.parent / MANIFEST_NAME
    preview_path = out.with_name(PREVIEW_NAME)
    pool_dir = Path(pool_dir) if pool_dir else (POOL_DIR if real_target else out.parent / "pool")
    pool_path = pool_dir / "pool.csv"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else None
    if freeze and (manifest or claude_hash):
        stop(f"already frozen ({manifest_path.name if manifest else 'CLAUDE.md'} holds the split): a second --freeze is refused. Changing the frozen test set needs a decision, "
             "not a rerun. New phones and screenshots go to the pool by a plain rerun.")
    if claude_hash and not manifest:
        stop(f"CLAUDE.md freezes a real test set but {manifest_path.name} is missing; restore it (it holds the split) before any rerun")
    if manifest and (not out.exists() or hashlib.sha256(out.read_bytes()).hexdigest() != manifest["test_sha256"]):
        stop(f"{out.name} is missing or no longer matches the hash in {manifest_path.name}; the frozen test set must not change. Restore it, do not rerun over it")
    mode = "post" if manifest else "freeze" if freeze else "preview"
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
    received = {src: n - sum(v for (s_, why), v in drops.items() if s_ == src and why in (NOT_RECEIVED, MMS_DROP)) for src, n in read.items()}

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
    auto_path = label_file.with_name(AUTO_NAMES_NAME)
    if auto:   # the words themselves go to a git-ignored file, never to the terminal or the report
        atomic_write(auto_path, "# words masked as names everywhere because they follow a greeting in many messages; written by src/intake_real.py on every run.\n"
                                f"# a wrong one: add '-word' to {Path(names_file).name}\n" + "".join(w + "\n" for w in auto))
        print(f"{len(auto)} words masked as names everywhere because they follow a greeting in many messages: listed in {auto_path.name} (a wrong one: add '-word' to {Path(names_file).name})")
    elif auto_path.exists():
        auto_path.unlink()
    state_path = label_file.with_name(label_file.stem + "_state.json")
    state = load_state(state_path)
    known_before = set(state["keys"].values())
    gstats = {}
    groups = make_groups(recs, state["keys"], gstats)
    vanished = sorted(known_before - set(groups))

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
    infos = {gid: (len(groups[gid]), any(r["sender_kind"] == "mobile_number" for r in groups[gid])) for gid in need}
    prio, n_new_prio = assign_priorities(infos, state, old_rows)
    kw = {gid: kw_bucket(top_text(m)) for gid, m in groups.items()}
    sheet, orphans = label_rows(groups, need, old_rows, prio)
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
    all_cands_names = Counter(r["id"] for r in cands for _ in name_tokens(r["masked"], vocab))   # counts only: what the review will ask once every group is labelled
    new_rows = [v for k, v in current.items() if k not in review_rows]
    merged = {**review_rows, **{k: v for k, v in current.items() if k not in review_rows}}
    open_ids = {k[0] for k, v in merged.items() if k in current and not v["replace_with"].strip()}   # blank = not looked at yet
    open_names = sum(1 for k, v in merged.items() if k in current and not v["replace_with"].strip())
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
        r["label_priority"] = prio.get(r["group"], "")
        r["kw_bucket"] = kw[r["group"]]
        final.append(r)

    # overlap with TRAIN for every candidate (the report counts unlabelled groups too); rows are never dropped for it
    flags = overlap_flags([r["masked"] for r in cands], messages) if cands else []
    for r, o in zip(cands, flags):
        r["overlap"] = bool(o)
    for r in final:
        r["hash"] = realguard.norm_key(r["final"])
    final.sort(key=lambda r: (-r["group_size"], r["group"], r["hash"]))
    keys_by_group = {gid: {r["gkey"] for r in m} for gid, m in groups.items()}

    # after a freeze nothing reaches the test set: a message of a TEST group (by id, or by a key that was in a TEST group at the freeze) or a
    # near-duplicate of any TEST message is dropped; a row whose name candidates are not reviewed yet waits; the rest is the pool
    if mode == "post":
        test_gids, test_kh = set(manifest["test_group_ids"]), set(manifest.get("test_key_hashes", []))
        in_test = lambda r: r["group"] in test_gids or key_hash(r["gkey"]) in test_kh
        ref = [r["text"] for r in read_rows(out)] + sorted({r["gkey"] for r in recs if in_test(r)})
        near = near_test_flags([r["final"] for r in final], ref)
        keep = []
        for r, nr in zip(final, near):
            if in_test(r):
                drops[(r["source"], TEST_GROUP_DROP)] += 1
            elif nr:
                drops[(r["source"], TEST_NEAR_DROP)] += 1
            elif r["id"] in open_ids and not allow_open_names:
                drops[(r["source"], "name candidate not reviewed yet (review_names.csv): held back from the pool")] += 1
            else:
                keep.append(r)
        final = keep

    if sum(read.values()) != len(final) + sum(drops.values()):
        stop(f"row accounting does not balance: read {sum(read.values())}, kept {len(final)}, dropped {sum(drops.values())}")

    freeze_error = None
    if freeze:
        blank_123 = [g for g in unlabelled_groups if prio.get(g, 4) <= 3]
        if not final:
            freeze_error = "--freeze needs at least one labelled row"
        elif unlabelled_groups and not allow_unlabelled:
            freeze_error = (f"--freeze: {len(unlabelled_groups)} groups in {label_file.name} still have no label (scam / genuine / skip). Label them, or pass --allow-unlabelled "
                            "to freeze without bucket 4 (its messages are then left out of both halves)")
        elif blank_123:
            freeze_error = (f"--freeze: {len(blank_123)} groups in label_priority buckets 1-3 still have no label; --allow-unlabelled leaves out bucket 4 only. "
                            "Label them with src/label_real.py first")
        elif open_names and not allow_open_names:
            freeze_error = (f"--freeze: {open_names} name candidates in {review.name} are still blank. Write <NAME> to mask a token, DROP to drop its row, or ok when it is not a name "
                            "(fill the column with ok, then fix the real names); or pass --allow-open-names to freeze with them as written")

    split = None
    test_final, pool_final = final, []
    if mode == "freeze" and not freeze_error:
        split = grouped_split(final, keys_by_group)
        test_final = [r for r in final if r["group"] in split["test"]]
        pool_final = [r for r in final if r["group"] in split["pool"]]
        both, cross = verify_disjoint(test_final, pool_final, keys_by_group)
        if both or cross or len(test_final) + len(pool_final) != len(final):
            stop(f"the split failed its own check ({both} groups on both sides, {cross} near-duplicate pairs across it); nothing was written")
    elif mode == "post":
        test_final, pool_final = [], final

    inv = {"investment": INVEST_RX, "crypto": CRYPTO_RX, "task": TASK_RX}
    inv_groups = {k: sum(any(rx.search(r["masked"]) for r in m) for m in groups.values()) for k, rx in inv.items()}
    inv_groups["any"] = sum(any(rx.search(r["masked"]) for rx in inv.values() for r in m) for m in groups.values())

    to_row = lambda r: {"id": r["id"], "text": r["final"], "label": r["label"], "language": r["language"], "category": r["category"], "overlap": r["overlap"],
                        "source_row_hash": r["hash"], "source": r["source"], "source_type": r["source_type"], "sender_kind": r["sender_kind"],
                        "group_id": r["group"], "group_size": r["group_size"], "label_priority": r["label_priority"], "kw_bucket": r["kw_bucket"],
                        "provenance": "real_circulating", "is_synthetic": False}
    out_rows = [to_row(r) for r in test_final]
    pool_rows = [to_row(r) for r in pool_final]
    out_text = csv_text(OUT_COLS, out_rows)
    pool_text = csv_text(POOL_COLS, pool_rows)
    sheet_text_csv = csv_text(LABEL_COLS, sheet + orphans)
    state_text = json.dumps(state, indent=1, sort_keys=True)
    review_rows_out = list(merged.values())
    man = None
    if mode == "freeze" and not freeze_error:
        man = {"version": 1, "frozen_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ"), "split_seed": SPLIT_SEED, "priority_seed": PRIORITY_SEED, "cap": cap,
               "test_sha256": hashlib.sha256(out_text.encode("utf-8")).hexdigest(), "test_rows": len(out_rows), "pool_rows_at_freeze": len(pool_rows),
               "pool_sha256_at_freeze": hashlib.sha256(pool_text.encode("utf-8")).hexdigest(), "test_group_ids": sorted(split["test"]), "pool_group_ids": sorted(split["pool"]),
               "test_key_hashes": sorted({key_hash(k) for g in split["test"] for k in keys_by_group[g]}),
               "strata": {f"{k[0]}|{k[1]}": v for k, v in sorted(split["strata"].items(), key=str)}}
    pinfo = dict(prio=prio, state=state, new=n_new_prio, need=need, labels=labels, groups=groups, gstats=gstats, vanished=vanished)
    summary = summarise(files, read, drops, groups, need, labels, unlabelled_groups, stale, orphans, cands, final, inv_groups, current, review_rows, new_rows, applied,
                        form_info, open_names, sens_counts=(len(sens.phones), len(sens.names), len(auto), len(extra)))
    summary.update(mode=mode, split=split, test_final=test_final, pool_final=pool_final, pinfo=pinfo, manifest=manifest or man, received=received,
                   all_cands_names=all_cands_names, preview_name=preview_path.name)
    sha = manifest["test_sha256"] if mode == "post" else (hashlib.sha256(out_text.encode("utf-8")).hexdigest() if test_final else None)
    report_text = write_summary(summary, sha, out)

    # nothing is written until every output has been checked for the phone numbers and names that were in the input
    scan_outputs(sens, {out.name: [r["text"] for r in out_rows], pool_path.name: [r["text"] for r in pool_rows],
                        label_file.name: [r[c] for r in sheet + orphans for c in ("example_1", "example_2")],
                        review.name: [r["context"] for r in review_rows_out], report.name: report_text.splitlines(),
                        state_path.name: flat(state), MANIFEST_NAME: flat(man or {})})
    atomic_write(label_file, sheet_text_csv)
    atomic_write(state_path, state_text)
    write_review(review, review_rows_out)
    shown = lambda p: p.relative_to(ROOT) if p.is_relative_to(ROOT) else p
    if mode == "freeze" and not freeze_error:
        atomic_write(manifest_path, json.dumps(man, indent=1))   # first: from here on a rerun is "post", and stops until the test file below matches it
        atomic_write(pool_path, pool_text)
        atomic_write(out, out_text)
        if preview_path.exists():
            preview_path.unlink()
        freeze_hash(sha, len(out_rows), f"- `{shown(pool_path)}`: the POOL half ({len(pool_rows)} rows at freeze, {len(split['pool'])} template groups; grows when a new phone or screenshots are added). "
                    f"Allowed for training / validation in splits-v3; shares no template group and no near-duplicate with the test file (`{shown(manifest_path)}`).")
    elif mode == "post":
        atomic_write(pool_path, pool_text)
    elif final:
        atomic_write(preview_path, out_text)
    elif preview_path.exists():
        preview_path.unlink()
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(report_text, encoding="utf-8")
    print(f"{len(cands)} candidate messages in {len(groups)} template groups; {len(need)} groups need a label ({len(unlabelled_groups)} still blank) -> {shown(label_file)}")
    if mode == "post":
        print(f"frozen test set untouched ({manifest['test_rows']} rows, sha256 {sha}); pool: {len(pool_rows)} rows -> {shown(pool_path)}")
    elif mode == "freeze" and not freeze_error:
        print(f"FROZEN: test {len(out_rows)} rows from {len(split['test'])} groups -> {shown(out)}\nsha256 {sha}\npool {len(pool_rows)} rows from {len(split['pool'])} groups -> {shown(pool_path)}")
    elif final:
        print(f"{len(final)} labelled rows -> {shown(preview_path)} (a preview: nothing is split and {out.name} is written only by --freeze)")
    else:
        print("no group is labelled yet: next, label with src/label_real.py")
    if freeze_error:
        stop(freeze_error)
    return sha, final


def summarise(files, read, drops, groups, need, labels, unlabelled_groups, stale, orphans, cands, final, inv_groups, current, review_rows, new_rows, applied, form_info, open_names, sens_counts):
    return dict(files=files, read=read, drops=drops, groups=groups, need=need, labels=labels, unlabelled_groups=unlabelled_groups, stale=stale, orphans=orphans,
                cands=cands, final=final, inv=inv_groups, current=current, review_rows=review_rows, new_rows=new_rows, applied=applied, form_info=form_info, open_names=open_names, sens=sens_counts)


def write_summary(s, sha, out):
    final, cands, groups, drops, read = s["final"], s["cands"], s["groups"], s["drops"], s["read"]
    mode, split, pinfo = s["mode"], s["split"], s["pinfo"]
    test_final, pool_final = s["test_final"], s["pool_final"]
    L = ["# Real-message intake v1\n",
         f"*Generated by `src/intake_real.py` on {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC. No message text, no file name, no number and no name "
         "in this report: texts are in `data/real/` (label_me.csv, the preview or the test file) and the pool file (all git-ignored).*\n",
         f"Mode: **{mode}** ({'not frozen: the labelled rows go to ' + s['preview_name'] + ' as a preview, nothing is split, real_test_v1.csv is not written' if mode == 'preview' else 'the labelled groups were split 50/50 into TEST and POOL just now' if mode == 'freeze' else 'the test set is frozen and untouched; new messages go to the pool only'}).\n",
         f"Files read: {len(s['files']['csv'])} Form CSV, {len(s['files']['xml'])} SMS Backup & Restore XML, {len(s['files']['txt'])} WhatsApp text. "
         f"Not read (other file types): {len(s['files']['other'])}.\n"]
    for roles, dropped_cols in s["form_info"]:
        L.append(f"Form columns mapped: {', '.join(f'{r} <- {c!r}' for r, c in roles.items())}. Dropped before anything else: {', '.join(repr(c) for c in dropped_cols) or 'none'}.\n")
    L.append("## Rows read per source\n")
    kept_t, kept_p, cand = Counter(r["source"] for r in test_final), Counter(r["source"] for r in pool_final), Counter(r["source"] for r in cands)
    dropped = Counter()
    for (src, _), n in drops.items():
        dropped[src] += n
    rec = s["received"]
    L += [f"| source | type | read | received | candidates (before labelling) | kept: {'labelled (preview)' if mode == 'preview' else 'test'} | kept: pool | dropped |",
          "|---|---|---:|---:|---:|---:|---:|---:|"]
    for src in sorted(read):
        L.append(f"| {src} | {'sms' if src.startswith('phone_') else 'whatsapp' if src.startswith('wa_') else 'form'} | {read[src]} | {rec[src]} | {cand[src]} | {kept_t[src]} | {kept_p[src]} | {dropped[src]} |")
    L.append(f"| **all** | | {sum(read.values())} | {sum(rec.values())} | {len(cands)} | {len(test_final)} | {len(pool_final)} | {sum(drops.values())} |\n")
    L.append("*read = every <sms> / <mms> element (SMS), chat line (WhatsApp) or row (Form); received = read minus sent messages and MMS. Candidates = what is left "
             "after the read filters, exact duplicates and the per-group cap: the rows that get a label from their group. read = kept + dropped; before labelling, "
             "every candidate is dropped as 'group not labelled yet'.*\n")
    L.append("## Kept vs dropped, and why\n")
    L.append(f"- Read {sum(read.values())}. **Kept {len(test_final) + len(pool_final)}** (test {len(test_final)}, pool {len(pool_final)}). Dropped {sum(drops.values())}.")
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
    phone_span = sum(len({r["source"] for r in m if r["source"].startswith("phone_")}) >= 2 for m in groups.values())
    L.append(f"- Groups that appear on two or more phones: **{phone_span}** of {len(groups)}.")
    L.append(f"- Each group keeps at most {CAP} messages (exact duplicates once), in the test file and in the pool alike: {len(final)} rows from {len({r['group'] for r in final})} groups; "
             f"`group_size` in the files is the whole group, so eval can report per message and per group and training can weight.")
    L.append(f"- Groups with a message to label: {len(s['need'])}. Labelled in `label_me.csv`: {sum(g in s['labels'] for g in s['need'])} "
             f"(skip: {sum(s['labels'].get(g) == 'skip' for g in s['need'])}), still blank: **{len(s['unlabelled_groups'])}**. "
             f"Labels in the file that match no group: {len(s['stale'])} (kept at the end of the file: {len(s['orphans'])}).")
    L.append(f"- Phone numbers and names seen in the input and masked wherever they appear: {s['sens'][0]} numbers, {s['sens'][1]} names "
             f"({s['sens'][2]} found after greetings, {s['sens'][3]} from `mask_names.txt`; values are not written anywhere).\n")
    L.append("## Labelling buckets (label_priority)\n")
    prio = pinfo["prio"]
    gs_ = pinfo["gstats"]
    L.append(f"- Fixed seed {PRIORITY_SEED}. 1 = the {PRIORITY_N1} largest groups; 2 = every other group with a `mobile_number` sender; 3 = a random {PRIORITY_N3} of the rest "
             f"(smallest md5(seed|group_id)); 4 = the rest. Buckets are stored in `label_me_state.json` and `label_me.csv`: a rerun or a new phone file never moves a group that "
             f"has a bucket; {pinfo['new']} groups were bucketed for the first time in this run. A new group later is bucketed by the first run's cut-offs "
             f"(bigger than the smallest bucket-1 group: 1; a `mobile_number` sender: 2; md5 key up to bucket 3's largest: 3; else 4), so bucket 1 can grow past {PRIORITY_N1}.")
    L.append(f"- Group registry (`label_me_state.json`, key hashes only): keys new in this run {gs_.get('new_keys', 0)}, of which joined an existing group "
             f"{gs_.get('joined_existing', 0)}; new groups {gs_.get('new_groups', 0)}; pairs of existing groups a new message is like both of, kept apart "
             f"{gs_.get('kept_apart', 0)} (the freeze puts such groups on one side); groups seen before with no message in this run {len(pinfo['vanished'])}.")
    L.append("- **Bucket 2 is scam-enriched by design** (messages from ordinary mobile numbers are much more often scams than messages from bank / DLT sender ids): "
             "do not read bucket 2's scam share as the base rate, and read results over buckets 1+3 for something closer to the inbox.")
    L += ["", "| bucket | groups | messages | labelled groups (scam / genuine / skip) | still blank |", "|---|---:|---:|---|---:|"]
    for b in (1, 2, 3, 4):
        gs = [g for g in pinfo["need"] if prio.get(g) == b]
        lab = Counter(pinfo["labels"].get(g) for g in gs)
        L.append(f"| {b} | {len(gs)} | {sum(len(groups[g]) for g in gs)} | {lab['scam'] + lab['genuine'] + lab['skip']} ({lab['scam']} / {lab['genuine']} / {lab['skip']}) | {lab[None]} |")
    L.append("")
    if split:
        L.append("## Freeze split (TEST vs POOL)\n")
        L.append(f"- Fixed seed {SPLIT_SEED}. Unit = template group; {split['merged_units']} groups were merged into a neighbour's unit because a near-duplicate look over all their "
                 f"messages (grouping seed and an independent one) found them similar ({split['mixed_units']} units hold both labels). Stratified by label x keyword bucket "
                 f"({' / '.join(KW_BUCKETS)}; first match wins), 50/50 by units inside each stratum. Only labelled groups are split; skip and blank groups are in neither half.")
        L.append(f"- **TEST**: {len(test_final)} rows from {len(split['test'])} groups ({sum(r['label'] == 1 for r in test_final)} scam / {sum(r['label'] == 0 for r in test_final)} genuine rows). "
                 f"**POOL**: {len(pool_final)} rows from {len(split['pool'])} groups ({sum(r['label'] == 1 for r in pool_final)} scam / {sum(r['label'] == 0 for r in pool_final)} genuine rows).")
        L.append("- Checked after the split with a seed neither the grouping nor the split used, over the stored rows and every message of each side: 0 groups on both "
                 "sides and 0 near-duplicate pairs across it (the run stops otherwise).\n")
        L += ["| label | keyword bucket | test groups | pool groups |", "|---|---|---:|---:|"]
        for (lab, kwb), (t, p_) in sorted(split["strata"].items(), key=lambda kv: (kv[0][0], KW_BUCKETS.index(kv[0][1]))):
            L.append(f"| {'scam' if lab == 1 else 'genuine'} | {kwb} | {t} | {p_} |")
        L.append("")
    if mode == "post":
        m = s["manifest"]
        L.append("## After the freeze\n")
        L.append(f"- Frozen on {m['frozen_utc']}: test {m['test_rows']} rows, SHA-256 `{m['test_sha256']}` (unchanged). Pool at freeze: {m['pool_rows_at_freeze']} rows; now {len(pool_final)}.")
        L.append(f"- Dropped on this run because of the TEST half: {sum(n for (_, r), n in drops.items() if r == TEST_GROUP_DROP)} (message of a TEST group) + "
                 f"{sum(n for (_, r), n in drops.items() if r == TEST_NEAR_DROP)} (near-duplicate of a TEST message: a stored TEST row or any message of a TEST group).\n")
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
    acn = s["all_cands_names"]
    L.append(f"- Kept rows with a likely name (capitalised word not in the common-word list): {len({k[0] for k in s['current']})}. Candidate tokens: {len(s['current'])}.")
    L.append(f"- Over all {len(cands)} candidate rows (labelled or not): {sum(acn.values())} name candidates in {len(acn)} rows. `review_names.csv` asks only about labelled rows, "
             "so this is the most it can grow to.")
    L.append(f"- Edits applied from `review_names.csv`: masks {sum(s['applied'].values())} (replacement values are not written here).")
    L.append(f"- Candidates still blank (not looked at; blank is kept as written, `ok` marks a reviewed non-name): {s['open_names']}; new since last run: {len(s['new_rows'])}; "
             f"entries for rows no longer in the set: {sum(1 for k in s['review_rows'] if k[0] not in ids)}.\n")
    L.append("## Output\n")
    if mode == "preview":
        L.append(f"- `{s['preview_name']}`: {len(test_final)} labelled rows" + (f", SHA-256 `{sha}` (a preview, not frozen)." if sha else " (not written: no labelled group yet).")
                 + f" `{out.name}` is written only by `--freeze`.")
    else:
        L.append(f"- `{out.name}`: {len(test_final) if mode == 'freeze' else s['manifest']['test_rows']} rows, SHA-256 `{sha}`" + (" (frozen just now)." if mode == "freeze" else " (frozen, unchanged)."))
        L.append(f"- pool: {len(pool_final)} rows from {len({r['group'] for r in pool_final})} groups.")
    return "\n".join(L) + "\n"


FREEZE_HEAD = "## Frozen hashes (real-message test set)"

def frozen_hash():
    if not CLAUDE.exists() or FREEZE_HEAD not in CLAUDE.read_text(encoding="utf-8"):
        return None
    m = re.search(r"SHA-256 `([0-9a-f]{64})`", CLAUDE.read_text(encoding="utf-8").split(FREEZE_HEAD, 1)[1])
    return m.group(1) if m else None

def freeze_hash(sha, n, extra_line=""):
    """Write (or replace) the frozen-hashes section of CLAUDE.md. Refuses to replace a different hash: that needs a human decision."""
    text = CLAUDE.read_text(encoding="utf-8")
    line = f"- `data/real/real_test_v1.csv`: {n} rows, SHA-256 `{sha}` (frozen {dt.date.today().isoformat()}, the TEST half of a grouped 50/50 split). TEST ONLY: never a training, tuning or calibration input (src/realguard.py)."
    if extra_line:
        line += "\n" + extra_line
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
    ap.add_argument("--freeze", action="store_true", help="split the labelled groups 50/50 (TEST -> real_test_v1.csv + its SHA-256 in CLAUDE.md, POOL -> data/collected/phones/pool.csv); once only")
    ap.add_argument("--allow-unlabelled", action="store_true", help="with --freeze: blank groups in bucket 4 are left out of both halves (buckets 1-3 must be labelled)")
    ap.add_argument("--pool-dir", type=Path, default=None, help=f"where the POOL half goes (default {POOL_DIR.relative_to(ROOT)}/)")
    ap.add_argument("--allow-open-names", action="store_true", help="with --freeze: freeze although name candidates in review_names.csv are still blank")
    a = ap.parse_args()
    run(a.input, a.out, a.review, a.report, a.freeze, a.messages, a.label_file, a.cap, a.allow_unlabelled, a.names_file, a.allow_open_names, a.pool_dir)


if __name__ == "__main__":
    try:
        main()
    except Stop as e:
        print(e, file=sys.stderr)
        sys.exit(2)
