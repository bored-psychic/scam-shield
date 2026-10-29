import functools, re

# PII masks shared by build_text.py (ingestion) and translate_parents.py (translation parents), so the two cannot
# drift apart. Same tokens for every source so masking itself isn't a label signal. Order matters: the account
# pattern runs after the phone pattern, so a 10-digit mobile number becomes <PHONE>, not <ACCOUNT>.
# (Moved verbatim from build_text.py; src/pii.py is the single copy now.)
# splits-v2 (2026-10-21): UPI ids match the NPCI app / bank handle list below (was 13 suffixes, so dunzo.payu@axisbank and
# olamoney.payu@indus slipped through), and any user@host left with a dotless host (root@localhost, x@python, OFFERS@VISHAL)
# becomes <EMAIL>. That catch-all also masks things that are not personal addresses (shell prompts, promo tags, junk inside
# encoded attachments); over-masking was chosen over a hand-tuned exception list (rule 5).
# 2026-10-25: SEBI's @valid handles (circular SEBI/HO/DEPA-II/DEPA-II_SRG/P/CIR/2025/86: name.brk@validhdfc, name.mf@validicici) now mask as <UPI_ID>; before this
# they fell to the dotless catch-all and became <EMAIL>. No row of data/ contains one (the sources predate October 2025), so messages.csv, text_hash and
# split_map are unchanged; the stored masking of any future row follows these masks. The text heads see <UPI_ID> for these ids from now on (textprep.model_text).
UPI_HANDLES = sorted({
    "abfspay", "airtel", "apl", "aubank", "axis", "axisb", "axisbank", "axl", "barodampay", "boi", "cbin", "centralbank", "citi",
    "cnrb", "cub", "dbs", "dlb", "equitas", "ezeepay", "fbl", "federal", "freecharge", "hdfc", "hdfcbank", "hsbc", "ibl", "icici",
    "idbi", "idfcbank", "idfcfirst", "ikwik", "indianbank", "indus", "iob", "jio", "jkb", "jupiteraxis", "kbl", "kmbl", "kotak",
    "kvb", "mahb", "mairtel", "naviaxis", "okaxis", "okhdfcbank", "okicici", "oksbi", "paytm", "pingpay", "pnb", "postbank", "psb",
    "ptaxis", "pthdfc", "ptsbi", "ptyes", "rapl", "rbl", "sbi", "sc", "sib", "slice", "superyes", "tapicici", "timecosmos", "tjsb",
    "uboi", "uco", "unionbank", "upi", "waaxis", "wahdfcbank", "waicici", "wasbi", "yapl", "ybl", "yesbank", "yesbankltd"}, key=lambda h: (-len(h), h))
# (longest first, ties alphabetical: it was key=len, reverse=True, whose order among equal lengths changed with PYTHONHASHSEED. Equal-length handles cannot
# prefix one another, so the matches are the same; the pattern text is now the same in every process, which tests/test_masks.py freezes.)
_V2_PATTERNS = [
    (r"[\w.+-]+@[\w-]+\.[\w.]+", "<EMAIL>"),
    (r"(?i)\b[\w.-]{2,}@(?:" + "|".join(UPI_HANDLES) + r")\b", "<UPI_ID>"),
    (r"(?i)\b[\w.-]{2,}@valid[a-z]*\b", "<UPI_ID>"),   # SEBI's @valid ids (name.brk@validhdfc, 2025): a UPI id, not an e-mail address (2026-10-25)
    (r"\b[\w.+-]+@[A-Za-z][\w-]*", "<EMAIL>"),   # dotless host: whatever is left of the user@host form
    (r"(?:\+91[\s-]?|\+92[\s-]?|\b0)?\b[6-9]\d{4}[\s-]?\d{5}\b", "<PHONE>"),
    (r"\b(?:XX|xx|\*{2,})?\d{9,18}\b", "<ACCOUNT>"),
]
MASK_TOKENS = ("<EMAIL>", "<UPI_ID>", "<PHONE>", "<ACCOUNT>")   # the v2 tokens; v3 adds MASK_TOKENS_V3
# What a mask miss looks like: a word character, "@", a letter. 0 rows of data/final/messages.csv after the splits-v2 masks.
MISS_RX = re.compile(r"\w@[A-Za-z]")

# The splits-v1 masks, frozen. build_text.py uses them ONLY to recompute the hash a row had under splits-v1, so a row whose
# masked text changed keeps its frozen split. Never use them to mask anything that is stored or scored.
MASKS_V1 = [
    (r"[\w.+-]+@[\w-]+\.[\w.]+", "<EMAIL>"),
    (r"\b[\w.-]{2,}@(?:ok)?(?:sbi|hdfc|icici|axis|paytm|ybl|ibl|upi|apl|okaxis|okhdfcbank|okicici|oksbi)\b", "<UPI_ID>"),
    (r"(?:\+91[\s-]?|\+92[\s-]?|\b0)?\b[6-9]\d{4}[\s-]?\d{5}\b", "<PHONE>"),
    (r"\b(?:XX|xx|\*{2,})?\d{9,18}\b", "<ACCOUNT>"),
]


# ---------------------------------------------------------------------------------------------------------------------------------
# Versioned mask sets (splits-v3 B0a, docs/plans/splits_v3.md D-v3.5). A text model must be scored with the masks it was trained on
# (CLAUDE.md rule 11), and a POOL row (masked by intake_real) must look like a messages.csv row, or the mask token itself becomes a
# "this row came from a phone" shortcut. So three frozen sets, each with a mask_version string:
#   MASKS_V2        "v2"        what pii.mask_text did up to splits-v2. The shipped MuRIL and the TF-IDF baseline were trained on it.
#                               `MASKS` (the list of patterns, used by build_text.py / intake_screens.py) is MASKS_V2.patterns.
#   MASKS_INTAKE_V1 "intake-v1" what intake_real.mask did on 2026-10-28, moved here unchanged. intake_real is pinned to it: changing it would
#                               change the digit-collapsed group keys its registry is built on. Takes name_rx (the contact / sender names).
#   MASKS_V3        "v3"        v2 + the intake numbers (card, OTP, account tails, any 9+ digit run, glued or not) + greeting names for
#                               every source + ALL-CAPS payer names for SMS-type channels. For splits-v3 data and a v3 bundle.
# Never edit a set after a model has been trained on it: add a new version. tests/test_masks.py freezes v2 and intake-v1 byte for byte.
V2, INTAKE_V1, V3 = "v2", "intake-v1", "v3"
MASK_TOKENS_V3 = MASK_TOKENS + ("<NAME>", "<OTP>")
# where the ALL-CAPS payer rule runs (not job posts, mail, calls). D-v3.5 also lists "email_or_sms" (ealvaradob_phishing), but a mask that depends on the channel stops two
# copies of one message from being duplicates: ealvaradob_phishing holds copies of phishing_email (channel "email") messages, the rule masked the copy and not the original,
# and the dry run kept 417 rows that v2 deduplicated (+40 val, +40 test). So that channel is treated as mail, like its originals.
SMS_TYPE_CHANNELS = frozenset({"sms", "whatsapp", "telegram", "app", "chat", "other"})

# the links stay out of the way of the number and name masks (a link is analysed as a string, never visited: CLAUDE.md rule 8)
URL_RX = re.compile(r"https?://\S+|www\.\S+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|net|org|co|io|ly|me|info|xyz|top|site|online|link|store|app|gov|edu|bank|shop|live)\b(?:/\S*)?", re.I)
CARD_RX = re.compile(r"\b(?:\d{4}[ -]){3}\d{4}\b")
OTP_RX = re.compile(r"(?i)\b(otp|code|pin|password)\b(?:\W{0,3}\b(?:is|was|number|no|code)\b){0,2}\W{0,5}(\d{4,8})\b")
# the code before its keyword: "482913 is your OTP", "123456 is the verification code", "Use 5566 as your login code"
OTP_BEFORE_RX = re.compile(r"(?i)\b\d{4,8}\b(?=\s*(?:is|as|are|was)\s+(?:your|the|an?|ur|my)?\s*[^.\d]{0,30}?\b(?:otp|code|pin|passcode|password)\b)")
# v3 only (intake-v1 stays as it was): an OTP keyword with the number further on, "OTP for Grapevine is 919157", "your OTP for txn of Rs 500 at X is 1234". The keyword
# set is the strong one (a bare "code" / "pin" / "password" is OTP_RX's, which needs the number right after it); the gap stops at a sentence end ('.' followed by a space)
# and is at most 60 characters; the number is the 4-8 digit run after is / are / was / ':' / '=' and is not a decimal.
OTP_NEAR_RX = re.compile(r"(?i)\b(?:otp|passcode|one[- ]time\s+(?:password|passcode|pin|code)|(?:verification|security|login|auth\w*|transaction|confirmation)\s+code)\b"
                         r"(?:[^.\n]|\.(?=\S)){0,60}?(?:\b(?:is|are|was)\b|[:=])\s*\W{0,3}?(\d{4,8})\b(?![.,]\d)")
# v3 copies of the two keyword rules that must not read the keyword inside a mask token: "<OTP>" holds the word OTP, so a second pass over "code + <OTP>\n52098236" masked the
# next number (v3 is idempotent, v3(v3(x)) == v3(x); the intake's OTP_RX, pinned, has this flaw). Same pattern text otherwise.
OTP_RX_V3 = re.compile(r"(?i)(?<!<)" + OTP_RX.pattern[len("(?i)"):])
OTP_NEAR_RX = re.compile(r"(?i)(?<!<)" + OTP_NEAR_RX.pattern[len("(?i)"):])
def _otp_near(t):
    return OTP_NEAR_RX.sub(lambda m: m.group(0)[: m.start(1) - m.start(0)] + "<OTP>", t)
# any run of 9+ digits left after the other masks, glued to letters or inside a link included: the v2 masks need word boundaries and stop at
# 18 digits, so a 21-digit transaction id and order / tracking ids like FMPIB1234567890 got through
LONG_RX = re.compile(r"\d{9,}")
# links are kept for the link checks, but a number inside one can be a person's: click-to-chat links (wa.me/91..., ?phone=91...) and any
# standalone Indian mobile number in a path or query (?id=98..., /bill-98...)
URL_PHONE_RX = re.compile(r"(?i)(wa\.me/|[?&]phone=)\+?\d{10,15}")
URL_MOBILE_RX = re.compile(r"(?<!\w)(?:\+?91)?[6-9]\d{9}(?!\w)")
# the last digits of an account or card: "A/c XX1234", "card ending 4455", "a/c no. 12345", and a bare XX1234 / ****1234
ACCT_TAIL_RX = re.compile(r"(?i)\b((?:a/c|acct?|account|card)\b(?:\s+(?:no\.?|number|ending(?:\s+(?:with|in))?|last\s+\d\s+digits(?:\s+are)?))?[\s.:#*x-]{0,12}?)(\d{3,6})\b")
XX_TAIL_RX = re.compile(r"(?i)\b(?:x{2,}|\*{2,})\d{3,8}\b")

# capitalised words that are not names (sentence starts, brands, banks, money, common nouns): intake_real uses them to decide what goes to the
# review file, v3 to decide what a greeting does not mask
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
NOT_NAMES = {w.lower() for w in COMMON} | set("""user valued there all team friend friends guest member applicant subscriber everyone folks sirji mam mama customer
passenger cardholder holder student parent donor investor policyholder beneficiary resident owner partner candidate aap aapka aapke hai ji sahab bhai didi
who you your are the and for with this that dost sahib""".split())
ACRONYMS = {"UPI", "SBI", "OTP", "ATM", "NEFT", "IMPS", "RTGS", "KYC", "PAN", "EMI", "IRCTC", "HDFC", "ICICI", "AXIS", "BANK", "NPCI", "LIC", "EPFO", "FASTAG", "AMAZON", "PAYTM"}
# a word right after a greeting is usually the recipient's name, in any case ("Hey prajval", "Dear PRAJVAL"); an ALL-CAPS run after from / to / by is a
# UPI payer or payee
GREETING_NAME_RX = re.compile(r"(?i)\b(?:hey|hi|hello|dear|namaste|namaskara|mr|mrs|ms|miss|shri|smt)\b\.?,?\s+([a-z]{3,15})\b")
CAPS_NAME_RX = re.compile(r"\b(?i:from|to|by|paid to|sent to|received from|credited by|beneficiary|payee)\s+([A-Z]{3,}\.{0,2}(?:\s+[A-Z]{3,}\.{0,2}){0,2})(?![A-Za-z])")

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

# the v2 patterns split by what they produce, not by position: the address masks run first, the phone / account masks after the links are set aside
ADDRESS_MASKS = [m for m in _V2_PATTERNS if m[1] in ("<EMAIL>", "<UPI_ID>")]
NUMBER_MASKS = [m for m in _V2_PATTERNS if m[1] not in ("<EMAIL>", "<UPI_ID>")]


class MaskSet:
    """One versioned mask set: mask_version, the callable, and (v2 only) the plain pattern list. Call it as mask_set(text, **keywords)."""
    def __init__(self, mask_version, fn, patterns=()):
        self.mask_version, self.fn, self.patterns = mask_version, fn, list(patterns)

    def __call__(self, text, **kw):
        return self.fn(text, **kw)

    def __repr__(self):
        return f"MaskSet({self.mask_version!r})"


def _mask_v2(text, channel=None, kinds=None):
    text = text.replace("<UPI>", "<UPI_ID>")   # web_scams.csv tags UPI ids <UPI>; unify so the token isn't source-specific
    for pat, tok in _V2_PATTERNS:
        text = re.sub(pat, tok, text)
    return text


def _phone_alt(p):
    return r"(?:(?<!\d)(?:(?:\+|00|0)?91|0)\D?)?" + r"\D?".join(p)


@functools.lru_cache(maxsize=4096)
def _phones_subset_rx(hit):
    """The alternation for just these numbers (a sorted tuple), in the order the full one would try them."""
    return re.compile("|".join(_phone_alt(p) for p in hit))


_NON_ASCII_DIGIT_RX = re.compile(r"[^0-9]+")


class KnownPhoneRx:
    """The numbers seen in the input as a masker with the `.sub(repl, text)` of one big alternation, without paying for it on every message. A match
    has the number's 10 digits in a row once everything that is not an ASCII digit is removed (separators sit between digits and a prefix only adds
    digits in front), so a text whose digits hold none of the numbers in any 10-digit window cannot match and is returned as it is; otherwise the
    regex for just the numbers found in those windows runs on the text. Every alternative that can match at all is in that subset, in the full
    alternation's order, so the output is the full alternation's."""
    def __init__(self, phones):
        self.phones = frozenset(phones)
        self.order = sorted(self.phones)

    def hits(self, text):
        digits = _NON_ASCII_DIGIT_RX.sub("", text)
        if len(digits) < 10:
            return ()
        found = {digits[i:i + 10] for i in range(len(digits) - 9)} & self.phones
        return tuple(p for p in self.order if p in found)

    def sub(self, repl, text):
        hit = self.hits(text)
        return _phones_subset_rx(hit).sub(repl, text) if hit else text


def known_phone_rx(phones):
    """The phone numbers seen in the input (each a 10-digit string) as a masker with `.sub`: the number with at most one non-digit character (space, -, ., /, a
    letter, anything) between any two digits, and an optional +91 / 0091 / 091 / 91 / 0 prefix (itself with at most one separator), so '98765 43210', '9876-543-210'
    and a coupon code like 'EYEC98765D43210' are found. The match takes the separators with it. Digits directly next to the number do not stop it
    (the contiguous 9+ digit rule would mask those anyway); the prefix only counts when no digit stands in front of it. None when there are no phones.
    Returns a `KnownPhoneRx` (pre-filtered, 2026-10-29), same output as one regex of all the numbers."""
    if not phones:
        return None
    return KnownPhoneRx(phones)


def _mask_intake_v1(text, name_rx=None, kinds=None, phone_rx=None):
    """src/pii.py v2 masks (emails and UPI ids first, then phones and accounts) with URLs kept, plus card, OTP, account-tail and long digit
    runs, and every contact / sender name seen in the input (name_rx) as <NAME>, inside links too (a link keeps its host and shape, never a
    name: /u/<NAME>/orders). Moved from intake_real.mask (2026-10-28) without a change. `phone_rx` (known_phone_rx, optional, 2026-10-29) masks the
    numbers seen in the input as <PHONE> even when separators split their digits; with None the function is byte-identical to before."""
    t = text
    for pat, tok in ADDRESS_MASKS:
        t = re.sub(pat, tok, t)
    if phone_rx is not None:
        t = phone_rx.sub("<PHONE>", t)
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


# v3 names. The greeting rule is intake_real's, with three refinements found on the TRAIN rows (reports/splits_v3_b0a.md): "MS" in capitals is
# Microsoft ("MS Office", "MS SQL", 450 train hits), not a title; function words and generic addressees are not names ("hi how are you", "Dear
# taxpayer"); and nothing masks MORE than intake_real's candidate rule, so a word the intake left alone (a reviewed `ok`) stays alone.
GREETING_NAME_RX_V3 = re.compile(r"\b(?:(?i:hey|hi|hello|dear|namaste|namaskara|mr|mrs|miss|shri|smt)|Ms)\b\.?,?\s+((?i:[a-z]{3,15}))\b")
NOT_NAMES_V3 = NOT_NAMES | set("""how what when where why which then than here out again show plus guys colleagues colleague readers reader fellow linguist linguists
consumer taxpayer homeowner citizen officer baby darlin everyone anyone someone sweetheart sweetie buddy bro dude mate pal all""".split())

# ALL-CAPS words after from / to / by that are places, organisations, brands or ordinary words, not a payer or payee. Curated by hand from the TRAIN SMS-type hits
# (reports/splits_v3_b0a.md), by category, not exhaustive: a name the list misses is masked, which is the safe side (rule 5), and an organisation it misses
# is over-masked. One of these words anywhere in the match leaves the whole match alone.
CAPS_NOT_NAMES_V3 = set("""
MUMBAI DELHI NEW BANGALORE BENGALURU HYDERABAD CHENNAI KOLKATA PUNE AHMEDABAD JAIPUR LUCKNOW SURAT KANPUR NAGPUR INDORE BHOPAL PATNA VADODARA GHAZIABAD LUDHIANA AGRA
NASHIK FARIDABAD MEERUT RAJKOT VARANASI SRINAGAR AMRITSAR PRAYAGRAJ ALLAHABAD RANCHI HOWRAH COIMBATORE JABALPUR GWALIOR VIJAYAWADA JODHPUR MADURAI RAIPUR KOTA CHANDIGARH
GUWAHATI MYSORE MYSURU NOIDA GURGAON GURUGRAM KOCHI COCHIN GOA THANE NAVI MAHARASHTRA KARNATAKA TAMIL NADU GUJARAT RAJASTHAN PUNJAB HARYANA BIHAR ODISHA ASSAM TELANGANA
KERALA UTTAR PRADESH BENGAL ANDHRA MADHYA JHARKHAND UTTARAKHAND INDIA USA UK UAE DUBAI CHINA PARIS LONDON BALI TAMPA SANYA NEPAL
HOME OFFICE STORE SHOP SITE LINK APP WEBSITE PORTAL CENTER CENTRE BRANCH WALLET SELF ONLY POST EMAIL MAIL INFORM YESTERDAY TODAY TOMORROW UNLIMITED PARTY EARTH SMS CALL APK
VPA URL PIN CVV NET MOBILE ONLINE OFFER OFFERS SALE FREE NOW CONFIRM VERIFY CLAIM CLICK REGISTER ACTIVATE UPDATE REPLY TEXT CASH CARD CREDIT DEBIT
AJIO AMAZON FLIPKART MYNTRA SWIGGY ZOMATO OLA UBER PHONEPE GPAY GOOGLE PAYTM RAZORPAY CRED BIGBASKET JIO AIRTEL BSNL NETFLIX HOTSTAR DISNEY SONYLIV EROSNOW IKEA NOKIA
DUNZO MEESHO NYKAA BLINKIT ZEPTO DOMINOS PIZZA LENSKART TATA RELIANCE INFOSYS WIPRO PREMIER WESTPAC UNICEF NHS CNN IBN XCHAT HOTMIX
INR RS XXXX XXXXX CBI NIA RBI SEBI TRAI UIDAI IRDAI NPCI EPFO ED ITR GST IRCTC RTO DOT NCB BESCOM MSEDCL BSES PSPCL TPDDL TNEB KSEB MSEB CESC BEST AWS EOD BVN CBN
""".split())

# The payer / payee rule (v3): after from / to / by / paid to ... a run of up to 4 ALL-CAPS tokens, initials included ("RENU R KUMAR" is one <NAME>). A token is 3+
# capitals or an initial (one capital, with or without a dot); a 2-letter token ("TO", "IN", "ON") ends the run, an initial without a dot may not end it ("AMIT I will pay"),
# and "A" / "I" without a dot are the English words, not initials. One 3+ token on a stoplist (COMMON, ACRONYMS, CAPS_NOT_NAMES_V3) anywhere in the run leaves the run alone.
CAPS_NAME_RX_V3 = re.compile(r"\b(?i:from|to|by|paid to|sent to|received from|credited by|beneficiary|payee)\s+([A-Z]+\.{0,2}(?:\s+[A-Z]+\.{0,2}){0,3})(?![A-Za-z])")

def _caps_name(m):
    keep = []
    for t in re.finditer(r"[A-Z]+\.{0,2}", m.group(1)):
        core = t.group(0).rstrip(".")
        if len(core) == 2 or (len(core) == 1 and core in "AI" and t.group(0) == core):
            break
        keep.append(t)
    while keep and len(keep[-1].group(0).rstrip(".")) == 1 and keep[-1].group(0) == keep[-1].group(0).rstrip("."):
        keep.pop()
    words = [t.group(0).rstrip(".") for t in keep]
    if not any(len(w) >= 3 for w in words):
        return None
    if any(len(w) >= 3 and (w.title() in COMMON or w in ACRONYMS or w in CAPS_NOT_NAMES_V3) for w in words):
        return None
    end = keep[-1].start() + len(keep[-1].group(0).rstrip("."))   # the dots after the last token stay (a sentence end)
    return m.group(1)[:end], m.group(1)[end:]

def _mask_names_v3(t, channel, kinds):
    def greeting(m):
        if m.group(1).lower() in NOT_NAMES_V3:
            return m.group(0)
        return m.group(0)[: m.start(1) - m.start(0)] + "<NAME>"
    new = GREETING_NAME_RX_V3.sub(greeting, t)
    if kinds is not None and new != t:
        kinds.add("greeting_name")
    t = new
    if channel is None or channel in SMS_TYPE_CHANNELS:   # the app has no channel: a pasted message is read like an SMS / chat message
        def caps(m):
            hit = _caps_name(m)
            if hit is None:
                return m.group(0)
            return m.group(0)[: m.start(1) - m.start(0)] + "<NAME>" + hit[1]
        new = CAPS_NAME_RX_V3.sub(caps, t)
        if kinds is not None and new != t:
            kinds.add("caps_name")
        t = new
    return t

def _mask_v3(text, channel=None, kinds=None):
    """v3 on one raw text. `channel` is the source channel (the ALL-CAPS payer rule runs on SMS-type channels, and when it is None). `kinds`, a set,
    collects which steps changed the text (build_text.py's dry-run table). The order is intake_real's (links set aside while names, card, OTP, tails
    and the v2 number masks run; then the link-borne phone numbers and every 9+ digit run), plus a last sweep of the v2 number masks over the whole
    text, so that v3 hides at least what v2 hid, links included."""
    def step(t, new, kind):
        if kinds is not None and new != t:
            kinds.add(kind)
        return new
    t = text.replace("<UPI>", "<UPI_ID>")
    for pat, tok in ADDRESS_MASKS:
        t = step(t, re.sub(pat, tok, t), "address")
    t, urls = protect_urls(t)
    t = _mask_names_v3(t, channel, kinds)
    t = step(t, CARD_RX.sub("<ACCOUNT>", t), "card")
    t = step(t, OTP_RX_V3.sub(lambda m: m.group(0)[: m.start(2) - m.start(0)] + "<OTP>", t), "otp")
    t = step(t, OTP_BEFORE_RX.sub("<OTP>", t), "otp")
    t = step(t, _otp_near(t), "otp")
    t = step(t, ACCT_TAIL_RX.sub(lambda m: m.group(1) + "<ACCOUNT>", t), "acct_tail")
    t = step(t, XX_TAIL_RX.sub("<ACCOUNT>", t), "acct_tail")
    for pat, tok in NUMBER_MASKS:
        t = step(t, re.sub(pat, tok, t), "phone_account")
    t = step(t, URL_PHONE_RX.sub(lambda m: m.group(1) + "<PHONE>", restore_urls(t, urls)), "link_phone")
    t = step(t, URL_MOBILE_RX.sub("<PHONE>", t), "link_phone")
    t = step(t, LONG_RX.sub("<ACCOUNT>", t), "long_digits")
    for pat, tok in NUMBER_MASKS:
        t = step(t, re.sub(pat, tok, t), "v2_sweep")
    return t


MASKS_V2 = MaskSet(V2, _mask_v2, _V2_PATTERNS)
MASKS_INTAKE_V1 = MaskSet(INTAKE_V1, _mask_intake_v1)
MASKS_V3 = MaskSet(V3, _mask_v3)
MASKS = MASKS_V2.patterns   # the v2 pattern list under its old name (build_text.py, intake_screens.py)
MASK_SETS = {V2: MASKS_V2, V3: MASKS_V3}   # what a text model can be trained on and the app can apply; "intake-v1" is the intake's own, never a bundle's
MASK_VERSIONS = tuple(MASK_SETS)

def mask_set(version):
    """The mask set for a bundle's mask_version; an unknown one is refused (the app must not guess what a model was trained on)."""
    try:
        return MASK_SETS[version]
    except (KeyError, TypeError):
        raise ValueError(f"unknown mask_version {version!r}; this code knows {list(MASK_VERSIONS)}") from None

def mask_text(text, masks=None, version=V2, channel=None):
    """Mask one string. Default = the v2 masks, exactly as before splits-v3. `version` picks a set by its mask_version; `channel` only matters to v3
    (the ALL-CAPS payer rule). `masks`, a list of (pattern, token), is the old form (build_text.py applies the same patterns column-wise with pandas)."""
    if masks is not None:
        text = text.replace("<UPI>", "<UPI_ID>")
        for pat, tok in masks:
            text = re.sub(pat, tok, text)
        return text
    return mask_set(version)(text, channel=channel)
