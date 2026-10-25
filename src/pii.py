import re

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
    "uboi", "uco", "unionbank", "upi", "waaxis", "wahdfcbank", "waicici", "wasbi", "yapl", "ybl", "yesbank", "yesbankltd"}, key=len, reverse=True)
MASKS = [
    (r"[\w.+-]+@[\w-]+\.[\w.]+", "<EMAIL>"),
    (r"(?i)\b[\w.-]{2,}@(?:" + "|".join(UPI_HANDLES) + r")\b", "<UPI_ID>"),
    (r"(?i)\b[\w.-]{2,}@valid[a-z]*\b", "<UPI_ID>"),   # SEBI's @valid ids (name.brk@validhdfc, 2025): a UPI id, not an e-mail address (2026-10-25)
    (r"\b[\w.+-]+@[A-Za-z][\w-]*", "<EMAIL>"),   # dotless host: whatever is left of the user@host form
    (r"(?:\+91[\s-]?|\+92[\s-]?|\b0)?\b[6-9]\d{4}[\s-]?\d{5}\b", "<PHONE>"),
    (r"\b(?:XX|xx|\*{2,})?\d{9,18}\b", "<ACCOUNT>"),
]
MASK_TOKENS = ("<EMAIL>", "<UPI_ID>", "<PHONE>", "<ACCOUNT>")
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

def mask_text(text, masks=MASKS):
    """Apply MASKS to one string (build_text.py applies the same patterns column-wise with pandas)."""
    text = text.replace("<UPI>", "<UPI_ID>")   # web_scams.csv tags UPI ids <UPI>; unify so the token isn't source-specific
    for pat, tok in masks:
        text = re.sub(pat, tok, text)
    return text
