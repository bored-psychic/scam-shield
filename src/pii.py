import re

# PII masks shared by build_text.py (ingestion) and translate_parents.py (translation parents), so the two cannot
# drift apart. Same tokens for every source so masking itself isn't a label signal. Order matters: the account
# pattern runs after the phone pattern, so a 10-digit mobile number becomes <PHONE>, not <ACCOUNT>.
# (Moved verbatim from build_text.py; src/pii.py is the single copy now.)
MASKS = [
    (r"[\w.+-]+@[\w-]+\.[\w.]+", "<EMAIL>"),
    (r"\b[\w.-]{2,}@(?:ok)?(?:sbi|hdfc|icici|axis|paytm|ybl|ibl|upi|apl|okaxis|okhdfcbank|okicici|oksbi)\b", "<UPI_ID>"),
    (r"(?:\+91[\s-]?|\+92[\s-]?|\b0)?\b[6-9]\d{4}[\s-]?\d{5}\b", "<PHONE>"),
    (r"\b(?:XX|xx|\*{2,})?\d{9,18}\b", "<ACCOUNT>"),
]
MASK_TOKENS = ("<EMAIL>", "<UPI_ID>", "<PHONE>", "<ACCOUNT>")

def mask_text(text):
    """Apply MASKS to one string (build_text.py applies the same patterns column-wise with pandas)."""
    text = text.replace("<UPI>", "<UPI_ID>")   # web_scams.csv tags UPI ids <UPI>; unify so the token isn't source-specific
    for pat, tok in MASKS:
        text = re.sub(pat, tok, text)
    return text
