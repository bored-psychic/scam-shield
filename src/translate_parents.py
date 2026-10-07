import argparse, datetime as dt, glob, hashlib, os, re, sys, unicodedata
import numpy as np, pandas as pd
import neardup
from pii import mask_text
from protect import protect, restore, strip_markers

# English parents for the Hindi / Kannada translation set (CLAUDE.md next step: benign Hindi/Kannada data).
#   python src/translate_parents.py parents    select + filter parents -> data/external/indic/translate_in/parents_<date>.csv
#                                              and reports/translate_parents.md (ledger, rules, samples)
#   python src/translate_parents.py finalise   (after the laptop run + translate_indic.py post) automatic filters, length
#                                              matching, spot-check CSVs -> see the finalise section at the bottom
# Parent sources:
#   benign: the free 10k preview of gandharvbakshi's OTP/phishing SMS set (data/sources.yaml: otp_sms_preview). Only rows
#     the dataset itself labels non-phishing and does not flag `synthetic`; "not flagged" is NOT "real" (the card says the set
#     mixes real-world, LLM-labelled and synthetic-augmented SMS), so provenance is recorded as unknown. None of the preview's
#     phishing rows, Hindi, Kannada or other-script rows are used.
#   scam: short non-synthetic scam rows of scam_ham_india / india_fraud_final already in messages.csv, kept only if they show
#     a fraud mechanism (SCAM RULE below). Promotional spam is not fraud and must not become a translated "scam".
# Every row is masked with the same pii.MASKS as build_text.py before it is written. Nothing here touches messages.csv or
# split_map.csv. Translations of these parents are is_synthetic=True whatever the parent was.

LEN_MIN, LEN_MAX = 40, 160           # parent length in characters (SMS-sized; matches synth_india's 94-122 median)
CAP_TEMPLATE = 3                     # max parents per template group (near-dup cluster, exact Jaccard >= TEMPLATE_JACCARD)
CAP_SENDER = 60                      # max benign parents per normalised sender id
TEMPLATE_JACCARD = 0.6
ANCHOR_LEN = 300                     # messages.csv rows longer than this cannot reach J >= 0.6 with a <=160-char parent
SOURCES_SCAM = ("scam_ham_india", "india_fraud_final")
PREVIEW_GLOB = "data/external/text/otp_sms_preview/otp_sms_preview_*.csv"
OUT_DIR = "data/external/indic/translate_in"
REPORT = "reports/translate_parents.md"

# ---------------------------------------------------------------------------------------------------------------------
# RULES. Case-insensitive regexes on the masked text. Read these before trusting the counts.
# ---------------------------------------------------------------------------------------------------------------------
def rx(*alts):
    return re.compile("|".join(alts), re.I)

# Advertising cues. Applied to BOTH labels: an ad is neither a scam nor a legitimate transaction message.
PROMO_AD = rx(r"rummy", r"betting", r"\bbet(?:s)?\b", r"casino", r"poker", r"\bludo\b", r"teen patti", r"dream11",
              r"fantasy (?:cricket|league|sports)", r"\bipl\b", r"cricket", r"satta", r"\bslots?\b",
              r"welcome bonus", r"\bbonus\b", r"t&cs?\b", r"\btncs?\b", r"terms (?:and|&) conditions", r"terms apply",
              r"unsubscribe", r"reply stop", r"opt[- ]?out", r"\bdnd\b",
              r"pre-?(?:approved|qualified)", r"instant (?:approval|loan)", r"apply now", r"\bloans? (?:offer|approved|up to|upto)\b",
              r"\d+\s?% ?off\b", r"flat (?:rs\.?\s?)?\d+", r"\bsale\b", r"discount", r"coupon",
              r"buy ?\d+ ?get ?\d+", r"limited[- ](?:time|period)", r"\bdeals?\b", r"(?:special|exclusive|festive|festival|monsoon|diwali|mega|"
              r"great|amazing|exciting|best) offers?", r"offers? (?:valid|ends|expires|on all|for you)", r"membership", r"\bgift card\b",
              r"holidays?\b", r"tourism", r"\bquiz\b", r"reply [a-z]/[a-z]\b", r"@ ?rs\.?\d+/", r"shop(?:ping)? (?:now|at|with)", r"\bfashion\b", r"\bsubscribe\b")
# Operator plan promos ("Get 1.5GB/day, unlimited calls, recharge Rs 299") and card/loan ads. Scam side only: on the benign side a
# recharge confirmation or "OTP for txn on ICICI Bank Credit Card" is exactly the legitimate message we want.
PROMO_SCAM_ONLY = rx(r"\bfeedback\b", r"e-?receipt", r"was delivered", r"is picked", r"\bfavou?rite\b", r"come back", r"new arrivals?", r"\bcollection\b",
                    r"\bexplore\b", r"check-?up", r"best prices?", r"rs\.?\s?\d+/-", r"\bjust rs", r"at just", r"for only", r"credit (?:card|limit)", r"\bemi\b", r"demat", r"savings account", r"mutual fund", r"\binsurance\b", r"\bshop\b", r"latest trends", r"know more", r"\bairtel\b", r"vodafone", r"\bbsnl\b", r"prepaid", r"postpaid", r"unlimited", r"\brecharge\b", r"\bgb\b", r"data/day", r"validity", r"valid (?:for|till|until)", r"airtel thanks",
                   r"\bvi\b", r"\bjio\b", r"hotstar|disney\+|zee5|netflix|prime video|sony ?liv", r"subscription", r"\bpremium\b",
                   r"data top-?up", r"\bpack\b", r"\broaming\b")

# Sentences that WARN about fraud (every legitimate OTP/bank SMS has one) are removed before the fraud patterns run, or
# "Do not share your OTP with anyone" would count as a request for the OTP.
WARNING = re.compile(r"(?:do not|don't|never|not to|kindly do not|please do not|should not|shouldn't)\s+(?:\w+\s+){0,3}?"
                     r"(?:share|disclose|reveal|give|tell|click|respond|reply)\b[^.!?]*"
                     r"|\b(?:\w+\s+){0,3}(?:never|will never)\s+(?:ask|asks|call|calls|send|sends|request|requests)\b[^.!?]*"
                     r"|\bbeware\b[^.!?]*|\bonly fraudsters\b[^.!?]*|\botps? (?:are|is) secret\b[^.!?]*", re.I)

# HARD fraud mechanisms: a request that harms the recipient. These beat any promo cue.
SECRETS = r"(?:otp|pin|cvv|password|passcode|aadhaar|aadhar|pan(?: card| number| details)?|card (?:number|details)|bank details|account (?:number|details)|login (?:id|details))"
H_CREDENTIAL = rx(rf"\b(?:share|send|give|tell|provide|enter|submit|reveal|read out)\b[^.!?]{{0,50}}\b{SECRETS}\b",
                  r"\botp\b[^.!?]{0,40}\b(?:to|with)\b[^.!?]{0,30}\b(?:officer|agent|executive|manager|caller|number)\b",
                  r"\b(?:update|verify|complete|link)\b[^.!?]{0,40}\b(?:pan|aadhaar|aadhar|e-?kyc|kyc|bank details|card details|account details)\b")
H_ADVANCE_FEE = rx(r"\b(?:pay|paying|deposit|depositing|send|transfer|remit|submit|provide)\b[^.!?]{0,60}\b(?:fees?|charges?|registration|security deposit|processing|clearance|release|gst|penalty|fine|insurance|shipping|kit)\b",
                   r"\b(?:pay|paying|deposit|send|transfer|remit)\b[^.!?]{0,40}\bto (?:clear|release|claim|receive|unlock|confirm|activate|get|avoid|process)\b",
                   r"\b(?:pay|paying)\b[^.!?]{0,20}\b(?:rs\.?|inr|\u20b9)\s?\d",
                   r"\b(?:registration|processing|security|clearance|release|handling|customs|gst) (?:fees?|charges?|deposit|amount)\b[^.!?]{0,30}\b(?:required|mandatory|payable|compulsory)\b",
                   r"\btransfer\b[^.!?]{0,40}\b(?:funds|savings|money|balance)\b")
H_AUTHORITY = rx(r"\b(?:cbi|police|customs|narcotics|nia|ncb|rbi|trai|income tax|tax department|uidai|cyber ?crime|court|enforcement directorate)\b"
                 r"[^.!?]{0,120}\b(?:arrest\w*|warrant|legal action|case|investigat\w+|penalty|fine|stay on (?:the )?call|video call|seiz\w+|illegal|prohibited|money laundering)\b",
                 r"\b(?:digital (?:house )?arrest|arrest warrant|warrant for your arrest|money laundering|face arrest|house arrest|interrogation|terror\w*|crime branch|supreme court|bail|ed alert)\b")
LOSS = rx(r"\b(?:accounts?|a/c|acct|sim|mobile number|kyc|aadhaar|card|wallet|licen[cs]e|connection|electricity|power|banking|net ?banking|rc|vehicle|passport)\b[^.!?]{0,60}"
          r"\b(?:block(?:ed)?|suspend\w*|deactivat\w+|disconnect\w*|freez\w+|expire[sd]?|cancel\w*|clos(?:e|ed|ure)|restrict\w*|lock(?:ed)?)\b")
CTA = rx(r"\bclick\b", r"\blink\b", r"https?://", r"www\.", r"\[link\]", r"\bupdate\b", r"\bverify\b", r"\bcall\b", r"\bpay\b", r"\bcontact\b",
         r"\bpress\b", r"\bdownload\b", r"\bimmediately\b", r"\btoday\b", r"\btonight\b", r"\bwithin\b", r"\btransfer\b", r"\bshare\b",
         r"\bconfirm\b", r"\bsubmit\b", r"re-?upload", r"\benter\b", r"\bprovide\b", r"reactivate", r"\bresolve\b", r"\bvisit\b", r"log ?in")
# SOFT fraud lures: a lure word plus a call to action. These lose to a promo cue.
def lure(subject, action):
    return (rx(rf"\b(?:{subject})\b"), rx(rf"\b(?:{action})\b"))
SOFT = {
    "prize":    lure(r"won|win(?:ner|ning)?|selected|lucky draw|lottery|jackpot|grand prize|prize|congratulations|rewards?",
                     r"claim|call|contact|click|link|collect|redeem|process|reply|whatsapp|\[number\]|\[link\]|agent|verify|provide|pay"),
    "delivery": lure(r"parcel|package|courier|delivery|shipment|consignment|india post|fedex|dhl|customs|order|ship",
                     r"held|fail\w*|unable|reschedule|address|incomplete|pay|fee|link|click|prohibited|seized|update|redeliver|\[link\]|confirm|stuck|invalid|fill|waiting|details"),
    "pay_link": lure(r"challan|fines?|bill|electricity|power|tax|refund|penalty|dues|overdue|pending|payment|rc|licen[cs]e|confiscat\w+|lok adalat|legal action|income tax",
                     r"pay|click|link|download|apk|update|immediately|now|tonight|today|within|\[link\]|required|resolve|process|portal|try again|clear|incorrect|rejected"),
    "verify":   lure(r"kyc|documents?|bank (?:login|details)|net banking|mobile banking|under review|disabled|profile details|personal details|your details|login",
                     r"update|verify|confirm|re-?upload|reactivate|provide|submit|enter|here|portal|link|prevent|avoid|restriction|suspension"),
    "job":      lure(r"job|hiring|salary|work from home|part[- ]time|data entry|earn|income|vacancy|recruit\w*|positions|tasks?|commission|boosters?",
                     r"tasks?|apply|telegram|whatsapp|register|registration|contact|like|liking|rating|task|click|link|pay|deposit|call|offer|profile|\[link\]|interested|start|per day|a day|daily|crypto|usdt|tiktok|youtube|sharing|join|paid|minutes"),
    "threat":   lure(r"legal action|court|jail(?:ed)?|police|\bfir\b|lok adalat|case against|arrest", r"press|call|contact|pay|now|immediately|wait|stay|speak"),
    "mistake":  lure(r"by mistake|wrongly|collect request|approve (?:the )?request|scan (?:the )?qr|receive (?:the )?money", r".*"),
    "apk":      lure(r"apk|anydesk|teamviewer|quicksupport|remote (?:access|support)", r".*"),
    "scratch":  lure(r"scratch card", r".*"),
}
# Benign side: a legitimate transactional message. Needs one of these words (and no advertising cue).
TXN = rx(r"\botps?\b", r"verification code", r"one[- ]time password", r"\bpasscode\b", r"your \w+ code\b", r"\bbal\b", r"fastag", r"\bpnr\b", r"credited", r"debited", r"\ba/c\b", r"\bacct\b", r"\baccount\b", r"recharge", r"delivered", r"delivery", r"\border\b",
         r"\bbill\b", r"payment", r"\btxn\b", r"transaction", r"\bspent\b", r"balance", r"\bupi\b", r"\bavl\b", r"statement", r"due date",
         r"\bemi\b", r"booking", r"\bticket\b", r"\bpnr\b", r"refund", r"dispatched", r"shipped", r"invoice", r"receipt", r"\bcard\b")
# Hinglish / non-English guard for rows that are Latin script but not English.
HINGLISH_STRONG = {"hai", "hain", "aapka", "aapke", "aapki", "nahi", "karein", "kripya", "liye", "mein", "kisi", "abhi", "dhanyavad", "hua", "gaya",
                   "karo", "kijiye", "dijiye", "bhejein", "batayein", "aap", "apna", "apne"}
HINGLISH_WEAK = {"ke", "ka", "ki", "ko", "se", "par", "pe", "ab", "bhi", "ho", "tha", "thi", "raha", "rahi", "ya", "aur", "toh", "kya"}
# Possible person names: salutation + capitalised word that is not a generic address. Dropped, not masked (the project
# has no <NAME> token; web_scams victim names are masked by extract_scams only).
GENERIC = ("customer|user|sir|madam|subscriber|member|partner|valued|cardmember|card|account|holder|student|applicant|client|player|friend|"
           "all|team|there|guest|merchant|consumer|investor|yatri|beneficiary|candidate|parent|parents|winner|lucky|sir/madam|dear|"
           "your|you|our|the|this|that|please|kindly|get|win|enjoy|thanks|thank|welcome|attention|alert|notice|urgent|important|final|great|good|happy|new|special")
NAME = re.compile(rf"\b(?i:dear|hi|hello|hey|mr\.?|mrs\.?|ms\.?|shri|smt|congratulations|congrats)[!,]?\s+(?!(?i:{GENERIC})\b)[A-Z][a-z]{{2,}}\b"
                  r"|\b(?i:i am|i'm|my name is|this is)\s+(?!(?i:from|the|a|an|calling|your|with)\b)[A-Z][a-z]{2,}(?:\s[A-Z][a-z]{2,})?\b(?=\s*[,.]|\s+(?:from|of|calling|here|at)\b)"
                  r"|^\([A-Z][a-z]{2,}\)")
BRACKET_SLOT = re.compile(r"\[[A-Za-z][A-Za-z ]{1,30}\]|\bX{4,}\b|\d+X{3,}")   # india_fraud_final template slots: [Link], [Phishing Link], [Vehicle Number], 8240XXXXXX
SELF_LABEL = re.compile(r"\b(?:scams?|phishing|malicious|fraudulent|fraudsters?|beware|stay alert|fake)\b", re.I)   # text that names itself, or an advisory
OK_NON_ASCII = set("₹’‘“”–—•…")


RULE_TEXT = """## The filter rules in words

**Scam parents** (scam_ham_india, india_fraud_final; non-synthetic, English, 40-160 chars, masked). Applied in this order, on text with warning sentences
("Do not share your OTP", "never asks") removed first:

1. Drop text that names itself or is an advisory (scam, phishing, malicious, fraudulent, beware, fake), contains a template slot (`[Link]`, `[Phishing Link]`,
   `8240XXXXXX`), a person name ("Dear Priya", "I am Vijay Khanna"), Hinglish, or odd characters. A literal `[Link]` or the word "scam" would survive translation and
   exist only on the scam side.
2. KEEP if a **hard fraud mechanism** matches, even when the text also looks promotional: a request to share/send/enter OTP, PIN, CVV, password, Aadhaar, PAN or card
   details; an advance fee ("pay Rs 500 registration fee", "pay Rs 25,000 to clear"); an authority threat (CBI / police / customs / court with arrest, warrant, digital
   arrest, money laundering); an account, SIM, wallet, KYC or electricity-disconnection threat with a call to action; "transfer your funds".
3. Otherwise DROP as **promotional** if an advertising cue matches: rummy / betting / casino / quiz contest, bonus, T&C, % off, sale, coupon, buy-1-get-1, pre-approved
   loan or card, EMI, demat, savings account ad, feedback request, e-receipt, shopping ad wording, and (scam side only) operator plan wording (recharge, unlimited, GB/day,
   validity, Airtel / Vi / Jio, Hotstar, subscription, credit card / limit).
4. Otherwise KEEP if a **soft lure** matches (lure word + call to action): prize / lucky draw + claim, parcel / order + update address, challan / bill / tax / refund + pay or
   link, KYC / details + verify, job / earn + register / WhatsApp / task, legal threat + press / call, refund-by-mistake / collect request, APK / remote-access, scratch card.
5. Otherwise DROP as **no_fraud_mechanism** (information notices, missed-call alerts, legitimate OTP messages that the source labelled spam, etc.).

**Benign parents** (otp_sms_preview; not phishing, not flagged synthetic, Latin script, English, 40-160 chars, masked): KEEP only if the text contains a transactional word
(OTP / verification code, credited, debited, a/c, recharge, delivery, order, bill, payment, txn, balance, UPI, card, PNR ...) AND no advertising cue from the shared list
(rule 3 without the operator / credit-card words, so recharge confirmations and "OTP for txn on ICICI Bank Credit Card" stay).

Both labels then: drop exact duplicates after masking, drop parents whose English near-twins sit in two splits, cap parents per template group and benign parents per sender.
"""

def strip_warnings(t):
    return WARNING.sub(" ", t)

def scam_bucket(text):
    """-> (keep, reason). SCAM RULE: HARD fraud mechanism keeps; else a promo cue drops; else a SOFT lure keeps; else drop."""
    t = strip_warnings(text)
    if H_CREDENTIAL.search(t):
        return True, "hard:credential_request"
    if H_ADVANCE_FEE.search(t):
        return True, "hard:advance_fee"
    if H_AUTHORITY.search(t):
        return True, "hard:authority_threat"
    if LOSS.search(t) and CTA.search(t):
        return True, "hard:account_loss_threat"
    if PROMO_AD.search(text) or PROMO_SCAM_ONLY.search(text):
        return False, "promotional"
    for name, (subject, action) in SOFT.items():
        if subject.search(t) and action.search(t):
            return True, f"soft:{name}"
    return False, "no_fraud_mechanism"

def benign_bucket(text):
    """-> (keep, reason). Legitimate transactional message: a TXN word and no advertising cue."""
    if PROMO_AD.search(text):
        return False, "promotional"
    if not TXN.search(strip_warnings(text)) and not TXN.search(text):
        return False, "not_transactional"
    return True, "transactional"

def english_ok(text):
    words = re.findall(r"[a-z]+", text.lower())
    return not (any(w in HINGLISH_STRONG for w in words) or sum(w in HINGLISH_WEAK for w in words) >= 2)

def ascii_ok(text):
    return all(c.isascii() or c in OK_NON_ASCII for c in text)

def text_hash(t):   # same key as build_text.py: md5 of the lower-cased, whitespace-collapsed text
    return hashlib.md5(re.sub(r"\s+", " ", t.lower()).encode()).hexdigest()

def sender_key(s):
    s = str(s).strip().upper() if isinstance(s, str) else ""
    if not s:
        return "unknown"
    if re.match(r"^[A-Z]{2}-", s):
        return s[3:]
    if len(s) >= 7 and s[:2] in {"VM", "VK", "VD", "VA", "TX", "TM", "JD", "JM", "BZ", "AX", "BP", "CP", "DM", "HP", "IM", "LM", "QP", "TD", "VL"}:
        return s[2:]
    return s

def category(text):
    """Coarse topic from the text alone, same function for both labels so topic is not a label cue."""
    for cat, pat in (("digital_arrest", r"arrest|warrant|cbi|police|narcotics|court"), ("echallan", r"challan|rto\b|parivahan|traffic|vehicle"),
                     ("kyc", r"kyc|aadhaar|aadhar|\bpan\b"), ("lottery", r"lottery|lucky draw|prize|\bwon\b|winner|reward|scratch"),
                     ("job", r"\bjob\b|hiring|salary|work from home|part[- ]time|earn"), ("upi", r"\bupi\b|collect request|gpay|phonepe|paytm"),
                     ("courier_customs", r"parcel|courier|deliver|shipment|consignment|india post|customs|\border\b"),
                     ("utility", r"electricity|power|\bgas\b|\bbill\b"),
                     ("bank", r"debited|credited|a/c|acct|account|card|bank|txn|transaction|neft|imps|balance|otp")):
        if re.search(pat, text, re.I):
            return cat
    return "other"

class Ledger:
    """Row counts at every step, so every row that goes in is accounted for as kept or dropped-for-a-reason."""
    def __init__(self):
        self.rows = []
        self.by_source = []      # (step, {source: rows in}, {source: rows left}) for the scam path
        self.scam_rows = None    # rows entering the SCAM RULE with their rule label, for examples in the report
    def add(self, group, step, n_in, n_out, note=""):
        self.rows.append({"group": group, "step": step, "in": n_in, "dropped": n_in - n_out, "left": n_out, "note": note})
    def frame(self):
        return pd.DataFrame(self.rows)

def md(df):
    cells = [[str(c) for c in df.columns]] + [[f"{v:.3f}" if isinstance(v, (float, np.floating)) else str(v) for v in r] for r in df.itertuples(index=False)]
    lines = ["| " + " | ".join(r) + " |" for r in cells]
    lines.insert(1, "|" + "|".join(" --- " for _ in cells[0]) + "|")
    return "\n".join(lines)

def step(led, group, name, d, mask, note=""):
    out = d[mask]
    led.add(group, name, len(d), len(out), note)
    if group.startswith("scam"):
        led.by_source.append((name, d["source"].value_counts().to_dict(), out["source"].value_counts().to_dict()))
    return out

def select_benign(led):
    f = sorted(glob.glob(PREVIEW_GLOB))[-1]
    d = pd.read_csv(f)
    g = "benign (otp_sms_preview)"
    led.add(g, "preview rows", len(d), len(d), os.path.basename(f))
    d = d.assign(raw=d["sms_text"].fillna("").astype(str))
    d = step(led, g, "drop rows the dataset labels phishing", d, ~d["is_phishing_original"].astype(bool), "is_phishing_original = True: not used")
    d = step(led, g, "drop empty text", d, d["raw"].str.strip().str.len() > 0)
    d = step(led, g, "drop rows the dataset flags synthetic", d, d["classification_status"] != "synthetic", "classification_status = synthetic")
    letters = d["raw"].map(lambda t: [c for c in t if c.isalpha()])
    ascii_share = letters.map(lambda L: sum(c.isascii() for c in L) / len(L) if L else 0)
    d = step(led, g, "drop non-Latin-script rows (incl. all Hindi / Kannada)", d, ascii_share >= 0.9, "ASCII letters < 90%")
    d["text"] = d["raw"].map(mask_text).str.strip()
    d = step(led, g, f"keep {LEN_MIN}-{LEN_MAX} chars (masked text)", d, d["text"].str.len().between(LEN_MIN, LEN_MAX))
    d = step(led, g, "drop odd characters (mojibake)", d, d["text"].map(ascii_ok))
    d = step(led, g, "drop Hinglish / non-English", d, d["text"].map(english_ok))
    d = step(led, g, "drop person names (salutation + name)", d, ~d["text"].str.contains(NAME))
    bk = d["text"].map(benign_bucket)
    d = d.assign(rule=[r for _, r in bk])
    d = step(led, g, "drop promotional / not transactional", d, np.array([k for k, _ in bk]), "; ".join(f"{k}={v}" for k, v in pd.Series([r for _, r in bk]).value_counts().items()))
    d = d.assign(parent_source="otp_sms_preview", parent_is_synthetic="unknown", sender=d["sender"].map(sender_key))
    return d[["text", "parent_source", "parent_is_synthetic", "sender", "rule"]]

def select_scam(led):
    m = pd.read_csv("data/final/messages.csv", low_memory=False, usecols=["text", "text_hash", "label", "source", "is_synthetic", "language", "split", "category"])
    g = "scam (messages.csv)"
    d = m[(m["label"] == 1) & m["source"].isin(SOURCES_SCAM)]
    led.add(g, "all scam rows of scam_ham_india + india_fraud_final", len(d), len(d), ", ".join(f"{k} {v}" for k, v in d["source"].value_counts().items()))
    led.by_source.append(("all scam rows in messages.csv", d["source"].value_counts().to_dict(), d["source"].value_counts().to_dict()))
    d = step(led, g, "drop rows the source flags synthetic", d, ~d["is_synthetic"], "india_fraud_final: 86% synthetic template text")
    d = step(led, g, "english only", d, d["language"] == "english")
    d = step(led, g, f"keep {LEN_MIN}-{LEN_MAX} chars", d, d["text"].str.len().between(LEN_MIN, LEN_MAX))
    d = step(led, g, "drop odd characters (mojibake)", d, d["text"].map(ascii_ok))
    d = step(led, g, "drop Hinglish / non-English", d, d["text"].map(english_ok))
    d = step(led, g, "drop person names (salutation + name)", d, ~d["text"].str.contains(NAME))
    d = step(led, g, "drop template slots ([Link], [Phishing Link], 8240XXXXXX)", d, ~d["text"].str.contains(BRACKET_SLOT),
             "a literal '[Link]' would survive translation and exist only on the scam side")
    d = step(led, g, "drop self-labelled / advisory text (scam, phishing, malicious, beware, fake)", d, ~d["text"].str.contains(SELF_LABEL),
             "the label word would be translated into the text")
    b = d["text"].map(scam_bucket)
    keep = np.array([k for k, _ in b])
    d = d.assign(rule=[r for _, r in b])
    led.scam_rows = d.assign(keep=keep)
    per_src = {s: d[~keep & (d["source"] == s).to_numpy()].groupby("rule").size().to_dict() for s in SOURCES_SCAM}
    d = step(led, g, "SCAM RULE: drop promotional / no fraud mechanism", d, keep, f"dropped by reason per source: {per_src}")
    return d.assign(parent_source=d["source"], parent_is_synthetic="False", sender=d["source"]), m

def build_pool(args):
    """Selection + filters + anchors + template groups, before any cap. -> (parents, ledger)."""
    led = Ledger()
    ben = select_benign(led)
    scam, msgs = select_scam(led)
    ben["label"], scam["label"] = 0, 1
    p = pd.concat([ben, scam[["text", "parent_source", "parent_is_synthetic", "sender", "rule", "label"]]], ignore_index=True)
    p["parent_hash"] = p["text"].map(text_hash)
    # pii.MASKS only knows some UPI handles (@ybl, @okaxis, ...); merchant handles like dunzo.payu@axisbank or olamoney.payu@indus slip through. Drop those parents
    # rather than translate an unmasked handle into the dataset (changing the shared masks would change existing rows' text hashes and splits: not done here).
    leak = p["text"].str.contains(r"[\w.-]+@[\w.-]+", regex=True)
    led.add("all", "drop parents with an unmasked @handle", len(p), len(p) - int(leak.sum()), "pii.MASKS misses handles such as @axisbank, @indus")
    p = p[~leak].reset_index(drop=True)
    # exact duplicates (after masking, case and whitespace): keep the first
    dup = p.duplicated("parent_hash")
    led.add("all", "drop exact duplicates after masking", len(p), len(p) - dup.sum(), f"benign {int(dup[p.label == 0].sum())}, scam {int(dup[p.label == 1].sum())}")
    p = p[~dup].reset_index(drop=True)
    # a text that is in messages.csv under the other label cannot be a parent
    ml = msgs.drop_duplicates("text_hash").set_index("text_hash")["label"]
    conflict = p["parent_hash"].map(ml).notna() & (p["parent_hash"].map(ml) != p["label"])
    led.add("all", "drop parents whose text is in messages.csv with the other label", len(p), len(p) - conflict.sum())
    p = p[~conflict].reset_index(drop=True)

    # template groups + anchors: one near-duplicate pass over [parents, short messages.csv rows]
    short = msgs[msgs["text"].str.len() <= ANCHOR_LEN].drop_duplicates("text_hash")
    short = short[~short["text_hash"].isin(p["parent_hash"])].reset_index(drop=True)   # scam parents anchor to themselves
    texts = list(p["text"]) + list(short["text"])
    n = len(p)
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    best = {}   # parent position -> (jaccard, messages row position)
    nbr_splits = {}
    for view, fn in neardup.VIEWS.items():
        shs = neardup.shingle_sets([fn(t) for t in texts])
        for i, j, jac in neardup.near_dup_pairs(shs, neardup.CHECK_SEED, TEMPLATE_JACCARD, queries=range(n)):
            if j < n:
                parent[find(i)] = find(j)
            else:
                nbr_splits.setdefault(i, set()).add(short.at[j - n, "split"])
                if jac > best.get(i, (0, None))[0]:
                    best[i] = (jac, j - n)
        del shs
    p["template_id"] = [find(i) for i in range(n)]
    msg_hash = dict(zip(msgs["text_hash"], msgs["split"]))
    anchor = []
    for i, r in p.iterrows():
        if r["parent_hash"] in msg_hash:
            anchor.append((r["parent_hash"], msg_hash[r["parent_hash"]], "self", 1.0))
        elif i in best:
            jac, j = best[i]
            anchor.append((short.at[j, "text_hash"], short.at[j, "split"], "near_twin", jac))
        else:
            anchor.append(("", "", "", np.nan))
    p[["anchor_hash", "anchor_split", "anchor_kind", "anchor_jaccard"]] = pd.DataFrame(anchor, index=p.index)
    conflict = pd.Series([len(nbr_splits.get(i, ())) > 1 for i in range(n)], index=p.index)
    led.add("all", "drop preview parents whose English near-twins sit in 2+ splits", len(p), len(p) - conflict.sum(),
            "the translation could not inherit one split without bridging frozen clusters")
    p = p[~conflict].reset_index(drop=True)
    anchored = p[p["anchor_kind"] == "near_twin"]
    print(f"preview parents with a near-twin (J >= {TEMPLATE_JACCARD}) already in messages.csv: {len(anchored)} "
          f"({anchored['anchor_split'].value_counts().to_dict()}); they inherit that split at build time")
    p["order"] = p["parent_hash"].map(lambda h: hashlib.md5((h + str(args.seed)).encode()).hexdigest())
    p = p.sort_values("order").reset_index(drop=True)
    p["category"] = p["text"].map(category)
    return p, led

def apply_caps(p, cap_template, cap_sender, led=None, balance_cues=True):
    """At most cap_template parents per template group, then at most cap_sender benign parents per named sender (rows without a
    sender id are exempt: they are not one sender). Deterministic. balance_cues=True: inside a template group the cap keeps the LEAST
    numeric benign parents and the MOST numeric scam parents (see richness); every group still keeps min(size, cap) parents, so no
    template or topic is dropped. balance_cues=False: hash order."""
    rich = p["text"].map(richness) if balance_cues else pd.Series(0.0, index=p.index)
    p = p.assign(_k=np.where(p["label"] == 0, rich, -rich)).sort_values(["template_id", "_k", "order"])
    sizes = p["template_id"].value_counts()
    q = p[p.groupby("template_id").cumcount() < cap_template]
    if led is not None:
        led.add("all", f"cap {cap_template} parents per template group", len(p), len(q),
                f"largest group before the cap: {int(sizes.max())} parents; groups > cap: {int((sizes > cap_template).sum())} of {len(sizes)}; "
                f"inside a group the least numeric benign / most numeric scam parents are kept" if balance_cues else f"largest group before the cap: {int(sizes.max())} parents")
    q = q.sort_values(["_k", "order"])
    ok = (q["label"] == 1) | (q["sender"] == "unknown") | (q.groupby(["label", "sender"]).cumcount() < cap_sender)
    if led is not None:
        led.add("all", f"cap {cap_sender} benign parents per named sender", len(q), int(ok.sum()), "rows without a sender id are exempt")
    return q[ok].drop(columns="_k").sort_values("order").reset_index(drop=True)

# synth_india Hindi / Kannada rows already in messages.csv (per language): 231 scam + 163 benign. They are never touched.
SYNTH_SCAM, SYNTH_BENIGN = 231, 163
SCAM_SHARE = 0.15        # scam share of the TRANSLATED rows: a design choice, not whatever the caps leave
TARGET_OVERALL = 0.35    # overall Hindi / Kannada scam share we want to be at or below (synth_india rows included)

MASK_RE = re.compile(r"<(?:EMAIL|UPI_ID|PHONE|ACCOUNT)>")
URL_RE = re.compile(r"https?://|www\.|\b[\w-]+\.(?:com|in|co|ly|me|it|im|cc|net|org|fm)\b", re.I)
AMOUNT_RE = re.compile(r"(?:rs\.?|inr|\u20b9)\s?\d|\d\s?(?:lakh|crore|thousand)", re.I)

def cue_frame(texts):
    """Surface cues a model could use instead of the meaning. Also run on the translations (finalise), where latin_share matters."""
    t = pd.Series(list(texts))
    n = t.str.len().clip(lower=1)
    letters = t.map(lambda x: [c for c in x if c.isalpha()])
    return pd.DataFrame({
        "log_len": np.log1p(t.str.len()), "len": t.str.len(),
        "digit_share": t.map(lambda x: sum(c.isdigit() for c in x)) / n,
        "mask_share": t.map(lambda x: sum(len(m) for m in MASK_RE.findall(x))) / n,
        "n_mask": t.map(lambda x: len(MASK_RE.findall(x))),
        "has_digit": t.map(lambda x: any(c.isdigit() for c in x)), "has_mask": t.map(lambda x: bool(MASK_RE.search(x))),
        "has_amount": t.map(lambda x: bool(AMOUNT_RE.search(x))), "has_url": t.map(lambda x: bool(URL_RE.search(x))),
        "latin_share": letters.map(lambda L: sum(c.isascii() for c in L) / len(L) if L else 1.0)})

def richness(text):
    """How numeric a message is: digit share plus 0.10 if it holds a mask token (<PHONE>, <ACCOUNT> ...). Used to prefer numeric scam
    parents and less numeric benign parents when a choice exists."""
    return sum(c.isdigit() for c in text) / max(1, len(text)) + 0.10 * bool(MASK_RE.search(text))

CONFOUND_MODELS = {"length only": ["log_len"], "digit/mask share only": ["digit_share", "mask_share", "n_mask"],
                   "latin share + length": ["latin_share", "log_len"],
                   "all cues (length, digit/mask, latin, url)": ["log_len", "digit_share", "mask_share", "n_mask", "latin_share", "has_url"]}

def auroc_ci(y, score, groups, boot, seed=0):
    """95% interval for an AUROC by resampling template groups (not rows) with replacement; the out-of-fold scores are reused, nothing is refitted."""
    from sklearn.metrics import roc_auc_score
    rng = np.random.default_rng(seed)
    keys = pd.unique(groups)
    where = {k: np.flatnonzero(groups == k) for k in keys}
    vals = []
    for _ in range(boot):
        ii = np.concatenate([where[keys[j]] for j in rng.integers(0, len(keys), len(keys))])
        if 0 < y[ii].sum() < len(ii):
            vals.append(roc_auc_score(y[ii], score[ii]))
    return tuple(np.percentile(vals, [2.5, 97.5]))

def confound_report(df, group_col="template_id", label_col="label", text_col="text", n_splits=5, seed=0, boot=0):
    """Cue-only models: each sees only surface cues, never the words. Depth-3 decision tree (balanced classes), out-of-fold scores with
    GroupKFold on the template group, so near-identical messages never sit in both train and test folds. AUROC near 0.5 = the cues
    carry no label signal; the translated set should be near 0.5 for 'latin share + length' and 'digit/mask share only' before it is used.
    boot > 0 adds a group-bootstrap 95% interval for the AUROC (columns AUROC_lo, AUROC_hi)."""
    from sklearn.metrics import balanced_accuracy_score, roc_auc_score
    from sklearn.model_selection import GroupKFold
    from sklearn.tree import DecisionTreeClassifier
    X, y, g = cue_frame(df[text_col]), df[label_col].to_numpy(), df[group_col].to_numpy()
    rows = []
    for name, cols in CONFOUND_MODELS.items():
        oof = np.zeros(len(df))
        for tr, te in GroupKFold(n_splits).split(X, y, g):
            clf = DecisionTreeClassifier(max_depth=3, min_samples_leaf=10, class_weight="balanced", random_state=seed).fit(X.iloc[tr][cols], y[tr])
            oof[te] = clf.predict_proba(X.iloc[te][cols])[:, 1]
        row = {"model": name, "AUROC": roc_auc_score(y, oof), "balanced_acc": balanced_accuracy_score(y, oof >= 0.5)}
        if boot:
            row["AUROC_lo"], row["AUROC_hi"] = auroc_ci(y, oof, g, boot, seed)
        rows.append(row)
    return pd.DataFrame(rows)

def pick_scam(q, share, seed, numeric=True, floor=3, n=None):
    """Size the scam parents from the benign count so scam is `share` of the translated rows: n = share / (1 - share) * benign.
    numeric=False: one parent per template group first, then hash order.
    numeric=True (default): spread n over the fraud-mechanism buckets (rule) so every bucket keeps min(available, floor) parents and the
    rest is proportional to what is left, then inside a bucket prefer one parent per template and the most numeric ones (amounts, numbers,
    mask tokens), so the scam side's digit/mask cues move toward the benign side without a whole scam type disappearing (the 17
    authority-threat parents have almost no digits; picking by digit share alone would drop them all). Anchor splits are frozen, so
    nothing here moves a row."""
    ben, sc = q[q.label == 0], q[q.label == 1]
    n = min(len(sc), int(round(share / (1 - share) * len(ben)))) if n is None else min(len(sc), n)   # n given: keep exactly n scam rows (finalise)
    if not numeric:
        sc = sc.assign(_rank=sc.groupby("template_id").cumcount()).sort_values(["_rank", "order"]).head(n).drop(columns="_rank")
        return pd.concat([ben, sc]).sort_values("order").reset_index(drop=True)
    sc = sc.assign(_rich=sc["text"].map(richness))
    avail = sc.groupby("rule").size()
    alloc = np.minimum(avail, floor).astype(int)
    spare = avail - alloc
    if n > alloc.sum() and spare.sum() > 0:
        extra = spare / spare.sum() * (n - alloc.sum())
        add = np.floor(extra).astype(int)
        for r in (extra - add).sort_values(ascending=False).index[: int(n - alloc.sum() - add.sum())]:
            add[r] += 1
        alloc = alloc + add
    parts = []
    for r, k in alloc.items():
        g = sc[sc["rule"] == r].sort_values(["_rich", "order"], ascending=[False, True])
        g = g.assign(_rank=g.groupby("template_id").cumcount()).sort_values(["_rank", "_rich", "order"], ascending=[True, False, True])
        parts.append(g.head(int(k)))
    sc = pd.concat(parts).drop(columns=["_rich", "_rank"])
    return pd.concat([ben, sc]).sort_values("order").reset_index(drop=True)

def split_sim(q, trials=2000, seed=0):
    """Expected benign rows per split if each template group gets a hash bucket (80/10/10) like build_text.py does for a fresh
    cluster. Parents with a near-twin in messages.csv are fixed to that row's split. -> {split: (mean, 5th percentile)}."""
    ben = q[q.label == 0]
    fixed = ben[ben.anchor_kind != ""].groupby("anchor_split").size()
    free = ben[ben.anchor_kind == ""].groupby("template_id").size().to_numpy()
    u = np.random.default_rng(seed).integers(0, 100, size=(trials, len(free)))
    out = {}
    for name, lo, hi in (("train", 0, 80), ("val", 80, 90), ("test", 90, 100)):
        c = ((u >= lo) & (u < hi)) @ free + int(fixed.get(name, 0))
        out[name] = (c.mean(), np.percentile(c, 5))
    return out

def sweep_table(pool, template_caps, sender_caps, share, seed, survival=0.85):
    rows = []
    for ct in template_caps:
        for cs in sender_caps:
            q = pick_scam(apply_caps(pool, ct, cs), share, seed)
            nb, ns = int((q.label == 0).sum()), int((q.label == 1).sum())
            sim = split_sim(q, seed=seed)
            sc = q[q.label == 1]
            rows.append({"cap_template": ct, "cap_sender": cs, "benign_parents": nb, "benign_templates": q[q.label == 0]["template_id"].nunique(),
                         "scam_parents": ns,
                         "hi_kn_scam_share": (SYNTH_SCAM + ns) / (SYNTH_SCAM + SYNTH_BENIGN + nb + ns),
                         f"share_if_{int(survival * 100)}pct_survive": (SYNTH_SCAM + survival * ns) / (SYNTH_SCAM + SYNTH_BENIGN + survival * (nb + ns)),
                         "benign_val_mean(p5)": f"{sim['val'][0]:.0f} ({sim['val'][1]:.0f})", "benign_test_mean(p5)": f"{sim['test'][0]:.0f} ({sim['test'][1]:.0f})",
                         "scam_val": int((sc.anchor_split == "val").sum()), "scam_test": int((sc.anchor_split == "test").sum())})
    return pd.DataFrame(rows)

def stage_selection(pool, args, benign_balanced, scam_numeric):
    """The selection under one of the three stages the report compares: A = hash order for both labels; B = numeric-preferring scam picks only;
    C = B plus the least numeric benign parents inside each template group (the default, what is written)."""
    q = apply_caps(pool, args.cap_template, args.cap_sender, balance_cues=benign_balanced or scam_numeric)
    if scam_numeric and not benign_balanced:
        qh = apply_caps(pool, args.cap_template, args.cap_sender, balance_cues=False)
        q = pd.concat([qh[qh.label == 0], q[q.label == 1]]).sort_values("order")
    return pick_scam(q, args.scam_share, args.seed, numeric=scam_numeric)

def run_parents(args):
    pool, led = build_pool(args)
    if args.sweep:
        print(md(sweep_table(pool, (1, 2, 3, 5, 8, 12, 15, 20), (60,), args.scam_share, args.seed)))
        return
    p = apply_caps(pool, args.cap_template, args.cap_sender, led)
    n_s = int((p.label == 1).sum())
    p = pick_scam(p, args.scam_share, args.seed)
    led.add("all", f"size scam parents to {args.scam_share:.0%} of the translated rows", len(p) + n_s - int((p.label == 1).sum()), len(p),
            f"{int((p.label == 0).sum())} benign -> {int((p.label == 1).sum())} scam parents (of {n_s} available)")
    p["channel"] = "sms"
    p["parent_provenance"] = "unknown"
    p = p.sort_values(["label", "parent_hash"]).reset_index(drop=True)
    p.insert(0, "parent_id", [f"p{i:05d}" for i in range(len(p))])
    cols = ["parent_id", "parent_hash", "anchor_hash", "anchor_kind", "anchor_split", "parent_source", "parent_is_synthetic", "parent_provenance",
            "label", "category", "channel", "template_id", "sender", "rule", "text"]
    os.makedirs(OUT_DIR, exist_ok=True)
    out = f"{OUT_DIR}/parents_{dt.date.today().isoformat()}.csv"
    p[cols].to_csv(out, index=False)
    write_report(p, led, out, args, pool)
    print(f"wrote {out} ({len(p)} parents: {int((p.label == 0).sum())} benign, {int((p.label == 1).sum())} scam) and {REPORT}")

def write_report(p, led, out, args, pool):
    tmpl = p.groupby("template_id").size()
    p = p.assign(norm_key=p["text"].map(lambda t: " ".join(re.sub(r"\d+", "N", t.lower()).split()[:6])))
    coarse = p.groupby("norm_key").size().sort_values(ascending=False)
    top_t = p.groupby("template_id").size().idxmax()
    L = [f"# Translation parents\n\nGenerated by `src/translate_parents.py parents` on {dt.date.today().isoformat()} -> `{out}`. "
         f"Settings: length {LEN_MIN}-{LEN_MAX} chars, template cap {args.cap_template}, sender cap {args.cap_sender}, template Jaccard {TEMPLATE_JACCARD}, seed {args.seed}. "
         "Nothing here changes messages.csv or split_map.csv; the English parents are not added to the dataset, only their translations will be.\n",
         "## Row ledger\n\n" + md(led.frame()),
         "\n## Scam path per source (rows in -> rows left at each step)\n\n" + md(pd.DataFrame(
             [{"step": n, **{f"{src}": f"{i.get(src, 0)} -> {o.get(src, 0)}" for src in SOURCES_SCAM}} for n, i, o in led.by_source])),
         "\n" + RULE_TEXT,
         f"\n## Parents written\n\n{md(p.groupby(['parent_source', 'label']).size().rename('parents').reset_index())}\n",
         "Anchors: `anchor_kind = self` means the parent is itself a messages.csv row; `near_twin` means a preview parent has a messages.csv row at "
         f"exact Jaccard >= {TEMPLATE_JACCARD} (raw or normalised view). At build time the translation joins that row's cluster and inherits its split, so an "
         "English twin in train can never have its Hindi/Kannada translation in test.\n\n" + md(p.groupby(["anchor_kind", "anchor_split"]).size().rename("parents").reset_index()),
         "\n## Template groups after the cap\n\n"
         f"- largest template group: {int(tmpl.max())} parents (cap {args.cap_template}); groups of that size: {int((tmpl == tmpl.max()).sum())}; groups with 1 parent: {int((tmpl == 1).sum())} of {len(tmpl)}.\n"
         f"- independent check with a coarser key (first 6 words, digits -> N): largest group {int(coarse.iloc[0])} parents (`{coarse.index[0]}`); "
         f"top 5: {', '.join(f'{k!r} x{v}' for k, v in coarse.head(5).items())}. The cap bounds near-duplicate clusters, not a shared sentence opening, so a coarse group can exceed the cap.\n"
         f"- benign senders: {p[p.label == 0]['sender'].nunique()} distinct, largest {p[p.label == 0]['sender'].value_counts().head(5).to_dict()}.\n",
         "\n## Label cues in the English parents (CLAUDE.md rule 3)\n\n@@CUES@@"]
    stages = {"A: hash order (before)": stage_selection(pool, args, False, False), "B: scam picks prefer numbers": stage_selection(pool, args, False, True),
              "C: B + benign least-numeric per template (written)": stage_selection(pool, args, True, True)}
    cue_rows, model_rows = [], []
    for name, q in stages.items():
        cf = cue_frame(q["text"])
        cf["label"] = q["label"].to_numpy()
        for lab, g in cf.groupby("label"):
            cue_rows.append({"stage": name, "label": ["benign", "scam"][lab], "n": len(g), "median_len": g["len"].median(), "digit_share": g["digit_share"].mean(),
                             "has_digit": g["has_digit"].mean(), "has_mask_token": g["has_mask"].mean(), "has_amount": g["has_amount"].mean(), "has_url": g["has_url"].mean()})
        m = confound_report(q)
        m.insert(0, "stage", name)
        model_rows.append(m)
    A, C = stages["A: hash order (before)"], p
    cov = pd.DataFrame({"scam parents, stage A": A[A.label == 1]["rule"].value_counts(), "scam parents, written": C[C.label == 1]["rule"].value_counts()}).fillna(0).astype(int)
    bcat = pd.DataFrame({"benign parents, stage A": A[A.label == 0]["category"].value_counts(), "benign parents, written": C[C.label == 0]["category"].value_counts()}).fillna(0).astype(int)
    syn = pd.read_csv("data/final/messages.csv", low_memory=False, usecols=["text", "label", "source", "language", "template_id"])
    syn = syn[(syn["source"] == "synth_india") & (syn["language"] == "hindi")]
    scf = cue_frame(syn["text"])
    scf["label"] = syn["label"].to_numpy()
    sauc = confound_report(syn.assign(template_id=syn["template_id"].astype(str))).set_index("model").loc["digit/mask share only"]
    base_line = (f"\n\n**Baseline for the post-translation confound check:** the existing synth_india Hindi rows ({int((scf.label == 0).sum())} benign, {int((scf.label == 1).sum())} scam) "
                 f"already have digit/mask share benign {scf[scf.label == 0]['digit_share'].mean():.1%} vs scam {scf[scf.label == 1]['digit_share'].mean():.1%}, and a digit/mask-share-only "
                 f"model scores AUROC {sauc['AUROC']:.2f} (balanced accuracy {sauc['balanced_acc']:.2f}) on them; the translated rows are judged against this.")
    cues = ("These cues carry into the translations: protected numbers, amounts and mask tokens are restored verbatim. A gap is not an error (real transaction alerts do "
            "carry more digits than real scams) but a model can use it instead of the message.\n\n"
            "**What was done, and what was not.** Scam parents are chosen per fraud-mechanism bucket with a floor of 3 per bucket (so digital-arrest and KYC scams, which have "
            "almost no digits, stay in) and, inside a bucket, the most numeric parents are preferred; benign parents inside a template group keep the least numeric ones "
            "(every template and topic still has at least one parent). Picking scam parents by digit share alone reaches only 4.5% and would drop all 17 authority-threat parents; "
            "only 3 of the 231 available scam parents contain a mask token and only 2 reach a 9.9% digit share, so the gap cannot be closed by selection. "
            "It was left as it is on purpose. The post-translation confound check (`finalise`) measures whether it matters on the translated text.\n\n"
            + md(pd.DataFrame(cue_rows)) + "\n\nCue-only models on the English parents (each sees surface cues, never the words; depth-3 tree, 5-fold GroupKFold by template; "
            "AUROC 0.5 = no label signal). Length alone separates the classes at stage C (scam parents are shorter); length is matched after translation in `finalise`.\n\n"
            + md(pd.concat(model_rows)) + "\n\nCoverage kept (stage A -> written):\n\n" + md(cov.reset_index().rename(columns={"index": "rule"}))
            + "\n\n" + md(bcat.reset_index().rename(columns={"index": "category"})) + base_line)
    L[-1] = L[-1].replace("@@CUES@@", cues)
    ex = led.scam_rows
    L.append("\n## SCAM RULE examples (random, 5 per cell)\n")
    for rule in sorted(ex["rule"].unique()):
        for src in SOURCES_SCAM:
            g = ex[(ex["rule"] == rule) & (ex["source"] == src)]
            if len(g):
                L.append(f"**{'kept' if g['keep'].iloc[0] else 'DROPPED'} / {rule} / {src}** ({len(g)} rows)\n")
                L.extend(f"- {t}" for t in g["text"].sample(min(5, len(g)), random_state=args.seed))
                L.append("")
    ben_all = pool[pool.label == 0]
    zero = ben_all["text"].str.contains(r"(?:INR|Rs\.?)\s?0\d").sum()
    L.append("\n## Hindi / Kannada scam share by cap setting\n\n"
             f"The {len(ben_all)} benign parents that pass the filters (before any cap) fall into only {ben_all['template_id'].nunique()} template groups "
             f"(exact Jaccard >= {TEMPLATE_JACCARD}); card-spend alerts, 'OTP for txn' and FASTag notices dominate. Scam parents are sized to {args.scam_share:.0%} of the translated rows. "
             "`hi_kn_scam_share` = (231 synth scam + scam parents) / (394 synth + all parents) per language, if every parent survives translation; the next column assumes 85% survive. "
             "`benign_val/test` = expected benign rows per split (and the 5th percentile) when each template group takes a hash bucket as build_text.py does for fresh clusters. "
             "The 394 existing synth_india rows per language (231 scam, 163 benign; 0 val rows) are untouched. Today's share is 58.6%.\n\n"
             + md(sweep_table(pool, (1, 2, 3, 5, 8, 12, 15, 20), (60,), args.scam_share, args.seed)))
    L.append(f"\n## Provenance of the preview rows\n\n- Dataset card: '73,470 SMS collected from real-world sources and labeled using manual annotation, prompt-based LLM evaluation, and synthetic augmentation'; "
             "title 'Synthetic + Labeled'. The preview README only says it is a subset of that set. `classification_status` = synthetic marks 1,632 of the preview's 10,000 rows; "
             "`auto_not_otp` / `success` rows are not flagged.\n"
             f"- Evidence the unflagged rows are not all untouched real SMS: {int(zero)} of the {len(ben_all)} filtered benign parents print an amount with a leading zero "
             "(`INR 040.27`, `Rs. 076.05`), which no bank statement does, so at least some numbers were machine-randomised; many rows share one template with different card digits, "
             "dates and amounts.\n- So parent provenance is recorded as `unknown`, parent_is_synthetic as `unknown`, and every translation is is_synthetic=True.\n")
    rng = np.random.default_rng(args.seed)
    L.append("\n## 20 random parents\n")
    for _, r in p.iloc[rng.choice(len(p), min(20, len(p)), replace=False)].iterrows():
        L.append(f"- `{r.parent_id}` {['benign', 'scam'][r.label]} / {r.parent_source} / {r.category} / {r.rule}: {r.text}")
    os.makedirs("reports", exist_ok=True)
    open(REPORT, "w").write("\n".join(L) + "\n")

# ---------------------------------------------------------------------------------------------------------------------
# FINALISE: content filters on the translations, scam trim, cue-only confound check, optional length-bin sampling, spot-check sheets.
#   python src/translate_parents.py finalise [--length-match]     (length-bin sampling is off unless asked for; see the decision section of the report)
# Reads the parents file and the raw translation CSV (latest dated file of each unless --parents / --raw), writes
#   data/external/indic/translated/translated_final_<date>.csv     kept translations (the rows build_text.py will ingest later)
#   data/external/indic/translated/translated_dropped_<date>.csv   every dropped translation and the step that dropped it
#   reports/translate_finalise.md, reports/spotcheck_hi.csv, reports/spotcheck_kn.csv
# It does not touch messages.csv or split_map.csv.
# ---------------------------------------------------------------------------------------------------------------------
FINAL_REPORT = "reports/translate_finalise.md"
SET_A, SET_B = "COMBINED pool, no length sampling", "COMBINED pool, length-bin sampled (pass B)"
TRANSLATED_DIR = "data/external/indic/translated"
LANG_BLOCK = {"hindi": (0x0900, 0x097F), "kannada": (0x0C80, 0x0CFF)}      # Unicode blocks of the two target scripts
LANG_CODE = {"hindi": "hi", "kannada": "kn"}
MIN_TARGET_SHARE = 0.5     # leftover English: at least half of the letters outside the protected spans must be in the target script
N_LEN_BINS = 8             # length-bin sampling: equal-mass bins of the scam-side length distribution
SPOT_N = 50
REF_SOURCES, REF_MAX_LEN = ("uci_sms_spam", "scam_ham_india"), 160     # English reference for the cue-only models: real short SMS
# Personal names found by eye in the English parents (rare capitalised tokens read in context: UPI payer names, a train passenger, a delivery
# rider, a doctor, a guest). pii.MASKS has no name masking, so these parents would put real-looking names into data/final/ (CLAUDE.md rule 5).
# Curated, not exhaustive: it only covers this parents file. The proper fix is name masking at ingestion (BUGS.md).
NAME_RX = re.compile(r"\b(?:GANDHARV|BHAKSHI|RACHURI|CHAKRAV|VUTNOORI|RAVINDER|GOKULA|MAHBUBAN|RENU|SIDDHARTH|PURUSHOTHAMA|MAHESH|Gowrisha|"
                     r"Saleem|Arun|CHINNAYYA|Srinivas|Rajashekar)\b", re.I)

def latest(pattern):
    found = sorted(glob.glob(pattern))
    if not found:
        sys.exit(f"nothing matches {pattern}")
    return found[-1]

def script_counts(text, lang):
    """(target-script letters+marks, letters of any other non-ASCII script, ASCII letters). Digits, punctuation and symbols are ignored."""
    lo, hi = LANG_BLOCK[lang]
    tgt = foreign = latin = 0
    for ch in text:
        if unicodedata.category(ch)[0] not in "LM":
            continue
        if lo <= ord(ch) <= hi:
            tgt += 1
        elif ch.isascii():
            latin += 1
        else:
            foreign += 1
    return tgt, foreign, latin

def evaluate_translations(raw, parents):
    """One row per (parent, language) with the parent's fields and the measurements the filters use. Hard checks: the parents file and the
    raw CSV agree, and every kept translation is exactly restore(raw_output)."""
    cols = ["parent_id", "category", "channel", "template_id", "sender", "rule", "anchor_hash", "anchor_kind", "anchor_split",
            "parent_is_synthetic", "parent_provenance", "text"]
    d = raw.merge(parents[cols].rename(columns={"text": "parent_text"}), on="parent_id", how="left", validate="m:1")
    assert d["parent_text"].notna().all(), "translation rows whose parent_id is not in the parents file"
    chk = raw.merge(parents[["parent_id", "label", "parent_hash"]], on="parent_id", suffixes=("", "_p"))
    assert (chk["label"] == chk["label_p"]).all() and (chk["parent_hash"] == chk["parent_hash_p"]).all(), "raw CSV and parents file disagree"
    d["anchor_kind"], d["anchor_split"] = d["anchor_kind"].fillna(""), d["anchor_split"].fillna("")
    d["marker_ok"] = d["translation"].notna()
    assert (d["marker_ok"] == (d["status"] == "ok")).all()
    out = []
    for r in d.itertuples():
        row = {"name_hit": bool(NAME_RX.search(r.parent_text))}
        if r.marker_ok:
            prot, spans = protect(r.parent_text)
            assert prot == r.protected, f"{r.parent_id}: protected text differs between the parents file and the raw CSV"
            assert restore(r.raw_output, spans)[0] == r.translation, f"{r.parent_id} {r.lang}: translation is not restore(raw_output)"
            tgt, foreign, latin = script_counts(strip_markers(r.raw_output), r.lang)
            row.update(tgt=tgt, foreign=foreign, latin=latin, target_share=tgt / max(1, tgt + latin),
                       digits_ok=sorted(re.findall(r"[0-9]", r.parent_text)) == sorted(re.findall(r"[0-9]", r.translation)),
                       masks_ok=sorted(MASK_RE.findall(r.parent_text)) == sorted(MASK_RE.findall(r.translation)),
                       text_hash=text_hash(r.translation), tlen=len(r.translation))
        out.append(row)
    return pd.concat([d, pd.DataFrame(out, index=d.index)], axis=1)

class FinLedger:
    """Row counts by label at every step, per language."""
    def __init__(self):
        self.rows = []
    def add(self, lang, step, before, after, note=""):
        b0, b1, a0, a1 = (int((x.label == k).sum()) for x in (before, after) for k in (0, 1))
        self.rows.append({"language": lang, "step": step, "benign_in": b0, "benign_dropped": b0 - a0, "scam_in": b1, "scam_dropped": b1 - a1,
                          "benign_left": a0, "scam_left": a1, "note": note})
    def frame(self):
        return pd.DataFrame(self.rows)

def length_match(a, synth_lang, seed, n_bins=N_LEN_BINS):
    """Length-bin sampling of the translated BENIGN rows so that, in the Hindi (or Kannada) training pool = existing synth_india rows + kept
    translations, the benign length histogram follows the scam one. Bins: equal-mass bins of the pool's scam lengths. Benign rows outside the
    scam range are dropped (no scam row lives there). With the synth rows fixed, bin b keeps round(r * scam_b) - synth_benign_b translated benign
    rows (clipped to [0, available]); r is the largest benign:scam ratio every bin can reach. Random within a bin (seeded). -> (kept index labels, bin table)."""
    t_ben, t_sc = a[a.label == 0], a[a.label == 1]
    s_ben = synth_lang.loc[synth_lang.label == 0, "text"].str.len().to_numpy().astype(int)
    sc_len = np.concatenate([synth_lang.loc[synth_lang.label == 1, "text"].str.len().to_numpy().astype(int), t_sc["tlen"].to_numpy().astype(int)])
    edges = np.unique(np.quantile(sc_len, np.linspace(0, 1, n_bins + 1)))
    nb = len(edges) - 1
    bin_of = lambda x: np.digitize(x, edges[1:-1])
    inside = lambda x: (x >= edges[0]) & (x <= edges[-1])
    scam_b = np.bincount(bin_of(sc_len), minlength=nb)
    synth_b = np.bincount(bin_of(s_ben[inside(s_ben)]), minlength=nb)
    tb = t_ben[inside(t_ben["tlen"].to_numpy().astype(int))]
    tb = tb.assign(_bin=bin_of(tb["tlen"].to_numpy().astype(int)))
    avail = np.bincount(tb["_bin"].to_numpy(), minlength=nb)
    r = np.min((synth_b + avail) / scam_b)
    target = np.clip(np.rint(r * scam_b).astype(int) - synth_b, 0, avail)
    rng, keep = np.random.default_rng(seed), []
    for b in range(nb):
        ids = np.sort(tb.index[tb["_bin"] == b].to_numpy())
        if target[b]:
            keep.extend(rng.choice(ids, size=int(target[b]), replace=False).tolist())
    table = pd.DataFrame({"length_bin": [f"{int(edges[b])}-{int(edges[b + 1])}" for b in range(nb)], "scam_in_pool": scam_b, "synth_benign": synth_b,
                          "translated_benign_available": avail, "translated_benign_kept": target})
    return keep, table.assign(ratio_r=round(float(r), 2))

def run_pipeline(d, args, existing, synth, match_langs=()):
    """Content filters -> (optional length-bin sampling against the pool's scam lengths) -> scam trim, per language. In a length-matched language the scam trim is skipped: it would cut scam to 15% of an already reduced benign set. Returns d with
    drop_step ('' = kept), the ledger, bin tables."""
    d = d.copy()
    d["drop_step"] = ""
    led, bins = FinLedger(), {}
    alive = lambda lang: (d["lang"] == lang) & (d["drop_step"] == "")
    def step_(lang, name, hit, note=""):
        before = d[alive(lang)]
        d.loc[alive(lang) & hit.astype(bool), "drop_step"] = name
        led.add(lang, name, before, d[alive(lang)], note)
    none = pd.Series(False, index=d.index)
    for lang in LANG_BLOCK:
        a = d[alive(lang)]
        led.add(lang, "translations requested (parents x 1 language)", a, a)
        step_(lang, "marker restore failed (after the greedy retry)", ~d["marker_ok"], "the model dropped or duplicated a number marker; strict restore, nothing is repaired by guessing")
        step_(lang, "person name in the English parent (rule 5)", d["name_hit"], "NAME_RX, curated by eye, not exhaustive")
        step_(lang, "digit or mask-token mismatch", d["digits_ok"].eq(False) | d["masks_ok"].eq(False), "ASCII digits and <PHONE>/<ACCOUNT>/... tokens must equal the parent's, as multisets")
        step_(lang, "wrong script", (d["foreign"] > 0) | (d["tgt"] == 0), "a letter of another non-ASCII script, or no target-script letter at all")
        step_(lang, "leftover English", d["target_share"] < args.min_target_share,
              f"fewer than {args.min_target_share:.0%} of the letters outside the protected spans are in the target script")
        step_(lang, "exact duplicate of a messages.csv row", d["text_hash"].isin(existing))
        step_(lang, "exact duplicate within the translations", a_dup(d, alive(lang)), "first kept")
        if lang in match_langs:
            keep, bins[lang] = length_match(d[alive(lang)], synth[synth.language == lang], args.seed)
            hit = pd.Series(~d.index.isin(keep), index=d.index) & (d["label"] == 0)
            step_(lang, "length-bin sampling of benign rows", hit, f"{N_LEN_BINS} equal-mass bins of the pool's scam lengths; kept benign:scam ratio equal in every bin")
        else:
            step_(lang, "length-bin sampling of benign rows (not applied)", none)
        a = d[alive(lang)]
        n_ben = int((a.label == 0).sum())
        n_target = int(round(args.scam_share / (1 - args.scam_share) * n_ben))
        sc, hit = a[a.label == 1], none.copy()
        if lang in match_langs:
            step_(lang, f"trim scam to ~{args.scam_share:.0%} of the translated rows (skipped)", hit,
                  f"skipped after length-bin sampling: {n_ben} benign would allow only {n_target} of the {len(sc)} scam rows")
            continue
        note = f"target {n_target} scam rows for {n_ben} benign ({args.scam_share:.0%} of the translated rows); {len(sc)} available"
        if len(sc) > n_target:
            ev = sc[sc["anchor_split"].isin(["val", "test"])]
            tr = sc.drop(ev.index)
            k = n_target - len(ev)
            kept = pick_scam(tr.assign(order=np.arange(len(tr)), text=tr["translation"], _id=tr.index), args.scam_share, args.seed, n=k)
            assert len(kept) == k, f"{lang}: scam trim kept {len(kept)} rows, wanted {k}"
            hit.loc[tr.index.difference(kept["_id"])] = True
            note += f"; the {len(ev)} val/test scam rows are never trimmed (val/test scam is thin), the cut comes from train rows, most numeric kept (floor 3 per fraud mechanism)"
        step_(lang, f"trim scam to ~{args.scam_share:.0%} of the translated rows", hit, note)
    return d, led, bins

def a_dup(d, alive_mask):
    dup = d[alive_mask].duplicated("text_hash", keep="first")
    return dup.reindex(d.index, fill_value=False)

def pool_frame(synth_lang, t):
    """The Hindi (or Kannada) training pool as the confound check sees it: existing synth_india rows + translations, groups kept apart by prefix."""
    s = pd.DataFrame({"text": synth_lang["text"].to_numpy(), "label": synth_lang["label"].to_numpy(), "template_id": "s" + synth_lang["template_id"].astype(str).to_numpy()})
    x = pd.DataFrame({"text": t["translation"].to_numpy(), "label": t["label"].to_numpy(), "template_id": "t" + t["template_id"].astype(str).to_numpy()})
    return pd.concat([s, x], ignore_index=True)

def english_reference(m, boot, seed):
    e = m[m["source"].isin(REF_SOURCES) & (m["language"] == "english") & (m["text"].str.len() <= REF_MAX_LEN)]
    assert not e["is_synthetic"].any()
    df = pd.DataFrame({"text": e["text"].to_numpy(), "label": e["label"].to_numpy(), "template_id": "c" + e["cluster_id"].astype(str).to_numpy()})
    return confound_report(df, boot=boot, seed=seed), df

def ci_str(r):
    return f"{r.AUROC:.2f} [{r.AUROC_lo:.2f}, {r.AUROC_hi:.2f}]"

def spot_sample(f, n, seed, min_per_source=10):
    """n rows: half benign, half scam; scam split over the parent sources in proportion to what is available (at least min_per_source each)."""
    n_b = n // 2
    ben, sc = f[f.label == 0], f[f.label == 1]
    picks = [ben.sample(min(n_b, len(ben)), random_state=seed)]
    counts = sc.groupby("parent_source").size()
    alloc = {s: min(int(c), min_per_source) for s, c in counts.items()}
    spare = {s: int(counts[s]) - alloc[s] for s in alloc}
    rest, tot = min(n - n_b - sum(alloc.values()), sum(spare.values())), sum(spare.values())
    if rest > 0:
        share = {s: spare[s] / tot * rest for s in spare}
        add = {s: int(v) for s, v in share.items()}
        for s in sorted(share, key=lambda s: share[s] - add[s], reverse=True)[: rest - sum(add.values())]:
            add[s] += 1
        alloc = {s: alloc[s] + add[s] for s in alloc}
    picks += [sc[sc.parent_source == s].sample(k, random_state=seed) for s, k in alloc.items()]
    return pd.concat(picks).sample(frac=1, random_state=seed)

def run_finalise(args):
    parents_path = args.parents or latest(f"{OUT_DIR}/parents_*.csv")
    raw_path = args.raw or latest(f"{TRANSLATED_DIR}/translated_raw_*.csv")
    parents, raw = pd.read_csv(parents_path), pd.read_csv(raw_path)
    assert not raw.duplicated(["parent_id", "lang"]).any() and len(raw) == len(LANG_BLOCK) * len(parents), \
        f"the raw CSV has {len(raw)} rows, expected {len(LANG_BLOCK) * len(parents)}: the run is not finished"
    stem = re.search(r"\d{4}-\d{2}-\d{2}", os.path.basename(raw_path)).group(0)
    print(f"parents: {parents_path}\nraw:     {raw_path}")
    m = pd.read_csv("data/final/messages.csv", low_memory=False, usecols=["text", "label", "source", "language", "template_id", "cluster_id", "text_hash", "is_synthetic", "split"])
    synth = m[(m["source"] == "synth_india") & m["language"].isin(LANG_BLOCK)]
    d = evaluate_translations(raw, parents)
    boot = args.boot
    # --- pass A: no length sampling (the output). Pass B: length-bin sampling against the pool's scam rows (synth_india + translated), run for the report
    # so the cost of matching is measured; its rows are written out only with --length-match.
    dA, ledA, _ = run_pipeline(d, args, set(m["text_hash"]), synth, ())
    dB, ledB, binsB = run_pipeline(d, args, set(m["text_hash"]), synth, tuple(LANG_BLOCK))
    kept = lambda x, lang: x[(x["lang"] == lang) & (x["drop_step"] == "")]
    ref, ref_df = english_reference(m, boot, args.seed)
    ref_i = ref.set_index("model")
    sets, cmp_rows, over = {}, [], {}
    for lang in LANG_BLOCK:
        sl = synth[synth.language == lang]
        raw_ok = d[(d["lang"] == lang) & d["marker_ok"]]
        sets[(lang, "synth_india only (existing rows)")] = pd.DataFrame({"text": sl["text"].to_numpy(), "label": sl["label"].to_numpy(), "template_id": "s" + sl["template_id"].astype(str).to_numpy()})
        sets[(lang, "translations, marker-ok, before content filters")] = pd.DataFrame({"text": raw_ok["translation"].to_numpy(), "label": raw_ok["label"].to_numpy(), "template_id": "t" + raw_ok["template_id"].astype(str).to_numpy()})
        fa, fb = kept(dA, lang), kept(dB, lang)
        sets[(lang, "translations, final (no length sampling)")] = pd.DataFrame({"text": fa["translation"].to_numpy(), "label": fa["label"].to_numpy(), "template_id": "t" + fa["template_id"].astype(str).to_numpy()})
        sets[(lang, SET_A)] = pool_frame(sl, fa)
        sets[(lang, SET_B)] = pool_frame(sl, fb)
    res = {k: confound_report(v.reset_index(drop=True), boot=boot, seed=args.seed).set_index("model") for k, v in sets.items()}
    counts = {k: (len(v), int(v["label"].sum())) for k, v in sets.items()}
    for lang in LANG_BLOCK:
        c = res[(lang, SET_A)]
        over[lang] = [mdl for mdl in c.index if c.loc[mdl, "AUROC_lo"] > ref_i.loc[mdl, "AUROC_hi"]]
    match_langs = set(LANG_BLOCK) if args.length_match else set()
    fin = {lang: (dB if lang in match_langs else dA) for lang in LANG_BLOCK}
    final_all = pd.concat([kept(fin[l], l) for l in LANG_BLOCK])
    dropped_all = pd.concat([fin[l][(fin[l]["lang"] == l) & (fin[l]["drop_step"] != "")] for l in LANG_BLOCK])
    led = pd.concat([(ledB if l in match_langs else ledA).frame().query("language == @l") for l in LANG_BLOCK], ignore_index=True)
    # accounting: every requested translation is kept or dropped for exactly one reason
    for lang in LANG_BLOCK:
        assert len(kept(fin[lang], lang)) + int(((fin[lang]["lang"] == lang) & (fin[lang]["drop_step"] != "")).sum()) == len(parents)
    # --- write the data files
    fcols = ["parent_id", "lang", "label", "parent_source", "parent_hash", "anchor_hash", "anchor_kind", "anchor_split", "template_id", "category", "channel", "rule",
             "parent_is_synthetic", "parent_provenance", "recovery", "text_hash", "parent_text", "translation"]
    out_final = f"{TRANSLATED_DIR}/translated_final_{stem}.csv"
    out_drop = f"{TRANSLATED_DIR}/translated_dropped_{stem}.csv"
    final_all[fcols].rename(columns={"lang": "language", "translation": "text"}).to_csv(out_final, index=False)
    dropped_all[["parent_id", "lang", "label", "parent_source", "drop_step", "parent_text", "translation"]].to_csv(out_drop, index=False)
    for lang, code in LANG_CODE.items():
        s = spot_sample(final_all[final_all["lang"] == lang], SPOT_N, args.seed)
        sheet = pd.DataFrame({"row_id": [f"{code}{i + 1:02d}" for i in range(len(s))], "parent_id": s["parent_id"].to_numpy(), "label": np.where(s["label"] == 1, "scam", "benign"),
                              "parent_source": s["parent_source"].to_numpy(), "english_parent": s["parent_text"].to_numpy(), "translation": s["translation"].to_numpy(),
                              "meaning_ok": "", "label_still_correct": "", "notes": ""})
        sheet.to_csv(f"reports/spotcheck_{code}.csv", index=False, encoding="utf-8-sig")
    write_final_report(args, parents_path, raw_path, out_final, out_drop, led, ref, ref_df, res, counts, over, match_langs, binsB, final_all, synth, d, dA, dB)
    for lang in LANG_BLOCK:
        f = kept(fin[lang], lang)
        nb, ns = int((f.label == 0).sum()), int((f.label == 1).sum())
        c = res[(lang, SET_A)]["AUROC"].round(2).to_dict()
        print(f"{lang}: kept {nb} benign + {ns} scam of {len(parents)}; overall scam share {(231 + ns) / (394 + nb + ns):.1%}; length matching {'APPLIED' if lang in match_langs else 'not applied'}; combined AUROC {c}")
    print(f"English reference ({len(ref_df)} rows, {int(ref_df['label'].sum())} scam): {ref['AUROC'].round(2).tolist()}")
    print(f"wrote {out_final}, {out_drop}, {FINAL_REPORT}, reports/spotcheck_hi.csv, reports/spotcheck_kn.csv")

def cue_means(df):
    cf = cue_frame(df["text"])
    cf["label"] = df["label"].to_numpy()
    g = cf.groupby("label")
    out = pd.DataFrame({"rows": g.size(), "median_len": g["len"].median(), "digit_share": g["digit_share"].mean(), "has_mask_token": g["has_mask"].mean(),
                        "latin_share": g["latin_share"].mean(), "has_url": g["has_url"].mean()}).reset_index()
    out["label"] = out["label"].map({0: "benign", 1: "scam"})
    return out

def write_final_report(args, parents_path, raw_path, out_final, out_drop, led, ref, ref_df, res, counts, over, match_langs, binsB, final_all, synth, d, dA, dB):
    from collections import Counter
    kept = lambda x, lang: x[(x["lang"] == lang) & (x["drop_step"] == "")]
    models = list(CONFOUND_MODELS)
    short = {"length only": "length only", "digit/mask share only": "digit/mask share only", "latin share + length": "latin share + length",
             "all cues (length, digit/mask, latin, url)": "all cues"}
    L = [f"# Translation finalise\n\nGenerated by `src/translate_parents.py finalise` on {dt.date.today().isoformat()}. Inputs: `{parents_path}`, `{raw_path}`. Outputs: `{out_final}` "
         f"(kept translations), `{out_drop}` (every dropped translation and why), `reports/spotcheck_hi.csv`, `reports/spotcheck_kn.csv`. "
         "Nothing here changes messages.csv or split_map.csv, and `build_text.py` has not been run. Every translation is `is_synthetic=True` whatever its parent was.\n"]
    # ---- ledger
    L.append("## Row ledger\n\nOne row per step and language; every one of the 735 requested translations per language ends up kept or dropped by exactly one step.\n\n" + md(led.drop(columns="note")))
    notes = led.drop_duplicates("step")[["step", "note"]]
    L.append("\nWhat each step does:\n\n" + "\n".join(f"- **{r.step}**: {r.note}" for r in notes.itertuples() if r.note))
    nm = d[(d["lang"] == "hindi") & d["name_hit"]]
    tok = Counter(t.upper() for x in nm["parent_text"] for t in NAME_RX.findall(x))
    L.append(f"\n### The person-name step (not in the original plan)\n\nCLAUDE.md rule 5 says victim names are masked before text reaches `data/final/`, but `pii.MASKS` has no name pattern, and the benign parents (bank alerts, "
             f"train tickets, delivery updates) carry real-looking names: UPI payers, a ticket passenger, a delivery rider, a doctor. {len(nm)} parents ({int((nm.label == 0).sum())} benign, "
             f"{int((nm.label == 1).sum())} scam) matched a short list of names found by reading the rare capitalised tokens of the parents file in context; their translations are dropped (the ledger shows how many were still alive at this step in each language; "
             "the rest had already failed the marker check). "
             f"Matched tokens: {', '.join(f'{k} x{v}' for k, v in sorted(tok.items()))}. **The list is curated, not exhaustive**: names the reading missed are still in the kept rows. The real fix is name masking in `pii.py` "
             "(BUGS.md). To undo this step, empty `NAME_RX`.\n")
    # ---- decision
    r_ref = ref.set_index("model")
    L.append(f"## Cue-only models: how much do surface cues separate the labels?\n\nEach model sees only surface cues (length, digit/mask share, latin share, URL), never the words; depth-3 tree, "
             f"out-of-fold, 5-fold GroupKFold by template group; AUROC 0.5 means no label signal. Intervals are 95% group-bootstrap ({args.boot} resamples). **Reference 1** is the "
             f"Hindi/Kannada training pool (existing `synth_india` rows + kept translations). **Reference 2** is real short English SMS: `uci_sms_spam` + `scam_ham_india` rows of at most {REF_MAX_LEN} characters "
             f"({len(ref_df)} rows, {int(ref_df['label'].sum())} scam, none synthetic; all splits, cues only, no text model trained).\n")
    rows = [{"language": "English", "set": f"REFERENCE: uci_sms_spam + scam_ham_india <= {REF_MAX_LEN} chars", "rows": len(ref_df), "scam": int(ref_df["label"].sum()),
             **{short[k]: ci_str(r_ref.loc[k]) for k in models}}]
    for (lang, name), r in res.items():
        rows.append({"language": lang, "set": name, "rows": counts[(lang, name)][0], "scam": counts[(lang, name)][1], **{short[k]: ci_str(r.loc[k]) for k in models}})
    L.append(md(pd.DataFrame(rows)))
    base = res[("hindi", "synth_india only (existing rows)")].loc["digit/mask share only", "AUROC"]
    L.append(f"\nCheck: the digit/mask-only AUROC on the existing Hindi `synth_india` rows is {base:.2f} here; CLAUDE.md quotes 0.58 ({'reproduced' if abs(base - 0.58) < 0.006 else 'NOT reproduced, investigate'}).\n")
    dec = []
    for lang in LANG_BLOCK:
        c = res[(lang, SET_A)]
        syn_len = res[(lang, 'synth_india only (existing rows)')].loc['length only', 'AUROC']
        dec.append(f"- **{lang}**: combined-pool length-only AUROC {ci_str(c.loc['length only'])} (synth_india alone: {syn_len:.2f}; the English reference: {ci_str(r_ref.loc['length only'])}). "
                   f"Models whose combined interval lies entirely above the English reference's interval: {', '.join(short[k] for k in over[lang]) if over[lang] else 'none'}. "
                   f"Gate verdict: **{'clearly above the reference' if over[lang] else 'accept'}**. Length-bin sampling: **{'APPLIED (--length-match)' if lang in match_langs else 'not applied'}**.")
    L.append("### Decision\n\nRule (instructions of 2026-10-07): decide against the English reference, not against 0.5. If the combined pool's cue AUROCs are at or below the English reference, accept and report "
             "them; if clearly above (interval entirely above), sample the translated rows by length bin and re-measure.\n\n" + "\n".join(dec) +
             "\n\nOne earlier instruction used a literal trigger instead (length-only AUROC clearly above the synth baseline, say > 0.65); that trigger " +
             ("fires" if any(res[(l, SET_A)].loc["length only", "AUROC"] > 0.65 for l in LANG_BLOCK) else "does not fire") +
             " here. The reference rule is the later and more specific instruction and is the one followed. The length-bin sampling is therefore **off** (it is a flag, `--length-match`, not a default). "
             "Pass B below is why it should stay off.\n")
    # ---- length-bin sampling cost
    vr = []
    for lang in LANG_BLOCK:
        for vname, dd, sname, used in (("A: no length sampling", dA, SET_A, lang not in match_langs), ("B: length-bin sampled", dB, SET_B, lang in match_langs)):
            f = kept(dd, lang)
            nb, ns = int((f.label == 0).sum()), int((f.label == 1).sum())
            c = res[(lang, sname)]
            vr.append({"language": lang, "variant": vname + (" (OUTPUT)" if used else " (report only)"), "translated_benign": nb, "translated_scam": ns,
                       "overall_scam_share_%": round(100 * (SYNTH_SCAM + ns) / (SYNTH_SCAM + SYNTH_BENIGN + nb + ns), 1), **{short[k]: ci_str(c.loc[k]) for k in models}})
    L.append("### Pass B: what length-bin sampling would cost\n\nBenign translations are longer than scam ones, while the existing synth rows go the other way. Pass B keeps, per length bin "
             f"({N_LEN_BINS} equal-mass bins of the pool's scam lengths, pool = existing `synth_india` rows + kept translations), as many translated benign rows as it takes for the pool's benign:scam ratio to be the same in "
             "every bin, drops translated benign rows outside the scam length range, and never touches the existing synth rows. The scam trim to 15% is skipped in pass B (it would cut scam to 15% of an already reduced benign set), "
             "so the overall scam share is shown against the <= 35% target.\n\n" + md(pd.DataFrame(vr)))
    for lang in LANG_BLOCK:
        L.append(f"\n{lang}, pass B bins (r = the largest benign:scam ratio every bin can reach):\n\n" + md(binsB[lang]))
    # ---- cue means
    cm = []
    for lang in LANG_BLOCK:
        sl = synth[synth.language == lang]
        f = kept(dA, lang)
        for name, df in (("synth_india only", sl[["text", "label"]]), ("translations, final", f.rename(columns={"translation": "text"})[["text", "label"]])):
            cm.append(cue_means(df).assign(language=lang, set=name))
    cm.append(cue_means(ref_df).assign(language="English", set="reference (short SMS)"))
    cmt = pd.concat(cm)[["language", "set", "label", "rows", "median_len", "digit_share", "has_mask_token", "latin_share", "has_url"]]
    L.append("\n## The cues behind those numbers\n\n" + md(cmt) + "\n\nThe translated benign rows are bank, OTP and delivery alerts (more digits, more mask tokens, more Latin abbreviations) and the scam rows are prose, so the cue gap comes "
             "from what the parents are, not from the translation. The English reference has the same kind of gap and much larger.\n")
    # ---- scam share and splits
    sh, sp = [], []
    for lang in LANG_BLOCK:
        sl = synth[synth.language == lang]
        f = kept(dA if lang not in match_langs else dB, lang)
        nb, ns = int((f.label == 0).sum()), int((f.label == 1).sum())
        sb, ss = int((sl.label == 0).sum()), int((sl.label == 1).sum())
        sh.append({"language": lang, "synth_benign": sb, "synth_scam": ss, "translated_benign": nb, "translated_scam": ns, "translated_scam_%": round(100 * ns / (nb + ns), 1),
                   "overall_scam_%": round(100 * (ss + ns) / (sb + ss + nb + ns), 1), "before_%": round(100 * ss / (sb + ss), 1), "target": "<= 35"})
        sim = split_sim(f)
        for split in ("train", "val", "test"):
            sp.append({"language": lang, "split": split, "synth_india (existing)": int((sl.split == split).sum()), "translated scam (exact)": int(((f.label == 1) & (f.anchor_split == split)).sum()),
                       "translated benign (expected, 5th pct)": f"{sim[split][0]:.0f} ({sim[split][1]:.0f})"})
        assert (f[f.label == 1]["anchor_split"] != "").all(), "a scam translation without an anchor split"
    L.append("## Scam share per language\n\n" + md(pd.DataFrame(sh)))
    L.append("\n## Where the rows will land\n\nTranslations inherit the split of their English parent's `messages.csv` row (`anchor_split`), so an English twin in train never has its translation in test. "
             "Benign parents without a twin (almost all) become fresh clusters at build time and take a hash bucket (80/10/10); the expected counts below simulate that.\n\n" + md(pd.DataFrame(sp)))
    # ---- spot-check
    sc_rows = []
    for lang, code in LANG_CODE.items():
        sheet = pd.read_csv(f"reports/spotcheck_{code}.csv", encoding="utf-8-sig")
        for (lab, src), n in sheet.groupby(["label", "parent_source"]).size().items():
            sc_rows.append({"sheet": f"spotcheck_{code}.csv", "label": lab, "parent_source": src, "rows": n})
    L.append("\n## Spot-check sheets\n\n`reports/spotcheck_hi.csv` and `reports/spotcheck_kn.csv`, 50 rows each, drawn from the kept rows: 25 benign, 25 scam split over the two scam sources in proportion to what is "
             "kept (at least 10 each), random within each stratum (seed 0), shuffled. Each row has the English parent, the translation, and three columns to fill in: `meaning_ok` (y/n: does the translation say what the "
             "English says), `label_still_correct` (y/n: is the benign/scam label still right for the translated text), `notes`. Accept a language at >= 90% y on both columns. The files are UTF-8 with a BOM so Excel "
             "shows the scripts correctly.\n\n" + md(pd.DataFrame(sc_rows)))
    # ---- caveats
    f_ben = final_all[final_all.label == 0]
    L.append(f"\n## Caveats\n\n- **Automatic filters do not check meaning.** Only the native-speaker spot-check does; build_text.py waits for it.\n"
             f"- **Benign diversity is low.** The kept benign translations (per language, about {int((final_all[(final_all.lang == 'hindi') & (final_all.label == 0)]).shape[0])}) come from {f_ben['template_id'].nunique()} template groups of one preview dataset "
             "(provenance unknown); card-spend alerts and OTP messages dominate. They teach 'transactional alert in Hindi/Kannada = benign', which is the point, but not much beyond it.\n"
             "- **Scam translations repeat English scam content already in `messages.csv`** (they are translations of those rows) and inherit their splits; val has 12 and test 5 scam parents in total, so val/test scam counts in Hindi/Kannada stay small.\n"
             "- **Names**: see the person-name step above; the list is curated, and the existing `messages.csv` rows were not checked for names.\n"
             "- **Leftover Latin is normal**: bank abbreviations (Txn, Avl Bal, A/c), brand and sender names stay Latin, as in the existing `synth_india` rows; only rows where most letters are Latin are dropped.\n")
    open(FINAL_REPORT, "w").write("\n".join(L) + "\n")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("parents")
    pp.add_argument("--cap-template", type=int, default=CAP_TEMPLATE)
    pp.add_argument("--cap-sender", type=int, default=CAP_SENDER)
    pp.add_argument("--seed", type=int, default=0)
    pp.add_argument("--scam-share", type=float, default=SCAM_SHARE, help="scam share of the translated rows (design choice)")
    pp.add_argument("--sweep", action="store_true", help="print parents / scam rate for a grid of cap values, write nothing")
    fp = sub.add_parser("finalise")
    fp.add_argument("--parents", help="default: the latest translate_in/parents_*.csv")
    fp.add_argument("--raw", help="default: the latest translated/translated_raw_*.csv")
    fp.add_argument("--scam-share", type=float, default=SCAM_SHARE, help="scam share of the translated rows")
    fp.add_argument("--min-target-share", type=float, default=MIN_TARGET_SHARE, help="leftover English: minimum target-script share of the letters outside the protected spans")
    fp.add_argument("--length-match", action="store_true",
                    help="write the pass-B rows (length-bin sampling of the translated benign rows against the pool's scam lengths); off by default, see the report for its cost")
    fp.add_argument("--boot", type=int, default=300, help="group-bootstrap resamples for the AUROC intervals")
    fp.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    {"parents": run_parents, "finalise": run_finalise}[args.cmd](args)
