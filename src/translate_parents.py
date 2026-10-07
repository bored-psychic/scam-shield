import argparse, datetime as dt, glob, hashlib, os, re, sys
import numpy as np, pandas as pd
import neardup
from pii import mask_text

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

def apply_caps(p, cap_template, cap_sender, led=None):
    """At most cap_template parents per template group, then at most cap_sender benign parents per named sender (rows without a
    sender id are exempt: they are not one sender). Deterministic (parents are already in hash order)."""
    sizes = p["template_id"].value_counts()
    rank = p.groupby("template_id").cumcount()
    q = p[rank < cap_template]
    if led is not None:
        led.add("all", f"cap {cap_template} parents per template group", len(p), len(q),
                f"largest group before the cap: {int(sizes.max())} parents; groups > cap: {int((sizes > cap_template).sum())} of {len(sizes)}")
    # rows with no sender id are not one sender: most of the preview (the ICICI card alerts) has none, so only the template cap bounds them
    ok = (q["label"] == 1) | (q["sender"] == "unknown") | (q.groupby(["label", "sender"]).cumcount() < cap_sender)
    if led is not None:
        led.add("all", f"cap {cap_sender} benign parents per named sender", len(q), int(ok.sum()), "rows without a sender id are exempt")
    return q[ok].reset_index(drop=True)

# synth_india Hindi / Kannada rows already in messages.csv (per language): 231 scam + 163 benign. They are never touched.
SYNTH_SCAM, SYNTH_BENIGN = 231, 163
SCAM_SHARE = 0.15        # scam share of the TRANSLATED rows: a design choice, not whatever the caps leave
TARGET_OVERALL = 0.35    # overall Hindi / Kannada scam share we want to be at or below (synth_india rows included)

def pick_scam(q, share, seed):
    """Size the scam parents from the benign count so scam is `share` of the translated rows: n = share / (1 - share) * benign.
    Picks one parent per template group first (round-robin over groups), then in hash order, so the scam parents are as
    varied as the pool allows; split mix follows what is available (anchor splits are frozen, so nothing here moves a row)."""
    ben, sc = q[q.label == 0], q[q.label == 1]
    n = min(len(sc), int(round(share / (1 - share) * len(ben))))
    sc = sc.assign(_rank=sc.groupby("template_id").cumcount()).sort_values(["_rank", "order"]).head(n).drop(columns="_rank")
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
    shortcut = p.groupby("label").agg(n=("text", "size"), median_len=("text", lambda s: s.str.len().median()),
                                      has_url=("text", lambda s: s.str.contains(r"https?://|www\.|\b[\w-]+\.(?:com|in|co|ly|me|it|im|cc|net|org)\b", case=False).mean()),
                                      has_mask_token=("text", lambda s: s.str.contains(r"<(?:PHONE|ACCOUNT|UPI_ID|EMAIL)>").mean()),
                                      has_digits=("text", lambda s: s.str.contains(r"\d").mean()),
                                      digit_share=("text", lambda s: np.mean([sum(c.isdigit() for c in t) / len(t) for t in s])),
                                      has_otp=("text", lambda s: s.str.contains(r"\botp", case=False).mean())).reset_index()
    shortcut["label"] = shortcut["label"].map({0: "benign", 1: "scam"})
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
         "\n## Label cues in the English parents (CLAUDE.md rule 3)\n\nThese cues carry into the translations, because protected tokens are restored verbatim. "
         "A gap here is not an error (real transaction alerts do carry more digits and real scams more links) but a model can use it instead of the message.\n\n" + md(shortcut)]
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

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("parents")
    pp.add_argument("--cap-template", type=int, default=CAP_TEMPLATE)
    pp.add_argument("--cap-sender", type=int, default=CAP_SENDER)
    pp.add_argument("--seed", type=int, default=0)
    pp.add_argument("--scam-share", type=float, default=SCAM_SHARE, help="scam share of the translated rows (design choice)")
    pp.add_argument("--sweep", action="store_true", help="print parents / scam rate for a grid of cap values, write nothing")
    args = ap.parse_args()
    {"parents": run_parents}[args.cmd](args)
