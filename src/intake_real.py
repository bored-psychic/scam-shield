"""Real-message intake (Google Form "Scam Shield - real message collection") -> data/real/real_test_v1.csv, a masked TEST-ONLY set.
No network. Run on the Mac:

    .venv/bin/python src/intake_real.py                       # newest CSV in data/real/raw/
    .venv/bin/python src/intake_real.py --input data/real/raw/x.csv --freeze   # also writes the frozen hash into CLAUDE.md

Steps: (1) map columns by header text, stop on anything unexpected; drop timestamp and contributor columns before anything else;
(2) clean: NFC, whitespace, rows under 10 characters, unknown labels, exact duplicates; (3) near-duplicates by src/neardup.py (the splits'
method), one per cluster; (4) mask phone / UPI / email / account / card / OTP with src/pii.py and extra card, OTP patterns (URLs are kept:
the link checks need them); names are NOT masked: rows with likely names go to data/real/review_names.csv, your edits are applied on rerun
(replace_with "<NAME>" masks the token, "DROP" drops the row, blank keeps it); (5) overlap: each row against the TRAIN split of
data/final/messages.csv with the same near-duplicate rule (overlap True/False, rows are never dropped for it).
Tripwire: realguard.py. The output's source_row_hash is the key training scripts refuse on.
"""
import argparse, csv, datetime as dt, hashlib, re, subprocess, sys, unicodedata
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]
import pandas as pd
import pii
import realguard
from neardup import CLUSTER_SEED, near_dup_pairs_any
from textprep import model_text

RAW_DIR = ROOT / "data" / "real" / "raw"
OUT = ROOT / "data" / "real" / "real_test_v1.csv"
REVIEW = ROOT / "data" / "real" / "review_names.csv"
REPORT = ROOT / "reports" / "real_intake_v1.md"
MESSAGES = ROOT / "data" / "final" / "messages.csv"
CLAUDE = ROOT / "CLAUDE.md"
MIN_CHARS = 10
CSV_ROW = re.compile(r"^R\d{4}$")

# header rules: (role, regex on the lower-cased header). Checked in this order; a header that matches two roles stops the run.
DROP_RX = re.compile(r"timestamp|time stamp|^time$|e-?mail|name|contact|phone|mobile|whatsapp|username|user id|consent|address")
ROLE_RX = [
    ("category", re.compile(r"categor|type of scam|scam type|kind of scam")),
    ("language", re.compile(r"language")),
    ("label", re.compile(r"scam or genuine|genuine or scam|is (this|it) a scam|label|genuine|legit|scam\?")),
    ("text", re.compile(r"message|sms|text|paste|content")),
]
REQUIRED = ("text", "label", "language")
LANG = {"english": "en", "en": "en", "hindi": "hi", "hi": "hi", "kannada": "kn", "kn": "kn", "hinglish": "hinglish", "mixed": "mixed"}
SCAM_WORDS = ("scam", "spam", "fraud", "phish", "yes", "1")
GENUINE_WORDS = ("genuine", "legit", "real", "ham", "not scam", "no", "0", "not a scam")

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
LONG_RX = re.compile(r"\b\d{13,19}\b")


class Stop(SystemExit):
    pass


def stop(msg):
    raise Stop(f"STOP: {msg}")


def newest_csv(folder=RAW_DIR):
    files = sorted(folder.glob("*.csv"), key=lambda p: p.stat().st_mtime) if folder.exists() else []
    if not files:
        stop(f"no CSV in {folder.relative_to(ROOT)} (the Form's export goes there; the folder is git-ignored)")
    return files[-1]


def map_headers(headers):
    """{role: header} for text, label, language, category (optional) and the list of dropped headers. Stops on anything unexpected."""
    roles, dropped, unexpected = {}, [], []
    for h in headers:
        low = h.strip().lower()
        if DROP_RX.search(low):
            dropped.append(h)
            continue
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
    s = str(v).strip().lower()
    if not s:
        return None
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
    t = unicodedata.normalize("NFC", str(text or "")).strip()
    return re.sub(r"\s+", " ", t)


def protect_urls(text):
    urls = []
    def keep(m):
        urls.append(m.group(0))
        return f"\x00{len(urls) - 1}\x00"
    return URL_RX.sub(keep, text), urls

def restore_urls(text, urls):
    return re.sub(r"\x00(\d+)\x00", lambda m: urls[int(m.group(1))], text)

def mask(text):
    """src/pii.py masks (emails and UPI ids first, then phones and accounts) with URLs kept, plus card, OTP and long digit runs."""
    t = text
    for pat, tok in pii.MASKS[:3]:
        t = re.sub(pat, tok, t)
    t, urls = protect_urls(t)
    t = CARD_RX.sub("<ACCOUNT>", t)
    t = OTP_RX.sub(lambda m: m.group(0)[: m.start(2) - m.start(0)] + "<OTP>", t)
    for pat, tok in pii.MASKS[3:]:
        t = re.sub(pat, tok, t)
    t = LONG_RX.sub("<ACCOUNT>", t)
    return restore_urls(t, urls)

def defang_span(s):
    return re.sub(r"https?://\S+|www\.\S+", lambda m: m.group(0).replace("http", "hxxp").replace(".", "[.]"), s)

def name_tokens(masked):
    """Capitalised words that may be a person's name. A word at the start of a sentence is only a candidate when another capitalised word follows
    it ("Ramesh Kumar") or a greeting precedes it; otherwise it is the sentence's first word (Reply, Track, Dinner)."""
    out = set()
    for m in TOKEN_RX.finditer(masked):
        tok = m.group(0)
        if tok in COMMON:
            continue
        before = masked[:m.start()]
        starts = not before.strip() or before.rstrip()[-1] in ".!?:;\n\"'("
        followed = re.match(r"\s+[A-Z][a-z]{2,}\b", masked[m.end():]) is not None
        if starts and not followed and not GREETING_RX.search(before):
            continue
        out.add(tok)
    return sorted(out)

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

def write_review(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "token", "context", "replace_with"])
        w.writeheader()
        for r in sorted(rows, key=lambda r: (r["id"], r["token"])):
            w.writerow({k: r.get(k, "") for k in w.fieldnames})


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


def run(input_path, out=OUT, review=REVIEW, report=REPORT, freeze=False, messages=MESSAGES):
    realguard.refuse_real_paths([input_path])
    with open(input_path, encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        headers = next(reader)
        raw_rows = list(reader)
    roles, dropped_cols = map_headers(headers)
    idx = {r: headers.index(h) for r, h in roles.items()}
    print("headers:", headers)
    print("mapped:", {r: headers[i] for r, i in idx.items()}, "| dropped before anything else:", dropped_cols)

    drops = Counter()
    rows = []
    for k, rr in enumerate(raw_rows, start=1):
        rid = f"R{k:04d}"
        text = clean(rr[idx["text"]]) if len(rr) > idx["text"] else ""
        if len(text) < MIN_CHARS:
            drops["shorter than 10 characters"] += 1
            continue
        label = label_of(rr[idx["label"]]) if len(rr) > idx["label"] else None
        if label is None:
            drops["label not recognised"] += 1
            continue
        rows.append({"id": rid, "text": text, "label": label, "language": language_of(rr[idx["language"]]) if len(rr) > idx["language"] else "unknown",
                     "category": (clean(rr[idx["category"]]) if "category" in idx and len(rr) > idx["category"] else "") or "unspecified"})
    seen = {}
    kept = []
    for r in rows:
        if r["text"] in seen:
            drops["exact duplicate"] += 1
            continue
        seen[r["text"]] = r["id"]
        kept.append(r)

    for r in kept:
        r["masked"] = mask(r["text"])
    # near-duplicates on the masked text: the splits' rule, keep the first of each cluster
    keyed = [r["masked"].lower() for r in kept]
    parent = list(range(len(kept)))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for i, j, _, _ in near_dup_pairs_any(keyed, ["real"] * len(kept), CLUSTER_SEED):
        a, b = find(min(i, j)), find(max(i, j))
        parent[max(a, b)] = min(a, b)
    first_of = {}
    unique = []
    for k, r in enumerate(kept):
        root = find(k)
        if root in first_of:
            drops["near-duplicate of an earlier row (same cluster)"] += 1
            continue
        first_of[root] = r["id"]
        unique.append(r)

    # names: candidates to review; edits from the review file are applied
    review_rows = read_review(review)
    current = {}
    for r in unique:
        for tok in name_tokens(r["masked"]):
            ctx = contexts(r["masked"], tok)
            if ctx:
                current[(r["id"], tok)] = {"id": r["id"], "token": tok, "context": ctx[0], "replace_with": ""}
    new_rows = [v for k, v in current.items() if k not in review_rows]
    merged = {**review_rows, **{k: v for k, v in current.items() if k not in review_rows}}
    write_review(review, list(merged.values()))
    applied = Counter()
    final = []
    for r in unique:
        edits = [v for (rid, tok), v in review_rows.items() if rid == r["id"]]
        if any(e["replace_with"].strip().upper() == "DROP" for e in edits):
            drops["review: marked DROP"] += 1
            continue
        t = r["masked"]
        for e in edits:
            rep = e["replace_with"].strip()
            if rep and rep.upper() != "DROP" and e["token"]:
                t, n = re.subn(rf"(?<!\w){re.escape(e['token'])}(?!\w)", rep, t)
                applied[rep] += n
        r["final"] = t
        final.append(r)

    flags = overlap_flags([r["final"] for r in final], messages) if final else []
    for r, o in zip(final, flags):
        r["overlap"] = bool(o)
        r["hash"] = realguard.norm_key(r["final"])

    out.parent.mkdir(parents=True, exist_ok=True)
    cols = ["id", "text", "label", "language", "category", "overlap", "source_row_hash"]
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in final:
            w.writerow({"id": r["id"], "text": r["final"], "label": r["label"], "language": r["language"], "category": r["category"],
                        "overlap": r["overlap"], "source_row_hash": r["hash"]})
    sha = hashlib.sha256(out.read_bytes()).hexdigest()
    write_summary(report, input_path, len(raw_rows), drops, final, sha, current, review_rows, new_rows, applied, roles, dropped_cols, out)
    if freeze:
        freeze_hash(sha, len(final))
    print(f"kept {len(final)} of {len(raw_rows)} rows -> {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}")
    print(f"sha256 {sha}")
    return sha, final


def write_summary(path, input_path, n_read, drops, final, sha, current, review_rows, new_rows, applied, roles, dropped_cols, out):
    L = ["# Real-message intake v1\n",
         f"*Generated by `src/intake_real.py` on {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC. No message text in this report: "
         "text is in `data/real/real_test_v1.csv` (git-ignored) and names in `data/real/review_names.csv`.*\n",
         f"Input: `{Path(input_path).name}` ({n_read} data rows). Columns mapped: {', '.join(f'{r} <- {c!r}' for r, c in roles.items())}. "
         f"Dropped before anything else: {', '.join(repr(c) for c in dropped_cols) or 'none'} (timestamp / contributor columns).\n",
         "## Rows\n"]
    L.append(f"- Read: {n_read}. Kept: **{len(final)}**. Dropped: {sum(drops.values())}.")
    for k, v in sorted(drops.items(), key=lambda kv: -kv[1]):
        L.append(f"  - {k}: {v}")
    L.append("")
    L.append("## Counts: label x language x category\n")
    L.append("| label | language | category | rows | overlap True |")
    L.append("|---|---|---|---:|---:|")
    c = Counter((r["label"], r["language"], r["category"]) for r in final)
    ov = Counter((r["label"], r["language"], r["category"]) for r in final if r["overlap"])
    for key in sorted(c):
        L.append(f"| {'scam' if key[0] else 'genuine'} | {key[1]} | {key[2]} | {c[key]} | {ov[key]} |")
    L.append("")
    L.append(f"**Overlap with the TRAIN split** (near-duplicate, the splits' rule): {sum(r['overlap'] for r in final)} of {len(final)} rows are flagged overlap=True. "
             "They are kept; `eval_real.py` reports them with and without.\n")
    L.append("## Names\n")
    L.append(f"- Rows with a likely name (capitalised word not in the common-word list): {len({k[0] for k in current})}. Candidate tokens: {len(current)}.")
    L.append(f"- Edits applied from `review_names.csv`: masks {sum(v for k, v in applied.items())} (replacement values are not written here).")
    L.append(f"- Tokens still open (blank review = kept as written): {sum(1 for v in review_rows.values() if not v['replace_with'].strip())} from the review file; new since last run: {len(new_rows)}.\n")
    L.append("## Output\n")
    L.append(f"- `{out.name}`: {len(final)} rows, SHA-256 `{sha}`.\n")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


FREEZE_HEAD = "## Frozen hashes (real-message test set)"

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
        text = text.replace(FREEZE_HEAD, FREEZE_HEAD + "\n\n" + line, 1)
    else:
        text = text.rstrip("\n") + f"\n\n{FREEZE_HEAD}\n\n{line}\n"
    CLAUDE.write_text(text, encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, help="the Form's CSV (default: newest in data/real/raw/)")
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--review", type=Path, default=REVIEW)
    ap.add_argument("--report", type=Path, default=REPORT)
    ap.add_argument("--messages", type=Path, default=MESSAGES, help="the training corpus for the overlap check (tests pass a tiny file)")
    ap.add_argument("--freeze", action="store_true", help="write the SHA-256 into CLAUDE.md's frozen-hashes section")
    a = ap.parse_args()
    src = a.input or newest_csv()
    run(src, a.out, a.review, a.report, a.freeze, a.messages)


if __name__ == "__main__":
    try:
        main()
    except Stop as e:
        print(e, file=sys.stderr)
        sys.exit(2)
