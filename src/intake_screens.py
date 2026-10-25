"""Public screenshots (or messages quoted on public pages) -> masked rows in data/collected/<source>/. No network.
Plan and sources: docs/plans/data_acquisition.md. Labels: docs/labelling_guide.md.

    .venv/bin/python src/intake_screens.py data/collected/inbox/2026-10-27/          # images + sources.csv in that folder
    .venv/bin/python src/intake_screens.py data/collected/inbox/pilot_quotes.csv     # quoted text only, no images
    .venv/bin/python src/intake_screens.py <input> --dry-run                         # every step and check, nothing written

Input: a sources.csv (inside the folder, or the CSV itself) with the columns filename, source_url, date_seen, channel. filename names an image
(PNG / JPEG / WEBP) next to sources.csv. A row with no filename and a `text` column is a message quoted as TEXT on the page (text-only mode).
An image row whose `text` is filled is a screenshot typed by hand: the typed text is stored (OCR on real public screenshots is not reliable
enough to store unread: reports/ocr_cer_public.md, CER 24% pooled on 5 images), OCR still runs, and ocr_cer is the OCR's character error rate
against the typed text (every typed screenshot is one more A2 measurement). Type what a reader would paste: the message body and any
attachment file name on its own line; leave out the sender header, times and file sizes.
Optional columns: label (scam / genuine / skip / blank), category, language, verified or a1_match (exact / near / none / syndicated_only: A1,
a second independent page with the same wording), a1_second_url, outlet, quote_type, notes (or a1_note), provenance (real_circulating, the default / illustrative / generic_script / unknown: rule 4; only
real_circulating ever counts as real, docs/labelling_guide.md says when a page's example is an illustration); source_group is kept as `arm`.
source_url is the page that SHOWS the message (an article, an advisory, a post), never a link from inside a message (rule 8).

Per row:
  1. text: the hand-typed text if there is one, else the app's own OCR path (shield.ocr.reader: same preparation, one Tesseract call over a pipe,
     same line joining; the image is read, never copied or stored); ocr_conf is the mean Tesseract word confidence (0-1). A row stored from OCR
     alone with ocr_conf < REVIEW_CONF gets needs_review = True: check it against the image and type it before use. Text-only rows skip OCR.
  2. mask: links re-fanged in memory (hxxp, [.]) so a defanged link is masked like a live one; then intake_real.mask (the src/pii.py masks plus
     card, OTP, account-tail and long digit-run masks, links kept); then the word after a greeting ("Dear Ravi") and social handles (u/name,
     @name) -> <NAME>. Over-masking is preferred to a leak (rule 5).
  3. defang: every link in the text, the source URL and a1_second_url -> hxxp / [.] (stored as strings, never clickable).
  4. checks before anything is written: no phone / UPI / e-mail / account / card pattern in the text (pii_leaks) and no live link in any column
     (live_links). Either one stops the run with the column and kind, never the value.
  5. near-duplicates (src/neardup.py's rule, both views, on textprep.model_text) against
       data/real/   the real-message TEST set: real_test_v1.csv, label_me.csv and the raw exports under raw/, read and masked in memory only;
       data/probe/  the PROBE-ONLY sets;
       data/final/messages.csv, every split (a twin of a test row would leak once collected rows are trained on; a twin of a train row adds
                    nothing new).
     Any collision drops the row; drops are counted by where they collided. No text of data/real/ or of a test row is printed or written.
  6. write data/collected/<group>/collected.csv, one folder per registered domain of the source URL (group "thequint_com"), so a later split
     can keep a whole source on one side. A rerun adds new rows (id = hash of the masked text + the source URL) and keeps the old ones;
     template groups (intake_real.make_groups) and group_sources (how many source groups carry the template: cross-source evidence for A1) are
     recomputed over all collected rows.
Report: reports/collected_intake.md (counts only, never message text). data/collected/ is git-ignored (data/). Rows are is_synthetic False and
provenance real_circulating unless the sheet says otherwise: public, circulating messages, NOT messages received by us, so they never go into
data/real/ (rule 12).
Tripwire: an input or output path under data/real/ or data/probe/ is refused (realguard.refuse_real_paths).
"""
import argparse, contextlib, csv, datetime as dt, hashlib, io, re, sys, unicodedata
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]
import pandas as pd
import intake_real, pii, realguard
from neardup import CLUSTER_SEED, near_dup_pairs_any
from textprep import _urls, model_text
from url_features import tld_ext
from shield.ocr import reader

COLLECTED = ROOT / "data" / "collected"
REPORT = ROOT / "reports" / "collected_intake.md"
MESSAGES = ROOT / "data" / "final" / "messages.csv"
INTAKE_VERSION = "screens-v1"
REQUIRED = ("source_url", "date_seen", "channel")
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp"}
MIN_CHARS = 10
REVIEW_CONF = 0.80     # provisional, n = 5 real screenshots (reports/ocr_cer_public.md): conf >= 0.82 had CER <= 5%, conf <= 0.79 had CER >= 18%
CUTOFF = dt.date(2024, 1, 1)          # A4: anything first seen before this is flagged pre_2024
LABELS = {"scam": "scam", "genuine": "genuine", "skip": "skip", "": "unlabelled"}
VERIFIED = {"exact", "near", "none", "syndicated_only"}
PROVENANCE = {"real_circulating", "illustrative", "generic_script", "unknown"}
OUT_COLS = ["id", "text", "label", "category", "channel", "language", "source_url", "source_group", "outlet", "arm", "date_seen", "date_flag",
            "collector", "verified", "a1_second_url", "ocr_conf", "ocr_cer", "needs_review", "input_kind", "quote_type", "filename", "image_sha256", "template_group",
            "group_size", "group_sources", "is_synthetic", "provenance", "batch", "ingested_utc", "intake_version", "notes"]
TEXT_COLS = ("text", "notes", "outlet")   # free text: masked and scanned for PII

HANDLE_RX = re.compile(r"(?<![\w/])u/[A-Za-z0-9_-]{3,20}\b|(?<![\w@<])@[A-Za-z_][A-Za-z0-9_.]{2,30}")
LIVE_RX = re.compile(r"(?i)\b(?:https?|ftp)://|\bwww\.[a-z0-9]")
LEAK_RX = [("an e-mail address", re.compile(pii.MASKS[0][0])), ("a UPI id", re.compile(pii.MASKS[1][0])), ("a UPI id", re.compile(pii.MASKS[2][0])),
           ("an e-mail address", re.compile(pii.MASKS[3][0])), ("a phone number", re.compile(pii.MASKS[4][0])),
           ("an account number", re.compile(pii.MASKS[5][0])), ("a card number", intake_real.CARD_RX), ("a long digit run", intake_real.LONG_RX),
           ("a phone number", intake_real.URL_MOBILE_RX), ("a user@host form", pii.MISS_RX)]
assert [t for _, t in pii.MASKS] == ["<EMAIL>", "<UPI_ID>", "<UPI_ID>", "<EMAIL>", "<PHONE>", "<ACCOUNT>"], "pii.MASKS changed: update LEAK_RX"


class Stop(SystemExit):
    pass


def stop(msg):
    raise Stop(f"STOP: {msg}")


# ---------------------------------------------------------------------------------------------------------------- OCR, masking, defanging

def ocr(data):
    """Image bytes -> (text, ocr_conf). The text is exactly what the app's reader.read_image returns (same _prepare, the same single Tesseract TSV
    call, the same join_wrapped_lines; tests/test_intake_screens.py S2 checks the two agree); ocr_conf is the mean confidence of the words
    Tesseract read, 0-1, None when it read none."""
    if len(data) > reader.MAX_BYTES:
        raise reader.ImageTooLarge("too large")
    if reader._kind(data) is None:
        raise reader.UnsupportedImage("not a PNG, JPEG or WEBP")
    tsv = reader._tesseract(reader._prepare(data))
    lines, _ = reader.join_wrapped_lines(*reader.parse_tsv(tsv))
    confs = []
    for row in tsv.splitlines()[1:]:
        c = row.split("\t", 11)
        if len(c) == 12 and c[0] == "5" and c[11].strip():
            try:
                v = float(c[10])
            except ValueError:
                continue
            if v >= 0:
                confs.append(v)
    return "\n".join(lines), (round(sum(confs) / len(confs) / 100, 3) if confs else None)


def cer_norm(t):
    """White space collapsed, bubble-corner times ("09:56", not "9:30 pm") removed: layout, not content (src/ocr_cer.py's normalised CER)."""
    return re.sub(r"\s+", " ", re.sub(r"(?i)\b\d{1,2}:\d{2}\b(?!\s*[ap]\.?\s?m\b)", " ", t)).strip()


def refang(text):
    return re.sub(r"(?i)\bhxxp", "http", text).replace("[.]", ".").replace("[dot]", ".")


# The person a greeting addresses: one or two words right after it, then punctuation or the line end ("Dear Ravindra,", "Hi Rahul Kumar!").
# Not intake_real.GREETING_NAME_RX alone: that takes ANY word after the greeting, which turned "Dear Punjab National bank customer" and
# "Dear Vehicle Owner/Driver," into "Dear <NAME> ..." on the pilot rows (2026-10-25). Words on intake_real.NOT_NAMES (customer, user, valued,
# sir ...) are never names.
GREET_NAME_RX = re.compile(r"(?im)\b(?:hey|hi|hello|dear|namaste|namaskara|mr|mrs|ms|miss|shri|smt)\b\.?\s+([a-z]{3,15})(?:\s+([a-z]{3,15}))?(?=\s*(?:[,!.:]|$))")


def _not_name(m):
    spans = [(m.start(g), m.end(g)) for g in (1, 2) if m.group(g)]
    if any(m.string[a:b].lower() in intake_real.NOT_NAMES for a, b in spans):
        return m.group(0)
    out, pos = [], m.start(0)
    for a, b in spans:
        out += [m.string[pos:a], "<NAME>"]
        pos = b
    return "".join(out) + m.string[pos:m.end(0)]


def mask(text):
    t = unicodedata.normalize("NFC", intake_real.MARKS_RX.sub("", text))   # intake_real.clean without collapsing the line breaks
    t = intake_real.mask(refang(t))
    t = GREET_NAME_RX.sub(_not_name, t)
    return HANDLE_RX.sub("<NAME>", t)


def defang_url(url):
    return re.sub(r"(?i)^http", "hxxp", url.strip()).replace(".", "[.]") if url.strip() else ""


def pii_leaks(value):
    """The kinds of PII pattern left in one string (counts only, never the string)."""
    return [kind for kind, rx in LEAK_RX if rx.search(value)]


def live_links(value):
    """True when a string still holds a clickable link: a scheme, a www., or a link textprep finds whose dots are not defanged."""
    if LIVE_RX.search(value):
        return True
    return any("[.]" not in core and not core.lower().startswith("hxxp") for _, _, core in _urls(value))


def source_group(url):
    """'https://www.thequint.com/news/x' -> 'thequint_com' (the registered domain, bundled suffix list: no network)."""
    host = re.sub(r"(?i)^[a-z]+://", "", refang(url)).split("/")[0].split("@")[-1].split(":")[0].lower()
    reg = tld_ext(host).top_domain_under_public_suffix or ".".join(re.sub(r"^www\.", "", host).split(".")[-2:])   # build_urls.py's rule; no public suffix: the last two labels
    return re.sub(r"[^a-z0-9]+", "_", reg).strip("_") or "unknown"


def date_flag(value):
    try:
        d = dt.date.fromisoformat(value.strip())
    except ValueError:
        return "unknown"
    return "pre_2024" if d < CUTOFF else ""


# ---------------------------------------------------------------------------------------------------------------- what collected rows are checked against

def real_texts(real_dir):
    """Every message text of the real-message TEST set, masked, in memory only: real_test_v1.csv, label_me.csv (both examples) and the raw
    exports under raw/ read with intake_real's own readers. Nothing is printed or kept."""
    real_dir = Path(real_dir)
    out = []
    for name, cols in (("real_test_v1.csv", ("text",)), ("label_me.csv", ("example_1", "example_2"))):
        p = real_dir / name
        if p.exists():
            with open(p, encoding="utf-8", newline="") as f:
                out += [refang(r[c]) for r in csv.DictReader(f) for c in cols if r.get(c)]
    raw = real_dir / "raw"
    if not raw.is_dir():
        return out
    with contextlib.redirect_stdout(io.StringIO()):   # intake_real's readers print header mappings; nothing of data/real/ is shown
        files = intake_real.discover([raw])
        sens, drops, read, recs = intake_real.Sensitive(), Counter(), Counter(), []
        for p in files["csv"]:
            recs += intake_real.read_form(p, drops, read)[0]
        for p, src in intake_real.assign_labels(files["xml"], "phone", intake_real.PHONE_LABEL).items():
            recs += intake_real.read_sms(p, src, drops, read, sens)
        for p, src in intake_real.assign_labels(files["txt"], "wa", intake_real.WA_LABEL).items():
            recs += intake_real.read_whatsapp(p, src, drops, read, sens)
    return out + [intake_real.mask(r["text"]) for r in recs]


def probe_texts(dirs):
    out = []
    for d in dirs:
        for f in sorted(Path(d).glob("*.csv")) if Path(d).is_dir() else ():
            with open(f, encoding="utf-8", newline="") as fh:
                out += [r["text"] for r in csv.DictReader(fh) if r.get("text")]
    return out


def collisions(texts, corpora):
    """texts: masked collected texts; corpora: [(where, [texts])]. -> one set per text of the `where` labels it is a near-duplicate of."""
    owner, allt = [], []
    for where, ts in corpora:
        owner += [where] * len(ts)
        allt += [model_text(t) for t in ts]
    n0 = len(allt)
    allt += [model_text(t) for t in texts]
    hits = [set() for _ in texts]
    if not texts or not n0:
        return hits
    for i, j, _, _ in near_dup_pairs_any(allt, ["x"] * len(allt), CLUSTER_SEED, skip=lambda i, j: (i < n0) == (j < n0), queries=range(n0, len(allt))):
        a, b = (i, j) if i >= n0 else (j, i)
        if a >= n0 and b < n0:
            hits[a - n0].add(owner[b])
    return hits


def message_corpora(messages):
    m = pd.read_csv(messages, usecols=["text", "split"], low_memory=False, keep_default_na=False)
    return [(f"messages.csv {s}", m.loc[m["split"] == s, "text"].tolist()) for s in ("train", "val", "test")]


# ---------------------------------------------------------------------------------------------------------------- reading the input

def read_sources(inp):
    """-> (sources.csv path, base folder for images, rows)."""
    inp = Path(inp)
    path = inp / "sources.csv" if inp.is_dir() else inp
    if not path.exists():
        stop(f"{path} does not exist (a folder needs a sources.csv with columns filename, source_url, date_seen, channel)")
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        stop(f"{path} has no rows")
    cols = {c.strip().lower() for c in rows[0]}
    missing = [c for c in REQUIRED if c not in cols]
    if missing or not ({"filename", "text"} & cols):
        stop(f"{path}: missing column(s) {', '.join(missing + ([] if {'filename', 'text'} & cols else ['filename or text']))}; found {', '.join(sorted(cols))}")
    return path, path.parent, [{k.strip().lower(): (v or "").strip() for k, v in r.items() if k} for r in rows]


def row_id(masked, url):
    return "C" + hashlib.md5((realguard.norm_key(masked) + "|" + url.strip()).encode()).hexdigest()[:10]


def build_rows(rows, base, batch, collector, drops):
    """Steps 1-4 for each input row -> [record]. Drops are counted in `drops`."""
    out, now = [], dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for r in rows:
        label = LABELS.get(r.get("label", "").lower())
        if label is None:
            stop(f"label {r.get('label')!r} is not scam / genuine / skip / blank")
        if label == "skip":
            drops["label skip"] += 1
            continue
        conf, sha, kind, cer = None, "", "quoted_text", None
        typed = r.get("text", "").replace("\\n", "\n").strip()
        if r.get("filename"):
            p = base / r["filename"]
            if p.suffix.lower() not in IMAGE_EXT or not p.is_file():
                drops["image missing or not PNG / JPEG / WEBP"] += 1
                continue
            data = p.read_bytes()
            sha, kind = hashlib.sha256(data).hexdigest(), "screenshot"
            try:
                text, conf = ocr(data)
            except reader.ImageRejected:
                drops["image unreadable"] += 1
                continue
            if typed:
                import jiwer   # only needed here (requirements-dev.txt)
                cer = round(jiwer.cer(cer_norm(refang(typed)), cer_norm(text) or " "), 3)
                text, kind = typed, "screenshot_typed"
        else:
            text = typed
        masked = mask(text).strip()
        if len(masked) < MIN_CHARS:
            drops["no text / under 10 characters"] += 1
            continue
        verified = (r.get("verified") or r.get("a1_match") or "").lower()
        prov = r.get("provenance", "").lower() or "real_circulating"
        if prov not in PROVENANCE:
            stop(f"provenance {r.get('provenance')!r} is not one of {', '.join(sorted(PROVENANCE))}")
        rec = {"text": intake_real.defang(masked), "label": label, "category": r.get("category", "").lower(), "channel": r.get("channel", "").lower() or "unknown",
               "language": r.get("language", "").lower() or intake_real.script_language(masked), "source_url": defang_url(r["source_url"]),
               "source_group": source_group(r["source_url"]), "outlet": intake_real.defang(mask(r.get("outlet", ""))), "arm": r.get("source_group", "") or r.get("arm", ""),
               "date_seen": r.get("date_seen", ""), "date_flag": date_flag(r.get("date_seen", "")), "collector": collector,
               "verified": verified if verified in VERIFIED else "unchecked", "a1_second_url": defang_url(r.get("a1_second_url", "")),
               "ocr_conf": "" if conf is None else conf, "ocr_cer": "" if cer is None else cer,
               "needs_review": kind == "screenshot" and (conf is None or conf < REVIEW_CONF), "input_kind": kind, "quote_type": r.get("quote_type", ""), "filename": r.get("filename", ""),
               "image_sha256": sha, "is_synthetic": False, "provenance": prov, "batch": batch, "ingested_utc": now,
               "intake_version": INTAKE_VERSION, "notes": intake_real.defang(mask(r.get("notes") or r.get("a1_note") or ""))}
        rec["id"] = row_id(masked, r["source_url"])
        rec["_masked"] = masked
        out.append(rec)
    return out


def check_outputs(recs):
    for rec in recs:
        for c in TEXT_COLS:
            hit = pii_leaks(str(rec.get(c, "")))
            if hit:
                stop(f"{hit[0]} survived masking in column {c} of row {rec['id']}; nothing was written")
        for c in OUT_COLS:
            if live_links(str(rec.get(c, ""))):
                stop(f"a live link survived in column {c} of row {rec['id']}; nothing was written")


# ---------------------------------------------------------------------------------------------------------------- writing

def read_collected(out_dir):
    rows = []
    for f in sorted(Path(out_dir).glob("*/collected.csv")):
        with open(f, encoding="utf-8", newline="") as fh:
            rows += list(csv.DictReader(fh))
    return rows


def regroup(rows):
    """template_group / group_size / group_sources over all collected rows (the real intake's grouping rule on the stored text)."""
    recs = [{"masked": refang(r["text"]), "row": r} for r in rows]
    if not recs:
        return
    groups = intake_real.make_groups(recs)
    for gid, members in groups.items():
        srcs = {m["row"]["source_group"] for m in members}
        for m in members:
            m["row"].update(template_group=gid, group_size=len(members), group_sources=len(srcs))


def write_collected(rows, out_dir):
    by = {}
    for r in rows:
        by.setdefault(r["source_group"], []).append(r)
    for g, rs in by.items():
        d = Path(out_dir) / g
        d.mkdir(parents=True, exist_ok=True)
        with open(d / "collected.csv", "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=OUT_COLS, extrasaction="ignore")
            w.writeheader()
            w.writerows(sorted(rs, key=lambda r: r["id"]))
    return by


def report(path, inp, read_n, kinds, drops, new, total_rows, dry):
    lines = ["# Collected public messages: intake report", "",
             f"Written by `src/intake_screens.py` ({INTAKE_VERSION}). Counts only, no message text. Rows: `data/collected/<source>/collected.csv` (git-ignored).", "",
             f"Last run: input `{Path(inp).name}`{' (dry run, nothing written)' if dry else ''}: {read_n} rows read ({', '.join(f'{k} {v}' for k, v in sorted(kinds.items()))}).", "",
             "| step | rows |", "|---|---|"]
    lines += [f"| dropped: {k} | {v} |" for k, v in sorted(drops.items())] or ["| dropped | 0 |"]
    lines += [f"| written (new) | {len(new)} |", "", "## All collected rows after this run", "",
              f"{len(total_rows)} rows in {len({r['source_group'] for r in total_rows})} source groups.", ""]
    for col in ("source_group", "label", "category", "language", "input_kind", "verified", "date_flag"):
        c = Counter(str(r.get(col, "")) or "(blank)" for r in total_rows)
        lines.append(f"- **{col}**: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))))
    confs = [float(r["ocr_conf"]) for r in total_rows if str(r.get("ocr_conf", "")) not in ("", "None")]
    if confs:
        lines.append(f"- **ocr_conf**: mean {sum(confs) / len(confs):.3f} over {len(confs)} screenshots")
    multi = sum(1 for r in total_rows if int(r.get("group_sources") or 1) > 1)
    lines.append(f"- **cross-source templates**: {multi} rows share a template group with another source group")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(inp, out_dir=COLLECTED, report_path=REPORT, messages=MESSAGES, real_dir=realguard.REAL_DIR, probe_dirs=(realguard.PROBE_DIR,),
        collector="prajval", batch=None, dry_run=False):
    realguard.refuse_real_paths([inp, out_dir])
    src, base, rows = read_sources(inp)
    drops = Counter()
    kinds = Counter("screenshot" if r.get("filename") else "quoted_text" for r in rows)
    recs = build_rows(rows, base, batch or Path(inp).stem, collector, drops)
    check_outputs(recs)
    old = read_collected(out_dir)
    old_ids = {r["id"] for r in old}
    fresh = []
    for rec in recs:
        if rec["id"] in old_ids or rec["id"] in {f["id"] for f in fresh}:
            drops["already collected (same text and page)"] += 1
        else:
            fresh.append(rec)
    corpora = [("data/real", real_texts(real_dir)), ("data/probe", probe_texts(probe_dirs))] + message_corpora(messages)
    hits = collisions([r["_masked"] for r in fresh], corpora)
    new = []
    for rec, h in zip(fresh, hits):
        if h:
            for where in sorted(h):
                drops[f"near-duplicate of {where}"] += 1   # a row twin of two places counts under both
        else:
            new.append(rec)
    total = old + new
    regroup(total)
    if not dry_run:
        write_collected(total, out_dir)
    report(report_path, inp, len(rows), kinds, drops, new, total, dry_run)
    print(f"{len(rows)} rows read, {len(new)} new rows {'would be ' if dry_run else ''}written, {len(total)} collected in all; drops: "
          + (", ".join(f"{k} {v}" for k, v in sorted(drops.items())) or "none"))
    return {"read": len(rows), "new": new, "total": total, "drops": drops}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("input", help="a folder with images + sources.csv, or a sources CSV of quoted texts")
    ap.add_argument("--collector", default="prajval")
    ap.add_argument("--batch", help="batch name stored on each row (default: the input's name)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    try:
        run(a.input, collector=a.collector, batch=a.batch, dry_run=a.dry_run)
    except Stop as e:
        print(e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
