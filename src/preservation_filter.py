import argparse
import csv
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from protect import PATTERNS  # noqa: E402  (the "url" pattern the translation step protects)
from spotcheck_score import parse_export  # noqa: E402

# MEASURE ONLY (decision D21, proposed): how many machine-translated rows a "preservation filter" would drop, and whether it catches the
# rows the Hindi spot-check judged wrong. Nothing is written, no data file is changed, the filter is not wired into any pipeline.
# Rule (fixed before any number was seen): drop a translated row if, in the English parent,
#   (1) a digit run [0-9]+ is not a digit run of the translation (native digits are mapped to ASCII first),
#   (2) a URL (protect.py's own url pattern, trailing punctuation stripped) is not in the translation (case-insensitive), or
#   (3) a Latin brand / sender token is not in the translation as a whole Latin word (case-insensitive).
# Brand / sender token = a run of >= 3 Latin letters that is ALL CAPS, or Capitalised and not the first word of the text or of a
# sentence, AND whose lower-case form never occurs as an ordinary lower-case word in the parents (a dictionary-free test: "bank" and
# "order" occur in lower case, "Licious" and "CAMS" do not). The mask tokens <ACCOUNT> / <PHONE> / <EMAIL> / <UPI_ID> are removed first:
# translate_parents.py finalise already requires them to survive.
# TEST-split rows: the very first thing the loader does with a row is look at anchor_split; a test row is skipped there, so its text is
# never tokenised, matched, counted or printed (the script has no code path that reports it). The ordinary-word list is built from the
# same rows only. Rows whose parent has no frozen split yet (every benign preview parent: they are not in messages.csv, so split_map.csv
# has no entry) are reported as their own pool, never added to the train / dev numbers.
#   .venv/bin/python -I src/preservation_filter.py [--no-exempt]   (stdout is ASCII-escaped; English tokens only; --no-exempt = strictest reading)
TRANSLATED = "data/external/indic/translated/translated_final_2026-10-07.csv"
SHEET = "reports/spotcheck_hi.csv"
EXPORT = "docs/spotcheck/hi_friend_v1.txt"
URL_RX = next(rx for kind, rx in PATTERNS if kind == "url")
MASK_RX = re.compile(r"<(?:EMAIL|UPI_ID|PHONE|ACCOUNT)>")
WORD_RX = re.compile(r"[A-Za-z]{3,}")
TRAIL = ".,;:!?)'\"]"
GROUP = {"train": "train", "val": "dev", "": "no split yet"}


def load(path):
    rows = []
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            if r["anchor_split"] == "test":
                continue  # first statement on a row: a test row goes no further
            rows.append({"key": (r["parent_id"], r["language"]), "lang": r["language"], "label": "scam" if r["label"] in ("1", "scam") else "benign",
                         "group": GROUP[r["anchor_split"]], "parent": r["parent_text"], "text": r["text"]})
    return rows


def ordinary_words(parents):
    return {w for p in parents for w in WORD_RX.findall(MASK_RX.sub(" ", p)) if w.islower()}


def brand_tokens(parent, ordinary):
    p = MASK_RX.sub(" ", parent)
    out = []
    for m in WORD_RX.finditer(p):
        w = m.group()
        if w.islower() or w.lower() in ordinary:
            continue
        if not (w.isupper() or w[0].isupper()):
            continue
        before = p[:m.start()].rstrip()
        sentence_initial = before == "" or before[-1] in ".!?:\n"
        if w.isupper() or not sentence_initial:  # an ALL-CAPS word counts even at the start; a Capitalised one only mid-sentence
            out.append(w)
    return out


def ascii_digits(s):
    return "".join(str(unicodedata.digit(c)) if c.isdigit() and not c.isascii() else c for c in s)


def flags(row, ordinary):
    parent, text = row["parent"], row["text"]
    runs = set(re.findall(r"[0-9]+", ascii_digits(text)))
    f = {"digit": sorted({d for d in re.findall(r"[0-9]+", parent) if d not in runs})}
    urls = [u.rstrip(TRAIL) for u in (m.group() for m in URL_RX.finditer(parent))]
    f["url"] = [u for u in urls if u and u.lower() not in text.lower()]
    f["brand"] = sorted({t for t in brand_tokens(parent, ordinary)
                         if not re.search(r"(?<![A-Za-z])" + re.escape(t) + r"(?![A-Za-z])", text, re.I)})
    return f


def hit(f):
    return any(f.values())


def main():
    ap = argparse.ArgumentParser(description="Measure the D21 preservation filter (no data is changed).")
    ap.add_argument("--top", type=int, default=12, help="how many flagged brand tokens to list")
    ap.add_argument("--no-exempt", action="store_true", help="strictest reading: no ordinary-word exemption, every Capitalised / ALL-CAPS word counts")
    a = ap.parse_args()
    rows = load(TRANSLATED)
    ordinary = set() if a.no_exempt else ordinary_words({r["parent"] for r in rows})
    print(f"variant: {'no ordinary-word exemption (strictest)' if a.no_exempt else 'ordinary-word exemption (default)'}")
    for r in rows:
        r["flags"] = flags(r, ordinary)
    by_key = {r["key"]: r for r in rows}

    print("== Reviewed Hindi rows (docs/spotcheck/hi_friend_v1.txt joined to reports/spotcheck_hi.csv) ==")
    _, _, answers = parse_export(EXPORT)
    with open(SHEET, encoding="utf-8-sig", newline="") as fh:
        sheet = {r["row_id"]: r for r in csv.DictReader(fh)}
    seen = {i: by_key.get((sheet[i]["parent_id"], "hindi")) for i in answers}
    skipped = [i for i, r in seen.items() if r is None]  # None = a test-split parent: not loaded
    measured = {i: r for i, r in seen.items() if r is not None}
    print(f"reviewed {len(answers)}; measured {len(measured)}; not measured because the parent is in the test split: {len(skipped)}")
    bad = [i for i in measured if not (answers[i]["meaning"] and answers[i]["label_ok"])]
    good = [i for i in measured if i not in bad]
    for i in sorted(bad):
        f = measured[i]["flags"]
        print(f"  n-row {i} ({measured[i]['label']}): {'CAUGHT ' + str({k: v for k, v in f.items() if v}) if hit(f) else 'not caught'}")
    wrongly = [i for i in good if hit(measured[i]["flags"])]
    print(f"  rows judged y/y measured: {len(good)}; flagged anyway: {len(wrongly)}")
    for i in sorted(wrongly):
        print(f"    {i} ({measured[i]['label']}): {({k: v for k, v in measured[i]['flags'].items() if v})}")
    print(f"  of the {len(bad)} n-rows measured, caught: {sum(hit(measured[i]['flags']) for i in bad)}")

    print("\n== Drop counts (rows with a frozen train / dev split, then the pool with no split yet) ==")
    for group in (("train", "dev"), ("no split yet",)):
        print(f"\npool: {' + '.join(group)}")
        print(f"{'language':<9}{'label':<8}{'rows':>6}{'dropped':>9}{'%':>7}{'digit':>7}{'url':>5}{'brand':>7}")
        tot = Counter()
        for lang in ("hindi", "kannada"):
            for lab in ("scam", "benign"):
                s = [r for r in rows if r["group"] in group and r["lang"] == lang and r["label"] == lab]
                if not s:
                    print(f"{lang:<9}{lab:<8}{0:>6}")
                    continue
                n_drop = sum(hit(r["flags"]) for r in s)
                c = {k: sum(bool(r["flags"][k]) for r in s) for k in ("digit", "url", "brand")}
                print(f"{lang:<9}{lab:<8}{len(s):>6}{n_drop:>9}{100 * n_drop / len(s):>6.1f}%{c['digit']:>7}{c['url']:>5}{c['brand']:>7}")
                tot.update({"rows": len(s), "drop": n_drop})
        if tot["rows"]:
            print(f"{'all':<17}{tot['rows']:>6}{tot['drop']:>9}{100 * tot['drop'] / tot['rows']:>6.1f}%")
        if group[0] == "train":
            for g in ("train", "dev"):
                s = [r for r in rows if r["group"] == g]
                print(f"  {g}: {len(s)} rows, {sum(hit(r['flags']) for r in s)} dropped")
    tokens = Counter(t for r in rows for t in r["flags"]["brand"])
    print(f"\nflagged brand tokens (over the loaded rows, top {a.top}): " + ", ".join(f"{t} x{n}" for t, n in tokens.most_common(a.top)))
    print(f"distinct flagged brand tokens: {len(tokens)}; ordinary lower-case words used to exempt tokens: {len(ordinary)}")


if __name__ == "__main__":
    main()
