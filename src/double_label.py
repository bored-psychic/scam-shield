"""Blind double labelling and Cohen's kappa for the labelling guide (docs/labelling_guide.md; docs/plans/data_acquisition.md, section 6).

    .venv/bin/python src/double_label.py make      # -> data/collected/double_label_sample.csv (the blind sheet) + double_label_key.csv
    .venv/bin/python src/double_label.py kappa     # after the second person filled label_2 -> reports/double_label_kappa.md

make: 50 rows. Every row of data/collected/*/collected.csv labelled scam or genuine (as many as fit), then real (is_synthetic False) VAL rows
of the short-message sources of data/final/messages.csv (uci_sms_spam, scam_ham_india, india_fraud_final) to fill up to 50, chosen so the
sheet is as close to 25 scam / 25 genuine as possible: a sheet of one class makes kappa meaningless, and the pilot's collected rows are all
scam. Test rows are never read (CLAUDE.md rule 1). The order is shuffled (seed 7). The sheet has item, text (links defanged, never starting
with a formula character), label_2 (blank) and notes: no origin, no first label, no model output. The first label and the origin are in
double_label_key.csv, which the second labeller must not open. label_1 is the collector's label for collected rows and the dataset's label
for val rows (1 -> scam, 0 -> genuine), so kappa on val rows also measures how far the old datasets' labels sit from this guide.
make refuses to overwrite a sheet that already has a label_2 filled in (--force to do it anyway).

kappa: Cohen's kappa (sklearn) between label_1 and label_2 over the rows with a label_2, (a) on scam / genuine / skip as three classes and
(b) on the rows both labelled scam or genuine; raw agreement, the confusion table, and both again per origin (collected / val). Landis and
Koch read kappa < 0.60 as moderate or worse: below that, the guide's edge cases need rewriting before more labelling.
"""
import argparse, csv, random, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]
import pandas as pd
from intake_real import sheet_text
from intake_screens import COLLECTED, read_collected, refang

SHEET = COLLECTED / "double_label_sample.csv"
KEY = COLLECTED / "double_label_key.csv"
MESSAGES = ROOT / "data" / "final" / "messages.csv"
REPORT = ROOT / "reports" / "double_label_kappa.md"
N, SEED = 50, 7
VAL_SOURCES = ("uci_sms_spam", "scam_ham_india", "india_fraud_final")
MAX_CHARS = 400
LABELS = ("scam", "genuine", "skip")


def make(force=False, sheet=SHEET, key=KEY, messages=MESSAGES):
    if sheet.exists() and not force:
        with open(sheet, encoding="utf-8", newline="") as f:
            if any((r.get("label_2") or "").strip() for r in csv.DictReader(f)):
                raise SystemExit(f"STOP: {sheet} already has labels in label_2; --force overwrites them")
    rng = random.Random(SEED)
    coll = [r for r in read_collected(COLLECTED) if r["label"] in ("scam", "genuine")]
    rng.shuffle(coll)
    items = [{"text": refang(r["text"]), "label_1": r["label"], "origin": "collected", "source": r["source_group"], "ref": r["id"]} for r in coll[:N]]
    m = pd.read_csv(messages, usecols=["text", "label", "source", "is_synthetic", "split", "text_hash"], low_memory=False, keep_default_na=False)
    m = m[(m["split"] == "val") & m["source"].isin(VAL_SOURCES) & (m["is_synthetic"].astype(str) == "False") & (m["text"].str.len() <= MAX_CHARS)]
    have = Counter(i["label_1"] for i in items)
    need_scam = max(0, min(N // 2 - have["scam"], N - len(items)))
    need_gen = N - len(items) - need_scam
    for lab, k in ((1, need_scam), (0, need_gen)):
        pool = m[m["label"] == lab].sample(n=k, random_state=SEED) if k else m.iloc[:0]
        items += [{"text": t, "label_1": "scam" if lab else "genuine", "origin": "val", "source": s, "ref": h}
                  for t, s, h in zip(pool["text"], pool["source"], pool["text_hash"])]
    rng.shuffle(items)
    sheet.parent.mkdir(parents=True, exist_ok=True)
    with open(sheet, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["item", "text", "label_2", "notes"])
        w.writerows([f"S{i + 1:02d}", sheet_text(it["text"]), "", ""] for i, it in enumerate(items))
    with open(key, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["item", "label_1", "origin", "source", "ref"])
        w.writerows([f"S{i + 1:02d}", it["label_1"], it["origin"], it["source"], it["ref"]] for i, it in enumerate(items))
    c = Counter((it["origin"], it["label_1"]) for it in items)
    print(f"wrote {sheet} ({len(items)} rows: " + ", ".join(f"{o} {l} {n}" for (o, l), n in sorted(c.items())) + f") and {key}")


def kappa(sheet=SHEET, key=KEY, report=REPORT):
    from sklearn.metrics import cohen_kappa_score
    with open(sheet, encoding="utf-8", newline="") as f:
        l2 = {r["item"]: (r.get("label_2") or "").strip().lower() for r in csv.DictReader(f)}
    with open(key, encoding="utf-8", newline="") as f:
        keyrows = list(csv.DictReader(f))
    bad = sorted({v for v in l2.values() if v and v not in LABELS})
    if bad:
        raise SystemExit(f"STOP: label_2 values {bad} are not scam / genuine / skip")
    rows = [(k["label_1"], l2[k["item"]], k["origin"]) for k in keyrows if l2.get(k["item"])]
    if not rows:
        raise SystemExit(f"STOP: no label_2 filled in {sheet}")

    def block(rs, title):
        a, b = [r[0] for r in rs], [r[1] for r in rs]
        two = [(x, y) for x, y in zip(a, b) if x in ("scam", "genuine") and y in ("scam", "genuine")]
        k3 = cohen_kappa_score(a, b, labels=list(LABELS)) if len(set(a) | set(b)) > 1 else float("nan")
        k2 = cohen_kappa_score(*zip(*two), labels=["scam", "genuine"]) if two and len({x for p in two for x in p}) > 1 else float("nan")
        out = [f"### {title}", "", f"n = {len(rs)} rows with a label_2; raw agreement {sum(x == y for x, y in zip(a, b)) / len(rs):.1%}; "
               f"kappa (3 classes) {k3:.3f}; kappa (scam / genuine only, n = {len(two)}) {k2:.3f}", "",
               "| label_1 \\ label_2 | " + " | ".join(LABELS) + " |", "|---|" + "---|" * len(LABELS)]
        cnt = Counter(zip(a, b))
        out += [f"| {x} | " + " | ".join(str(cnt[(x, y)]) for y in LABELS) + " |" for x in ("scam", "genuine")]
        return out + [""]

    lines = ["# Double labelling: Cohen's kappa", "", "Written by `src/double_label.py kappa` (sklearn `cohen_kappa_score`). Guide: `docs/labelling_guide.md`. "
             "label_1 = the collector's label (collected rows) or the dataset's label (val rows); label_2 = the second person, blind.", ""]
    lines += block(rows, "All rows")
    for o in sorted({r[2] for r in rows}):
        lines += block([r for r in rows if r[2] == o], f"origin = {o}")
    lines.append("Reading (Landis and Koch): < 0.60 moderate or worse -> rewrite the guide's edge cases before more labelling; >= 0.80 almost perfect.")
    Path(report).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[5:9]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["make", "kappa"])
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    make(a.force) if a.cmd == "make" else kappa()


if __name__ == "__main__":
    main()
