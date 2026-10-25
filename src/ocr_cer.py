"""Is the OCR faithful on real public screenshots?  (Assumption A2 in docs/plans/data_acquisition.md.)

    .venv/bin/python src/ocr_cer.py data/collected/inbox/a2/            # images + typed.csv in that folder -> reports/ocr_cer_public.md

typed.csv: filename, typed_text, language (en / hi / kn / ...), and optionally source_url, who_typed. typed_text is typed by hand from the image
BEFORE looking at the OCR output (line breaks as \\n; links defanged, hxxps / [.], as everywhere in data/collected: they are re-fanged in memory
before scoring). What to type: every legible character inside the crop (message, sender line, attachment name and size), except what the
reader drops by design (a time on its own line, Today / Yesterday, Forwarded, tick marks), icons, and characters cut off at the crop's edge.
Each image goes through intake_screens.ocr, which is the app's own reader (shield.ocr.reader), and the character error rate (jiwer: edits /
reference characters) is computed per image and pooled per language, two ways:
  strict      the texts as they are (a bubble-corner time the reader kept counts as an error);
  normalised  bubble-corner times (HH:MM not followed by am / pm, e.g. "09:56") removed from both texts, then every run of white space -> one
              space, ends stripped (line breaks and wrap points are layout, not content). This is the CER tests/test_ocr.py O1-O3 report, and
              the one the target (<= 3% for English) is judged on.
Images are read, never copied; the report names images by file name and holds no message text. No network.
"""
import argparse, csv, re, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]
import jiwer
import realguard
from intake_screens import cer_norm as norm, ocr, refang

REPORT = ROOT / "reports" / "ocr_cer_public.md"
TARGET_EN = 0.03


def run(folder, report=REPORT):
    folder = Path(folder)
    realguard.refuse_real_paths([folder])
    with open(folder / "typed.csv", encoding="utf-8-sig", newline="") as f:
        rows = [r for r in csv.DictReader(f) if r.get("filename") and r.get("typed_text")]
    per, by_lang = [], defaultdict(lambda: {"ref": [], "hyp": [], "ref_n": [], "hyp_n": []})
    for r in rows:
        ref = refang(r["typed_text"].replace("\\n", "\n"))
        hyp, conf = ocr((folder / r["filename"]).read_bytes())
        lang = (r.get("language") or "en").strip().lower()
        s, n = jiwer.cer(ref, hyp) if hyp else 1.0, jiwer.cer(norm(ref), norm(hyp)) if hyp else 1.0
        per.append((r["filename"], lang, len(ref), s, n, conf))
        for k, v in (("ref", ref), ("hyp", hyp or " "), ("ref_n", norm(ref)), ("hyp_n", norm(hyp) or " ")):
            by_lang[lang][k].append(v)
    lines = ["# OCR character error rate on real public screenshots (A2)", "",
             "Written by `src/ocr_cer.py`: hand-typed text vs the app's OCR (`shield.ocr.reader` via `intake_screens.ocr`), jiwer CER = character edits / "
             "reference characters, pooled over the images of a language. No message text in this report.", "",
             "| language | images | reference chars | CER strict | CER normalised (white space) | target |", "|---|---|---|---|---|---|"]
    for lang, d in sorted(by_lang.items()):
        tgt = f"<= {TARGET_EN:.0%}: {'met' if jiwer.cer(d['ref_n'], d['hyp_n']) <= TARGET_EN else 'NOT met'}" if lang == "en" else "reported separately"
        lines.append(f"| {lang} | {len(d['ref'])} | {sum(map(len, d['ref']))} | {jiwer.cer(d['ref'], d['hyp']):.3f} | {jiwer.cer(d['ref_n'], d['hyp_n']):.3f} | {tgt} |")
    lines += ["", "| image | language | reference chars | CER strict | CER normalised | ocr_conf |", "|---|---|---|---|---|---|"]
    lines += [f"| {f} | {lang} | {n} | {s:.3f} | {nn:.3f} | {'' if c is None else c} |" for f, lang, n, s, nn, c in per]
    Path(report).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[4:4 + len(by_lang) + 2]))
    return per


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--report", default=str(REPORT))
    a = ap.parse_args()
    run(a.folder, a.report)


if __name__ == "__main__":
    main()
