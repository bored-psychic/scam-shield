"""OCR sweep: how the screenshot reader copes with chat bubbles in different app themes, with and without the dark-mode colour step.

    python src/ocr_sweep.py                       both configurations (step off = how it was before, step on = production) -> reports/ocr_sweep.md
    python src/ocr_sweep.py --no-colour-step      only the step-off configuration, table to stdout, no report written
    python src/ocr_sweep.py --tesseract PATH [--tessdata DIR]   read with another Tesseract build (the report records its version)

SYNTHETIC renders. The theme colours are ASSUMED (written from memory of the apps), except "Google Messages dark (MEASURED)", whose page, bubble, text
and link colours were measured from one real screenshot (tests/fixtures/real/jio_kiwi_dark.jpg; its timestamp colour is still assumed). The text is the
14 demo messages of docs/demo/demo_set.json and nothing else. This is a regression guard for the colour step, NOT evidence of real-world accuracy.

Everything is drawn and read in memory: no image is saved, and the OCR path is the production one (`reader.read_image`: stdin / stdout, no temp file).
`--no-colour-step` is a monkeypatch of `reader._coloured_ink` inside this script; production code has no such switch.
The renders have no random element; the seed only fixes the order the jobs are submitted in, so two runs give identical results (the report prints a
digest of the raw texts of each configuration to show it).
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
from PIL import Image

from ocr_render import bubble
from shield.ocr import reader
from textprep import extract_urls

SEED = 0
WORKERS = 4
REPORT = os.path.join(ROOT, "reports", "ocr_sweep.md")
DEMO = json.load(open(os.path.join(ROOT, "docs", "demo", "demo_set.json"), encoding="utf-8"))

# key, label, how the colours were obtained, kind (light | dark | saturated: white text on a saturated bubble), (page, bubble, ink, timestamp, link)
THEMES = [
    ("wa_light", "WhatsApp light", "assumed", "light", ((239, 234, 226), (255, 255, 255), (17, 27, 33), (102, 119, 129), (2, 126, 181))),
    ("wa_dark", "WhatsApp dark", "assumed", "dark", ((11, 20, 26), (32, 44, 51), (233, 237, 239), (134, 150, 160), (83, 189, 235))),
    ("ios_light", "iOS Messages light", "assumed", "light", ((255, 255, 255), (233, 233, 235), (0, 0, 0), (130, 130, 135), (0, 122, 255))),
    ("ios_dark", "iOS Messages dark", "assumed", "dark", ((0, 0, 0), (38, 38, 41), (255, 255, 255), (140, 140, 145), (10, 132, 255))),
    ("gmsg_dark_assumed", "Google Messages dark (assumed)", "assumed", "dark", ((32, 33, 36), (60, 64, 67), (232, 234, 237), (154, 160, 166), (138, 180, 248))),
    ("gmsg_dark_measured", "Google Messages dark (MEASURED)", "measured", "dark", ((0, 0, 0), (32, 33, 37), (240, 240, 240), (140, 140, 145), (40, 105, 220))),
    ("tg_dark", "Telegram dark", "assumed", "dark", ((14, 22, 33), (24, 37, 51), (255, 255, 255), (109, 127, 143), (106, 179, 243))),
    ("blue_on_dark", "plain blue on dark grey", "assumed", "dark", ((18, 18, 18), (40, 40, 40), (235, 235, 235), (140, 140, 140), (0, 0, 238))),
    ("blue_on_light", "plain blue on light grey", "assumed", "light", ((240, 240, 240), (255, 255, 255), (20, 20, 20), (110, 110, 110), (0, 0, 238))),
    ("ios_sent_light", "iOS sent, light page (white on blue)", "assumed", "saturated", ((255, 255, 255), (0, 122, 255), (255, 255, 255), (200, 225, 255), (255, 255, 255))),
    ("ios_sent_dark", "iOS sent, dark page (white on blue)", "assumed", "saturated", ((0, 0, 0), (10, 132, 255), (255, 255, 255), (200, 225, 255), (255, 255, 255))),
    ("wa_out_dark", "WhatsApp dark outgoing (teal)", "assumed", "saturated", ((11, 20, 26), (0, 92, 75), (233, 237, 239), (150, 190, 180), (83, 189, 235))),
    ("wa_out_light", "WhatsApp light outgoing (pale green)", "assumed", "light", ((239, 234, 226), (217, 253, 211), (17, 27, 33), (90, 130, 100), (2, 126, 181))),
    ("tg_out_dark", "Telegram dark outgoing (blue)", "assumed", "saturated", ((14, 22, 33), (43, 82, 120), (255, 255, 255), (160, 190, 220), (140, 200, 255))),
    ("gmsg_light", "Google Messages light", "assumed", "light", ((255, 255, 255), (241, 243, 244), (32, 33, 36), (95, 99, 104), (11, 87, 208))),
]
HIGHLIGHT = "gmsg_dark_measured"
# name, font size, change: png as drawn | jpg = JPEG quality 80 | wNNN = shrunk to NNN px wide
CONDITIONS = [("png40", 40, "png"), ("png28", 28, "png"), ("png34", 34, "png"), ("png48", 48, "png"), ("jpg80", 40, "jpg"), ("w900", 40, "w900"), ("w720", 40, "w720"), ("w540", 40, "w540")]


def cer(ref, hyp):
    """Levenshtein distance / len(ref), both whitespace-normalised."""
    ref, hyp = " ".join(ref.split()), " ".join(hyp.split())
    prev = list(range(len(hyp) + 1))
    for i, a in enumerate(ref, 1):
        cur = [i]
        for j, b in enumerate(hyp, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a != b)))
        prev = cur
    return prev[-1] / max(len(ref), 1)


def render(item, theme_colours, size, change):
    png = bubble(item["text"], size=size, theme=theme_colours)
    if change == "png":
        return png
    img = Image.open(io.BytesIO(png)).convert("RGB")
    out = io.BytesIO()
    if change == "jpg":
        img.save(out, "JPEG", quality=80)
    else:
        w = int(change[1:])
        img.resize((w, round(img.height * w / img.width)), Image.Resampling.LANCZOS).save(out, "PNG")
    return out.getvalue()


def measure(step_on):
    """Reads every (theme, condition, message) once. Returns {(theme, condition, id): {"text", "cer", "link"}}; link is None for a message without a URL."""
    jobs = [(t[0], t[4], c, it) for t in THEMES for c in CONDITIONS for it in DEMO]
    random.Random(SEED).shuffle(jobs)

    def one(job):
        key, colours, (cname, size, change), item = job
        text = reader.read_image(render(item, colours, size, change))["text"]
        urls = extract_urls(item["text"])
        flat = "".join(text.split())
        return (key, cname, item["id"]), {"text": text, "cer": cer(item["text"], text), "link": (all(u in flat for u in urls) if urls else None)}

    patch = contextlib.nullcontext() if step_on else mock.patch.object(reader, "_coloured_ink", lambda rgb, grey, box: grey)
    with patch, ThreadPoolExecutor(WORKERS) as ex:
        return dict(ex.map(one, jobs))


def digest(results):
    h = hashlib.sha256()
    for k in sorted(results):
        h.update(repr((k, results[k]["text"])).encode("utf-8"))
    return h.hexdigest()[:12]


def outcome(b, a):
    """'better' / 'same' / 'worse' for one render: a link kept or lost decides first, then the character error rate."""
    lb, la = b["link"], a["link"]
    if lb is not None and lb != la:
        return "better" if la else "worse"
    if abs(a["cer"] - b["cer"]) < 1e-9:
        return "same"
    return "better" if a["cer"] < b["cer"] else "worse"


def diff_lines(b, a):
    bl, al = b["text"].splitlines(), a["text"].splitlines()
    out = [(x, y) for x, y in zip(bl, al) if x != y]
    if len(bl) != len(al):
        out.append((f"[{len(bl)} lines]", f"[{len(al)} lines]"))
    return out[:3]


def tesseract_version():
    exe = reader._find_tesseract()
    p = subprocess.run([exe, "--version"], capture_output=True, text=True)
    return ((p.stdout or p.stderr).splitlines() or ["unknown"])[0].strip() + f" ({exe})"


def git_state():
    try:
        h = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain", "--", "src", "tests"], capture_output=True, text=True, cwd=ROOT).stdout.strip())
        return h + (" + uncommitted changes in src/ or tests/" if dirty else "")
    except Exception:
        return "unknown"


def table(before, after):
    rows, worse_cases, totals = [], [], {"better": 0, "same": 0, "worse": 0}
    for key, label, prov, kind, _ in THEMES:
        ks = [k for k in before if k[0] == key]
        nlink = [k for k in ks if before[k]["link"] is not None]
        lb, la = sum(before[k]["link"] for k in nlink), sum(after[k]["link"] for k in nlink)
        cb, ca = sum(before[k]["cer"] for k in ks) / len(ks), sum(after[k]["cer"] for k in ks) / len(ks)
        c = {"better": 0, "same": 0, "worse": 0}
        for k in sorted(ks):
            o = outcome(before[k], after[k])
            c[o] += 1
            if o == "worse":
                worse_cases.append((label, k, before[k], after[k]))
        for o in c:
            totals[o] += c[o]
        name = f"{label}" + (" (colours assumed)" if prov == "assumed" else " (colours measured)")
        row = f"| {name} | {kind} | {lb} -> {la} of {len(nlink)} | {cb:.3f} -> {ca:.3f} | {c['better']} | {c['same']} | {c['worse']} |"
        rows.append(f"| **>> {name.replace('| ', '')}** | **{kind}** | **{lb} -> {la} of {len(nlink)}** | **{cb:.3f} -> {ca:.3f}** | **{c['better']}** | **{c['same']}** | **{c['worse']}** |" if key == HIGHLIGHT else row)
    return rows, worse_cases, totals


def write_report(before, after, secs, path):
    rows, worse_cases, totals = table(before, after)
    light = [k for k in before if next(t for t in THEMES if t[0] == k[0])[3] == "light"]
    light_changed = sum(before[k]["text"] != after[k]["text"] for k in light)
    sat = [k for k in before if next(t for t in THEMES if t[0] == k[0])[3] == "saturated"]
    sat_worse = sum(outcome(before[k], after[k]) == "worse" for k in sat)
    lines = [
        "# OCR sweep: colour step off vs on", "",
        "> **SYNTHETIC renders.** Theme colours are **assumed** (written from memory) except **Google Messages dark (MEASURED)**, whose page, bubble, text and link colours were",
        "> measured from one real screenshot (`tests/fixtures/real/jio_kiwi_dark.jpg`; its timestamp colour is still assumed). Text = the 14 demo messages only.",
        "> This is a regression guard for the dark-mode colour step, **not evidence of real-world accuracy.**", "",
        f"- Generated {date.today().isoformat()} by `python src/ocr_sweep.py` at commit {git_state()}; {secs:.0f} s; seed {SEED} (fixes the job order only: the renders are deterministic).",
        f"- Tesseract: {tesseract_version()}, languages `{reader.LANGS}`, `--psm 6`.",
        f"- {len(THEMES)} themes x {len(CONDITIONS)} conditions ({', '.join(c[0] for c in CONDITIONS)}) x {len(DEMO)} messages = {len(before)} reads per configuration. "
        "A condition is a font size, a JPEG at quality 80, or a shrink to a narrower width.",
        f"- **before** = `reader._coloured_ink` switched off by a monkeypatch in this script (the plain inverted-luma conversion; digest `{digest(before)}`). **after** = production code (digest `{digest(after)}`).",
        "- *links kept* = renders of the 4 messages that contain a link whose link text survives (spaces ignored, after `repair_links`). *CER* = mean character error rate over all 14 messages. "
        "*better / same / worse* count single renders: a link gained or lost decides first, then the CER.", "",
        "| Theme | kind | links kept (before -> after) | mean CER (before -> after) | better | same | worse |", "|---|---|---|---|---|---|---|", *rows, "",
        f"**Total: better {totals['better']}, same {totals['same']}, worse {totals['worse']}** of {len(before)} renders.", "",
        "## Guards", "",
        f"- Light themes (the step is never called there): {light_changed} of {len(light)} renders read differently. Must be 0.",
        f"- Saturated bubbles, white text on a saturated colour (iOS sent, WhatsApp / Telegram outgoing): {sat_worse} of {len(sat)} renders worse.", "",
        f"## Every worse case ({len(worse_cases)})", "",
    ]
    if not worse_cases:
        lines.append("None.")
    for label, k, b, a in worse_cases:
        lines.append(f"- **{label}**, {k[1]}, {k[2]}: CER {b['cer']:.3f} -> {a['cer']:.3f}" + ("" if b["link"] == a["link"] else f", link {b['link']} -> {a['link']}"))
        for x, y in diff_lines(b, a):
            lines.append(f"    - before `{x}`  /  after `{y}`")
    lines.append("")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w", encoding="utf-8").write("\n".join(lines))
    return rows, totals, worse_cases


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--no-colour-step", action="store_true", help="only the step-off configuration; prints a table, writes no report")
    ap.add_argument("--tesseract", help="path of another tesseract executable")
    ap.add_argument("--tessdata", help="TESSDATA_PREFIX for it")
    ap.add_argument("--out", default=REPORT, help="report path (default reports/ocr_sweep.md)")
    ap.add_argument("--themes", help="comma-separated theme keys to run (default all); a subset report is meant for quick checks, give it its own --out")
    args = ap.parse_args()
    if args.tesseract:
        reader._find_tesseract = lambda: args.tesseract
    if args.tessdata:
        os.environ["TESSDATA_PREFIX"] = args.tessdata
    if args.themes:
        keep = set(args.themes.split(","))
        unknown = keep - {t[0] for t in THEMES}
        if unknown:
            ap.error(f"unknown theme keys {sorted(unknown)}; known: {', '.join(t[0] for t in THEMES)}")
        THEMES[:] = [t for t in THEMES if t[0] in keep]
    t0 = time.perf_counter()
    if args.no_colour_step:
        off = measure(False)
        print(f"step OFF only: {len(off)} reads, digest {digest(off)}, {time.perf_counter() - t0:.0f} s")
        for key, label, prov, kind, _ in THEMES:
            ks = [k for k in off if k[0] == key]
            nl = [k for k in ks if off[k]["link"] is not None]
            print(f"  {label:42s} links kept {sum(off[k]['link'] for k in nl):2d}/{len(nl)}  mean CER {sum(off[k]['cer'] for k in ks) / len(ks):.3f}")
        return
    before = measure(False)
    print(f"before (step off) done: digest {digest(before)}", flush=True)
    after = measure(True)
    print(f"after  (step on)  done: digest {digest(after)}", flush=True)
    rows, totals, worse = write_report(before, after, time.perf_counter() - t0, args.out)
    print("\n".join(rows))
    print(f"total better {totals['better']} same {totals['same']} worse {totals['worse']}; report: {os.path.relpath(args.out, ROOT)}")


if __name__ == "__main__":
    main()
