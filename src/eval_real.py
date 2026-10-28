"""Once-only evaluation on the frozen real-message TEST set data/real/real_test_v1.csv (made by src/intake_real.py).

    .venv/bin/python src/eval_real.py --final            # offline link checks (live=False), both text heads, the full router
    .venv/bin/python src/eval_real.py --final --live     # also RDAP / DNS for links, only through shield.core.net

Refuses to run without --final, and refuses a second run on the same file (same SHA-256) unless --again "reason" is given; every run that
completes appends ONE line to reports/real_eval_ledger.md (UTC time, git commit, file SHA, settings, headline numbers). Nothing here may be used
to choose a threshold, a model or a rule: that is tuning on the test set (CLAUDE.md rule 1). The report holds numbers only, no message text.
Metrics: flagged = router level Suspicious or Likely scam (None = not judged = not flagged); F1, recall (scams flagged), false-alarm rate (genuine
flagged) on that; AUROC is the text head's score (the router's level is not a score). 95% intervals: Wilson for recall and false alarms,
bootstrap (1,000 resamples, seed 0) for F1 and AUROC. Overall, per language and per label_priority bucket (the labelling bucket a group was in:
1 = largest groups, 2 = groups with a mobile_number sender, SCAM-ENRICHED BY DESIGN (since --trim-bucket2: the labelled ones + a seeded
sample), 3 = random, 4 = rest), with and without the overlap=True rows.
"""
import argparse, csv, datetime as dt, hashlib, math, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]
import numpy as np

import realguard

DATA = ROOT / "data" / "real" / "real_test_v1.csv"
LEDGER = ROOT / "reports" / "real_eval_ledger.md"
REPORT = ROOT / "reports" / "real_eval_v1.md"
LEDGER_HEAD = ("# Real-message evaluation ledger\n\nOne line per `src/eval_real.py --final` run on the frozen test set. Appended by the script; "
               "never edit. A second run on the same file is refused unless `--again` gives a reason (recorded in the last column).\n\n"
               "| UTC | commit | file SHA-256 | settings | headline (router F1 / recall / false alarms; text AUROC) | reason for rerun |\n|---|---|---|---|---|---|\n")


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def git_commit():
    try:
        c = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        return c + ("+dirty" if dirty else "")
    except Exception:
        return "unknown"

def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)

def auroc(y, s):
    y, s = np.asarray(y), np.asarray(s, dtype=float)
    pos, neg = s[y == 1], s[y == 0]
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    allv = np.concatenate([pos, neg])   # average ranks for ties
    order = np.argsort(allv, kind="stable")
    r = np.empty(len(allv))
    i = 0
    while i < len(allv):
        j = i
        while j + 1 < len(allv) and allv[order[j + 1]] == allv[order[i]]:
            j += 1
        r[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    return (r[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))

def f1(y, flag):
    y, flag = np.asarray(y), np.asarray(flag)
    tp, fp, fn = int(((y == 1) & flag).sum()), int(((y == 0) & flag).sum()), int(((y == 1) & ~flag).sum())
    return 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else float("nan")

def boot(fn, arrays, n=1000, seed=0):
    rng = np.random.default_rng(seed)
    m = len(arrays[0])
    vals = []
    for _ in range(n):
        ix = rng.integers(0, m, m)
        v = fn(*[a[ix] for a in arrays])
        if not math.isnan(v):
            vals.append(v)
    return (float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))) if len(vals) > 20 else (float("nan"), float("nan"))

def fmt(v, ci):
    return "n/a" if math.isnan(v) else f"{v:.3f} ({ci[0]:.2f}-{ci[1]:.2f})" if not math.isnan(ci[0]) else f"{v:.3f}"

def metrics(y, flag, score):
    y, flag, score = np.asarray(y), np.asarray(flag, dtype=bool), np.asarray(score, dtype=float)
    n_s, n_g = int((y == 1).sum()), int((y == 0).sum())
    tp, fp = int(((y == 1) & flag).sum()), int(((y == 0) & flag).sum())
    out = {"n": len(y), "scams": n_s, "genuine": n_g}
    out["f1"] = (f1(y, flag), boot(lambda a, b: f1(a, b.astype(bool)), [y, flag.astype(int)]) if len(y) >= 10 else (float("nan"),) * 2)
    out["recall"] = (tp / n_s if n_s else float("nan"), wilson(tp, n_s))
    out["fa"] = (fp / n_g if n_g else float("nan"), wilson(fp, n_g))
    out["auroc"] = (auroc(y, score), boot(auroc, [y, score]) if n_s and n_g and len(y) >= 10 else (float("nan"),) * 2)
    return out

def load_rows(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))

def score_rows(rows, live, heads=None):
    """{head: (flags, text scores, not-judged count)} through the full router (shield.core.router.analyse) for each text head.
    The rows are intake-masked text (the intake's masks, not the model's): the router masks every input with the head's own mask_version
    (textprep.model_text), so a v3 bundle sees the v3 masks on top of the intake's and a v2 bundle the v2 ones; tests/test_masks.py M8.
    `heads` replaces the two shipped heads (tests only)."""
    from shield import config
    from shield.core import router
    from shield.links.gambling import load_gambling
    from shield.links.lexical import load_url_model
    from shield.links.lists import warm as warm_lists
    from shield.messages.text_head import MurilScorer, load_baseline
    if live:
        os.environ.pop("SAFE_BROWSING_KEY", None)   # RDAP and DNS only
        assert not config.CRTSH_CHECK, "crt.sh must stay off for the real-message evaluation"
    load_gambling()
    warm_lists()
    url_model = load_url_model()
    if heads is None:
        heads = {"MuRIL": MurilScorer(config.MURIL_DIR, config.TEXT_DEVICE), "baseline": load_baseline()}
    out = {}
    for name, head in heads.items():
        flags, scores, unjudged = [], [], 0
        for r in rows:
            res = router.analyse(r["text"], head, url_model, live=live)
            lvl = res["level"]
            unjudged += lvl is None
            flags.append(lvl is not None and lvl >= 1)
            scores.append(res["text_score"] if res["text_score"] is not None else 0.0)
        out[name] = (np.array(flags), np.array(scores), unjudged)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--final", action="store_true", help="REQUIRED: score the test set (once)")
    ap.add_argument("--live", action="store_true", help="also run the live link checks (RDAP / DNS only, through shield.core.net)")
    ap.add_argument("--again", metavar="REASON", help="allow a rerun on a file that is already in the ledger; the reason is recorded")
    ap.add_argument("--data", type=Path, default=DATA)
    ap.add_argument("--ledger", type=Path, default=LEDGER)
    ap.add_argument("--report", type=Path, default=REPORT)
    a = ap.parse_args()
    if not a.final:
        sys.exit("refused: this is the once-only real-message test set. Run with --final to score it; it cannot be used for development.")
    if not a.data.exists():
        sys.exit(f"refused: {a.data} not found (run src/intake_real.py first)")
    sha = sha256(a.data)
    ledger = a.ledger.read_text(encoding="utf-8") if a.ledger.exists() else ""
    if sha in ledger and not a.again:
        sys.exit(f"refused: this file ({sha[:16]}...) is already in {a.ledger.name}. The test set is scored once; a rerun needs --again \"reason\" and is recorded.")
    rows = load_rows(a.data)
    y = np.array([int(r["label"]) for r in rows])
    overlap = np.array([r["overlap"] == "True" for r in rows])
    lang = np.array([r["language"] for r in rows])
    prio = np.array([r.get("label_priority", "") or "" for r in rows])
    res = score_rows(rows, a.live)

    L = ["# Real-message evaluation v1 (once-only)\n",
         f"*{dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC, commit {git_commit()}, file SHA-256 `{sha}`, {len(rows)} rows "
         f"({int(y.sum())} scam, {int((y == 0).sum())} genuine; {int(overlap.sum())} overlap=True). Live link checks: {'RDAP + DNS' if a.live else 'off (offline link analysis)'}. Numbers only; no message text.*\n",
         "Flagged = router level Suspicious or Likely scam. AUROC = the text head's score. 95% intervals in brackets (Wilson for recall and false alarms, bootstrap for F1 and AUROC). "
         "This set was never used to train, tune or calibrate anything; do not use these numbers to choose a threshold, rule or model.\n"]
    headline = {}
    subsets = [("all rows", np.ones(len(rows), bool)), ("without overlap rows", ~overlap)]
    langs = sorted(set(lang))
    buckets = sorted(b for b in set(prio) if b)
    if buckets:
        L.append("Rows per label_priority bucket (scam / genuine): " + "; ".join(f"{b}: {int(((prio == b) & (y == 1)).sum())} / {int(((prio == b) & (y == 0)).sum())}" for b in buckets)
                 + ". **Bucket 2 is scam-enriched by design** (groups with a mobile_number sender were labelled on purpose, so its scam share is not the inbox base rate, and "
                   "its precision-like numbers are not comparable with the other buckets).\n")
    for head, (flags, scores, unjudged) in res.items():
        L.append(f"## {head}\n")
        L.append(f"Not judged by the router (no level): {unjudged}.\n")
        L.append("| group | rows | n scam / genuine | F1 | recall | false alarms | AUROC |\n|---|---:|---|---|---|---|---|")
        for sname, m in subsets:
            for g, gm in [("overall", np.ones(len(rows), bool))] + [(f"lang={l}", lang == l) for l in langs] + [(f"label_priority={b}", prio == b) for b in buckets]:
                mm = m & gm
                if mm.sum() == 0:
                    continue
                r = metrics(y[mm], flags[mm], scores[mm])
                if g == "overall" and sname == "all rows":
                    headline[head] = r
                L.append(f"| {sname}, {g} | {r['n']} | {r['scams']} / {r['genuine']} | {fmt(*r['f1'])} | {fmt(*r['recall'])} | {fmt(*r['fa'])} | {fmt(*r['auroc'])} |")
        L.append("")
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text("\n".join(L) + "\n", encoding="utf-8")

    def short(h):
        r = headline[h]
        return f"{h}: {r['f1'][0]:.3f} / {r['recall'][0]:.3f} / {r['fa'][0]:.3f}; AUROC {r['auroc'][0]:.3f}"
    settings = f"heads MuRIL + baseline; live={'yes' if a.live else 'no'}; n={len(rows)}; report {a.report.name}"
    line = f"| {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%MZ')} | {git_commit()} | `{sha}` | {settings} | {short('MuRIL')} ; {short('baseline')} | {a.again or ''} |\n"
    a.ledger.parent.mkdir(parents=True, exist_ok=True)
    if not a.ledger.exists():
        a.ledger.write_text(LEDGER_HEAD, encoding="utf-8")
    with open(a.ledger, "a", encoding="utf-8") as f:
        f.write(line)
    print(f"wrote {a.report} and one line to {a.ledger}")
    for h in headline:
        print(short(h))


if __name__ == "__main__":
    main()
