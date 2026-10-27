"""Evaluation of the D11 folded view (shield.core.fold) -> reports/fold_v1.md.

    .venv/bin/python src/eval_fold.py            # both heads for the val part; no network (live=False)

1. messages_aug.csv (train parents only, 20,022 rows), the three training attack families homoglyph / leet / zero_width: how often a rule fires on the attacked
   text, read raw (before D11) and folded (after), next to the clean parent. 'Recovered' = fires on the attacked text / fires on the clean parent. Rows whose
   parent the rule does not fire on count in no ratio but are in the rates. The stored text is PII-masked, so A1 (a UPI id) reads the stored <UPI_ID> / <EMAIL>
   tokens as a plain non-@valid handle (the same proxy as src/eval_invest_rules.py); a zero-width character inside such a token breaks that proxy on the raw view.
2. Val, every row (5,267; 4,115 genuine / 1,152 scam): per rule family how many rows fire before / after, by label; every genuine row newly hit; and the whole app
   (router.analyse, MuRIL and the TF-IDF baseline, fold off vs on): F1, precision and recall of 'flagged' (Suspicious or Likely scam) and every row whose level
   changed. Rows whose folded text equals the text are analysed once (the result is the same by construction; 200 of them are re-run to check it).
3. Train, clean text: what the fold does to the unattacked train messages (38,953 rows): how many change, and the rule families that fire on the folded
   text but not on the raw one (noise from the fold itself), and the other way round.
No test-split row is read: messages.csv is streamed and a row whose split is not val or train is skipped before its text is used (CLAUDE.md rule 1).
"""
import csv, random, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]
csv.field_size_limit(sys.maxsize)

from pii import mask_text
from shield.core.fold import fold
from shield.messages.invest_rules import RULES, invest_rule_hits
from shield.messages.rules import cred_requests, pin_to_receive
from shield.messages.tactics import tactic_tags

MESSAGES, AUG = ROOT / "data" / "final" / "messages.csv", ROOT / "data" / "final" / "messages_aug.csv"
REPORT = ROOT / "reports" / "fold_v1.md"
CODES = [r[0] for r in RULES]
TAGS = ["authority", "urgency", "payment", "isolation"]
FAMILIES = ["homoglyph", "leet", "zero_width"]


def proxy(text):
    return re.sub(r"<(?:UPI_ID|EMAIL)>", "x@ybl", text)[:20000]


def fires(view):
    """The rule families that fire on one text view: {'OTP', 'R2', 'invest', 'A1'.., 'tactic', 'tactic.urgency'.., 'rule' (OTP, R2 or any invest rule)}."""
    cred = cred_requests(view)
    out = set()
    if cred:
        out.add("OTP")
    if pin_to_receive(view):
        out.add("R2")
    inv = {h["code"] for h in invest_rule_hits(proxy(view))}
    out |= inv
    if inv:
        out.add("invest")
    tags = tactic_tags(mask_text(view), cred)
    out |= {f"tactic.{t}" for t, c in tags.items() if c}
    if any(tags.values()):
        out.add("tactic")
    if out & ({"OTP", "R2", "invest"}):
        out.add("rule")
    return out


def pct(k, n):
    return f"{k / n:.1%}" if n else "-"


def rows_of(path, splits):
    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["split"] in splits:   # a test row is skipped here, before anything else of it is used
                yield r


def aug_section(L):
    parents = {}
    with open(MESSAGES, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["split"] == "train":
                parents[r["text_hash"]] = r["text"]
    rows = [r for r in rows_of(AUG, {"train"}) if r["aug_method"] in FAMILIES]
    fam_n, raw, new, clean = (defaultdict(Counter) for _ in range(4))
    changed = Counter()
    seen_parent = {}
    for r in rows:
        fam = r["aug_method"]
        fam_n[fam]["n"] += 1
        t = r["text"]
        f_t, _ = fold(t)
        changed[fam] += f_t != t
        a, b = fires(t), fires(f_t)
        if r["parent_hash"] not in seen_parent:
            seen_parent[r["parent_hash"]] = fires(parents[r["parent_hash"]])
        c = seen_parent[r["parent_hash"]]
        for k in ("rule", "OTP", "R2", "invest", "tactic") + tuple(CODES) + tuple(f"tactic.{t_}" for t_ in TAGS):
            clean[fam][k] += k in c
            raw[fam][k] += k in a
            new[fam][k] += k in b
            if k in c:   # recovery is counted over the rows whose parent fires
                raw[fam][k + "|c"] += k in a
                new[fam][k + "|c"] += k in b
                clean[fam][k + "|c"] += 1
    L += ["## 1. messages_aug.csv, train parents: rule hit rate on attacked rows, before (raw) and after (folded)", "",
          f"{len(rows):,} rows ({', '.join(f'{fam} {fam_n[fam]['n']:,}' for fam in FAMILIES)}); the fold changed the text of "
          f"{', '.join(f'{changed[fam]:,} {fam}' for fam in FAMILIES)} rows. 'clean' = the unattacked parent, 'before' = the rules on the attacked text read raw "
          f"(D11 off), 'after' = read folded. Rate = share of all rows of the family on which the rule fires. 'Recovered' = of the rows whose clean parent fires "
          f"the rule, the share on which the attacked text fires it.", ""]
    keys = [("rule", "any hard rule (OTP / PIN / R2 / A1-A12)"), ("OTP", "OTP / PIN / CVV / password request"), ("R2", "R2 PIN to receive"), ("invest", "any investment rule A1-A12")]
    keys += [(c, f"{c} {next(x[4] for x in RULES if x[0] == c)}") for c in CODES] + [("tactic", "any tactic tag")] + [(f"tactic.{t}", f"tactic: {t}") for t in TAGS]
    for fam in FAMILIES:
        n = fam_n[fam]["n"]
        L += [f"### {fam} ({n:,} rows)", "", "| rule | clean | before | after | recovered before | recovered after |", "|---|---|---|---|---|---|"]
        for k, name in keys:
            nc = clean[fam][k + "|c"]
            if not clean[fam][k] and not raw[fam][k] and not new[fam][k]:
                continue
            L.append(f"| {name} | {pct(clean[fam][k], n)} ({clean[fam][k]:,}) | {pct(raw[fam][k], n)} ({raw[fam][k]:,}) | {pct(new[fam][k], n)} ({new[fam][k]:,}) | "
                     f"{pct(raw[fam][k + '|c'], nc)} | **{pct(new[fam][k + '|c'], nc)}** |")
        L.append("")
    return L


class Cached:
    """A text head that remembers its scores (the folded view never reaches a model, so fold off / on score the same prepared text)."""
    def __init__(self, head):
        self._h, self._c = head, {}
    def score(self, text):
        if text not in self._c:
            self._c[text] = self._h.score(text)
        return self._c[text]
    def __getattr__(self, name):
        return getattr(self._h, name)


def f1(tp, fp, fn):
    return 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else float("nan")


def val_section(L):
    from shield import config
    from shield.core.router import analyse
    from shield.links.gambling import load_gambling
    from shield.links.lexical import load_url_model
    from shield.links.lists import warm
    from shield.messages.text_head import MurilScorer, load_baseline
    load_gambling(); warm()
    um = load_url_model()
    heads = {"MuRIL (the app)": Cached(MurilScorer(config.MURIL_DIR, config.TEXT_DEVICE)), "TF-IDF baseline": Cached(load_baseline())}
    rows = [r for r in rows_of(MESSAGES, {"val"})]
    n, n_scam = len(rows), sum(r["label"] == "1" for r in rows)
    folded = [fold(r["text"])[0] for r in rows]
    diff = [i for i in range(n) if folded[i] != rows[i]["text"]]
    L += ["## 2. Val (every row)", "",
          f"{n:,} rows ({n - n_scam:,} genuine / {n_scam:,} scam). The fold changes the text of **{len(diff)}** of them "
          f"({Counter(rows[i]['source'] for i in diff).most_common(6)}); the other rows read the same text with fold off and on.", ""]

    # --- rule families, before / after
    fam_keys = ["OTP", "R2", "invest"] + CODES + ["tactic"] + [f"tactic.{t}" for t in TAGS]
    cnt = {(k, lab, view): 0 for k in fam_keys for lab in "01" for view in ("raw", "fold")}
    newly, lost, f_raw, f_new = [], [], {}, {}
    for i in range(n):
        r = rows[i]
        a = fires(r["text"])
        b = a if i not in set(diff) else fires(folded[i])
        f_raw[i], f_new[i] = a, b
        for k in fam_keys:
            cnt[(k, r["label"], "raw")] += k in a
            cnt[(k, r["label"], "fold")] += k in b
        for k in sorted((b - a) & set(fam_keys)):
            newly.append((i, k))
        for k in sorted((a - b) & set(fam_keys)):
            lost.append((i, k))
    L += ["### 2a. Rows on which each rule family fires", "", "| rule | genuine before | genuine after | scam before | scam after |", "|---|---|---|---|---|"]
    for k in fam_keys:
        vals = [cnt[(k, "0", "raw")], cnt[(k, "0", "fold")], cnt[(k, "1", "raw")], cnt[(k, "1", "fold")]]
        if any(vals):
            L.append(f"| {k} | " + " | ".join(str(v) for v in vals) + " |")
    L += ["", f"Rows newly hit by a family after the fold: **{len(newly)}** ({sum(rows[i]['label'] == '0' for i, _ in newly)} genuine); rows that lose a hit: **{len(lost)}**.", ""]
    for title, items in (("Newly hit", newly), ("No longer hit", lost)):
        if items:
            L += [f"{title} (family, label, source, text):", ""]
            for i, k in items[:40]:
                L.append(f"- `{k}` label {rows[i]['label']} {rows[i]['source']}: {rows[i]['text'][:160]!r}")
            L.append("")

    # --- the whole app
    L += ["### 2b. The whole app: flagged = Suspicious or Likely scam", "", "| head | fold | F1 | precision | recall | flagged | levels changed vs off |", "|---|---|---|---|---|---|---|"]
    detail = []
    for hname, head in heads.items():
        off = [analyse(r["text"], head, um, fold=False)["level"] for r in rows]
        on = list(off)
        for i in diff:
            on[i] = analyse(rows[i]["text"], head, um, fold=True)["level"]
        rng = random.Random(11)
        same = rng.sample([i for i in range(n) if i not in set(diff)], 200)
        check = [analyse(rows[i]["text"], head, um, fold=True)["level"] == off[i] for i in same]
        assert all(check), f"{head}: a row the fold leaves unchanged got another level with fold on"
        for name, lv in (("off", off), ("on", on)):
            fl = [(l or 0) >= 1 for l in lv]
            tp = sum(f and r["label"] == "1" for f, r in zip(fl, rows)); fp = sum(f and r["label"] == "0" for f, r in zip(fl, rows)); fn = sum((not f) and r["label"] == "1" for f, r in zip(fl, rows))
            ch = sum(a != b for a, b in zip(off, lv))
            L.append(f"| {hname} | {name} | {f1(tp, fp, fn):.4f} | {tp / (tp + fp):.4f} | {tp / (tp + fn):.4f} | {sum(fl)} | {ch} |")
        for i in range(n):
            if off[i] != on[i]:
                detail.append((hname, i, off[i], on[i]))
    L += ["", f"(200 rows the fold leaves unchanged were re-run with fold on: same level on all 200, both heads.)", ""]
    L += [f"### 2c. Rows whose level changed ({len(detail)} in all, both heads)", ""]
    for hname, i, a, b in detail[:60]:
        L.append(f"- {hname}: {a} -> {b}, label {rows[i]['label']}, {rows[i]['source']}: {rows[i]['text'][:160]!r}")
    if not detail:
        L.append("None.")
    L.append("")
    return L


def train_section(L):
    rows = list(rows_of(MESSAGES, {"train"}))
    new, lost, ex, ch = Counter(), Counter(), {}, 0
    for r in rows:
        t = r["text"]
        f, _ = fold(t)
        if f == t:
            continue
        ch += 1
        a, b = fires(t), fires(f)
        for k in b - a:
            new[(k, r["label"])] += 1
            ex.setdefault(k, []).append(r["text"])
        for k in a - b:
            lost[(k, r["label"])] += 1
            ex.setdefault("lost " + k, []).append(r["text"])
    L += ["## 3. Train, clean text: what the fold does to unattacked messages", "",
          f"{len(rows):,} train rows; the fold changes the text of {ch:,} (mostly no-break spaces, mojibake accents, ellipses and trade-mark signs in the long email sources). "
          "Rule families that fire on the folded text and did not on the raw text (label 0 = genuine, 1 = scam):", ""]
    L += ["| family | genuine | scam |", "|---|---|---|"] + [f"| {k} | {new[(k, '0')]} | {new[(k, '1')]} |" for k in sorted({k for k, _ in new})] + ["" if new else "None.", ""]
    L += ["Families that stop firing:", "", "| family | genuine | scam |", "|---|---|---|"] + [f"| {k} | {lost[(k, '0')]} | {lost[(k, '1')]} |" for k in sorted({k for k, _ in lost})] + ["" if lost else "None.", ""]
    return L


NOTES = '''## Notes (hand-written; `eval_fold.py` appends this text)

- **The attacks.** `augment.py` attacks every letter independently (homoglyph 15%, leet 20%, zero-width 10% per letter), so a rule word is often hit more than once. Read raw, the hard rules (OTP / PIN / R2 / A1-A12) fire on 34-54% of the rows whose clean parent fires; read folded, on 100% in all three families. Tactic tags: 75-84% raw, 98.8-100% folded. The three leet cases it cannot undo: a word-initial `@` whose word the rules do not know, a `1` in a word the rules do not know (read as `i`), a run of leet digits longer than three.
- **A raw-view false alarm that the fold removes.** On the leet rows A1 (non-@valid UPI id, a Likely-scam floor) fires on 69 rows whose clean parent does not: `se@rch`, `em@il`, `incre@se` have the shape of a UPI id. Folded, 3 remain. It is not a gain in detection, but it shows the raw view was noisy on leet text.
- **Val: nothing changes.** The fold changes the text of about 2,000 val rows (mostly no-break spaces, mojibake accents, ellipses and trade-mark signs in `fake_job_postings` and `phishing_email`), and no rule family gains or loses a row, no level changes, F1 is identical for both heads. This is a statement about val, whose genuine rows hold no disguise; it does not measure how often a real scam is disguised.
- **Train, clean text.** 14 scam rows newly get the authority tag: they write `FL1PKART` (the fold reads the brand, as intended). One genuine and one scam row lose a payment cue and one scam row an isolation cue (`Secret$` becomes `Secrets`: the fold removed a `secret` word-boundary match). No hard rule fires on any train row because of the fold. Two fold rules were added after this check showed they were noisy: a `$` between hex digits (the `$` in e-mail Message-IDs) is not leet, and a short id with one digit at its end (`CB1`, `SB1`, `EH1`) is not read as `cbi` / `sbi` / `ehi`; and `Rs 151OFF` stays a number.
- **Not done on purpose.** Separators between letters (`O.T.P`, `O T P`) are the held-out `spaced_keywords` attack and are not folded here. Devanagari and Kannada are not folded (only invisible characters are dropped, ZWJ / ZWNJ kept); a Latin look-alike inside a Hindi sentence is folded like any Latin text.
'''


def main():
    L = ["# D11 folded view: evaluation", "",
         "`src/eval_fold.py`, offline (`live=False`), " + __import__("datetime").date.today().isoformat() + ". Fold: `src/shield/core/fold.py`. Rules, tactic cues and fear cues "
         "match on the folded text; the models, link extraction and the language detection read the raw text. No test-split row was read.", ""]
    aug_section(L)
    val_section(L)
    train_section(L)
    L += ["", NOTES]
    REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"wrote {REPORT}")


if __name__ == "__main__":
    main()
