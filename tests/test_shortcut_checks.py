import json, os, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(os.path.abspath(globals().get("__file__", "tests/test_shortcut_checks.py"))).parent   # exec()-ed from the project root there is no __file__
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "src"), str(HERE)]

import numpy as np, pandas as pd
import shortcut_checks as sc
from pool_fixture import WORDS

# python tests/test_shortcut_checks.py   (from the project root). splits-v3 shortcut checks (docs/plans/splits_v3.md section 3; src/shortcut_checks.py). Every check runs on
# INVENTED frames (random word salad; nothing under data/ or models/ is read or written, nothing under data/real/ is touched).
#   T1  clean frame (cues independent of label and of pool origin): no flag, in any section
#   T2  planted label shortcut (<OTP> only in the scam rows of one source): exactly that cue flags, in that source and overall, nowhere else
#   T3  planted POOL-origin shortcut (<ACCOUNT> only in pool rows): flags as a pool cue (all rows, genuine rows only, vs each source) and not as a label cue
#   T4  length: a planted length gap flags; length with / without POOL differ when the pool is short and genuine
#   T5  synthetic family vs real collect rows: planted token flags, identical rows do not, family off -> not checked, too few real rows -> no flag
#   T6  loader: test rows never kept, a v2-style file (no kw_bucket / real_group, no pool) works and the pool section is "not measurable"
#   T7  CLI (sanity_checks.py --v3-shortcuts) on an invented folder: prints RED FLAG lines, writes only the requested report, leaves reports/sanity.md alone
#   T8  (opt-in, SHORTCUT_FIXTURE_BUILD=<folder with messages.csv>) on a B0b fixture build: runs, and a plant on top of it makes exactly the planted flags appear new


def frame(rng, split, n_per=240, with_pool=True, srcs=("srcA", "srcB")):
    """Invented rows: every source (and the pool) is half scam; tokens, length and language do not depend on label or source."""
    rows = []
    for s in list(srcs) + ([sc.POOL_SOURCE] if with_pool else []):
        for i in range(n_per):
            label = i % 2
            body = " ".join(rng.choice(WORDS, size=int(rng.integers(8, 30))))
            toks = " ".join(t for t in sc.TOKENS if rng.random() < 0.3)
            rows.append({"text": f"{body} {toks}".strip(), "label": label, "source": s, "language": "english", "is_synthetic": "False", "split": split,
                         "kw_bucket": ["kyc-bank", "delivery", "other"][int(rng.integers(0, 3))] if s == sc.POOL_SOURCE else "", "real_group": ""})
    return pd.DataFrame(rows)


def flagged(flags):
    return sorted(f.split(":")[0] for f in flags)


def make(seed=1, **kw):
    rng = np.random.default_rng(seed)
    return frame(rng, "train", **kw), frame(rng, "val", **kw)


def t1(tmp):
    tr, va = make()
    flags, report = sc.run(tr, va)
    bad = [f"clean frame flagged: {f}" for f in flags]
    if "## Flags (0)" not in report:
        bad.append("the report does not say 0 flags")
    return bad


def t2(tmp):
    tr, va = make()
    hit = (va["source"] == "srcA") & (va["label"] == 1)
    va.loc[hit, "text"] += " <OTP>"
    flags, _ = sc.run(tr, va)
    kinds = {(f.split("] ")[0] + "]", f.split("] ")[1].split(" | ")[0], f.split(" | ")[1].split(":")[0]) for f in flags}
    want = {("RED FLAG [label cue]", "has <OTP>", "source srcA"), ("RED FLAG [label cue]", "has <OTP>", "all val")}
    bad = []
    # 'all val' also holds the other sources, so the overall AUROC is diluted: strength is about 0.5 + 0.5 * (0.5 * 1/3)... only the per-source flag is required
    if ("RED FLAG [label cue]", "has <OTP>", "source srcA") not in kinds:
        bad.append(f"planted <OTP> label shortcut in srcA not flagged: {sorted(kinds)}")
    extra = kinds - want
    if extra:
        bad.append(f"unplanted flags: {sorted(extra)}")
    return bad


def t3(tmp):
    tr, va = make()
    va.loc[va["source"] == sc.POOL_SOURCE, "text"] += " <ACCOUNT>"
    flags, _ = sc.run(tr, va)
    bad = []
    pool_flags = [f for f in flags if f.startswith("RED FLAG [POOL-origin cue] has <ACCOUNT> |")]
    scopes = {f.split(" | ")[1].split(":")[0] for f in pool_flags}
    for want in ("all val rows", "genuine rows only", "genuine"):
        if not any(s.startswith(want) for s in scopes):
            bad.append(f"no POOL-origin flag for scope {want!r}: {sorted(scopes)}")
    if any("[label cue]" in f for f in flags):
        bad.append("a pool-only token is reported as a label cue: " + str([f for f in flags if "[label cue]" in f]))
    others = [f for f in flags if "has <ACCOUNT>" not in f]
    if others:
        bad.append(f"unplanted flags: {others}")
    # without any pool rows the pool section is not measurable and never flags
    tr2, va2 = make(with_pool=False)
    va2["text"] += " <ACCOUNT>"
    f2, rep2 = sc.run(tr2, va2)
    if f2 or "not measurable" not in rep2:
        bad.append(f"no-pool frame: flags {f2}, 'not measurable' in report: {'not measurable' in rep2}")
    return bad


def t4(tmp):
    tr, va = make()
    pool = va["source"] == sc.POOL_SOURCE
    va.loc[pool, "text"] = va.loc[pool, "text"].str.slice(0, 40)   # the pool is short (and half scam here)
    flags, _ = sc.run(tr, va)
    bad = []
    if not any(f.startswith("RED FLAG [POOL-origin cue] length |") for f in flags):
        bad.append("short pool rows: no POOL-origin length flag")
    # length gap on the label inside one source: scam rows are long
    tr, va = make()
    hit = (va["source"] == "srcB") & (va["label"] == 1)
    va.loc[hit, "text"] = va.loc[hit, "text"] + " " + " ".join(["filler"] * 60)
    flags, _ = sc.run(tr, va)
    if not any(f.startswith("RED FLAG [label cue] length | source srcB") for f in flags):
        bad.append(f"planted length gap in srcB not flagged: {flagged(flags)}")
    # with / without POOL: the pool carries genuine short rows and nothing else does -> the two numbers differ
    rng = np.random.default_rng(3)
    _, va = make(seed=3)
    pool = va["source"] == sc.POOL_SOURCE
    va.loc[pool & (va["label"] == 0), "text"] = "short ok"
    d = sc.length_with_without_pool(va.assign(is_synthetic="False"))
    a = d.set_index("scope")["AUROC"]
    if not (abs(a["all val"] - a["all val, without POOL"]) > 0.02):
        bad.append(f"length AUROC with / without POOL did not differ: {a.to_dict()}")
    return bad


def t5(tmp):
    rng = np.random.default_rng(5)
    def rows(n, source, extra, text_fn=lambda i: f"collect request from {rng.choice(WORDS)} {rng.choice(WORDS)}"):
        return [{"text": text_fn(i) + extra, "label": 0, "source": source, "language": "english", "is_synthetic": "False", "split": "val", "kw_bucket": "", "real_group": ""} for i in range(n)]
    tr = pd.DataFrame(rows(5, "srcA", ""))
    tr["split"] = "train"
    bad = []
    va = pd.DataFrame(rows(30, sc.SYNTH_UPI_SOURCE, " <UPI_ID>") + rows(30, sc.POOL_SOURCE, ""))
    flags, _ = sc.run(tr, va)
    if not any("[synthetic-vs-real cue] has <UPI_ID>" in f for f in flags):
        bad.append(f"planted synthetic-only <UPI_ID> not flagged: {flags}")
    va = pd.DataFrame(rows(30, sc.SYNTH_UPI_SOURCE, " <UPI_ID>") + rows(30, sc.POOL_SOURCE, " <UPI_ID>"))
    flags, _ = sc.run(tr, va)
    if any("[synthetic-vs-real cue] has <UPI_ID>" in f for f in flags):
        bad.append("identical token in both groups flagged")
    va = pd.DataFrame(rows(30, sc.POOL_SOURCE, ""))
    d, note = sc.synth_vs_real(va)
    if d is not None or "not in this build" not in note:
        bad.append(f"family off: {d}, {note!r}")
    va = pd.DataFrame(rows(30, sc.SYNTH_UPI_SOURCE, " <UPI_ID>") + rows(3, sc.POOL_SOURCE, ""))
    d, _ = sc.synth_vs_real(va)
    if d["flag"].any() or not d["note"].str.contains("too few").all():
        bad.append("3 real collect rows: should be 'too few rows', no flag")
    return bad


def write_messages(folder, tr, va, te=None):
    te = te if te is not None else va.assign(split="test", text="TESTROW POISON <OTP>")
    pd.concat([tr, va, te], ignore_index=True).to_csv(Path(folder) / "messages.csv", index=False)


def t6(tmp):
    tr, va = make()
    write_messages(tmp, tr, va)
    tr2, va2 = sc.load(str(tmp / "messages.csv"))
    bad = []
    if set(tr2["split"]) != {"train"} or set(va2["split"]) != {"val"}:
        bad.append("loader returned a split other than train / val")
    if va2["text"].str.contains("TESTROW").any() or tr2["text"].str.contains("TESTROW").any():
        bad.append("a test row was kept")
    if len(tr2) != len(tr) or len(va2) != len(va):
        bad.append(f"row counts: {len(tr2)}/{len(va2)} vs {len(tr)}/{len(va)}")
    # a v2-style file: no kw_bucket / real_group columns, no pool
    tr3, va3 = make(with_pool=False)
    v2 = Path(tmp) / "v2"
    v2.mkdir()
    write_messages(v2, tr3.drop(columns=["kw_bucket", "real_group"]), va3.drop(columns=["kw_bucket", "real_group"]),
                   va3.assign(split="test").drop(columns=["kw_bucket", "real_group"]))
    a, b = sc.load(str(v2 / "messages.csv"))
    f, rep = sc.run(a, b)
    if f or "not measurable" not in rep:
        bad.append(f"v2-style file: flags {f}, report says not measurable: {'not measurable' in rep}")
    return bad


def t7(tmp):
    tr, va = make()
    va.loc[va["source"] == sc.POOL_SOURCE, "text"] += " <NAME>"
    write_messages(tmp, tr, va)
    out = Path(tmp) / "r" / "shortcuts.md"
    sanity = ROOT / "reports" / "sanity.md"
    before = sanity.read_bytes() if sanity.exists() else None
    p = subprocess.run([sys.executable, str(ROOT / "src/sanity_checks.py"), "--v3-shortcuts", "--shortcuts-data-dir", str(tmp), "--shortcuts-out", str(out)],
                       capture_output=True, text=True, cwd=ROOT, timeout=300)
    bad = []
    if p.returncode != 0:
        return [f"exit {p.returncode}: {(p.stdout + p.stderr)[-500:]}"]
    if "RED FLAG [POOL-origin cue] has <NAME>" not in p.stdout:
        bad.append(f"stdout has no RED FLAG line for the planted token: {p.stdout[-400:]}")
    if not out.exists() or "## Flags" not in out.read_text(encoding="utf-8"):
        bad.append("report not written")
    if (sanity.read_bytes() if sanity.exists() else None) != before:
        bad.append("reports/sanity.md changed")
    return bad


def t8(tmp):
    folder = os.environ.get("SHORTCUT_FIXTURE_BUILD")
    if not folder:
        print("      skipped (set SHORTCUT_FIXTURE_BUILD=<scratch build folder with messages.csv>)")
        return []
    tr, va = sc.load(str(Path(folder) / "messages.csv"))
    base, report = sc.run(tr, va, "fixture build")
    (tmp / "fixture_report.md").write_text(report, encoding="utf-8")
    keep = os.environ.get("SHORTCUT_FIXTURE_REPORT")
    if keep:
        Path(keep).write_text(report, encoding="utf-8")
    pool = va["source"] == sc.POOL_SOURCE
    va2 = va.copy()
    va2.loc[pool, "text"] = va2.loc[pool, "text"] + " <ACCOUNT>"
    planted, _ = sc.run(tr, va2, "fixture build + planted <ACCOUNT> in pool val rows")
    new = [f for f in planted if f not in base]
    print(f"      fixture: {len(va)} val rows, {int(pool.sum())} pool; flags on the build: {len(base)}; with the plant: {len(planted)}; new: {len(new)}")
    bad = []
    if not any("[POOL-origin cue] has <ACCOUNT>" in f for f in new):
        bad.append(f"the plant did not make a POOL-origin <ACCOUNT> flag: {new}")
    return bad


CHECKS = [("T1", "clean frame: no flag in any section", t1),
          ("T2", "planted label shortcut flags exactly that cue", t2),
          ("T3", "planted POOL-origin token flags as a pool cue; no pool -> not measurable", t3),
          ("T4", "length: planted gaps flag; with / without POOL differ", t4),
          ("T5", "synthetic family vs real collect rows: flag, no flag, off, too few", t5),
          ("T6", "loader never keeps test rows; v2-style file works", t6),
          ("T7", "CLI prints red flags, writes only its report, sanity.md untouched", t7),
          ("T8", "(opt-in SHORTCUT_FIXTURE_BUILD) fixture build: runs, plant shows up as new flags", t8)]


def run():
    out = []
    with tempfile.TemporaryDirectory() as d:
        for cid, title, fn in CHECKS:
            sub = Path(d) / cid
            sub.mkdir()
            try:
                bad = fn(sub)
            except BaseException as e:   # SystemExit included
                bad = [f"{type(e).__name__}: {str(e)[:500]}"]
            out.append((cid, title, bad))
    return out


def test_shortcut_checks():
    bad = [f"{cid}: {b}" for cid, _, bs in run() for b in bs]
    assert not bad, "\n".join(bad)


if __name__ == "__main__":
    res = run()
    for cid, title, bad in res:
        print(("PASS" if not bad else "FAIL"), cid, title)
        for b in bad:
            print("    ", b.encode("ascii", "backslashreplace").decode()[:600])
    print(f"\n{sum(not b for _, _, b in res)}/{len(res)} passed")
    sys.exit(any(b for _, _, b in res))
