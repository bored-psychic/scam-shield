import csv, hashlib, os, re, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(os.path.abspath(globals().get("__file__", "tests/test_real_intake.py"))).parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "src")]
PY = sys.executable
FIXTURE = HERE / "fixtures" / "real_fake.csv"

# python tests/test_real_intake.py   (from the project root). Real-message intake + once-only evaluation, on the FAKE fixture tests/fixtures/real_fake.csv
# (20 invented rows: fake numbers, fake UPI handle, fake name, example.invalid domains; never real responses). Nothing here touches data/real/.
#   R1  header mapping: an unexpected header, a missing required header and an ambiguous header STOP the run with the header list
#   R2  intake on the fixture: columns, drops with reasons, contributor columns gone, masked output has no phone / UPI / email / OTP / card pattern, URLs kept
#   R3  overlap: a near-duplicate of a TRAIN row is overlap=True, the same text in the val split is not; rows are never dropped for it
#   R4  names: review file written; edits (<NAME>, DROP) applied on rerun and never overwritten
#   R5  freeze: the SHA goes into CLAUDE.md's frozen-hashes section; a different hash is refused
#   R6  tripwire module: a path under data/real/, a text equal to a real test row, a text_hash equal to one: refused; a clean frame passes
#   R7  tripwire in finetune.py and calibrate_text_head.py: --data-dir / --run under data/real/ exits before anything is created; build_text.py calls it before writing
#   R8  eval_real.py refuses without --final
#   R9  eval_real.py --final on the fixture: one ledger line per run, a second run on the same file refused, --again records the reason
FAKE_ROWS_IN_TRAIN = "Your package is waiting. Track at https://fake-parcel-track.example.invalid/x9 and pay the customs charge now."


def tiny_messages(path):
    rows = [("t1", FAKE_ROWS_IN_TRAIN, "train"), ("t2", "Completely unrelated training sentence about a cat sitting on a warm mat today.", "train"),
            ("v1", "Dinner at 8, will you come? Let me know by 6.", "val")]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "text", "split"])
        w.writerows(rows)


def write_csv(path, headers, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def rows_of(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def intake(tmp, review=True):
    import intake_real as I
    tiny_messages(tmp / "messages.csv")
    return I.run(FIXTURE, tmp / "real_test_v1.csv", tmp / "review_names.csv", tmp / "report.md", False, tmp / "messages.csv")


def r1(tmp):
    import intake_real as I
    bad = []
    base = ["Timestamp", "Email address", "Message text", "Is this a scam or genuine?", "Language", "Category"]
    cases = {"unexpected header": (base + ["Favourite colour"], "Favourite colour"),
             "missing language": ([h for h in base if h != "Language"], "missing"),
             "ambiguous": (base + ["Scam category type text"], "more than one role")}
    for name, (hdr, want) in cases.items():
        try:
            I.map_headers(hdr)
            bad.append(f"{name}: did not stop")
        except I.Stop as e:
            if want not in str(e) or ("headers found" not in str(e) and name != "ambiguous"):
                bad.append(f"{name}: message {str(e)[:150]!r}")
    roles, dropped = I.map_headers(base)
    if set(roles) != {"text", "label", "language", "category"} or set(dropped) != {"Timestamp", "Email address"}:
        bad.append(f"expected mapping not produced: {roles}, {dropped}")
    return bad


def r2(tmp):
    bad = []
    sha, final = intake(tmp)
    out = rows_of(tmp / "real_test_v1.csv")
    if list(out[0]) != ["id", "text", "label", "language", "category", "overlap", "source_row_hash"]:
        bad.append(f"columns {list(out[0])}")
    rep = (tmp / "report.md").read_text()
    for reason in ("shorter than 10 characters: 1", "label not recognised: 1", "exact duplicate: 1"):
        if reason not in rep:
            bad.append(f"report lacks {reason!r}")
    blob = "\n".join(r["text"] for r in out)
    patterns = {"phone": r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)", "upi": r"[\w.-]+@(?:ybl|okaxis|oksbi|upi|paytm)\b", "email": r"[\w.+-]+@[\w-]+", "otp": r"\b(?:482913|556677)\b",
                "card": r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b", "long digits": r"\b\d{9,}\b"}
    for k, rx in patterns.items():
        if re.search(rx, blob):
            bad.append(f"masked output still has a {k} pattern")
    for who in ("Asha", "Ravi", "Meera", "fake.contrib", "2026-10-20"):
        if who in blob or who in rep:
            bad.append(f"contributor column value {who!r} reached the output or report")
    if "https://fakebank-kyc-check.example.invalid/login" not in blob:
        bad.append("URL was not kept")
    for tok in ("<PHONE>", "<UPI_ID>", "<EMAIL>", "<ACCOUNT>", "<OTP>"):
        if tok not in blob:
            bad.append(f"no {tok} in the output")
    if len(out) != 18 or any(r["source_row_hash"] != hashlib.md5(re.sub(r"\s+", " ", r["text"].lower()).encode()).hexdigest() for r in out):
        bad.append(f"{len(out)} rows or source_row_hash is not realguard.norm_key")
    if re.search(r"Dear customer|Congratulations|\bOTP is\b", rep):
        bad.append("message text in the report")
    return bad


def r3(tmp):
    out = {r["id"]: r for r in rows_of(tmp / "real_test_v1.csv")}
    bad = []
    if out["R0013"]["overlap"] != "True":
        bad.append("near-duplicate of a train row not flagged overlap=True")
    if out["R0016"]["overlap"] != "False":
        bad.append("a val-split twin must not count (train only)")
    if out["R0001"]["overlap"] != "False" or len(out) != 18:
        bad.append("overlap changed rows or flagged an unrelated row")
    return bad


def r4(tmp):
    import intake_real as I
    bad = []
    rv = rows_of(tmp / "review_names.csv")
    toks = {(r["id"], r["token"]) for r in rv}
    if ("R0020", "Kiran") not in toks or ("R0020", "Pretendname") not in toks:
        bad.append(f"fake name not flagged: {sorted(toks)[:6]}")
    if any(r["token"] in ("Reply", "Dinner", "Track", "Meeting", "Oct") for r in rv):
        bad.append("sentence-start verbs / month names flagged")
    for r in rv:
        if "http" in r["context"] and "hxxp" not in r["context"]:
            bad.append("URL not defanged in the review file")
        if r["id"] == "R0020" and r["token"] in ("Kiran", "Pretendname"):
            r["replace_with"] = "<NAME>"
        if r["id"] == "R0019":
            r["replace_with"] = "DROP"
    rv.append({"id": "R0019", "token": "Bank", "context": "x", "replace_with": "DROP"})
    I.write_review(tmp / "review_names.csv", rv)
    I.run(FIXTURE, tmp / "real_test_v1.csv", tmp / "review_names.csv", tmp / "report.md", False, tmp / "messages.csv")
    out = {r["id"]: r for r in rows_of(tmp / "real_test_v1.csv")}
    if "Kiran" in out["R0020"]["text"] or "Pretendname" in out["R0020"]["text"] or out["R0020"]["text"].count("<NAME>") != 2:
        bad.append(f"name edit not applied: {out['R0020']['text'][:60]!r}")
    if "R0019" in out:
        bad.append("DROP not applied")
    after = {(r["id"], r["token"]): r["replace_with"] for r in rows_of(tmp / "review_names.csv")}
    if after.get(("R0020", "Kiran")) != "<NAME>":
        bad.append("rerun overwrote the review file")
    return bad


def r5(tmp):
    import intake_real as I
    bad = []
    claude = tmp / "CLAUDE.md"
    claude.write_text("# CLAUDE.md\n\nbody\n", encoding="utf-8")
    saved = I.CLAUDE
    I.CLAUDE = claude
    try:
        I.freeze_hash("a" * 64, 18)
        txt = claude.read_text()
        if I.FREEZE_HEAD not in txt or "a" * 64 not in txt:
            bad.append("frozen-hashes section not written")
        I.freeze_hash("a" * 64, 18)
        if claude.read_text().count("a" * 64) != 1:
            bad.append("same hash written twice")
        try:
            I.freeze_hash("b" * 64, 18)
            bad.append("a different hash was accepted")
        except I.Stop:
            pass
    finally:
        I.CLAUDE = saved
    if "real_test_v1.csv" in (ROOT / "CLAUDE.md").read_text() and "a" * 64 in (ROOT / "CLAUDE.md").read_text():
        bad.append("a test hash leaked into the real CLAUDE.md")
    return bad


def r6(tmp):
    import pandas as pd
    import realguard as G
    bad = []
    real = tmp / "real_test_v1.csv"
    rows = rows_of(real)
    hashes = G.real_hashes(real)
    if len(hashes) != len(rows):
        bad.append("real_hashes does not read the file")
    for path in ("data/real/raw/x.csv", "data/real", str(ROOT / "data" / "real" / "real_test_v1.csv")):
        try:
            G.refuse_real_paths([path])
            bad.append(f"{path} not refused")
        except G.RealDataTripwire:
            pass
    G.refuse_real_paths(["data/final", "data/final/messages.csv"])
    for name, df in {"text": pd.DataFrame({"text": ["something else", rows[0]["text"]]}), "text_hash": pd.DataFrame({"text_hash": [rows[1]["source_row_hash"], "zz"]})}.items():
        try:
            G.guard_inputs([], [(name, df)], real_path=real)
            bad.append(f"a frame with a real {name} was accepted")
        except G.RealDataTripwire:
            pass
    G.guard_inputs([], [("clean", pd.DataFrame({"text": ["an ordinary training message", "another"], "text_hash": ["x1", "x2"]}))], real_path=real)
    return bad


def r7(tmp):
    bad = []
    n_before = len(list((ROOT / "models" / "finetune").glob("*"))) if (ROOT / "models" / "finetune").exists() else 0
    for cmd, want in (([PY, "src/finetune.py", "--data-dir", "data/real/raw", "--smoke"], "data/real"),
                      ([PY, "src/calibrate_text_head.py", "--run", "data/real/raw"], "data/real")):
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        if p.returncode == 0 or want not in (p.stderr + p.stdout) or "refused" not in (p.stderr + p.stdout):
            bad.append(f"{cmd[1]}: exit {p.returncode}, {(p.stderr + p.stdout)[-160:]!r}")
    n_after = len(list((ROOT / "models" / "finetune").glob("*"))) if (ROOT / "models" / "finetune").exists() else 0
    if n_after != n_before:
        bad.append("finetune.py created a run directory before the tripwire")
    src = (ROOT / "src" / "build_text.py").read_text()
    if "realguard.guard_inputs" not in src or src.index("realguard.guard_inputs") > src.index('df.to_csv("data/final/messages.csv"'):
        bad.append("build_text.py does not call the tripwire before writing messages.csv")
    for f in ("finetune.py", "calibrate_text_head.py"):
        if "guard_inputs(" not in (ROOT / "src" / f).read_text():
            bad.append(f"{f} has no guard_inputs call")
    return bad


def r8(tmp):
    p = subprocess.run([PY, "src/eval_real.py", "--data", str(tmp / "real_test_v1.csv"), "--ledger", str(tmp / "ledger.md")], cwd=ROOT, capture_output=True, text=True)
    bad = []
    if p.returncode == 0 or "--final" not in (p.stderr + p.stdout):
        bad.append(f"ran without --final: exit {p.returncode}")
    if (tmp / "ledger.md").exists():
        bad.append("a ledger was written without --final")
    return bad


def r9(tmp):
    bad = []
    cmd = [PY, "src/eval_real.py", "--final", "--data", str(tmp / "real_test_v1.csv"), "--ledger", str(tmp / "ledger.md"), "--report", str(tmp / "eval.md")]
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if p.returncode != 0:
        return [f"--final run failed: {(p.stderr + p.stdout)[-400:]}"]
    lines = [l for l in (tmp / "ledger.md").read_text().splitlines() if l.startswith("| 20")]
    sha = hashlib.sha256((tmp / "real_test_v1.csv").read_bytes()).hexdigest()
    if len(lines) != 1 or sha not in lines[0] or "MuRIL" not in lines[0] or "baseline" not in lines[0]:
        bad.append(f"ledger lines after run 1: {lines}")
    rep = (tmp / "eval.md").read_text()
    if "without overlap rows" not in rep or "lang=en" not in rep or "AUROC" not in rep or "Dear customer" in rep:
        bad.append("report lacks the overlap split / languages, or holds message text")
    p2 = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if p2.returncode == 0 or "already in" not in (p2.stderr + p2.stdout):
        bad.append("a second run on the same file was not refused")
    if len([l for l in (tmp / "ledger.md").read_text().splitlines() if l.startswith("| 20")]) != 1:
        bad.append("the refused run wrote a ledger line")
    p3 = subprocess.run(cmd + ["--again", "fixture test"], cwd=ROOT, capture_output=True, text=True)
    lines = [l for l in (tmp / "ledger.md").read_text().splitlines() if l.startswith("| 20")]
    if p3.returncode != 0 or len(lines) != 2 or "fixture test" not in lines[1]:
        bad.append(f"--again: exit {p3.returncode}, {len(lines)} ledger lines")
    return bad


CHECKS = [("R1", "header mapping stops on unexpected / missing / ambiguous", r1), ("R2", "intake on the fake fixture: drops, masks, no PII pattern", r2),
          ("R3", "overlap: train near-duplicate flagged, val twin not, nothing dropped", r3), ("R4", "names: review file, edits applied on rerun, not overwritten", r4),
          ("R5", "freeze writes the hash into CLAUDE.md, refuses a different one", r5), ("R6", "realguard refuses real paths, real texts and real hashes", r6),
          ("R7", "finetune / calibrate / build_text tripwires", r7), ("R8", "eval_real refuses without --final", r8),
          ("R9", "eval_real --final: one ledger line per run, once-only, --again recorded", r9)]


def run():
    out = []
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        for cid, title, fn in CHECKS:
            try:
                bad = fn(tmp)
            except BaseException as e:   # SystemExit included: a script that stops is a failed check, not a crashed suite
                bad = [f"{type(e).__name__}: {str(e)[:300]}"]
            out.append((cid, title, bad))
    return out


def test_real_intake():
    bad = [f"{cid}: {b}" for cid, _, bs in run() for b in bs]
    assert not bad, "\n".join(bad)


if __name__ == "__main__":
    res = run()
    for cid, title, bad in res:
        print(("PASS" if not bad else "FAIL"), cid, title)
        for b in bad:
            print("    ", b)
    print(f"\n{sum(not b for _, _, b in res)}/{len(res)} passed")
    sys.exit(any(b for _, _, b in res))
