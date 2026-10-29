import ast, csv, hashlib, os, re, shutil, subprocess, sys, tempfile
from collections import Counter
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
#   R10 probe tripwire: data/probe/investment_v1.csv is PROBE-ONLY with a source per row; its path, its texts and their keys are refused,
#       and finetune.py exits on --data-dir data/probe before anything is created
# SMS XML, WhatsApp txt, template groups (fixtures sms_fake.xml, sms_fake_emoji.xml, whatsapp_fake_*.txt, real_fake_headers.csv: invented numbers and names):
#   R11 Form headers: the real header set (text, label, language, collected_by, script, date_received, source, notes) maps; not_scam / unsure labels
#   R12 SMS: sender_kind rules, received only, the address and contact name never reach a row, surrogate-pair emoji parse, phone_N labels from file names
#   R13 WhatsApp: Android and iOS lines, continuation lines, system / media / deleted / short lines dropped, names and timestamps gone, mentions masked
#   R14 groups and labelling: label_me.csv (columns, biggest first, two defanged examples, no model output), rerun applies a label to the whole group,
#       at most 3 per group with group_size, blank and skip groups left out and counted, labels kept, orphans kept, a bad label stops, ids stable
#   R15 privacy: no phone number, address, contact / sender name, chat file name or timestamp in any output; report has no message text; data/real/ is ignored
#   R16 the intake reads under data/real/ (the tripwire is for training scripts) but refuses a PROBE-ONLY folder
#   R17 names: greeting names masked everywhere (aap / customer are not), mask_names.txt add and veto, ok / <NAME> / DROP, --freeze guards, frozen file kept
# Label buckets, the terminal labeller and the grouped freeze split (a generated three-phone world: invented numbers, names and senders, Hindi and Kannada rows;
# the bucket sizes are patched to 3 / 2 so a handful of groups fill all four buckets):
#   R18 label_priority: 1 = largest, 2 = mobile_number sender, 3 = seeded random, 4 = rest; seed and "scam-enriched" in the report; a new phone file keeps every
#       group id, bucket and label (a new smallest key, a message like two groups), buckets the new groups on arrival; a second rerun changes nothing
#   R19 src/label_real.py on a pipe: s / g / k / b / q, progress "bucket N: x/y", the guide line, Hindi and Kannada printed intact, the freeze command at the
#       end; killed mid-session and restarted it loses no label; a failed save leaves the old file; a sheet rewritten under it keeps the session's labels;
#       no model import, a score-like column refused
#   R20 --freeze: blank bucket 1-3 refused, bucket 4 left out with --allow-unlabelled; TEST / POOL share no group and no near-duplicate (brute force), the
#       two groups a bridge message links sit on one side, <= 3 rows per group with group_size; realguard refuses TEST and lets POOL through; second freeze refused
#   R21 after the freeze: a new phone file goes to the pool, its message of a TEST group is dropped and counted, the test file never changes; with the group
#       registry deleted the TEST messages still stay out of the pool; near_test_flags catches a twin of a TEST message
#   R23 --trim-bucket2: labelled bucket-2 groups stay, a seeded sample of the unlabelled ones fills bucket 2 to N, the rest go to bucket 4; only the
#       label_priority column changes; same result from the same files; an intake rerun keeps it; a new mobile group follows the sample's cut-off; a labeller
#       open across the trim keeps its labels; N below the labelled count keeps them all; a second, different trim and a trim after the freeze are refused
#   R22 privacy over every output of R18-R21 and R23 (preview, test, pool, label sheet, review, reports, state and manifest JSON, labeller output): no number, contact
#       name, family name (also inside a link: /track/Name/, ?ref=Name123) or address; the JSON files hold ids, hashes and numbers only
# Separator-tolerant known-phone mask and re-masked examples (2026-10-29):
#   R24 a known sender number is masked as <PHONE> when a letter / space / hyphen / dot / slash splits its digits (with or without +91 / 91 / 0 and the sheet's
#       defanged links); a coupon with the same shape that is NOT a known number is unchanged; masking twice changes nothing; with no phones the masks are the old
#       ones; end to end, a coupon with a split known number no longer stops the run, and an example kept from an earlier run (orphan row, labelled) is masked with
#       the name and number learned since, its group_id, label and the registry untouched
PREVIEW = "labelled_preview.csv"   # before a freeze the labelled rows go here; real_test_v1.csv is written only by --freeze
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


def row_with(rows, prefix):
    hit = [r for r in rows if r["text"].startswith(prefix)]
    assert len(hit) == 1, f"{len(hit)} rows start with {prefix!r}"
    return hit[0]


def intake(tmp, review=True):
    import intake_real as I
    tiny_messages(tmp / "messages.csv")
    return I.run(FIXTURE, tmp / "real_test_v1.csv", tmp / "review_names.csv", tmp / "report.md", False, tmp / "messages.csv", label_file=tmp / "label_me.csv",
                 names_file=tmp / "no_names.txt")


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
    out = rows_of(tmp / PREVIEW)
    import intake_real as I
    if list(out[0]) != I.OUT_COLS:
        bad.append(f"columns {list(out[0])}")
    rep = (tmp / "report.md").read_text()
    for reason in ("shorter than 10 characters: 1", "label not recognised: 1", "exact duplicate: 1", "Read 21. **Kept 18**"):
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
    rows = rows_of(tmp / PREVIEW)
    out = {"R0013": row_with(rows, "Your package is waiting"), "R0016": row_with(rows, "Dinner at 8"), "R0001": row_with(rows, "Dear customer, FakeBank KYC expires today")}
    bad = []
    if out["R0013"]["overlap"] != "True":
        bad.append("near-duplicate of a train row not flagged overlap=True")
    if out["R0016"]["overlap"] != "False":
        bad.append("a val-split twin must not count (train only)")
    if out["R0001"]["overlap"] != "False" or len(rows) != 18:
        bad.append("overlap changed rows or flagged an unrelated row")
    return bad


def r4(tmp):
    import intake_real as I
    bad = []
    rv = rows_of(tmp / "review_names.csv")
    out0 = rows_of(tmp / PREVIEW)
    kiran_id = row_with(out0, "Hi Kiran Pretendname")["id"]
    drop_id = row_with(out0, "Your bank statement for September")["id"]
    toks = {(r["id"], r["token"]) for r in rv}
    if (kiran_id, "Kiran") not in toks or (kiran_id, "Pretendname") not in toks:
        bad.append(f"fake name not flagged: {sorted(toks)[:6]}")
    if any(r["token"] in ("Reply", "Dinner", "Track", "Meeting", "Oct") for r in rv):
        bad.append("sentence-start verbs / month names flagged")
    for r in rv:
        if "http" in r["context"] and "hxxp" not in r["context"]:
            bad.append("URL not defanged in the review file")
        if r["id"] == kiran_id and r["token"] in ("Kiran", "Pretendname"):
            r["replace_with"] = "<NAME>"
        if r["id"] == drop_id:
            r["replace_with"] = "DROP"
    rv.append({"id": drop_id, "token": "Bank", "context": "x", "replace_with": "DROP"})
    I.write_review(tmp / "review_names.csv", rv)
    I.run(FIXTURE, tmp / "real_test_v1.csv", tmp / "review_names.csv", tmp / "report.md", False, tmp / "messages.csv", label_file=tmp / "label_me.csv", names_file=tmp / "no_names.txt")
    out = {r["id"]: r for r in rows_of(tmp / PREVIEW)}
    if kiran_id not in out or "Kiran" in out[kiran_id]["text"] or "Pretendname" in out[kiran_id]["text"] or out[kiran_id]["text"].count("<NAME>") != 2:
        bad.append(f"name edit not applied: {out.get(kiran_id, {}).get('text', '')[:60]!r}")
    if drop_id in out:
        bad.append("DROP not applied")
    after = {(r["id"], r["token"]): r["replace_with"] for r in rows_of(tmp / "review_names.csv")}
    if after.get((kiran_id, "Kiran")) != "<NAME>":
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
    real = tmp / PREVIEW   # the labelled rows of R2's run, standing in for a frozen test file
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
    if "realguard.guard_inputs" not in src or src.index("realguard.guard_inputs") > src.index("df.to_csv(OUT_MESSAGES"):
        bad.append("build_text.py does not call the tripwire before writing messages.csv")
    for f in ("finetune.py", "calibrate_text_head.py"):
        if "guard_inputs(" not in (ROOT / "src" / f).read_text():
            bad.append(f"{f} has no guard_inputs call")
    return bad


def r8(tmp):
    p = subprocess.run([PY, "src/eval_real.py", "--data", str(tmp / PREVIEW), "--ledger", str(tmp / "ledger.md")], cwd=ROOT, capture_output=True, text=True)
    bad = []
    if p.returncode == 0 or "--final" not in (p.stderr + p.stdout):
        bad.append(f"ran without --final: exit {p.returncode}")
    if (tmp / "ledger.md").exists():
        bad.append("a ledger was written without --final")
    return bad


def r9(tmp):
    bad = []
    cmd = [PY, "src/eval_real.py", "--final", "--data", str(tmp / PREVIEW), "--ledger", str(tmp / "ledger.md"), "--report", str(tmp / "eval.md")]
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if p.returncode != 0:
        return [f"--final run failed: {(p.stderr + p.stdout)[-400:]}"]
    lines = [l for l in (tmp / "ledger.md").read_text().splitlines() if l.startswith("| 20")]
    sha = hashlib.sha256((tmp / PREVIEW).read_bytes()).hexdigest()
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


def r10(tmp):
    import pandas as pd
    import realguard as G
    bad = []
    probe = ROOT / "data" / "probe" / "investment_v1.csv"
    if not probe.exists():
        return [f"{probe} missing"]
    rows = rows_of(probe)
    if any(r["use"] != "PROBE-ONLY" for r in rows) or any(not r["source_url"].startswith(("https://", "http://")) for r in rows):
        bad.append("a probe row is not marked PROBE-ONLY or has no source URL")
    for path in ("data/probe/investment_v1.csv", "data/probe", str(probe), "data/probes/investment_probe.csv"):
        try:
            G.refuse_real_paths([path])
            bad.append(f"{path} not refused")
        except G.RealDataTripwire:
            pass
    nofile = tmp / "no_real_test.csv"   # only the probe check can fire
    if len(G.probe_hashes()) != len({G.norm_key(r["text"]) for r in rows}):
        bad.append("probe_hashes does not read data/probe/")
    for name, df in {"text": pd.DataFrame({"text": ["an ordinary training message", rows[3]["text"].upper()]}),
                     "text_hash": pd.DataFrame({"text_hash": ["zz", G.norm_key(rows[-1]["text"])]})}.items():
        try:
            G.guard_inputs([], [(name, df)], real_path=nofile)
            bad.append(f"a frame with a probe {name} was accepted")
        except G.RealDataTripwire as e:
            if "PROBE-ONLY" not in str(e):
                bad.append(f"probe refusal does not say PROBE-ONLY: {e}")
    G.guard_inputs([], [("clean", pd.DataFrame({"text": ["an ordinary training message"], "text_hash": ["x1"]}))], real_path=nofile)
    n_before = len(list((ROOT / "models" / "finetune").glob("*"))) if (ROOT / "models" / "finetune").exists() else 0
    p = subprocess.run([PY, "src/finetune.py", "--data-dir", "data/probe", "--smoke"], cwd=ROOT, capture_output=True, text=True)
    if p.returncode == 0 or "PROBE-ONLY" not in (p.stderr + p.stdout):
        bad.append(f"finetune.py on data/probe: exit {p.returncode}, {(p.stderr + p.stdout)[-160:]!r}")
    if (len(list((ROOT / "models" / "finetune").glob("*"))) if (ROOT / "models" / "finetune").exists() else 0) != n_before:
        bad.append("finetune.py created a run directory before the probe tripwire")
    return bad


# ---------------------------------------------------------------------------------------------------------------- SMS / WhatsApp / groups
FIX = HERE / "fixtures"
PHONES = [f"98765000{n:02d}" for n in range(1, 11)]
NAMES = ["Zoya Testperson", "Pritam Faker", "Sent Recipient", "Short Sender", "Mms Contact", "Asha Testperson", "Ravi Sample", "Meera Dummy", "WhatsApp Chat with"]


def build_raw(tmp, sms_name="sms-20261001000000.xml"):
    """A raw folder like the real one: folder names with spaces, a file named for its phone, an iOS _chat.txt, a Form export, and files that must be ignored."""
    raw = tmp / "raw"
    for d in ("Sms backup", "WhatsApp exports", "Form"):
        (raw / d).mkdir(parents=True)
    shutil.copyfile(FIX / "sms_fake.xml", raw / "Sms backup" / sms_name)
    shutil.copyfile(FIX / "sms_fake_emoji.xml", raw / "Sms backup" / "phone_2.xml")
    shutil.copyfile(FIX / "whatsapp_fake_android.txt", raw / "WhatsApp exports" / "WhatsApp Chat with Pritam Faker.txt")
    shutil.copyfile(FIX / "whatsapp_fake_ios.txt", raw / "WhatsApp exports" / "_chat.txt")
    shutil.copyfile(FIX / "real_fake_headers.csv", raw / "Form" / "form export.csv")
    (raw / ".DS_Store").write_bytes(b"\0")
    (raw / "Sms backup" / "._phone_2.xml").write_bytes(b"\0")
    (raw / "notes.pdf").write_bytes(b"%PDF-1.4 not an intake file")
    return raw


def e2e(tmp, raw, tag="a", label_file=None, **kw):
    import intake_real as I
    d = tmp / tag
    d.mkdir(exist_ok=True)
    tiny_messages(d / "messages.csv")
    paths = dict(out=d / "real_test_v1.csv", preview=d / PREVIEW, review=d / "review_names.csv", report=d / "report.md", label_file=label_file or d / "label_me.csv",
                 names_file=kw.pop("names_file", d / "no_names.txt"))
    res = I.run(raw, paths["out"], paths["review"], paths["report"], kw.pop("freeze", False), d / "messages.csv", label_file=paths["label_file"], names_file=paths["names_file"], **kw)
    return d, paths, res


def find_group(rows, needle):
    hit = [r for r in rows if needle in r["example_1"] or needle in r["example_2"]]
    assert len(hit) == 1, f"{len(hit)} label rows contain {needle!r}"
    return hit[0]


def r11(tmp):
    import intake_real as I
    bad = []
    hdr = ["text", "label", "language", "collected_by", "script", "date_received", "source", "notes"]
    roles, dropped = I.map_headers(hdr)
    if roles != {"text": "text", "label": "label", "language": "language", "source": "source"} or set(dropped) != {"collected_by", "script", "date_received", "notes"}:
        bad.append(f"real header set mapped to {roles}, dropped {dropped}")
    roles2, _ = I.map_headers(["Message", "Label", "Language", "Collected_By", "Script", "Date_Received", "Source", "Notes"])
    if roles2.get("text") != "Message":
        bad.append("'message' is not accepted as the text header")
    try:
        I.map_headers(hdr + ["favourite colour"])
        bad.append("an unexpected header next to the real set did not stop")
    except I.Stop:
        pass
    want = {"scam": 1, "Scam": 1, "not_scam": 0, "Not Scam": 0, "genuine": 0, "unsure": "unsure", "Unsure": "unsure", "": None, "maybe": None}
    for v, w in want.items():
        if I.label_of(v) != w:
            bad.append(f"label_of({v!r}) = {I.label_of(v)!r}, want {w!r}")
    d = tmp / "form"
    d.mkdir(exist_ok=True)
    tiny_messages(d / "messages.csv")
    sha, final = I.run(FIX / "real_fake_headers.csv", d / "o.csv", d / "r.csv", d / "rep.md", False, d / "messages.csv", label_file=d / "l.csv", names_file=d / "n.txt")
    out = rows_of(d / PREVIEW)
    rep = (d / "rep.md").read_text()
    if len(out) != 3 or {r["source"] for r in out} != {"form_whatsapp", "form_sms", "form_other"} or {r["label"] for r in out} != {"0", "1"}:
        bad.append(f"{len(out)} rows, sources {sorted({r['source'] for r in out})}")
    if "label unsure (excluded): 1" not in rep:
        bad.append("unsure was not counted in the report")
    if any(n in (d / f).read_text() for n in ("Asha", "Ravi", "Meera", "Priya") for f in (PREVIEW, "rep.md")):
        bad.append("a collected_by value or the free-text source reached the output")
    return bad


def r12(tmp):
    import intake_real as I
    bad = []
    kinds = {"AX-HDFCBK": "dlt_header", "AX-HDFCBK-S": "dlt_header", "JD-AIRTLP-P": "dlt_header", "HDFCBK": "dlt_header", "56161": "short_code", "919876500001": "mobile_number",
             "+919876500001": "mobile_number", "9876500001": "mobile_number", "+44 20 7946 0958": "mobile_number", "18001234567": "other", "1409123456": "other", "": "other",
             "user@example.invalid": "other"}
    for a, k in kinds.items():
        if I.sender_kind(a) != k:
            bad.append(f"sender_kind({a!r}) = {I.sender_kind(a)}, want {k}")
    raw = I.sanitize_xml(b"<a x='&#55357;&#56834;&#1;&#x1F600;&amp;'/>")
    import xml.etree.ElementTree as ET
    if ET.fromstring(raw).get("x") != "\U0001F602\U0001F600&":
        bad.append(f"sanitize_xml gave {ET.fromstring(raw).get('x')!r}")
    paths = I.assign_labels([Path("a/sms-1.xml"), Path("b/phone_2.xml"), Path("c/zz.xml")], "phone", I.PHONE_LABEL)
    if sorted(paths.values()) != ["phone_1", "phone_2", "phone_3"] or paths[Path("b/phone_2.xml")] != "phone_2":
        bad.append(f"assign_labels: {paths}")
    from collections import Counter
    drops, read, sens = Counter(), Counter(), I.Sensitive()
    recs = I.read_sms(FIX / "sms_fake.xml", "phone_1", drops, read, sens)
    recs2 = I.read_sms(FIX / "sms_fake_emoji.xml", "phone_2", drops, read, sens)
    if read["phone_1"] != 20 or len(recs) != 16 or len(recs2) != 3:
        bad.append(f"read {read['phone_1']} elements, kept {len(recs)} + {len(recs2)}")
    want_drops = {"not a received message (type != 1)": 1, "empty body": 1, "shorter than 10 characters": 1, "MMS element (only <sms> is read)": 1}
    if {k[1]: v for k, v in drops.items()} != want_drops:
        bad.append(f"drops {dict(drops)}")
    if not any("\U0001F602" in r["text"] for r in recs2) or any("\x01" in r["text"] for r in recs2):
        bad.append("emoji pair not joined or control character kept")
    if Counter(r["sender_kind"] for r in recs) != Counter({"dlt_header": 10, "mobile_number": 4, "short_code": 1, "other": 1}):
        bad.append(f"sender kinds {Counter(r['sender_kind'] for r in recs)}")
    if any(set(r) - {"text", "label", "language", "category", "source", "source_type", "sender_kind"} for r in recs):
        bad.append("a row carries a field beyond text, label, language, category, source, source_type, sender_kind")
    blob = "\n".join(str(sorted(r.items())) for r in recs + recs2)
    for who in PHONES[:1] + ["Sent Recipient", "Short Sender", "Mms Contact", "readable_date", "12 Oct 2026"]:
        if who in blob:
            bad.append(f"{who!r} reached a row")
    if "Sent Recipient" in "".join(sens.names) or "Mms Contact" in "".join(sens.names) or len(sens.phones) != 6:
        bad.append(f"sensitive set: {len(sens.phones)} numbers, names {sorted(sens.names)}")   # six received-from-a-person numbers; a sent message's or an MMS contact is never read
    if {r["language"] for r in recs} != {"en", "hi"}:
        bad.append("Devanagari text not labelled hi")
    return bad


def r13(tmp):
    import intake_real as I
    from collections import Counter
    bad = []
    a = I.parse_whatsapp((FIX / "whatsapp_fake_android.txt").read_text(encoding="utf-8"))
    i = I.parse_whatsapp((FIX / "whatsapp_fake_ios.txt").read_text(encoding="utf-8"))
    if len(a) != 9 or len(i) != 4:
        bad.append(f"parsed {len(a)} Android and {len(i)} iOS entries, want 9 and 4")
    if not a[0][0] is None or a[1][0] is not None or a[2][0] != "Zoya Testperson":
        bad.append("system lines are not sender-less / sender not parsed")
    multi = [b for s_, b in a if s_ and s_.startswith("+91")]
    if len(multi) != 1 or multi[0].count("\n") != 2:
        bad.append("continuation lines not joined to the message")
    drops, read, sens = Counter(), Counter(), I.Sensitive()
    recs = I.read_whatsapp(FIX / "whatsapp_fake_android.txt", "wa_1", drops, read, sens) + I.read_whatsapp(FIX / "whatsapp_fake_ios.txt", "wa_2", drops, read, sens)
    reasons = Counter()
    for (_, why), n in drops.items():
        reasons[why] += n
    if reasons != Counter({"system, media or deleted line": 6, "20 characters or fewer": 1}) or len(recs) != 6:
        bad.append(f"drops {dict(reasons)}, kept {len(recs)}")
    texts = "\n".join(r["text"] for r in recs)
    for who in ("12/10", "10:15", "10:22", "Zoya Testperson:", "Pritam Faker:", "created group", "end-to-end", "omitted", "deleted"):
        if who in texts:
            bad.append(f"{who!r} survived in a message")
    if "@⁨" in texts or "<NAME>" not in texts or "<PHONE>" not in texts:
        bad.append("iOS mention not turned into <NAME>")
    if {"Zoya Testperson", "Pritam Faker"} - sens.names or len(sens.phones) != 1:
        bad.append(f"sender names / number not collected: {sorted(sens.names)}, {len(sens.phones)} numbers")
    if any(r["source_type"] != "whatsapp" or r["sender_kind"] != "n/a" or r["label"] is not None for r in recs):
        bad.append("WhatsApp rows must be unlabelled, sender_kind n/a")
    try:
        (tmp / "x.txt").write_text("just some notes, no chat lines here at all\n")
        I.read_whatsapp(tmp / "x.txt", "wa_9", drops, read, sens)
        bad.append("a .txt without WhatsApp lines did not stop")
    except I.Stop:
        pass
    return bad


def r14(tmp):
    import intake_real as I
    bad = []
    raw = build_raw(tmp)
    d, paths, (sha, final) = e2e(tmp, raw, "g1")
    sheet = rows_of(paths["label_file"])
    if list(sheet[0]) != I.LABEL_COLS or any(w in c.lower() for c in sheet[0] for w in ("score", "prob", "pred", "model")):
        bad.append(f"label_me columns {list(sheet[0])}")
    imports = {n.names[0].name.split(".")[0] for n in ast.walk(ast.parse((ROOT / "src" / "intake_real.py").read_text())) if isinstance(n, ast.Import)} | \
              {n.module.split(".")[0] for n in ast.walk(ast.parse((ROOT / "src" / "intake_real.py").read_text())) if isinstance(n, ast.ImportFrom) and n.module}
    if imports & {"torch", "joblib", "sklearn", "shield", "transformers", "eval_real", "app"}:
        bad.append(f"intake_real imports a model module: {imports}")
    sizes = [int(r["size"]) for r in sheet]
    if sizes != sorted(sizes, reverse=True) or sizes[:3] != [4, 4, 4]:
        bad.append(f"label_me not sorted by size, biggest first: {sizes[:6]}")
    bank, otp, kyc = find_group(sheet, "debited from"), find_group(sheet, "is your OTP"), find_group(sheet, "KYC expires today")
    if "XX4455" in bank["example_1"] or "<ACCOUNT>" not in bank["example_1"] or not bank["example_2"] or not (0 < float(bank["example_similarity"]) < 1):
        bad.append(f"bank group example / similarity: {bank['example_1'][:70]!r} {bank['example_similarity']}")
    if otp["example_2"] or "<OTP>" not in otp["example_1"] or "482913" in otp["example_1"]:
        bad.append("OTP digits not collapsed into one text / not masked")
    if not (kyc["sources"].count(";") == 3 and "mobile_number:2" in kyc["sender_kind_mix"]):
        bad.append(f"the KYC template should span SMS, WhatsApp and the Form: {kyc['sources']} | {kyc['sender_kind_mix']}")
    for r in sheet:
        for c in ("example_1", "example_2"):
            if re.search(r"https?://|www\.", r[c], re.I) or re.search(r"[A-Za-z0-9]\.(?:invalid|com|in|xyz)\b", r[c]):
                bad.append(f"a clickable link in the label sheet: {r[c][:60]!r}")
                break
    if any(r["label"] for r in sheet):
        bad.append("label column is not empty on the first run")
    first = rows_of(paths["preview"])
    if {r["source_type"] for r in first} != {"form"}:
        bad.append("rows from unlabelled groups reached the test set")
    rep = (paths["report"]).read_text()
    for src in ("phone_1", "phone_2", "wa_1", "wa_2", "form_sms"):
        if f"| {src} |" not in rep:
            bad.append(f"report has no row for source {src}")
    if "Read 40." not in rep or "Groups: **19**" not in rep or "group not labelled yet" not in rep:
        bad.append("report counts differ from the fixture run (40 read, 19 groups)")
    # fill the sheet and rerun
    lab = {"debited from": "genuine", "is your OTP": "genuine", "KYC expires today": "scam", "EMI of Rs": "", "call me on": "skip", "stock market tips": "scam", "trading group": "scam"}
    for r in sheet:
        r["label"] = next((v for k, v in lab.items() if k in r["example_1"]), "genuine")
    write_csv(paths["label_file"], I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet])
    d2, paths2, (sha2, final2) = e2e(tmp, raw, "g1", label_file=paths["label_file"])
    out = rows_of(paths2["preview"])
    per = {}
    for r in out:
        per.setdefault(r["group_id"], []).append(r)
    if max(len(v) for v in per.values()) > 3:
        bad.append("more than 3 rows from one group")
    gb, go, gk = per[bank["group_id"]], per[otp["group_id"]], per[kyc["group_id"]]
    if len(gb) != 3 or {r["label"] for r in gb} != {"0"} or {r["group_size"] for r in gb} != {"4"}:
        bad.append(f"bank group: {len(gb)} rows, labels {[r['label'] for r in gb]}, sizes {[r['group_size'] for r in gb]}")
    if len(go) != 1 or go[0]["group_size"] != "4":
        bad.append(f"OTP group should keep one row of size 4 (exact duplicates once): {len(go)}")
    if len(gk) != 3 or {r["label"] for r in gk} != {"1"} or "form" not in {r["source_type"] for r in gk}:
        bad.append(f"KYC group: {len(gk)} rows, labels {[r['label'] for r in gk]}, types {[r['source_type'] for r in gk]} (the Form's own row must stay)")
    sz = [int(r["group_size"]) for r in out]
    if sz != sorted(sz, reverse=True):
        bad.append("test set not ordered by group_size")
    rep2 = paths2["report"].read_text()
    if not re.search(r"group marked skip: 1 ", rep2) or not re.search(r"group not labelled yet: 1 ", rep2) or "still blank: **1**" not in rep2:
        bad.append("skip / blank groups not counted in the report")
    if any("call me on" in r["text"] or "EMI of Rs" in r["text"] for r in out):
        bad.append("a skipped or blank group reached the test set")
    again = {r["group_id"]: r["label"] for r in rows_of(paths["label_file"])}
    if again[bank["group_id"]] != "genuine" or again[kyc["group_id"]] != "scam":
        bad.append("a rerun lost the labels in label_me.csv")
    if int(sha2 is not None) + int(sha is not None) != 2 or sha == sha2:
        bad.append("the test set did not change after labelling")
    # a label for a group that no longer exists is kept; a wrong word stops; ids do not depend on the order of the files
    sheet2 = rows_of(paths["label_file"])
    sheet2.append({**{c: "" for c in I.LABEL_COLS}, "group_id": "Gdeadbeef", "label": "scam", "size": "9", "example_1": "old"})
    write_csv(paths["label_file"], I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet2])
    e2e(tmp, raw, "g1", label_file=paths["label_file"])
    kept = rows_of(paths["label_file"])
    if kept[-1]["group_id"] != "Gdeadbeef" or kept[-1]["label"] != "scam":
        bad.append("a labelled row whose group vanished was not kept")
    if "match no group: 1" not in paths2["report"].read_text() and "match no group: 1" not in (d2 / "report.md").read_text():
        bad.append("orphan label not reported")
    sheet2[0]["label"] = "maybe"
    write_csv(tmp / "badlabel.csv", I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet2])
    try:
        e2e(tmp, raw, "g2", label_file=tmp / "badlabel.csv")
        bad.append("a label other than scam / genuine / skip did not stop")
    except I.Stop as e:
        if "label must be" not in str(e):
            bad.append(f"bad label message: {e}")
    (tmp / "other").mkdir()
    raw2 = build_raw(tmp / "other")
    for f in list((raw2 / "Sms backup").glob("sms-*.xml")):
        f.rename(raw2 / "Sms backup" / "zzz-last.xml")
    shutil.copyfile(paths["label_file"], tmp / "labels_copy.csv")
    d3, paths3, _ = e2e(tmp, raw2, "g3", label_file=tmp / "labels_copy.csv")
    ids = lambda p: sorted((r["id"], r["group_id"], r["label"]) for r in rows_of(p))
    if ids(paths3["preview"]) != ids(paths2["preview"]):
        bad.append("row ids / group ids / labels changed when the same files were named differently")
    return bad


def r15(tmp):
    import intake_real as I
    bad = []
    (tmp / "pv").mkdir()
    raw = build_raw(tmp / "pv")
    d, paths, _ = e2e(tmp, raw, "p1")
    sheet = rows_of(paths["label_file"])
    for r in sheet:
        r["label"] = "genuine"
    write_csv(paths["label_file"], I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet])
    d, paths, _ = e2e(tmp, raw, "p1", label_file=paths["label_file"])
    out_rows = rows_of(paths["preview"])
    if len(out_rows) < 15:
        bad.append(f"only {len(out_rows)} rows in the test set after labelling every group")
    files = {"real_test_v1.csv": "\n".join(r["text"] for r in out_rows), "label_me.csv": paths["label_file"].read_text(encoding="utf-8"),
             "review_names.csv": paths["review"].read_text(encoding="utf-8"), "real_intake_v1.md": paths["report"].read_text(encoding="utf-8")}
    for fname, blob in files.items():
        blob = re.sub(r"`[0-9a-f]{64}`", "", blob)   # the report's SHA-256 is hex: its digit runs are not numbers
        for ph in PHONES:
            if ph in blob or ph[:5] + " " + ph[5:] in blob or ph in re.sub(r"[\s-]", "", blob):
                bad.append(f"{fname}: phone number {ph} survived")
        for who in NAMES + ["fake.contrib", "Zoya", "Pritam Faker"]:
            if who in blob:
                bad.append(f"{fname}: {who!r} survived")
        stamps = (r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", r"2026-10-2\d", r"\b\d{1,2}:\d{2}\b") if fname != "real_intake_v1.md" else ()   # the report is dated
        for rx in stamps + (r"(?<!\d)[6-9]\d{9}(?!\d)", r"\d{9,}", r"\w@[A-Za-z]"):
            if re.search(rx, blob):
                bad.append(f"{fname}: pattern {rx} found")
    if re.search(r"Dear customer|KYC|OTP is|debited|Pay in the|stock market", files["real_intake_v1.md"]):
        bad.append("message text in the report")
    if any(w in files["real_intake_v1.md"] for w in ("sms-2026", "phone_2.xml", "_chat", "WhatsApp Chat", "form export", "notes.pdf", ".xml")):
        bad.append("a file name in the report")
    wa = [r for r in out_rows if r["source"] == "wa_1"]
    if not any("<PHONE>" in r["text"] for r in out_rows) or any("wa.me/9" in r["text"] for r in out_rows):
        bad.append("the number inside a wa.me link was kept")
    if not (wa and any("<NAME>" in r["text"] for r in out_rows)):
        bad.append("a name known from the input was not masked in a message body")
    for f in ("data/real/label_me.csv", "data/real/raw/x.xml", "data/real/real_test_v1.csv", "data/real/review_names.csv", "data/real/mask_names.txt",
              "data/real/label_me_state.json", "data/real/freeze_manifest.json", "data/real/labelled_preview.csv", "data/real/auto_names.txt",
              "data/collected/phones/pool.csv"):
        if subprocess.run(["git", "check-ignore", "-q", f], cwd=ROOT).returncode != 0:
            bad.append(f"{f} is not git-ignored")
    tracked = subprocess.run(["git", "ls-files", "data/real"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    if tracked:
        bad.append(f"files under data/real/ are tracked: {tracked[:80]}")
    # the final check inside the run: a leaked value stops it before any file is written
    sens = I.Sensitive()
    sens.add_phone("919876500001")
    sens.add_name("Zoya Testperson")
    try:
        I.scan_outputs(sens, {"x.csv": ["clean text <PHONE>", "call 98765 00001 now"]})
        bad.append("scan_outputs missed a number written with a space")
    except I.Stop as e:
        if "9876500001" in str(e):
            bad.append("the stop message repeats the number")
    try:
        I.scan_outputs(sens, {"x.csv": ["hello ZOYA TESTPERSON"]})
        bad.append("scan_outputs missed a name in capitals")
    except I.Stop:
        pass
    return bad


def r16(tmp):
    import intake_real as I
    import realguard as G
    bad = []
    fake_real = tmp / "fakeroot" / "data" / "real"
    (tmp / "fr").mkdir()
    shutil.copytree(build_raw(tmp / "fr"), fake_real / "raw")
    saved = (G.REAL_DIR, G.REAL_TEST_PATH)
    try:
        G.REAL_DIR, G.REAL_TEST_PATH = fake_real, fake_real / "real_test_v1.csv"
        try:
            G.refuse_real_paths([fake_real / "raw"])
            bad.append("setup: the stand-in data/real/ is not refused by the tripwire")
        except G.RealDataTripwire:
            pass
        d = tmp / "t16"
        d.mkdir()
        tiny_messages(d / "messages.csv")
        I.run(fake_real / "raw", d / "o.csv", d / "r.csv", d / "rep.md", False, d / "messages.csv", label_file=d / "l.csv", names_file=d / "n.txt")
        if not (d / "label_me.csv").exists() and not (d / "l.csv").exists():
            bad.append("the intake did not run on a folder under data/real/")
    except BaseException as e:
        bad.append(f"the intake refused or failed on a folder under data/real/: {type(e).__name__}: {str(e)[:160]}")
    finally:
        G.REAL_DIR, G.REAL_TEST_PATH = saved
    probe = tmp / "probe"
    probe.mkdir()
    shutil.copyfile(FIX / "real_fake_headers.csv", probe / "x.csv")
    saved_dirs = G.PROBE_DIRS
    try:
        G.PROBE_DIRS = (probe,)
        I.run(probe, tmp / "po.csv", tmp / "pr.csv", tmp / "prep.md", False, tmp / "messages.csv", label_file=tmp / "pl.csv", names_file=tmp / "pn.txt")
        bad.append("a PROBE-ONLY folder was accepted as an intake input")
    except I.Stop:
        pass
    finally:
        G.PROBE_DIRS = saved_dirs
    return bad


def sms_xml(path, rows):
    from xml.sax.saxutils import quoteattr
    els = [f'  <sms protocol="0" address={quoteattr(a)} date="1700000000000" type="1" subject="null" body={quoteattr(b)} contact_name="(Unknown)" />' for a, b in rows]
    path.write_text("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n" + f'<smses count="{len(els)}">\n' + "\n".join(els) + "\n</smses>\n", encoding="utf-8")


def r17(tmp):
    import intake_real as I
    bad = []
    raw = tmp / "nm"
    raw.mkdir()
    rows = [("AX-FAKESH-S", f"Hey zorbaxo, your order {code} from {shop} has been placed and will arrive tomorrow.") for code, shop in
            (("A1", "FakeMart"), ("B2", "SampleCafe"), ("C3", "DemoStore"), ("D4", "TestShop"))]
    rows += [("AX-FAKEIN-S", "Hey customer, your policy renewal is due soon, pay in the app today to avoid lapse."), ("AX-FAKEIN-S", "Hi customer, thanks for choosing us, your claim is registered and open."),
             ("AX-FAKEIN-S", "Dear customer, your premium receipt is attached, keep it safe for your records."),
             ("AX-FAKEHI-S", "Namaste, aap ka bill is mahine ka hai, aap app par bhugtan kar sakte hain jaldi."), ("AX-FAKEHI-S", "Namaste, aap ke khate me paise aa gaye hain, aap check kar lijiye abhi."),
             ("AX-FAKEHI-S", "Namaste, aap ka order nikal chuka hai, aap track kar sakte hain app me aaj."), ("919876500011", "Meet Quentin Fakename at the gate tomorrow morning at nine please.")]
    sms_xml(raw / "names.xml", rows)
    names = tmp / "mask_names.txt"
    d, paths, _ = e2e(tmp, raw, "n1")
    sheet_txt = paths["label_file"].read_text(encoding="utf-8")
    if "zorbaxo" in sheet_txt or "<NAME>" not in sheet_txt:
        bad.append("a name that follows a greeting in many messages was not masked everywhere")
    if sheet_txt.count("customer") < 2:
        bad.append("'customer' was masked as a name")
    if "Namaste, <NAME>" in sheet_txt or "aap" not in sheet_txt:
        bad.append("the Hinglish word 'aap' was masked as a name")
    if "Quentin Fakename" not in sheet_txt:
        bad.append("setup: the unlisted name should still be visible before it is listed")
    names.write_text("# own name and teammates\nQuentin Fakename\n-zorbaxo\n", encoding="utf-8")
    d, paths, _ = e2e(tmp, raw, "n2", names_file=names)
    sheet_txt = paths["label_file"].read_text(encoding="utf-8")
    if "Quentin" in sheet_txt or "<NAME>" not in sheet_txt:
        bad.append("a name in mask_names.txt was not masked")
    if "zorbaxo" not in sheet_txt:
        bad.append("a '-name' veto in mask_names.txt did not keep the word")
    # review states, --freeze guards, the frozen file
    sheet = rows_of(paths["label_file"])
    for r in sheet:
        r["label"] = "genuine"
    lf = tmp / "n_labels.csv"
    write_csv(lf, I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet])
    claude = tmp / "CLAUDE.md"
    claude.write_text("# CLAUDE.md\n\n## Frozen hashes (real-message test set)\n\nNot frozen yet: nothing collected.\n", encoding="utf-8")
    saved = I.CLAUDE
    I.CLAUDE = claude
    try:
        kw = dict(names_file=names, label_file=lf)
        d, paths, _ = e2e(tmp, raw, "n3", **kw)
        review = rows_of(paths["review"])
        if not any(r["token"] == "zorbaxo" for r in review):
            bad.append("a greeting name that was vetoed from auto-masking is not offered for review")
        try:
            e2e(tmp, raw, "n3", freeze=True, **kw)
            bad.append("--freeze went through with blank name candidates")
        except I.Stop as e:
            if "still blank" not in str(e):
                bad.append(f"freeze refusal text: {str(e)[:100]}")
        for r in review:
            r["replace_with"] = "<NAME>" if r["token"] == "zorbaxo" else "ok"
        I.write_review(paths["review"], review)
        d, paths, (sha, final) = e2e(tmp, raw, "n3", **kw)
        out_text = "\n".join(r["text"] for r in rows_of(paths["preview"]))
        if "zorbaxo" in out_text or "FakeMart" not in out_text:
            bad.append("<NAME> / ok edits not applied (<NAME> must mask the token, ok must keep the word)")
        if "Candidates still blank (not looked at; blank is kept as written, `ok` marks a reviewed non-name): 0" not in paths["report"].read_text():
            bad.append("open candidates not counted as 0 after review")
        write_csv(tmp / "unl.csv", I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet[:-1]] + [[sheet[-1][c] if c != "label" else "" for c in I.LABEL_COLS]])
        try:
            e2e(tmp, raw, "n3", freeze=True, names_file=names, label_file=tmp / "unl.csv")
            bad.append("--freeze went through with an unlabelled group")
        except I.Stop as e:
            if "no label" not in str(e):
                bad.append(f"freeze refusal text: {str(e)[:100]}")
        if paths["out"].exists():
            bad.append("real_test_v1.csv was written before the freeze")
        d, paths, (sha, final) = e2e(tmp, raw, "n3", freeze=True, **kw)
        if sha not in claude.read_text() or "Not frozen yet" in claude.read_text() or I.frozen_hash() != sha:
            bad.append("freeze did not write the hash / left the 'not frozen' sentence")
        if paths["preview"].exists():
            bad.append("the preview file was left next to the frozen test set")
        write_csv(tmp / "chg.csv", I.LABEL_COLS, [[r[c] if c != "label" else "scam" for c in I.LABEL_COLS] for r in sheet])
        before = paths["out"].read_bytes()
        e2e(tmp, raw, "n3", names_file=names, label_file=tmp / "chg.csv")   # after the freeze a rerun goes to the pool, never to the test file
        if paths["out"].read_bytes() != before:
            bad.append("the frozen file changed")
        if "Mode: **post**" not in paths["report"].read_text():
            bad.append("a rerun after the freeze is not in post mode")
    finally:
        I.CLAUDE = saved
    return bad


# ---------------------------------------------------------------------------------------------------------------- buckets, labeller, freeze split
X_LOAN = "Get a pre-approved personal loan of Rs 2 lakh at a low interest rate with instant disbursal to your bank account today, no documents needed."
CONTACTS = {"+91 98765 00021": "Kavya Fakename", "9876500022": "Rohan Notreal", "09876500023": "Dadi Testname", "+919876500024": "Suresh Fakeperson",
            "9876500025": "Unknownish Caller", "9876500026": "Bunty Pretendson"}
FAMILY = "Testfamilyname"   # stands in for a name in data/real/mask_names.txt
NEEDLES = {"T1": "debited from", "T2": "is your OTP", "T3": "FakeCart order", "T4": "बिजली बिल", "T5": "ನೀರಿನ ಬಿಲ್", "A": "Reply STOP", "B": "nearest branch",
           "M1": "won a lottery", "M2": "reached home safely", "M3": "KYC", "N1": "FakeFlix", "N2": "match tickets", "N3": "gas cylinder", "P1": "property tax"}
HI = "आपका बिजली बिल ₹{n} है, कृपया अंतिम तिथि से पहले भुगतान करें। धन्यवाद, नकली बिजली विभाग"
KN = "ನಿಮ್ಮ ನೀರಿನ ಬಿಲ್ ₹{n} ಆಗಿದೆ, ದಯವಿಟ್ಟು ಕೊನೆಯ ದಿನಾಂಕದ ಮೊದಲು ಪಾವತಿಸಿ. ಧನ್ಯವಾದಗಳು"


def t1(amt, acct, d, ref, bal, pre=""):
    return f"{pre}Rs {amt}.00 debited from A/c XX{acct} on {d}-10-26 by UPI ref {ref}. Avl bal Rs {bal}. Not you? Report to Fake Bank customer care at once."


def sms_xml_full(path, rows):
    """rows: (address, body, contact_name, type); type 1 = received, 2 = sent."""
    from xml.sax.saxutils import quoteattr
    els = [f'  <sms protocol="0" address={quoteattr(a)} date="1700000000000" type="{t}" subject="null" body={quoteattr(b)} contact_name={quoteattr(c)} />'
           for a, b, c, t in rows]
    path.write_text("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n" + f'<smses count="{len(els)}">\n' + "\n".join(els) + "\n</smses>\n", encoding="utf-8")


def phone_world(raw):
    """phone_1.xml + phone_2.xml: 5 shared / repeated templates (T1-T5, Hindi T4, Kannada T5), 5 one-off messages from mobile numbers (A, B: two halves
    of a loan offer a later message links; M1-M3), 6 one-off sender-id messages."""
    raw.mkdir(parents=True, exist_ok=True)
    dlt = lambda b: ("AX-FKBANK-S", b, "(Unknown)", "1")
    p1 = [dlt(t1(a, c, d, r, b)) for a, c, d, r, b in ((1500, 4455, 12, 6123, "20,331.50"), (250, 4455, 13, 6188, "20,081.50"), (99, 4455, 14, 6201, "19,982.50"),
                                                       (3000, 4455, 15, 6250, "16,982.50"), (45, 4455, 16, 6299, "16,937.50"))]
    p1 += [("VM-FKAPPS-S", f"{otp} is your OTP for login to FakeApp. Do not share it with anyone. Valid for 10 minutes.", "(Unknown)", "1") for otp in (482913, 110022, 993311, 450067)]
    p1 += [("JD-FKCART-S", f"Your FakeCart order with {n} items has been shipped and will be delivered by Friday. Track it in the FakeCart app.", "(Unknown)", "1") for n in (2, 3, 5)]
    p1 += [("BZ-FKPOWR-S", HI.format(n=n), "(Unknown)", "1") for n in (640, 712)] + [("BZ-FKWATR-S", KN.format(n=n), "(Unknown)", "1") for n in (220, 245)]
    p1 += [("+91 98765 00021", X_LOAN + " Reply STOP to unsubscribe from these offers now.", CONTACTS["+91 98765 00021"], "1"),
           ("9876500022", "Congratulations! You won a lottery of Rs 25 lakh. Pay the processing fee today to claim your prize from the claims desk.", CONTACTS["9876500022"], "1"),
           ("09876500023", f"{FAMILY} ji, Dadi Testname here, I reached home safely, will call you after dinner tonight, take care of yourself and eat well.", CONTACTS["09876500023"], "1"),
           ("09876500023", "This one I sent myself and it must never be read into any row at all.", CONTACTS["09876500023"], "2")]
    p1 += [("AD-FKLIBR-S", "Your library book is due on Monday, renew it online or return it at the front desk."), ("AD-FKYOGA-S", "Join our weekend yoga class at the community hall, first session free for members."),
           ("AD-FKWATR-S", "Water supply will be interrupted tomorrow from 10 am to 2 pm for pipeline maintenance work."), ("AD-FKAIRL-S", "Flight FK 101 is delayed by 40 minutes, new departure time will be shared at the gate."),
           ("AD-FKPOST-S", f"Your parcel is ready for pickup, track it at https://fake-post.example.invalid/track/{FAMILY}/9?ref={FAMILY}123 before Friday.")]
    p1 = [r if len(r) == 4 else (r[0], r[1], "(Unknown)", "1") for r in p1]
    p2 = [dlt(t1(a, c, d, r, b)) for a, c, d, r, b in ((700, 4455, 17, 6301, "16,237.50"), (1200, 4455, 18, 6355, "15,037.50"))]
    p2 += [("VM-FKAPPS-S", "771100 is your OTP for login to FakeApp. Do not share it with anyone. Valid for 10 minutes.", "(Unknown)", "1"),
           ("+919876500024", X_LOAN + " Visit the nearest branch with your PAN card soon.", CONTACTS["+919876500024"], "1"),
           ("9876500025", "Dear customer your KYC has expired, update it now at https://fake-kyc-update.example.invalid/verify or your account will be blocked today.",
            CONTACTS["9876500025"], "1"),
           ("AD-FKSCHL-S", "Parent teacher meeting is on Saturday at 10 am in the school auditorium, please attend.", "(Unknown)", "1"),
           ("AD-FKMALL-S", "Weekend sale at the city mall, flat discounts on clothing and footwear for all members.", "(Unknown)", "1")]
    sms_xml_full(raw / "phone_1.xml", p1)
    sms_xml_full(raw / "phone_2.xml", p2)
    return raw


def phone_3(raw):
    """A third phone that arrives before the freeze: a T1 message whose key sorts before every T1 key so far, the loan offer's common part (like A and
    B, which are not like each other), a new 4-message template (bucket 1 on arrival), a new mobile one-off (bucket 2), a new sender-id one-off."""
    rows = [("AX-FKBANK-S", t1(80, 4455, 19, 6400, "14,957.50", pre="Alert: "), "(Unknown)", "1"), ("VM-FKLOAN-S", X_LOAN, "(Unknown)", "1"),
            ("VM-FKAPPS-S", "120034 is your OTP for login to FakeApp. Do not share it with anyone. Valid for 10 minutes.", "(Unknown)", "1"),
            ("9876500026", "Bro, the match tickets are booked for Sunday, meet me at the stadium gate at four sharp.", CONTACTS["9876500026"], "1"),
            ("AD-FKGASB-S", "Your gas cylinder booking is confirmed and will be delivered within 2 working days.", "(Unknown)", "1")]
    rows += [("AD-FKFLIX-S", f"Your FakeFlix subscription renews on the 5th, amount Rs {n} will be charged to your saved card.", "(Unknown)", "1") for n in (149, 199, 499, 649)]
    sms_xml_full(raw / "phone_3.xml", rows)


def run_world(I, raw, d, **kw):
    d.mkdir(parents=True, exist_ok=True)
    tiny_messages(d / "messages.csv")
    names = d / "mask_names.txt"
    names.write_text(f"# family\n{FAMILY}\n", encoding="utf-8")
    return I.run(raw, d / "real_test_v1.csv", d / "review_names.csv", d / "report.md", kw.pop("freeze", False), d / "messages.csv", label_file=d / "label_me.csv",
                 names_file=names, **kw)


class small_buckets:
    """Bucket sizes 3 / 2 instead of 150 / 150, so a handful of groups fill all four buckets."""
    def __enter__(self):
        import intake_real as I
        self.saved = (I.PRIORITY_N1, I.PRIORITY_N3)
        I.PRIORITY_N1, I.PRIORITY_N3 = 3, 2
    def __exit__(self, *exc):
        import intake_real as I
        I.PRIORITY_N1, I.PRIORITY_N3 = self.saved


def by_needle(sheet):
    return {k: find_group(sheet, v) for k, v in NEEDLES.items() if any(v in r["example_1"] or v in r["example_2"] for r in sheet)}


def r18(tmp):
    import intake_real as I
    bad = []
    with small_buckets():
        raw = phone_world(tmp / "w18" / "raw")
        d = tmp / "w18" / "out"
        run_world(I, raw, d)
        sheet = rows_of(d / "label_me.csv")
        g = by_needle(sheet)
        pr = {k: r["label_priority"] for k, r in g.items()}
        if [pr[k] for k in ("T1", "T2", "T3")] != ["1"] * 3:
            bad.append(f"the 3 largest groups are not bucket 1: {pr}")
        if {pr[k] for k in ("A", "B", "M1", "M2", "M3")} != {"2"}:
            bad.append(f"groups with a mobile_number sender are not bucket 2: {pr}")
        rest = [r["label_priority"] for r in sheet if r["group_id"] not in {g[k]["group_id"] for k in ("T1", "T2", "T3", "A", "B", "M1", "M2", "M3")}]
        if sorted(rest).count("3") != 2 or set(rest) != {"3", "4"}:
            bad.append(f"bucket 3 should be 2 of the rest and the others bucket 4: {sorted(rest)}")
        keyed = [(int(r["label_priority"]), -int(r["size"]), r["group_id"]) for r in sheet]
        if keyed != sorted(keyed):
            bad.append("label_me.csv is not ordered by bucket, then size")
        rep = (d / "report.md").read_text()
        if f"Fixed seed {I.PRIORITY_SEED}" not in rep or "Bucket 2 is scam-enriched by design" not in rep:
            bad.append("the report does not state the bucket seed / that bucket 2 is scam-enriched by design")
        if "| 1 | 3 |" not in rep or "| 2 | 5 |" not in rep or "| 3 | 2 |" not in rep:
            bad.append("bucket sizes not in the report")
        # label a few, then a third phone arrives
        for r in sheet:
            r["label"] = {g["T1"]["group_id"]: "genuine", g["M1"]["group_id"]: "scam", g["A"]["group_id"]: "scam"}.get(r["group_id"], "")
        write_csv(d / "label_me.csv", I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet])
        before = {r["group_id"]: (r["label_priority"], r["label"]) for r in sheet}
        phone_3(raw)
        run_world(I, raw, d)
        sheet2 = rows_of(d / "label_me.csv")
        after = {r["group_id"]: (r["label_priority"], r["label"]) for r in sheet2}
        moved = [gid for gid, v in before.items() if after.get(gid) != v]
        if moved:
            bad.append(f"a new phone file moved / renamed / relabelled existing groups: {moved}")
        g2 = by_needle(sheet2)
        if g2["T1"]["group_id"] != g["T1"]["group_id"] or g2["T1"]["size"] != "8":
            bad.append(f"T1 got a new id or did not grow ({g2['T1']['group_id']} vs {g['T1']['group_id']}, size {g2['T1']['size']})")
        if g2["A"]["group_id"] == g2["B"]["group_id"]:
            bad.append("the bridge message merged two existing groups")
        rep2 = (d / "report.md").read_text()
        if "kept apart 1" not in rep2:
            bad.append("the report does not count the pair of groups the bridge message links")
        if (g2["N1"]["label_priority"], g2["N2"]["label_priority"]) != ("1", "2"):
            bad.append(f"new groups not bucketed on arrival: N1 {g2['N1']['label_priority']}, N2 {g2['N2']['label_priority']}")
        st = I.load_state(d / "label_me_state.json")
        want3 = "3" if I.hkey(g2["N3"]["group_id"]) <= st["b3_max_key"] else "4"
        if g2["N3"]["label_priority"] != want3:
            bad.append(f"new sender-id group bucket {g2['N3']['label_priority']}, the first run's cut-off says {want3}")
        snap = (d / "label_me.csv").read_bytes(), (d / "label_me_state.json").read_bytes()
        run_world(I, raw, d)
        if ((d / "label_me.csv").read_bytes(), (d / "label_me_state.json").read_bytes()) != snap:
            bad.append("a rerun with nothing new changed the label sheet or the state")
    return bad


def labeller(sheet, keys, *extra, timeout=60):
    return subprocess.run([PY, "src/label_real.py", "--file", str(sheet), *extra], cwd=ROOT, input=keys.encode(), capture_output=True, timeout=timeout)


def r19(tmp):
    import intake_real as I
    import label_real as L
    bad = []
    with small_buckets():
        raw = phone_world(tmp / "w19" / "raw")
        d = tmp / "w19" / "out"
        run_world(I, raw, d)
    fresh = d / "label_me.csv"
    order = [r["group_id"] for r in L.order(rows_of(fresh), 3)]
    # piped keys: s g k b g q
    sh = d / "a.csv"
    shutil.copyfile(fresh, sh)
    p = labeller(sh, "s g k b g q")
    outp = p.stdout.decode("utf-8")
    lab = {r["group_id"]: r["label"] for r in rows_of(sh)}
    if p.returncode != 0 or [lab[gid] for gid in order[:4]] != ["scam", "genuine", "genuine", ""] or sum(bool(v) for v in lab.values()) != 3:
        bad.append(f"piped keys s g k b g q gave {[lab[gid] for gid in order[:4]]} (rc {p.returncode}, {p.stderr.decode()[-200:]})")
    if L.GUIDE not in outp or "bucket 1: 0/3" not in outp or "bucket 1: 2/3" not in outp or "back (it was skip)" not in outp:
        bad.append("guide line / progress / back message missing from the screen")
    if "score" in outp.lower():
        bad.append("the labeller printed something called a score")
    # everything in buckets 1-4, then the next steps with the freeze command; Hindi and Kannada come out intact
    sh2 = d / "b.csv"
    shutil.copyfile(fresh, sh2)
    p = labeller(sh2, "g" * len(rows_of(fresh)), "--max-bucket", "4")
    outp = p.stdout.decode("utf-8")
    hi = next(r["example_1"] for r in rows_of(fresh) if NEEDLES["T4"] in r["example_1"])
    kn = next(r["example_1"] for r in rows_of(fresh) if NEEDLES["T5"] in r["example_1"])
    if hi not in outp or kn not in outp:
        bad.append("a Hindi or Kannada example did not come out byte for byte")
    if L.FREEZE_CMD not in outp or any(not r["label"] for r in rows_of(sh2)):
        bad.append("labelling every group did not end with the freeze command")
    if L.show_text("a\u200db\u200cc\x1b[31md\u202ee") != "a\u200db\u200cc[31mde":
        bad.append("show_text strips ZWJ / ZWNJ or keeps ESC / bidi controls")
    # killed mid-session, restarted: no label lost
    sh3 = d / "c.csv"
    shutil.copyfile(fresh, sh3)
    proc = subprocess.Popen([PY, "src/label_real.py", "--file", str(sh3)], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(b"sg")
    proc.stdin.flush()
    import time
    t0 = time.time()
    while time.time() - t0 < 30 and sum(bool(r["label"]) for r in rows_of(sh3)) < 2:
        time.sleep(0.1)
    proc.kill()
    proc.wait()
    got = [r["label"] for r in sorted(rows_of(sh3), key=lambda r: order.index(r["group_id"]) if r["group_id"] in order else 99)]
    if got[:2] != ["scam", "genuine"] or sum(bool(x) for x in got) != 2:
        bad.append(f"after a kill: {got[:4]}")
    if list(d.glob(".c.csv.*.tmp")):
        bad.append("a temp file was left after the kill")
    p = labeller(sh3, "k q")
    lab = {r["group_id"]: r["label"] for r in rows_of(sh3)}
    if [lab[gid] for gid in order[:3]] != ["scam", "genuine", "skip"] or "bucket 1: 2/3" not in p.stdout.decode():
        bad.append(f"the restart did not continue where the kill stopped: {[lab[gid] for gid in order[:3]]}")
    # a save that fails half-way leaves the old file; a sheet rewritten under the labeller keeps the session's labels
    snap = sh3.read_bytes()
    fields, rows = L.load(sh3)
    rows[3]["label"] = "scam"
    saved_fsync = L.os.fsync
    try:
        L.os.fsync = lambda fd: (_ for _ in ()).throw(OSError("disk full (simulated)"))
        L.save(sh3, fields, rows)
        bad.append("a failing save did not raise")
    except OSError:
        pass
    finally:
        L.os.fsync = saved_fsync
    if sh3.read_bytes() != snap or list(d.glob(".c.csv.*.tmp")):
        bad.append("a failed save changed the sheet or left a temp file")
    sheet = L.Sheet(sh3)
    sheet.set(order[3], "scam")
    fields, rows = L.load(sh3)
    for r in rows:
        if r["group_id"] == order[3]:
            r["label"] = ""   # the intake read the sheet before that key and wrote it back after
    rows.insert(0, {**rows[0], "group_id": "Gnewgroup", "label": "", "label_priority": "1", "size": "99"})
    import time as _t
    _t.sleep(0.01)
    L.save(sh3, fields, rows)
    sheet.set(order[4], "genuine")
    lab = {r["group_id"]: r["label"] for r in rows_of(sh3)}
    if lab.get(order[3]) != "scam" or lab.get(order[4]) != "genuine" or "Gnewgroup" not in lab:
        bad.append(f"a sheet rewritten under the labeller lost a label or a new row: {lab.get(order[3])}, {lab.get(order[4])}, {'Gnewgroup' in lab}")
    # no model output: no model import, no score-like column; a sheet with one is refused
    src = (ROOT / "src" / "label_real.py").read_text()
    imports = {n.names[0].name.split(".")[0] for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Import)} | \
              {n.module.split(".")[0] for n in ast.walk(ast.parse(src)) if isinstance(n, ast.ImportFrom) and n.module}
    if imports & {"torch", "joblib", "sklearn", "shield", "transformers", "eval_real", "app", "intake_real", "numpy", "pandas"}:
        bad.append(f"label_real imports {imports}")
    if any(w in c.lower() for c in rows_of(fresh)[0] for w in L.BANNED_COLUMNS):
        bad.append("label_me.csv has a score-like column")
    scored = d / "scored.csv"
    write_csv(scored, I.LABEL_COLS + ["model_score"], [[r[c] for c in I.LABEL_COLS] + ["0.9"] for r in rows_of(fresh)])
    if labeller(scored, "q").returncode == 0:
        bad.append("the labeller accepted a sheet with a model_score column")
    return bad


def jac_max(a_texts, b_texts):
    """Largest exact Jaccard between any text of a and any of b, over neardup's two views of model_text and of the digit-collapsed key (brute force)."""
    import intake_real as I
    from neardup import VIEWS, shingle_sets
    best = 0.0
    for prep in (I.model_text, I.group_key):
        for fn in VIEWS.values():
            A = shingle_sets([fn(prep(t)) for t in a_texts])
            B = shingle_sets([fn(prep(t)) for t in b_texts])
            for x in A:
                for y in B:
                    best = max(best, len(x & y) / len(x | y))
    return best


def freeze_world(tmp, tag):
    """phone_1-2, then phone_3; buckets 1-3 labelled, one bucket-4 group labelled, the others blank, one group skip; names reviewed; CLAUDE.md pointed
    at a copy. -> (I, raw, d, claude path, saved CLAUDE, groups by needle)."""
    import intake_real as I
    raw = phone_world(tmp / tag / "raw")
    d = tmp / tag / "out"
    run_world(I, raw, d)   # phones 1-2 first, so A and B are two groups before the message like both arrives
    phone_3(raw)
    run_world(I, raw, d)
    sheet = rows_of(d / "label_me.csv")
    g = by_needle(sheet)
    scam = {g[k]["group_id"] for k in ("A", "B", "M1", "M3")}
    four = [r for r in sheet if r["label_priority"] == "4"]
    for r in sheet:
        r["label"] = "scam" if r["group_id"] in scam else "genuine" if r["label_priority"] != "4" else ""
    four[0]["label"] = "genuine"
    g["M2"]["label"] = "skip"
    next(r for r in sheet if r["group_id"] == g["M2"]["group_id"])["label"] = "skip"
    write_csv(d / "label_me.csv", I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet])
    run_world(I, raw, d)
    review = rows_of(d / "review_names.csv")
    for r in review:
        r["replace_with"] = "ok"
    I.write_review(d / "review_names.csv", review)
    claude = tmp / tag / "CLAUDE.md"
    claude.write_text("# CLAUDE.md\n\n## Frozen hashes (real-message test set)\n\nNot frozen yet: nothing collected.\n", encoding="utf-8")
    saved = I.CLAUDE
    I.CLAUDE = claude
    return I, raw, d, claude, saved, g


def r20(tmp):
    import realguard as G
    bad = []
    with small_buckets():
        I, raw, d, claude, saved, g = freeze_world(tmp, "w20")
        try:
            if (d / "real_test_v1.csv").exists() or not (d / PREVIEW).exists():
                bad.append("before the freeze there must be a preview and no real_test_v1.csv")
            try:
                run_world(I, raw, d, freeze=True)
                bad.append("--freeze without --allow-unlabelled went through with bucket 4 blank")
            except I.Stop as e:
                if "no label" not in str(e):
                    bad.append(f"refusal text: {str(e)[:100]}")
            sheet = rows_of(d / "label_me.csv")
            keep = next(r for r in sheet if r["label_priority"] == "3")
            lab3 = keep["label"]
            keep["label"] = ""
            write_csv(d / "label_me.csv", I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet])
            try:
                run_world(I, raw, d, freeze=True, allow_unlabelled=True)
                bad.append("--allow-unlabelled let a blank bucket-3 group through")
            except I.Stop as e:
                if "buckets 1-3" not in str(e):
                    bad.append(f"refusal text: {str(e)[:100]}")
            if (d / "real_test_v1.csv").exists() or (d / I.MANIFEST_NAME).exists():
                bad.append("a refused freeze wrote the test file or the manifest")
            keep["label"] = lab3
            write_csv(d / "label_me.csv", I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet])
            sha, final = run_world(I, raw, d, freeze=True, allow_unlabelled=True)
            test, pool = rows_of(d / "real_test_v1.csv"), rows_of(d / "pool" / "pool.csv")
            man = __import__("json").loads((d / I.MANIFEST_NAME).read_text())
            tg, pg = {r["group_id"] for r in test}, {r["group_id"] for r in pool}
            if not test or not pool or tg & pg or tg != set(man["test_group_ids"]) or pg != set(man["pool_group_ids"]):
                bad.append(f"TEST / POOL groups: {len(tg)} / {len(pg)}, shared {len(tg & pg)}")
            labelled = {r["group_id"] for r in sheet if r["label"] in ("scam", "genuine")}
            if tg | pg != labelled:
                bad.append(f"split groups != labelled groups ({len(tg | pg)} vs {len(labelled)}); skip / blank groups must be in neither half")
            if g["M2"]["group_id"] in tg | pg:
                bad.append("a skip group was split")
            jm = jac_max([r["text"] for r in test], [r["text"] for r in pool])
            if jm >= 0.7:
                bad.append(f"a near-duplicate pair crosses the split (Jaccard {jm:.2f})")
            if (g["A"]["group_id"] in tg) != (g["B"]["group_id"] in tg):
                bad.append("the two groups the bridge message links sit on different sides")
            per = Counter(r["group_id"] for r in test)
            if max(per.values()) > 3 or any(not r["group_size"] for r in test) or {r["source"] for r in pool} - {"phone_1", "phone_2", "phone_3"}:
                bad.append("more than 3 rows per group / no group_size / a pool source that is not phone_N")
            if sha not in claude.read_text() or "pool.csv" not in claude.read_text() or (d / PREVIEW).exists():
                bad.append("the freeze did not write the hash and pool line into CLAUDE.md, or left the preview")
            if hashlib.sha256((d / "real_test_v1.csv").read_bytes()).hexdigest() != sha or man["split_seed"] != I.SPLIT_SEED:
                bad.append("manifest / file hash / seed mismatch")
            rep = (d / "report.md").read_text()
            if "## Freeze split (TEST vs POOL)" not in rep or f"Fixed seed {I.SPLIT_SEED}" not in rep:
                bad.append("the report has no freeze-split section with its seed")
            # realguard: TEST refused (path and rows), POOL allowed
            import pandas as pd
            saved_g = (G.REAL_DIR, G.REAL_TEST_PATH)
            try:
                G.REAL_DIR, G.REAL_TEST_PATH = d, d / "real_test_v1.csv"
                for what, call in (("TEST path", lambda: G.guard_inputs(paths=[d / "real_test_v1.csv"])),
                                   ("TEST rows", lambda: G.guard_inputs(frames=[("t", pd.DataFrame(test))], real_path=d / "real_test_v1.csv"))):
                    try:
                        call()
                        bad.append(f"realguard let the {what} through")
                    except G.RealDataTripwire:
                        pass
                G.REAL_DIR = d / "real_only"   # the pool sits in data/collected/phones/, outside data/real/
                G.guard_inputs(paths=[d / "pool" / "pool.csv"], frames=[("p", pd.DataFrame(pool))], real_path=d / "real_test_v1.csv")
            except G.RealDataTripwire as e:
                bad.append(f"realguard refused the POOL: {e}")
            finally:
                G.REAL_DIR, G.REAL_TEST_PATH = saved_g
            if I.POOL_DIR.relative_to(ROOT).parts[:2] != ("data", "collected"):
                bad.append("the real pool folder is not under data/collected/")
            try:
                run_world(I, raw, d, freeze=True, allow_unlabelled=True)
                bad.append("a second --freeze went through")
            except I.Stop as e:
                if "second --freeze is refused" not in str(e):
                    bad.append(f"second-freeze text: {str(e)[:100]}")
        finally:
            I.CLAUDE = saved
    return bad


def r21(tmp):
    import json
    bad = []
    with small_buckets():
        I, raw, d, claude, saved, g = freeze_world(tmp, "w21")
        try:
            run_world(I, raw, d, freeze=True, allow_unlabelled=True)
            frozen = (d / "real_test_v1.csv").read_bytes()
            test = rows_of(d / "real_test_v1.csv")
            man = json.loads((d / I.MANIFEST_NAME).read_text())
            pool0 = rows_of(d / "pool" / "pool.csv")
            # a fourth phone after the freeze: one message of a TEST group, one of a POOL group, a new two-message template
            t_row, p_row = test[0], next(r for r in pool0 if r["group_size"] == "1")
            rows = [("AX-FKNEWS-S", "Note: " + t_row["text"], "(Unknown)", "1"), ("AX-FKNEWS-S", "Note: " + p_row["text"], "(Unknown)", "1")]
            rows += [("AD-FKCITY-S", f"Your property tax for ward {w} is due by 31 March, pay at the municipal office or online.", "(Unknown)", "1") for w in (7, 9)]
            sms_xml_full(raw / "phone_4.xml", rows)
            run_world(I, raw, d)
            sheet = rows_of(d / "label_me.csv")
            for r in sheet:
                if NEEDLES["P1"] in r["example_1"]:
                    r["label"] = "genuine"
            write_csv(d / "label_me.csv", I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet])
            run_world(I, raw, d)
            review = rows_of(d / "review_names.csv")   # new rows bring new name candidates: they wait outside the pool until answered
            for r in review:
                r["replace_with"] = r["replace_with"] or "ok"
            I.write_review(d / "review_names.csv", review)
            run_world(I, raw, d)
            pool = rows_of(d / "pool" / "pool.csv")
            rep = (d / "report.md").read_text()
            if (d / "real_test_v1.csv").read_bytes() != frozen:
                bad.append("the frozen test file changed after the freeze")
            if not any(NEEDLES["P1"] in r["text"] for r in pool) or not any(r["source"] == "phone_4" for r in pool):
                bad.append("the new phone's labelled template did not reach the pool")
            if {r["group_id"] for r in pool} & set(man["test_group_ids"]):
                bad.append("a TEST group reached the pool")
            if not re.search(r"group is in the frozen TEST half: [1-9]", rep) or "Mode: **post**" not in rep:
                bad.append("the message of a TEST group was not dropped and counted")
            if not any(r["text"].startswith("Note: ") for r in pool):
                bad.append("the new message of a POOL group did not reach the pool")
            if jac_max([r["text"] for r in test], [r["text"] for r in pool]) >= 0.7:
                bad.append("a pool row is a near-duplicate of a TEST row")
            # the group registry is gone: the manifest's TEST key hashes still keep the TEST messages out
            (d / "label_me_state.json").unlink()
            run_world(I, raw, d)
            pool2 = rows_of(d / "pool" / "pool.csv")
            if jac_max([r["text"] for r in test], [r["text"] for r in pool2]) >= 0.7 or (d / "real_test_v1.csv").read_bytes() != frozen:
                bad.append("without the group registry a TEST message reached the pool")
            flags = I.near_test_flags(["Note: " + t_row["text"], "An unrelated sentence about the monsoon arriving early in Kerala this year."], [t_row["text"]])
            if flags != [True, False]:
                bad.append(f"near_test_flags: {flags}")
            try:
                run_world(I, raw, d, freeze=True, allow_unlabelled=True)
                bad.append("a second --freeze went through after the post-freeze runs")
            except I.Stop:
                pass
        finally:
            I.CLAUDE = saved
    return bad


def r23(tmp):
    import json
    import intake_real as I
    import label_real as L
    bad = []
    with small_buckets():
        raw = phone_world(tmp / "w23" / "raw")
        d = tmp / "w23" / "out"
        run_world(I, raw, d)
        sheet = rows_of(d / "label_me.csv")
        g = by_needle(sheet)
        b2 = {r["group_id"] for r in sheet if r["label_priority"] == "2"}
        if b2 != {g[k]["group_id"] for k in ("A", "B", "M1", "M2", "M3")}:
            bad.append("setup: bucket 2 is not A, B, M1-M3")
        lab = {g["A"]["group_id"]: "scam", g["M1"]["group_id"]: "skip", g["T1"]["group_id"]: "genuine"}
        for r in sheet:
            r["label"] = lab.get(r["group_id"], "")
        write_csv(d / "label_me.csv", I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet])
        def copy_pre(name, manifest=False):   # the two files as they were before any trim
            q = tmp / "w23" / name
            q.mkdir()
            for f in ("label_me.csv", "label_me_state.json"):
                shutil.copy(d / f if name == "pre" else tmp / "w23" / "pre" / f, q / f)
            if manifest:
                (q / I.MANIFEST_NAME).write_text("{}")
            return q
        copy_pre("pre")
        tr = I.trim_bucket2(d / "label_me.csv", 3, d / "real_test_v1.csv")
        after = rows_of(d / "label_me.csv")
        a2 = {r["group_id"] for r in after if r["label_priority"] == "2"}
        blank = sorted(b2 - set(lab), key=lambda x: I.hkey(x, I.B2_TRIM_SEED))
        if a2 != {g["A"]["group_id"], g["M1"]["group_id"], blank[0]}:
            bad.append("bucket 2 after the trim is not the 2 labelled groups + the unlabelled one with the smallest trim key")
        if {r["group_id"] for r in after if r["label_priority"] == "4"} != {r["group_id"] for r in sheet if r["label_priority"] == "4"} | set(blank[1:]):
            bad.append("the unlabelled bucket-2 groups left out of the sample did not all move to bucket 4 (or something else moved)")
        same = all(r1[c] == r2[c] for r1, r2 in zip(sheet, after) for c in I.LABEL_COLS if c != "label_priority") and len(sheet) == len(after)
        if not same:
            bad.append("the trim changed something besides label_priority")
        st = I.load_state(d / "label_me_state.json")
        if (tr["labelled_kept"], tr["sampled"], len(tr["moved_to_4"]), tr["seed"]) != (2, 1, 2, I.B2_TRIM_SEED) or st["b2_trim"]["moved_to_4"] != sorted(blank[1:], key=lambda x: (I.hkey(x, I.B2_TRIM_SEED), x)):
            bad.append(f"trim record wrong: {tr}")
        if any(str(st["assigned"][r["group_id"]]) != r["label_priority"] for r in after):
            bad.append("the state and the sheet disagree after the trim")
        twin = copy_pre("twin")
        I.trim_bucket2(twin / "label_me.csv", 3, twin / "real_test_v1.csv")
        strip = lambda p: {k: v for k, v in json.loads(p.read_text()).items() if k != "b2_trim"} | {"trim": {k: v for k, v in json.loads(p.read_text())["b2_trim"].items() if k != "utc"}}
        if (twin / "label_me.csv").read_bytes() != (d / "label_me.csv").read_bytes() or strip(twin / "label_me_state.json") != strip(d / "label_me_state.json"):
            bad.append("the same files trimmed twice gave different results (the draw is not seeded)")
        snap = (d / "label_me.csv").read_bytes(), (d / "label_me_state.json").read_bytes()
        if I.trim_bucket2(d / "label_me.csv", 3, d / "real_test_v1.csv")["total"] != 3 or ((d / "label_me.csv").read_bytes(), (d / "label_me_state.json").read_bytes()) != snap:
            bad.append("the same trim again changed something")
        try:
            I.trim_bucket2(d / "label_me.csv", 4, d / "real_test_v1.csv")
            bad.append("a second trim with a different size was not refused")
        except SystemExit:
            pass
        # a labeller open across the trim: its next key reads the new buckets and keeps the labels it gave
        op = copy_pre("open")
        lab_sheet = L.Sheet(op / "label_me.csv")
        lab_sheet.set(g["M2"]["group_id"], "genuine")
        I.trim_bucket2(op / "label_me.csv", 3, op / "real_test_v1.csv")
        lab_sheet.set(g["T2"]["group_id"], "genuine")
        got = {r["group_id"]: (r["label_priority"], r["label"]) for r in rows_of(op / "label_me.csv")}
        if got[g["M2"]["group_id"]] != ("2", "genuine") or got[g["T2"]["group_id"]] != ("1", "genuine") or got[g["A"]["group_id"]] != ("2", "scam") \
                or sum(v[0] == "2" for v in got.values()) != 3:
            bad.append("a labeller open across the trim lost a label or did not pick up the new buckets")
        # N below the number of labelled groups: every labelled group stays, no unlabelled one
        low = copy_pre("low")
        trl = I.trim_bucket2(low / "label_me.csv", 1, low / "real_test_v1.csv")
        if (trl["labelled_kept"], trl["sampled"]) != (2, 0) or trl["max_key"] != -1.0 or sum(r["label_priority"] == "2" for r in rows_of(low / "label_me.csv")) != 2:
            bad.append(f"a size below the labelled count did not keep exactly the labelled groups: {trl}")
        # an intake rerun keeps the trim; a third phone's new mobile group follows the sample's cut-off
        before = {r["group_id"]: (r["label_priority"], r["label"]) for r in rows_of(d / "label_me.csv")}
        phone_3(raw)
        run_world(I, raw, d)
        sheet3 = rows_of(d / "label_me.csv")
        now = {r["group_id"]: (r["label_priority"], r["label"]) for r in sheet3}
        if any(now.get(k) != v for k, v in before.items()):
            bad.append("an intake rerun with a new phone undid the trim or changed a label")
        n2 = by_needle(sheet3)["N2"]
        want = "2" if I.hkey(n2["group_id"], I.B2_TRIM_SEED) <= tr["max_key"] else "4"
        if n2["label_priority"] != want:
            bad.append(f"new mobile-sender group got bucket {n2['label_priority']}, the trim's cut-off says {want}")
        rep = (d / "report.md").read_text()
        if "Bucket 2 trimmed" not in rep or f"seed {I.B2_TRIM_SEED}" not in rep or "Bucket 2 is scam-enriched by design" not in rep:
            bad.append("the report does not describe the trim (seed, counts) next to the scam-enriched note")
        frozen = copy_pre("frozen", manifest=True)
        try:
            I.trim_bucket2(frozen / "label_me.csv", 3, frozen / "real_test_v1.csv")
            bad.append("a trim after the freeze was not refused")
        except SystemExit:
            pass
        main = ("import sys; sys.path.insert(0, 'src'); import intake_real as I; I.PRIORITY_N1, I.PRIORITY_N3 = 3, 2; "   # the state was made with the patched sizes
                "sys.argv = ['intake_real.py'] + sys.argv[1:]; I.main()")
        cli = subprocess.run([PY, "-c", main, "--trim-bucket2", "3", "--label-file", str(d / "label_me.csv"), "--out", str(d / "real_test_v1.csv")],
                             cwd=ROOT, capture_output=True, text=True, timeout=60)
        if cli.returncode != 0 or "2 labelled groups kept + 1 of 3 unlabelled drawn = 3 groups; 2 moved to bucket 4" not in cli.stdout:
            bad.append(f"the command line does not report the trim: {cli.returncode} {cli.stdout[-200:]} {cli.stderr[-200:]}")
    return bad


def _phone_prefilter_equal():
    """The pre-filtered pii.known_phone_rx gives byte-identical output to the one big alternation it replaced (kept here as the reference), on the R24 cases
    and 2,000 seeded fixture-style messages (digit runs, separators, prefixes, coupons, unicode digits, numbers that are not known ones)."""
    import random, pii
    def full(phones):   # the function as of a045705
        alts = [r"(?:(?<!\d)(?:(?:\+|00|0)?91|0)\D?)?" + r"\D?".join(p) for p in sorted(phones)]
        return re.compile("|".join(alts))
    rng = random.Random(24)
    phones = {"".join(rng.choice("6789") if i == 0 else rng.choice("0123456789") for i in range(10)) for _ in range(60)} | {"9876500031", "9876543210"}
    plist = sorted(phones)
    seps = ["", "", "", " ", "-", ".", "/", "A", "x", "\n", "\u0661"]
    def noisy(p):
        pre = rng.choice(["", "", "+91", "91", "0", "0091", "091", "+91 ", "91-", "1", "9"])
        return pre + "".join(c + rng.choice(seps) for c in p[:-1]) + p[-1]
    words = "your a/c debited rs 500 ref use code EYEC at checkout call now otp 123456 order total save 20% on".split()
    texts = ["Use code EYEC98765D00031 now", "call +91 98765 00031 or 9876-500-031 or 098765-00031", "ref 100200300 total 9876500031999", "9876543210" * 2,
             "1 2 3 4 5 6 7 8 9 0 1 2 3", "", "x", "\u0669\u0668\u0667\u0666\u0665\u0660\u0660\u0660\u0663\u0661"]
    for _ in range(2000):
        parts = [rng.choice(words) for _ in range(rng.randint(2, 14))]
        for _ in range(rng.choice([0, 0, 1, 1, 2, 3])):
            p = rng.choice(plist) if rng.random() < 0.8 else "".join(rng.choice("0123456789") for _ in range(10))
            parts.insert(rng.randint(0, len(parts)), noisy(p) if rng.random() < 0.7 else p)
        texts.append(" ".join(parts) if rng.random() < 0.8 else "".join(parts))
    new, old = pii.known_phone_rx(phones), full(phones)
    diff = [t for t in texts if new.sub("<PHONE>", t) != old.sub("<PHONE>", t)]
    hits = sum(old.sub("<PHONE>", t) != t for t in texts)
    out = [f"the pre-filtered known-phone mask differs from the full alternation on {len(diff)} of {len(texts)} texts, e.g. {diff[0]!r}"] if diff else []
    if hits < 500:
        out.append(f"setup: only {hits} of {len(texts)} texts hold a known number")
    return out


def r24(tmp):
    import intake_real as I, pii
    bad = []
    s = I.Sensitive()
    s.add_phone("+91 98765 00031")
    prx = s.phone_rx()
    s.add_name("Quentin Fakename")
    nrx = s.name_rx()
    must_mask = ["Use code EYEC98765D00031 at checkout", "call 98765 00031 now", "call 98765-00031 now", "call 9876-500-031 now", "call 98765.00031 now", "call 98765/00031 now",
                 "call +91 98765 00031 now", "call +91-98765-00031 now", "call 091 98765 00031 now", "call 91-9876500031 now", "call 0 98765 00031 now",
                 "see hxxps://fake-shop[.]example[.]invalid/c/EYEC98765D00031/x", "coupon 9X8X7X6X5X0X0X0X3X1 here".replace("X", "-")]
    for t in must_mask:
        m = I.mask(t, nrx, prx)
        if re.search(r"9\D?8\D?7\D?6\D?5\D?0\D?0\D?0\D?3\D?1", m) or "<PHONE>" not in m:
            bad.append(f"a known number split by a separator survived: {t!r} -> {m!r}")
        if I.mask(m, nrx, prx) != m:
            bad.append(f"masking twice changed {m!r}")
    if I.mask("Use code EYEC98765D00031 now", nrx, prx) != "Use code EYEC<PHONE> now":
        bad.append("the whole span (digits, the separator, +91) should become one <PHONE>")
    for t in ("Use code EYEC12345D67890 at checkout", "ref 9876-500-032 total", "order 98765 00032 shipped", "promo SAVE98765D00032NOW", "id 5X5X5X5X5X5X5X5X5X5X".replace("X", " ")):
        if I.mask(t, nrx, prx) != pii.MASKS_INTAKE_V1(t, name_rx=nrx):
            bad.append(f"a number that is not a known one is not handled by the old masks alone: {t!r} -> {I.mask(t, nrx, prx)!r}")
    for t in ("Use code EYEC12345D67890 at checkout", "promo SAVE98765D00032NOW"):
        if I.mask(t, nrx, prx) != t:
            bad.append(f"an unrelated coupon was changed: {t!r} -> {I.mask(t, nrx, prx)!r}")
    if I.mask("Use code EYEC98765D00031 with 98765 00031 or Quentin Fakename") != pii.MASKS_INTAKE_V1("Use code EYEC98765D00031 with 98765 00031 or Quentin Fakename"):
        bad.append("with no phone / name regex mask() must be the old masks")
    if pii.known_phone_rx(set()) is not None:
        bad.append("no phones should give no regex")
    bad += _phone_prefilter_equal()
    # end to end: a coupon with the sender's number split by a letter
    raw = tmp / "r24raw"
    raw.mkdir()
    rows = [("AX-FAKESH-S", f"Fake Mart festival sale: use code EYEC98765D00031 at checkout and save {n}% on your next order, offer ends soon.") for n in (10, 20, 30)]
    rows += [("AX-FAKESH-S", "Fake Mart festival sale: use code EYEC12345D67890 at checkout and save 40% on your next order, offer ends soon."),
             ("+919876500031", "Meet Quentin Fakename at the gate tomorrow morning at nine please, I will bring the keys."),
             ("AX-FAKEBK-S", "Rs 500.00 debited from A/c XX1234 on 29-10-26 by UPI ref 100200300. Avl bal Rs 9,000.00. Not you? Call Fake Bank care."),
             ("AX-FAKEBK-S", "Rs 750.00 debited from A/c XX1234 on 30-10-26 by UPI ref 100200301. Avl bal Rs 8,250.00. Not you? Call Fake Bank care.")]
    sms_xml(raw / "phone_1.xml", rows)
    try:
        d, paths, _ = e2e(tmp, raw, "p1")
    except I.Stop as e:
        return bad + [f"the run stopped on a split known number: {str(e)[:120]}"]
    sheet = rows_of(paths["label_file"])
    text = paths["label_file"].read_text(encoding="utf-8")
    coupon = find_group(sheet, "festival sale: use code EYEC<PHONE>")
    if "98765D00031" in text or "EYEC12345D67890" not in text:
        bad.append("the split known number survived in the sheet, or the unrelated coupon was changed")
    # an example kept from an earlier run: labelled orphan row masked before a name and number were known
    old = {**{c: "" for c in I.LABEL_COLS}, "group_id": "Gdeadbeef", "label": "scam", "size": "9", "label_priority": "4",
           "example_1": "Call Quentin Fakename on EYEC98765D00031 today", "example_2": " Quentin Fakename wrote hxxps://fake[.]example[.]invalid/u/Quentin Fakename/x ..."}
    lf = tmp / "r24_labels.csv"
    write_csv(lf, I.LABEL_COLS, [[r[c] for c in I.LABEL_COLS] for r in sheet] + [[old[c] for c in I.LABEL_COLS]])
    names = tmp / "r24_names.txt"
    names.write_text("Quentin Fakename\n", encoding="utf-8")
    d, paths2, _ = e2e(tmp, raw, "p2", label_file=lf, names_file=names)
    st = d / "label_me_state.json"
    state_after = st.read_text() if st.exists() else None
    after = rows_of(lf)
    orphan = [r for r in after if r["group_id"] == "Gdeadbeef"]
    if len(orphan) != 1 or orphan[0]["label"] != "scam" or orphan[0]["size"] != "9" or orphan[0]["label_priority"] != "4":
        bad.append(f"the orphan row lost its id / label / size: {orphan}")
    elif any(w in orphan[0]["example_1"] + orphan[0]["example_2"] for w in ("Quentin", "98765D00031")) or "<NAME>" not in orphan[0]["example_1"] \
            or "<PHONE>" not in orphan[0]["example_1"]:
        bad.append(f"the orphan's old examples were not masked with the name / number learned since: {orphan[0]['example_1']!r} | {orphan[0]['example_2']!r}")
    elif not orphan[0]["example_2"].startswith(" ") or not orphan[0]["example_2"].endswith("..."):
        bad.append(f"the cut or the leading space changed: {orphan[0]['example_2']!r}")
    # (the message from the known number is a different group once its name is masked, so only the three bank / sale groups can be compared)
    if len({r["group_id"] for r in after} & {r["group_id"] for r in sheet}) < 2 or len(after) != len(sheet) + 1:
        bad.append("group ids changed or rows were added / lost")
    # a rerun on its own output changes nothing
    d, paths3, _ = e2e(tmp, raw, "p2", label_file=lf, names_file=names)
    if rows_of(lf) != after or (st.read_text() if st.exists() else None) != state_after:
        bad.append("a second rerun changed the sheet or the registry")
    return bad


def r22(tmp):
    """Every output of R18-R21 and R23 (they ran before this one in the same temp folder), plus a labeller session's screen."""
    import json
    bad = []
    phones = [re.sub(r"\D", "", a)[-10:] for a in CONTACTS]
    names = list(CONTACTS.values()) + [w for n in CONTACTS.values() for w in n.split()] + [FAMILY]
    outs = [p for w in ("w18", "w19", "w20", "w21", "w23") for p in (tmp / w / "out").rglob("*") if p.is_file() and p.suffix in (".csv", ".md", ".json")
            and p.name not in ("messages.csv", "mask_names.txt")]
    if len(outs) < 12 or not any(p.name == "pool.csv" for p in outs) or not any(p.name == I_MAN for p in outs):
        bad.append(f"setup: only {len(outs)} output files found")
    screen = labeller(tmp / "w19" / "out" / "label_me.csv", "q").stdout.decode("utf-8")
    blobs = [(p.relative_to(tmp), p.read_text(encoding="utf-8")) for p in outs] + [("labeller screen", screen)]
    for name, blob in blobs:
        txt = re.sub(r"`[0-9a-f]{64}`|\b[0-9a-f]{16,64}\b|\bG[0-9a-f]{8}\b|\bR[0-9a-f]{10}\b", "", blob)   # hashes and ids are hex, not numbers
        for ph in phones:
            if ph in re.sub(r"[\s-]", "", txt):
                bad.append(f"{name}: a phone number survived")
        for who in names:
            if re.search(rf"(?<![^\W\d_]){re.escape(who)}(?![^\W\d_])", txt):   # inside a link too: /track/Name/, ?ref=Name123
                bad.append(f"{name}: the name {who!r} survived")
        for rx in (r"(?<!\d)[6-9]\d{9}(?!\d)", r"\d{9,}", r"\w@[A-Za-z]", r"\+91"):
            if re.search(rx, txt):
                bad.append(f"{name}: pattern {rx} found")
        if str(name).endswith(".json"):
            def leaves(o):
                return [x for k, v in o.items() for x in [k] + leaves(v)] if isinstance(o, dict) else [x for v in o for x in leaves(v)] if isinstance(o, list) else [o]
            odd = [x for x in leaves(json.loads(blob)) if not (isinstance(x, (int, float)) or x is None or re.fullmatch(r"G[0-9a-f]{8}|[0-9a-f]{16}|[0-9a-f]{64}|[a-z_0-9]+|"
                                                                                                                 r"\d+\|[a-z-]+|\d{4}-\d\d-\d\dT\d\d:\d\dZ", str(x)))]
            if odd:
                bad.append(f"{name}: a JSON value that is not an id, hash, number or field name ({len(odd)})")
    return bad


I_MAN = "freeze_manifest.json"


CHECKS = [("R1", "header mapping stops on unexpected / missing / ambiguous", r1), ("R2", "intake on the fake fixture: drops, masks, no PII pattern", r2),
          ("R3", "overlap: train near-duplicate flagged, val twin not, nothing dropped", r3), ("R4", "names: review file, edits applied on rerun, not overwritten", r4),
          ("R5", "freeze writes the hash into CLAUDE.md, refuses a different one", r5), ("R6", "realguard refuses real paths, real texts and real hashes", r6),
          ("R7", "finetune / calibrate / build_text tripwires", r7), ("R8", "eval_real refuses without --final", r8),
          ("R9", "eval_real --final: one ledger line per run, once-only, --again recorded", r9),
          ("R10", "probe tripwire: data/probe/ path, texts and keys refused; finetune exits", r10),
          ("R11", "Form: real header set, not_scam / unsure labels", r11), ("R12", "SMS XML: sender_kind, received only, nothing personal in rows", r12),
          ("R13", "WhatsApp txt: Android + iOS lines, system / media dropped, names gone", r13), ("R14", "groups + label_me.csv: label the group once, cap 3, ids stable", r14),
          ("R15", "privacy: no number / name / address / timestamp in any output", r15), ("R16", "intake reads under data/real/, refuses PROBE-ONLY", r16),
          ("R17", "names: greeting names, mask_names.txt, review states, freeze guards", r17),
          ("R18", "label_priority buckets: rule, seed, stable when a new phone file arrives", r18),
          ("R19", "label_real.py: piped keys, kill + restart, atomic save, Hindi / Kannada, no model output", r19),
          ("R20", "--freeze: grouped 50/50 split, 0 shared groups / near-duplicates, realguard, once only", r20),
          ("R21", "after the freeze: new phone -> pool, TEST messages dropped, test file unchanged", r21),
          ("R23", "--trim-bucket2: labelled stay, seeded sample to N, rest -> bucket 4, kept by reruns, refused twice / after the freeze", r23),
          ("R22", "privacy: no number / name / address in any output, JSON holds ids and numbers only", r22),
          ("R24", "known-phone mask tolerates separators; kept examples are re-masked, labels and ids kept", r24)]


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
