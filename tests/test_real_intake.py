import ast, csv, hashlib, os, re, shutil, subprocess, sys, tempfile
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
    out = rows_of(tmp / "real_test_v1.csv")
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
    rows = rows_of(tmp / "real_test_v1.csv")
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
    out0 = rows_of(tmp / "real_test_v1.csv")
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
    out = {r["id"]: r for r in rows_of(tmp / "real_test_v1.csv")}
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
    paths = dict(out=d / "real_test_v1.csv", review=d / "review_names.csv", report=d / "report.md", label_file=label_file or d / "label_me.csv",
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
    out = rows_of(d / "o.csv")
    rep = (d / "rep.md").read_text()
    if len(out) != 3 or {r["source"] for r in out} != {"form_whatsapp", "form_sms", "form_other"} or {r["label"] for r in out} != {"0", "1"}:
        bad.append(f"{len(out)} rows, sources {sorted({r['source'] for r in out})}")
    if "label unsure (excluded): 1" not in rep:
        bad.append("unsure was not counted in the report")
    if any(n in (d / f).read_text() for n in ("Asha", "Ravi", "Meera", "Priya") for f in ("o.csv", "rep.md")):
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
    first = rows_of(paths["out"])
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
    out = rows_of(paths2["out"])
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
    if ids(paths3["out"]) != ids(paths2["out"]):
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
    out_rows = rows_of(paths["out"])
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
    for f in ("data/real/label_me.csv", "data/real/raw/x.xml", "data/real/real_test_v1.csv", "data/real/review_names.csv", "data/real/mask_names.txt"):
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
        out_text = "\n".join(r["text"] for r in rows_of(paths["out"]))
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
        d, paths, (sha, final) = e2e(tmp, raw, "n3", freeze=True, **kw)
        if sha not in claude.read_text() or "Not frozen yet" in claude.read_text() or I.frozen_hash() != sha:
            bad.append("freeze did not write the hash / left the 'not frozen' sentence")
        write_csv(tmp / "chg.csv", I.LABEL_COLS, [[r[c] if c != "label" else "scam" for c in I.LABEL_COLS] for r in sheet])
        before = paths["out"].read_bytes()
        try:
            e2e(tmp, raw, "n3", names_file=names, label_file=tmp / "chg.csv")
            bad.append("a rerun replaced the frozen test set")
        except I.Stop as e:
            if "frozen test set" not in str(e):
                bad.append(f"frozen-file refusal text: {str(e)[:100]}")
        if paths["out"].read_bytes() != before:
            bad.append("the frozen file changed")
    finally:
        I.CLAUDE = saved
    return bad


CHECKS = [("R1", "header mapping stops on unexpected / missing / ambiguous", r1), ("R2", "intake on the fake fixture: drops, masks, no PII pattern", r2),
          ("R3", "overlap: train near-duplicate flagged, val twin not, nothing dropped", r3), ("R4", "names: review file, edits applied on rerun, not overwritten", r4),
          ("R5", "freeze writes the hash into CLAUDE.md, refuses a different one", r5), ("R6", "realguard refuses real paths, real texts and real hashes", r6),
          ("R7", "finetune / calibrate / build_text tripwires", r7), ("R8", "eval_real refuses without --final", r8),
          ("R9", "eval_real --final: one ledger line per run, once-only, --again recorded", r9),
          ("R10", "probe tripwire: data/probe/ path, texts and keys refused; finetune exits", r10),
          ("R11", "Form: real header set, not_scam / unsure labels", r11), ("R12", "SMS XML: sender_kind, received only, nothing personal in rows", r12),
          ("R13", "WhatsApp txt: Android + iOS lines, system / media dropped, names gone", r13), ("R14", "groups + label_me.csv: label the group once, cap 3, ids stable", r14),
          ("R15", "privacy: no number / name / address / timestamp in any output", r15), ("R16", "intake reads under data/real/, refuses PROBE-ONLY", r16),
          ("R17", "names: greeting names, mask_names.txt, review states, freeze guards", r17)]


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
