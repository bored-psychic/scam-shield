import csv, os, re, shutil, sys, tempfile
from pathlib import Path

HERE = Path(os.path.abspath(globals().get("__file__", "tests/test_intake_screens.py"))).parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "src"), str(HERE)]

# python tests/test_intake_screens.py   (from the project root). Screenshot / quoted-text intake (src/intake_screens.py) on a FAKE fixture: the
# screenshots are drawn in memory by tests/ocr_render.py and written only to a temp folder, every number, UPI id, address, name and domain is
# invented (example.invalid), and the "real", "probe" and messages.csv corpora are temp files. Only S5 and S8 look at the repo's own folders.
#   S1  sources.csv: a missing column, no filename / text column and a bad label STOP the run
#   S2  OCR: intake_screens.ocr gives exactly reader.read_image's text on the real dev fixture, and a confidence in (0, 1]
#   S3  fixture run: screenshots + quoted text -> data/collected/<group>/collected.csv; columns, source groups, ocr_conf only on screenshots,
#       a typed screenshot stores the typed text with its ocr_cer, verified / date_flag / collector, greeting names and handles -> <NAME>,
#       skip rows dropped
#   S4  privacy: no phone / UPI / e-mail / account / card pattern in any output, every link (text, source_url, a1_second_url) defanged,
#       the report has no message text; a leak or a live link planted in a record stops check_outputs
#   S5  tripwire: realguard still refuses data/real/ and data/probe/; the intake refuses an input or output folder under either
#   S6  collisions: a near-duplicate of a data/real/ text (raw Form export and real_test_v1.csv), of a probe row, and of a messages.csv test /
#       train row is dropped and counted by where; nothing else is
#   S7  rerun: the same input again adds 0 rows, ids are stable, a second source with the same wording gives group_sources 2
#   S8  the repo's own data/collected/ (if any rows exist) has 0 near-duplicates of data/real/
import intake_screens as S
import realguard
from ocr_render import bubble
from shield.ocr import reader

FAKE_SHOTS = {
    "kyc.png": "Dear Ravindra, your FakeBank KYC is pending. Update today at https://fakebank-kyc.example.invalid/upd or call 9000012345. "
               "Mail kyc.help@example.invalid",
    "task.png": "Hello! Part time job, earn Rs 3000 daily by liking videos. Pay Rs 200 joining fee to taskboss.fake@ybl. Account 123456789012",
    "real_twin.png": "Congratulations! You won Rs 50000. Send Rs 500 to fake.winner@ybl to claim the prize.",
}
QUOTED = [
    # text, source_url, date_seen, channel, label, verified, a1_second_url
    ("Your parcel is held at customs. Pay the duty at hxxps://parcel-duty[.]example[.]invalid/pay within 24 hours.", "https://news-fake.invalid/a/1",
     "2025-03-02", "sms", "scam", "exact", "https://other-news.invalid/b/2"),
    ("Your demat account was debited for 10 shares of EXAMPLETECH. If not done by you, contact your DP. Ask u/fakeuser on reddit or @fakehandle.",
     "https://www.broker-fake.invalid/help", "2023-11-05", "sms", "genuine", "", ""),
    ("This is a probe-only sentence about an invented trading group called FakeGroup VIP 77 that promises guaranteed returns daily.",
     "https://news-fake.invalid/a/3", "2025-01-01", "whatsapp", "scam", "none", ""),
    ("Training twin sentence: your electricity connection will be cut tonight, call the officer at once to avoid disconnection.",
     "https://news-fake.invalid/a/4", "", "sms", "scam", "", ""),
    ("A test-split twin: your FASTag is blocked, recharge through this link now or pay a penalty at the toll plaza today please.",
     "https://news-fake.invalid/a/5", "2026-01-10", "sms", "scam", "", ""),
    ("skip me: this row is a meme, not a message at all and the labeller said skip.", "https://news-fake.invalid/a/6", "2025-05-05", "social", "skip", "", ""),
]
SOURCE_COLS = ["filename", "text", "source_url", "date_seen", "channel", "label", "verified", "a1_second_url", "outlet"]
PII_RX = [re.compile(p) for p in (r"[\w.+-]+@[\w-]+\.[\w.]+", r"\b[\w.-]{2,}@[A-Za-z]+\b", r"\b[6-9]\d{9}\b", r"\d{9,}", r"\b(?:\d{4}[ -]){3}\d{4}\b")]
LIVE_RX = re.compile(r"(?i)\bhttps?://|\bwww\.[a-z]")


def write_csv(path, headers, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def rows_of(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def make_world(tmp):
    """A fake inbox folder, a fake data/real/ (raw Form export + real_test_v1.csv), a fake probe folder and a tiny messages.csv."""
    inbox = tmp / "inbox"
    inbox.mkdir()
    rows = []
    for name, text in FAKE_SHOTS.items():
        (inbox / name).write_bytes(bubble(text))
        typed = text if name == "task.png" else ""   # task.png is typed by hand: its typed text is stored, OCR only measured
        rows.append([name, typed, "https://www.thequint-fake.invalid/webqoof/x", "2025-06-01", "whatsapp", "scam", "near", "", "Fake Outlet"])
    for text, url, date, ch, label, ver, a1 in QUOTED:
        rows.append(["", text, url, date, ch, label, ver, a1, "Fake News"])
    write_csv(inbox / "sources.csv", SOURCE_COLS, rows)
    real = tmp / "real"
    (real / "raw").mkdir(parents=True)
    shutil.copy(HERE / "fixtures" / "real_fake.csv", real / "raw" / "form.csv")   # holds the "You won Rs 50000 ... fake.winner@ybl" row
    write_csv(real / "real_test_v1.csv", ["text", "source_row_hash"], [["Unrelated real test row about a library book due on Friday.", "x"]])
    probe = tmp / "probe"
    probe.mkdir()
    write_csv(probe / "p.csv", ["id", "text"], [["s1", QUOTED[2][0].replace("daily", "every day")]])
    msgs = tmp / "messages.csv"
    write_csv(msgs, ["text", "split"], [[QUOTED[3][0].replace("tonight", "today"), "train"], [QUOTED[4][0].replace("today please", "today"), "test"],
                                        ["Completely unrelated sentence about a cat sitting on a warm mat in the sun.", "val"]])
    return inbox, real, probe, msgs


def run_world(tmp, inbox=None, **kw):
    inbox_, real, probe, msgs = make_world(tmp) if inbox is None else (inbox, tmp / "real", tmp / "probe", tmp / "messages.csv")
    out = tmp / "collected"
    res = S.run(inbox_, out_dir=out, report_path=tmp / "report.md", messages=msgs, real_dir=real, probe_dirs=(probe,), **kw)
    return res, out


def s1(tmp):
    bad = []
    for headers, row, want in ((["filename", "source_url", "channel"], ["a.png", "https://x.example.invalid", "sms"], "date_seen"),
                               (["source_url", "date_seen", "channel"], ["https://x.example.invalid", "2025-01-01", "sms"], "filename or text"),
                               (["text", "source_url", "date_seen", "channel", "label"], ["some long enough text here", "https://x.example.invalid", "2025-01-01", "sms", "maybe"], "label")):
        p = tmp / "s1.csv"
        write_csv(p, headers, [row])
        try:
            S.run(p, out_dir=tmp / "s1_out", report_path=tmp / "s1.md", messages=tmp / "none.csv", real_dir=tmp / "noreal", probe_dirs=())
            bad.append(f"no stop for {want}")
        except S.Stop as e:
            if want not in str(e):
                bad.append(f"stop for {want} does not name it: {e}")
    return bad


def s2(tmp):
    data = (HERE / "fixtures" / "real" / "jio_kiwi_dark.jpg").read_bytes()
    text, conf = S.ocr(data)
    bad = [] if text == reader.read_image(data)["text"] else ["ocr text differs from reader.read_image"]
    if conf is None or not 0 < conf <= 1:
        bad.append(f"confidence {conf} not in (0, 1]")
    return bad


def s3(tmp):
    res, out = run_world(tmp)
    bad = []
    files = sorted(p.relative_to(out).as_posix() for p in out.glob("*/collected.csv"))
    if files != ["broker_fake_invalid/collected.csv", "news_fake_invalid/collected.csv", "thequint_fake_invalid/collected.csv"]:
        bad.append(f"source groups {files}")
    rows = [r for f in out.glob("*/collected.csv") for r in rows_of(f)]
    if rows and list(rows[0]) != S.OUT_COLS:
        bad.append("columns differ from OUT_COLS")
    if len(rows) != 4:
        bad.append(f"{len(rows)} rows written, want 4 (kyc.png, task.png, the parcel quote, the demat quote)")
    by = {r["text"][:12]: r for r in rows}
    shots = [r for r in rows if r["input_kind"] in ("screenshot", "screenshot_typed")]
    if len(shots) != 2 or any(not (0 < float(r["ocr_conf"]) <= 1) or len(r["image_sha256"]) != 64 for r in shots):
        bad.append("screenshot rows need an ocr_conf in (0, 1] and an image hash")
    typed = [r for r in shots if r["input_kind"] == "screenshot_typed"]
    if len(typed) != 1 or not typed[0]["text"].startswith("Hello! Part time job") or not 0 <= float(typed[0]["ocr_cer"] or 9) < 0.1:
        bad.append(f"typed screenshot: want the typed text and an ocr_cer < 0.1, got {[(r['text'][:20], r['ocr_cer']) for r in typed]}")
    if any(r["needs_review"] not in ("True", "False") for r in rows) or any(r["needs_review"] == "True" for r in rows if r["input_kind"] != "screenshot"):
        bad.append("needs_review must be True / False and only ever True for an OCR-only screenshot")
    if any(r["ocr_conf"] or r["image_sha256"] for r in rows if r["input_kind"] == "quoted_text"):
        bad.append("quoted-text rows must have no ocr_conf / image hash")
    parcel = next((r for r in rows if r["text"].startswith("Your parcel")), None)
    demat = next((r for r in rows if r["text"].startswith("Your demat")), None)
    if not parcel or parcel["verified"] != "exact" or parcel["date_flag"] != "" or parcel["label"] != "scam":
        bad.append(f"parcel row verified / date_flag / label wrong: {parcel and (parcel['verified'], parcel['date_flag'])}")
    if not demat or demat["verified"] != "unchecked" or demat["date_flag"] != "pre_2024" or demat["label"] != "genuine":
        bad.append("demat row: verified unchecked, date_flag pre_2024, label genuine expected")
    if demat and ("fakeuser" in demat["text"] or "fakehandle" in demat["text"]):
        bad.append("social handles not masked")
    kyc = next((r for r in shots if "KYC" in r["text"]), None)
    if not kyc or "Ravindra" in kyc["text"] or "<NAME>" not in kyc["text"]:
        bad.append("greeting name not masked in the OCR row")
    if any(r["collector"] != "prajval" or r["provenance"] != "real_circulating" or r["is_synthetic"] != "False" for r in rows):
        bad.append("collector / provenance / is_synthetic wrong")
    for raw, want in (("Dear Vehicle Owner/Driver, pay now", "Vehicle"), ("Dear Punjab National bank customer your account", "Punjab"),
                      ("Dear Electrcity user, power cut", "Electrcity"), ("Dear Valued Customer, points expire", "Valued")):
        if want not in S.mask(raw):
            bad.append(f"over-masked: {raw!r} -> {S.mask(raw)!r}")
    for raw, gone in (("Hi Rahul, your OTP", "Rahul"), ("Dear Ravi Kumar,\nyour loan", "Kumar"), ("hello priya!", "priya")):
        if gone in S.mask(raw):
            bad.append(f"name kept: {raw!r} -> {S.mask(raw)!r}")
    if res["drops"].get("label skip") != 1:
        bad.append(f"skip row not dropped once: {dict(res['drops'])}")
    return bad


def s4(tmp):
    res, out = run_world(tmp)
    bad = []
    for f in out.glob("*/collected.csv"):
        for r in rows_of(f):
            for c in ("text", "notes", "outlet"):
                for rx in PII_RX:
                    if rx.search(r[c]):
                        bad.append(f"{c} of {r['id']} matches {rx.pattern}")
            for c, v in r.items():
                if LIVE_RX.search(v) or S.live_links(v):
                    bad.append(f"live link in {c} of {r['id']}")
            if r["input_kind"] == "screenshot" and "kyc" in r["text"].lower() and "[.]" not in r["text"]:
                bad.append("the OCR row's link is not defanged")
    rep = (tmp / "report.md").read_text()
    for t in list(FAKE_SHOTS.values()) + [q[0] for q in QUOTED]:
        if t[:25] in rep:
            bad.append("report contains message text")
    rec = dict(res["new"][0])
    for col, val, kind in (("text", rec["text"] + " call 9876543210", "phone"), ("notes", "pay x.y@okaxis", "UPI"), ("source_url", "https://live.example.invalid/x", "live link")):
        try:
            S.check_outputs([dict(rec, **{col: val})])
            bad.append(f"check_outputs let a planted {kind} in {col} through")
        except S.Stop:
            pass
    return bad


def s5(tmp):
    bad = []
    for p in ("data/real/raw/x.csv", "data/real", "data/probe/investment_v1.csv", "data/probe"):
        try:
            realguard.refuse_real_paths([p])
            bad.append(f"realguard let {p} through")
        except realguard.RealDataTripwire:
            pass
    inbox, *_ = make_world(tmp)
    for kw in ({"inp": ROOT / "data" / "real" / "raw"}, {"inp": inbox, "out_dir": ROOT / "data" / "probe" / "collected"}, {"inp": ROOT / "data" / "probe"}):
        try:
            S.run(**dict({"out_dir": tmp / "o", "report_path": tmp / "r.md", "messages": tmp / "messages.csv", "real_dir": tmp / "real", "probe_dirs": ()}, **kw))
            bad.append(f"intake ran with {kw}")
        except realguard.RealDataTripwire:
            pass
    if (ROOT / "data" / "probe" / "collected").exists():
        bad.append("an output folder was created under data/probe/")
    return bad


def s6(tmp):
    res, _ = run_world(tmp)
    want = {"near-duplicate of data/real": 1, "near-duplicate of data/probe": 1, "near-duplicate of messages.csv train": 1,
            "near-duplicate of messages.csv test": 1, "label skip": 1}
    got = {k: v for k, v in res["drops"].items()}
    return [] if got == want else [f"drops {got}, want {want}"]


def s7(tmp):
    res1, out = run_world(tmp)
    ids1 = sorted(r["id"] for r in res1["total"])
    res2, _ = run_world(tmp, inbox=tmp / "inbox")
    bad = []
    if res2["new"]:
        bad.append(f"rerun added {len(res2['new'])} rows")
    if sorted(r["id"] for r in res2["total"]) != ids1:
        bad.append("ids changed on rerun")
    second = tmp / "second.csv"
    write_csv(second, SOURCE_COLS, [["", QUOTED[0][0], "https://another-outlet.invalid/p/9", "2025-03-04", "sms", "scam", "", "", "Other"]])
    S.run(second, out_dir=out, report_path=tmp / "report.md", messages=tmp / "messages.csv", real_dir=tmp / "real", probe_dirs=(tmp / "probe",))
    rows = [r for f in out.glob("*/collected.csv") for r in rows_of(f) if r["text"].startswith("Your parcel")]
    if len(rows) != 2 or {r["group_sources"] for r in rows} != {"2"} or len({r["template_group"] for r in rows}) != 1:
        bad.append(f"same wording from two sources: {[(r['source_group'], r['group_sources']) for r in rows]}")
    return bad


def s8(tmp):
    rows = S.read_collected(S.COLLECTED)
    if not rows:
        return []
    hits = S.collisions([S.refang(r["text"]) for r in rows], [("data/real", S.real_texts(realguard.REAL_DIR))])
    n = sum(bool(h) for h in hits)
    return [f"{n} rows of data/collected/ are near-duplicates of data/real/"] if n else []


CHECKS = [("S1", "sources.csv: missing columns and bad labels stop", s1), ("S2", "OCR text identical to the app's reader, confidence in (0, 1]", s2),
          ("S3", "fixture run: groups, columns, conf, verified, dates, names", s3), ("S4", "privacy: no PII pattern, all links defanged, report has no text", s4),
          ("S5", "tripwire: data/real/ and data/probe/ refused", s5), ("S6", "collisions with real / probe / messages.csv dropped and counted", s6),
          ("S7", "rerun adds nothing; same wording from two sources groups", s7), ("S8", "repo data/collected/ has 0 near-duplicates of data/real/", s8)]


def run():
    out = []
    for cid, title, fn in CHECKS:
        with tempfile.TemporaryDirectory() as d:
            try:
                bad = fn(Path(d))
            except BaseException as e:   # SystemExit included: a script that stops is a failed check, not a crashed suite
                bad = [f"{type(e).__name__}: {str(e)[:300]}"]
        out.append((cid, title, bad))
    return out


def test_intake_screens():
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
