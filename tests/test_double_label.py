import csv, os, re, sys, tempfile
from collections import Counter
from pathlib import Path

HERE = Path(os.path.abspath(globals().get("__file__", "tests/test_double_label.py"))).parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "src"), str(HERE)]

# python tests/test_double_label.py   (from the project root). The blind second-labeller sheet of src/double_label.py, --real mode
# (make_real), on a FAKE labelled_preview.csv in a temp folder: every text is invented (example.invalid). Only D6 looks at the repo's own
# data/real/double_label_real_sheet.csv (skipped when it does not exist). label_me.csv is never opened.
#   D1  sheet columns are exactly item, text, label_2, notes (no label, bucket or group column); the key is a separate file; label_2 is blank
#   D2  one row per template group: the key's refs map to distinct group_ids even where a group has several messages
#   D3  masking: no pii.MISS_RX hit, no live link (links defanged), no message id or group id inside any sheet text
#   D4  selection: every scam group up to N // 2, genuine for the rest; texts over MAX_CHARS and non-0/1 labels never appear; same seed, same sheet
#   D5  a sheet with a label_2 filled in is not overwritten without --force
#   D6  the repo's own real sheet (if made): 50 rows, the same columns, one row per group, masking check passes
import double_label as D
import pii

COLS = ["item", "text", "label_2", "notes"]
PREVIEW_COLS = ["id", "text", "label", "language", "category", "overlap", "source_row_hash", "source", "source_type", "sender_kind",
                "group_id", "group_size", "label_priority", "kw_bucket"]


def fake_preview(path):
    """10 scam groups (3 with 3 messages), 60 genuine groups (10 with 3), plus a long genuine group, a long-only scam group and a skip row."""
    rows = []

    def add(gid, k, label, text, prio):
        rows.append({"id": f"Rfake{gid}m{k}", "text": text, "label": label, "language": "en", "category": "unspecified", "overlap": "False",
                     "source_row_hash": f"h{gid}{k}", "source": "phone_x", "source_type": "sms", "sender_kind": "mobile_number",
                     "group_id": f"Gfake{gid}", "group_size": "3", "label_priority": str(prio), "kw_bucket": "other"})
    for g in range(10):
        for k in range(3 if g < 3 else 1):
            add(f"s{g}", k, "1", f"Fake notice {g}.{k}: your FakeBank KYC expires today, update at https://kyc-{g}.example.invalid/u{k}", 2)
    for g in range(60):
        for k in range(3 if g < 10 else 1):
            add(f"g{g}", k, "0", f"Fake reminder {g}.{k}: invented clinic closed on Sundays, visit https://clinic-{g}.example.invalid/{k}", 1 + g % 3)
    add("longg", 0, "0", "Invented long genuine text. " * 30, 1)
    add("longs", 0, "1", "Invented long scam text, update at https://long.example.invalid. " * 12, 2)
    add("skip", 0, "", "Invented undecided message", 3)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=PREVIEW_COLS)
        w.writeheader()
        w.writerows(rows)
    return rows


def read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def masking_bad(sheet_rows, tag):
    bad = []
    for r in sheet_rows:
        if pii.MISS_RX.search(r["text"]):
            bad.append(f"{tag} {r['item']}: pii.MISS_RX hit")
        if re.search(r"(?i)\bhttps?://|\bwww\.", r["text"]):
            bad.append(f"{tag} {r['item']}: live link")
    return bad


def make_fake(d, force=False):
    prev = d / "preview.csv"
    rows = fake_preview(prev)
    sheet, key = d / "sheet.csv", d / "key.csv"
    D.make_real(force=force, preview=prev, sheet=sheet, key=key)
    return rows, sheet, key


def d1(d):
    _, sheet, key = make_fake(d)
    s, bad = read(sheet), []
    with open(sheet, encoding="utf-8", newline="") as f:
        header = next(csv.reader(f))
    if header != COLS:
        bad.append(f"sheet header {header}, expected {COLS}")
    if any(r["label_2"] or r["notes"] for r in s):
        bad.append("label_2 / notes not blank")
    if [r["item"] for r in s] != [f"S{i + 1:02d}" for i in range(len(s))]:
        bad.append("item ids are not S01..Sn in order")
    if not read(key) or "label_1" not in read(key)[0]:
        bad.append("key file has no label_1")
    if sheet == key:
        bad.append("sheet and key are the same file")
    return bad


def d2(d):
    rows, sheet, key = make_fake(d)
    gid = {r["id"]: r["group_id"] for r in rows}
    k = read(key)
    groups = [gid[r["ref"]] for r in k]
    multi = {g for g, n in Counter(r["group_id"] for r in rows).items() if n > 1}
    bad = []
    if len(groups) != len(set(groups)):
        bad.append(f"{len(groups) - len(set(groups))} groups appear twice")
    if not (set(groups) & multi):
        bad.append("fixture drew no multi-message group, the check proves nothing")
    return bad


def d3(d):
    rows, sheet, _ = make_fake(d)
    s = read(sheet)
    bad = masking_bad(s, "D3")
    if not any("hxxp" in r["text"] for r in s):
        bad.append("no defanged link in the sheet: the fixture's links should have been defanged")
    ids = [r["id"] for r in rows] + sorted({r["group_id"] for r in rows})
    for r in s:
        if any(i in r["text"] for i in ids):
            bad.append(f"{r['item']}: a message id or group id sits in the text")
    return bad


def d4(d):
    rows, sheet, key = make_fake(d)
    k, bad = read(key), []
    c = Counter(r["label_1"] for r in k)
    if len(k) != D.N or c["scam"] != 10 or c["genuine"] != D.N - 10:
        bad.append(f"expected 10 scam + {D.N - 10} genuine, got {dict(c)}")
    ref_text = {r["id"]: r for r in rows}
    for r in k:
        src = ref_text[r["ref"]]
        if len(src["text"]) > D.MAX_CHARS or src["label"] not in ("0", "1") or src["group_id"] in ("Gfakelongg", "Gfakelongs", "Gfakeskip"):
            bad.append(f"{r['item']}: ref {r['ref']} should have been excluded")
        if r["label_1"] != ("scam" if src["label"] == "1" else "genuine"):
            bad.append(f"{r['item']}: label_1 does not match the preview")
    first = (sheet.read_bytes(), key.read_bytes())
    D.make_real(force=True, preview=d / "preview.csv", sheet=sheet, key=key)
    if first != (sheet.read_bytes(), key.read_bytes()):
        bad.append("a second run with the same seed gave a different sheet")
    return bad


def d5(d):
    _, sheet, key = make_fake(d)
    s = read(sheet)
    s[0]["label_2"] = "scam"
    with open(sheet, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        w.writerows(s)
    bad = []
    try:
        D.make_real(preview=d / "preview.csv", sheet=sheet, key=key)
        bad.append("make_real overwrote a sheet with a label_2 filled in")
    except SystemExit:
        pass
    if read(sheet)[0]["label_2"] != "scam":
        bad.append("the filled label_2 was lost")
    D.make_real(force=True, preview=d / "preview.csv", sheet=sheet, key=key)
    if read(sheet)[0]["label_2"] != "":
        bad.append("--force did not rewrite the sheet")
    return bad


def d6(d):
    if not (D.REAL_SHEET.exists() and D.REAL_KEY.exists() and D.PREVIEW.exists()):
        return []
    s, k = read(D.REAL_SHEET), read(D.REAL_KEY)
    with open(D.REAL_SHEET, encoding="utf-8", newline="") as f:
        header = next(csv.reader(f))
    bad = []
    if header != COLS:
        bad.append(f"real sheet header {header}")
    if len(s) != D.N:
        bad.append(f"real sheet has {len(s)} rows, expected {D.N}")
    gid = {r["id"]: r["group_id"] for r in read(D.PREVIEW)}
    groups = [gid.get(r["ref"]) for r in k]
    if None in groups or len(groups) != len(set(groups)):
        bad.append("real key: a ref is not in the preview, or a group appears twice")
    return bad + masking_bad(s, "D6")


CHECKS = [("D1", "sheet columns, blank label_2, key is a separate file", d1), ("D2", "one row per template group", d2),
          ("D3", "masking: no MISS_RX hit, no live link, no ids in text", d3), ("D4", "selection, exclusions, determinism", d4),
          ("D5", "a filled label_2 is not overwritten without --force", d5), ("D6", "the repo's real sheet (if made) passes the same checks", d6)]


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


def test_double_label():
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
