"""Terminal labeller for data/real/label_me.csv (one row per template group of your own phones' messages). No network, no model.

    .venv/bin/python src/label_real.py                 # buckets 1-3 (label_priority), bucket by bucket, biggest group first
    .venv/bin/python src/label_real.py --max-bucket 4  # also bucket 4

Keys (no Enter needed):  s = scam   g = genuine   k = skip   b = back one (clears the last label you gave and shows that group again)   q = quit.
A paste is ignored whole ("paste ignored - type one key"): if more keys are already waiting when one arrives, none of them counts.
Every key writes label_me.csv at once (temp file + rename), so closing the window, Ctrl-C, a crash or a kill never loses a label, and a rerun starts
at the first group without a label. skip is a label (the group is left out of both halves of the freeze split). If src/intake_real.py rewrites the
sheet while this is open (a new phone file), the next key reloads it and puts this session's labels back before saving.
Each screen shows the bucket and your progress in it, the group's size, which phones it appears on (phone_1, phone_2, ... only), the sender kinds,
and two masked, defanged examples (terminal control characters stripped; the joiners Hindi and Kannada need are kept). No model score is read,
computed or shown. When buckets 1-3 are done the script prints the next commands, ending with the freeze, and stops.
"""
import argparse, contextlib, csv, os, re, select, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABEL_ME = ROOT / "data" / "real" / "label_me.csv"
GUIDE = ("scam = wants money/OTP/click/app under false pretences, incl. betting, shady loans (pay-before-loan, no-CIBIL, random number, APK) · "
         "genuine = real bank/OTP/delivery/bills, normal company promos, loan promos from banks/registered lenders · skip = unsure or examples differ")
WORDS = {"s": "scam", "g": "genuine", "k": "skip"}
BANNED_COLUMNS = ("score", "prob", "pred", "model", "logit")
# C0 / C1 controls (ESC included: no terminal escape sequence from a message reaches the screen), line / paragraph separators, zero-width space,
# LRM / RLM, bidi embeddings and isolates, BOM. ZWNJ / ZWJ (U+200C / U+200D) are kept: Devanagari and Kannada use them to pick a glyph form.
CTRL_RX = re.compile("[\x00-\x1f\x7f-\x9f  ​‎‏‪-‮⁦-⁩﻿]")
PHONE_RX = re.compile(r"phone_\d+")
FREEZE_CMD = ".venv/bin/python src/intake_real.py --freeze --allow-unlabelled"
NEXT_STEPS = f"""Buckets 1-3 are labelled. Next, in this order:
  1. .venv/bin/python src/intake_real.py      # gives every message its group's label, lists name candidates in data/real/review_names.csv
  2. open data/real/review_names.csv: replace_with = <NAME> masks the token, DROP drops its row, ok = not a name; rerun step 1 until none are blank
  3. {FREEZE_CMD}      # ONCE: grouped 50/50 split, TEST frozen, POOL for training; bucket 4 stays out"""


def priority(row):
    v = (row.get("label_priority") or "").strip()
    return int(v) if v in ("1", "2", "3", "4") else 4


def labelled(row):
    return bool((row.get("label") or "").strip())


def stamp(path):
    st = os.stat(path)
    return st.st_mtime_ns, st.st_size, st.st_ino


def load(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    if "group_id" not in fields or "label" not in fields:
        sys.exit(f"{path} has no group_id / label columns (columns: {fields}); run src/intake_real.py first")
    bad = [c for c in fields if any(w in c.lower() for w in BANNED_COLUMNS)]
    if bad:
        sys.exit(f"{path} has a column that looks like model output ({bad}); the labelling sheet must not")
    return fields, rows


def save(path, fields, rows):
    """Write the whole sheet next to the file and rename it over the original: a reader sees the old file or the new one, never half of one."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, lineterminator="\r\n", extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


class Sheet:
    """label_me.csv in memory. set() saves at once; if the file changed on disk since it was read (src/intake_real.py rewrote it), it is read
    again first and every label given in this session is put back on its group."""
    def __init__(self, path):
        self.path, self.session = Path(path), {}
        self.reload()

    def reload(self):
        self.fields, self.rows = load(self.path)
        self.stamp = stamp(self.path)
        for r in self.rows:
            if r["group_id"] in self.session:
                r["label"] = self.session[r["group_id"]]

    def set(self, gid, value):
        self.session[gid] = value
        if stamp(self.path) != self.stamp:
            self.reload()
        hit = [r for r in self.rows if r["group_id"] == gid]
        if not hit:
            raise SystemExit(f"group {gid} is no longer in {self.path.name} (the intake regrouped it); restart the labeller")
        hit[0]["label"] = value
        save(self.path, self.fields, self.rows)
        self.stamp = stamp(self.path)

    def get(self, gid):
        return next((r for r in self.rows if r["group_id"] == gid), None)


def order(rows, max_bucket):
    """The rows to walk: bucket (label_priority) first, then biggest group first."""
    rs = [r for r in rows if priority(r) <= max_bucket]
    return sorted(rs, key=lambda r: (priority(r), -int(r.get("size") or 0), r["group_id"]))


@contextlib.contextmanager
def key_mode(stream):
    """On a terminal: one key at a time, not echoed, for the whole session (Ctrl-C still works); the old settings come back on any exit."""
    if not stream.isatty():
        yield
        return
    import termios, tty
    fd = stream.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def read_key(stream):
    """One key. On a pipe (tests) white space is skipped. '' = end of input."""
    while True:
        ch = stream.read(1)
        if ch == "" or not ch.isspace():
            return ch


PASTE_WAIT = 0.05   # s: more input already waiting this long after a key = a paste, not typing


def _waiting(fd):
    return bool(select.select([fd], [], [], PASTE_WAIT)[0])


class KeyReader:
    """read_key plus a paste guard. On a terminal it reads the raw bytes of the tty (the stdin text wrapper would swallow a whole paste into its own
    buffer, where select() cannot see it) and, if more than the one key arrived or more is waiting after PASTE_WAIT, drains all of it and reports
    pasted=True: the caller applies nothing. On a pipe (tests, scripts) it is read_key and nothing is ever a paste."""
    def __init__(self, stream):
        self.stream = stream
        self.tty = stream.isatty()

    def get(self):
        """(key, pasted). key '' = end of input."""
        if not self.tty:
            return read_key(self.stream), False
        fd = self.stream.fileno()
        data = os.read(fd, 4096)
        if not data:
            return "", False
        pasted = len(data) > 1 or _waiting(fd)
        while pasted and _waiting(fd):
            if not os.read(fd, 4096):
                break
        return ("" if pasted else data.decode("utf-8", "replace")), pasted


def show_text(s):
    return CTRL_RX.sub("", s or "")


def phones_of(sources):
    """'phone_1:35; phone_2:12; wa_1:2' -> 'phone_1 x35, phone_2 x12'. Only the phone labels, never anything else."""
    out = []
    for part in (sources or "").split(";"):
        name, _, n = part.strip().partition(":")
        if PHONE_RX.fullmatch(name):
            out.append(f"{name} x{n}" if n.strip().isdigit() else name)
    return ", ".join(out) or "-"


def screen(r, walk_rows, max_bucket, out, note=""):
    p = priority(r)
    in_bucket = [x for x in walk_rows if priority(x) == p]
    done = sum(labelled(x) for x in in_bucket)
    left = sum(not labelled(x) for x in walk_rows)
    print("\n" + "=" * 100, file=out)
    print(GUIDE, file=out)
    print("-" * 100, file=out)
    print(f"bucket {p}: {done}/{len(in_bucket)}    ({left} left in buckets 1-{max_bucket})    group size {show_text(r.get('size')) or '?'}    "
          f"phones: {phones_of(r.get('sources'))}{note}", file=out)
    print(f"sender kinds: {show_text(r.get('sender_kind_mix')) or '-'}", file=out)
    print(f"example 1: {show_text(r.get('example_1'))}", file=out)
    if (r.get("example_2") or "").strip():
        print(f"example 2: {show_text(r.get('example_2'))}    (similarity to example 1: {show_text(r.get('example_similarity'))})", file=out)
    print("[s] scam   [g] genuine   [k] skip   [b] back   [q] quit > ", end="", file=out, flush=True)


def walk(path, max_bucket=3, stdin=None, out=None):
    """The labelling loop. Returns 'done', 'quit' or 'eof'."""
    stdin, out = stdin or sys.stdin, out or sys.stdout
    sheet = Sheet(path)
    keys = KeyReader(stdin)
    history, forced = [], None   # history: group ids labelled in this session, for b
    if not order(sheet.rows, max_bucket):
        print(f"nothing to label in buckets 1-{max_bucket} of {Path(path).name}", file=out)
        return "done"
    while True:
        walk_rows = order(sheet.rows, max_bucket)
        r = sheet.get(forced) if forced else None
        r = r if r is not None and not labelled(r) else next((x for x in walk_rows if not labelled(x)), None)
        forced = None
        if r is None:
            print("\n" + NEXT_STEPS, file=out)
            return "done"
        screen(r, walk_rows, max_bucket, out)
        while True:
            key, pasted = keys.get()
            if pasted:   # a burst of keys is a paste: nothing in it is an answer, not even a 'q'
                print("\npaste ignored - type one key\n> ", end="", file=out, flush=True)
                continue
            key = key.lower()
            if key in ("", "q", "\x04"):
                print(f"\nsaved. {sum(not labelled(x) for x in walk_rows)} groups left in buckets 1-{max_bucket}.", file=out)
                return "quit" if key else "eof"
            if key in WORDS:
                sheet.set(r["group_id"], WORDS[key])
                history.append(r["group_id"])
                print(WORDS[key], file=out)
                break
            if key == "b":
                if history:
                    gid = history.pop()
                else:   # a fresh session: the group just before this one in the walk
                    before = walk_rows[:walk_rows.index(r)] if r in walk_rows else []
                    prev = [x for x in before if labelled(x)]
                    gid = prev[-1]["group_id"] if prev else None
                if gid is None:
                    print("\nnothing to go back to.", file=out)
                    continue
                was = (sheet.get(gid) or {}).get("label", "")
                sheet.set(gid, "")
                forced = gid
                print(f"back -> previous group (its label was {was or 'blank'})", file=out)
                break
            # any other key is ignored


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", type=Path, default=LABEL_ME)
    ap.add_argument("--max-bucket", type=int, default=3, choices=(1, 2, 3, 4), help="walk buckets up to this label_priority (default 3)")
    a = ap.parse_args()
    for s in (sys.stdout, sys.stdin):
        if hasattr(s, "reconfigure"):
            s.reconfigure(encoding="utf-8")
    if not a.file.exists():
        sys.exit(f"{a.file} does not exist: put the exports in data/real/raw/ and run src/intake_real.py first")
    try:
        with key_mode(sys.stdin):
            walk(a.file, a.max_bucket)
    except KeyboardInterrupt:
        print("\nstopped; every label so far is already saved.")


if __name__ == "__main__":
    main()
