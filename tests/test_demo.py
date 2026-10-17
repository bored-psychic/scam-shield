import hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_demo.py")))   # exec()-ed from the project root there is no __file__: tests/ relative to the cwd
sys.path[:0] = [os.path.join(HERE, "..", "src"), HERE]
from demo_check import evaluate, load_demo
from shield.links.lexical import load_url_model
from shield.messages.text_head import load_text_model

# python tests/test_demo.py   (from the project root; needs both models). Locks the CURRENT behaviour of the 14 illustrative demo messages
# (docs/demo/demo_set.json, reports/demo_check.md), with the default config:
#   S1 the set is exactly the 14 entries below, texts included (SHA-256 over id, kind, type and text), 10 scam + 4 genuine
#   S2 each entry's verdict level is exactly the locked one. A scam entry should be at least Suspicious and a genuine one No warning signs found; an
#      entry that is not is a MISS, and its current level is locked all the same and printed as "KNOWN MISS: <id>", so a change that fixes OR
#      worsens it fails here and has to be looked at on purpose (then update LOCKED and reports/demo_check.md together).
# This is a regression lock on 14 hand-written messages, not an accuracy test: they are illustrative and never count as real data (CLAUDE.md rule 4).
DEMO_SHA256 = "e6f85c7d2dc8a60ee64a33c96663eb6ae631005cbb60847d38645ae7d9f34549"
LOCKED = {"d01": "likely_scam", "d02": "likely_scam", "d03": "likely_scam", "d04": "likely_scam", "d05": "likely_scam",
          "d06": "likely_scam", "d07": "likely_scam", "d08": "likely_scam", "d09": "suspicious", "d10": "likely_scam",
          "g01": "no_warning_signs", "g02": "no_warning_signs", "g03": "no_warning_signs", "g04": "no_warning_signs"}


def set_problems(entries):
    """S1."""
    bad = []
    if [e["id"] for e in entries] != list(LOCKED):
        bad.append(f"ids {[e['id'] for e in entries]}, wanted {list(LOCKED)}")
    if any(set(e) != {"id", "kind", "type", "text"} for e in entries):
        bad.append("an entry does not have exactly the keys id, kind, type, text")
    kinds = [e["kind"] for e in entries]
    if kinds.count("scam") != 10 or kinds.count("genuine") != 4:
        bad.append(f"{kinds.count('scam')} scam / {kinds.count('genuine')} genuine entries, wanted 10 / 4")
    blob = json.dumps([[e["id"], e["kind"], e["type"], e["text"]] for e in entries], ensure_ascii=False, separators=(",", ":"))
    if hashlib.sha256(blob.encode("utf-8")).hexdigest() != DEMO_SHA256:
        bad.append("the demo texts changed (SHA-256 differs from DEMO_SHA256)")
    return bad


def level_problem(row):
    """S2: None when the entry's level is the locked one."""
    if row["level"] != LOCKED[row["id"]]:
        return f"level {row['level']}, locked {LOCKED[row['id']]} (entry was {row['status']})"
    return None


def run():
    entries = load_demo()
    tm, um = load_text_model(), load_url_model()
    return entries, [evaluate(e, tm, um) for e in entries]


def test_demo():
    entries, rows = run()
    bad = set_problems(entries)
    bad += [f"{r['id']}: {p}" for r in rows if (p := level_problem(r))]
    assert not bad, "\n".join(bad)


if __name__ == "__main__":
    entries, rows = run()
    n_bad = 0
    for p in set_problems(entries):
        n_bad += 1
        print(f"FAIL S1 {p}")
    if not n_bad:
        print(f"PASS S1 {len(entries)} entries, texts unchanged")
    for r in rows:
        p = level_problem(r)
        n_bad += bool(p)
        print(f"{'FAIL' if p else 'PASS'} S2 {r['id']} {r['type']:<15} level={r['level']} (entry {r['status']})" + (f"  <- {p}" if p else ""))
        if r["status"] == "MISS":
            print(f"KNOWN MISS: {r['id']}")
    n_miss = sum(r["status"] == "MISS" for r in rows)
    print(f"\n{len(rows) - n_miss} of {len(rows)} entries behave as expected, {n_miss} known miss(es); {n_bad} test failure(s)")
    sys.exit(1 if n_bad else 0)
