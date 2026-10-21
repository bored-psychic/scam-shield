import hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(globals().get("__file__", "tests/test_demo.py")))   # exec()-ed from the project root there is no __file__: tests/ relative to the cwd
sys.path[:0] = [os.path.join(HERE, "..", "src"), HERE]
from demo_check import evaluate, load_demo
from shield import config
from shield.links.lexical import load_url_model
from shield.messages.text_head import load_text_model

# python tests/test_demo.py   (from the project root; needs both models). Locks the CURRENT behaviour of the 14 illustrative demo messages
# (docs/demo/demo_set.json, reports/demo_check.md), with the default config:
#   S1 the set is exactly the 14 entries below, texts included (SHA-256 over id, kind, type and text), 10 scam + 4 genuine
#   S2 each entry's verdict level is exactly the locked one. A scam entry should be at least Suspicious and a genuine one No warning signs found; an
#      entry that is not is a MISS, and its current level is locked all the same and printed as "KNOWN MISS: <id>", so a change that fixes OR
#      worsens it fails here and has to be looked at on purpose (then update LOCKED and reports/demo_check.md together).
#   S3 d03 is caught by the PIN-to-receive rule (R2, 2026-10-17): its Report has a danger rule.pin_to_receive evidence with the exact title, tag and quote below,
#      and that title is its first reason. No other demo entry carries that evidence. (Its LEVEL did not change: the wording model already said Likely scam.)
# This is a regression lock on 14 hand-written messages, not an accuracy test: they are illustrative and never count as real data (CLAUDE.md rule 4).
DEMO_SHA256 = "e6f85c7d2dc8a60ee64a33c96663eb6ae631005cbb60847d38645ae7d9f34549"
# One lock per text head (D27): the levels the app gives with that head loaded (config.text_head_choice()). TF-IDF: the 2026-10-17 lock, 14 of 14.
# MuRIL (2026-10-21): the same except g03, the genuine Amazon delivery message, which MuRIL flags Suspicious (score 0.162, cut-off 0.103): a KNOWN MISS,
# accepted under the val flag policy of reports/calibration_muril_v2.md (MuRIL flags 1.56% of val benign messages at Suspicious-or-above, the baseline 4.06%).
LOCKS = {config.TEXT_MODEL_KIND: {"d01": "likely_scam", "d02": "likely_scam", "d03": "likely_scam", "d04": "likely_scam", "d05": "likely_scam",
                                  "d06": "likely_scam", "d07": "likely_scam", "d08": "likely_scam", "d09": "suspicious", "d10": "likely_scam",
                                  "g01": "no_warning_signs", "g02": "no_warning_signs", "g03": "no_warning_signs", "g04": "no_warning_signs"}}
LOCKS[config.MURIL_KIND] = {**LOCKS[config.TEXT_MODEL_KIND], "g03": "suspicious"}
LOCKED = LOCKS[config.text_head_choice()[0]]

RULE_EVIDENCE = {"d03": ("PIN to receive", "enter your UPI PIN to receive", "Asks for your UPI PIN to receive money (receiving money never needs a PIN)")}


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


def rule_problems(rows):
    """S3."""
    bad, by_id = [], {r["id"]: r for r in rows}
    for id_, (tag, quote, title) in RULE_EVIDENCE.items():
        found = [e for e in by_id[id_]["report"].evidence if e.id == "rule.pin_to_receive"]
        if len(found) != 1:
            bad.append(f"{id_}: {len(found)} rule.pin_to_receive evidence, wanted 1")
            continue
        e = found[0]
        if (e.effect.value, e.tag, e.title) != ("danger", tag, title) or e.quote != quote:
            bad.append(f"{id_}: evidence (effect {e.effect.value}, tag {e.tag!r}, quote {e.quote!r}, title {e.title!r}), wanted (danger, {tag!r}, {quote!r}, {title!r})")
        if by_id[id_]["reasons"][:1] != [title]:
            bad.append(f"{id_}: first reason {by_id[id_]['reasons'][:1]}, wanted {[title]}")
    carriers = [r["id"] for r in rows if any(e.id == "rule.pin_to_receive" for e in r["report"].evidence)]
    if carriers != list(RULE_EVIDENCE):
        bad.append(f"entries carrying rule.pin_to_receive: {carriers}, wanted {list(RULE_EVIDENCE)}")
    return bad


def run():
    entries = load_demo()
    tm, um = load_text_model(), load_url_model()
    return entries, [evaluate(e, tm, um) for e in entries]


def test_demo():
    entries, rows = run()
    bad = set_problems(entries)
    bad += [f"{r['id']}: {p}" for r in rows if (p := level_problem(r))]
    bad += rule_problems(rows)
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
    for p in rule_problems(rows):
        n_bad += 1
        print(f"FAIL S3 {p}")
    if not rule_problems(rows):
        print(f"PASS S3 {' '.join(RULE_EVIDENCE)}: rule.pin_to_receive evidence, first reason; no other entry carries it")
    n_miss = sum(r["status"] == "MISS" for r in rows)
    print(f"\n{len(rows) - n_miss} of {len(rows)} entries behave as expected, {n_miss} known miss(es); {n_bad} test failure(s)")
    sys.exit(1 if n_bad else 0)
