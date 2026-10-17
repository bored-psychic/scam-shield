import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from shield.core.router import analyse, safety_advice_cap
from shield.links.lexical import load_url_model
from shield.messages.rules import cred_requests
from shield.messages.tactics import tactic_tags
from shield.messages.text_head import load_text_model
from textprep import extract_urls, model_text
from tricky_inputs import INPUTS

# python tests/test_tricky_inputs.py [--no-models]   (from the project root). Rule checks always run; verdict-level checks need the two
# models and are skipped (and said so) when they can't load, e.g. models/text_baseline.joblib is missing or predates <URL> preprocessing.
# The verdict-level checks run twice, with the safety-advice cap forced OFF and ON (analyse(..., safety_cap=...)), so every expectation holds whichever
# way config.SAFETY_ADVICE_CAP is set; the cap only ever lowers Suspicious, so a min_level that a rule guarantees must survive it.
def _models():
    try:
        return load_text_model(), load_url_model()
    except SystemExit as e:
        print(f"[skip level checks] {e}")
        return None, None

def check(entry, tm, um):
    t, e, bad = entry["text"], entry["expect"], []
    cred = cred_requests(t)
    tags = {k: bool(v) for k, v in tactic_tags(t, cred).items()}
    if "cred_request" in e and bool(cred) != e["cred_request"]:
        bad.append(f"cred_request {bool(cred)} (hits {cred}), wanted {e['cred_request']}")
    bad += [f"tag {k} missing" for k in e.get("tags", []) if not tags[k]]
    bad += [f"tag {k} present" for k in e.get("no_tags", []) if tags[k]]
    if "urls" in e and extract_urls(t) != e["urls"]:
        bad.append(f"urls {extract_urls(t)}, wanted {e['urls']}")
    prep = model_text(t, mask_pii=True)
    bad += [f"model_text lacks {s!r}: {prep!r}" for s in e.get("prep_has", []) if s not in prep]
    bad += [f"model_text still has {s!r}: {prep!r}" for s in e.get("prep_lacks", []) if s in prep]
    if tm is not None and "cap_blocked_by" in e:
        _, blockers = safety_advice_cap(t, analyse(t, tm, um, safety_cap=False))
        bad += [f"cap not blocked by {b!r} (blockers: {blockers})" for b in e["cap_blocked_by"] if b not in blockers]
    if tm is not None and ("min_level" in e or "link_kinds" in e or "no_safety_advice" in e):
        for cap in (False, True):
            r, tag = analyse(t, tm, um, safety_cap=cap), f"[cap {'on' if cap else 'off'}] "
            if "link_kinds" in e and [l["kind"] for l in r["links"]] != e["link_kinds"]:
                bad.append(f"{tag}link kinds {[l['kind'] for l in r['links']]}, wanted {e['link_kinds']}")
            if "min_level" in e and (r["level"] is None or r["level"] < e["min_level"]):
                bad.append(f"{tag}level {r['level']}, wanted >= {e['min_level']}")
            if e.get("no_safety_advice") and r.get("safety_advice") is not None:
                bad.append(f"{tag}the safety-advice cap fired on {r['safety_advice']}")
    return bad

def test_tricky_inputs():
    tm, um = (None, None) if "--no-models" in sys.argv else _models()
    failures = {x["id"]: b for x in INPUTS if (b := check(x, tm, um))}
    assert not failures, "\n".join(f"{k}: {'; '.join(v)}" for k, v in failures.items())

if __name__ == "__main__":
    tm, um = (None, None) if "--no-models" in sys.argv else _models()
    n_bad = 0
    for x in INPUTS:
        bad = check(x, tm, um)
        n_bad += bool(bad)
        print(("FAIL " if bad else "ok   ") + x["id"] + ("" if not bad else "  <- " + "; ".join(bad)))
    print(f"\n{len(INPUTS) - n_bad}/{len(INPUTS)} passed" + ("" if tm else " (level / link-kind checks skipped)"))
    sys.exit(1 if n_bad else 0)
