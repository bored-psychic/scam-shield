"""W1 golden comparison (docs/plans/multi_input.md section 8.1, CT08): proves that the schema-6 refactor (reasons_from, assess_links, the new
Report.input / details fields, advice_for(input=...)) changes nothing the message path produces.

    SHIELD_TEXT_DEVICE=cpu [SHIELD_TEXT_HEAD=baseline] .venv/bin/python tests/golden_w1.py run before|after
    .venv/bin/python tests/golden_w1.py compare [muril] [baseline]   (counts only; writes reports/golden_w1.md)

`run` analyses four sets with live=False (no link is ever opened; sockets are patched to refuse every connection) and writes one JSON line per
input to /tmp/golden_w1/<phase>_<head>.jsonl (outside the repo: it contains message text):
    (a) contract: every input tests/test_contracts.py uses (tricky + examples + its 300 val rows + 3 extras + 2 probes)
    (b) demo: docs/demo/demo_set.json (14)    (c) tricky: tests/tricky_inputs.py    (d) val: every splits-v2 VAL row of data/final/messages.csv
        (via split_map.csv; 5,267). Test rows are dropped while reading and never looked at.
Per input: "router" = the exact router.analyse() dict (JSON, sorted keys) and "report" = to_report(text, r) as JSON. `compare` requires the
routers to be equal and the Reports to be equal once schema_version and input are removed. Any difference is a bug in the refactor.

--write-ct08 (with `run before`) also writes tests/fixtures/ct08_v5_digests.json: per head and per contract input, SHA-256 of the text -> SHA-256
of (level, reasons, advice, risk_score) from the schema-5 code. tests/test_contracts.py CT08 reads it. Hashes only, no message text.
"""
import contextlib, hashlib, json, os, re, socket, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path[:0] = [os.path.join(ROOT, "src"), HERE]

OUT_DIR = "/tmp/golden_w1"
SETS = ("contract", "demo", "tricky", "val")
CT08_PATH = os.path.join(HERE, "fixtures", "ct08_v5_digests.json")
REPORT_PATH = os.path.join(ROOT, "reports", "golden_w1.md")


def jsonable(o):
    """The exact content of an analyse() dict as plain JSON types. Anything unknown is an error, never a repr (a repr could hide a difference)."""
    if o is None or isinstance(o, (bool, int, str)):
        return o
    if isinstance(o, float):
        return o if o == o else "nan"
    if isinstance(o, dict):
        return {str(k): jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [jsonable(v) for v in o]
    if isinstance(o, (set, frozenset)):
        return sorted((jsonable(v) for v in o), key=json.dumps)
    if hasattr(o, "to_dict") and hasattr(o, "columns"):   # pandas DataFrame (the URL model's occlusion breakdown): index, columns and every cell
        return {"__type__": "DataFrame", **jsonable(o.to_dict(orient="split"))}
    if hasattr(o, "to_dict") and hasattr(o, "index"):   # pandas Series
        return {"__type__": "Series", **jsonable(o.to_dict())}
    if hasattr(o, "item") and hasattr(o, "dtype"):   # numpy scalar
        return jsonable(o.item())
    if hasattr(o, "value") and hasattr(type(o), "__members__"):   # Enum
        return jsonable(o.value)
    if hasattr(o, "__dataclass_fields__"):
        return {"__type__": type(o).__name__, **{k: jsonable(getattr(o, k)) for k in o.__dataclass_fields__}}
    if hasattr(type(o), "__slots__"):
        return {"__type__": type(o).__name__, **{k: jsonable(getattr(o, k)) for k in type(o).__slots__}}
    raise TypeError(f"golden_w1: cannot serialise {type(o).__name__}")


def dumps(o):
    return json.dumps(jsonable(o), sort_keys=True, ensure_ascii=False)


def val_rows():
    """(id, text) of every splits-v2 val row. Rows of other splits are dropped chunk by chunk and never kept."""
    import pandas as pd
    sm = pd.read_csv(os.path.join(ROOT, "data", "final", "split_map.csv"))
    val = set(sm.loc[sm["split"] == "val", "text_hash"])
    out = []
    for chunk in pd.read_csv(os.path.join(ROOT, "data", "final", "messages.csv"), usecols=["text", "text_hash"], chunksize=5000):
        keep = chunk[chunk["text_hash"].isin(val)]
        out += [(f"val-{h[:12]}", t) for h, t in zip(keep["text_hash"], keep["text"])]
    return out


def collect():
    import test_contracts as tc
    from demo_check import load_demo
    from tricky_inputs import INPUTS
    contract = [(f"{k}:{n}", t) for k, n, t in tc.inputs()] + [(f"probe:{n}", t) for n, t in tc.PROBES]
    return {"contract": contract, "demo": [(f"demo-{d['id']}", d["text"]) for d in load_demo()],
            "tricky": [(x["id"], x["text"]) for x in INPUTS], "val": val_rows()}


@contextlib.contextmanager
def no_network():
    """live=False must never connect; make any attempt an error rather than a silent success."""
    saved = {n: getattr(socket, n) for n in ("create_connection", "getaddrinfo", "gethostbyname")}
    saved_methods = {n: socket.socket.__dict__.get(n) for n in ("connect", "connect_ex")}
    def refuse(*a, **k):
        raise OSError("golden_w1: outbound network call blocked")
    try:
        for n in saved:
            setattr(socket, n, refuse)
        for n in saved_methods:
            setattr(socket.socket, n, refuse)
        yield
    finally:
        for n, f in saved.items():
            setattr(socket, n, f)
        for n, f in saved_methods.items():
            delattr(socket.socket, n) if f is None else setattr(socket.socket, n, f)


def run(phase, write_ct08):
    from shield import config
    from shield.core.report import to_report
    from shield.core.router import analyse
    from shield.links.lexical import load_url_model
    from shield.messages.text_head import load_text_model
    head = config.text_head_choice()[0]
    tm, um = load_text_model(), load_url_model()
    sets = collect()
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, f"{phase}_{'baseline' if head == config.TEXT_MODEL_KIND else 'muril'}.jsonl")
    counts, digests = {}, {}
    with no_network(), open(path, "w", encoding="utf-8") as f:
        for name in SETS:
            for id_, text in sets[name]:
                r = analyse(text, tm, um, live=False)
                rep = to_report(text, r)
                f.write(json.dumps({"set": name, "id": id_, "router": dumps(r), "report": rep.model_dump_json()}, ensure_ascii=False) + "\n")
                counts[name] = counts.get(name, 0) + 1
                if name == "contract":
                    d = rep.model_dump(mode="json")
                    digests[hashlib.sha256(text.encode("utf-8")).hexdigest()] = hashlib.sha256(
                        json.dumps([d["level"], d["reasons"], d["advice"], d["risk_score"]], ensure_ascii=False).encode("utf-8")).hexdigest()
    print(f"head {head}: wrote {path}")
    for name in SETS:
        print(f"  {name:<9}{counts.get(name, 0):>6} inputs")
    if write_ct08:
        os.makedirs(os.path.dirname(CT08_PATH), exist_ok=True)
        data = json.load(open(CT08_PATH)) if os.path.exists(CT08_PATH) else {}
        data[head] = dict(sorted(digests.items()))
        json.dump(data, open(CT08_PATH, "w"), indent=0, sort_keys=True)
        print(f"  CT08 digests for head {head}: {len(digests)} -> {os.path.relpath(CT08_PATH, ROOT)}")


# The one thing that differs between two honest runs of the same code: the link-list freshness phrase of the "Website details" facts ("OpenPhish updated 0 h
# ago", shield.links.reputation, computed from the wall clock), because the before and after runs are hours apart. Only this phrase is ignored, and every
# occurrence is counted and printed.
AGE_RX = re.compile(r"updated \d+ (h|days) ago")

def strip(report_json):
    """The Report as a dict without what schema 6 added, on the Report and on every child: schema_version, input, and details when it is null."""
    def clean(d):
        d.pop("schema_version", None)
        d.pop("input", None)
        if d.get("details", 0) is None:
            d.pop("details")
        for c in d.get("children", []):   # every child (link) Report carries the same three keys
            clean(c)
        return d
    return clean(json.loads(report_json))

def norm(text):
    """(text with the freshness phrase's number replaced, how many were replaced)."""
    return AGE_RX.subn(lambda m: f"updated N {m.group(1)} ago", text)


def compare(heads=("muril", "baseline")):
    rows, lines, total_diff = [], [], 0
    for head in heads:
        b, a = (os.path.join(OUT_DIR, f"{p}_{head}.jsonl") for p in ("before", "after"))
        if not (os.path.exists(b) and os.path.exists(a)):
            print(f"head {head}: missing {b if not os.path.exists(b) else a}")
            total_diff += 1
            continue
        per = {s: [0, 0, 0, 0, 0] for s in SETS}   # compared, router differences, report differences, freshness phrases ignored, inputs where only that phrase differs
        n_b, n_a = (sum(1 for _ in open(p, encoding="utf-8")) for p in (b, a))
        assert n_b == n_a, f"head {head}: the two runs have different lengths ({n_b} vs {n_a})"
        with open(b, encoding="utf-8") as fb, open(a, encoding="utf-8") as fa:
            for lb, la in zip(fb, fa):
                x, y = json.loads(lb), json.loads(la)
                assert (x["set"], x["id"]) == (y["set"], y["id"]), "the two runs list different inputs"
                c = per[x["set"]]
                c[0] += 1
                (rx, nx), (ry, ny) = norm(x["router"]), norm(y["router"])
                (px, mx), (py, my) = norm(json.dumps(strip(x["report"]), sort_keys=True)), norm(json.dumps(strip(y["report"]), sort_keys=True))
                c[1] += rx != ry
                c[2] += px != py
                c[3] += nx + ny + mx + my
                c[4] += (x["router"] != y["router"]) or (json.dumps(strip(x["report"]), sort_keys=True) != json.dumps(strip(y["report"]), sort_keys=True))
        for s in SETS:
            rows.append((s, head, *per[s]))
            total_diff += per[s][1] + per[s][2]
    print(f"{'set':<10}{'head':<10}{'inputs':>8}{'router diff':>13}{'report diff':>13}{'age phrases':>13}{'age-only inputs':>17}")
    for s, h, n, dr, dp, ages, age_only in rows:
        print(f"{s:<10}{h:<10}{n:>8}{dr:>13}{dp:>13}{ages:>13}{age_only:>17}")
    print(f"\ntotal differences: {total_diff}")
    md = ["# W1 golden comparison (counts only)", "",
          "Schema 6 refactor (`reasons_from`, `assess_links`, `Report.input` / `details`, `advice_for(input=)`) against the code of master before W1.",
          "Both heads, `live=False`, `SHIELD_TEXT_DEVICE=cpu`; sockets patched to refuse every connection. Per input the exact `router.analyse()` dict",
          "(JSON, sorted keys) and the `to_report` Report JSON were stored outside the repo (`/tmp/golden_w1/`, it holds message text); the routers must",
          "be equal and the Reports equal once `schema_version`, `input` and a null `details` are removed (on the Report and on every child). Generated by `python tests/golden_w1.py compare`.", "",
          "| set | head | inputs compared | router differences | Report differences | list-age phrases ignored | inputs that differ only in that phrase |",
          "|---|---|---:|---:|---:|---:|---:|"]
    md += [f"| {s} | {h} | {n:,} | {dr} | {dp} | {ages:,} | {age_only:,} |" for s, h, n, dr, dp, ages, age_only in rows]
    md += ["", f"**Total differences: {total_diff}.**", "",
           "The comparison ignores exactly one phrase, the list-freshness text of the link facts (`updated N h ago` / `updated N days ago`, `shield.links.reputation`),",
           "because it is computed from the wall clock and the two runs were hours apart. The last two columns count how often it was ignored; nothing else differs.", "",
           "Sets: contract = every input of `tests/test_contracts.py` (tricky + examples + its 300 val rows + 3 extras + 2 probes); demo = `docs/demo`;",
           "tricky = `tests/tricky_inputs.py`; val = every splits-v2 val row of `messages.csv` (via `split_map.csv`). Test rows were never read into the run."]
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    open(REPORT_PATH, "w").write("\n".join(md) + "\n")
    sys.exit(1 if total_diff else 0)


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["compare"]:
        compare(tuple(args[1:]) or ("muril", "baseline"))
    elif args[:1] == ["run"] and len(args) >= 2 and args[1] in ("before", "after"):
        run(args[1], "--write-ct08" in args)
    else:
        sys.exit(__doc__)
