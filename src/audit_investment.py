"""Investment / trading / task-scam audit (docs/plans/investment_scams.md). Measurement only: no detection code, nothing here changes the app.

    .venv/bin/python src/audit_investment.py            # all four parts -> reports/investment_audit.md (+ the CSVs below)
    .venv/bin/python src/audit_investment.py --no-probe # skip scoring the probe (no MuRIL load)

1. Inventory: rows of data/final/messages.csv about investment / trading / stock tips / IPO / crypto and task / part-time-job scams, found by
   keyword (INVEST_RX, CRYPTO_RX, TASK_RX below) and by category (india_fraud_final's *_Task subcategories), counted by source, split, label.
   TEST ROWS ARE NEVER READ: the CSV is streamed and a row whose split is 'test' is dropped before its text is looked at (CLAUDE.md rule 1).
   Likely mislabelled rows (scam-group chat labelled genuine, GROUP_RX) -> reports/investment_mislabel_candidates.csv (row ids only).
2. Val subset: the EXISTING val predictions (reports/eval_preds/<model>/predictions_val.csv, MuRIL's bundle score and the splits-v2 baseline),
   at each model's own val cut-offs (scored.json). Nothing is re-scored.
3. Probe: data/probe/investment_v1.csv (PROBE-ONLY, eval only; src/realguard.py refuses it as a training input) through both text heads
   and the full router (shield.core.router.analyse, live=False: no network). Scores -> reports/investment_probe_v1_scores.csv (no text).
4. Rule feasibility: each RULES regex counted on the probe scams / genuine rows and on the val genuine rows of the short-message sources.
   Regexes only; none of them is in the app.
"""
import argparse, csv, json, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]
csv.field_size_limit(sys.maxsize)

MESSAGES = ROOT / "data" / "final" / "messages.csv"
PROBE = ROOT / "data" / "probe" / "investment_v1.csv"
PREDS = {"MuRIL": ROOT / "reports" / "eval_preds" / "muril_len128_20261021T135255Z",
         "baseline (splits-v2)": ROOT / "reports" / "eval_preds" / "baseline_splits_v2"}
REPORT = ROOT / "reports" / "investment_audit.md"
MISLABEL_OUT = ROOT / "reports" / "investment_mislabel_candidates.csv"
PROBE_OUT = ROOT / "reports" / "investment_probe_v1_scores.csv"

# short-message sources (SMS / chat / India); the two long-form sources are counted apart, their keyword hits are mostly off-topic
SHORT = ["india_fraud_final", "scam_ham_india", "synth_india", "translated_indic", "web_scams", "uci_sms_spam", "hinglish_conversations",
         "cmu_hinglish_dog", "scam_dialogue", "ealvaradob_phishing"]
LONG = ["phishing_email", "fake_job_postings"]
TASK_SUBCATS = {"VIP_Task", "Investment_Task", "YouTube_Task", "Survey_Task", "eBay_Task", "Instagram_Task", "TikTok_Task"}

F = re.I
INVEST_RX = re.compile(
    r"\b(stock market|share market|share bazaar|stock tips?|stock (?:picks?|names?|selection|recommendations?)|recommended stocks?|"
    r"(?<!fresh )(?<!limited )(?<!new )stocks\b(?! (?:runs?|run out|added|lasts?))|(?:this|the|a|which|our|that) stock\b(?! (?:runs?|run out|lasts?))|"
    r"stock (?:price|analysis|exchange|indices|community)|intraday|nifty|bank ?nifty|sensex|demat|multibagger|f&o|"
    r"ipos?|mutual funds?|sip|sebi|trading (?:account|group|app|platform|tips?|calls?|signals?|skills)|upper circuit|block (?:deal|trade)s?|"
    r"pre-?allot\w*|institutional (?:account|trading)|(?:guaranteed|assured|fixed) (?:monthly )?returns?|double your money)\b", F)
CRYPTO_RX = re.compile(r"\b(crypto(?:currency)?|bitcoin|btc|usdt|ethereum|binance|forex)\b", F)
TASK_RX = re.compile(
    r"\b(part[- ]?time (?:jobs?|work|online)|work from home|simple tasks?|prepaid tasks?|(?:like|liking|watch(?:ing)?) (?:youtube )?videos?|"
    r"hotel (?:reviews?|ratings?)|rating tasks?|grab orders?|(?:daily|per day|a day|every day) (?:income|earning|salary)|"
    r"earn (?:rs\.?|₹|inr)?\s?\d[\d,]*(?:\s?-\s?\d[\d,]*)?\s*(?:rs|rupees)?\s*(?:/-)?\s*(?:daily|per day|a day|every day))", F)
# scam-group markers: the WhatsApp 'stock-advisor group' pattern (a professor / master / teacher, an assistant, recommended stocks, the group)
GROUP_RX = re.compile(
    r"\b(professor|prof\.?|master|teacher|mr\.'s|assistant|group members|members of the group|in the group|the group|our team|stock community|"
    r"recommend(?:ed|s|ing)? (?:stocks?|the stock|early morning stocks)|stocks? (?:recommended|selected)|internal stock|official group|"
    r"courseware|check-in|sharing session|technical sharing|momentum stocks|strong stocks|bull stocks|trading instructions|next instruction|"
    r"buying and selling points|join me|follow the professor)\b", F)

LEVEL = {0: "No warning signs", 1: "Suspicious", 2: "Likely scam"}


def stream_non_test(path=MESSAGES):
    """Rows of messages.csv whose split is train or val. A test row is skipped before any other field of it is used."""
    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["split"] == "test":
                continue
            yield r


def topics(r):
    t = r["text"]
    out = []
    if INVEST_RX.search(t):
        out.append("invest")
    if CRYPTO_RX.search(t):
        out.append("crypto")
    if TASK_RX.search(t) or r["subcategory"] in TASK_SUBCATS:
        out.append("task")
    return out


# ---------------------------------------------------------------- 1. inventory
def inventory():
    rows = []
    for r in stream_non_test():
        tp = topics(r)
        if tp:
            rows.append({"hash": r["text_hash"], "source": r["source"], "split": r["split"], "label": int(r["label"]), "topics": tp,
                         "subcat_task": r["subcategory"] in TASK_SUBCATS, "group": bool(GROUP_RX.search(r["text"])),
                         "kw_task": bool(TASK_RX.search(r["text"])), "text": r["text"]})
    return rows


def mislabel_candidates(rows):
    """Genuine-labelled short-message rows that read as part of an investment / task scam. Rule names say why."""
    out = []
    for r in rows:
        if r["label"] != 0 or r["source"] not in SHORT:
            continue
        if "invest" in r["topics"] and r["group"]:
            out.append((r["hash"], r["split"], r["source"], "stock-group chat (GROUP_RX)"))
        elif "task" in r["topics"] and re.search(r"earn|salary|join|whatsapp|telegram|click", r["text"], F):
            out.append((r["hash"], r["split"], r["source"], "task / part-time offer"))
        elif "invest" in r["topics"] and r["source"] == "scam_ham_india":
            out.append((r["hash"], r["split"], r["source"], "uncertain: market chat in the same source, no group marker"))
    return out


# ---------------------------------------------------------------- 2. val subset
def load_preds():
    out = {}
    for name, d in PREDS.items():
        meta = json.loads((d / "scored.json").read_text())
        with open(d / "predictions_val.csv", encoding="utf-8", newline="") as f:
            sc = {r["text_hash"]: float(r["score"]) for r in csv.DictReader(f)}
        out[name] = (sc, meta["threshold_suspicious"], meta["threshold_likely"])
    return out


def level(score, ts, tl):
    return 2 if score >= tl else 1 if score >= ts else 0


def val_table(rows, preds, mislabels):
    """Per group of val rows: n scams, recall at >= Suspicious and at Likely; n genuine, false alarms at >= Suspicious and at Likely."""
    mis = {h for h, *_ in mislabels}
    val = [r for r in rows if r["split"] == "val"]
    groups = {
        "investment / stock (short-message sources)": [r for r in val if "invest" in r["topics"] and r["source"] in SHORT],
        "task / part-time (short-message sources)": [r for r in val if "task" in r["topics"] and r["source"] in SHORT],
        "crypto (all sources)": [r for r in val if "crypto" in r["topics"]],
        "investment keywords, phishing_email (US stock spam)": [r for r in val if "invest" in r["topics"] and r["source"] == "phishing_email"],
        "task keywords, fake_job_postings": [r for r in val if "task" in r["topics"] and r["source"] == "fake_job_postings"],
    }
    lines = ["| val subset | model | scams | caught >= Suspicious | caught Likely | genuine | false alarms >= Suspicious | false alarms Likely |",
             "|---|---|---|---|---|---|---|---|"]
    for gname, g in groups.items():
        for m, (sc, ts, tl) in preds.items():
            s = [level(sc[r["hash"]], ts, tl) for r in g if r["label"] == 1]
            b = [level(sc[r["hash"]], ts, tl) for r in g if r["label"] == 0 and r["hash"] not in mis]
            lines.append(f"| {gname} | {m} | {len(s)} | {frac(sum(x >= 1 for x in s), len(s))} | {frac(sum(x == 2 for x in s), len(s))} | "
                         f"{len(b)} | {frac(sum(x >= 1 for x in b), len(b))} | {frac(sum(x == 2 for x in b), len(b))} |")
    lines.append("")
    reason = {h: why for h, _, _, why in mislabels}
    for tier, keep in (("likely mislabelled (scam-group chat labelled genuine)", lambda w: not w.startswith("uncertain")),
                       ("uncertain (market chat in the same source, no group marker)", lambda w: w.startswith("uncertain"))):
        ml = [r for r in val if r["hash"] in reason and keep(reason[r["hash"]])]
        lines.append(f"Val rows {tier}, left out of the genuine columns above: {len(ml)}. If they are scams, this is recall on them:")
        for m, (sc, ts, tl) in preds.items():
            lv = [level(sc[r["hash"]], ts, tl) for r in ml]
            lines.append(f"- {m}: flagged >= Suspicious {frac(sum(x >= 1 for x in lv), len(lv))}, Likely {frac(sum(x == 2 for x in lv), len(lv))}")
        lines.append("")
    return lines, groups


def frac(k, n):
    return f"{k}/{n} ({k / n:.0%})" if n else "0/0"


# ---------------------------------------------------------------- 3. probe
def read_probe():
    with open(PROBE, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def score_probe(probe):
    from shield import config
    from shield.core import router
    from shield.links.gambling import load_gambling
    from shield.links.lexical import load_url_model
    from shield.links.lists import warm as warm_lists
    from shield.messages.text_head import MurilScorer, load_baseline
    load_gambling()
    warm_lists()
    url_model = load_url_model()
    heads = {"MuRIL": MurilScorer(config.MURIL_DIR, config.TEXT_DEVICE), "baseline": load_baseline()}
    out = []
    for r in probe:
        row = {k: r[k] for k in ("id", "label", "kind", "provenance", "language")}
        for name, head in heads.items():
            res = router.analyse(r["text"], head, url_model, live=False)
            key = "muril" if name == "MuRIL" else "baseline"
            row[f"{key}_text_score"] = res["text_score"]
            row[f"{key}_text_level"] = res["text_level"]
            row[f"{key}_router_level"] = res["level"]
            row[f"{key}_escalated"] = res["escalated"]
            row[f"{key}_url_level"] = res["url_level"]
        out.append(row)
    return out


def probe_tables(scored, probe):
    by_id = {r["id"]: r for r in probe}
    lines = ["| set | head | scams | text head >= Suspicious | router >= Suspicious | router Likely | genuine | router false alarms >= Suspicious | router false alarms Likely |",
             "|---|---|---|---|---|---|---|---|---|"]
    subsets = {"all": lambda r: True, "quoted (verbatim + fragments)": lambda r: r["provenance"] in ("verbatim_quote", "quote_fragments"),
               "written from a cited source": lambda r: r["provenance"] == "written_from_source"}
    for sname, keep in subsets.items():
        for key, name in (("muril", "MuRIL"), ("baseline", "baseline (app, splits-v1)")):
            s = [r for r in scored if r["label"] == "1" and keep(r)]
            g = [r for r in scored if r["label"] == "0"] if sname == "all" else []
            tl = lambda r: (r[f"{key}_text_level"] or 0)
            rl = lambda r: (r[f"{key}_router_level"] or 0)
            lines.append(f"| {sname} | {name} | {len(s)} | {frac(sum(tl(r) >= 1 for r in s), len(s))} | {frac(sum(rl(r) >= 1 for r in s), len(s))} | "
                         f"{frac(sum(rl(r) == 2 for r in s), len(s))} | {len(g) if g else '-'} | "
                         f"{frac(sum(rl(r) >= 1 for r in g), len(g)) if g else '-'} | {frac(sum(rl(r) == 2 for r in g), len(g)) if g else '-'} |")
    # per kind, MuRIL router
    kinds = defaultdict(list)
    for r in scored:
        kinds[(r["label"], r["kind"])].append(r)
    klines = ["| label | kind | rows | MuRIL router >= Suspicious | baseline router >= Suspicious |", "|---|---|---|---|---|"]
    for (lab, kind), rs in sorted(kinds.items(), key=lambda t: (t[0][0] != "1", t[0][1])):
        klines.append(f"| {'scam' if lab == '1' else 'genuine'} | {kind} | {len(rs)} | {sum((r['muril_router_level'] or 0) >= 1 for r in rs)} | "
                      f"{sum((r['baseline_router_level'] or 0) >= 1 for r in rs)} |")
    # 10 worst misses: scams the MuRIL router leaves at the lowest level, then lowest MuRIL text score
    miss = sorted((r for r in scored if r["label"] == "1"),
                  key=lambda r: ((r["muril_router_level"] or 0), r["muril_text_score"] if r["muril_text_score"] is not None else -1))[:10]
    wl = ["| id | kind | provenance | MuRIL score / router | baseline score / router | text (first 90 chars) |", "|---|---|---|---|---|---|"]
    for r in miss:
        t = by_id[r["id"]]["text"].replace("|", "/")
        wl.append(f"| {r['id']} | {r['kind']} | {r['provenance']} | {r['muril_text_score']} / {LEVEL.get(r['muril_router_level'], 'not judged')} | "
                  f"{r['baseline_text_score']} / {LEVEL.get(r['baseline_router_level'], 'not judged')} | {t[:90]} |")
    fa = [r for r in scored if r["label"] == "0" and ((r["muril_router_level"] or 0) >= 1 or (r["baseline_router_level"] or 0) >= 1)]
    fl = ["| id | kind | MuRIL score / router | baseline score / router | text (first 90 chars) |", "|---|---|---|---|---|"]
    for r in fa:
        t = by_id[r["id"]]["text"].replace("|", "/")
        fl.append(f"| {r['id']} | {r['kind']} | {r['muril_text_score']} / {LEVEL.get(r['muril_router_level'], 'not judged')} | "
                  f"{r['baseline_text_score']} / {LEVEL.get(r['baseline_router_level'], 'not judged')} | {t[:90]} |")
    return lines, klines, wl, fl


# ---------------------------------------------------------------- 4. rules
NEG = r"(?:no one|nobody|never|not|don't|do not|cannot|can't|prohibited|beware|caution|avoid)"
INVEST_CTX = r"(?:trad\w*|stock|share|ipo|invest\w*|profit|returns?|demat|broker|fund|nifty|sebi|vip|group)"
RULES = {
    "A1 UPI id that is not @valid, in an investment context":
        lambda t: bool(re.search(r"\b[\w.-]+@(?!valid)[a-z]{2,}\b(?!\.[a-z])", t, F)) and bool(re.search(INVEST_CTX, t, F)),
    "A2 'SEBI registered / certified' claim with no INA/INH/INZ/INP number":
        lambda t: bool(re.search(r"sebi[- ]?(?:registered|certified|approved|regd)|(?:registered|certified) (?:with|by) sebi|sebi registration certificate", t, F))
                  and not re.search(r"\bIN[AHZPM]\d{9}\b", t),
    "A3 guaranteed / assured / fixed / sure-shot returns (not negated)":
        lambda t: any(not re.search(NEG + r"\W+(?:\w+\W+){0,4}$", t[:m.start()], F) for m in re.finditer(
            r"\b(?:guarantee\w*|assured|fixed|sure[- ]?shot|pakka|zero risk|no risk|100% (?:safe|guaranteed))\b(?:\W+\w+){0,4}?\W+(?:returns?|profits?|income|payouts?|allotment|target|calls?)\b"
            r"|\b(?:returns?|profits?|income)\b(?:\W+\w+){0,3}?\W+(?:guaranteed|assured)\b", t, F)),
    "A4 pay a fee / tax / deposit to withdraw, release or unfreeze":
        lambda t: bool(re.search(r"(?:withdraw\w*|release|unfreeze|unlock|unblock|frozen|locked)[^.!?]{0,90}(?:pay|deposit|fee|tax|charges?)"
                                 r"|(?:pay|deposit)[^.!?]{0,60}(?:to|before you can) (?:withdraw|release|unfreeze|unlock)", t, F)),
    "A5 join / upgrade to a VIP or tips group, channel or club":
        lambda t: bool(re.search(r"\b(?:join|joining|add(?:ed)?|upgraded?|welcome)\b[^.!?]{0,50}\b(?:vip|group|channel|club|academy|telegram|whatsapp)\b", t, F))
                  and bool(re.search(r"\b(?:stocks?|signals?|tips?|calls?|trad\w*|ipo|returns?|profit|nifty|invest\w*)\b", t, F)),
    "A6 share login / password, or 'we handle your account'":
        lambda t: bool(re.search(r"share (?:your )?(?:login|password|user ?id|credentials)|handle (?:your )?(?:trading )?account|account handling", t, F))
                  and not re.search(NEG + r"\W+(?:\w+\W+){0,3}share (?:your )?(?:login|password)", t, F),
    "A7 task pay: earn N per day / daily for likes, ratings, reviews, part-time":
        lambda t: bool(re.search(r"(?:rs\.?|₹|inr|rupees)?\s?\d[\d,]*(?:\s?-\s?\d[\d,]*)?\+?\s*(?:rs|rupees|€|usdt)?\s*(?:/-)?\s*(?:daily|per day|a day|every day|roz)"
                                 r"|(?:daily|roz) (?:rs\.?|₹)\s?\d", t, F))
                  and bool(re.search(r"part[- ]?time|task|like|rating|review|video|subscribe|ghar baithe|work from home|job|kamai", t, F)),
    "A8 prepaid task / deposit for a task, tier or level":
        lambda t: bool(re.search(r"(?:prepaid|task deposit|(?:task|tier|level|round)[^.!?]{0,40}(?:deposit|pay|needs? rs|requires?)|(?:deposit|pay)[^.!?]{0,40}(?:task|tier|level|round))", t, F)),
    "A9 app / APK to install from a link, in an investment context":
        lambda t: bool(re.search(r"\.apk\b|(?:download|install)\w*\s+(?:our|the|this)\s+[\w ]{0,20}app\b", t, F)) and bool(re.search(INVEST_CTX, t, F))
                  and not re.search(r"official (?:broker )?app|we never ask you to install", t, F),
    "A10 IPO pre-allotment / institutional account / block trade / FII channel":
        lambda t: bool(re.search(r"pre-?allot\w*|institutional (?:trading )?account|block trades?|fii channel|(?:allotment|allocation) is guaranteed|priority allotment|vip allocation", t, F)),
    "A11 minister / celebrity-endorsed scheme":
        lambda t: bool(re.search(r"(?:sitharaman|sudha murthy|murthy|ambani|ratan tata|finance minister)[^.!?]{0,120}(?:invest|scheme|earn|returns?|income|trading)"
                                 r"|(?:invest|scheme|earn|trading)[^.!?]{0,120}(?:sitharaman|sudha murthy|finance minister)", t, F)),
    "A12 crypto / USDT deposit":
        lambda t: bool(re.search(r"\b(?:usdt|crypto|bitcoin|btc)\b", t, F)) and bool(re.search(r"deposit|pay|takes|transfer|invest|open your", t, F)),
}


def rule_counts(probe, val_benign, val_scam):
    s = [r["text"] for r in probe if r["label"] == "1"]
    g = [r["text"] for r in probe if r["label"] == "0"]
    lines = ["| rule | probe scams caught (of %d) | probe genuine wrongly fired (of %d) | val genuine short-msg fired (of %d) | val scam short-msg fired (of %d) |"
             % (len(s), len(g), len(val_benign), len(val_scam)), "|---|---|---|---|---|"]
    union_s, union_g = set(), set()
    per = {}
    for name, fn in RULES.items():
        cs = [i for i, t in enumerate(s) if fn(t)]
        cg = [i for i, t in enumerate(g) if fn(t)]
        vb = sum(fn(t) for t in val_benign)
        vs = sum(fn(t) for t in val_scam)
        union_s |= set(cs)
        union_g |= set(cg)
        per[name] = (cs, cg)
        lines.append(f"| {name} | {len(cs)} | {len(cg)} | {vb} | {vs} |")
    lines.append(f"| any rule (union) | {len(union_s)} | {len(union_g)} | {sum(any(fn(t) for fn in RULES.values()) for t in val_benign)} | "
                 f"{sum(any(fn(t) for fn in RULES.values()) for t in val_scam)} |")
    sid = [r["id"] for r in probe if r["label"] == "1"]
    gid = [r["id"] for r in probe if r["label"] == "0"]
    lines += ["", "Rows each rule fires on (probe ids): " + "; ".join(
        f"{n.split()[0]}: {' '.join(sid[i] for i in cs) or '-'}" + (f" | genuine {' '.join(gid[i] for i in cg)}" if cg else "")
        for n, (cs, cg) in per.items())]
    return lines, per


def rule_gain(probe, scored, per):
    """What the rules would add on top of the MuRIL router, if each fired rule floored the level at Suspicious (like the OTP rule)."""
    sid = [r["id"] for r in probe if r["label"] == "1"]
    gid = [r["id"] for r in probe if r["label"] == "0"]
    lvl = {r["id"]: (r["muril_router_level"] or 0) for r in scored}
    lines = ["| rule | MuRIL misses it would catch | genuine rows it would newly flag |", "|---|---|---|"]
    tot_s, tot_g = set(), set()
    for name, (cs, cg) in per.items():
        add_s = [sid[i] for i in cs if lvl[sid[i]] == 0]
        add_g = [gid[i] for i in cg if lvl[gid[i]] == 0]
        tot_s |= set(add_s)
        tot_g |= set(add_g)
        lines.append(f"| {name} | {len(add_s)} {' '.join(add_s)} | {len(add_g)} {' '.join(add_g)} |")
    n_s, n_g = len(sid), len(gid)
    base_s = sum(lvl[i] >= 1 for i in sid)
    base_g = sum(lvl[i] >= 1 for i in gid)
    lines += [f"| all rules | {len(tot_s)} | {len(tot_g)} |", "",
              f"MuRIL router recall {base_s}/{n_s} -> {base_s + len(tot_s)}/{n_s} with all rules; genuine flagged {base_g}/{n_g} -> {base_g + len(tot_g)}/{n_g}."]
    return lines


def phrases(probe, k=10):
    """Top word 1-3-grams by the number of probe scam rows they occur in, with the genuine-row count beside (document frequency)."""
    def grams(t):
        w = re.findall(r"[a-z0-9%₹]+", t.lower())
        return {" ".join(w[i:i + n]) for n in (1, 2, 3) for i in range(len(w) - n + 1)}
    stop = set("the a an to and of in for your you is are our on with this it be by we from at or as will get all has been if not".split())
    s = Counter(g for r in probe if r["label"] == "1" for g in grams(r["text"]))
    gq = Counter(g for r in probe if r["label"] == "0" for g in grams(r["text"]))
    def keep(x):
        ws = x.split()
        # placeholders written into the probe (EXAMPLE..., XXXX1234, a/c, dates) are not phrases
        return (ws[0] not in stop and ws[-1] not in stop and not any(w.isdigit() or "example" in w or "xxxx" in w or len(w) < 3 for w in ws))
    ranked = sorted((x for x in s if keep(x)), key=lambda x: (-(s[x] - gq[x]), -s[x], x))[:k]
    top_g = sorted((x for x in gq if keep(x)), key=lambda x: (-(gq[x] - s[x]), -gq[x], x))[:k]
    return [(x, s[x], gq[x]) for x in ranked], [(x, gq[x], s[x]) for x in top_g]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-probe", action="store_true")
    a = ap.parse_args()

    rows = inventory()
    mis = mislabel_candidates(rows)
    with open(MISLABEL_OUT, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        # status (2026-10-25): splits-v3 relabel candidates, NOT edited in the data. tier "likely" = a scam-group chat line labelled genuine, "uncertain" = market chat
        # from the same source with no group marker (a labelling-policy decision, plan Phase B step 1).
        w.writerow(["text_hash", "split", "source", "reason", "tier", "status"])
        w.writerows((h, sp, src, why, "uncertain" if why.startswith("uncertain") else "likely", "splits-v3 candidate (data not edited)")
                    for h, sp, src, why in sorted(mis, key=lambda t: (t[3], t[1], t[0])))

    L = ["# Investment / trading / task-scam audit", "",
         "Made by `src/audit_investment.py` (measurement only; nothing here is in the app). Plan: `docs/plans/investment_scams.md`. "
         "**No test-split row was read**: `messages.csv` is streamed and test rows are dropped before their text is used; the val numbers come from the "
         "cached `reports/eval_preds/*/predictions_val.csv`.", "",
         "## 1. Data inventory (train + val; test not read)", "",
         "No source has an investment, trading or crypto category. The only category route is `india_fraud_final`'s task subcategories "
         f"({', '.join(sorted(TASK_SUBCATS))}). Everything else is keyword search: `INVEST_RX`, `CRYPTO_RX`, `TASK_RX` in the script.", ""]
    L += ["| topic | source | train scam | train genuine | val scam | val genuine |", "|---|---|---|---|---|---|"]
    cnt = Counter((tp, r["source"], r["split"], r["label"]) for r in rows for tp in r["topics"])
    for tp in ("invest", "crypto", "task"):
        for src in SHORT + LONG:
            c = [cnt[(tp, src, sp, lb)] for sp in ("train", "val") for lb in (1, 0)]
            if sum(c):
                L.append(f"| {tp} | {src}{' (long-form)' if src in LONG else ''} | {c[0]} | {c[1]} | {c[2]} | {c[3]} |")
    sub = Counter((r["split"], r["label"]) for r in rows if r["subcat_task"])
    L += ["", f"Category route alone (`india_fraud_final` task subcategories): train {sub[('train', 1)]} scam / {sub[('train', 0)]} genuine, "
          f"val {sub[('val', 1)]} / {sub[('val', 0)]}.", "",
          f"Likely mislabelled (genuine label, reads as scam-group or task chat): **{len(mis)} rows** -> `{MISLABEL_OUT.relative_to(ROOT)}` (ids only). "
          + ", ".join(f"{k}: {v}" for k, v in sorted(Counter((m[3], m[1]) for m in mis).items())), ""]

    preds = load_preds()
    vlines, groups = val_table(rows, preds, mis)
    L += ["## 2. Val subset, existing predictions", "",
          "Cut-offs: each model's own val cut-offs from `scored.json` (MuRIL 0.037 / 0.405 on the uncalibrated score = the app's 0.103 / 0.436 after "
          "temperature; splits-v2 baseline 0.456 / 0.661). The app's TF-IDF head is the splits-v1 fit and has no cached val predictions, so the "
          "splits-v2 refit stands in for it here.", ""] + vlines + [""]

    probe = read_probe()
    val_short = [r for r in stream_non_test() if r["split"] == "val" and r["source"] in SHORT]
    mis_h = {m[0] for m in mis}
    val_benign = [r["text"] for r in val_short if r["label"] == "0" and r["text_hash"] not in mis_h]
    val_scam = [r["text"] for r in val_short if r["label"] == "1"]
    if not a.no_probe:
        scored = score_probe(probe)
        with open(PROBE_OUT, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(scored[0]))
            w.writeheader()
            w.writerows(scored)
        pl, kl, wl, fl = probe_tables(scored, probe)
        L += ["## 3. Probe set v1 (`data/probe/investment_v1.csv`, PROBE-ONLY)", "",
              f"{sum(r['label'] == '1' for r in probe)} scam rows, {sum(r['label'] == '0' for r in probe)} genuine rows; router with `live=False`. "
              "Flagged = Suspicious or Likely scam.", ""] + pl + ["", "By kind:", ""] + kl + ["", "10 worst misses (MuRIL router):", ""] + wl + \
             ["", "Genuine rows flagged by either head:", ""] + fl + [""]
    rl, per = rule_counts(probe, val_benign, val_scam)
    if not a.no_probe:
        rl += ["", "Gain on top of the MuRIL router (a fired rule floors the level at Suspicious):", ""] + rule_gain(probe, scored, per)
    ps, pg = phrases(probe)
    L += ["## 4. Rule feasibility (regex counts only; none of these is in the app)", "",
          "Val columns: the val split of the short-message sources (genuine rows minus the mislabel candidates). Val text is PII-masked, so "
          "A1 (UPI handles) cannot fire there: a UPI id is already `<UPI_ID>` / `<EMAIL>`.", ""] + rl + ["",
          "Top 10 word n-grams in probe scams (rows with it: scam / genuine):", ""] + [f"- `{x}`: {a_} / {b_}" for x, a_, b_ in ps] + ["",
          "Top 10 in probe genuine rows (genuine / scam):", ""] + [f"- `{x}`: {a_} / {b_}" for x, a_, b_ in pg] + [""]
    REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
