"""How often each OFFLINE link signal of decision D23 fires on dev (val) links, scam vs benign. Writes reports/link_signals_val.md.

    .venv/bin/python src/link_signals_val.py

Offline only: brand-owned TLD (P1), .bank.in (P1) / .gov.in / .nic.in (display), high-abuse TLD (display), Tranco top 10k (P2) / top 1M,
OpenPhish + URLhaus (R1), Indian brand lookalike (R4), IDN homograph (R3), raw IP (R5). No RDAP, DNS, crt.sh or Safe Browsing call is made
(D23: no live checks on bulk data); nothing leaves the machine. The test split is never read (split == "val" rows only).
Two sets:
  (a) data/final/urls.csv, split val: one row per URL, label from its source (phishing / malware = scam, benign, gambling_spam apart)
  (b) the links in val messages (messages.csv, split val), labelled by their message (an approximation: a scam message can carry a genuine link)
"""
import datetime as dt, sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from shield.links.lists import load_lists
from shield.links.lookalike import abuse_tld, brand_tld, homograph, link_domain, lookalike, raw_ip, restricted_zone
from shield.links.platforms import SHORTENERS, platform_of, suffix_match
from textprep import extract_urls

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports" / "link_signals_val.md"
SIGNALS = [("P1 brand-owned TLD", "p1_brand"), ("P1 .bank.in", "p1_bank"), ("display .gov.in / .nic.in", "gov"), ("P2 Tranco top 10k (eligible)", "p2"),
           ("Tranco top 1M", "top1m"), ("R1 OpenPhish / URLhaus", "r1"), ("R3 IDN homograph", "r3"), ("R4 brand lookalike", "r4"),
           ("R5 raw IP", "r5"), ("display high-abuse TLD", "abuse"), ("any red flag (R1/R3/R4/R5)", "any_r")]


def signals(url, lists):
    host, reg = link_domain(url)
    if not host:
        return None
    rank = lists.tranco_rank(reg)
    zone = restricted_zone(host)
    bt = brand_tld(host)
    root = platform_of(host)
    s = {"p1_brand": bool(bt), "p1_bank": bool(zone and zone["zone"] == "bank.in"), "gov": bool(zone and zone["zone"] in ("gov.in", "nic.in")),
         "top1m": rank is not None, "p2": rank is not None and rank <= 10_000 and not root and not raw_ip(host),
         "r1": bool(lists.listed(url, host)), "r3": bool(homograph(host, lists.top_labels)),
         "r4": not (bt or zone) and lookalike(host, reg, rank) is not None, "r5": bool(raw_ip(host)), "abuse": bool(abuse_tld(reg)) and not raw_ip(host)}
    s["any_r"] = s["r1"] or s["r3"] or s["r4"] or s["r5"]
    s["_reg"] = reg
    return s


def table(rows, group_col):
    """rows: list of (group, is_scam, signals). Markdown: per signal, scam hits / n and benign hits / n, overall and per group."""
    lines = ["| signal | scam hits | scam rate | benign hits | benign rate |", "|---|---|---|---|---|"]
    n_s = sum(1 for _, y, _ in rows if y == 1)
    n_b = sum(1 for _, y, _ in rows if y == 0)
    for name, key in SIGNALS:
        hs = sum(1 for _, y, s in rows if y == 1 and s[key])
        hb = sum(1 for _, y, s in rows if y == 0 and s[key])
        lines.append(f"| {name} | {hs:,} / {n_s:,} | {hs / max(n_s, 1):.1%} | {hb:,} / {n_b:,} | {hb / max(n_b, 1):.1%} |")
    by = defaultdict(list)
    for g, y, s in rows:
        by[g].append((y, s))
    lines += ["", f"Per {group_col} (hits / rows; only the signals that fire):", "",
              f"| {group_col} | label | rows | " + " | ".join(n for n, k in SIGNALS if k != "any_r") + " |",
              "|---|---|---|" + "---|" * (len(SIGNALS) - 1)]
    for g in sorted(by):
        for y in (1, 0):
            sub = [s for yy, s in by[g] if yy == y]
            if sub:
                lines.append(f"| {g} | {'scam' if y else 'benign'} | {len(sub):,} | " +
                             " | ".join(str(sum(1 for s in sub if s[k])) for n, k in SIGNALS if k != "any_r") + " |")
    return lines


LICENCES = ["", "## Licences: what is non-commercial, and what a commercial version would need instead", "",
            "This is a student project; three of the sources are licensed for **non-commercial use only**:", "",
            "| source | used for | terms | commercial replacement |", "|---|---|---|---|",
            "| Tranco top 1M | popularity, P2, the lookalike exemption, homograph targets | no licence for the list; built partly from Cloudflare Radar (CC BY-NC 4.0); cite Le Pochat et al., NDSS 2019 | a commercially usable ranking: Majestic Million (CC BY 3.0, attribution) or the Chrome UX Report top sites (CC BY-SA 4.0) |",
            "| OpenPhish community feed | R1 | research / personal use only; no commercial use; no redistribution | OpenPhish's paid commercial feed, or another licensed phishing feed |",
            "| Google Safe Browsing API | R2 (only with SAFE_BROWSING_KEY) | non-commercial use only | Google Web Risk API (paid) |",
            "", "Also to re-check before any commercial use or public hosting: URLhaus (free under abuse.ch fair use; commercial use may need abuse.ch's paid "
            "plan), the Interisle high-abuse TLD table (all rights reserved; only the TLD names are kept, as cited facts), crt.sh (no stated terms; "
            "rate-limited), and OpenPhish's no-redistribution clause (a hosted server holding the feed). iptoasn.com (PDDL 1.0) and the IANA / ICANN "
            "registry data have no such limit."]


def level_changes(m):
    """(c) The verdicts of the val messages that have a link, from the offline analysis (no live checks) with the D23 checks and without them
    (shield.core.router.assess_background replaced by a function that returns None: no flags, no positives, as before D23)."""
    from shield.core import router
    from shield.links.lexical import load_url_model
    from shield.messages.text_head import load_text_model
    tm, um = load_text_model(), load_url_model()
    real = router.assess_background
    name = {0: "No warning signs", 1: "Suspicious", 2: "Likely scam", None: "Can't judge", "promotional": "Promotional"}
    moves, why = Counter(), defaultdict(Counter)
    for text, label in m[["text", "label"]].itertuples(index=False):
        text = text if isinstance(text, str) else ""
        if not extract_urls(text, 10):
            continue
        try:
            router.assess_background = lambda *a, **k: None
            before = router.analyse(text, tm, um)["level"]
        finally:
            router.assess_background = real
        r = router.analyse(text, tm, um)
        moves[(int(label), before, r["level"])] += 1
        if before != r["level"]:
            codes = sorted({c for l in r["links"] for c in l["flags"]}) or sorted({l["positive"] for l in r["links"] if l.get("positive_applied")})
            why[(int(label), before, r["level"])]["+".join(codes) + (" (P1 cap)" if r.get("positive_cap") else "")] += 1
    out = ["", "## (c) Verdict changes on val messages with a link (offline D23 on vs off)", "",
           "The same code with the D23 checks switched off (as before D23) and on, offline (no live checks: the live red flags R2 / R6 / R7 / R8 "
           "cannot fire here). Rows that did not change are counted in the first table only.", "",
           "| message label | rows | unchanged | raised | lowered |", "|---|---|---|---|---|"]
    rank = {None: -1, 0: 0, 1: 1, 2: 2}
    for y in (1, 0):
        sub = {k: v for k, v in moves.items() if k[0] == y}
        up = sum(v for (_, b, a), v in sub.items() if rank[a] > rank[b])
        down = sum(v for (_, b, a), v in sub.items() if rank[a] < rank[b])
        out.append(f"| {'scam' if y else 'benign'} | {sum(sub.values()):,} | {sum(sub.values()) - up - down:,} | {up:,} | {down:,} |")
    out += ["", "| label | before | after | messages | because of |", "|---|---|---|---|---|"]
    for (y, b, a), n in sorted(((k, v) for k, v in moves.items() if k[1] != k[2]), key=lambda kv: (-kv[0][0], str(kv[0]))):
        out.append(f"| {'scam' if y else 'benign'} | {name[b]} | {name[a]} | {n} | " + ", ".join(f"{c} {k}" for c, k in why[(y, b, a)].most_common()) + " |")
    return out


def main():
    lists = load_lists()
    out = [f"# D23 offline link signals on dev (val) links", "",
           f"Generated by `src/link_signals_val.py` on {dt.date.today()} (lists: " +
           ", ".join(f"{n} {lists.updated(n):%Y-%m-%d %H:%M} UTC" for n in ("tranco", "openphish", "urlhaus") if lists.updated(n)) + ").",
           "Offline signals only; no RDAP / DNS / crt.sh / Safe Browsing call was made. The test split was not read.", ""]
    # (a) urls.csv val
    u = pd.read_csv(ROOT / "data" / "final" / "urls.csv", usecols=["url", "label", "source", "split"], low_memory=False)
    u = u[u.split == "val"]
    rows, gamb, examples = [], [], defaultdict(list)
    for url, label, source in u[["url", "label", "source"]].itertuples(index=False):
        s = signals(url, lists)
        if s is None:
            continue
        if label == "gambling_spam":
            gamb.append(s)
            continue
        y = 1 if label in ("phishing", "malware") else 0
        rows.append((source, y, s))
        for key in ("r4", "r3", "r1", "p2", "p1_brand"):
            if s[key] and y == 0 and len(examples[(key, "benign")]) < 12:
                examples[(key, "benign")].append(s["_reg"])
            if s[key] and y == 1 and len(examples[(key, "scam")]) < 12:
                examples[(key, "scam")].append(s["_reg"])
    out += ["## (a) `urls.csv`, val split", "",
            f"{len(rows):,} URLs (scam = phishing + malware: {sum(1 for _, y, _ in rows if y):,}; benign: {sum(1 for _, y, _ in rows if not y):,}); "
            f"{len(gamb):,} `gambling_spam` rows reported apart. **Circular sources:** the `tranco` benign rows were drawn from the Tranco list "
            "(so the Tranco signals fire on them by construction), and the `openphish` / `urlhaus` rows came from those feeds on 2026-10-05 "
            "(so R1 can fire on them by construction, when the entry is still in today's feed). The independent slice is `ealvaradob`.", ""]
    out += table(rows, "source")
    out += ["", "`gambling_spam` (val): " + ", ".join(f"{n} {sum(1 for s in gamb if s[k])}" for n, k in SIGNALS if sum(1 for s in gamb if s[k])), ""]
    out += ["Examples (registered domains, up to 12):", ""]
    for (key, side), doms in sorted(examples.items()):   # registered domains only (the hosts may carry a brand as a subdomain: amazon.co.jp.apung.cn)
        out.append(f"- {dict((k, n) for n, k in SIGNALS)[key]}, {side}: " + ", ".join(f"`{d}`" for d in doms))
    # (b) links in val messages
    m = pd.read_csv(ROOT / "data" / "final" / "messages.csv", usecols=["text", "label", "source", "split"], low_memory=False)
    m = m[m.split == "val"]
    rows_b, n_msgs = [], Counter()
    flagged_msgs = defaultdict(set)
    for i, (text, label, source) in enumerate(m[["text", "label", "source"]].itertuples(index=False)):
        links = extract_urls(text if isinstance(text, str) else "", 10)
        if links:
            n_msgs[int(label)] += 1
        for url in links:
            s = signals(url, lists)
            if s is None:
                continue
            rows_b.append((source, int(label), s))
            for name, key in SIGNALS:
                if s[key]:
                    flagged_msgs[(key, int(label))].add(i)
    out += ["", "## (b) Links in val messages", "",
            f"{len(rows_b):,} parseable links in {sum(n_msgs.values()):,} val messages ({n_msgs[1]:,} scam / {n_msgs[0]:,} benign), each labelled "
            "by its message.", ""]
    out += table(rows_b, "source")
    out += ["", "Messages with at least one link carrying the signal:", "", "| signal | scam messages | benign messages |", "|---|---|---|"]
    for name, key in SIGNALS:
        out.append(f"| {name} | {len(flagged_msgs[(key, 1)]):,} / {n_msgs[1]:,} | {len(flagged_msgs[(key, 0)]):,} / {n_msgs[0]:,} |")
    out += level_changes(m)
    out += LICENCES
    OUT.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
