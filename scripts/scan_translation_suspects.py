"""Scan the kept Hindi / Kannada translations for probable bad translations (READ-ONLY).

Reads data/external/indic/translated/translated_final_2026-10-07.csv (English `parent_text` next to
the machine translation `text`), the two exclude lists and the spot-check sheets (only to show which
rows are already known). Writes reports/translation_suspects.md and nothing else.

Reason codes:
  a  number / amount / % / date / time / phone / URL in the source missing or different
  b  unit or time word of the source (per month, daily, only, free, within N hours, ...) has no counterpart
  c  capitalised word or ALL-CAPS phrase of the source (brand, sender, company) not kept unchanged
  d  translation length under 40% or over 250% of the source (characters)
  e  translation identical to the source, or empty

Heuristics only: the checks look for word lists in the target language, so a hit means "look at it",
not "wrong". Code c also fires when a brand was legitimately transliterated (Netflix -> नेटफ्लिक्स).
Run: python3 scripts/scan_translation_suspects.py
"""
import csv, re, sys, collections
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRANS = ROOT / "data/external/indic/translated/translated_final_2026-10-07.csv"
DROPPED = ROOT / "data/external/indic/translated/translated_dropped_2026-10-07.csv"
OUT = ROOT / "reports/translation_suspects.md"
EXCLUDES = {"hindi": ROOT / "docs/spotcheck/exclude_v1.txt", "kannada": ROOT / "docs/spotcheck/exclude_kn_v1.txt"}
SHEETS = {"hindi": ROOT / "reports/spotcheck_hi.csv", "kannada": ROOT / "reports/spotcheck_kn.csv"}
CODES = "abcde"

# ---- digits -----------------------------------------------------------------------------------
DIGIT_MAP = {c: str(i) for i in range(10) for c in (chr(0x0966 + i), chr(0x0CE6 + i))}


def ascii_digits(s):
    return "".join(DIGIT_MAP.get(c, c) for c in s)


def mask_tokens(s):
    """Remove placeholder tokens like <ACCOUNT>, <URL>, [Link]."""
    return re.sub(r"<[A-Za-z_]+>|\[(?:Link|URL)\]", " ", s)


URL_RX = re.compile(r"(?:https?://|www\.)\S+|\b[\w-]+(?:\.[\w-]+)*\.(?:com|in|me|co|org|net|ly|io|info|xyz|top|club|app|link)\b(?:/\S*)?", re.I)


def numbers(s):
    s = ascii_digits(mask_tokens(URL_RX.sub(" ", s)))
    toks = re.findall(r"\d+(?:[.,:]\d+)*", s)
    return collections.Counter(t.replace(",", "") for t in toks)


# ---- units / time words -----------------------------------------------------------------------
PER_HI = ["प्रति", "हर ", "रोज", "/", "मासिक", "दैनिक", "साप्ताहिक", "वार्षिक", "प्रत्येक", "रोज़", "हफ्ते में", "दिन में", "महीने में", "माह में"]
PER_KN = ["ಪ್ರತಿ", "/", "ಮಾಸಿಕ", "ದೈನಂದಿನ", "ವಾರ್ಷಿಕ", "ಸಾಪ್ತಾಹಿಕ", "ದಿನಕ್ಕೆ", "ತಿಂಗಳಿಗೆ", "ವಾರಕ್ಕೆ", "ವರ್ಷಕ್ಕೆ", "ಗಂಟೆಗೆ", "ದಿನಕ್ಕೊಮ್ಮೆ"]
UNIT = {  # english unit -> target-language stems
    "hindi": {"hour": ["घंट", "घण्ट", "घन्ट"], "minute": ["मिनट"], "day": ["दिन", "रोज"], "week": ["सप्ताह", "हफ्त", "हफ़्त"],
              "month": ["महीन", "माह", "मास"], "year": ["साल", "वर्ष", "बरस"]},
    "kannada": {"hour": ["ಗಂಟೆ"], "minute": ["ನಿಮಿಷ"], "day": ["ದಿನ"], "week": ["ವಾರ"], "month": ["ತಿಂಗಳ"], "year": ["ವರ್ಷ"]},
}
ONLY = {"hindi": ["केवल", "सिर्फ", "मात्र", "बस ", "ही "], "kannada": ["ಮಾತ್ರ", "ಕೇವಲ", "ಬರೀ"]}
FREE = {"hindi": ["मुफ्त", "मुफ़्त", "निःशुल्क", "नि:शुल्क", "निशुल्क", "फ्री", "बिना शुल्क", "बिना किसी शुल्क", "free", "Free", "FREE"],
        "kannada": ["ಉಚಿತ", "ಫ್ರೀ", "ಶುಲ್ಕವಿಲ್ಲ", "ಶುಲ್ಕ ಇಲ್ಲ", "free", "Free", "FREE"]}
WITHIN = {"hindi": ["भीतर", "अंदर", "अन्दर", "में", "तक"], "kannada": ["ಒಳಗೆ", "ಒಳಗಾಗಿ", "ಳಗೆ", "ಳಗಾಗಿ", "ಅವಧಿಯಲ್ಲಿ", "ಒಳ", "ಲ್ಲಿ"]}
UNIT_RX = re.compile(r"\b(\d[\d,]*)\s*(hours?|hrs?|minutes?|mins?|days?|weeks?|months?|years?)\b", re.I)
UNIT_NORM = {"h": "hour", "m": "minute", "d": "day", "w": "week", "y": "year"}


def unit_of(w):
    w = w.lower()
    if w.startswith("hr") or w.startswith("hour"): return "hour"
    if w.startswith("min"): return "minute"
    if w.startswith("mo"): return "month"
    return {"d": "day", "w": "week", "y": "year"}[w[0]]


def has_any(t, stems):
    return any(s in t for s in stems)


def check_b(src, tr, lang):
    out = []
    t = ascii_digits(mask_tokens(URL_RX.sub(" ", tr))) + " "
    per = PER_HI if lang == "hindi" else PER_KN
    s = src
    # rates: "X/month", "per day", "a month" is left alone
    for m in re.finditer(r"(?:/|\bper\s+)\s*(month|mo|day|week|year|yr|hour|hr)\b", s, re.I):
        u = unit_of(m.group(1) if m.group(1).lower() not in ("mo",) else "month")
        if not has_any(t, per):
            out.append(f'rate "{m.group(0).strip()}": no "per" word in the translation (unit {"kept" if has_any(t, UNIT[lang][u]) else "also missing"})')
    for m in re.finditer(r"\b(daily|weekly|monthly|yearly|annual(?:ly)?|every\s+(?:day|week|month|year))\b", s, re.I):
        w = m.group(1).lower()
        u = "day" if ("dai" in w or "day" in w) else "week" if "week" in w else "month" if "month" in w else "year"
        if not (has_any(t, per) or has_any(t, UNIT[lang][u])):
            out.append(f'"{m.group(1)}": no recurrence word in the translation')
    if re.search(r"\bonly\b", s, re.I) and not has_any(t, ONLY[lang]):
        out.append('"only": no counterpart')
    if re.search(r"\bfree\b", s, re.I) and not has_any(t, FREE[lang]):
        out.append('"free": no counterpart')
    for m in UNIT_RX.finditer(s):
        u = unit_of(m.group(2))
        if not has_any(t, UNIT[lang][u]):
            out.append(f'"{m.group(0)}": the unit word "{u}" is missing')
    for m in re.finditer(r"\bwithin\s+(?:\d[\d,]*|an?|one|two|three|four|five|ten)\s*(?:hours?|hrs?|minutes?|mins?|days?|weeks?|months?)", s, re.I):
        if not has_any(t, WITHIN[lang]):
            out.append(f'"{m.group(0)}": no "within" word')
    return out


# ---- brands ------------------------------------------------------------------------------------
try:
    WORDS = {w.strip().lower() for w in open("/usr/share/dict/words", encoding="utf-8", errors="ignore")}
except OSError:
    WORDS = set()
STOP = {"rs", "inr", "i", "am", "pm", "sms", "sir", "madam", "dear", "hi", "hello", "mr", "mrs", "ms", "dr", "ok", "t", "c", "tc", "no", "id",
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "january", "february", "march", "april", "may",
        "june", "july", "august", "september", "october", "november", "december", "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept", "oct", "nov", "dec", "mon", "tue", "wed", "thu", "fri", "sat", "sun", "ist", "aadhaar", "aadhar", "india", "indian", "whatsapp_"}
EXTRA_WORDS = {"info", "internet", "congratulations", "acc", "pls", "please", "dated", "email", "online", "sms", "app", "bank"}
# instruction words that are capitalised for emphasis in genuine OTP / bank alerts ("DO NOT SHARE"), not brands
EMPHASIS = {"do", "not", "never", "share", "secret", "only", "always", "dont", "ever", "anyone", "with", "your", "this", "and", "the", "for", "fund"}


def is_word(tok):
    t = tok.lower()
    if t in WORDS or t in EXTRA_WORDS:
        return True
    for suf in ("s", "es", "ed", "d", "ing"):
        if t.endswith(suf) and t[: -len(suf)] in WORDS:
            return True
    return False


TOK_RX = re.compile(r"[A-Za-z][A-Za-z0-9&']*(?:[-.][A-Za-z0-9&']+)*")


def norm_alnum(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def brand_suspects(src, tr):
    s = mask_tokens(URL_RX.sub(" ", src))
    tr_n = norm_alnum(tr)
    found, seen = [], set()
    caps_run = []

    def flush():
        if len(caps_run) >= 1:
            pass
    for m in TOK_RX.finditer(s):
        tok = m.group(0).strip(".'-")
        if len(tok) < 2 or tok.lower() in STOP or norm_alnum(tok) in seen:
            continue
        letters = re.sub(r"[^A-Za-z]", "", tok)
        allcaps = len(letters) >= 2 and letters.isupper()
        before = s[:m.start()].rstrip()
        sent_start = (not before) or before[-1] in ".!?:\n\u2022*-|" or before.endswith("\n")
        mixed_inner = "-" not in tok and any(c.isupper() for c in tok[1:]) and not allcaps
        title = tok[0].isupper() and not allcaps
        kind = None
        indict = is_word(tok)
        if "'" in tok or "\u2019" in tok or tok.lower() in EMPHASIS:
            continue
        if allcaps:
            # a dictionary word in capitals (NOT, NEVER, URGENT) is only weak evidence
            kind = ("ALL-CAPS", "low" if indict else "high")
        elif mixed_inner:
            kind = ("CamelCase", "high")
        elif title and not indict:
            kind = ("Capitalised, not an English word", "high")
        # capitalised dictionary words (Bank, Card, Amazon, Express) are not flagged: far too many generic hits
        if kind and norm_alnum(tok) not in tr_n:
            seen.add(norm_alnum(tok))
            found.append((tok, kind[0], kind[1]))
    return found


# ---- length ------------------------------------------------------------------------------------
def read_rows(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def esc(s):
    return s.replace("|", "\\|").replace("\n", " ⏎ ")


def load_excludes():
    ex = {}
    for lang, p in EXCLUDES.items():
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.startswith("#") or "|" not in line:
                continue
            parts = [x.strip() for x in line.split("|")]
            if len(parts) >= 3:
                ex[(parts[1], parts[2])] = parts[0] if parts[0] != "-" else "listed"
    return ex


def load_sheet_ids():
    ids = {}
    for lang, p in SHEETS.items():
        if p.exists():
            for r in read_rows(p):
                ids[(r["parent_id"], lang)] = r["row_id"]
    return ids


def scan(rows):
    res = []  # (row, code, detail)
    for r in rows:
        lang, src, tr = r["language"], r["parent_text"], r["text"]
        s_, t_ = src.strip(), tr.strip()
        # e
        if not t_:
            res.append((r, "e", "translation is empty")); continue
        if s_ == t_:
            res.append((r, "e", "translation identical to the source"))
        # a
        ns, nt = numbers(src), numbers(tr)
        miss, extra = ns - nt, nt - ns
        det = []
        if miss: det.append("missing in translation: " + ", ".join(sorted(miss.elements())))
        if extra: det.append("not in source: " + ", ".join(sorted(extra.elements())))
        if "%" in src and "%" not in tr and not has_any(tr, ["प्रतिशत", "ಶೇಕಡಾ", "ಪ್ರತಿಶತ", "ಶೇ"]):
            det.append('"%" lost')
        su = [u.rstrip(".,)") for u in URL_RX.findall(src)] if False else [m.group(0).rstrip(".,)") for m in URL_RX.finditer(src)]
        for u in su:
            if u.lower() not in tr.lower():
                det.append(f"URL/domain changed or missing: {u}")
        if det:
            res.append((r, "a", "; ".join(det)))
        # b
        det = check_b(src, tr, lang)
        if det:
            res.append((r, "b", "; ".join(det)))
        # c
        br = brand_suspects(src, tr)
        if br:
            conf = "high" if any(cf == "high" for _, _, cf in br) else "low"
            res.append((r, "c", f"[{conf}] not kept as written: " + ", ".join(f"{w} ({k})" for w, k, _ in br)))
        # d
        ratio = len(t_) / max(1, len(s_))
        if ratio < 0.4 or ratio > 2.5:
            res.append((r, "d", f"length ratio {ratio:.2f} ({len(t_)} vs {len(s_)} chars)"))
    return res


def main():
    rows = read_rows(TRANS)
    langs = sorted({r["language"] for r in rows})
    tot = collections.Counter(r["language"] for r in rows)
    res = scan(rows)
    ex, sheet = load_excludes(), load_sheet_ids()

    ratios = collections.defaultdict(list)
    for r in rows:
        ratios[r["language"]].append(len(r["text"].strip()) / max(1, len(r["parent_text"].strip())))

    by = collections.Counter((r["language"], c) for r, c, _ in res)
    rows_any = collections.defaultdict(set)
    for r, c, _ in res:
        rows_any[r["language"]].add(r["parent_id"])

    # known cases
    def has(pid, lang, code, needle=""):
        return any(r["parent_id"] == pid and r["language"] == lang and c == code and needle in d for r, c, d in res)
    known = [
        ("kn22 = p00696 kannada, 'per month' lost", has("p00696", "kannada", "b")),
        ("Licious (p00339 hindi)", has("p00339", "hindi", "c", "[high] not kept as written: Licious")),
        ("Licious (p00339 kannada)", has("p00339", "kannada", "c", "[high] not kept as written: Licious")),
        ("URGENT HIRING (p00720 kannada)", has("p00720", "kannada", "c", "URGENT") and has("p00720", "kannada", "c", "HIRING")),
        ("URGENT HIRING (p00720 hindi, translated 'जरुरी नियुक्ति')", has("p00720", "hindi", "c", "URGENT")),
        ("p00720 hindi 'Rs 30,000/month' lost 'per'", has("p00720", "hindi", "b")),
        ("p00719 hindi '/day' lost 'per'", has("p00719", "hindi", "b")),
        ("p00720 kannada '/month' lost 'per'", has("p00720", "kannada", "b")),
        ("p00719 kannada '/day' lost 'per'", has("p00719", "kannada", "b")),
    ]

    L = []
    L.append("# Translation suspects (read-only scan)\n")
    L.append("Generated by `scripts/scan_translation_suspects.py` from `data/external/indic/translated/translated_final_2026-10-07.csv` "
             "(the kept translations, each next to its English parent). Nothing in `data/`, `split_map.csv`, `models/` or the test set was read for "
             "labels or changed; this report only lists rows for you to review. **Heuristic**: a hit means \"look at it\", not \"wrong\".\n")
    L.append("Reason codes: **a** number / amount / % / URL missing or different · **b** unit or time word has no counterpart "
             "(per month, daily, only, free, within N hours, N hours/days) · **c** capitalised word or ALL-CAPS phrase not kept as written "
             "(high = non-dictionary / CamelCase word, low = ordinary English word in capitals; some are legitimate transliterations such as Netflix → नेटफ्लिक्स; capitalised dictionary words like Bank or Amazon are not checked) · **d** length under 40% or over 250% of the source · **e** identical or empty.\n")
    L.append("## Summary\n")
    L.append("| Language | Translated rows | Rows with any suspect | % | " + " | ".join(f"a-e: {c}" for c in CODES) + " |")
    L.append("|---|---|---|---|" + "---|" * len(CODES))
    for lg in langs:
        n = len(rows_any[lg])
        L.append(f"| {lg} | {tot[lg]} | {n} | {100*n/tot[lg]:.1f}% | " + " | ".join(f"{by[(lg,c)]} ({100*by[(lg,c)]/tot[lg]:.1f}%)" for c in CODES) + " |")
    n_all = sum(len(v) for v in rows_any.values())
    L.append(f"| **all** | {len(rows)} | {n_all} | {100*n_all/len(rows):.1f}% | " + " | ".join(f"{sum(by[(lg,c)] for lg in langs)}" for c in CODES) + " |")
    L.append("\nA row can carry several codes, so the code counts add up to more than the row count. Median length ratio (translation / source, characters): "
             + ", ".join(f"{lg} {sorted(v)[len(v)//2]:.2f}" for lg, v in sorted(ratios.items())) + ".\n")

    # code c: split into kinds for context
    kinds = collections.Counter()
    for r, c, d in res:
        if c == "c":
            kinds[(r["language"], d[1:d.index("]")])] += 1
    L.append("Code c rows by confidence (high = a non-dictionary or CamelCase word such as Licious, StanChart; low = an ordinary English word in capitals such as URGENT, NEVER): "
             + "; ".join(f"{lg} {k}: {n}" for (lg, k), n in sorted(kinds.items())) + ".\n")

    wc = collections.Counter()
    for r, c, d in res:
        if c == "c":
            for w in re.findall(r"([^,:]+?) \((?:ALL-CAPS|CamelCase|Capitalised, not an English word)\)", d.split("written: ", 1)[1]):
                wc[(w.strip(), r["language"])] += 1
    top = collections.Counter()
    for (w, lg), n in wc.items():
        top[w] += n
    L.append("## Most frequent code-c words\n")
    L.append("Review these per word rather than per row: if a word is a brand that should stay in Latin script, every row with it is a suspect; if the translation transliterated it correctly, none are. Count = rows (both languages).\n")
    L.append("| word | rows | hindi | kannada |\n|---|---|---|---|")
    for w, n in top.most_common(40):
        L.append(f"| {esc(w)} | {n} | {wc[(w,'hindi')]} | {wc[(w,'kannada')]} |")
    L.append("")
    L.append("## Known cases (the script has to find these)\n")
    L.append("| Case | Found |\n|---|---|")
    for name, ok in known:
        L.append(f"| {name} | {'yes' if ok else '**NO**'} |")
    L.append("")
    dropped = [r for r in read_rows(DROPPED) if r.get("parent_id") == "p00696" and r.get("language") == "hindi"]
    L.append("Hindi `p00696` is **not in the kept set** (dropped by the scam trim to 15%), so it is not scanned above. Its dropped translation "
             "reads `वेतन 23,00 महीना है` for \"Salary is 23,00/month\": the same lost \"per\" as kn22.\n")
    L.append("## Suspects\n")
    L.append("`sheet` = the spot-check row id if the row was on a sheet; `listed` = already in an exclude list (`exclude_v1.txt` / `exclude_kn_v1.txt`). "
             "Sorted by code, then language, then parent id.\n")
    L.append("| row id | sheet | listed | lang | code | source | translation | what looks wrong |")
    L.append("|---|---|---|---|---|---|---|---|")
    for r, c, d in sorted(res, key=lambda x: (x[1], x[0]["language"], x[0]["parent_id"])):
        key = (r["parent_id"], r["language"])
        L.append(f"| {r['parent_id']} | {sheet.get(key,'')} | {'yes' if key in ex else ''} | {r['language']} | {c} | {esc(r['parent_text'])} | {esc(r['text'])} | {esc(d)} |")
    OUT.write_text("\n".join(L) + "\n", encoding="utf-8")

    print(f"rows {len(rows)}; suspects (row,code) {len(res)}; rows with any suspect {n_all}")
    for lg in langs:
        print(lg, tot[lg], {c: by[(lg, c)] for c in CODES}, "rows:", len(rows_any[lg]))
    bad = [n for n, ok in known if not ok]
    for name, ok in known:
        print("OK " if ok else "MISS", name)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
