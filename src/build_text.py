import argparse, ast, glob, hashlib, json, os, re, unicodedata
from collections import Counter
import pandas as pd
import company_key, neardup, pii, pool, realguard, synth_upi_collect, textprep
from protect import PATTERNS as PROTECT_PATTERNS

# Build data/final/messages.csv from data/messages/ + data/external/{text,indic}/ (see data/sources.yaml).
# benign Hinglish is plentiful but Hinglish scam text is only synthetic (~220 rows); capping keeps
# the scam share within Hinglish near the overall ~20%, so language alone doesn't predict the label
HINGLISH_BENIGN_PER_SOURCE = 500
# near-duplicate clusters (see neardup.py): exact Jaccard >= 0.7 on char 5-grams, on the raw OR the normalised text
# (templated prefixes/suffixes stripped, numbers -> <NUM>), 0.6 within india_fraud_final (slot-filler templates), plus
# two forced groupings: translations of one synth_india
# template (template_family) and posts by one company (company_key, from fake_job_postings.company_profile; the
# dataset has no company-name column, and 18% of posts have no profile, so those cluster by text only).
# Whole clusters go to one split; the result is frozen in SPLIT_MAP and reused on later runs.
COMPANY_KEY_CHARS, MIN_COMPANY_PROFILE = 150, 20
SPLIT_MAP = "data/final/split_map.csv"
# splits-v3 B0a: --mask-version picks the pii.py mask set the stored text is masked with (default v2: a rebuild today is identical to the splits-v2 build).
# --out-dir writes messages.csv, split_map.csv and build_meta.json there instead of data/final/ (a dry run writes nothing under data/); the frozen
# split map is always read from SPLIT_MAP. A row's frozen split is found through its hash under the masks it was frozen with (text_hash, else hash_v2,
# else hash_v1; its own earlier hash first), so a row re-keyed by v3 keeps its split.
ap = argparse.ArgumentParser(description="Build data/final/messages.csv (see the comments in this file).")
ap.add_argument("--mask-version", default=pii.V2, choices=pii.MASK_VERSIONS, help="mask set for the stored text (default v2)")
ap.add_argument("--out-dir", default="data/final", help="where messages.csv, split_map.csv and build_meta.json are written (default data/final)")
ap.add_argument("--report-translation-drift", action="store_true", help="dry runs only: count the translations the mask set changes without changing their English parent the same way, instead of stopping")
# splits-v3 B0b (docs/plans/splits_v3.md D-v3.1, D-v3.3, D-v3.4). With none of the three below and no pool file, a build is byte-identical to the splits-v2 one.
ap.add_argument("--pool-file", default=pool.POOL_PATH, help="the POOL half of the real phone messages (intake_real.py --freeze); read when it exists, 'none' to skip it (default %(default)s)")
ap.add_argument("--freeze-manifest", default=pool.MANIFEST_PATH, help="the intake's freeze manifest; only its existence is checked, the file is never opened (default %(default)s)")
ap.add_argument("--real-test-file", default=None, help="the file realguard takes the real_test_v1 hashes from (default: realguard's own path); a fixture build passes its own")
ap.add_argument("--company-name-key", action="store_true", help="D-v3.4: give fake_job_postings posts without a profile the company_key of the company named in them; a company group that then "
                "straddles frozen splits keeps its highest-priority split (test > val > train) and the other frozen rows are dropped and counted")
ap.add_argument("--synth-upi-collect", action="store_true", help="D-v3.3 item 3: add the synthetic benign UPI collect-request families (synth_upi_collect.py); OFF by default, switched on 1 Nov only if POOL-val has < 10 real collect-request groups")
ARGS = ap.parse_args()
LEDGER = {}   # every drop and every addition of this build that the splits-v2 build did not have, by reason (printed at the end and written to build_meta.json)
POOL_ON = ARGS.pool_file.lower() != "none" and os.path.exists(ARGS.pool_file)
OUT_DIR = ARGS.out_dir
OUT_SPLIT_MAP, OUT_MESSAGES, OUT_META = (os.path.join(OUT_DIR, n) for n in ("split_map.csv", "messages.csv", "build_meta.json"))
print(f"mask version {ARGS.mask_version}; outputs to {OUT_DIR}")
COLS = ["text", "label", "category", "subcategory", "channel", "language", "source", "is_synthetic", "template_id",
        "template_family", "company_key", "provenance", "note", "translation_of"]
# Hindi / Kannada machine translations (translate_parents.py finalise / replace): TRAINING augmentation only (D20, D26).
TRANSLATED = "data/external/indic/translated/translated_final_*.csv"
EXCLUDE_FILES = ("docs/spotcheck/exclude_v1.txt", "docs/spotcheck/exclude_kn_v1.txt")   # D20 / D26 + translation_suspects review
TWIN_JACCARD = 0.6   # a translation whose English parent has a val/test twin at this Jaccard (either view) would leak across languages

def latest(name, module="text"):
    files = sorted(glob.glob(f"data/external/{module}/{name}/{name}_*"))
    if not files:
        print(f"missing {name}, run src/pull_hf.py")
    return files[-1] if files else None

frames = []

# 1. India (local)
d = pd.read_csv("data/messages/india_fraud_detection_FINAL.csv")
topic = {"Echallan": "echallan", "Electricity": "utility", "Lottery": "lottery", "Courier": "courier_customs",
         "KYC": "kyc", "Tax": "tax", "Job": "job", "Digital_Arrest": "digital_arrest"}
d["category"] = d["category"].map(lambda c: next(v for k, v in topic.items() if c.startswith(k)))
chan = {"SMS": "sms", "WhatsApp": "whatsapp", "Email": "email", "Call": "call", "Telegram": "telegram",
        "App Notification": "app"}
frames.append(pd.DataFrame({
    "text": d["message_text"], "label": d["label"], "category": d["category"], "subcategory": d["subcategory"],
    "channel": d["platform_found"].map(chan).fillna("other"), "language": d["language"].str.lower(),
    "source": "india_fraud_final", "is_synthetic": d["is_synthetic"].astype(str) == "True"}))

d = pd.read_csv("data/messages/scam_ham_india.csv")
frames.append(pd.DataFrame({"text": d["text"], "label": (d["label"] == "spam").astype(int), "category": "other",
                            "channel": "sms", "language": "english", "source": "scam_ham_india", "is_synthetic": False}))

# scam quotes from scraped Indian articles/advisories (src/extract_manual.py); all scams. provenance says whether
# the quote is a real circulating message, a generic script or an illustrative example written by the publisher
if os.path.exists(f := "data/extracted/web_scams.csv"):
    d = pd.read_csv(f, keep_default_na=False)
    cat = {"parcel": "courier_customs"}
    frames.append(pd.DataFrame({"text": d["text"], "label": 1, "category": d["scam_type"].map(lambda t: cat.get(t, t)),
                                "channel": d["channel"], "language": d["language"], "source": "web_scams",
                                "is_synthetic": False, "provenance": d["provenance"], "note": d["note"]}))
else:
    print("missing web_scams, run src/extract_manual.py")

# 2. Generic SMS / email / jobs / calls (HF)
if f := latest("uci_sms_spam"):
    d = pd.read_parquet(f)
    frames.append(pd.DataFrame({"text": d["sms"], "label": d["label"], "category": "other", "channel": "sms",
                                "language": "english", "source": "uci_sms_spam", "is_synthetic": False}))

if f := latest("phishing_email"):
    d = pd.read_csv(f)
    frames.append(pd.DataFrame({"text": d["Email Text"], "label": (d["Email Type"] == "Phishing Email").astype(int),
                                "category": "other", "channel": "email", "language": "english",
                                "source": "phishing_email", "is_synthetic": False}))

if f := latest("ealvaradob_phishing"):
    d = pd.DataFrame(json.load(open(f)))
    t = d["text"].astype(str).str.strip()
    # mixed corpus: drop raw HTML pages and bare URLs, keep messages (email + SMS, not distinguishable)
    d = d[~t.str.startswith("<") & t.str.contains(r"\s")]
    frames.append(pd.DataFrame({"text": d["text"], "label": d["label"], "category": "other", "channel": "email_or_sms",
                                "language": "english", "source": "ealvaradob_phishing", "is_synthetic": False}))

if f := latest("fake_job_postings"):
    d = pd.read_csv(f)
    parts = ["title", "company_profile", "description", "requirements", "benefits"]
    text = d[parts].fillna("").astype(str).agg("\n".join, axis=1)
    prof = d["company_profile"].fillna("").astype(str).str.lower().str.replace(r"\s+", " ", regex=True).str.strip()
    prof = prof.str.slice(0, COMPANY_KEY_CHARS)
    company = prof.map(lambda p: hashlib.md5(p.encode()).hexdigest() if len(p) >= MIN_COMPANY_PROFILE else "")
    if ARGS.company_name_key:
        # D-v3.4: a post without a profile gets the company_key of the company named in its title / description (company_key.py)
        company, ck_ledger = company_key.fill_company_keys(pd.DataFrame({"title": d["title"].fillna("").astype(str), "description": d["description"].fillna("").astype(str),
                                                                         "company_profile": d["company_profile"].fillna("").astype(str), "company_key": company}))
        COMPANY_NAMES = ck_ledger.pop("key_names")
        LEDGER["company_name_key"] = ck_ledger
        print(f"company-name key: {ck_ledger['keyed']} of {ck_ledger['profile_less']} profile-less posts get a company_key ({ck_ledger['no_name_found']} name none, "
              f"{ck_ledger['several_names_found']} name several, {ck_ledger['ambiguous_name']} name a company with two profile texts, {ck_ledger['common_word_names_dropped']} profile names dropped as common words)")
        print("  largest new company groups (posts newly keyed): " + ", ".join(f"{n} {c}" for n, c in ck_ledger["new_groups_by_size"][:20]))
    frames.append(pd.DataFrame({"text": text, "label": d["fraudulent"], "category": "job", "channel": "job_post",
                                "language": "english", "source": "fake_job_postings", "is_synthetic": False,
                                "company_key": company}))

if f := latest("scam_dialogue"):
    d = pd.read_csv(f)
    cat = {"delivery": "courier_customs", "refund": "refund", "reward": "lottery", "support": "tech_support",
           "ssn": "impersonation", "insurance": "insurance"}
    frames.append(pd.DataFrame({"text": d["dialogue"], "label": d["label"], "category": d["type"].map(cat),
                                "subcategory": d["type"], "channel": "call", "language": "english",
                                "source": "scam_dialogue", "is_synthetic": True}))

# synthetic India templates (src/synth_india.py), multilingual scam + benign pairs
if os.path.exists(f := "data/external/text/synth_india/synth_india.csv"):
    d = pd.read_csv(f)
    d["source"], d["is_synthetic"] = "synth_india", True
    frames.append(d)
else:
    print("missing synth_india, run src/synth_india.py")

# 3c. Hindi / Kannada machine translations. Train split only: a translation whose English parent is a val/test row is dropped
# before anything else is read from it (a train translation of a val/test row would leak). Then the review exclusions (each listed
# text_hash must match the stored row) and the D21 preservation rule: drop a row if a digit run or a link of its English parent is
# missing (links: protect.py's url pattern AND every link textprep finds, verbatim, so klr.pw-style links outside protect's TLD list
# count too). Each translation joins its English parent's cluster (anchor row) and its sibling language (translation_of).
TR_LEDGER = []
def tr_step(name, before, after):
    for lang in ("hindi", "kannada"):
        b, a = before[before["language"] == lang], after[after["language"] == lang]
        TR_LEDGER.append({"language": lang, "step": name, "benign_dropped": int((b.label == 0).sum() - (a.label == 0).sum()),
                          "scam_dropped": int((b.label == 1).sum() - (a.label == 1).sum()),
                          "benign_left": int((a.label == 0).sum()), "scam_left": int((a.label == 1).sum())})

def exclusions():
    keys = {}
    for f in EXCLUDE_FILES:
        for line in open(f, encoding="utf-8"):
            if line.startswith("#") or not line.strip():
                continue
            parts = [x.strip() for x in line.split("|")]
            keys[(parts[1], parts[2])] = (parts[3], f)
    return keys

def d21_missing(parent, text):
    """Digit runs and links of the English parent that the translation lost (D21; native digits mapped to ASCII first)."""
    t = "".join(str(unicodedata.digit(c)) if c.isdigit() and not c.isascii() else c for c in text)
    lost = sorted(set(re.findall(r"[0-9]+", parent)) - set(re.findall(r"[0-9]+", t)))
    url_rx = next(rx for kind, rx in PROTECT_PATTERNS if kind == "url")
    links = {m.group().rstrip(".,;:!?)'\"]") for m in url_rx.finditer(parent)} | {core for _, _, core in textprep._urls(parent)}
    return lost + sorted(u for u in links if u and u.lower() not in text.lower())

if files := sorted(glob.glob(TRANSLATED)):
    t = pd.read_csv(files[-1], keep_default_na=False, dtype={"label": int})
    print(f"translations: {files[-1]} ({len(t)} rows)")
    all_t = t
    keep = ~t["anchor_split"].isin(["val", "test"])   # first look at a row: nothing else of a val/test-anchored row is used
    tr_step("start: kept by finalise / replace", t, t)
    t2 = t[keep]
    tr_step("English parent is a val/test row (train-only)", t, t2)
    ex = exclusions()
    for (pid, lang), (h, f) in ex.items():
        hit = all_t[(all_t["parent_id"] == pid) & (all_t["language"] == lang)]
        assert len(hit) == 1 and hit["text_hash"].iloc[0] == h, f"{f}: {pid} {lang} {h} does not match the translations file"
        assert hit["anchor_split"].iloc[0] in ("train", ""), f"{f}: {pid} {lang} is not a train / no-split row"
    t3 = t2[[(pid, lang) not in ex for pid, lang in zip(t2["parent_id"], t2["language"])]]
    tr_step("review exclusions (docs/spotcheck/exclude_*.txt)", t2, t3)
    lost = [d21_missing(p, x) for p, x in zip(t3["parent_text"], t3["text"])]
    for (pid, lang), l in zip(zip(t3["parent_id"], t3["language"]), lost):
        if l:
            print(f"  D21 drop {pid} {lang}: lost {[ascii(x) for x in l]}")
    t4 = t3[[not l for l in lost]]
    tr_step("D21 digit run / link missing", t3, t4)
    # rule 5: a parent whose translation the PII masks would change carries PII the masks missed in the English (an account number
    # glued to letters, "THTHA2077...", where the translation put a space before it); all its translations go, in every language
    from pii import mask_text
    pii_parents = set(t4.loc[[mask_text(x) != x for x in t4["text"]], "parent_id"])
    if pii_parents:
        print(f"  PII drop (masks change a translation): {sorted(pii_parents)}")
    t5 = t4[~t4["parent_id"].isin(pii_parents)]
    tr_step("PII the masks miss in the parent (rule 5)", t4, t5)
    t4 = t5
    frames.append(pd.DataFrame({"text": t4["text"], "label": t4["label"], "category": t4["category"], "channel": t4["channel"],
                                "language": t4["language"], "source": "translated_indic", "is_synthetic": True,
                                "provenance": t4["parent_provenance"], "note": "translated from " + t4["parent_id"],
                                "translation_of": t4["parent_hash"], "_anchor": t4["anchor_hash"], "_parent_text": t4["parent_text"]}))
else:
    print("missing translations, run src/translate_parents.py finalise")

# 3. Benign code-mixed (HF): balances script/language so "Hinglish" can't stand in for "scam"
if f := latest("cmu_hinglish_dog", "indic"):
    d = pd.read_parquet(f).sample(HINGLISH_BENIGN_PER_SOURCE, random_state=0)
    text = d["translation"].map(lambda x: x["hi_en"] if isinstance(x, dict) else ast.literal_eval(x)["hi_en"])
    frames.append(pd.DataFrame({"text": text, "label": 0, "category": "benign_chat", "channel": "chat",
                                "language": "hinglish", "source": "cmu_hinglish_dog", "is_synthetic": False}))

if f := latest("hinglish_conversations", "indic"):
    d = pd.read_csv(f).sample(HINGLISH_BENIGN_PER_SOURCE // 2, random_state=0)
    text = pd.concat([d["input"], d["output"]], ignore_index=True)
    frames.append(pd.DataFrame({"text": text, "label": 0, "category": "benign_chat", "channel": "chat",
                                "language": "hinglish", "source": "hinglish_conversations", "is_synthetic": True}))

# splits-v3 D-v3.3 item 3: the synthetic benign UPI collect-request families (OFF by default; tagged is_synthetic, provenance illustrative, source synth_upi_collect_v3)
if ARGS.synth_upi_collect:
    frames.append(synth_upi_collect.make_family())
    print(f"synthetic UPI collect families: {synth_upi_collect.N_TEMPLATES} families x 4 languages x {synth_upi_collect.N_PER_TEMPLATE} rows, placement {synth_upi_collect.placement()}")

# splits-v3 D-v3.1: the POOL half of the real phone messages, last in the frame so that an existing row always wins a clash with a pool row (never the other way round)
if ARGS.pool_file.lower() != "none" and ARGS.pool_file != pool.POOL_PATH and not os.path.exists(ARGS.pool_file):
    raise SystemExit(f"--pool-file {ARGS.pool_file} does not exist")
POOL = pool.load_pool(ARGS.pool_file, ARGS.freeze_manifest, ARGS.real_test_file) if POOL_ON else None
if POOL is not None:
    frames.append(POOL)
    print(f"pool: {len(POOL)} rows from {POOL['real_group'].nunique()} template groups ({ARGS.pool_file}); {int(POOL['_real_match'].sum())} are the same text as a real_test_v1 row")
    LEDGER["pool"] = {"file": ARGS.pool_file, "rows_in_file": len(POOL), "groups_in_file": int(POOL["real_group"].nunique()), "seed": pool.POOL_SEED,
                      "drops": {}, "placed": {}}
else:
    print(f"pool: {ARGS.pool_file} not used ({'none requested' if ARGS.pool_file.lower() == 'none' else 'file not found'}); no phones_pool rows in this build")

# real_group (the intake's template group id) is a forced-group column of a build with a pool; _kw / _gsize / _real_match are the pool's temporary columns
df = pd.concat(frames, ignore_index=True).reindex(columns=COLS + ["real_group", "_kw", "_gsize", "_real_match", "_anchor", "_parent_text"])
df["text"] = df["text"].astype(str).str.strip()
df = df[df["text"].str.len() > 3]
df["label"] = df["label"].astype(int)
df["subcategory"] = df["subcategory"].fillna("")
FILL = ["template_id", "template_family", "company_key", "provenance", "note", "translation_of", "real_group", "_kw", "_anchor", "_parent_text"]
df[FILL] = df[FILL].fillna("")
df["_gsize"] = df["_gsize"].map(lambda v: int(v) if v == v else 0)
df["_real_match"] = df["_real_match"].map(lambda v: bool(v) if v == v else False)

# 3b. mask PII (README: ethics). Same tokens for every source so masking itself isn't a label signal.
from pii import MASKS, MASKS_V1, MISS_RX   # shared with translate_parents.py
# web_scams.csv is already masked by extract_scams.PII, which tags UPI IDs <UPI>; unify so the token isn't source-specific
df["text"] = df["text"].str.replace("<UPI>", "<UPI_ID>", regex=False)
unmasked = df["text"]
misses_v1 = unmasked.copy()
for pat, tok in MASKS_V1:   # the splits-v1 masks, only to recompute each row's splits-v1 hash (step 5)
    misses_v1 = misses_v1.str.replace(pat, tok, regex=True)
for pat, tok in MASKS:
    df["text"] = df["text"].str.replace(pat, tok, regex=True)
text_v2 = df["text"]   # every row masked with the v2 masks (the stored text itself in a v2 build): gives hash_v2 in step 5
is_tr = df["source"] == "translated_indic"
if ARGS.mask_version == pii.V2:
    assert (df.loc[is_tr, "text"] == unmasked[is_tr]).all(), "a translation contains something the PII masks change"
else:
    # the other mask set runs on the raw text of each row, with its channel (the ALL-CAPS payer rule is for SMS-type channels only)
    mask_fn, kinds_of = pii.mask_set(ARGS.mask_version), []
    masked = []
    for t, ch in zip(unmasked, df["channel"]):
        k = set()
        masked.append(mask_fn(t, channel=ch, kinds=k))
        kinds_of.append(k)
    df["text"] = pd.Series(masked, index=df.index)
    # splits-v3 D-v3.1 / D-v3.5: the masks are idempotent, v3(v3(x)) == v3(x), so a POOL row the intake masked (or a stored row) goes through them again unchanged.
    # A row the masks did not change is a fixed point already; only the changed rows can differ.
    ch_rows = (df["text"] != unmasked).to_numpy()
    again = [mask_fn(t, channel=ch) for t, ch in zip(df["text"][ch_rows], df["channel"][ch_rows])]
    not_idem = int(sum(a != b for a, b in zip(again, df["text"][ch_rows])))
    assert not_idem == 0, f"STOP: the {ARGS.mask_version} masks are not idempotent on {not_idem} of {int(ch_rows.sum())} changed rows"
    print(f"{ARGS.mask_version} masks idempotent on all {int(ch_rows.sum())} rows they change")
    # splits-v3 D-v3.5: the masks change a translation only where they change its English parent the same way
    chg = is_tr & (df["text"] != unmasked)
    kinds_s = pd.Series(kinds_of, index=df.index)   # df's index has gaps (the length filter above does not reset it)
    drift = Counter()
    for t, ptext, k in zip(unmasked[chg], df.loc[chg, "_parent_text"], kinds_s[chg]):
        pk = set()
        parent_changed = mask_fn(ptext, channel="sms", kinds=pk) != ptext
        if not (parent_changed and k <= pk):
            drift[(tuple(sorted(k)), "parent changed" if parent_changed else "parent not changed")] += 1
    if drift:
        msg = f"{sum(drift.values())} of {int(chg.sum())} changed translations are not changed by the {ARGS.mask_version} masks the way their English parent is: {dict(drift)}"
        assert ARGS.report_translation_drift, "STOP: " + msg + " (D-v3.5: decide the mask rule, or look with --report-translation-drift)"
        print("TRANSLATION DRIFT (report only): " + msg)
    df["_v3_changed"] = df["text"] != text_v2   # for the table printed after the split check (rows that survive the dedupe)
    df["_v3_kinds"] = [",".join(sorted(k)) for k in kinds_of]
print(f"PII mask misses (word@letter): splits-v1 masks {int(misses_v1.str.contains(MISS_RX).sum())} rows, now {int(df['text'].str.contains(MISS_RX).sum())} rows")

# 4. script detection by Unicode block share
def script(t):
    letters = [c for c in t if c.isalpha()]
    if not letters:
        return "latin"
    dev = sum("ऀ" <= c <= "ॿ" for c in letters) / len(letters)
    kan = sum("ಀ" <= c <= "೿" for c in letters) / len(letters)
    # Latin tokens (Rs, OTP, URLs, bank names) are common in Indic SMS, so a majority share is enough
    if dev >= 0.5: return "devanagari"
    if kan >= 0.5: return "kannada"
    if dev + kan > 0.1: return "mixed"
    return "latin"
df["script"] = df["text"].map(script)

# 5. dedupe on normalised text; keep first, remember every source it appeared in
norm = df["text"].str.lower().str.replace(r"\s+", " ", regex=True)
df["text_hash"] = norm.map(lambda s: hashlib.md5(s.encode()).hexdigest())
# the hash the same row had under the splits-v1 masks: rows whose masked text changed keep their frozen split through it
# (same pandas normalisation as text_hash: pandas' \s does not match a no-break space, Python's re does, so the two differ)
norm_v1 = misses_v1.str.lower().str.replace(r"\s+", " ", regex=True)
df["hash_v1"] = df["text_hash"].where(df["text"] == misses_v1, norm_v1.map(lambda s: hashlib.md5(s.encode()).hexdigest()))
# ... and under the v2 masks: the same as text_hash in a v2 build, the key splits-v2 froze the row under in a v3 build
norm_v2 = text_v2.str.lower().str.replace(r"\s+", " ", regex=True)
df["hash_v2"] = df["text_hash"].where(df["text"] == text_v2, norm_v2.map(lambda s: hashlib.md5(s.encode()).hexdigest()))
df["dup_sources"] = df.groupby("text_hash")["source"].transform(lambda s: ",".join(sorted(set(s))))

# frozen splits. A row whose masked text changed (splits-v2 masks, then v3) is found through the hash it had under the masks it was frozen with.
frozen = pd.read_csv(SPLIT_MAP).set_index("text_hash")["split"] if os.path.exists(SPLIT_MAP) else pd.Series(dtype=str)
# The row's OWN previous hash comes first: under v3 a changed row can get the very hash another, unchanged row was frozen under (two texts that differ only
# in a name or an id), and looking up its text_hash first would hand it that row's key and split. In a v2 build hash_v2 is text_hash, so nothing changes there.
fixed_of = lambda d: d["hash_v2"].map(frozen).fillna(d["text_hash"].map(frozen)).fillna(d["hash_v1"].map(frozen))
def frozen_key(d):
    """The split_map.csv key each row is found by (hash_v2, else text_hash, else hash_v1); NaN for a row that is not in the map."""
    return d["hash_v2"].where(d["hash_v2"].isin(frozen.index), d["text_hash"].where(d["text_hash"].isin(frozen.index), d["hash_v1"].where(d["hash_v1"].isin(frozen.index))))
DROPPED_KEYS = set()   # frozen keys of rows this build drops on purpose (counted), so "no frozen row lost" can still be asserted

# splits-v3 D-v3.1: a pool row that is the same text as a real test row, as an existing row, or as another pool row is dropped and counted. It is the POOL row that goes,
# never the existing row (so no frozen row is lost and no existing label is overturned by a pool label).
if POOL is not None:
    df, pool_dropped = pool.prefilter(df)
    # a pool row frozen in an earlier split_map that is dropped now; not the key of an existing row it merely duplicates (that row stays and keeps its key)
    DROPPED_KEYS |= set(frozen_key(pool_dropped).dropna()) - set(frozen_key(df).dropna())
    LEDGER["pool"]["drops"].update({k: int(v) for k, v in pool_dropped["_reason"].value_counts().items()})
    print(f"pool prefilter: {len(pool_dropped)} of {len(POOL)} pool rows dropped: {LEDGER['pool']['drops']}")

# v3 never un-merges what v2 merged: rows that are the same text under the v2 masks stay duplicates (and label conflicts) even when a v3 rule that depends on the
# row's channel (ALL-CAPS payer names) reads their copies differently
conflict = (df.groupby("text_hash")["label"].transform("nunique") > 1) | (df.groupby("hash_v2")["label"].transform("nunique") > 1)
print(f"rows {len(df)}, exact dups {df['text_hash'].duplicated().sum()}, label-conflicting dups {conflict.sum()}")
if len(frozen):
    fz = fixed_of(df)
    # two frozen rows that are the same text under the new masks: a train row goes (counted), a val row and a test row stop the build, and so does a
    # label conflict that reaches a val / test row (never silently dropped)
    sp = pd.DataFrame({"h": df["text_hash"], "s": fz}).dropna()
    n_sp = sp.groupby("h")["s"].nunique()
    cross = set(n_sp[n_sp > 1].index)
    if cross:
        vt = sp[sp["h"].isin(cross) & (sp["s"] != "train")].groupby("h")["s"].nunique()
        assert not (vt > 1).any(), f"STOP: {int((vt > 1).sum())} texts are one val row and one test row under the new masks: decide before dropping either"
        drop = df["text_hash"].isin(cross) & (fz == "train")
        print(f"dropping {int(drop.sum())} frozen train rows that are the same text as a frozen val / test row under the {ARGS.mask_version} masks: "
              f"{df[drop].groupby('source').size().to_dict()}")
        DROPPED_KEYS |= set(frozen_key(df[drop]).dropna())
        df, conflict, fz = df[~drop], conflict[~drop], fz[~drop]
    assert not (conflict & fz.isin(["val", "test"])).any(), "STOP: a val / test row is the same text as a row of the other label under the new masks"
    DROPPED_KEYS |= set(frozen_key(df[conflict]).dropna())
df = df[~conflict]
# web quotes often also appear in india_fraud_final (which comes first and is kept); keep their provenance on the kept row
is_pool = df["source"] == pool.POOL_SOURCE   # pool rows keep their own provenance / note (phone_N) and never lend them to another row
web = df[(df["provenance"] != "") & ~is_pool].drop_duplicates("hash_v2").set_index("hash_v2")   # by the v2 hash: a copy a v3 rule reads differently still hands its provenance on
for c in ["provenance", "note"]:
    df.loc[~is_pool, c] = df.loc[~is_pool, "hash_v2"].map(web[c]).fillna("")
before = df[df["source"] == "translated_indic"]
# every hash a row is known by -> the text_hash it is deduplicated on, so a translation's anchor still finds its parent when the parent was merged into another row
canon = df["hash_v2"].map(df.groupby("hash_v2")["text_hash"].first())   # the text_hash of the row that survives the v2-hash dedupe below
alias = {**dict(zip(df["hash_v1"], canon)), **dict(zip(df["hash_v2"], canon)), **dict(zip(df["text_hash"], canon))}
DROPPED_KEYS |= set(frozen_key(df[df["hash_v2"].duplicated()]).dropna())   # kept rows' keys come back through new_map below
df = df.drop_duplicates("hash_v2")
DROPPED_KEYS |= set(frozen_key(df[df["text_hash"].duplicated()]).dropna())
df = df.drop_duplicates("text_hash").reset_index(drop=True)
tr_step("exact duplicate of another row (dedupe)", before, df[df["source"] == "translated_indic"])
df["fkey"] = frozen_key(df)

# splits-v3 D-v3.4: a company group (company_key) that holds frozen rows of more than one split keeps the rows of its highest-priority split (test > val > train); its other
# frozen rows are dropped and counted. Test membership is frozen (D-v3.2), so a test row never moves. Only the name-filled keys can cause this: the profile-based keys
# were already one split each. Dropped keys go to DROPPED_KEYS so "no frozen row is lost" still holds for the rest.
if ARGS.company_name_key:
    cdrop = company_key.keep_by_priority(fixed_of(df), df["company_key"])
    names = globals().get("COMPANY_NAMES", {})
    gone = df[cdrop]
    LEDGER["company_straddle_drops"] = {"rows": int(cdrop.sum()),
        "by_company_split_label": {f"{names.get(k, k[:8])} | {sp} | label {lab}": int(n) for (k, sp, lab), n in
                                   gone.assign(sp=fixed_of(df)[cdrop]).groupby(["company_key", "sp", "label"]).size().items()}}
    print(f"company groups that straddle frozen splits: {int(cdrop.sum())} frozen rows dropped (the higher split stays): {LEDGER['company_straddle_drops']['by_company_split_label']}")
    DROPPED_KEYS |= set(frozen_key(gone).dropna())
    df = df[~cdrop].reset_index(drop=True)

# 5b. cross-language leakage guard: a translation is dropped if its English parent has a val/test row of messages.csv at
# exact Jaccard >= TWIN_JACCARD on either view (finalise anchored parents against short rows only; this looks at every row)
is_tr = df["source"] == "translated_indic"
if is_tr.any():
    ev = df.index[fixed_of(df).isin(["val", "test"])].tolist()
    ptexts = sorted(set(df.loc[is_tr, "_parent_text"]))
    texts = list(df.loc[ev, "text"]) + ptexts
    q = range(len(ev), len(texts))
    bad = set()
    for fn in neardup.VIEWS.values():
        shs = neardup.shingle_sets([fn(x) for x in texts])
        for i, j, _ in neardup.near_dup_pairs(shs, neardup.CHECK_SEED, TWIN_JACCARD, queries=q, skip=lambda i, j: j >= len(ev)):
            bad.add(texts[i])
        del shs
    before = df[is_tr]
    DROPPED_KEYS |= set(frozen_key(df[is_tr & df["_parent_text"].isin(bad)]).dropna())
    df = df[~(is_tr & df["_parent_text"].isin(bad))].reset_index(drop=True)
    tr_step(f"English parent has a val/test twin at J >= {TWIN_JACCARD}", before, df[df["source"] == "translated_indic"])
    is_tr = df["source"] == "translated_indic"

# 6. near-duplicate clusters, joined by union-find. cluster_id = smallest text_hash in the cluster, so a singleton's
# cluster_id is its own text_hash.
parent = list(range(len(df)))
def find(x):
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x
def union(a, b):
    parent[find(a)] = find(b)
# forced groups first: they make most of the big job-post clusters, so the text pass can skip those pairs
for key in ("template_family", "company_key", "translation_of", "real_group"):   # real_group (splits-v3 D-v3.1): an intake template group never straddles splits
    for rows in df[df[key] != ""].groupby(key).groups.values():
        for j in rows[1:]:
            union(rows[0], j)
# a translation also joins its English parent's messages.csv row (anchor_hash is a splits-v1 hash)
pos = dict(zip(df["text_hash"], df.index))
for i, a in df.loc[is_tr & (df["_anchor"] != ""), "_anchor"].items():
    assert a in alias and alias[a] in pos, f"anchor {a} of a translation is not a messages.csv row"
    union(i, pos[alias[a]])
forced = len({find(i) for i in range(len(df))})
for i, j, _, _ in neardup.near_dup_pairs_any(df["text"], df["source"], neardup.CLUSTER_SEED,
                                           skip=lambda i, j: find(i) == find(j)):
    union(i, j)
root = pd.Series([find(i) for i in range(len(df))], index=df.index)
df["cluster_id"] = df["text_hash"].groupby(root).transform("min")
print(f"clusters: {len(df)} rows -> {forced} after template-family/company/translation grouping -> {df['cluster_id'].nunique()} after text pass")

# 7. split. Rule for a fresh cluster: hash bucket 80/10/10 (same scheme as build_urls.py). Clusters holding synth_india
# rows are stratified per (category, label) instead, so every language/label pair reaches test (a template family spans
# all four languages): in each cell, clusters ordered by md5: 1st -> test, 2nd -> val if the cell has 3+, rest -> train.
# A one-cluster cell stays in train. Rows already in SPLIT_MAP keep their split; new rows join their cluster's.
md5 = lambda k: hashlib.md5(k.encode()).hexdigest()
templated = df["template_family"] != ""
def rule_split(unit):
    tpl = unit.isin(set(unit[templated]))
    split = pd.Series("", index=df.index)
    split[~tpl] = pd.cut(unit[~tpl].map(lambda h: int(h, 16) % 100), [-1, 79, 89, 99],
                         labels=["train", "val", "test"]).astype(str)
    cells = df[templated].assign(unit=unit[templated])
    cells = cells.loc[cells["template_family"].map(md5).sort_values().index].drop_duplicates("unit")
    assign = {}
    for cell, g in cells.groupby(["category", "label"]):
        ids = sorted(g["unit"], key=md5)
        if len(ids) < 2:
            print(f"warning: only one template cluster in {cell}, kept in train")
        for i, u in enumerate(ids):
            assign[u] = "test" if i == 0 and len(ids) > 1 else "val" if i == 1 and len(ids) > 2 else "train"
    split[tpl] = unit[tpl].map(assign)
    return split

prev = None   # last build's split per text_hash, only to report what moved
if os.path.exists(f := "data/final/messages.csv"):
    prev = pd.read_csv(f, usecols=["text_hash", "split"]).drop_duplicates("text_hash").set_index("text_hash")["split"]
fixed = fixed_of(df)   # NaN for rows not frozen yet
lost_v1 = set(frozen.index) - set(df["hash_v1"]) - set(df["text_hash"]) - set(df["hash_v2"]) - DROPPED_KEYS
assert not lost_v1, f"{len(lost_v1)} frozen rows are missing from this build, in splits {frozen.loc[sorted(lost_v1)].value_counts().to_dict()}"
# A row that is not in the map (splits-v2 dropped one phishing_email train row because the v2 masks made it a twin of a test row; it comes back here as a
# new row) whose cluster holds a frozen test row is dropped and counted, never placed in test (docs/plans/splits_v3.md D-v3.2). The map holds the
# translations since splits-v2 (train); one that is not in it is new and goes to train below.
known0 = pd.DataFrame({"c": df["cluster_id"], "s": fixed}).dropna().groupby("c")["s"].first()
is_pool = df["source"] == pool.POOL_SOURCE
is_syn = df["source"] == synth_upi_collect.SOURCE
new_in_test = fixed.isna() & ~is_tr & (df["cluster_id"].map(known0) == "test")
if new_in_test.any():
    if POOL is not None:
        LEDGER["pool"]["drops"][pool.DROP_TEST_CLUSTER] = int((new_in_test & is_pool).sum())
    if ARGS.synth_upi_collect:
        LEDGER["synth_upi_collect_dropped_test_cluster"] = int((new_in_test & is_syn).sum())
    print(f"dropping {int(new_in_test.sum())} rows that are not in split_map.csv and whose cluster holds a frozen test row: {df[new_in_test].groupby(['source', 'label']).size().to_dict()}")
    df = df[~new_in_test].reset_index(drop=True)
    is_tr = df["source"] == "translated_indic"
    is_pool, is_syn = df["source"] == pool.POOL_SOURCE, df["source"] == synth_upi_collect.SOURCE
    fixed = fixed_of(df)
assert not (fixed.isna() & ~is_tr & ~is_pool & ~is_syn).any(), ("every row except the translations must be in split_map.csv (directly or by its splits-v1 / v2 hash); not in it: "
                                           f"{df[fixed.isna() & ~is_tr & ~is_pool & ~is_syn].groupby('source').size().to_dict()} (only phones_pool and the synth_upi_collect_v3 families are added as new rows)")
rule = rule_split(df["cluster_id"])
if fixed.notna().any():
    known = pd.DataFrame({"c": df["cluster_id"], "s": fixed}).dropna().groupby("c")["s"].agg(["first", "nunique"])
    inherit = df["cluster_id"].map(known["first"])
    clash = fixed.isna() & (df["cluster_id"].map(known["nunique"]) > 1)   # new row that bridges frozen rows of 2+ splits
    df["split"] = fixed.fillna(inherit).fillna(rule)
    # translations are train only (D20, D26): one that inherited a val/test cluster's split is a leak, not a choice
    assert not (is_tr & inherit.isin(["val", "test"])).any(), "a translation landed in a val/test cluster"
    fresh = is_tr & inherit.isna()
    assert df.loc[df["cluster_id"].isin(set(df.loc[fresh, "cluster_id"])), "source"].eq("translated_indic").all()
    df.loc[fresh, "split"] = "train"
    # splits-v3 D-v3.1: a pool cluster that joined no frozen row is split 50 % val / 50 % train, stratified by label x the intake's keyword bucket (pool.place_fresh, seeded,
    # written to the ledger); one that joined a frozen train / val cluster took that split above (inherit). Never test: a cluster that reached a test row was dropped before.
    # The synthetic UPI collect families are placed by synth_upi_collect.placement() the same way (never test, whatever the synth_india cell rule says).
    fresh_cl = inherit.isna() & fixed.isna()
    fresh_pool = fresh_cl & df["cluster_id"].isin(set(df.loc[is_pool & fresh_cl, "cluster_id"]))
    if fresh_pool.any():
        placed, strata = pool.place_fresh(df[is_pool & fresh_cl])
        df.loc[fresh_pool, "split"] = df.loc[fresh_pool, "cluster_id"].map(placed)
        LEDGER["pool"]["placed"]["fresh_clusters_val_train"] = [sum(v == s_ for v in placed.values()) for s_ in ("val", "train")]
        LEDGER["pool"]["strata_label_kw_val_train_units"] = {f"{l} | {k}": c for (l, k), c in strata.items()}
    fresh_syn = fresh_cl & is_syn
    if fresh_syn.any():
        sp_of = synth_upi_collect.placement()
        df.loc[fresh_syn, "split"] = df.loc[fresh_syn, "template_family"].map(sp_of)
    if POOL is not None:
        how = pd.Series("frozen in split_map.csv (an earlier build)", index=df.index).where(fixed.notna(), pd.Series("joined an existing cluster", index=df.index).where(inherit.notna(), "placed as a fresh cluster"))
        LEDGER["pool"]["placed"]["rows_by_how_and_split"] = {f"{h} | {sp}": int(n) for (h, sp), n in df[is_pool].assign(h=how[is_pool]).groupby(["h", "split"]).size().items()}
    print(f"split_map: {fixed.notna().sum()} rows frozen, {fixed.isna().sum()} new "
          f"({(fixed.isna() & inherit.notna()).sum()} inherited a cluster's split, "
          f"{(fixed.isna() & inherit.isna()).sum()} placed by rule)")
    if clash.any():
        if POOL is not None:
            LEDGER["pool"]["drops"][pool.DROP_BRIDGE] = int((clash & is_pool).sum())
        print(f"warning: dropping {clash.sum()} new rows that bridge frozen clusters in different splits")
        before = df[is_tr]
        df = df[~clash].reset_index(drop=True)
        tr_step("bridges frozen clusters in different splits", before, df[df["source"] == "translated_indic"])
        is_tr = df["source"] == "translated_indic"
else:
    df["split"] = rule

# The splits-v2 masks can make two frozen rows of different splits near-duplicates (a pair at J 0.69 under the old masks reaches 0.72
# once both handles are <EMAIL>). Val / test stay exactly as frozen: the TRAIN rows of such a cluster are dropped. Only for clusters that
# hold a re-keyed row and a train row; any other straddle still fails in assert_no_leakage below.
n_split = df.groupby("cluster_id")["split"].nunique()
mask_join = df["cluster_id"].isin(n_split[n_split > 1].index)
if mask_join.any():
    g = df[mask_join].groupby("cluster_id")
    ok = g.apply(lambda c: ((c["hash_v1"] != c["text_hash"]).any() or (c["hash_v2"] != c["text_hash"]).any()) and (c["split"] == "train").any() and c["split"].nunique() == 2)
    assert ok.all(), (f"STOP: {int((~ok).sum())} clusters straddle splits for a reason other than the new masks, or hold a val and a test row joined by them "
                      f"(decide before dropping either): {list(ok[~ok].index[:3])}")
    drop = mask_join & (df["split"] == "train")
    print(f"dropping {int(drop.sum())} train rows whose cluster now reaches a val/test row through the new masks: "
          f"{df[drop].groupby(['source', 'label']).size().to_dict()}")
    MASK_DROPPED = df.loc[drop, ["text_hash", "fkey", "source", "label"]]
    df = df[~drop].reset_index(drop=True)
    is_tr = df["source"] == "translated_indic"
# the real leakage check: runs before anything is written, so a leaky split can't overwrite the last good files
neardup.assert_no_leakage(df)
print(f"leakage check passed: no cluster / template family / company straddles splits, no cross-split pair with exact "
      f"Jaccard >= {neardup.MIN_JACCARD} on raw or normalised text ({neardup.SOURCE_MIN_JACCARD} within those sources)")
assert (df.loc[is_tr, "split"] == "train").all(), "a translation outside train"
fo = fixed_of(df)
is_new = (df["source"] == pool.POOL_SOURCE) | (df["source"] == synth_upi_collect.SOURCE)   # the only rows that may be absent from the frozen map (a pool row is in it from the second build on)
assert not (fo.isna() & ~is_tr & ~is_new).any(), "a row that should be frozen is not in split_map.csv"
assert (df.loc[~is_tr & fo.notna(), "split"] == fo[~is_tr & fo.notna()]).all(), "a splits-v1 row changed split"
assert not (df.loc[df["source"] == synth_upi_collect.SOURCE, "split"] == "test").any(), "a synthetic UPI collect row is in test (D-v3.2: test membership is frozen)"
for msg in pool.straddles(df):   # splits-v3 D-v3.1: no real_group in two splits, no pool row in test
    raise AssertionError(msg)
if ARGS.company_name_key and df["company_key"].ne("").any():
    ck = df[df["company_key"] != ""]
    assert not (ck["split"].astype(str).groupby(ck["company_key"]).nunique() > 1).any(), "a company group straddles splits"
df["split"] = pd.Categorical(df["split"], ["train", "val", "test"])

os.makedirs(OUT_DIR, exist_ok=True)
new_map = pd.DataFrame({"text_hash": df["text_hash"], "split": df["split"].astype(str)})
old_map = frozen.rename("split").rename_axis("text_hash").reset_index()
rehashed = df[df["fkey"].notna() & (df["fkey"] != df["text_hash"])]
old_map = old_map[~old_map["text_hash"].isin(rehashed["fkey"])]   # replaced by the row's new hash, same split
old_map = old_map[~old_map["text_hash"].isin(DROPPED_KEYS)]   # rows dropped on purpose before the split step (exact duplicates under the new masks, label conflicts)
if "MASK_DROPPED" in globals():
    old_map = old_map[~old_map["text_hash"].isin(MASK_DROPPED["fkey"].dropna())]   # dropped above: its cluster reached a val / test row through the new masks
rekey_tab = rehashed.groupby(["source", "split"], observed=True).size().unstack(fill_value=0)
if ARGS.mask_version != pii.V2:
    ADDED = ["greeting_name", "caps_name", "card", "otp", "acct_tail", "long_digits"]   # what v3 adds to v2; the other steps (address, phone_account, link_phone, v2_sweep) mostly redo v2
    tab = pd.DataFrame({"source": df["source"], "split": df["split"].astype(str), "changed": df["_v3_changed"],
                        **{k: df["_v3_kinds"].str.split(",").map(lambda s: k in s) for k in ADDED + ["link_phone", "v2_sweep"]}})
    print(f"\n{ARGS.mask_version} masks vs the v2 masks, on the {len(df)} rows of this build: {int(tab['changed'].sum())} get a different text ({tab['changed'].mean():.1%}), by split "
          f"{tab.groupby('split')['changed'].sum().astype(int).to_dict()}")
    print(tab.drop(columns="split").groupby("source").sum().astype(int).to_string())
    print(tab[tab["changed"]].groupby("split")[ADDED].sum().astype(int).to_string())
print(f"split_map: {len(rehashed)} rows re-keyed to their {ARGS.mask_version} hash (same split): "
      f"{rehashed.groupby('split', observed=True).size().to_dict()}")
if len(rehashed):
    print(rekey_tab.to_string())
pd.concat([old_map, new_map]).drop_duplicates("text_hash").sort_values("text_hash").to_csv(OUT_SPLIT_MAP, index=False)

size = df["cluster_id"].value_counts()
mixed = df.groupby("cluster_id")["label"].nunique() > 1
print(f"\nnear-dup clusters: {len(size)} for {len(df)} rows; {(size > 1).sum()} multi-row clusters hold "
      f"{size[size > 1].sum()} rows; {mixed.sum()} mix scam and benign")
for cid in mixed[mixed].index[:8]:
    g = df[df["cluster_id"] == cid]
    print(f"  mixed ({len(g)} rows, labels {g['label'].tolist()[:6]}): " + " ~ ".join(ascii(t[:55]) for t in g["text"].head(2)))
print("10 largest:")
for cid, n in size.head(10).items():
    r = df[df["cluster_id"] == cid].iloc[0]
    print(f"  {n:4d}  {r['source']:<18} {ascii(r['text'][:90])}")
if prev is not None:
    old = df["hash_v2"].map(prev).fillna(df["text_hash"].map(prev)).fillna(df["hash_v1"].map(prev))
    moved = old.notna() & (old != df["split"].astype(str))
    print(f"\nvs previous messages.csv: {old.isna().sum()} new rows, {moved.sum()} of {old.notna().sum()} existing rows "
          f"changed split ({moved.sum() / old.notna().sum():.1%})")
    print(pd.crosstab(old[moved].rename("old"), df.loc[moved, "split"].rename("new")))
    print(df[moved].groupby("source").size().sort_values(ascending=False).to_string())

if TR_LEDGER:
    print("\ntranslation ledger (rows dropped at each step, rows left after it):")
    print(pd.DataFrame(TR_LEDGER).to_string(index=False))
if POOL is not None:
    df["kw_bucket"] = df["_kw"]   # the intake's keyword bucket of a pool row ("" elsewhere): gates_v3.py counts the Indian alert groups with it
df = df.drop(columns=["_anchor", "_parent_text", "hash_v1", "hash_v2", "fkey", "_v3_changed", "_v3_kinds", "_kw", "_gsize", "_real_match"] + ([] if POOL is not None else ["real_group"]), errors="ignore")
# tripwire: no row of the real-message TEST set (data/real/real_test_v1.csv) may enter messages.csv
realguard.guard_inputs([], [("messages.csv to be written", df)], real_path=ARGS.real_test_file)
df.to_csv(OUT_MESSAGES, index=False)
# the mask set the stored text was masked with, for whoever trains on it (a bundle records it as shield_meta.json "mask_version"; the app masks input with it)
with open(OUT_META, "w", encoding="utf-8") as f:
    json.dump({"mask_version": ARGS.mask_version, "rows": len(df), "split_map_rows": int(len(new_map)), "pool_rows": int((df["source"] == pool.POOL_SOURCE).sum()),
               "real_group_column": POOL is not None, "company_name_key": ARGS.company_name_key, "synth_upi_collect": ARGS.synth_upi_collect, "ledger": LEDGER}, f, indent=1, default=str)
print(f"wrote {OUT_MESSAGES}, {OUT_SPLIT_MAP}, {OUT_META} (mask_version {ARGS.mask_version})")
if POOL is not None:
    pr = df[df["source"] == pool.POOL_SOURCE]
    print("\npool ledger (D-v3.1): rows in file %d -> kept %d; drops by reason %s; test rows %d; real_group count by split %s" % (
        len(POOL), len(pr), LEDGER["pool"]["drops"], int((pr["split"] == "test").sum()), pr.groupby("split", observed=True)["real_group"].nunique().to_dict()))
    print("  placed:", LEDGER["pool"]["placed"])
    print("  rows by split x label:", pr.groupby(["split", "label"], observed=True).size().to_dict())
    if "strata_label_kw_val_train_units" in LEDGER["pool"]:
        print("  fresh strata (label | keyword bucket: val units, train units):", LEDGER["pool"]["strata_label_kw_val_train_units"])
print(df.groupby(["source", "label"]).size().unstack(fill_value=0))
print("\nby category:\n", df.groupby(["category", "label"]).size().unstack(fill_value=0))
print("\nsplit:\n", df.groupby(["split", "label"], observed=True).size().unstack(fill_value=0))
print("\nsource x split:\n", df.groupby(["source", "split"], observed=True).size().unstack(fill_value=0))
print("\nscript x label:\n", df.groupby(["script", "label"]).size().unstack(fill_value=0))
print("\nlanguage x label:\n", df.groupby(["language", "label"]).size().unstack(fill_value=0))
print("\nprovenance x split (web quotes):\n", df[df["provenance"] != ""].groupby(["provenance", "split"], observed=True).size().unstack(fill_value=0))
print("\nmasked:", {t: int(df["text"].str.contains(t, regex=False).sum()) for _, t in MASKS})
print("\nsynthetic share by label:", df.groupby("label")["is_synthetic"].mean().round(2).to_dict())
print("\nshortcut check (share of each class):")
df["has_url"] = df["text"].str.contains(r"https?://|www\.|\.(?:com|in|ly|vip)\b", regex=True)
df["len"] = df["text"].str.len()
print(df.groupby("label")[["has_url", "is_synthetic"]].mean().round(2), df.groupby("label")["len"].median())
