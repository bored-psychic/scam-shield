import ast, glob, hashlib, json, os, re, unicodedata
import pandas as pd
import neardup, textprep
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

df = pd.concat(frames, ignore_index=True).reindex(columns=COLS + ["_anchor", "_parent_text"])
df["text"] = df["text"].astype(str).str.strip()
df = df[df["text"].str.len() > 3]
df["label"] = df["label"].astype(int)
df["subcategory"] = df["subcategory"].fillna("")
FILL = ["template_id", "template_family", "company_key", "provenance", "note", "translation_of", "_anchor", "_parent_text"]
df[FILL] = df[FILL].fillna("")

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
is_tr = df["source"] == "translated_indic"
assert (df.loc[is_tr, "text"] == unmasked[is_tr]).all(), "a translation contains something the PII masks change"
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
df["dup_sources"] = df.groupby("text_hash")["source"].transform(lambda s: ",".join(sorted(set(s))))
conflict = df.groupby("text_hash")["label"].transform("nunique") > 1
print(f"rows {len(df)}, exact dups {df['text_hash'].duplicated().sum()}, label-conflicting dups {conflict.sum()}")
df = df[~conflict]
# web quotes often also appear in india_fraud_final (which comes first and is kept); keep their provenance on the kept row
web = df[df["provenance"] != ""].drop_duplicates("text_hash").set_index("text_hash")
for c in ["provenance", "note"]:
    df[c] = df["text_hash"].map(web[c]).fillna("")
before = df[df["source"] == "translated_indic"]
df = df.drop_duplicates("text_hash").reset_index(drop=True)
tr_step("exact duplicate of another row (dedupe)", before, df[df["source"] == "translated_indic"])

# frozen splits. A row whose masked text changed with the splits-v2 masks is found through its splits-v1 hash.
frozen = pd.read_csv(SPLIT_MAP).set_index("text_hash")["split"] if os.path.exists(SPLIT_MAP) else pd.Series(dtype=str)
fixed_of = lambda d: d["text_hash"].map(frozen).fillna(d["hash_v1"].map(frozen))

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
for key in ("template_family", "company_key", "translation_of"):
    for rows in df[df[key] != ""].groupby(key).groups.values():
        for j in rows[1:]:
            union(rows[0], j)
# a translation also joins its English parent's messages.csv row (anchor_hash is a splits-v1 hash)
pos = {**dict(zip(df["hash_v1"], df.index)), **dict(zip(df["text_hash"], df.index))}
for i, a in df.loc[is_tr & (df["_anchor"] != ""), "_anchor"].items():
    assert a in pos, f"anchor {a} of a translation is not a messages.csv row"
    union(i, pos[a])
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
lost_v1 = set(frozen.index) - set(df["hash_v1"]) - set(df["text_hash"])
assert not lost_v1, f"{len(lost_v1)} splits-v1 rows are missing from this build"
assert (fixed.isna() == is_tr).all(), "every row except the translations must be in split_map.csv (directly or by its splits-v1 hash)"
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
    print(f"split_map: {fixed.notna().sum()} rows frozen, {fixed.isna().sum()} new "
          f"({(fixed.isna() & inherit.notna()).sum()} inherited a cluster's split, "
          f"{(fixed.isna() & inherit.isna()).sum()} placed by rule)")
    if clash.any():
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
    ok = g.apply(lambda c: (c["hash_v1"] != c["text_hash"]).any() and (c["split"] == "train").any() and c["split"].nunique() == 2)
    assert ok.all(), f"clusters straddle splits for a reason other than the new masks: {list(ok[~ok].index[:3])}"
    drop = mask_join & (df["split"] == "train")
    print(f"dropping {int(drop.sum())} train rows whose cluster now reaches a val/test row through the new masks: "
          f"{df[drop].groupby(['source', 'label']).size().to_dict()}")
    MASK_DROPPED = df.loc[drop, ["text_hash", "hash_v1", "source", "label"]]
    df = df[~drop].reset_index(drop=True)
    is_tr = df["source"] == "translated_indic"
# the real leakage check: runs before anything is written, so a leaky split can't overwrite the last good files
neardup.assert_no_leakage(df)
print(f"leakage check passed: no cluster / template family / company straddles splits, no cross-split pair with exact "
      f"Jaccard >= {neardup.MIN_JACCARD} on raw or normalised text ({neardup.SOURCE_MIN_JACCARD} within those sources)")
assert (df.loc[is_tr, "split"] == "train").all(), "a translation outside train"
assert (df.loc[~is_tr, "split"] == fixed_of(df)[~is_tr]).all(), "a splits-v1 row changed split"
df["split"] = pd.Categorical(df["split"], ["train", "val", "test"])

os.makedirs("data/final", exist_ok=True)
new_map = pd.DataFrame({"text_hash": df["text_hash"], "split": df["split"].astype(str)})
old_map = frozen.rename("split").rename_axis("text_hash").reset_index()
rehashed = df[(df["hash_v1"] != df["text_hash"]) & df["hash_v1"].isin(frozen.index)]
old_map = old_map[~old_map["text_hash"].isin(rehashed["hash_v1"])]   # replaced by the row's new hash, same split
if "MASK_DROPPED" in globals():
    old_map = old_map[~old_map["text_hash"].isin(MASK_DROPPED["hash_v1"])]   # dropped above: not in splits-v2 at all
print(f"split_map: {len(rehashed)} rows re-keyed to their splits-v2 hash (same split): "
      f"{rehashed.groupby('split', observed=True).size().to_dict()}")
pd.concat([old_map, new_map]).drop_duplicates("text_hash").sort_values("text_hash").to_csv(SPLIT_MAP, index=False)

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
    old = df["text_hash"].map(prev).fillna(df["hash_v1"].map(prev))
    moved = old.notna() & (old != df["split"].astype(str))
    print(f"\nvs previous messages.csv: {old.isna().sum()} new rows, {moved.sum()} of {old.notna().sum()} existing rows "
          f"changed split ({moved.sum() / old.notna().sum():.1%})")
    print(pd.crosstab(old[moved].rename("old"), df.loc[moved, "split"].rename("new")))
    print(df[moved].groupby("source").size().sort_values(ascending=False).to_string())

if TR_LEDGER:
    print("\ntranslation ledger (rows dropped at each step, rows left after it):")
    print(pd.DataFrame(TR_LEDGER).to_string(index=False))
df = df.drop(columns=["_anchor", "_parent_text", "hash_v1"])
import realguard   # tripwire: no row of the real-message TEST set (data/real/real_test_v1.csv) may enter messages.csv
realguard.guard_inputs([], [("messages.csv to be written", df)])
df.to_csv("data/final/messages.csv", index=False)
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
