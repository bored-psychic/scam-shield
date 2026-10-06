import ast, glob, hashlib, json, os, re
import pandas as pd
import neardup

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
        "template_family", "company_key", "provenance", "note"]

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

df = pd.concat(frames, ignore_index=True).reindex(columns=COLS)
df["text"] = df["text"].astype(str).str.strip()
df = df[df["text"].str.len() > 3]
df["label"] = df["label"].astype(int)
df["subcategory"] = df["subcategory"].fillna("")
df[["template_id", "template_family", "company_key", "provenance", "note"]] = \
    df[["template_id", "template_family", "company_key", "provenance", "note"]].fillna("")

# 3b. mask PII (README: ethics). Same tokens for every source so masking itself isn't a label signal.
MASKS = [
    (r"[\w.+-]+@[\w-]+\.[\w.]+", "<EMAIL>"),
    (r"\b[\w.-]{2,}@(?:ok)?(?:sbi|hdfc|icici|axis|paytm|ybl|ibl|upi|apl|okaxis|okhdfcbank|okicici|oksbi)\b", "<UPI_ID>"),
    (r"(?:\+91[\s-]?|\+92[\s-]?|\b0)?\b[6-9]\d{4}[\s-]?\d{5}\b", "<PHONE>"),
    (r"\b(?:XX|xx|\*{2,})?\d{9,18}\b", "<ACCOUNT>"),
]
# web_scams.csv is already masked by extract_scams.PII, which tags UPI IDs <UPI>; unify so the token isn't source-specific
df["text"] = df["text"].str.replace("<UPI>", "<UPI_ID>", regex=False)
for pat, tok in MASKS:
    df["text"] = df["text"].str.replace(pat, tok, regex=True)

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
df["dup_sources"] = df.groupby("text_hash")["source"].transform(lambda s: ",".join(sorted(set(s))))
conflict = df.groupby("text_hash")["label"].transform("nunique") > 1
print(f"rows {len(df)}, exact dups {df['text_hash'].duplicated().sum()}, label-conflicting dups {conflict.sum()}")
df = df[~conflict]
# web quotes often also appear in india_fraud_final (which comes first and is kept); keep their provenance on the kept row
web = df[df["provenance"] != ""].drop_duplicates("text_hash").set_index("text_hash")
for c in ["provenance", "note"]:
    df[c] = df["text_hash"].map(web[c]).fillna("")
df = df.drop_duplicates("text_hash").reset_index(drop=True)

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
for key in ("template_family", "company_key"):
    for rows in df[df[key] != ""].groupby(key).groups.values():
        for j in rows[1:]:
            union(rows[0], j)
forced = len({find(i) for i in range(len(df))})
for i, j, _, _ in neardup.near_dup_pairs_any(df["text"], df["source"], neardup.CLUSTER_SEED,
                                           skip=lambda i, j: find(i) == find(j)):
    union(i, j)
root = pd.Series([find(i) for i in range(len(df))], index=df.index)
df["cluster_id"] = df["text_hash"].groupby(root).transform("min")
print(f"clusters: {len(df)} rows -> {forced} after template-family/company grouping -> {df['cluster_id'].nunique()} after text pass")

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
frozen = pd.read_csv(SPLIT_MAP).set_index("text_hash")["split"] if os.path.exists(SPLIT_MAP) else pd.Series(dtype=str)
fixed = df["text_hash"].map(frozen)   # NaN for rows not frozen yet
rule = rule_split(df["cluster_id"])
if fixed.notna().any():
    known = pd.DataFrame({"c": df["cluster_id"], "s": fixed}).dropna().groupby("c")["s"].agg(["first", "nunique"])
    inherit = df["cluster_id"].map(known["first"])
    clash = fixed.isna() & (df["cluster_id"].map(known["nunique"]) > 1)   # new row that bridges frozen rows of 2+ splits
    df["split"] = fixed.fillna(inherit).fillna(rule)
    print(f"split_map: {fixed.notna().sum()} rows frozen, {fixed.isna().sum()} new "
          f"({(fixed.isna() & inherit.notna()).sum()} inherited a cluster's split, "
          f"{(fixed.isna() & inherit.isna()).sum()} placed by rule)")
    if clash.any():
        print(f"warning: dropping {clash.sum()} new rows that bridge frozen clusters in different splits")
        df = df[~clash].reset_index(drop=True)
else:
    df["split"] = rule

# the real leakage check: runs before anything is written, so a leaky split can't overwrite the last good files
neardup.assert_no_leakage(df)
print(f"leakage check passed: no cluster / template family / company straddles splits, no cross-split pair with exact "
      f"Jaccard >= {neardup.MIN_JACCARD} on raw or normalised text ({neardup.SOURCE_MIN_JACCARD} within those sources)")
df["split"] = pd.Categorical(df["split"], ["train", "val", "test"])

os.makedirs("data/final", exist_ok=True)
new_map = pd.DataFrame({"text_hash": df["text_hash"], "split": df["split"].astype(str)})
old_map = frozen.rename("split").rename_axis("text_hash").reset_index()
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
    old = df["text_hash"].map(prev)
    moved = old.notna() & (old != df["split"].astype(str))
    print(f"\nvs previous messages.csv: {old.isna().sum()} new rows, {moved.sum()} of {old.notna().sum()} existing rows "
          f"changed split ({moved.sum() / old.notna().sum():.1%})")
    print(pd.crosstab(old[moved].rename("old"), df.loc[moved, "split"].rename("new")))
    print(df[moved].groupby("source").size().sort_values(ascending=False).to_string())

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
