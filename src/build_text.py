import ast, glob, hashlib, json, os, re
import pandas as pd
from datasketch import MinHash, MinHashLSH

# Build data/final/messages.csv from data/messages/ + data/external/{text,indic}/ (see data/sources.yaml).
# benign Hinglish is plentiful but Hinglish scam text is only synthetic (~220 rows); capping keeps
# the scam share within Hinglish near the overall ~20%, so language alone doesn't predict the label
HINGLISH_BENIGN_PER_SOURCE = 500
# near-duplicate clustering: MinHash over char 5-grams of the first 2000 normalised chars, Jaccard >= 0.8.
# At 0.8 the big clusters are fake_job_postings sharing a company profile and templated phishing_email batches
# (0.7 starts merging scam with benign; 0.9 misses reworded copies)
SHINGLE, NUM_PERM, NEAR_DUP_JACCARD, SHINGLE_CHARS = 5, 128, 0.8, 2000
COLS = ["text", "label", "category", "subcategory", "channel", "language", "source", "is_synthetic", "template_id",
        "provenance", "note"]

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
    frames.append(pd.DataFrame({"text": text, "label": d["fraudulent"], "category": "job", "channel": "job_post",
                                "language": "english", "source": "fake_job_postings", "is_synthetic": False}))

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

df = pd.concat(frames, ignore_index=True)[COLS]
df["text"] = df["text"].astype(str).str.strip()
df = df[df["text"].str.len() > 3]
df["label"] = df["label"].astype(int)
df["subcategory"] = df["subcategory"].fillna("")
df["template_id"] = df["template_id"].fillna("")
df[["provenance", "note"]] = df[["provenance", "note"]].fillna("")

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

# 6. near-duplicate clusters (MinHash LSH, then the estimated Jaccard re-checked per candidate pair), joined by
# union-find; rows of one template are also joined. cluster_id = smallest text_hash in the cluster, so a singleton's
# cluster_id is its own text_hash.
norm = df["text"].str.lower().str.replace(r"\s+", " ", regex=True).str.slice(0, SHINGLE_CHARS)
shingles = [{t[i:i + SHINGLE].encode() for i in range(max(1, len(t) - SHINGLE + 1))} for t in norm]
mh = MinHash.bulk(shingles, num_perm=NUM_PERM)
lsh = MinHashLSH(threshold=NEAR_DUP_JACCARD, num_perm=NUM_PERM)
for i, m in enumerate(mh):
    lsh.insert(i, m)
parent = list(range(len(df)))
def find(x):
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x
for i, m in enumerate(mh):
    for j in lsh.query(m):
        if j > i and m.jaccard(mh[j]) >= NEAR_DUP_JACCARD:
            parent[find(i)] = find(j)
templated = df["template_id"] != ""
for rows in df.groupby("template_id").indices.values():   # positions in df (index is 0..n-1 after dedupe)
    if df.at[rows[0], "template_id"]:
        for j in rows[1:]:
            parent[find(rows[0])] = find(j)
root = pd.Series([find(i) for i in range(len(df))], index=df.index)
df["cluster_id"] = df["text_hash"].groupby(root).transform("min")

# 7. deterministic split by unit: hash bucket for real units (same scheme as build_urls.py); units holding templated
# rows are stratified per (category, label, language) cell so every language/label pair reaches test. In each cell
# (units ordered by md5): 1st -> test, 2nd -> val if the cell has 3+, rest -> train. A single-unit cell stays in train.
md5 = lambda k: hashlib.md5(k.encode()).hexdigest()
def assign_split(unit, warn=True):
    tpl_unit = unit.isin(set(unit[templated]))
    split = pd.Series("", index=df.index)
    split[~tpl_unit] = pd.cut(unit[~tpl_unit].map(lambda h: int(h, 16) % 100), [-1, 79, 89, 99],
                              labels=["train", "val", "test"]).astype(str)
    cells = df[templated].assign(unit=unit[templated])
    cells = cells.loc[cells["template_id"].map(md5).sort_values().index].drop_duplicates("unit")
    assign = {}
    for cell, g in cells.groupby(["category", "label", "language"]):
        ids = sorted(g["unit"], key=md5)
        if len(ids) < 2 and warn:
            print(f"warning: only one template cluster in {cell}, kept in train")
        for i, u in enumerate(ids):
            assign[u] = "test" if i == 0 and len(ids) > 1 else "val" if i == 1 and len(ids) > 2 else "train"
    split[tpl_unit] = unit[tpl_unit].map(assign)
    return split

# previous scheme (unit = text_hash, or template_id for templated rows), kept only to report what moved
before = assign_split(df["template_id"].where(templated, df["text_hash"]), warn=False)
df["split"] = assign_split(df["cluster_id"])
assert df.groupby("cluster_id")["split"].nunique().max() == 1, "a near-duplicate cluster straddles splits"
df["split"] = pd.Categorical(df["split"], ["train", "val", "test"])

size = df["cluster_id"].value_counts()
print(f"\nnear-dup clusters (Jaccard >= {NEAR_DUP_JACCARD}): {len(size)} for {len(df)} rows; "
      f"{(size > 1).sum()} multi-row clusters hold {size[size > 1].sum()} rows; "
      f"{(df.groupby('cluster_id')['label'].nunique() > 1).sum()} mix scam and benign")
print("10 largest:")
for cid, n in size.head(10).items():
    r = df[df["cluster_id"] == cid].iloc[0]
    print(f"  {n:4d}  {r['source']:<18} {r['text'][:90]!r}")
moved = before != df["split"].astype(str)
print(f"rows that changed split: {moved.sum()} ({moved.mean():.1%})")
print(pd.crosstab(before[moved].rename("old"), df.loc[moved, "split"].rename("new")))

os.makedirs("data/final", exist_ok=True)
df.to_csv("data/final/messages.csv", index=False)
print(df.groupby(["source", "label"]).size().unstack(fill_value=0))
print("\nby category:\n", df.groupby(["category", "label"]).size().unstack(fill_value=0))
print("\nsplit:\n", df.groupby(["split", "label"], observed=True).size().unstack(fill_value=0))
print("\nscript x label:\n", df.groupby(["script", "label"]).size().unstack(fill_value=0))
print("\nlanguage x label:\n", df.groupby(["language", "label"]).size().unstack(fill_value=0))
print("\nprovenance x split (web quotes):\n", df[df["provenance"] != ""].groupby(["provenance", "split"], observed=True).size().unstack(fill_value=0))
print("\nmasked:", {t: int(df["text"].str.contains(t, regex=False).sum()) for _, t in MASKS})
print("\nsynthetic share by label:", df.groupby("label")["is_synthetic"].mean().round(2).to_dict())
print("\nshortcut check (share of each class):")
df["has_url"] = df["text"].str.contains(r"https?://|www\.|\.(?:com|in|ly|vip)\b", regex=True)
df["len"] = df["text"].str.len()
print(df.groupby("label")[["has_url", "is_synthetic"]].mean().round(2), df.groupby("label")["len"].median())
