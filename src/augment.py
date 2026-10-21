import os, random, re
import pandas as pd
import neardup

# Character-level adversarial variants of scam messages (label 1), the obfuscations scammers use to dodge filters.
# Attack families are split too, so the robustness test uses attack types the model never trained on:
#   train parents -> data/final/messages_aug.csv       homoglyph, leet, zero_width         (training augmentation)
#   test parents  -> data/final/messages_adv_test.csv  char_noise, url_obfuscate, spaced_keywords
#                                                      (held-out attacks; never train on it)
# Output rows are machine-generated: source = "augmented", is_synthetic = True, so real-only evaluation drops them;
# the parent's source / is_synthetic / provenance / split are kept in parent_source, parent_is_synthetic, provenance,
# split (filter on parent_is_synthetic == False for robustness numbers on real parents only).
# Back-translation / TextAttack word-level recipes are not here yet (see README).
# Randomness is seeded per (split, attack) (2026-10-21, splits-v2): with one stream for everything, any change to the TRAIN parents
# shifted every draw that followed, so the held-out test variants changed too. Now messages_adv_test.csv depends on the test parents only.
HOMO = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "i": "і", "y": "у", "s": "ѕ"}   # Cyrillic
LEET = {"a": "@", "o": "0", "i": "1", "e": "3", "s": "$"}
ZW = "​"
MAX_LEN = 1000   # skip long emails / job posts; the attacks target short messages

def homoglyph(t, p=0.15):
    return "".join(HOMO[c] if c in HOMO and random.random() < p else c for c in t)

def leet(t, p=0.2):
    return "".join(LEET[c] if c in LEET and random.random() < p else c for c in t)

def zero_width(t, p=0.1):
    return "".join(c + ZW if c.isalpha() and random.random() < p else c for c in t)

def char_noise(t, p=0.05):
    w = list(t)
    for i in range(len(w) - 1):
        if w[i].isalpha() and random.random() < p:
            if random.random() < 0.5:
                w[i], w[i + 1] = w[i + 1], w[i]
            else:
                w[i] = ""
    return "".join(w)

def spaced_keywords(t):
    for k in ["KYC", "OTP", "UPI", "PIN", "account", "blocked", "verify", "lottery", "prize", "arrest"]:
        t = t.replace(k, " ".join(k))
    return t

URL_RE = re.compile(r"(?:https?://)?(?:[\w-]+\.)+[a-z]{2,}(?:/\S*)?", re.I)

def url_obfuscate(t):
    # only touch URL / domain tokens: hxxp scheme and "[.]" dots, as in defanged-link spam
    return URL_RE.sub(lambda m: m.group().replace("http", "hxxp").replace(".", "[.]"), t)

TRAIN_ATTACKS = {"homoglyph": homoglyph, "leet": leet, "zero_width": zero_width}
HELD_OUT_ATTACKS = {"char_noise": char_noise, "url_obfuscate": url_obfuscate, "spaced_keywords": spaced_keywords}

df = pd.read_csv("data/final/messages.csv", low_memory=False)
df["orig_id"] = df.index   # row position in messages.csv; parent_hash is the stable key if the file is rebuilt
base = df[(df["label"] == 1) & (df["text"].str.len() <= MAX_LEN)]

def build(part, attacks, split):
    rows = []
    for name, fn in attacks.items():
        random.seed(f"{split}:{name}")
        a = part.copy()
        a["text"] = a["text"].map(fn)
        a = a[a["text"] != part["text"]]   # attack didn't apply (e.g. no URL)
        rows.append(a.assign(aug_method=name))
    a = pd.concat(rows, ignore_index=True)
    return a.assign(parent_hash=a["text_hash"], parent_source=a["source"], parent_is_synthetic=a["is_synthetic"],
                    source="augmented", is_synthetic=True)

cols = ["orig_id", "parent_hash", "cluster_id", "text", "label", "category", "channel", "language", "source",
        "parent_source", "parent_is_synthetic", "aug_method", "is_synthetic", "provenance", "split"]
os.makedirs("data/final", exist_ok=True)

# messages.csv must be the frozen split, or orig_id / the parents' splits mean something else
frozen = pd.read_csv("data/final/split_map.csv").set_index("text_hash")["split"]
assert (df["split"] == df["text_hash"].map(frozen)).all(), "messages.csv doesn't match split_map.csv; rerun build_text.py"

outputs = {}
for split, out, attacks in (("train", "messages_aug.csv", TRAIN_ATTACKS), ("test", "messages_adv_test.csv", HELD_OUT_ATTACKS)):
    a = build(base[base["split"] == split], attacks, split)[cols]
    assert (df.loc[a["orig_id"], "split"] == split).all(), f"{out}: parent from another split"
    assert (df.loc[a["orig_id"], "text_hash"].values == a["parent_hash"].values).all(), f"{out}: orig_id / parent_hash mismatch"
    outputs[out] = a
# no parent may have a near-duplicate (exact Jaccard >= 0.7, normalised text) in another split, or a test variant's
# twin could be trained on; this replaces the old asserts, which held by construction and could not fail
parents = sorted(set().union(*(a["orig_id"] for a in outputs.values())))
neardup.assert_no_leakage(df, queries=parents)
for out, a in outputs.items():
    a.to_csv(f"data/final/{out}", index=False)
    print(f"{out}: {len(a)} rows from {a['orig_id'].nunique()} parents", a["aug_method"].value_counts().to_dict())
