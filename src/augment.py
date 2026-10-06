import os, random, re
import pandas as pd

# Character-level adversarial variants of scam messages (label 1), the obfuscations scammers use to dodge filters.
#   train split -> data/final/messages_aug.csv       (training augmentation)
#   test split  -> data/final/messages_adv_test.csv  (robustness eval; never train on it)
# Back-translation / TextAttack word-level recipes are not here yet (see README).
random.seed(0)
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

ATTACKS = {"homoglyph": homoglyph, "leet": leet, "zero_width": zero_width, "char_noise": char_noise,
           "spaced_keywords": spaced_keywords, "url_obfuscate": url_obfuscate}

df = pd.read_csv("data/final/messages.csv", low_memory=False)
df["orig_id"] = df.index
base = df[(df["label"] == 1) & (df["text"].str.len() <= MAX_LEN)]

def build(part):
    rows = []
    for name, fn in ATTACKS.items():
        a = part.copy()
        a["text"] = a["text"].map(fn)
        a = a[a["text"] != part["text"]]   # attack didn't apply (e.g. no URL)
        rows.append(a.assign(aug_method=name, is_synthetic=True))
    return pd.concat(rows, ignore_index=True)

cols = ["orig_id", "cluster_id", "text", "label", "category", "channel", "language", "source", "aug_method", "split"]
os.makedirs("data/final", exist_ok=True)
for split, out in (("train", "messages_aug.csv"), ("test", "messages_adv_test.csv")):
    a = build(base[base["split"] == split])[cols]
    # variants must come only from parents in this split, and no parent's near-dup cluster may reach another split
    # (build_text.py splits by cluster_id), else a test variant's twin could be trained on
    assert (df.loc[a["orig_id"], "split"] == split).all(), f"{out}: parent from another split"
    assert (df.loc[df["cluster_id"].isin(a["cluster_id"]), "split"] == split).all(), f"{out}: parent cluster straddles splits"
    a.to_csv(f"data/final/{out}", index=False)
    print(f"{out}: {len(a)} rows", a["aug_method"].value_counts().to_dict())
