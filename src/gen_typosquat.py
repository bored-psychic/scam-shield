import os
import pandas as pd

# Generate typosquat / homoglyph / IDN lookalikes of Indian brand domains -> data/final/typosquat_candidates.csv.
# These are *candidates*, not confirmed phishing: kept out of urls.csv and used as a lookalike-detection test set
# (optionally resolve DNS later to keep only registered ones).
SEEDS = ["onlinesbi.sbi", "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com", "paytm.com",
         "phonepe.com", "npci.org.in", "indiapost.gov.in", "irctc.co.in", "incometax.gov.in", "uidai.gov.in",
         "parivahan.gov.in", "amazon.in", "flipkart.com", "cybercrime.gov.in", "epfindia.gov.in"]

ASCII_LOOK = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5"], "b": ["8"],
              "m": ["rn"], "w": ["vv"], "g": ["9", "q"]}
UNI_LOOK = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "i": "і", "y": "у"}   # Cyrillic
KEYWORDS = ["login", "secure", "kyc", "verify", "update", "support", "online"]
TLDS = ["com", "in", "co.in", "net", "org", "online", "site", "top", "vip", "xyz", "info", "cc"]

def split(domain):
    name, _, tld = domain.partition(".")
    return name, tld

def variants(domain):
    name, tld = split(domain)
    out = {}
    for i in range(len(name)):
        out[name[:i] + name[i + 1:]] = "omission"
        out[name[:i] + name[i] + name[i:]] = "repetition"
        if i < len(name) - 1:
            out[name[:i] + name[i + 1] + name[i] + name[i + 2:]] = "transposition"
        for r in ASCII_LOOK.get(name[i], []):
            out[name[:i] + r + name[i + 1:]] = "ascii_homoglyph"
        if name[i] in UNI_LOOK:
            out[name[:i] + UNI_LOOK[name[i]] + name[i + 1:]] = "idn_homograph"
    for k in KEYWORDS:
        out[f"{name}-{k}"] = "keyword"
        out[f"{k}-{name}"] = "keyword"
    rows = [(f"{n}.{tld}", how) for n, how in out.items() if n and n != name]
    rows += [(f"{name}.{t}", "tld_swap") for t in TLDS if t != tld]
    return rows

rows = []
for seed in SEEDS:
    for dom, how in variants(seed):
        try:
            puny = dom.encode("idna").decode()
        except UnicodeError:
            continue
        rows.append({"seed": seed, "domain": dom, "punycode": puny, "method": how, "is_idn": puny != dom})

df = pd.DataFrame(rows).drop_duplicates("domain")
df = df[~df["domain"].isin(SEEDS)]
os.makedirs("data/final", exist_ok=True)
df.to_csv("data/final/typosquat_candidates.csv", index=False)
print(len(df), "candidates\n", df["method"].value_counts().to_dict())
