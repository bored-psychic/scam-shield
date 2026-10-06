import glob, hashlib, json, os, re
from urllib.parse import urlsplit
import pandas as pd
import tldextract

ext = tldextract.TLDExtract(suffix_list_urls=())   # uses bundled list, no network
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# 1. load everything pulled so far
files = glob.glob("data/raw/*.csv")
df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)

# 1b. ISCX-URL2016 (manual download, see MANUAL_DOWNLOADS.md): URL lists named by class, e.g. phishing_dataset.csv
ISCX_LABEL = {"benign": "benign", "phishing": "phishing", "malware": "malware", "spam": "spam", "defacement": "defacement"}
for f in glob.glob("data/external/urls/iscx/*.csv"):
    cls = next((v for k, v in ISCX_LABEL.items() if k in os.path.basename(f).lower()), None)
    if cls:
        u = pd.read_csv(f, header=None, names=["url"], usecols=[0])
        df = pd.concat([df, u.assign(label=cls, source="iscx_url2016", date_added="2016")], ignore_index=True)

# 1c. ealvaradob/phishing-dataset (src/pull_hf.py): mixed text corpus, keep only its bare-URL rows.
# Its benign URLs mostly have paths, which offsets the bare-domain Tranco rows (has_path shortcut).
for f in sorted(glob.glob("data/external/text/ealvaradob_phishing/*.json"))[-1:]:
    e = pd.DataFrame(json.load(open(f)))
    t = e["text"].astype(str).str.strip()
    e = e[~t.str.startswith("<") & ~t.str.contains(r"\s")]
    df = pd.concat([df, pd.DataFrame({"url": e["text"], "label": e["label"].map({1: "phishing", 0: "benign"}),
                                      "source": "ealvaradob", "date_added": None})], ignore_index=True)
df = df[["url", "label", "source", "date_added"]]
df["url"] = df["url"].astype(str).str.strip()
df = df.drop_duplicates("url").reset_index(drop=True)

# 2. parse
def parse(u):
    s = urlsplit(u if "://" in u else "http://" + u)
    host = (s.hostname or "").lower()
    return pd.Series({
        "scheme": s.scheme or "http",
        "host": host,
        "reg_domain": ext(host).registered_domain or host,   # IPs fall back to host
        "has_ip": bool(IP_RE.match(host)),
        "has_path": len(s.path) > 1 or bool(s.query),
        "ext": os.path.splitext(s.path)[1].lower(),
    })

df = pd.concat([df, df["url"].apply(parse)], axis=1)
df = df[df["host"] != ""]

# 3. labels
df["is_bad"] = (df["label"] != "benign").astype(int)

# 4. fair view: host-only URL (removes the path shortcut)
df["url_host_only"] = df["host"]
# scheme-free URL for models: pull_urls.py prepends https:// to every Tranco domain, so the scheme is an artifact
df["url_noscheme"] = df["url"].str.replace(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", regex=True)

# 5. domain collisions (e.g. malware hosted on github.io / pages.dev)
by_dom = df.groupby("reg_domain")["is_bad"].nunique()
conflicts = by_dom[by_dom > 1].index
print(f"reg_domains with both benign and bad rows: {len(conflicts)}")
df["domain_conflict"] = df["reg_domain"].isin(conflicts)

# 5b. domain age from src/enrich_domains.py cache (NaN when not looked up)
CACHE = "data/external/urls/whois_cache.json"
if os.path.exists(CACHE):
    reg = {d: v["registered"] for d, v in json.load(open(CACHE)).items() if v.get("registered")}
    when = pd.to_datetime(df["reg_domain"].map(reg), utc=True, errors="coerce")
    df["domain_age_days"] = (pd.Timestamp.now(tz="UTC") - when).dt.days
    print("domain_age_days median by label:", df.groupby("label")["domain_age_days"].median().to_dict())

# 6. deterministic split by registered domain (same domain never straddles splits)
def bucket(d):
    return int(hashlib.md5(d.encode()).hexdigest(), 16) % 100
b = df["reg_domain"].map(bucket)
df["split"] = pd.cut(b, [-1, 79, 89, 99], labels=["train", "val", "test"])

# 7. save + report
os.makedirs("data/final", exist_ok=True)
df.to_csv("data/final/urls.csv", index=False)
print(df.groupby(["label", "split"], observed=True).size().unstack(fill_value=0))
print("\nshortcut check (share of each class):")
df["noscheme_len"] = df["url_noscheme"].str.len()
print(df.groupby("label")[["has_ip", "has_path", "noscheme_len"]].mean().round(2))
print("\nscheme share by source (artifact check):")
print(pd.crosstab(df["source"], df["scheme"], normalize="index").round(2))