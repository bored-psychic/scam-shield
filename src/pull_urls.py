import os, io, zipfile, datetime as dt
import requests, pandas as pd

today = dt.date.today().isoformat()
os.makedirs("data/raw", exist_ok=True)

# 1. URLhaus (malware URLs, needs your key)
r = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/",
                 headers={"Auth-Key": os.environ["URLHAUS_KEY"]}, timeout=30)
r.raise_for_status()
uh = pd.DataFrame(r.json()["urls"])[["url", "url_status", "date_added", "threat", "tags"]]
uh["label"], uh["source"] = "malware", "urlhaus"
uh.to_csv(f"data/raw/urlhaus_{today}.csv", index=False)

# 2. OpenPhish (phishing URLs, free community feed, plain text, one URL per line)
r = requests.get("https://openphish.com/feed.txt", timeout=30)
r.raise_for_status()
op = pd.DataFrame({"url": r.text.split()})
op["label"], op["source"], op["date_added"] = "phishing", "openphish", today
op.to_csv(f"data/raw/openphish_{today}.csv", index=False)

# 3. Tranco (benign domains, top 1M)
r = requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=60)
r.raise_for_status()
with zipfile.ZipFile(io.BytesIO(r.content)) as z:
    tr = pd.read_csv(z.open("top-1m.csv"), names=["rank", "domain"])
tr = tr.head(20000)   # take the top 20k, you don't need all 1M
tr["url"] = "https://" + tr["domain"]
tr["label"], tr["source"], tr["date_added"] = "benign", "tranco", today
tr.to_csv(f"data/raw/tranco_{today}.csv", index=False)

print(len(uh), len(op), len(tr))
