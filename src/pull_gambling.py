import argparse, datetime, hashlib, io, os, sys, zipfile
import requests

# Dated snapshots of the two gambling lists and the Tranco top 100k, for the gambling_spam class (see gambling_lists.py).
# Files are plain strings that are never resolved or visited (CLAUDE.md rule 8). They are NOT saved as .csv: build_urls.py
# globs data/raw/*.csv as URL rows. An existing dated file is never overwritten.
#   python src/pull_gambling.py [--out data/raw]
UT1 = "https://dsi.ut-capitole.fr/blacklists/download/gambling.tar.gz"                       # CC BY-SA 4.0 (sources.yaml)
BLP = "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt"          # Unlicense
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"

ap = argparse.ArgumentParser()
ap.add_argument("--out", default="data/raw")
out = ap.parse_args().out
today = datetime.date.today().isoformat()
os.makedirs(out, exist_ok=True)

def save(name, data):
    path = os.path.join(out, name)
    if os.path.exists(path):
        sys.exit(f"{path} already exists, not overwriting")
    with open(path, "wb") as f:
        f.write(data)
    print(f"{path}  {len(data):,} bytes  sha256 {hashlib.sha256(data).hexdigest()}")

for url, name in ((UT1, f"ut1_gambling_{today}.tar.gz"), (BLP, f"blocklistproject_gambling_{today}.txt")):
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    save(name, r.content)

r = requests.get(TRANCO, timeout=120)
r.raise_for_status()
with zipfile.ZipFile(io.BytesIO(r.content)) as z:
    top = z.read("top-1m.csv").decode().splitlines()[:100000]
save(f"tranco_top100k_{today}.txt", ("\n".join(top) + "\n").encode())
