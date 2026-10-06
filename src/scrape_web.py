import os, sys, json, time, hashlib, datetime
import requests, pandas as pd

# Scrape every URL in data/sources.csv with Firecrawl into data/raw_web/<md5(url)[:16]>.md + .json,
# the input format of extract_scams.py. Already-scraped URLs are skipped, so reruns only fetch new rows.
# Usage: FIRECRAWL_API_KEY=... python src/scrape_web.py [max_new_pages]   (1 credit per page)
SOURCES, RAW_DIR = "data/sources.csv", "data/raw_web"
API = "https://api.firecrawl.dev/v2/scrape"

key = os.environ.get("FIRECRAWL_API_KEY")
if not key:
    sys.exit("set FIRECRAWL_API_KEY")
limit = int(sys.argv[1]) if len(sys.argv) > 1 else None

def scrape(url):
    body = {"url": url, "formats": ["markdown"], "onlyMainContent": True, "timeout": 60000}
    for attempt in range(4):
        r = requests.post(API, json=body, headers={"Authorization": f"Bearer {key}"}, timeout=120)
        if r.status_code == 429:
            time.sleep(15 * (attempt + 1))
            continue
        r.raise_for_status()
        return r.json()["data"]
    raise RuntimeError("rate limited 4 times")

os.makedirs(RAW_DIR, exist_ok=True)
src = pd.read_csv(SOURCES).drop_duplicates("url")
done = fetched = 0
for row in src.itertuples():
    path = f"{RAW_DIR}/{hashlib.md5(row.url.encode()).hexdigest()[:16]}"
    if os.path.exists(path + ".md"):
        done += 1
        continue
    if limit is not None and fetched >= limit:
        break
    try:
        data = scrape(row.url)
    except Exception as e:
        print(f"{row.url}: FAILED ({e})")
        continue
    md = data.get("markdown") or ""
    if len(md) < 200:
        print(f"{row.url}: SKIPPED (only {len(md)} chars, likely blocked)")
        continue
    meta = data.get("metadata", {})
    with open(path + ".md", "w", encoding="utf-8") as f:
        f.write(md)
    json.dump({"url": row.url, "source_type": row.source_type, "notes": row.notes,
               "title": meta.get("title"), "status_code": meta.get("statusCode"),
               "scraped_at": datetime.date.today().isoformat()},
              open(path + ".json", "w"), indent=1, ensure_ascii=False)
    fetched += 1
    print(f"{row.url}: {len(md)} chars")

print(f"{fetched} new pages, {done} already cached, {len(src)} sources -> {RAW_DIR}/")
