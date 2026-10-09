import json, os, sys, time, datetime as dt
import requests, pandas as pd

# RDAP lookup of registration date per reg_domain in data/final/urls.csv, cached in
# data/external/urls/whois_cache.json (re-runs only query new domains). build_urls.py joins it as domain_age_days.
# Usage: python src/enrich_domains.py [limit]   (rdap.org redirects to the right registry; be gentle)
CACHE = "data/external/urls/whois_cache.json"
limit = int(sys.argv[1]) if len(sys.argv) > 1 else 500

os.makedirs(os.path.dirname(CACHE), exist_ok=True)
cache = json.load(open(CACHE)) if os.path.exists(CACHE) else {}
urls = pd.read_csv("data/final/urls.csv", usecols=["reg_domain", "has_ip", "label"])
urls = urls[urls["label"] != "gambling_spam"]   # 26k list domains, no model uses their age; not worth the RDAP traffic
todo =[d for d in urls.loc[~urls["has_ip"], "reg_domain"].unique() if d not in cache][:limit]
print(f"{len(cache)} cached, querying {len(todo)}")

for i, dom in enumerate(todo):
    try:
        r = requests.get(f"https://rdap.org/domain/{dom}", timeout=20)
        if r.status_code == 200:
            ev = {e.get("eventAction"): e.get("eventDate") for e in r.json().get("events", [])}
            cache[dom] = {"registered": ev.get("registration"), "status": 200}
        else:
            cache[dom] = {"registered": None, "status": r.status_code}
    except (requests.RequestException, ValueError) as e:
        cache[dom] = {"registered": None, "status": type(e).__name__}
    if i % 50 == 0:
        json.dump(cache, open(CACHE, "w"))
    time.sleep(0.5)

json.dump(cache, open(CACHE, "w"))
ok = sum(1 for v in cache.values() if v["registered"])
print(f"done: {ok}/{len(cache)} with a registration date")
