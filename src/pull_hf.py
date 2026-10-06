import os, shutil, sys, datetime as dt
import yaml
from huggingface_hub import hf_hub_download

# Pull every `access: hf` entry in data/sources.yaml into data/external/<module>/<name>/.
# Optional args: names to pull (default all).
today = dt.date.today().isoformat()
sources = yaml.safe_load(open("data/sources.yaml"))
wanted = set(sys.argv[1:])

for s in sources:
    if s["access"] != "hf" or (wanted and s["name"] not in wanted):
        continue
    out_dir = f"data/external/{s['module']}/{s['name']}"
    os.makedirs(out_dir, exist_ok=True)
    ext = os.path.splitext(s["file"])[1]
    out = f"{out_dir}/{s['name']}_{today}{ext}"
    if os.path.exists(out):
        print(f"skip {s['name']} (have {out})")
        continue
    path = hf_hub_download(s["id"], s["file"], repo_type="dataset")
    shutil.copy(path, out)
    print(f"{s['name']}: {os.path.getsize(out) / 1e6:.1f} MB -> {out}")
