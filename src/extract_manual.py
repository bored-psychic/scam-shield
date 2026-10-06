import sys, json, glob, os
from extract_scams import PROVENANCE, pages, provenance, verify, write

# Manual alternative to extract_scams.py's Claude API call: a human (or Claude Code in-session) reads each
# trimmed page and writes candidates to data/extracted/manual/batch_NN.json as {page_id: [candidate, ...]}
# (page_id = basename of data/raw_web/<page_id>.md; [] = reviewed, nothing quoted). Candidates use the
# same fields as extract_scams.SCHEMA plus a "note" (its opening words set the provenance column, see
# extract_scams.PROVENANCE) and go through the same verbatim check and PII masking.
#   python src/extract_manual.py dump 0 10   # print trimmed pages 0-9 for reading
#   python src/extract_manual.py             # verify all batches -> data/extracted/web_scams.csv
CAND_GLOB = "data/extracted/manual/batch_*.json"

all_pages = list(pages())
if len(sys.argv) > 1 and sys.argv[1] == "dump":
    lo, hi = int(sys.argv[2]), int(sys.argv[3])
    for i, (md_path, meta, page) in enumerate(all_pages[lo:hi], lo):
        print(f"\n<page n={i} id={os.path.basename(md_path)[:-3]} url={meta['url']}>\n{page}\n</page>")
    sys.exit()

cands = {}
for f in sorted(glob.glob(CAND_GLOB)):
    cands.update(json.load(open(f, encoding="utf-8")))
rows, unreviewed = [], []
for md_path, meta, page in all_pages:
    pid = os.path.basename(md_path)[:-3]
    if pid not in cands:
        unreviewed.append(meta["url"])
        continue
    rows += verify(page, cands[pid], meta["url"])
# every manual candidate needs a note starting with a PROVENANCE key, so web_scams.csv never has "unknown" here
bad = [r["text"][:60] for r in rows if provenance(r["note"]) == "unknown"]
if bad:
    sys.exit(f"candidates without a provenance note ({'/'.join(PROVENANCE)}):\n  " + "\n  ".join(bad))
write(rows)
print(f"{len(all_pages) - len(unreviewed)}/{len(all_pages)} pages reviewed")
