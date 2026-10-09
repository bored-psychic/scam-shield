import glob, hashlib, json, os, re
from urllib.parse import urlsplit
import pandas as pd
import tldextract
import gambling_lists as gl

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

# 2b. gambling_spam (snapshots from src/pull_gambling.py, helpers in src/gambling_lists.py). The class is the registered domains
# on BOTH UT1 and the Blocklist Project: (i) existing benign domains whose name looks like gambling and that are on either list
# are relabelled (provenance list_confirmed); (ii) both-list domains not in urls.csv yet are added as bare domains, one row each,
# like the Tranco rows (provenance list_confirmed). Keyword candidates on neither list wait in reports/gambling_manual_review.csv
# (written once, never overwritten; the user fills `decision`): provenance pending_review, left benign, and url_head.py leaves them
# out of training until marked; decision gambling_spam relabels them (provenance manual_review). The split is a hash of
# reg_domain, so existing rows keep their split and new domains never straddle (asserted at the end).
df["provenance"] = "source_label"
df["label_before"] = df["label"]
G, GINFO = gl.load_lists()
led = {}
if G is None:
    print("gambling snapshots missing, run src/pull_gambling.py: no gambling_spam rows")
else:
    ut, bl = gl.domain_sets(G)
    both, listed = ut & bl, ut | bl
    labels_by_dom = df.groupby("reg_domain")["label"].agg(set)
    cand = {d for d, ls in labels_by_dom.items() if ls == {"benign"} and gl.keyword_candidate(d)}
    on_list, pending = {d for d in cand if d in listed}, {d for d in cand if d not in listed}
    if not os.path.exists(gl.REVIEW_PATH):
        gl.write_review_sheet(pending, listed)
        print(f"wrote {gl.REVIEW_PATH} ({len(pending)} domains): fill the `decision` column, then rerun this script")
    elif added := gl.append_review_rows(pending, listed):   # append-only: rows already in the sheet keep their decisions
        print(f"appended {len(added)} new pending domains to {gl.REVIEW_PATH}: {', '.join(added)}")
    review = gl.read_review()
    manual_yes = {d for d in pending if review.get(d, ("", ""))[0] == "gambling_spam"}
    manual_no = {d for d in pending if review.get(d, ("", ""))[0] == "benign"}
    waiting = pending - manual_yes - manual_no
    for dom_set, prov in ((on_list, "list_confirmed"), (manual_yes, "manual_review"), (manual_no, "manual_review"),
                          (waiting, "pending_review")):
        df.loc[df["reg_domain"].isin(dom_set), "provenance"] = prov
    df.loc[df["reg_domain"].isin(on_list | manual_yes), "label"] = "gambling_spam"
    have = set(df["reg_domain"])
    new_regs = sorted(both - have)
    new = pd.DataFrame({"url": ["https://" + d for d in new_regs], "label": "gambling_spam", "source": "ut1_blp_gambling",
                        "date_added": GINFO["ut1_date"]})
    new = pd.concat([new, new["url"].apply(parse)], axis=1)
    assert (new["reg_domain"] == new_regs).all(), "a list domain changed under parse()"
    new["provenance"], new["label_before"] = "list_confirmed", "(new)"
    df = pd.concat([df, new], ignore_index=True)
    df = df[df["host"] != ""]
    other_both = both & have - on_list - manual_yes   # already in urls.csv under another label / not a keyword candidate
    led = {"candidates": len(cand), "on_list": len(on_list), "pending": len(pending), "manual_yes": len(manual_yes),
           "manual_no": len(manual_no), "waiting": len(waiting), "new": len(new_regs),
           "other_both_labels": df[df["reg_domain"].isin(other_both)].drop_duplicates(["reg_domain", "label"])["label"].value_counts().to_dict(),
           "phishing_lookalikes": sorted(d for d in labels_by_dom.index
                                         if labels_by_dom[d] == {"phishing"} and gl.keyword_candidate(d))}
    print(f"gambling_spam: {len(on_list)} existing domains relabelled, {len(new_regs)} new domains added, {len(waiting)} pending review")

# 3. labels. is_bad stays phishing / malware (and any other bad class, e.g. ISCX spam / defacement); gambling_spam is a category
# of site, not a verdict, so it is 0 here like benign.
df["is_bad"] = (~df["label"].isin(["benign", "gambling_spam"])).astype(int)

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
OUT = "data/final/urls.csv"
if os.path.exists(OUT):   # an existing row must keep its split (it is a hash of reg_domain), and no domain may straddle splits
    old = pd.read_csv(OUT, usecols=["url", "split"]).drop_duplicates("url").set_index("url")["split"].astype(str)
    now = df.drop_duplicates("url").set_index("url")["split"].astype(str)
    common = old.index.intersection(now.index)
    assert (old[common] == now[common]).all(), "an existing row changed split"
    print(f"split stability: {len(common):,} of {len(old):,} rows of the previous urls.csv are still present, 0 changed split")
assert df.groupby("reg_domain")["split"].nunique().max() == 1, "a registered domain straddles splits"
order = [c for c in df.columns if c not in ("provenance", "label_before")] + ["provenance"]   # new column last, old ones keep their place
df[order].to_csv(OUT, index=False)
print(df.groupby(["label", "split"], observed=True).size().unstack(fill_value=0))
print("\nshortcut check (share of each class):")
df["noscheme_len"] = df["url_noscheme"].str.len()
print(df.groupby("label")[["has_ip", "has_path", "noscheme_len"]].mean().round(2))
print("\nscheme share by source (artifact check):")
print(pd.crosstab(df["source"], df["scheme"], normalize="index").round(2))

# 8. gambling_spam ledger -> reports/urls_gambling.md (row accounting, before / after per split and label, TLD shares)
if G is not None:
    sp = ["train", "val", "test"]
    tab = lambda s, lab: s.groupby([lab, "split"], observed=True).size().unstack(fill_value=0).reindex(columns=sp, fill_value=0).assign(total=lambda t: t.sum(axis=1))
    def md(t):   # markdown table without the tabulate dependency
        t = t.reset_index()
        rows = ["| " + " | ".join(map(str, t.columns)) + " |", "|" + "---|" * len(t.columns)]
        return "\n".join(rows + ["| " + " | ".join(map(str, r)) + " |" for r in t.itertuples(index=False)])
    was = df[df["label_before"] != "(new)"]
    n_rel = int((was["label_before"] != was["label"]).sum())
    df["tld"] = df["reg_domain"].str.rsplit(".", n=1).str[-1]
    keys = ["com", "in", "bet", "casino", "net", "org", "xyz", "top"]
    tld = pd.DataFrame({lab: {k: round(float((g["tld"] == k).mean()), 4) for k in keys} for lab, g in df.groupby("label")}).T
    txt = [
        "# gambling_spam in urls.csv\n",
        f"Generated by `src/build_urls.py` (snapshots {GINFO['ut1_date']}). Strings only, nothing was resolved or visited. "
        "**The label means \"registered domain on both UT1 and the Blocklist Project\" = a gambling category, not a scam verdict**; "
        "licensed operators are on both lists. `is_bad` stays phishing / malware only.\n",
        "## Sources\n",
        f"- UT1 `gambling` (CC BY-SA 4.0): `{os.path.basename(GINFO['ut1'])}`, sha256 `{GINFO['ut1_sha256']}`",
        f"- Blocklist Project `gambling` (Unlicense): `{os.path.basename(GINFO['blp'])}`, sha256 `{GINFO['blp_sha256']}`",
        f"- Registered domains after dropping {int(G.platform.sum()):,} entries on hosting / pseudo-registry suffixes (pages.dev, cloudfront.net, com.de ...) "
        f"and {int(G.ip.sum())} IPs: UT1 {len(ut):,}, Blocklist Project {len(bl):,}, both {len(both):,}, union {len(listed):,}.\n",
        "## Row accounting\n",
        f"- previous rows {int((df['label_before'] != '(new)').sum()):,} -> {len(df):,} rows (+{led['new']:,} new bare-domain rows, source `ut1_blp_gambling`)",
        f"- {n_rel} existing rows ({led['on_list'] + led['manual_yes']} domains) relabelled benign -> gambling_spam: {led['on_list']} keyword candidates confirmed by a list, "
        f"{led['manual_yes']} confirmed by hand",
        f"- keyword candidates (benign-only domains with a gambling word in the name, look-alikes removed): {led['candidates']}; "
        f"on neither list: {led['pending']} (marked benign by hand {led['manual_no']}, gambling_spam {led['manual_yes']}, **waiting {led['waiting']}**: provenance `pending_review`, "
        "left benign, excluded from training)",
        f"- both-list domains already in urls.csv and left alone (not keyword candidates; mostly platforms such as wordpress.com): "
        f"{led['other_both_labels']} (domains by label)",
        f"- gambling-looking domains labelled phishing, left as phishing ({len(led['phishing_lookalikes'])}): {', '.join(led['phishing_lookalikes'])}\n",
        "## Before\n", md(tab(was, "label_before").rename_axis("label")),
        "\n## After\n", md(tab(df, "label")),
        "\n## TLD share of rows per label (shortcut check)\n", md(tld.rename_axis("label")),
        "\nThe `.bet` / `.casino` share of gambling_spam is a near-perfect cue (those TLDs are almost absent from every other label); "
        "gambling_spam rows are bare registered domains, the phishing rows are not (subdomain depth, `n_labels`, `host_len`): "
        "see BUGS.md before retraining the URL head.\n",
    ]
    os.makedirs("reports", exist_ok=True)
    open("reports/urls_gambling.md", "w").write("\n".join(txt))
    print("\nBEFORE (rows)\n", tab(was, "label_before"), "\n\nAFTER (rows)\n", tab(df, "label"), "\n\nwrote reports/urls_gambling.md")
