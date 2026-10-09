import json, os, re
import pandas as pd
import gambling_lists as gl

# Lookup files for the Links engine blocklist, built from the same snapshots as the gambling_spam class (gambling_lists.py).
# Strings only: nothing is resolved or visited (CLAUDE.md rule 8). Run from the project root: python src/gambling_lookup.py
#   data/final/gambling_domains.tsv         domain, lists (both | ut1 | blp | search_review | manual_review), tranco_rank (top 100k
#                                           only, else empty) = union of the two lists as registered domains, EXCEPT Blocklist-Project-
#                                           only domains in the Tranco top 10k (a lone auto-aggregated hit on a popular site is ignored)
#                                           UNLESS the registered domain contains a gambling token (GAMBLING_TOKENS); both groups are
#                                           listed in reports/gambling_lookup.md. PLUS every domain decided gambling_spam in
#                                           reports/gambling_manual_review.csv, tagged with the same provenance build_urls.py gives it
#                                           (search_review = decision equals the search suggestion, else manual_review), whatever its
#                                           Tranco rank: a decision is the user's, the Tranco rule only filters lone list hits.
#                                           The `lists` column holds the tag of whatever supports the entry.
#   data/final/gambling_platform_hosts.tsv  host-level entries on hosting platforms (pages.dev, cloudfront.net, com.de ...): a
#                                           registered-domain entry would cover every tenant
#   data/final/gambling_india.json          India seed list + token rule (UT1 and the Blocklist Project barely cover Satta / Matka);
#                                           rule semantics are gambling_lists.india_hit
# The lists are a gambling CATEGORY, not a scam verdict (licensed operators are on them). Licence of the source: UT1 CC BY-SA 4.0,
# Blocklist Project Unlicense; keep these files out of any public release (data/ is git-ignored).
TRANCO_IGNORE_BLP_ONLY = 10_000
# Substring of the registered domain (whole string, TLD included). A plain substring, so it also lets look-alikes through
# (betterhelp, bethesda ...); the report lists every domain that comes back.
GAMBLING_TOKENS = re.compile(r"bet|casino|satta|sattaking|dpboss|poker|slot|rummy")

G, info = gl.load_lists()
if G is None:
    raise SystemExit("gambling snapshots missing, run src/pull_gambling.py")
ut, bl = gl.domain_sets(G)
both = ut & bl
rank = gl.tranco_ranks()
if not rank:
    raise SystemExit("data/raw/tranco_top100k_*.txt missing, run src/pull_gambling.py")

rows, omitted, returned = [], [], []   # omitted = still ignored; returned = would have been ignored by the plain Tranco rule
for d in sorted(ut | bl):
    lists = "both" if d in both else "ut1" if d in ut else "blp"
    r = rank.get(d)
    if lists == "blp" and r is not None and r <= TRANCO_IGNORE_BLP_ONLY:
        if not GAMBLING_TOKENS.search(d):
            omitted.append((d, r))
            continue
        returned.append((d, r))
    rows.append((d, lists, "" if r is None else int(r)))
# review-sheet decisions (reports/gambling_manual_review.csv); a domain already in through a list keeps its list tag
review, sugg = gl.read_review(), gl.read_review_suggestions()
in_lookup = {d for d, _, _ in rows}
rev_rows, rev_already = [], []
for d, (decision, india) in sorted(review.items()):
    if decision != "gambling_spam":
        continue
    if d in in_lookup:
        rev_already.append(d)
        continue
    r = rank.get(d)
    rev_rows.append((d, gl.decision_provenance(decision, sugg.get(d, "")), "" if r is None else int(r)))
look = pd.DataFrame(rows + rev_rows, columns=["domain", "lists", "tranco_rank"]).sort_values("domain", kind="stable")
assert look["domain"].is_unique
os.makedirs("data/final", exist_ok=True)
look.to_csv("data/final/gambling_domains.tsv", sep="\t", index=False)

plat = G[G.platform & ~G.ip].copy()
plat["suffix"] = [gl.ext(h).registered_domain for h in plat.host]
ph = plat.groupby(["host", "suffix"])["src"].agg(lambda s: "both" if set(s) == {"ut1", "blp"} else s.iloc[0]).reset_index()
ph.columns = ["host", "platform_suffix", "lists"]
ph.sort_values("host").to_csv("data/final/gambling_platform_hosts.tsv", sep="\t", index=False)

# ---- India seed + token rule ----
seed = {}
for d in sorted(both):
    if d.endswith(".in"):
        seed[d] = "both lists, .in registered domain"
    elif gl.india_hit(d) == "strong":
        seed[d] = "both lists, India token"
for d, (decision, india) in sorted(review.items()):
    if decision == "gambling_spam" and (india == "yes" or d.endswith(".in") or gl.india_hit(d)):
        seed[d] = "review sheet"
india_json = {
    "snapshot": info["ut1_date"],
    "rule": ("substring of the host, lower case. 'strong' = one strong token or two different India tokens; 'weak' = a single weak token "
             "(never a match on its own: matka is also Finnish for 'trip', kalyan is a common name and a jeweller). Hosts under "
             "exempt_suffixes and registered domains in allow_domains never match."),
    "strong_tokens": list(gl.INDIA_STRONG), "weak_tokens": list(gl.INDIA_WEAK),
    "exempt_suffixes": list(gl.INDIA_EXEMPT_SUFFIXES), "allow_domains": sorted(gl.INDIA_ALLOW),
    "seed_domains": [{"domain": d, "basis": b} for d, b in seed.items()],
    "note": ("Seed = domains on BOTH lists that are .in or carry a strong token, plus domains decided gambling_spam in "
             "reports/gambling_manual_review.csv that are India-flavoured (india = yes, .in or a token). Review domains with a blank "
             "decision are not in it."),
}
json.dump(india_json, open("data/final/gambling_india.json", "w"), indent=1)

# ---- report ----
sizes = look["lists"].value_counts().to_dict()
top = lambda lists: look[(look.lists == lists) & look.tranco_rank.ne("") & (pd.to_numeric(look.tranco_rank, errors="coerce") <= TRANCO_IGNORE_BLP_ONLY)]
kept_top = {k: len(top(k)) for k in ("both", "ut1")}
ex = lambda k, n=14: ", ".join(top(k).sort_values("tranco_rank", key=lambda s: pd.to_numeric(s)).domain.head(n))
t100 = pd.Series(list(rank)).rename("domain").to_frame()
t100["india"] = t100["domain"].map(gl.india_hit)
strong_hits = t100[t100.india == "strong"]["domain"].tolist()
weak_hits = t100[t100.india == "weak"]["domain"].tolist()
u = pd.read_csv("data/final/urls.csv", usecols=["reg_domain", "label", "provenance"], low_memory=False).drop_duplicates(["reg_domain", "label"])
u["india"] = u["reg_domain"].map(gl.india_hit)
uh = u[u.india.notna()].groupby(["india", "label", "provenance"]).size()
md = [
    "# Gambling lookup files\n",
    f"Built by `src/gambling_lookup.py` from the {info['ut1_date']} snapshots (UT1 sha256 `{info['ut1_sha256'][:12]}`, Blocklist Project `{info['blp_sha256'][:12]}`). "
    "Gambling *category*, not a scam verdict. Strings only.\n",
    "## `data/final/gambling_domains.tsv`\n",
    f"- {len(look):,} registered domains: both lists {sizes.get('both', 0):,}, UT1 only {sizes.get('ut1', 0):,}, Blocklist Project only {sizes.get('blp', 0):,}, "
    f"review-sheet decisions {len(rev_rows)} (`search_review` {sizes.get('search_review', 0)}, `manual_review` {sizes.get('manual_review', 0)})"
    + (f"; {len(rev_already)} decided domains were already in through a list" if rev_already else ""),
    f"- the review-sheet domains are decided `gambling_spam` and are added whatever their Tranco rank ({sum(1 for _, _, r in rev_rows if r != '' and r <= TRANCO_IGNORE_BLP_ONLY)} are in the top "
    f"{TRANCO_IGNORE_BLP_ONLY:,}, {sum(1 for _, _, r in rev_rows if r == '')} are outside the top 100k); tag `search_review` = the decision equals the search suggestion, `manual_review` = it overrides it.",
    f"- **Tranco rule:** a Blocklist-Project-only hit in the Tranco top {TRANCO_IGNORE_BLP_ONLY:,} is ignored (a lone hit from the auto-aggregated list on a "
    f"popular site) unless the registered domain contains a gambling token (`{GAMBLING_TOKENS.pattern}`). {len(omitted) + len(returned)} domains fall under the rule: "
    f"**{len(returned)} come back** (token in the name), **{len(omitted)} stay ignored**. Both groups are listed at the end.",
    f"- **still in, in the Tranco top {TRANCO_IGNORE_BLP_ONLY:,}:** {kept_top['both']} on both lists, {kept_top['ut1']} on UT1 only and {len(returned)} Blocklist-Project-only (token exception); the `tranco_rank` column lets "
    f"the engine tighten this without a rebuild. Highest ranked, both lists: {ex('both')}. Several are general platforms (wordpress.com, okta.com, "
    "b-cdn.net ...), so a list hit on a top-ranked domain is weak evidence; that is the Links ladder's rule to set.\n",
    f"## `data/final/gambling_platform_hosts.tsv`\n\n- {len(ph):,} host-level entries on hosting platforms ({ph.platform_suffix.nunique()} suffixes, e.g. "
    f"{', '.join(ph.platform_suffix.value_counts().head(6).index)}), kept out of the registered-domain set above.\n",
    "## `data/final/gambling_india.json`\n",
    f"- seed domains: {len(seed)} ({sum(b != 'review sheet' for b in seed.values())} from the lists, "
    f"{sum(b == 'review sheet' for b in seed.values())} from the review sheet decisions, provenance search_review or manual_review)",
    f"- rule: strong tokens {list(gl.INDIA_STRONG)}, weak tokens {list(gl.INDIA_WEAK)} (never on their own), exempt suffixes {list(gl.INDIA_EXEMPT_SUFFIXES)}, "
    f"allow-list {sorted(gl.INDIA_ALLOW)} (the three false positives found in the Tranco top 100k)",
    f"- Tranco top 100k: **{len(strong_hits)} strong matches**, {len(weak_hits)} weak-only. Weak-only domains are about two thirds gambling by eye "
    f"({', '.join(weak_hits[:12])} ...), which is why they never match alone.",
    "- urls.csv reg_domains hit by the rule (strong / weak) by label and provenance: " + (str(uh.to_dict()) if len(uh) else "none"),
    "- Recall caveat: the rule only sees names with these tokens; it measures nothing about Indian gambling sites with other names "
    "(cricket / IPL / colour-prediction apps ...).\n",
    f"## Came back through the token exception ({len(returned)})\n",
    ", ".join(f"{d} ({r:,})" for d, r in sorted(returned, key=lambda t: t[1])) + "\n",
    f"## Still omitted from the domain lookup ({len(omitted)})\n",
    ", ".join(f"{d} ({r:,})" for d, r in sorted(omitted, key=lambda t: t[1])) + "\n",
]
open("reports/gambling_lookup.md", "w").write("\n".join(md))
print("\n".join(md[:9]))
print(f"seed {len(seed)}; wrote data/final/gambling_domains.tsv, gambling_platform_hosts.tsv, gambling_india.json, reports/gambling_lookup.md")
