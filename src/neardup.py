import bisect, re
from datasketch import MinHash, MinHashLSH

# Near-duplicate machinery shared by build_text.py (clusters), augment.py and split_audit.py (cross-split checks).
# Similarity = exact Jaccard over the char 5-grams of the first 2000 chars, computed on two views of the text: raw
# (lowercased, whitespace-collapsed) and normalised (templated prefixes/suffixes stripped, numbers -> <NUM>). Two rows
# are near-duplicates if either view reaches the threshold: normalising raises J for pairs that differ only in
# amounts or boilerplate, but lowers it for pairs that share numbers or boilerplate (the shared shingles disappear).
# MinHash LSH only proposes candidate pairs (at a threshold well below MIN_JACCARD so true pairs are almost never
# missed); every candidate is then checked with the exact Jaccard, not the MinHash estimate.
SHINGLE, SHINGLE_CHARS = 5, 2000
MIN_JACCARD = 0.7
# india_fraud_final is slot-filler templates ("Cashback of Rs N credited to your Paytm wallet for your <order | bill>"),
# which reach only 0.6-0.7 on short texts, so two rows of the same such source merge at the lower threshold. Those
# pairs are brute-forced (LSH recall is only 98% at 0.6) inside the source, which is small.
SOURCE_MIN_JACCARD = {"india_fraud_final": 0.6}
NUM_PERM, LSH_THRESHOLD, LSH_WEIGHTS = 256, 0.5, (0.2, 0.8)   # b=51, r=5: P(candidate | J=0.7) = 0.9999
CLUSTER_SEED, CHECK_SEED = 1, 2    # different permutations, so the check is an independent second look

# Variants of one message added by the india_fraud_final generator (found by diffing its near-duplicate pairs).
# Stripped for clustering only, so "NOTICE: <msg>" and "<msg> Do not delay." land in the msg's cluster.
PREFIXES = ["immediate action", "action required", "final reminder", "critical notice", "important", "notice",
            "warning", "alert", "urgent", "dear customer"]
SUFFIXES = ["for queries, call our helpline", "thank you for choosing our service", "thanks for choosing our service",
            "thank you for banking with us", "thanks for banking with us", "we appreciate for banking with us",
            "visit our official website for more details", "ignore at your own risk", "this is your final notice",
            "contact us immediately", "act immediately to avoid legal consequences",
            "failure to respond will result in account suspension", "do not delay"]
_WS = re.compile(r"\s+")
_PRE = re.compile(r"^(?:(?:" + "|".join(PREFIXES) + r")\s*[:,!\-]+\s*)+")
_SUF = re.compile(r"(?:[\s.!,]*(?:" + "|".join(map(re.escape, SUFFIXES)) + r")[\s.!]*)+$")
# amounts and other numbers, with their currency / unit words: "Rs.250", "INR 1000.00", "25 lakhs", "XX1234", "2001"
_NUM = re.compile(r"(?:(?:rs\.?|inr|₹)\s*)?\d[\d,]*(?:\.\d+)?(?:\s*(?:lakhs?|crores?))?")

def raw(text):
    """Lowercased, whitespace-collapsed first 2000 chars: what a plain near-duplicate scan would compare."""
    return _WS.sub(" ", text.lower()).strip()[:SHINGLE_CHARS]

def normalise(text):
    """raw() with templated prefixes/suffixes stripped and numbers replaced by <NUM>. Used for clustering only."""
    t = _WS.sub(" ", text.lower()).strip()
    stripped = _SUF.sub("", _PRE.sub("", t)).strip()
    return _NUM.sub("<NUM>", stripped or t)[:SHINGLE_CHARS]

VIEWS = {"raw": raw, "normalised": normalise}

def shingle_sets(texts):
    return [{t[i:i + SHINGLE].encode() for i in range(max(1, len(t) - SHINGLE + 1))} for t in texts]

def near_dup_pairs(shs, seed, min_jac=MIN_JACCARD, skip=None, queries=None):
    """Yield (i, j, jaccard) for row pairs with exact Jaccard >= min_jac, candidates from MinHash LSH.
    skip(i, j) -> True drops a candidate before the (costly) exact check; queries limits i to those rows."""
    mh = MinHash.bulk(shs, num_perm=NUM_PERM, seed=seed)
    lsh = MinHashLSH(threshold=LSH_THRESHOLD, num_perm=NUM_PERM, weights=LSH_WEIGHTS)
    for i, m in enumerate(mh):
        lsh.insert(i, m)
    for i in (range(len(shs)) if queries is None else queries):
        for j in lsh.query(mh[i]):
            if j == i or (queries is None and j < i) or (skip is not None and skip(i, j)):
                continue
            inter = len(shs[i] & shs[j])
            jac = inter / (len(shs[i]) + len(shs[j]) - inter)
            if jac >= min_jac:
                yield i, j, jac

def exact_pairs(shs, rows, min_jac, skip=None, queries=None):
    """Like near_dup_pairs but brute force over the row subset `rows`, no LSH. A size filter keeps it cheap:
    J <= min(|A|, |B|) / max(|A|, |B|), so only rows whose size is within a factor min_jac of each other are compared."""
    order = sorted(rows, key=lambda r: len(shs[r]))
    sizes = [len(shs[r]) for r in order]
    qs = None if queries is None else set(queries)
    for pos, i in enumerate(order):
        if qs is not None and i not in qs:
            continue
        for j in order[bisect.bisect_left(sizes, sizes[pos] * min_jac):bisect.bisect_right(sizes, sizes[pos] / min_jac)]:
            if j == i or (qs is None and j < i) or (skip is not None and skip(i, j)):
                continue
            inter = len(shs[i] & shs[j])
            jac = inter / (len(shs[i]) + len(shs[j]) - inter)
            if jac >= min_jac:
                yield i, j, jac

def near_dup_pairs_any(texts, sources, seed, skip=None, queries=None):
    """Yield (i, j, jaccard, view) for every pair that counts as a near-duplicate: exact Jaccard >= MIN_JACCARD on
    either view, or >= SOURCE_MIN_JACCARD[s] on either view for two rows of source s. A pair can come out more than
    once. Views are built one at a time so only one set of shingles is in memory."""
    sources = list(sources)
    for view, fn in VIEWS.items():
        shs = shingle_sets([fn(t) for t in texts])
        for i, j, jac in near_dup_pairs(shs, seed, MIN_JACCARD, skip, queries):
            yield i, j, jac, view
        for src, t in SOURCE_MIN_JACCARD.items():
            for i, j, jac in exact_pairs(shs, [r for r, s in enumerate(sources) if s == src], t, skip, queries):
                yield i, j, jac, view

def assert_no_leakage(df, queries=None):
    """Fail if anything that must share a split does not. Needs df.index == 0..n-1 and columns split, cluster_id,
    template_family, company_key, source, text (translation_of and real_group too, when present). Two parts:
      1. every cluster / template family / company sits in one split (true by construction when the split is fresh,
         but not when rows came from a frozen split_map);
      2. no two rows in different splits are near-duplicates by near_dup_pairs_any. Candidates come from an LSH built
         with CHECK_SEED, not the one the clusters were built with, so a clustering that missed pairs is caught here.
         queries = row positions to check (all rows by default)."""
    split = df["split"].astype(str)
    for key in ("cluster_id", "template_family", "company_key", "translation_of", "real_group"):   # real_group: the intake's template group of a phones_pool row (splits-v3)
        if key not in df:
            continue
        k = df[key].fillna("")
        n = split[k != ""].groupby(k[k != ""]).nunique()
        if (n > 1).any():
            raise AssertionError(f"{key}: {(n > 1).sum()} groups straddle splits, e.g. {list(n[n > 1].index[:3])}")
    sp = split.to_numpy()
    bad = {}
    for i, j, jac, view in near_dup_pairs_any(df["text"], df["source"], CHECK_SEED, skip=lambda i, j: sp[i] == sp[j],
                                              queries=queries):
        bad.setdefault((min(i, j), max(i, j)), (jac, view))
    if bad:
        lines = [f"  J={jac:.2f} ({view}) {sp[i]}|{sp[j]}  {ascii(df['text'][i][:70])} ~ {ascii(df['text'][j][:70])}"
                 for (i, j), (jac, view) in list(bad.items())[:8]]
        raise AssertionError(f"{len(bad)} near-duplicate pairs cross splits:\n" + "\n".join(lines))

def train_twin_rows(df, min_jac=0.6):
    """Positions (df.index must be 0..n-1) of val/test rows that have a train row at exact Jaccard >= min_jac on
    either view. Same lookup as split_audit.py (CHECK_SEED; india_fraud_final brute-forced), so the counts agree."""
    sp = df["split"].to_numpy()
    src = df["source"].to_numpy()
    india = [r for r, s in enumerate(src) if s == "india_fraud_final"]
    same = lambda i, j: sp[i] == sp[j] or (sp[i] != "train" and sp[j] != "train")   # keep only train <-> val/test
    rows = set()
    for fn in VIEWS.values():
        shs = shingle_sets([fn(t) for t in df["text"]])
        pairs = list(near_dup_pairs(shs, CHECK_SEED, min_jac, skip=same)) + list(exact_pairs(shs, india, min_jac, skip=same))
        for i, j, _ in pairs:
            rows.add(j if sp[i] == "train" else i)
        del shs
    return rows
