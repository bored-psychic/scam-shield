import os, random
from collections import Counter, defaultdict

import pandas as pd

import realguard

# splits-v3 D-v3.1 (docs/plans/splits_v3.md): the POOL half of the real phone messages (data/collected/phones/pool.csv, written by intake_real.py --freeze)
# enters messages.csv as source "phones_pool". This module holds the parts of that which can be tested on an invented pool; build_text.py calls it.
#   load_pool()      read + validate the file (never a path under data/real/), map it to build_text.py's columns, flag rows whose text is a real_test_v1 row
#   prefilter()      drop-and-count pool rows that are the same text as a real test row (realguard hashes), as an existing row, or as another pool row
#   place_fresh()    split the pool clusters that joined no existing row 50 % val / 50 % train, stratified by label x the intake's keyword bucket
#   straddles()      the asserts: no real_group in two splits, no pool row in test
# No row of data/real/ is read: the real test rows are known here only by realguard's hashes. A pool row that is a NEAR-duplicate of a real test row is
# dropped by the intake itself after the freeze (intake_real.py post mode, TEST_NEAR_DROP); a pool row that reaches a splits-v2 TEST row through the
# normal near-duplicate clustering is dropped in build_text.py (D-v3.2: test membership is frozen).

POOL_PATH = "data/collected/phones/pool.csv"
MANIFEST_PATH = "data/real/freeze_manifest.json"   # only its existence is checked (the pool is post-freeze); the file is never opened
POOL_SOURCE = "phones_pool"
POOL_SEED = 20261101   # the seed of place_fresh(); written to build_meta.json
PROVENANCE = "real_circulating"
NEEDED = ["text", "label", "language", "category", "source", "source_type", "group_id", "group_size", "kw_bucket", "provenance", "is_synthetic"]
LANGUAGE = {"en": "english", "hi": "hindi", "kn": "kannada", "mixed": "mixed"}   # Hinglish stays "english" (BUGS.md real-intake limit)
# the reasons a pool row can be dropped, in the order they are tried; build_text.py adds the ones only it can decide (cluster reaches a test row, bridges splits)
DROP_REAL_TEST = "same text as a real_test_v1 row (realguard hash)"
DROP_EXISTING_SAME = "same text as an existing row (same label)"
DROP_EXISTING_CONFLICT = "same text as an existing row of the other label"
DROP_POOL_DUP = "same text as an earlier pool row (same label)"
DROP_POOL_CONFLICT = "same text twice in the pool with different labels"
DROP_TEST_CLUSTER = "near-duplicate cluster holds a splits-v2 test row (test is frozen)"
DROP_BRIDGE = "bridges existing rows of different splits"


class PoolError(SystemExit):
    pass


def load_pool(path, manifest_path=MANIFEST_PATH, real_path=None):
    """The pool file as a frame in build_text.py's columns (text, label, category, subcategory, channel, language, source, is_synthetic, provenance, note,
    real_group) plus the temporary columns _kw (keyword bucket), _gsize (group_size) and _real_match (text is a real_test_v1 row by realguard's hash).
    Returns None when the file does not exist."""
    realguard.refuse_real_paths([path])
    if not os.path.exists(path):
        return None
    if not os.path.exists(manifest_path):
        raise PoolError(f"refused: {path} exists but the intake's freeze manifest {manifest_path} does not (the pool is the POOL half of a freeze split); run intake_real.py --freeze first")
    d = pd.read_csv(path, keep_default_na=False, dtype=str)
    missing = [c for c in NEEDED if c not in d.columns]
    if missing:
        raise PoolError(f"{path}: missing columns {missing}")
    if not d["provenance"].eq(PROVENANCE).all():
        raise PoolError(f"{path}: every pool row must have provenance {PROVENANCE!r} (hard rule 4); got {sorted(set(d['provenance']))}")
    if not d["is_synthetic"].str.lower().eq("false").all():
        raise PoolError(f"{path}: every pool row must have is_synthetic False (hard rule 4)")
    if not d["label"].isin(["0", "1"]).all():
        raise PoolError(f"{path}: label must be 0 or 1; got {sorted(set(d['label']))}")
    if (d["group_id"].str.strip() == "").any() or (d["text"].str.strip() == "").any():
        raise PoolError(f"{path}: empty group_id or text")
    unknown = sorted(set(d["language"]) - set(LANGUAGE))
    if unknown:
        raise PoolError(f"{path}: unknown language codes {unknown}; known {sorted(LANGUAGE)}")
    sizes = pd.to_numeric(d["group_size"], errors="coerce")
    if sizes.isna().any() or (sizes < 1).any():
        raise PoolError(f"{path}: group_size must be a positive integer")
    real = realguard.real_hashes(real_path)
    keys = d["text"].map(realguard.norm_key)
    match = keys.isin(real)
    if "source_row_hash" in d.columns:
        match |= d["source_row_hash"].isin(real)
    out = pd.DataFrame({
        "text": d["text"], "label": d["label"].astype(int), "category": d["category"].replace("", "unspecified"), "subcategory": "",
        "channel": d["source_type"].map(lambda s: "whatsapp" if s == "whatsapp" else "sms"), "language": d["language"].map(LANGUAGE),
        "source": POOL_SOURCE, "is_synthetic": False, "provenance": PROVENANCE, "note": d["source"], "real_group": d["group_id"],
        "_kw": d["kw_bucket"], "_gsize": sizes.astype(int), "_real_match": match.to_numpy()})
    return out


def prefilter(df):
    """df = the whole build frame with text_hash and hash_v2 (pool rows are source == POOL_SOURCE; _real_match is set on them). Returns (kept, dropped):
    dropped is the pool rows removed, with a `_reason`. A pool row never removes an existing row: a clash with one drops the pool row only. Rows are
    tried against the reasons in the order DROP_REAL_TEST, DROP_EXISTING_*, DROP_POOL_*."""
    is_pool = df["source"] == POOL_SOURCE
    if not is_pool.any():
        return df, df.iloc[0:0].assign(_reason="")
    base, pool = df[~is_pool], df[is_pool]
    reason = pd.Series("", index=pool.index)
    reason[pool["_real_match"].astype(bool)] = DROP_REAL_TEST
    by_hash = {}
    for h1, h2, lab in zip(base["text_hash"], base["hash_v2"], base["label"]):
        by_hash.setdefault(h1, set()).add(lab)
        by_hash.setdefault(h2, set()).add(lab)
    for i, h1, h2, lab in zip(pool.index, pool["text_hash"], pool["hash_v2"], pool["label"]):
        if reason[i]:
            continue
        labs = by_hash.get(h1, set()) | by_hash.get(h2, set())
        if labs:
            reason[i] = DROP_EXISTING_SAME if labs == {lab} else DROP_EXISTING_CONFLICT
    rest = pool[reason == ""]
    labs = defaultdict(set)
    for h, lab in zip(rest["hash_v2"], rest["label"]):
        labs[h].add(lab)
    seen = set()
    for i, h, lab in zip(rest.index, rest["hash_v2"], rest["label"]):
        if len(labs[h]) > 1:
            reason[i] = DROP_POOL_CONFLICT
        elif h in seen:
            reason[i] = DROP_POOL_DUP
        else:
            seen.add(h)
    gone = reason != ""
    return df.drop(index=pool.index[gone]), pool[gone].assign(_reason=reason[gone])


def place_fresh(units, seed=POOL_SEED):
    """Split fresh pool clusters 50 % val / 50 % train (D-v3.1). `units`: a frame with one row per pool message and columns cluster_id, label,
    real_group, _gsize, _kw. A unit is a cluster; its weight is the sum of the group sizes of its real_groups; its label the majority label of its rows
    (ties -> scam); its keyword bucket that of its biggest group. Inside a label x keyword-bucket stratum the units are sorted by weight, taken in pairs
    and a seeded coin decides which of a pair goes to val (the rule of intake_real.grouped_split); an odd one out is a coin flip. Returns
    ({cluster_id: "val" | "train"}, {(label, kw): [val units, train units]})."""
    strata = defaultdict(list)
    for cid, g in units.groupby("cluster_id", sort=True):
        by_group = g.groupby("real_group")["_gsize"].max()
        lab = Counter(g["label"])
        label = max(lab, key=lambda l: (lab[l], l))
        big = max(by_group.index, key=lambda k: (by_group[k], k))
        kw = g.loc[g["real_group"] == big, "_kw"].iloc[0]
        strata[(label, kw)].append((cid, int(by_group.sum())))
    split, counts = {}, {}
    for key in sorted(strata, key=str):
        us = sorted(strata[key], key=lambda x: (-x[1], x[0]))
        rng = random.Random(f"{seed}|{key[0]}|{key[1]}")
        v = t = 0
        for k in range(0, len(us), 2):
            pair = [x[0] for x in us[k:k + 2]]
            if len(pair) == 2:
                rng.shuffle(pair)
                to_val, to_train = [pair[0]], [pair[1]]
            else:
                to_val, to_train = ([pair[0]], []) if rng.random() < 0.5 else ([], [pair[0]])
            for u in to_val:
                split[u] = "val"; v += 1
            for u in to_train:
                split[u] = "train"; t += 1
        counts[key] = [v, t]
    return split, counts


def straddles(df):
    """The pool asserts on the finished frame (columns source, split, real_group): no real_group in two splits, no pool row in test. Returns a list of messages."""
    bad = []
    if "real_group" not in df:
        return bad
    k = df["real_group"].fillna("")
    sp = df["split"].astype(str)
    n = sp[k != ""].groupby(k[k != ""]).nunique()
    if (n > 1).any():
        bad.append(f"real_group: {int((n > 1).sum())} groups straddle splits, e.g. {list(n[n > 1].index[:3])}")
    pool_in_test = int(((df["source"] == POOL_SOURCE) & (sp == "test")).sum())
    if pool_in_test:
        bad.append(f"{pool_in_test} pool rows are in test (D-v3.2: test membership is frozen)")
    return bad
