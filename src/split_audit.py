import pandas as pd
import neardup as nd

# Read-only audit of data/final/messages.csv: how many near-duplicate pairs still cross splits, and how many val/test
# rows have a train neighbour. Pairs are looked up with the check seed (not the one the clusters were built with) at
# exact Jaccard >= 0.6, on two views of the text:
#   raw         lowercased, whitespace-collapsed: what a plain near-duplicate scan sees
#   normalised  prefixes/suffixes stripped, numbers -> <NUM>
# build_text.py merges a pair if EITHER view reaches 0.7 (0.6 within india_fraud_final), so "violations" below must be
# zero. india_fraud_final pairs at >= 0.6 are brute-forced (exact), the rest come from LSH (recall ~98% at 0.6).
#   python src/split_audit.py
THRESHOLDS = (0.8, 0.7, 0.6)
df = pd.read_csv("data/final/messages.csv", low_memory=False)
sp = df["split"].to_numpy()
print(f"{len(df)} rows; split {df['split'].value_counts().to_dict()}")

src = df["source"].to_numpy()
india = [r for r, s in enumerate(src) if s == "india_fraud_final"]
cross = lambda i, j: sp[i] == sp[j]
violations = set()
for view, fn in nd.VIEWS.items():
    shs = nd.shingle_sets([fn(t) for t in df["text"]])
    found = list(nd.near_dup_pairs(shs, nd.CHECK_SEED, min(THRESHOLDS), skip=cross)) + \
        [(min(i, j), max(i, j), jac) for i, j, jac in nd.exact_pairs(shs, india, min(THRESHOLDS), skip=cross)]
    p = pd.DataFrame(found, columns=["i", "j", "jac"]).drop_duplicates(["i", "j"])
    del shs
    rule = (p["jac"] >= nd.MIN_JACCARD) | ((p["jac"] >= nd.SOURCE_MIN_JACCARD["india_fraud_final"]) &
                                           (src[p["i"]] == "india_fraud_final") & (src[p["j"]] == "india_fraud_final"))
    violations |= set(zip(p["i"][rule], p["j"][rule]))
    print(f"\n=== {view} text: cross-split pairs", {f">={t}": int((p["jac"] >= t).sum()) for t in THRESHOLDS},
          f"| india_fraud_final pairs >= 0.6: {int(((src[p['i']] == 'india_fraud_final') & (src[p['j']] == 'india_fraud_final')).sum())}")
    if p.empty:
        continue
    p["src"] = [" / ".join(sorted({df["source"][i], df["source"][j]})) for i, j in zip(p["i"], p["j"])]
    print(p["src"].value_counts().head(8).to_string())
    for t in THRESHOLDS[1:]:
        # val/test rows with a train neighbour at >= t
        q = p[p["jac"] >= t]
        rows = {k for i, j in zip(q["i"], q["j"]) for k, o in ((i, j), (j, i)) if sp[o] == "train" and sp[k] != "train"}
        ex = df.loc[sorted(rows)]
        tab = pd.DataFrame({"val+test rows": df[df["split"] != "train"].groupby("source").size(),
                            "with train twin": ex.groupby("source").size()}).fillna(0).astype(int)
        for s in ("val", "test"):
            tab[f"{s} exposed"] = ex[ex["split"] == s].groupby("source").size().reindex(tab.index).fillna(0).astype(int)
            tab[f"{s} total"] = df[df["split"] == s].groupby("source").size().reindex(tab.index).fillna(0).astype(int)
        tab["% exposed"] = (100 * tab["with train twin"] / tab["val+test rows"]).round(1)
        print(f"\nval/test rows with a train neighbour at >= {t}: {len(ex)} of {(df['split'] != 'train').sum()} "
              f"({len(ex) / (df['split'] != 'train').sum():.1%})")
        print(tab[["val exposed", "val total", "test exposed", "test total", "% exposed"]].to_string())

print(f"\nviolations of the clustering rule (>= {nd.MIN_JACCARD} on either view, {nd.SOURCE_MIN_JACCARD} within source): "
      f"{len(violations)} cross-split pairs (must be 0)")

size = df["cluster_id"].value_counts()
mixed = df.groupby("cluster_id")["label"].nunique() > 1
ind = df["cluster_id"].isin(df.loc[df["source"] == "india_fraud_final", "cluster_id"])
mi = mixed & ind.groupby(df["cluster_id"]).first()
print(f"mixed scam/benign clusters containing india_fraud_final rows: {mi.sum()} "
      f"({df['cluster_id'].isin(mi[mi].index).sum()} rows); by source of their rows: "
      f"{df[df['cluster_id'].isin(mixed[mixed].index)].groupby('source').size().to_dict()}")
for cid in mi[mi].index[:10]:
    g = df[df["cluster_id"] == cid]
    print(f"  {len(g)} rows, labels {g['label'].tolist()[:8]}, sources {g['source'].tolist()[:4]}: " +
          " ~ ".join(ascii(t[:60]) for t in g["text"].head(3)))
print(f"\nclusters: {len(size)}; multi-row {(size > 1).sum()} ({size[size > 1].sum()} rows); "
      f"mixed scam/benign {mixed.sum()} ({df['cluster_id'].isin(mixed[mixed].index).sum()} rows)")
print("largest clusters:")
for cid, n in size.head(10).items():
    g = df[df["cluster_id"] == cid]
    print(f"  {n:4d}  {g['split'].iloc[0]:<5} {g['source'].iloc[0]:<18} fraud/scam share {g['label'].mean():.2f}  {ascii(g['text'].iloc[0][:70])}")
print("split x label of the 10 largest clusters' rows:",
      df[df["cluster_id"].isin(size.head(10).index)].groupby(["split", "label"]).size().to_dict())
