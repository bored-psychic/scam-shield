import glob, hashlib, os
import pandas as pd

# Build data/final/apps.csv from Android permission datasets in data/external/apps/.
# CICMalDroid / Drebin are manual downloads (MANUAL_DOWNLOADS.md) and need their own readers once present.
f = sorted(glob.glob("data/external/apps/android_malware_hf/android_malware_hf_*.csv"))[-1]
d = pd.read_csv(f)
perm_cols = [c for c in d.columns if c != "Result"]

df = pd.DataFrame({
    "permissions": d[perm_cols].apply(lambda r: "|".join(c for c in perm_cols if r[c]), axis=1),
    "n_permissions": d[perm_cols].sum(axis=1),
    "label": d["Result"].astype(int),
    "source": "android_malware_hf",
})
# no package names in this source, so dedupe + split on the permission set itself
df["perm_hash"] = df["permissions"].map(lambda s: hashlib.md5(s.encode()).hexdigest())
conflict = df.groupby("perm_hash")["label"].transform("nunique") > 1
print(f"rows {len(df)}, identical permission sets {df['perm_hash'].duplicated().sum()}, "
      f"of which label-conflicting {conflict.sum()}")
df = df[~conflict].drop_duplicates("perm_hash").reset_index(drop=True)
b = df["perm_hash"].map(lambda h: int(h, 16) % 100)
df["split"] = pd.cut(b, [-1, 79, 89, 99], labels=["train", "val", "test"])

os.makedirs("data/final", exist_ok=True)
df.to_csv("data/final/apps.csv", index=False)
print(df.groupby(["label", "split"], observed=True).size().unstack(fill_value=0))
print("\nmedian permissions by label:", df.groupby("label")["n_permissions"].median().to_dict())
