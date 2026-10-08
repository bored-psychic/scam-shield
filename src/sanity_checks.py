import argparse, hashlib, os, re, sys, time
import numpy as np, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, recall_score, roc_auc_score
from sklearn.preprocessing import OneHotEncoder
from textprep import model_text

# Shortcut / confounding checks on data/final/messages.csv -> reports/sanity.md.
#   1. source x label, language x split, language x label crosstabs (counts only; read them before any model score)
#   2. language-only and source-only classifiers: what a model that never reads the text scores on test
#   3. leave-one-source-out (LOSO) F1 for each major source: train on the train rows of every other source, score the
#      held-out source; the gap to the in-distribution score is how much the model leans on source-specific style
#   4. the attack rates in src/augment.py, and which n-gram type the baseline TF-IDF uses (both read from the source
#      files, so the report cannot drift from the code)
#   python src/sanity_checks.py              full report (about 7 min, dominated by the 8 LOSO fits)
#   python src/sanity_checks.py --only-loso  refit and rescore LOSO only, then replace section 5 of the existing
#                                            reports/sanity.md in place (the other sections are left untouched)
# LOSO also reports AUROC and PR-AUC from the logistic-regression decision function. They don't depend on the 0.5
# threshold, so they separate "the ranking broke" from "the threshold moved under domain shift"; PR-AUC is only
# readable against the held-out source's scam rate (a random ranking scores that), so the rate is printed beside it.
# Only val/test rows are scored. This is the project's internal test split, not the final real-message test set.
# A hand-written "## Interpretation" section at the end of the report is carried over on every rewrite (full or
# --only-loso). It must name the split_map hash it was written against; if that differs from the current one, a
# "Stale" warning goes under its heading.
MIN_SOURCE_ROWS = 500   # "major" source for LOSO: at least this many rows and both labels (single-class sources have no F1)
OUT = "reports/sanity.md"
INTERP = "\n## Interpretation"

def md(df, index=True):
    """DataFrame -> GitHub markdown table (no tabulate dependency)."""
    d = df.reset_index() if index else df
    cells = [[str(c) for c in d.columns]] + [[f"{v:.3f}" if isinstance(v, (float, np.floating)) and not pd.isna(v)
                                              else ("" if pd.isna(v) else str(v)) for v in r] for r in d.itertuples(index=False)]
    lines = ["| " + " | ".join(r) + " |" for r in cells]
    lines.insert(1, "|" + "|".join(" --- " for _ in cells[0]) + "|")
    return "\n".join(lines)

ap = argparse.ArgumentParser()
ap.add_argument("--only-loso", action="store_true", help="rerun the LOSO section and splice it into the existing report")
args = ap.parse_args()

def log(msg):
    print(msg, file=sys.stderr, flush=True)

df = pd.read_csv("data/final/messages.csv", low_memory=False)
df["text"] = df["text"].map(model_text)   # the text models' input, as in baseline.py: URLs -> <URL>, then the first 2000 characters
df["label_name"] = df["label"].map({0: "benign", 1: "scam"})
tr, va, te = (df[df["split"] == s] for s in ("train", "val", "test"))
split_hash = hashlib.sha256(open("data/final/split_map.csv", "rb").read()).hexdigest()
prev_report = open(OUT).read() if os.path.exists(OUT) else ""

def interpretation(report):
    """The '## Interpretation' block (to the end of the file) of an existing report, or "" if it has none. An old Stale warning is
    dropped and re-added if the block names a different split_map hash than the current one, or doesn't mention `model_text` (it was written
    before the text models read textprep.model_text, so the F1 / AUROC values it quotes are the old pipeline's)."""
    if INTERP not in report:
        return ""
    block = re.sub(r"\n> \*\*Stale:\*\*[^\n]*\n", "", report[report.index(INTERP):], count=1)
    stale = []
    m = re.search(r"split_map SHA-256 `([0-9a-f]{16})", block)
    if not m or m.group(1) != split_hash[:16]:
        was = f"split_map `{m.group(1)}...`" if m else "an unrecorded split_map"
        stale.append(f"written against {was}; the report above is on `{split_hash[:16]}...`, so numbers quoted below may not match the tables.")
    if "model_text" not in block:
        stale.append("written before the text models read `textprep.model_text` (links replaced by `<URL>`); the tables above are on that "
                     "pipeline, so F1 / AUROC values quoted below (e.g. 0.895, the LOSO columns) are the old pipeline's. See reports/url_token.md. "
                     "Rewrite this section, mention `model_text` in it, and this warning goes away.")
    if stale:
        block = block.replace(INTERP, INTERP + "\n\n> **Stale:** " + " ".join(stale), 1)
    return block
out = [f"# Sanity checks\n\nGenerated by `src/sanity_checks.py`. {len(df)} rows; split_map.csv SHA-256 `{split_hash[:16]}...`. "
       f"Scores are on the internal test split (n={len(te)}), never the final real-message test set. "
       "\"Real-only\" drops rows with `is_synthetic = True`.\n"]

# ---- 1-3. crosstabs ----
src_label = pd.crosstab(df["source"], df["label_name"])
src_label["scam %"] = (100 * src_label["scam"] / (src_label["benign"] + src_label["scam"])).round(1)
src_label["synthetic %"] = (100 * df.groupby("source")["is_synthetic"].mean()).round(0)
src_label["languages"] = df.groupby("source")["language"].agg(lambda s: ", ".join(f"{k} {v}" for k, v in s.value_counts().items()))
out.append("## 1. Source x label\n\n" + md(src_label))

lang_split = pd.crosstab(df["language"], df["split"])[["train", "val", "test"]]
lang_split["total"] = lang_split.sum(axis=1)
out.append("\n## 2. Language x split\n\n" + md(lang_split))

lang_label = pd.crosstab(df["language"], df["label_name"])
lang_label["scam %"] = (100 * lang_label["scam"] / (lang_label["benign"] + lang_label["scam"])).round(1)
out.append("\n## 3. Benign vs scam per language\n\nAll rows:\n\n" + md(lang_label))
ll_split = pd.crosstab([df["language"], df["split"]], df["label_name"]).reindex(
    pd.MultiIndex.from_product([lang_label.index, ["train", "val", "test"]], names=["language", "split"]), fill_value=0)
out.append("\nBy split:\n\n" + md(ll_split))
real = df[~df["is_synthetic"]]
ll_real = pd.crosstab(real["language"], real["label_name"]).reindex(lang_label.index, fill_value=0)
ll_real["scam %"] = (100 * ll_real["scam"] / (ll_real["benign"] + ll_real["scam"]).replace(0, np.nan)).round(1)
out.append("\nReal rows only (`is_synthetic = False`):\n\n" + md(ll_real))
lang_src = pd.crosstab(df["source"], df["language"])
out.append("\nLanguage by source (rows):\n\n" + md(lang_src))

# ---- 4. language-only and source-only baselines ----
def score(d, pred):
    return {"n": len(d), "F1": f1_score(d["label"], pred, zero_division=0), "scam_recall": recall_score(d["label"], pred, zero_division=0),
            "benign_acc": float((pred[d["label"].to_numpy() == 0] == 0).mean())}

tab = []
te_real = te[~te["is_synthetic"]]
def one_hot_baseline(name, cols):
    enc = OneHotEncoder(handle_unknown="ignore")
    clf = LogisticRegression(class_weight="balanced", max_iter=1000).fit(enc.fit_transform(tr[cols]), tr["label"])
    pred = lambda d: clf.predict(enc.transform(d[cols]))
    for subset, d in (("all test", te), ("real-only test", te_real)):
        tab.append({"model": name, "eval on": subset, **score(d, pred(d))})
    return pred

one_hot_baseline("language-only", ["language"])
source_pred = one_hot_baseline("source-only", ["source"])
vec = lambda: TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=3, max_features=200000, sublinear_tf=True)
log("fitting reference text model")
t0 = time.time()
v = vec()
ref = LogisticRegression(max_iter=2000, class_weight="balanced").fit(v.fit_transform(tr["text"]), tr["label"])
ref_pred = lambda d: ref.predict(v.transform(d["text"]))
for subset, d in (("all test", te), ("real-only test", te_real)):
    tab.append({"model": "text TF-IDF (baseline.py settings)", "eval on": subset, **score(d, ref_pred(d))})
log(f"  {time.time() - t0:.0f}s")
out.append("\n## 4. Language-only and source-only baselines\n\nOne-hot logistic regression, `class_weight=balanced`, fit on train, "
           "scored on test. Neither sees the text. Anything near the text model's F1 means the text model may just be "
           "reading the shortcut.\n\n" + md(pd.DataFrame(tab), index=False))
spt = te.assign(pred=source_pred(te)).groupby("source").apply(
    lambda g: pd.Series({"n": len(g), "scam": int(g["label"].sum()), "source-only acc": (g["label"] == g["pred"]).mean()}), include_groups=False)
out.append("\nSource-only accuracy per source on test (the 'a model that only knows the source' view):\n\n" + md(spt.assign(**{"scam": spt["scam"].astype(int), "n": spt["n"].astype(int)})))

# ---- 5. leave-one-source-out ----
vt = pd.concat([va, te])
sizes = df.groupby("source")["label"].agg(n="size", scam="sum", classes="nunique")
major = sizes[(sizes["n"] >= MIN_SOURCE_ROWS) & (sizes["classes"] == 2)].sort_values("n", ascending=False).index.tolist()
rows = []
for s in major:
    log(f"LOSO: holding out {s}")
    t0 = time.time()
    rest = tr[tr["source"] != s]
    vl = vec()
    m = LogisticRegression(max_iter=2000, class_weight="balanced").fit(vl.fit_transform(rest["text"]), rest["label"])
    held_vt, held_all = vt[vt["source"] == s], df[df["source"] == s]
    p = lambda d, model=m, vv=vl: model.predict(vv.transform(d["text"]))
    sc = score(held_vt, p(held_vt))
    sc_in = score(held_vt, ref_pred(held_vt))
    y = held_vt["label"]
    s_loso, s_in = m.decision_function(vl.transform(held_vt["text"])), ref.decision_function(v.transform(held_vt["text"]))
    rows.append({"held-out source": s, "train rows left": len(rest), "val+test n": sc["n"], "val+test scam": int(y.sum()),
                 "scam rate": y.mean(),
                 "in-dist F1": sc_in["F1"], "LOSO F1": sc["F1"],
                 "in-dist AUROC": roc_auc_score(y, s_in), "LOSO AUROC": roc_auc_score(y, s_loso),
                 "in-dist PR-AUC": average_precision_score(y, s_in), "LOSO PR-AUC": average_precision_score(y, s_loso),
                 "LOSO scam recall": sc["scam_recall"], "LOSO benign acc": sc["benign_acc"],
                 "LOSO F1 (all rows)": score(held_all, p(held_all))["F1"]})
    log(f"  {time.time() - t0:.0f}s")
loso = pd.DataFrame(rows)
loso["F1 drop"] = loso["in-dist F1"] - loso["LOSO F1"]
out.append(f"\n## 5. Leave-one-source-out\n\nMajor sources = at least {MIN_SOURCE_ROWS} rows and both labels ({len(major)} of {len(sizes)}). "
           "Each fold trains on the train rows of every other source (same TF-IDF settings, vectorizer refit) and scores the held-out "
           "source's val+test rows. Clusters never straddle splits, so these rows have no >= 0.7 twin in the training rows. "
           "`in-dist` columns are the full model (section 4) on the same rows, so the difference is what losing the source costs. "
           "AUROC and PR-AUC use the decision function (no threshold): a high AUROC with a low F1 means the ranking survived but the "
           "0.5 cut-off moved; PR-AUC should be read against `scam rate`, which is what a random ranking scores. "
           "The last column scores all of the source's rows (train split too) for a steadier number on small sources; cross-source "
           "near-duplicates are not excluded there, so treat it as optimistic. Sources with one class (`cmu_hinglish_dog`, "
           "`hinglish_conversations`, `web_scams`) have no F1 and stay in training.\n\n" + md(loso, index=False))

if args.only_loso:
    new = out[-1]
    old = open(OUT).read()
    a, b = old.index("\n## 5. Leave-one-source-out"), old.index("\n## 6. Attack rates")
    tail = old[b:old.index(INTERP)] + interpretation(old) if INTERP in old else old[b:]
    open(OUT, "w").write(old[:a] + new + "\n" + tail)
    print(new)
    log(f"replaced section 5 in {OUT}")
    sys.exit(0)

# ---- attack rates and n-gram type, read from the source ----
aug = open("src/augment.py").read()
base_src = open("src/baseline.py").read()
rates = re.findall(r"def (\w+)\(t, p=([\d.]+)\)", aug)
maxlen = re.search(r"^MAX_LEN = (\d+)", aug, re.M).group(1)
fam = {k: re.findall(r'"(\w+)"', v) for k, v in zip(("train", "held_out"), re.findall(r"^(?:TRAIN|HELD_OUT)_ATTACKS = \{(.*)\}", aug, re.M))}
hmap = {k: len(re.findall(r'"\S": "\S"', re.search(rf"^{k} = \{{(.*)\}}", aug, re.M).group(1))) for k in ("HOMO", "LEET")}
desc = {"homoglyph": "each letter in the Cyrillic look-alike map (a e o p c x i y s) is swapped",
        "leet": "each letter in {a o i e s} becomes @ 0 1 3 $",
        "zero_width": "a zero-width space is inserted after each letter",
        "char_noise": "each letter is swapped with its neighbour or deleted (50/50)"}
arow = [{"attack": n, "per-character probability": float(p), "applies to": desc[n], "used for": "train augmentation" if n in fam["train"] else "held-out test"} for n, p in rates]
arow += [{"attack": "url_obfuscate", "per-character probability": "n/a", "applies to": "every URL/domain token: http -> hxxp, '.' -> '[.]'", "used for": "held-out test"},
         {"attack": "spaced_keywords", "per-character probability": "n/a", "applies to": "every occurrence of KYC OTP UPI PIN account blocked verify lottery prize arrest is letter-spaced", "used for": "held-out test"}]
out.append("\n## 6. Attack rates in `augment.py`\n\nProbabilities are per eligible character, so the share of characters actually changed in a "
           f"message is lower (about p x the fraction of eligible letters). Only scam rows of at most {maxlen} characters are attacked. "
           "`random.seed(0)` is set once, so reruns are reproducible.\n\n" + md(pd.DataFrame(arow), index=False))
rt = []
for f, label in (("messages_aug.csv", "messages_aug.csv (train parents)"), ("messages_adv_test.csv", "messages_adv_test.csv (test parents)")):
    a = pd.read_csv(f"data/final/{f}", usecols=["aug_method", "parent_is_synthetic", "parent_hash"])
    g = a.groupby("aug_method").agg(rows=("parent_hash", "size"), parents=("parent_hash", "nunique"),
                                    real_parent_rows=("parent_is_synthetic", lambda s: int((~s).sum())))
    out.append(f"\n{label}:\n\n" + md(g))

ana = re.search(r'TfidfVectorizer\(analyzer="(\w+)", ngram_range=\((\d), (\d)\), min_df=(\d+), max_features=(\d+), sublinear_tf=(\w+)', base_src)
assert ana, "could not find the TfidfVectorizer call in baseline.py"
assert ana.groups() == ("char_wb", "2", "4", "3", "200000", "True"), f"baseline.py vectorizer changed ({ana.groups()}); update vec() above"
out.append(f"\n## 7. Baseline TF-IDF n-grams\n\n`baseline.py` uses **character** n-grams, not word n-grams: `analyzer=\"{ana[1]}\"` (character n-grams "
           f"taken inside word boundaries, padded with spaces), `ngram_range=({ana[2]}, {ana[3]})`, `min_df={ana[4]}`, `max_features={ana[5]}`, "
           f"`sublinear_tf={ana[6]}`, URLs replaced by `<URL>` (`textprep.model_text`) and the text cut to the first 2000 characters, logistic regression with `class_weight=balanced`. "
           "Consequences: it needs no tokenizer, so Hindi and Kannada script work with the same code, and it tolerates the "
           "typo-style attacks better than word n-grams would, but it also picks up script, casing and boilerplate fragments "
           "that identify a source. A word-level run is the obvious ablation.\n")

# ---- flags ----
flags = []
lang_scam = lang_label["scam %"]
for lang in lang_scam.index:
    srcs = lang_src.loc[:, lang]
    srcs = srcs[srcs > 0]
    if lang != "english" and len(srcs) <= 3:
        flags.append(f"`{lang}`: {int(srcs.sum())} rows from only {len(srcs)} source(s) ({', '.join(srcs.index)}), "
                     f"{int(real[real['language'] == lang].shape[0])} real rows; scam rate {lang_scam[lang]}% vs {lang_scam['english']}% for English.")
single = sizes[sizes["classes"] == 1]
for s_, r in single.iterrows():
    flags.append(f"`{s_}` is single-class ({'scam' if r['scam'] else 'benign'}, {int(r['n'])} rows): a source indicator predicts the label for it.")
big_drop = loso[loso["F1 drop"] > 0.1]
for _, r in big_drop.iterrows():
    flags.append(f"`{r['held-out source']}`: LOSO F1 {r['LOSO F1']:.3f} vs {r['in-dist F1']:.3f} in-distribution (drop {r['F1 drop']:.2f}).")
out.insert(1, "## Flags (auto-generated; interpretation is a separate step)\n\n" + "\n".join(f"- {f}" for f in flags) + "\n")

os.makedirs("reports", exist_ok=True)
open(OUT, "w").write("\n".join(out).rstrip("\n") + "\n" + interpretation(prev_report))
log(f"wrote {OUT}")
