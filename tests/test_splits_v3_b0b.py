import json, os, string, sys, tempfile
from pathlib import Path

HERE = Path(os.path.abspath(globals().get("__file__", "tests/test_splits_v3_b0b.py"))).parent   # exec()-ed from the project root there is no __file__
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "src"), str(HERE)]

import numpy as np, pandas as pd
import company_key, gates_v3, neardup, pool, synth_upi_collect
import pool_fixture

# python tests/test_splits_v3_b0b.py   (from the project root). splits-v3 step B0b (docs/plans/splits_v3.md D-v3.1, D-v3.3, D-v3.4, sections 4 and 5). Code only: every check
# runs on invented data or on read-only copies of the splits-v2 files; nothing is written under data/ or models/, nothing under data/real/ is read.
#   B1  company_key: the profile name rule, the stop list, the common-word guard, one name -> that company's key, several / none / ambiguous -> no key, longest name wins,
#       and the straddle rule keeps the highest split (test > val > train) and drops the frozen rows of the others
#   B2  pool.load_pool on an invented pool: mapping, validation (provenance, is_synthetic, label, language, columns), a path under data/real/ refused, the freeze
#       manifest required, no file -> None, the realguard-hash flag
#   B3  pool.prefilter: each drop reason, in order; an existing row is never dropped by a pool row
#   B4  pool.place_fresh: only val / train, pairs split evenly inside each label x keyword stratum, deterministic, the seed matters, a cluster counts once
#   B5  neardup.assert_no_leakage and pool.straddles cover real_group; finetune.GROUP_KEYS has it; a pool row in test is caught
#   B6  finetune: read_mask_version refuses missing / unknown; load_data needs real_group once a pool exists, catches a straddling group and a stale build_meta.json;
#       a CPU run of a tiny invented model writes mask_version and the build_meta hash into shield_meta.json (skipped without data/final)
#   B7  synth_upi_collect: 8 families x 4 languages, label 0, synthetic, illustrative, 5 families to val and 3 to train, never test, no near-duplicate across families, none
#       near the test family synth_upi_0_7_1
#   B8  gates_v3 on invented val predictions: every gate passes, fails and is "not measurable" when it should; any test row is refused; the loader keeps val rows only;
#       the report names the verdict
#   B9  eval_loso --val-only: test rows dropped unread, an unknown split refused, the v2 fold's val numbers reproduce (0.149 / 0.961 / 0.828), the CLI path writes val rows only
#   B10 (opt-in, B0B_E2E=1: about 8 minutes, 10 GB) build_text.py on an invented pool, written to a scratch folder; ledger, 0 straddles, 0 pool rows in test

def refuses(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except (SystemExit, AssertionError, ValueError) as e:
        return str(e) or type(e).__name__
    return None


# ------------------------------------------------------------------------------------------------------------------------------------------------------------ B1
def b1(tmp):
    bad = []
    cases = {"VAM SYSTEMS is a Business Consulting and IT company": "VAM SYSTEMS", "We are a leading firm": "", "Our company is a leader": "", "The ABC Group is the best": "ABC Group",
             "Point Nine Capital is an investor in startups": "Point Nine Capital", "lowercase start is a thing": "", "Acme, a global firm": "", "Aker Solutions, a Norwegian firm": "Aker Solutions",
             "Founded in 1985, Acme Industries is a maker": "", "One Two Three Four Five is a six-token name": ""}
    for text, want in cases.items():
        got = company_key.name_of_profile(text)
        if got != want:
            bad.append(f"name_of_profile({text!r}) = {got!r}, wanted {want!r}")
    K = lambda s: s * 32
    posts = [
        {"title": "t", "description": "d", "company_profile": "VAM SYSTEMS is a consulting company", "company_key": K("a")},
        {"title": "t", "description": "d", "company_profile": "VAM SYSTEMS is a consulting company", "company_key": K("a")},
        {"title": "t", "description": "d", "company_profile": "Aker Solutions is an engineering firm", "company_key": K("b")},
        {"title": "t", "description": "d", "company_profile": "There is a place for everyone", "company_key": K("c")},
        {"title": "t", "description": "d", "company_profile": "Zeta Corp is a firm of one kind", "company_key": K("d")},
        {"title": "t", "description": "d", "company_profile": "Zeta Corp is a firm of another kind", "company_key": K("e")},
        {"title": "t", "description": "d", "company_profile": "Zeta Corp Holdings is a holding firm", "company_key": K("f")},
        # profile-less posts
        {"title": "Engineer", "description": "Work at VAM SYSTEMS in Dubai", "company_profile": "", "company_key": ""},       # 7  -> a
        {"title": "vam systems role", "description": "apply now", "company_profile": "", "company_key": ""},                   # 8  -> a (case-insensitive)
        {"title": "Engineer", "description": "VAM SYSTEMS and Aker Solutions both", "company_profile": "", "company_key": ""},  # 9  -> none (two names)
        {"title": "Role", "description": "There are openings", "company_profile": "", "company_key": ""},                       # 10 -> none (common word)
        {"title": "Role", "description": "contact VAM about it", "company_profile": "", "company_key": ""},                     # 11 -> none (partial name)
        {"title": "Role", "description": "VAMSYSTEMS is hiring", "company_profile": "", "company_key": ""},                     # 12 -> none (glued)
        {"title": "Role", "description": "Join Aker Solutions Ltd today", "company_profile": "", "company_key": ""},            # 13 -> b (name inside a longer phrase)
        {"title": "Role", "description": "Zeta Corp needs you", "company_profile": "", "company_key": ""},                       # 14 -> none (two profile texts: ambiguous)
        {"title": "Role", "description": "Zeta Corp Holdings needs you", "company_profile": "", "company_key": ""},             # 15 -> f (longest name wins, not 'several')
        {"title": "Role", "description": "nothing to see", "company_profile": "", "company_key": ""},                           # 16 -> none
    ]
    for i in range(4):   # "there" in plain lowercase text in >= 3 posts: the common-word test
        posts.append({"title": "x", "description": "is there anything here, there it is", "company_profile": "", "company_key": ""})
    d = pd.DataFrame(posts)
    keys, led = company_key.fill_company_keys(d)
    want = {7: K("a"), 8: K("a"), 9: "", 10: "", 11: "", 12: "", 13: K("b"), 14: "", 15: K("f"), 16: ""}
    for i, w in want.items():
        if keys[i] != w:
            bad.append(f"profile-less post {i}: key {keys[i][:3]!r}, wanted {w[:3]!r}")
    if not (keys[:7] == d["company_key"][:7]).all():
        bad.append("a post that already had a key was changed")
    exp = {"keyed": 4, "several_names_found": 1, "ambiguous_name": 1, "common_word_names_dropped": 1}
    for k, v in exp.items():
        if led[k] != v:
            bad.append(f"ledger {k} = {led[k]}, wanted {v}")
    if led["key_names"].get(K("a")) != "VAM SYSTEMS":
        bad.append(f"key_names: {led['key_names']}")
    # straddle rule
    sp = pd.Series(["train", "train", "val", "test", np.nan, "train", "val", "train", "train", "test"])
    key = pd.Series(["k1", "k1", "k1", "k1", "k1", "k2", "k2", "k3", "k3", ""])
    drop = company_key.keep_by_priority(sp, key)
    if list(drop) != [True, True, True, False, False, True, False, False, False, False]:
        bad.append(f"keep_by_priority: {list(drop)}")
    return bad


# ------------------------------------------------------------------------------------------------------------------------------------------------------------ B2
def b2(tmp):
    bad = []
    fx = pool_fixture.make(tmp / "fx")
    p = pool.load_pool(fx["pool"], fx["manifest"], fx["real_test"])
    if len(p) != fx["rows"]:
        bad.append(f"{len(p)} rows loaded, the fixture has {fx['rows']}")
    if set(p["source"]) != {"phones_pool"} or set(p["provenance"]) != {"real_circulating"} or p["is_synthetic"].any():
        bad.append("source / provenance / is_synthetic not phones_pool / real_circulating / False")
    if int(p["_real_match"].sum()) != 1:
        bad.append(f"{int(p['_real_match'].sum())} rows flagged as a real_test_v1 text, wanted 1")
    if set(p["channel"]) != {"sms", "whatsapp"} or "kannada" not in set(p["language"]) or "en" in set(p["language"]):
        bad.append(f"channel {set(p['channel'])} / language {set(p['language'])}")
    if not p["note"].str.startswith("phone_").all() or not p["real_group"].str.match(r"^[gs]_").all():
        bad.append("note / real_group not taken from source / group_id")
    if pool.load_pool(str(tmp / "nothing.csv"), fx["manifest"]) is not None:
        bad.append("a missing pool file did not give None")
    if not refuses(pool.load_pool, fx["pool"], str(tmp / "no_manifest.json"), fx["real_test"]):
        bad.append("a pool without the freeze manifest was loaded")
    if not refuses(pool.load_pool, str(ROOT / "data/real/pool.csv"), fx["manifest"]):
        bad.append("a path under data/real/ was not refused")
    d = pd.read_csv(fx["pool"], keep_default_na=False, dtype=str)
    variants = {"provenance": ("provenance", "unknown"), "is_synthetic": ("is_synthetic", "True"), "label": ("label", "2"), "language": ("language", "fr"), "group_size": ("group_size", "0"),
                "empty group": ("group_id", "")}
    for what, (col, val) in variants.items():
        e = d.copy()
        e.loc[0, col] = val
        e.to_csv(tmp / f"bad_{what.replace(' ', '_')}.csv", index=False)
        if not refuses(pool.load_pool, str(tmp / f"bad_{what.replace(' ', '_')}.csv"), fx["manifest"], fx["real_test"]):
            bad.append(f"a pool with a bad {what} was loaded")
    d.drop(columns=["kw_bucket"]).to_csv(tmp / "bad_cols.csv", index=False)
    if not refuses(pool.load_pool, str(tmp / "bad_cols.csv"), fx["manifest"], fx["real_test"]):
        bad.append("a pool without kw_bucket was loaded")
    return bad


# ------------------------------------------------------------------------------------------------------------------------------------------------------------ B3
def b3(tmp):
    bad = []
    rows = [("base", "A", 0, False), ("base", "B", 1, False),
            ("phones_pool", "R", 0, True),          # real test text
            ("phones_pool", "A", 0, False),         # same as an existing row, same label
            ("phones_pool", "B", 0, False),         # same as an existing row, other label
            ("phones_pool", "D", 0, False), ("phones_pool", "D", 0, False),   # twice in the pool
            ("phones_pool", "E", 0, False), ("phones_pool", "E", 1, False),   # twice with two labels
            ("phones_pool", "U", 1, False)]
    df = pd.DataFrame([{"source": s, "text_hash": h, "hash_v2": h, "label": l, "_real_match": r} for s, h, l, r in rows])
    kept, dropped = pool.prefilter(df)
    got = dict(zip(dropped.index, dropped["_reason"]))
    want = {2: pool.DROP_REAL_TEST, 3: pool.DROP_EXISTING_SAME, 4: pool.DROP_EXISTING_CONFLICT, 6: pool.DROP_POOL_DUP, 7: pool.DROP_POOL_CONFLICT, 8: pool.DROP_POOL_CONFLICT}
    if got != want:
        bad.append(f"drop reasons {got}, wanted {want}")
    if list(kept.index) != [0, 1, 5, 9]:
        bad.append(f"kept rows {list(kept.index)}, wanted [0, 1, 5, 9]")
    k2, d2 = pool.prefilter(df[df["source"] == "base"])
    if len(d2) or len(k2) != 2:
        bad.append("a frame without pool rows changed")
    return bad


# ------------------------------------------------------------------------------------------------------------------------------------------------------------ B4
def units_frame(n_clusters=60, seed=3):
    rng = np.random.default_rng(seed)
    rows = []
    for c in range(n_clusters):
        label = int(c % 7 == 0)
        kw = ["kyc-bank", "delivery", "other", "investment"][c % 4]
        for g in range(1 + (c % 3 == 0)):   # every third cluster holds two groups
            size = int(rng.integers(1, 9))
            for _ in range(int(rng.integers(1, 4))):
                rows.append({"cluster_id": f"c{c:03d}", "label": label, "real_group": f"c{c:03d}_g{g}", "_gsize": size, "_kw": kw})
    return pd.DataFrame(rows)


def b4(tmp):
    bad = []
    u = units_frame()
    split, counts = pool.place_fresh(u)
    if set(split.values()) - {"val", "train"}:
        bad.append(f"placed outside val / train: {set(split.values())}")
    if set(split) != set(u["cluster_id"]):
        bad.append("not every cluster was placed exactly once")
    for key, (v, t) in counts.items():
        if abs(v - t) > 1:
            bad.append(f"stratum {key}: {v} val vs {t} train units")
    if sum(v + t for v, t in counts.values()) != u["cluster_id"].nunique():
        bad.append("the strata do not add up to the clusters")
    if pool.place_fresh(u) != (split, counts):
        bad.append("not deterministic")
    if pool.place_fresh(u, seed=pool.POOL_SEED + 1)[0] == split:
        bad.append("the seed has no effect")
    # a two-group cluster counts once, with the weight of both groups
    one = pd.DataFrame([{"cluster_id": "x", "label": 0, "real_group": "a", "_gsize": 2, "_kw": "other"}, {"cluster_id": "x", "label": 0, "real_group": "b", "_gsize": 5, "_kw": "kyc-bank"}])
    s1, c1 = pool.place_fresh(one)
    if list(c1) != [(0, "kyc-bank")] or sum(c1[(0, "kyc-bank")]) != 1:
        bad.append(f"a two-group cluster: strata {c1} (the biggest group sets the bucket, the cluster counts once)")
    return bad


# ------------------------------------------------------------------------------------------------------------------------------------------------------------ B5
def b5(tmp):
    bad = []
    import finetune
    if "real_group" not in finetune.GROUP_KEYS or "real_group" not in finetune.OPTIONAL_KEYS:
        bad.append("finetune.GROUP_KEYS / OPTIONAL_KEYS lack real_group")
    rng = np.random.default_rng(1)
    texts = [" ".join(rng.choice(pool_fixture.WORDS, 12)) + f" {i}" for i in range(6)]
    df = pd.DataFrame({"text": texts, "source": "phones_pool", "split": ["train", "train", "val", "val", "train", "val"], "cluster_id": [f"c{i}" for i in range(6)],
                       "template_family": "", "company_key": "", "translation_of": "", "real_group": ["g1", "g2", "g3", "g3", "g4", "g5"]})
    neardup.assert_no_leakage(df)
    df2 = df.assign(real_group=["g1", "g1", "g3", "g3", "g4", "g5"])   # g1 in train and train: fine
    neardup.assert_no_leakage(df2)
    df3 = df.assign(real_group=["g1", "g2", "g1", "g3", "g4", "g5"])   # g1 in train and val
    msg = refuses(neardup.assert_no_leakage, df3)
    if not (msg and "real_group" in msg):
        bad.append(f"assert_no_leakage on a straddling real_group: {msg!r}")
    if pool.straddles(df3) == [] or pool.straddles(df) != []:
        bad.append(f"pool.straddles: {pool.straddles(df3)} / {pool.straddles(df)}")
    if not any("test" in m for m in pool.straddles(df.assign(split=["test"] + list(df["split"][1:])))):
        bad.append("a pool row in test was not caught")
    return bad


# ------------------------------------------------------------------------------------------------------------------------------------------------------------ B6
def b6(tmp):
    import finetune
    bad = []
    d = tmp / "data"
    d.mkdir()
    for v in ("v2", "v3"):
        (d / "build_meta.json").write_text(json.dumps({"mask_version": v}), encoding="utf-8")
        if finetune.read_mask_version(d)[0] != v:
            bad.append(f"read_mask_version did not return {v}")
    for what, content in (("missing", None), ("no version", {}), ("unknown version", {"mask_version": "v9"}), ("intake-v1 (not a bundle's)", {"mask_version": "intake-v1"})):
        if content is None:
            (d / "build_meta.json").unlink()
        else:
            (d / "build_meta.json").write_text(json.dumps(content), encoding="utf-8")
        if not refuses(finetune.read_mask_version, d):
            bad.append(f"build_meta.json {what} was not refused")
    # load_data on a tiny invented dataset (the split map hash patched to the fixture's)
    from unittest import mock
    def write(dirpath, df, meta):
        dirpath.mkdir(exist_ok=True)
        df.to_csv(dirpath / "messages.csv", index=False)
        df[["text_hash", "split"]].to_csv(dirpath / "split_map.csv", index=False)
        (dirpath / "build_meta.json").write_text(json.dumps(meta), encoding="utf-8")
        return finetune.sha256(dirpath / "split_map.csv")
    base = pd.DataFrame({"text": [f"message number {i} about alerts" for i in range(6)], "label": [0, 0, 1, 0, 0, 1], "source": ["phones_pool"] * 4 + ["uci_sms_spam"] * 2,
                         "split": ["train", "train", "val", "val", "train", "val"], "text_hash": [f"h{i}" for i in range(6)], "cluster_id": [f"c{i}" for i in range(6)],
                         "template_family": "", "company_key": "", "translation_of": "", "real_group": ["g1", "g1", "g2", "g3", "", ""]})
    # g1 sits in train twice: fine
    sha = write(tmp / "ok", base, {"mask_version": "v3", "rows": 6, "split_map_rows": 6})
    with mock.patch.object(finetune, "SPLIT_MAP_SHA256", sha):
        out = finetune.load_data(tmp / "ok", False, False)
        if len(out[0]) != 6 - 0 - 0 and len(out[0]) <= 0:
            bad.append("load_data on a good dataset")
        sha2 = write(tmp / "straddle", base.assign(real_group=["g1", "g1", "g1", "g3", "", ""]), {"mask_version": "v3"})   # g1: train, train, val
        with mock.patch.object(finetune, "SPLIT_MAP_SHA256", sha2):
            m = refuses(finetune.load_data, tmp / "straddle", False, False)
            if not (m and "real_group" in m and "straddle" in m):
                bad.append(f"a straddling real_group was not caught by load_data: {m!r}")
        sha3 = write(tmp / "nocol", base.drop(columns=["real_group"]), {"mask_version": "v3"})
        with mock.patch.object(finetune, "SPLIT_MAP_SHA256", sha3):
            m = refuses(finetune.load_data, tmp / "nocol", False, False)
            if not (m and "real_group" in m):
                bad.append(f"phones_pool rows without a real_group column were accepted: {m!r}")
        sha4 = write(tmp / "nopool", base.drop(columns=["real_group"]).assign(source="uci_sms_spam"), {"mask_version": "v2", "rows": 6, "split_map_rows": 6})
        with mock.patch.object(finetune, "SPLIT_MAP_SHA256", sha4):
            finetune.load_data(tmp / "nopool", False, False)   # no pool, no column: the splits-v2 shape still loads
        sha5 = write(tmp / "stale", base, {"mask_version": "v3", "rows": 7, "split_map_rows": 6})
        with mock.patch.object(finetune, "SPLIT_MAP_SHA256", sha5):
            m = refuses(finetune.load_data, tmp / "stale", False, False)
            if not (m and "another build" in m):
                bad.append(f"a stale build_meta.json was accepted: {m!r}")
    # a CPU run of a tiny invented model on the real splits-v2 files writes mask_version into shield_meta.json
    data = ROOT / "data/final"
    if not (data / "messages.csv").exists():
        print("      data/final not on this machine: the shield_meta.json mask_version run is skipped")
        return bad
    import torch
    from transformers import BertConfig, BertForSequenceClassification, BertTokenizer
    chars = sorted({c for c in string.printable if c.strip()})
    vocab = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"] + chars + ["##" + c for c in chars]
    (tmp / "vocab.txt").write_text("\n".join(vocab), encoding="utf-8")
    tok = BertTokenizer(str(tmp / "vocab.txt"), do_lower_case=False)
    cfg = BertConfig(vocab_size=len(vocab), hidden_size=32, num_hidden_layers=1, num_attention_heads=2, intermediate_size=64, max_position_embeddings=130, num_labels=2)
    dd = tmp / "v2files"
    dd.mkdir()
    for n in ("messages.csv", "split_map.csv", "messages_adv_test.csv", "messages_aug.csv"):
        if (data / n).exists():
            (dd / n).symlink_to(data / n)
    (dd / "build_meta.json").write_text(json.dumps({"mask_version": "v3"}), encoding="utf-8")   # the label is the test's own: the run must copy it, whatever the files are
    for what, argv_extra in (("normal", []),):
        out = tmp / "run"
        argv = ["finetune.py", "--epochs", "1", "--limit", "60", "--device", "cpu", "--data-dir", str(dd), "--out", str(out), *argv_extra]
        torch.manual_seed(0)
        with mock.patch.object(sys, "argv", argv), mock.patch.object(finetune.AutoTokenizer, "from_pretrained", return_value=tok), \
                mock.patch.object(finetune.AutoModelForSequenceClassification, "from_pretrained", return_value=BertForSequenceClassification(cfg)):
            finetune.main()
        meta = json.loads((out / "shield_meta.json").read_text(encoding="utf-8"))
        if meta.get("mask_version") != "v3":
            bad.append(f"shield_meta.json mask_version = {meta.get('mask_version')!r}, wanted 'v3'")
        if meta["data_sha256"].get("build_meta.json") != finetune.sha256(dd / "build_meta.json"):
            bad.append("the build_meta.json hash is not in shield_meta.json data_sha256")
    # and the app reads it
    from shield.messages.text_head import bundle_mask_version
    if bundle_mask_version({"mask_version": "v3"}, "x") != "v3" or bundle_mask_version({}, "x") != "v2":
        bad.append("bundle_mask_version does not read what finetune writes")
    return bad


# ------------------------------------------------------------------------------------------------------------------------------------------------------------ B7
def b7(tmp):
    bad = []
    f = synth_upi_collect.make_family()
    n = synth_upi_collect
    if len(f) != n.N_TEMPLATES * 4 * n.N_PER_TEMPLATE or f["template_family"].nunique() != n.N_TEMPLATES or n.N_TEMPLATES != 8:
        bad.append(f"{len(f)} rows, {f['template_family'].nunique()} families")
    if set(f["label"]) != {0} or not f["is_synthetic"].all() or set(f["provenance"]) != {"illustrative"} or set(f["source"]) != {n.SOURCE}:
        bad.append("label / is_synthetic / provenance / source")
    if set(f["language"]) != {"english", "hinglish", "hindi", "kannada"}:
        bad.append(f"languages {set(f['language'])}")
    if f.groupby("template_id")["text"].apply(lambda s: s.is_unique).all() is False or f["text"].duplicated().any():
        bad.append("duplicate texts")
    if any("{" in t for t in f["text"]):
        bad.append("an unfilled slot")
    pl = n.placement()
    if sorted(pl.values()) != ["train"] * 3 + ["val"] * 5 or "test" in pl.values() or set(pl) != set(f["template_family"]):
        bad.append(f"placement {pl}")
    if n.make_family().equals(f) is False:
        bad.append("not deterministic")
    # no near-duplicate between two different families (they must be able to sit in different splits), none with the test family
    texts, fam = list(f["text"]), list(f["template_family"])
    sy = ROOT / "data/external/text/synth_india/synth_india.csv"
    n_syn = 0
    if sy.exists():
        t = pd.read_csv(sy)
        t = t[t["template_family"] == "synth_upi_0_7_1"]
        texts += list(t["text"])
        fam += ["TEST_FAMILY"] * len(t)
        n_syn = len(t)
    hits = [(fam[i], fam[j], round(jac, 2)) for i, j, jac, _ in neardup.near_dup_pairs_any(texts, ["a"] * len(texts), neardup.CHECK_SEED, skip=lambda i, j: fam[i] == fam[j])]
    if hits:
        bad.append(f"{len(hits)} near-duplicate pairs across families, e.g. {hits[:3]}")
    print(f"      {len(f)} rows in {n.N_TEMPLATES} families; checked against {n_syn} rows of the test family synth_upi_0_7_1: {len(hits)} near-duplicate pairs")
    return bad


# ------------------------------------------------------------------------------------------------------------------------------------------------------------ B8
CUT = {"temperature": 1.0, "susp": 0.1, "likely": 0.4, "source": "invented"}
LOW, MID, HIGH = 0.02, 0.2, 0.9   # raw score: not flagged / Suspicious only / Likely scam


def invented_val(n_alert=50, n_collect=12, n_syn=6, n_core=300, seed=5):
    """A val frame: v2-core rows (genuine and scam), POOL-val alert groups (kyc-bank / delivery), POOL-val collect-request groups, synthetic UPI families."""
    rng = np.random.default_rng(seed)
    rows = []
    def add(source, label, group_col, group, text="plain text", kw="", lang="english", syn=False):
        rows.append({"text_hash": f"h{len(rows)}", "text": text, "label": label, "source": source, "language": lang, "is_synthetic": syn, "template_family": group if group_col == "tf" else "",
                     "split": "val", "real_group": group if group_col == "rg" else "", "kw_bucket": kw})
    for i in range(n_core):
        add("uci_sms_spam", int(i % 5 == 0), None, "")
    for g in range(n_alert):
        for _ in range(1 + g % 3):
            add("phones_pool", 0, "rg", f"alert{g}", kw="kyc-bank" if g % 2 else "delivery", lang="kannada" if g % 10 == 0 else "english")
    for g in range(n_collect):
        add("phones_pool", 0, "rg", f"collect{g}", text="You have a collect request of Rs <ACCOUNT> from <NAME>", kw="kyc-bank")
    for g in range(n_syn):
        add("synth_upi_collect_v3", 0, "tf", f"synth_upi_collect_benign_v3_{g}", syn=True)
    for g in range(8):
        add("phones_pool", 1, "rg", f"scam{g}", kw="other")
    d = pd.DataFrame(rows)
    d["is_synthetic"] = d["is_synthetic"].astype(bool)
    return d


def invented_preds(val, flags, noise=0.0, seed=1):
    """Raw scores for every row: scam rows HIGH, genuine rows LOW, except the rows `flags` (a Series of LOW / MID / HIGH by index) overrides."""
    s = np.where(val["label"] == 1, HIGH, LOW).astype(float)
    for idx, v in flags.items():
        s[idx] = v
    return pd.DataFrame({"text_hash": val["text_hash"], "split": "val", "label": val["label"], "score": s})


def models(val, v3=None, shipped=None, baseline=None):
    out = []
    for name, f in (("v3", v3), ("shipped", shipped), ("baseline", baseline)):
        if f is not None:
            out.append(gates_v3.Model(name, invented_preds(val, f), CUT, val))
    return out


def b8(tmp):
    bad = []
    val = invented_val()
    pool_alert = val.index[(val["source"] == "phones_pool") & val["real_group"].str.startswith("alert")]
    core_gen = val.index[(val["source"] == "uci_sms_spam") & (val["label"] == 0)]
    core_scam = val.index[(val["source"] == "uci_sms_spam") & (val["label"] == 1)]
    pool_collect = val.index[val["real_group"].str.startswith("collect")]
    syn = val.index[val["source"] == "synth_upi_collect_v3"]
    loso = pd.DataFrame({"text_hash": [f"l{i}" for i in range(100)], "split": "val", "label": [0] * 60 + [1] * 40, "score": [0.1] * 40 + [0.6] * 20 + [0.9] * 38 + [0.1] * 2})
    # ---- all pass
    def run(v3=None, shipped=None, baseline=None, loso_=loso, val_=val):
        gates, extra = gates_v3.run_gates(val_, models(val_, v3, shipped, baseline), loso_)
        return {g["gate"]: g for g in gates}, gates, extra
    one_flag_baseline = {core_gen[0]: HIGH, core_gen[1]: MID, core_gen[2]: MID}
    r, gates, extra = run(v3={}, shipped={}, baseline=one_flag_baseline)
    for g in ("G1", "G2", "G3", "G5"):
        if r[g]["status"] != gates_v3.PASS:
            bad.append(f"all-clean scenario: {g} is {r[g]['status']}: {r[g]['why']}")
    if r["G4"]["status"] != gates_v3.PASS:
        bad.append(f"G4 (genuine accuracy {40 / 60:.2f}, AUROC high) should pass: {r['G4']['why']}")
    if not gates_v3.verdict(gates).startswith("ALL BLOCKING GATES PASS"):
        bad.append(f"verdict: {gates_v3.verdict(gates)}")
    text = gates_v3.render(gates, extra, models(val, {}, {}, one_flag_baseline), val)
    if "no test row was read" not in text or "**pass**" not in text:
        bad.append("the report text lacks the val-only statement or the pass marks")
    # ---- G1: the alert groups are the 50 "alert" groups and the 12 "collect" groups (kyc-bank): 62 in all. 2 at Likely = 3.2 % fails the 2 % cap, 1 = 1.6 % passes;
    # 7 at Suspicious = 11.3 % fails the 10 % cap, 5 = 8.1 % passes
    groups = val.loc[pool_alert].groupby("real_group").head(1).index   # the first row of each alert group
    r, *_ = run(v3={i: HIGH for i in groups[:2]}, shipped={}, baseline=one_flag_baseline)
    if r["G1"]["status"] != gates_v3.FAIL or r["G1"]["n_groups"] != 62:
        bad.append(f"G1 with 2 of 62 groups at Likely should fail (cap 2 %): {r['G1']['status']}, n {r['G1']['n_groups']}")
    r, *_ = run(v3={groups[0]: HIGH}, shipped={}, baseline=one_flag_baseline)
    if r["G1"]["status"] != gates_v3.PASS:
        bad.append(f"G1 with 1/62 at Likely should pass: {r['G1']['status']}: {r['G1']['why']}")
    r, *_ = run(v3={i: MID for i in groups[:7]}, shipped={}, baseline=one_flag_baseline)
    if r["G1"]["status"] != gates_v3.FAIL:
        bad.append(f"G1 with 7 of 62 groups at Suspicious should fail: {r['G1']['status']}")
    r, *_ = run(v3={i: MID for i in groups[:5]}, shipped={}, baseline=one_flag_baseline)
    if r["G1"]["status"] != gates_v3.PASS:
        bad.append(f"G1 with 5 of 62 at Suspicious should pass: {r['G1']['status']}")
    num = lambda prefix: val["real_group"].where(val["real_group"].str.startswith(prefix), "").str[len(prefix):].pipe(pd.to_numeric, errors="coerce")   # the group number after a prefix, NaN elsewhere
    small = val[~(num("alert") >= 20)].reset_index(drop=True)
    small["text_hash"] = [f"s{i}" for i in range(len(small))]
    r, *_ = run(v3={}, shipped={}, baseline={}, val_=small)
    if r["G1"]["status"] != gates_v3.NOT_MEASURABLE or r["G1"]["n_groups"] != 32:
        bad.append(f"G1 with 32 groups should be not measurable: {r['G1']['status']} ({r['G1']['n_groups']} groups)")
    # ---- G2: v3 misses 40 of the 60 core scam rows
    r, *_ = run(v3={i: LOW for i in core_scam[:40]}, shipped={}, baseline=one_flag_baseline)
    if r["G2"]["status"] != gates_v3.FAIL:
        bad.append(f"G2 with a much lower F1 should fail: {r['G2']['why']}")
    r, *_ = run(v3={core_scam[0]: LOW}, shipped={}, baseline=one_flag_baseline)   # one miss in 60: F1 drops by about 0.008 > 0.005
    if r["G2"]["status"] != gates_v3.FAIL:
        bad.append(f"G2 with a drop just over the tolerance should fail: {r['G2']['why']}")
    r, *_ = run(v3={}, shipped={core_scam[0]: LOW}, baseline=one_flag_baseline)   # v3 better than shipped
    if r["G2"]["status"] != gates_v3.PASS:
        bad.append("G2 with v3 better than shipped should pass")
    # ---- G3: real collect proxy has 12 groups, synthetic 6: pass; 2 of 12 real at Likely = 17 % fails; 1 of 6 synthetic = 17 % fails
    cg = val.loc[pool_collect].groupby("real_group").head(1).index
    r, *_ = run(v3={cg[0]: HIGH, cg[1]: HIGH}, shipped={}, baseline=one_flag_baseline)
    if r["G3"]["status"] != gates_v3.FAIL:
        bad.append(f"G3 with 17 % of the real collect groups at Likely should fail: {r['G3']['why']}")
    r, *_ = run(v3={syn[0]: HIGH}, shipped={}, baseline=one_flag_baseline)
    if r["G3"]["status"] != gates_v3.FAIL:
        bad.append(f"G3 with 1 of 6 synthetic groups at Likely should fail: {r['G3']['why']}")
    r, *_ = run(v3={cg[0]: HIGH}, shipped={}, baseline=one_flag_baseline)   # 1/12 = 8 %: pass
    if r["G3"]["status"] != gates_v3.PASS:
        bad.append(f"G3 with 8 % should pass: {r['G3']['why']}")
    few = val[~(num("collect") >= 3) & ~(val["source"] == "synth_upi_collect_v3")].reset_index(drop=True)
    few["text_hash"] = [f"f{i}" for i in range(len(few))]
    r, *_ = run(v3={}, shipped={}, baseline={}, val_=few)
    if r["G3"]["status"] != gates_v3.NOT_MEASURABLE:
        bad.append(f"G3 with 3 real and 0 synthetic groups should be not measurable: {r['G3']['status']}")
    only_syn = val[~val["real_group"].str.startswith("collect")].reset_index(drop=True)
    only_syn["text_hash"] = [f"o{i}" for i in range(len(only_syn))]
    r, *_ = run(v3={}, shipped={}, baseline={}, val_=only_syn)
    if r["G3"]["status"] != gates_v3.PASS or "not gated" not in r["G3"]["why"]:
        bad.append(f"G3 with only the synthetic proxy should pass on it alone and say the other is not gated: {r['G3']['status']} {r['G3']['why']}")
    # ---- G4
    r, *_ = run(v3={}, shipped={}, baseline=one_flag_baseline, loso_=None)
    if r["G4"]["status"] != gates_v3.NOT_MEASURABLE:
        bad.append("G4 without a LOSO file should be not measurable")
    worse = loso.assign(score=[0.9] * 50 + [0.1] * 10 + [0.9] * 40)   # genuine accuracy 10/60 = 0.17
    r, *_ = run(v3={}, shipped={}, baseline=one_flag_baseline, loso_=worse)
    if r["G4"]["status"] != gates_v3.FAIL or r["G4"]["blocking"]:
        bad.append(f"G4 with genuine accuracy 0.17 should fail and be non-blocking: {r['G4']['status']}")
    # ---- G5: v3 flags 5 core genuine rows at Suspicious, the baseline 3: fails; equal passes
    r, *_ = run(v3={i: MID for i in core_gen[:5]}, shipped={}, baseline={i: MID for i in core_gen[:3]})
    if r["G5"]["status"] != gates_v3.FAIL:
        bad.append(f"G5 with v3 flagging more than the baseline should fail: {r['G5']['why']}")
    r, *_ = run(v3={i: MID for i in core_gen[:3]}, shipped={}, baseline={i: MID for i in core_gen[:3]})
    if r["G5"]["status"] != gates_v3.PASS:
        bad.append("G5 with equal flag counts should pass")
    # ---- blocking gate failure -> the verdict names the fallback
    r, gates, _ = run(v3={i: LOW for i in core_scam[:40]}, shipped={}, baseline=one_flag_baseline)
    if "stays in the app" not in gates_v3.verdict(gates):
        bad.append(f"verdict on a failed blocking gate: {gates_v3.verdict(gates)}")
    # ---- test rows are refused
    with_test = invented_preds(val, {})
    with_test.loc[3, "split"] = "test"
    m = refuses(gates_v3.Model, "v3", with_test, CUT, val)
    if not (m and "val" in m):
        bad.append(f"a test row in the predictions was not refused: {m!r}")
    if not refuses(gates_v3.Model, "v3", invented_preds(val, {}).drop(columns=["split"]), CUT, val):
        bad.append("predictions without a split column were accepted")
    if not refuses(gates_v3.Model, "v3", invented_preds(val, {}).iloc[:-1], CUT, val):
        bad.append("predictions that do not cover the val rows were accepted")
    if not refuses(gates_v3.gate_g4, loso.assign(split="test")):
        bad.append("G4 on test rows was not refused")
    # ---- the loader keeps val rows only
    msgs = pd.concat([val.assign(split="val"), val.head(30).assign(split="test", text="TESTROW secret", text_hash=lambda d: "t" + d["text_hash"])], ignore_index=True)
    msgs["is_synthetic"] = msgs["is_synthetic"].map(str)
    msgs.to_csv(tmp / "messages.csv", index=False)
    lv = gates_v3.load_val_messages(tmp / "messages.csv")
    if len(lv) != len(val) or (lv["split"] != "val").any() or lv["text"].str.contains("TESTROW").any():
        bad.append(f"load_val_messages kept {len(lv)} rows (wanted {len(val)}) or a test row")
    # ---- the CLI, end to end on invented files
    for name, f in (("v3", {}), ("shipped", {}), ("baseline", one_flag_baseline)):
        invented_preds(val, f).to_csv(tmp / f"{name}_preds.csv", index=False)
        (tmp / f"{name}_meta.json").write_text(json.dumps({"calibration": {"temperature": 1.0, "threshold_suspicious": 0.1, "threshold_likely": 0.4}} if name != "baseline"
                                                           else {"threshold_suspicious": 0.1, "threshold_likely": 0.4}), encoding="utf-8")
    loso.to_csv(tmp / "loso_val.csv", index=False)
    import subprocess
    cmd = [sys.executable, str(ROOT / "src/gates_v3.py"), "--messages", str(tmp / "messages.csv"), "--out", str(tmp / "gates.md"), "--loso-val", str(tmp / "loso_val.csv")]
    for name in ("v3", "shipped", "baseline"):
        cmd += [f"--{name}-preds", str(tmp / f"{name}_preds.csv"), f"--{name}-meta", str(tmp / f"{name}_meta.json")]
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if p.returncode != 0 or "ALL BLOCKING GATES PASS" not in p.stdout or not (tmp / "gates.md").exists():
        bad.append(f"CLI: exit {p.returncode}: {(p.stdout + p.stderr)[-500:]}")
    pd.concat([invented_preds(val, {}), invented_preds(val, {}).head(2).assign(split="test", text_hash=["t1", "t2"])]).to_csv(tmp / "v3_preds_test.csv", index=False)
    cmd2 = [c if c != str(tmp / "v3_preds.csv") else str(tmp / "v3_preds_test.csv") for c in cmd]
    p = subprocess.run(cmd2, capture_output=True, text=True, cwd=ROOT)
    if p.returncode == 0 or "split != 'val'" not in (p.stdout + p.stderr):
        bad.append(f"CLI with a test row in the predictions: exit {p.returncode}: {(p.stdout + p.stderr)[-300:]}")
    return bad


# ------------------------------------------------------------------------------------------------------------------------------------------------------------ B9
def b9(tmp):
    import eval_loso
    bad = []
    p = pd.DataFrame({"text_hash": list("abcdef"), "split": ["val", "val", "test", "val", "test", "test"], "label": [0, 1, 0, 1, 1, 0], "score": [0.1, 0.9, 0.9, 0.8, 0.2, 0.7]})
    val, n_test = eval_loso.val_only_frame(p)
    if list(val["text_hash"]) != ["a", "b", "d"] or n_test != 3:
        bad.append(f"val_only_frame: {list(val['text_hash'])}, {n_test} test rows")
    if not refuses(eval_loso.val_only_frame, p.assign(split=["val", "dev", "val", "val", "val", "val"])):
        bad.append("an unknown split was accepted")
    if not refuses(gates_v3.g4_numbers, p):
        bad.append("g4_numbers accepted a frame with test rows")
    cached = ROOT / "reports/eval_preds/loso_muril/india_fraud_final/predictions_loso.csv"
    if cached.exists():
        v, nt = eval_loso.val_only_frame(pd.read_csv(cached))
        r = gates_v3.g4_numbers(v)
        got = (round(r["genuine_accuracy"], 3), round(r["scam_recall"], 3), round(r["auroc"], 3), r["n_genuine"], r["n_scam"])
        if got != (0.149, 0.961, 0.828, 195, 155):
            bad.append(f"the v2 fold's val numbers: {got}, plan section 4 says (0.149, 0.961, 0.828, 195, 155)")
        print(f"      v2 fold, val rows only: genuine accuracy {got[0]}, scam recall {got[1]}, AUROC {got[2]}, n {got[3]} / {got[4]} ({nt} test rows dropped unread)")
    else:
        print("      the cached v2 fold is not on this machine: reproduction skipped")
    # the whole --val-only path on an invented fold of the real data (needs data/final)
    if (ROOT / "data/final/messages.csv").exists():
        import test_loso
        df, sha = test_loso.messages()
        d, meta = test_loso.fake_fold(tmp / "fold", "scam_ham_india", df, sha)
        if not refuses(eval_loso.val_only, {"scam_ham_india": d}, df, sha, tmp / "out"):
            bad.append("a fold without mask_version passed --val-only")
        (d / "shield_meta.json").write_text(json.dumps({**meta, "mask_version": "v2"}), encoding="utf-8")
        res = eval_loso.val_only({"scam_ham_india": d}, df, sha, tmp / "out")
        w = pd.read_csv(tmp / "out/scam_ham_india/predictions_loso_val.csv")
        if set(w["split"]) != {"val"} or len(w) != meta["loso_held_out_rows"]["val"] or "scam_ham_india" not in res:
            bad.append(f"--val-only wrote {set(w['split'])}, {len(w)} rows (wanted {meta['loso_held_out_rows']['val']} val rows)")
        if (tmp / "out/scam_ham_india/predictions_loso.csv").exists():
            bad.append("--val-only wrote the full predictions")
    return bad


# ------------------------------------------------------------------------------------------------------------------------------------------------------------ B10
def b10(tmp):
    """Opt-in end to end: a build on the real splits-v2 data with an invented pool, the company-name key and the synthetic UPI families, written to a scratch folder."""
    import subprocess
    if os.environ.get("B0B_E2E") != "1":
        print("      skipped (set B0B_E2E=1: about 8 minutes, 10 GB peak)")
        return []
    bad = []
    m = pd.read_csv(ROOT / "data/final/messages.csv", usecols=["text", "split", "source", "label"])
    pick = lambda split, label=0, k=3: m[(m["split"] == split) & (m["source"] == "uci_sms_spam") & (m["label"] == label) & (m["text"].str.len() > 60)]["text"].iloc[k]
    # planted rows: an exact copy of a train row (same label, then the other label), a near-copy of a test row, of a val row and of a train row
    fx = pool_fixture.make(tmp / "fx", existing={"exact_same:0": pick("train"), "exact_other:1": pick("train", 0, 4), "near_test:0": pick("test"), "near_val:0": pick("val"),
                                                 "near_train:1": pick("train", 1)})
    out = tmp / "build"
    cmd = [sys.executable, str(ROOT / "src/build_text.py"), "--out-dir", str(out), "--mask-version", "v3", "--pool-file", fx["pool"], "--freeze-manifest", fx["manifest"],
           "--real-test-file", fx["real_test"], "--company-name-key", "--synth-upi-collect"]
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    (tmp / "build.log").write_text(p.stdout + p.stderr, encoding="utf-8")
    if os.environ.get("B0B_E2E_KEEP"):   # a folder to keep the build log, build_meta.json and the fixture pool in (the temp folder is deleted)
        keep = Path(os.environ["B0B_E2E_KEEP"])
        keep.mkdir(parents=True, exist_ok=True)
        (keep / "build.log").write_text(p.stdout + p.stderr, encoding="utf-8")
        for n in ("build_meta.json", "messages.csv", "split_map.csv"):
            if (out / n).exists():
                (keep / n).write_bytes((out / n).read_bytes())
        (keep / "pool.csv").write_bytes(Path(fx["pool"]).read_bytes())
    if p.returncode != 0:
        return [f"build failed: {(p.stdout + p.stderr)[-800:]}"]
    meta = json.loads((out / "build_meta.json").read_text(encoding="utf-8"))
    led = meta["ledger"]["pool"]
    msgs = pd.read_csv(out / "messages.csv", keep_default_na=False, low_memory=False)
    pr = msgs[msgs["source"] == "phones_pool"]
    if (pr["split"] == "test").any() or (msgs[msgs["source"] == "synth_upi_collect_v3"]["split"] == "test").any():
        bad.append("a pool / synthetic row is in test")
    if (pr.groupby("real_group")["split"].nunique() > 1).any():
        bad.append("a real_group straddles splits")
    want = {pool.DROP_REAL_TEST: 1, pool.DROP_EXISTING_SAME: 1, pool.DROP_EXISTING_CONFLICT: 1, pool.DROP_POOL_DUP: 1, pool.DROP_POOL_CONFLICT: 2}
    for k, v in want.items():
        if led["drops"].get(k) != v:
            bad.append(f"drop {k!r}: {led['drops'].get(k)}, wanted {v}")
    if led["drops"].get(pool.DROP_TEST_CLUSTER) != 1:
        bad.append(f"the near-duplicate of a test row was not dropped: {led['drops']}")
    print("      ledger:", json.dumps(led, default=str)[:900])
    return bad


CHECKS = [("B1", "company_key: name rule, guards, one/several/none/ambiguous, straddle priority", b1),
          ("B2", "pool.load_pool: mapping, validation, real path refused, manifest required, realguard flag", b2),
          ("B3", "pool.prefilter: each drop reason in order; existing rows never dropped", b3),
          ("B4", "pool.place_fresh: val / train only, balanced per stratum, deterministic, seeded", b4),
          ("B5", "real_group in assert_no_leakage, pool.straddles, finetune.GROUP_KEYS", b5),
          ("B6", "finetune: mask_version required and recorded; real_group and stale build_meta caught in load_data", b6),
          ("B7", "synth_upi_collect: 8 families, label 0, synthetic, 5 val / 3 train, never test, no near-duplicates", b7),
          ("B8", "gates_v3: pass / fail / not measurable for G1-G5, test rows refused, val-only loader, CLI", b8),
          ("B9", "eval_loso --val-only: test rows dropped unread, v2 fold numbers reproduce", b9),
          ("B10", "(opt-in B0B_E2E=1) build_text.py on an invented pool: ledger, 0 straddles, 0 pool rows in test", b10)]


def run():
    out = []
    with tempfile.TemporaryDirectory() as d:
        for cid, title, fn in CHECKS:
            sub = Path(d) / cid
            sub.mkdir()
            try:
                bad = fn(sub)
            except BaseException as e:   # SystemExit included: a script that stops is a failed check
                bad = [f"{type(e).__name__}: {str(e)[:500]}"]
            out.append((cid, title, bad))
    return out


def test_splits_v3_b0b():
    bad = [f"{cid}: {b}" for cid, _, bs in run() for b in bs]
    assert not bad, "\n".join(bad)


if __name__ == "__main__":
    res = run()
    for cid, title, bad in res:
        print(("PASS" if not bad else "FAIL"), cid, title)
        for b in bad:
            print("    ", b.encode("ascii", "backslashreplace").decode()[:600])
    print(f"\n{sum(not b for _, _, b in res)}/{len(res)} passed")
    sys.exit(any(b for _, _, b in res))
