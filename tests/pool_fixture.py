import csv, json, os, random, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "..", "src")]
import realguard
from intake_real import POOL_COLS

# An INVENTED pool for splits-v3 B0b (docs/plans/splits_v3.md D-v3.1): nothing here is a real message and nothing under data/ is read or written. make() writes, into a folder,
#   pool.csv                   the POOL_COLS of intake_real.py, label 0/1, provenance real_circulating, is_synthetic False
#   freeze_manifest.json       an empty stand-in (pool.load_pool checks only that the file exists)
#   real_test_v1_fixture.csv   one source_row_hash column: the key of one pool text (so the realguard-hash drop can be seen)
# and returns what a build should do with it. Texts are random word salad (distinct groups never reach Jaccard 0.6 of each other); `existing` lets a build against the real
# data/final/messages.csv plant rows that are exact / near duplicates of given texts (a test row, a val row, a train row).
WORDS = ("account alert bank branch cashback claim code credit debit deliver dispatch due expire fund gift help insured invoice kindly limit link loan lucky "
         "merchant notice offer order parcel payment policy prize profile receipt recharge refund reward saved secure service settle statement suspended ticket "
         "transfer update urgent verify voucher wallet warranty withdraw yearly zonal amber basil cedar dahlia elm fern ginger hazel iris jasmine kale lotus mango "
         "neem olive peony quince rose saffron tulsi umber violet willow yarrow zinnia").split()


def sentence(rng, n=14, prefix=""):
    return prefix + " ".join(rng.choice(WORDS) for _ in range(n))


def row(gid, text, label, kw, size, i, lang="en", src="phone_1", stype="sms"):
    return {"id": f"{gid}_{i}", "text": text, "label": label, "language": lang, "category": "unspecified", "overlap": "False", "source_row_hash": realguard.norm_key(text), "source": src,
            "source_type": stype, "sender_kind": "dlt_header", "group_id": gid, "group_size": size, "label_priority": 1, "kw_bucket": kw, "provenance": "real_circulating", "is_synthetic": "False"}


def make(folder, existing=None, seed=7, n_genuine_kyc=14, n_genuine_delivery=10, n_genuine_other=8, n_scam=6):
    rng = random.Random(seed)
    os.makedirs(folder, exist_ok=True)
    rows, groups = [], {}   # groups: gid -> (label, kw)
    def add(gid, label, kw, n_rows, **kw_):
        size = n_rows + rng.randint(0, 4)
        for i in range(n_rows):
            rows.append(row(gid, sentence(rng, prefix=f"{gid}: "), label, kw, size, i, **kw_))
        groups[gid] = (label, kw)
    for k in range(n_genuine_kyc):
        add(f"g_kyc_{k}", 0, "kyc-bank", rng.randint(1, 3), lang="kn" if k % 5 == 0 else "en")
    for k in range(n_genuine_delivery):
        add(f"g_del_{k}", 0, "delivery", rng.randint(1, 3))
    for k in range(n_genuine_other):
        add(f"g_oth_{k}", 0, "other", rng.randint(1, 3), stype="whatsapp" if k % 4 == 0 else "sms")
    for k in range(n_scam):
        add(f"s_{k}", 1, "investment" if k % 3 == 0 else "other", rng.randint(1, 3))
    expect = {"plain_groups": len(groups)}
    # a group whose text is a "real_test_v1" row: dropped by the realguard hash
    rt_text = sentence(rng, prefix="RTV1: ")
    rows.append(row("g_realtest", rt_text, 0, "kyc-bank", 1, 0))
    groups["g_realtest"] = (0, "kyc-bank")
    with open(os.path.join(folder, "real_test_v1_fixture.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["source_row_hash"])
        w.writerow([realguard.norm_key(rt_text)])
    # the same text in two pool groups (the second row is a duplicate of the first), and in two groups with different labels (both dropped)
    dup = sentence(rng, prefix="DUPP: ")
    rows.append(row("g_dup_a", dup, 0, "other", 1, 0))
    rows.append(row("g_dup_b", dup, 0, "other", 1, 0))
    clash = sentence(rng, prefix="CLSH: ")
    rows.append(row("g_clash_a", clash, 0, "other", 1, 0))
    rows.append(row("g_clash_b", clash, 1, "other", 1, 0))
    for g, (l, k) in (("g_dup_a", (0, "other")), ("g_dup_b", (0, "other")), ("g_clash_a", (0, "other")), ("g_clash_b", (1, "other"))):
        groups[g] = (l, k)
    for name, text in (existing or {}).items():
        # name: "exact<anything>:<label>" (the text as it is), "near<anything>:<label>" (the text with one short word appended); the label after the colon
        kind, _, lab = name.partition(":")
        label = int(lab) if lab else 0
        if kind.startswith("exact"):
            rows.append(row(f"g_{name}", text, label, "other", 1, 0))
        else:   # a near-duplicate: the text with one short word appended (Jaccard well above 0.7 for a message of any length)
            rows.append(row(f"g_{name}", text + " ok", label, "other", 1, 0))
        groups[f"g_{name}"] = (label, "other")
    rng.shuffle(rows)
    with open(os.path.join(folder, "pool.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=POOL_COLS)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(folder, "freeze_manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"version": 0, "note": "invented stand-in: B0b fixture, no real data"}, f)
    return {"pool": os.path.join(folder, "pool.csv"), "manifest": os.path.join(folder, "freeze_manifest.json"), "real_test": os.path.join(folder, "real_test_v1_fixture.csv"),
            "rows": len(rows), "groups": groups, "realtest_text": rt_text}
