# splits-v3 B0b: pool loader, company key, gates (code only, 2026-10-29)

Nothing under `data/` or `models/` was written, `data/real/` was not read, and no pool file exists yet. Every number below comes from a scratch build into the session's scratch folder
with an **invented** pool (`tests/pool_fixture.py`, random word salad plus a few rows planted as copies of rows in `data/final/messages.csv`). Counts only; no message text.
The fixture build is `B0B_E2E=1 tests/test_splits_v3_b0b.py` check B10: `build_text.py --mask-version v3 --pool-file <fixture> --company-name-key --synth-upi-collect`.

## Default build is unchanged

`build_text.py` with no flag and no pool file (v2 masks) was run twice, once before and once after the last edit, to a scratch folder: `messages.csv` and `split_map.csv`
are byte-identical (`cmp`) to `data/final/` (49,931 rows, SHA-256 of the map `8263df1c...`). `messages.csv` gets the columns `real_group` and `kw_bucket` only when a pool is loaded.

## Fixture build: row ledger (v3 masks, pool, company key, synthetic UPI families)

| step | rows | train | val | test |
|---|---:|---:|---:|---:|
| splits-v2 `messages.csv` | 49,931 | 38,953 | 5,267 | 5,711 |
| v3 masks merge exact duplicates (B0a, `reports/splits_v3_b0a.md`) | -77 | -67 | -1 | -9 |
| = v3 build before B0b | 49,854 | 38,886 | 5,266 | 5,702 |
| company-name key: frozen rows of straddling company groups dropped | -81 | -73 | -8 | 0 |
| pool rows kept (87 in the fixture file, 7 dropped, below) | +80 | +39 | +41 | 0 |
| synthetic UPI-collect families (8 families x 4 languages x 15) | +480 | +180 | +300 | 0 |
| **fixture build** | **50,333** | **39,032** | **5,599** | **5,702** |

Test is the splits-v2 test minus the 9 B0a merges; no pool row and no synthetic row is in it. 0 `real_group`s straddle; the leakage check and the new asserts pass.

**Pool rows dropped (87 in the file):**

| reason | rows |
|---|---:|
| same text as a row of the fixture `real_test_v1` file (realguard hash) | 1 |
| same text as an existing row, same label | 1 |
| same text as an existing row, other label (the pool row goes, never the existing row) | 1 |
| same text as an earlier pool row | 1 |
| same text twice in the pool with different labels (both go) | 2 |
| near-duplicate cluster holds a splits-v2 test row (test stays frozen) | 1 |
| **kept** | **80** |

**Pool placement (80 kept):** 2 rows joined an existing cluster and took its split (1 train, 1 val); 78 rows in 39 fresh clusters were split by `pool.place_fresh` (seed 20261101): 19 clusters to val, 20 to train.
By stratum (label | keyword bucket: val units, train units): 0 delivery 5/5; 0 kyc-bank 7/7; 0 other 4/5; 1 investment 1/1; 1 other 2/2. Rows: val 41 (35 genuine, 6 scam; 20 groups), train 39 (32 genuine, 7 scam; 21 groups).

**Company-name key** (real `fake_job_postings`, 17,880 raw posts, 3,310 without a profile): 111 get a company_key (3,197 name no company, 0 name several, 2 name a company with two profile texts, 14 profile names dropped as common words).
The 20 largest new groups: Point Nine Capital 39, Aker Solutions 21, Appear Here 21, VAM SYSTEMS 13, Casper 4, QB Medical Inc 3, Solutions3 2, Up Group 2, then six single posts.
Straddling frozen rows dropped (the highest split of a company stays: test > val > train): **VAM SYSTEMS 9 train + 1 val (as the plan expects, all fraud)**, and 71 more that the plan did not list:
Point Nine Capital 35 train + 4 val, Appear Here 16 + 2, Solutions3 5 train, Casper 4 train, Up Group 2 train, Cloudreach 1 val, Focus Camera 1 train, AlfaVAD 1 train (all benign). Total 81 = 73 train + 8 val.

**Synthetic UPI-collect families:** none dropped by the test-cluster rule; Jaccard check against the 60 rows of the test family `synth_upi_0_7_1`: 0 near-duplicate pairs; 0 across the 8 families. Val 300 rows (5 families), train 180 (3 families).

## Gates on invented val predictions (`src/gates_v3.py`, `tests/test_splits_v3_b0b.py` B8)

62 POOL-val alert groups (50 + 12 collect-request groups), 300 v2-core rows, 6 synthetic families. A group is flagged at a level if any of its rows is.

| scenario | G1 | G2 | G3 | G4 (report-only) | G5 | verdict |
|---|---|---|---|---|---|---|
| all clean | pass | pass | pass | pass | pass | go |
| G1: 2 of 62 groups at Likely | fail | pass | pass | pass | pass | shipped stays |
| G1: 7 of 62 groups at Suspicious | fail | pass | pass | pass | pass | shipped stays |
| G1: 32 groups only | not measurable | pass | pass | pass | pass | shipped stays |
| G2: v3 misses 1 of 60 core scams (F1 -0.0084 > 0.005) | pass | fail | pass | pass | pass | shipped stays |
| G3: 2 of 12 real collect groups at Likely | fail (they are alert groups too) | pass | fail | pass | pass | shipped stays |
| G3: 3 real, 0 synthetic groups | pass | pass | not measurable | pass | pass | shipped stays |
| G4: no LOSO file | pass | pass | pass | not measurable | pass | go |
| G4: genuine accuracy 0.17 | pass | pass | pass | fail | pass | go |
| G5: v3 flags 5 genuine, baseline 3 | pass | pass | pass | pass | fail | shipped stays |

Any test row in a predictions file, a missing split column, or predictions that do not cover exactly the val rows stops the script. `messages.csv` is read in chunks that keep val rows only.
`eval_loso.py --val-only` on the cached v2 fold reproduces the plan's numbers from its val rows alone (350 rows): genuine accuracy 0.149, scam recall 0.961, AUROC 0.828, 195 / 155.
