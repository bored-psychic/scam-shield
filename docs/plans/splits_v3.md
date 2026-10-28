# splits-v3: one rebuild for the known data gaps, with pre-registered gates

**Status: APPROVED in part (2026-10-27).** Decided by the user: D-v3.1 (50 / 50), D-v3.3 (label), D-v3.4, D-v3.5 (full mask set), D-v3.7
(defer), D-v3.8 (D-a, row added to `docs/decisions/README.md`), G4 report-only, the answers in section 8, D-v3.2 (frozen internal test,
confirmed 2026-10-27), and pushing `split_map.csv` with the `splits-v3` tag on 2 Nov (section 7 item 10). Only D-v3.6 remains: go / no-go on
1 Nov. Code (B0) may be written 28-30 Oct with dry-run counts only, no data
written; nothing else is built yet. The build starts after the real-message freeze (planned 31 Oct); the retrain must finish before 6 Nov. Nothing here reads `data/real/real_test_v1.csv` or any score of it (it does not exist
yet). The gates in section 4 are written **before** any v3 model exists; this file's commit is the proof of the order (git history).

Two numbers in this plan were computed in this session by read-only scratch scripts (outside the repo, nothing written to `data/`): the mask
dry count (decision 5) from `data/final/messages.csv`, counts only, no text printed; and the val-only LOSO numbers (G4) from
`reports/eval_preds/loso_muril/india_fraud_final/predictions_loso.csv`, rows with `split == "val"` only. Build step B1 recomputes the first with
the real code. Every other number is quoted from the file and section given next to it.

## 0. In one screen

| | what v3 does | what v3 leaves alone |
|---|---|---|
| new rows | the phones' POOL (`data/collected/phones/pool.csv`) as source `phones_pool`, real, split train / val by template group | no new test rows of any kind |
| val | gains real Indian genuine bank / UPI / OTP / delivery messages (today: ~0-10 real ones, `docs/decisions/D5_operating_point.md` 1.3) | the 5,267 splits-v2 val messages stay val (re-masked, re-keyed) |
| test | same 5,711 messages as splits-v1 / v2, re-masked | membership frozen |
| masks | one mask set for every source and for app input: intake_real's number masks + name masks; old hashes carried as in splits-v2 | the real TEST file and the intake's own registry |
| grouping | company key for job posts without a profile (VAM SYSTEMS) | the near-dup rule (0.7 / 0.6) |
| optional | a benign UPI-collect family in val/train (synthetic, tagged) if POOL-val has too few real ones; the investment slot only if Phase B is "go" on 1 Nov | promo_gray relabel (deferred), synth_india link-rate fix of existing families (would change test text) |
| model | one MuRIL run (shipped recipe: len 128, no aug, 3 epochs, seed 42) + one LOSO fold (`india_fraud_final`) | no hyper-parameter search, no second attempt against a failed gate |

## 1. Why (the problem, from the files)

- **Out-of-source India failure.** On unseen `india_fraud_final` both heads fail: AUROC drop 0.227 (MuRIL) vs 0.219 (baseline), LOSO AUROC
  0.768 vs 0.766; MuRIL catches 0.964 of scams but passes only 0.116 of genuine messages at 0.5 (`reports/eval_muril_v2.md` section 9, table 3;
  summary point 6). `synth_india`: drop 0.059 vs 0.014. The report calls this "the main argument for real Indian genuine messages in splits-v3".
- **Test false alarms.** MuRIL 112 vs baseline 81; 50 of the 112 are one benign UPI-collect template (`synth_upi_0_7_1`, 15 rows per language,
  test only; the only "collect request" text in train is 7 scam rows); 18 are `VAM SYSTEMS` job posts (company-grouping gap); Kannada AUROC
  0.878 vs 0.930 (`reports/eval_muril_v2.md` summary 3, Reading; section 8 false alarm #1 and #5; BUGS.md "synth_india has no val rows",
  "Company grouping only covers job posts with a profile").
- **PII gaps.** No person-name masking in `pii.py`; account-like numbers glued to letters are not masked (BUGS.md, both entries; both named
  splits-v3 candidates in `reports/splits_v2.md` "Not in this rebuild").
- **Val cannot see the problem.** Val has 0 Hindi / Kannada rows (`reports/splits_v2.md` language table) and almost no real Indian genuine
  alerts (D5 1.3), so no cut-off has ever been checked on them.
- **The POOL exists from 31 Oct.** `--freeze` sends the POOL half of the labelled phone groups to `data/collected/phones/pool.csv`, columns
  `OUT_COLS + provenance, is_synthetic` with `provenance = real_circulating`, `is_synthetic = False` (`src/intake_real.py` docstring (9),
  `POOL_COLS`, `to_row`). Labelled before the freeze (`reports/real_intake_v1.md`, Labelling buckets table): bucket 1: 0 scam / 146 genuine
  groups; bucket 2: 21 / 368; bucket 3: 0 / 150; bucket 4: 4,406 groups unlabelled. 1,039 rows from 685 groups. Kannada `dlt_header` genuine
  rows: 74 (Label counts table). So the POOL should get roughly **330 genuine groups and ~10 scam groups (~520 rows)**: a genuine-heavy set.
  The exact count, per keyword bucket, is in the freeze report's strata table on 31 Oct.

## 2. The eight decisions

Each: **recommendation**, the alternative, what it costs, and what you decide.

### D-v3.1 POOL rows: how they enter `messages.csv`, and train / val

**Recommendation.**
- `build_text.py` reads `data/collected/phones/pool.csv` (never anything under `data/real/`; `realguard.refuse_real_paths` and
  `guard_inputs` already run in the build) and adds each row with: `source = phones_pool`, `provenance = real_circulating`,
  `is_synthetic = False`, `channel = sms` (`whatsapp` for WhatsApp rows), `language` mapped en -> english, hi -> hindi, kn -> kannada,
  mixed -> mixed (Hinglish stays "english": BUGS.md real-intake limit (2)), `category` from the intake, `note = phone_N`, and a new forced-group
  column `real_group = group_id`.
- `real_group` joins `template_family`, `company_key`, `translation_of` as a forced group: in `build_text.py`'s union step, in
  `neardup.assert_no_leakage`'s key list and in `finetune.GROUP_KEYS`. So an intake template group can never straddle splits, and a POOL row
  that is a near-duplicate of an existing row joins that row's cluster (the normal text pass).
- **Split of POOL clusters:** a POOL cluster that joins an existing train cluster is train; one that joins a val cluster is val; one that joins
  a **test** cluster is **dropped and counted** (test membership is frozen, D-v3.2). A fresh POOL cluster is split **50 % val / 50 % train**,
  stratified by label x the intake's `kw_bucket`, the same pair-and-coin rule as `intake_real.grouped_split` (new seed, written to the report),
  so val gets about **165 genuine groups** and train the same.
- Rows keep the intake's cap of <= 3 per group and its `group_size`. Training is unweighted (as today); `group_size` is used only for
  per-group metrics.
- Groups labelled after the freeze (bucket 4, labelled by you between 31 Oct and the build) are POOL rows like the others and follow the same
  rule. Labelling more `kyc-bank` / `delivery` groups before 1 Nov is the cheapest way to make the val gate (G1) measurable.
- Asserts (rule 2): no `real_group` in two splits; no POOL row in test; every POOL row's `text_hash` absent from the real TEST keys (realguard);
  the v3 masks change no POOL text (D-v3.5); the intake's freeze manifest exists (the pool is post-freeze).

**Alternative:** 30 % val / 70 % train. More training signal (~230 genuine groups), but val falls to ~100 groups, below D5's 150 for a 5 %
target (D5 1.4) and only just above the 75 needed to show <= 5 % with zero false alarms.

**Cost:** the train half is small (~165 groups, ~250 rows) against ~38k train rows; it may not move MuRIL much. G1 will show it.

**Decided (user, 2026-10-27):** 50 / 50. The user labels ~100 bucket-4 `kyc-bank` / `delivery` groups on 1 Nov, before the post-freeze
intake rerun.

### D-v3.2 Internal test: frozen or open?

**Recommendation: keep the splits-v2 test membership frozen.** The same 5,711 messages, re-masked with the v3 masks and re-keyed through
the v2-hash lineage (D-v3.5). No POOL row, no synthetic row, no investment row enters test; a new row whose cluster reaches a test row is
dropped and counted (train side), never moved into test.

**What it costs:**
1. The internal test still has **no real Indian genuine alerts**, so it cannot show the v3 goal. That is measured on POOL-val (optimistic: the
   cut-offs are chosen on val too) and, once, on `real_test_v1.csv` at the end (rule 12; not part of this plan).
2. Test is already opened: MuRIL and the baseline were scored on it on 2026-10-21, and it informed D27 (`docs/decisions/README.md` D27: "no
   longer an untouched comparison"). It is a comparison set, not an untouched one.
3. The UPI-collect and VAM SYSTEMS failures were found on test; the v3 fixes are aimed at them, so their test numbers after v3 are a
   follow-up of a known failure, not evidence of generalisation. Say so when reporting.
4. "Same messages, new masks": the shipped model must be re-scored on the v3 text for a like-for-like comparison.
5. A test-only family (synth_india `synth_upi_0_7_1`, the 18 VAM test posts) stays test-only.

**Alternative:** re-split, letting POOL (and new synthetic families) into test. It gives real Indian rows in the internal test but breaks
comparability with every v2 number, takes POOL rows from val / train, and duplicates the job of `real_test_v1.csv`.

**Decided (user, 2026-10-27):** frozen internal test, as recommended.

### D-v3.3 UPI-collect and Indian alert coverage

**Recommendation, in order:**
1. **POOL first.** The benign Indian bank / UPI / OTP / delivery examples come from POOL (`kw_bucket` `kyc-bank` and `delivery`). Nothing
   else counts as real.
2. **UPI collect specifically:** count POOL rows that are collect-request / request-money alerts (regex on `collect request|request money|
   payment request` in the masked text, counted at build step B1). If POOL-val has **>= 10 such groups**, nothing synthetic is added.
3. **Otherwise, one new synthetic benign family** in the `synth_india` style: "a collect request was received, approving it will debit you,
   decline if you do not know the sender", en / hinglish / hi / kn, written fresh, `is_synthetic = True`, `provenance = illustrative`,
   `template_family = synth_upi_collect_benign_v3`, placed by the existing synth_india cell rule extended to val (BUGS.md's "third family per
   cell" fix, for this one cell). It must not be a near-duplicate of the test family (the build drops it if it joins a test cluster; B1 reports
   its Jaccard to `synth_upi_0_7_1`). Reported **separately** from real rows everywhere.
4. **Not used:** `otp_sms_preview` (rejected, `docs/plans/data_acquisition.md` section 4), more translations (D20 / D26: train only, and the
   translation run is not repeatable before 6 Nov), new links in existing synth_india families (would change test text).

**Label (decided by the user, 2026-10-27):** a bank's collect-request PIN warning ("Entering your PIN will DEBIT your account") is
**genuine**. So `synth_upi_0_7_1` keeps label 0, and the BUGS.md question (`reports/eval_muril_v2.md` Hindi / Kannada reading) is closed; the
synthetic family, if built, is labelled 0 too.

**Alternative:** add the synthetic family to train only (no val). Cheaper, but then G3 has no val rows and the only measurement is test.

**Honesty note:** the family is written knowing the test failure. Its val numbers measure the fix on our own wording, not real-world behaviour.

**Rule as planned:** the synthetic family is built only if POOL-val has < 10 real collect-request groups (counted at B1).

### D-v3.4 VAM SYSTEMS / company grouping

**Recommendation: a company-name key for job posts without a profile**, in `build_text.py`'s `fake_job_postings` loader.
1. From every post **with** a profile, take the company name: the leading proper-noun phrase of the profile before " is a / is an / is the /
   , a " (1-4 capitalised tokens, >= 5 characters, not on a stop list such as "We", "Our company", "The company").
2. For each post **without** a profile, search title + description for those names (case-insensitive, word-bounded). Exactly one match ->
   that company's `company_key`; zero or several -> no key (as today).
3. Acceptance test: all 11 profile-less VAM SYSTEMS posts (9 train, 1 val, 1 test; BUGS.md) get the VAM key. B1 reports how many of the 3,082
   profile-less posts get a key (BUGS.md: 15.2 % of them are fraud) and lists the 20 largest new company groups for a by-eye check.
4. **With test frozen:** a company group that now straddles splits keeps its test rows; its train and val rows are **dropped and counted**
   (the splits-v2 precedent of dropping the train side, `reports/splits_v2.md` mask-join row). For VAM that drops 9 train + 1 val fraud posts.

**Alternative:** a lower near-dup threshold (0.6 everywhere) for `fake_job_postings`. BUGS.md ("Template reuse...") says it merges more
scam / benign posts and does not target the name.

**Cost:** train loses some fraud job posts (`fake_job_postings` scam recall is already 0.18-0.20: `reports/eval_muril_v2.md` section 3).

**Decided (user, 2026-10-27):** approved as recommended (name key; straddling train / val rows dropped and counted).

### D-v3.5 Name masking + glued account numbers in `pii.py`

**Recommendation: one mask set for every source and for app input**, reusing `intake_real`'s approach, because the POOL text is already masked
by `intake_real.mask` (pii.py masks **plus** card, OTP, account-tail, `XX`-tail, every 9+ digit run, names). If only POOL rows carried
`<OTP>` / `<NAME>` / tail masks, the model would learn "these tokens = genuine" (pii.py's own comment: "same tokens for every source so
masking itself isn't a label signal").

- **Numbers:** add intake's `CARD_RX`, `OTP_RX`, `OTP_BEFORE_RX`, `ACCT_TAIL_RX`, `XX_TAIL_RX` and `LONG_RX` (any 9+ digit run, glued or
  not, -> `<ACCOUNT>`) to `pii.MASKS`, with intake's link protection. This closes the glued-number gap by over-masking (rule 5's safe side;
  BUGS.md said a fix "needs a rule that tells an account number from a reference number": this plan chooses not to tell them apart).
- **Names:** intake's greeting rule (`GREETING_NAME_RX`, a word after hey / hi / dear / ... that is not in `NOT_NAMES` -> `<NAME>`) on every
  source; intake's ALL-CAPS payer rule (`CAPS_NAME_RX`, "from RENU R ...") on SMS-type channels only (sms, whatsapp, telegram, app, chat,
  email_or_sms, other), because on job posts and call transcripts it mostly hits headings (918 and 502 hits below).
- **App input:** `textprep.model_text(mask_pii=True)` uses the same masks, so train and serve agree (rule 11). **The shipped bundle was trained
  on the v2 masks**, so the masks the app applies must follow the bundle: the bundle records `mask_version`, and the app uses `MASKS_V2` for
  the shipped bundle and the v3 set for a v3 bundle. Without this the shipped model would silently see `<OTP>` / `<NAME>` in the app.
- **Freeze two snapshots first:** `pii.MASKS_V2` (today's masks, for the hash lineage) and `pii.MASKS_INTAKE_V1` (the set `intake_real`
  uses, which today is built from `pii.MASKS` by reference). `intake_real` must keep `MASKS_INTAKE_V1` after the freeze: changing its masks
  would change its digit-collapsed keys and could stop a TEST group's later messages from being recognised (its registry is keyed on masked
  text).

**How many stored rows change (dry count, this session, intake regexes without link protection, an estimate; B1 gives the exact number):**

| | train | val | test | all |
|---|---:|---:|---:|---:|
| number masks (OTP, card / tail, 9+ digits) | 2,472 | 303 | 419 | 3,194 |
| greeting names (only names seen after a greeting in >= 3 rows, 203 names) | 2,003 | 398 | 253 | 2,654 |
| greeting names, any non-common word (the rule above, no threshold) | 2,583 | 471 | 355 | 3,409 |
| ALL-CAPS payer rule, all channels | 1,659 | 215 | 279 | 2,153 |
| any of number / greeting (>= 3) / caps | 5,686 | 846 | 845 | **7,377 (14.8 % of 49,931)** |

By source (any): `fake_job_postings` 3,603 (2,073 of them 9+ digit ids), `phishing_email` 1,542, `scam_dialogue` 700, `india_fraud_final` 669,
`translated_indic` 303, `synth_india` 258, `uci_sms_spam` 169, `scam_ham_india` 85. ALL-CAPS hits by channel: job_post 918, email 571, call
502, sms 94. So expect **several thousand re-keyed rows**, against 81 at splits-v2 (`reports/splits_v2.md` first table).

**Old-mask hash handling (as splits-v2):** `build_text.py` computes each row's hash under `MASKS_V2` (`hash_v2`) and finds its frozen split
through `split_map.csv` (splits-v2 keys) by `text_hash`, else by `hash_v2`; the `MASKS_V1` path is retired (the v2 map has no v1 keys). Asserts:
no splits-v2 row lost, none moves split. A new-mask join between a train row and a val / test row drops the **train** row (counted, splits-v2
rule); a join between a val and a test row **stops the build** for a decision (never silently dropped). The build's "the masks change no
translation" assert becomes "the v3 masks change a translation only where they change its English parent the same way".

**Alternative:** mask names only in SMS-type sources and leave the 9+ digit ids in job posts alone. ~2,000 fewer re-keyed rows, but two mask
sets again, and rule 5 covers every source.

**Decided (user, 2026-10-27):** the full mask set for every source (the ALL-CAPS payer rule stays limited to SMS-type channels, as above).

### D-v3.6 Investment slot

Phase B go / no-go is decided on **1 Nov** (`docs/plans/investment_scams.md` section 6: all three conditions; condition 2, >= 40 investment-scam
and >= 40 genuine investment rows that can sit in val, is "the blocker").

**If "go":** the slot holds, all through the D-v3.1 rule: POOL groups with `kw_bucket = investment` (labelled by you); collected public
`real_circulating` investment scams from `data/collected/` if D-b (`data_acquisition.md` section 10) is "yes" (reported apart); synthetic
investment templates **train only** (rule 4, investment plan step 3); the 39 likely mislabels relabelled under the labelling policy (step 1,
which must be decided by then; the 84 uncertain ones follow the policy). Gate G-inv (section 4) is added. `data/probe/investment_v1.csv`
stays PROBE-ONLY (realguard refuses it).

**If "no-go" (expected: the intake found 40 investment / crypto / task keyword groups among 5,103, `reports/real_intake_v1.md`, and a
keyword is not a label):** the build reserves nothing. Genuine broker / bank alerts that arrive in POOL anyway are ingested like any POOL row and
reported as their own `kw_bucket` in val. No relabel, no synthetic investment templates, Phase A rules unchanged; the gap goes to BUGS.md
(investment plan section 6, last paragraph).

**Note:** the investment plan's stop rule allows collecting until about 8 Nov (`data_acquisition.md` section 9, stop condition 2). A 1 Nov
"no-go" for v3 does not end Phase B; it moves to a later rebuild.

**You decide:** the go / no-go on 1 Nov; the labelling policy only if "go".

### D-v3.7 promo_gray (D5b)

**Recommendation: defer.** D5b ("relabel in splits-v2") was not done in splits-v2 (`reports/splits_v2.md` "Not in this rebuild"). Doing it
now changes labels on val rows (D5 1.1: 470 `scam_ham_india` promo rows of 40-160 characters across splits), which breaks G2's comparison with
the shipped model on the splits-v2 val; it needs the tagger of D5 section 4 (`src/legit_tiers.py`, not built) and its 100-row spot-check; and
a third class has no training design (drop, 0 or 1?). None of that fits 1-6 Nov.

**Alternative:** a tag-only `scam_tier` column (no label change), so val reports promo_gray recall apart. Costs a session for the tagger and
its spot-check; not on the critical path.

**Decided (user, 2026-10-27):** deferred, as recommended.

### D-v3.8 D-a: recorded as decided

**D-a (phones for training vs the test set), decided 2026-10-27, built in `src/intake_real.py`:** the same two phones serve both, split once,
50 / 50 by template group, stratified by label x keyword bucket (seed 20261026), groups with any near-duplicate pair between them moved
together; the TEST half is `data/real/real_test_v1.csv` (frozen, realguard), the POOL half is `data/collected/phones/pool.csv` (training and
validation); after the freeze every new message of a TEST group or near-duplicate of a TEST message is dropped from the pool. This is option
(3) of `data_acquisition.md` section 10 (a template-group split on the same phones), not that plan's recommended option (1) (different
people), chosen because no other people's phones were available. Its cost: TEST and POOL share senders, so a bank whose different templates
fall on both sides gives the final real-test numbers a mild optimistic bias; the near-duplicate rules remove copies, not shared style.
**Consent:** both phone owners have consented to their masked messages being used for training, validation and the test set, and to the
masked training data going to the private Kaggle dataset (user, 2026-10-27). Approved by the user 2026-10-27; row D-a in
`docs/decisions/README.md`.

## 3. Shortcuts to flag at sanity (rule 3)

- `phones_pool` is ~97 % genuine (about 10 scam groups of ~340), so "looks like a real Indian DLT SMS" may become "genuine". That is partly the
  lesson we want, and exactly what a scam copying a bank format exploits. Report POOL-val scam recall (few groups: report the count, not a rate).
- `<OTP>` will sit mostly in genuine OTP alerts (the OTP mask hits India / synthetic / translated benign alerts, decision 5 table). Report the
  `<OTP>` cue AUROC as `text_shortcuts.py` does for amounts.
- Length: real SMS are short; job posts are long. Report the length-only AUROC on val with and without POOL.
- Kannada: POOL-val may hold the first real Kannada val rows (all genuine, `dlt_header`). Report their false-alarm count; D5's language cap
  (text model alone at most Suspicious in hi / kn / Hinglish until >= 150 real-dev templates) stays.

## 4. Success criteria (pre-registered; measured on val only before test)

**Setting.** One v3 MuRIL bundle, trained with the shipped recipe (`finetune.LOSO_REFERENCE` settings: MuRIL, len 128, 3 epochs, batch 16,
lr 2e-5, seed 42, no aug), best epoch on v3 val F1@0.5, temperature and cut-offs fitted on v3 val by `calibrate_text_head.py` with the D27 rule
(Suspicious = highest cut-off with val scam recall >= 0.95; Likely = val max F1). The **shipped bundle** (`muril_len128_20261021T135255Z`) is
re-scored on the Mac on the same v3 text for every comparison. Text head alone unless stated; the offline router verdict (`live=False`) is
reported beside it, never gated.

**Val subsets.**
- *v2-core val:* the 5,267 splits-v2 val messages still in val after v3 (by v2-hash lineage), minus the counted drops of D-v3.4 / D-v3.5.
- *POOL-val alerts:* POOL-val genuine rows with `kw_bucket` in {`kyc-bank`, `delivery`}, counted per template group (`real_group`).
- *UPI-collect proxy:* POOL-val collect-request alerts (real) and the synthetic family's val rows (D-v3.3), reported separately.

| gate | measured on | pass if | shipped model, for reference | blocking |
|---|---|---|---|---|
| **G1 Indian genuine alerts** | POOL-val alerts, per group, at the v3 cut-offs | n >= 39 groups (`data_acquisition.md` section 2, +-15 points) **and** at least Suspicious <= 10 % of groups (D5 ship gate) **and** Likely scam <= 2 % of groups. Report Wilson 95 % upper bounds and D5's targets (5 % / 1 %) | re-scored on the same rows, reported | yes |
| **G2 no regression** | v2-core val, F1 at each model's own val-chosen Likely cut-off | v3 >= shipped (re-scored on v3 text) **- 0.005** (the D27 rule's tolerance: 0.946 = 0.951 - 0.005). Shipped on v2 text: 0.9514 (`reports/eval_muril_v2.md` section 1) | 0.9514 | yes |
| **G3 UPI collect** | UPI-collect proxy, per group | Likely scam <= 10 % of groups, real and synthetic each (whichever exists; if neither has >= 5 groups, G3 is "not measurable" and blocks) | re-scored, reported | yes |
| **G4 LOSO `india_fraud_final`** | one fold, v3 data, cluster-strict rule; **its 350 val rows only** (195 genuine / 155 scam) | "improved" = genuine accuracy at 0.5 >= 0.30 **and** val AUROC >= 0.828. v2 fold, same rows: genuine accuracy 0.149, scam recall 0.961, val AUROC 0.828 (computed from the cached `predictions_loso.csv`, val rows only) | 0.149 / 0.828 | **no** (report-only, decided by the user 2026-10-27) |
| **G5 flag policy** | v2-core val genuine, at least Suspicious | v3 MuRIL <= the v3 TF-IDF baseline refit (D27 Suspicious flag policy) | MuRIL 1.56 % vs baseline 4.06 % on v2 (D27) | yes |
| **G-inv** (only if Phase B "go") | investment val rows, per group | genuine at least Suspicious <= 10 % **and** scam recall >= 0.80 (investment plan section 6, condition 1 thresholds) | reported | yes |

Also reported on val, not gated: overall and real-only F1 / AUROC on all v3 val; per source; Kannada / Hindi POOL-val genuine false alarms;
POOL-val scam count caught; the shortcut checks of section 3.

**Stop rule.** One training run. If any blocking gate fails, the shipped bundle stays in the app and the result is written up. A second
Kaggle run is allowed only for a technical failure (crash, OOM, hash mismatch, wrong settings), never with changed settings to pass a gate.

**Fallback (deadline).** If the blocking gates are not met (failed, or not measurable) by **5 Nov**, the shipped MuRIL
(`muril_len128_20261021T135255Z`) stays in the app, and the v3 report says so in its first line, with the gate table as it stands.

**Read on test, once, after G1, G2, G3, G5 (and G-inv) pass** (internal test = the frozen splits-v2 messages on v3 text; v3 MuRIL, shipped MuRIL
and the v3 baseline refit, each with its own val cut-offs, through `eval_text_head.py`):
- overall and real-only F1, precision, recall, AUROC (shipped on v2 text: 0.918 / 0.906, AUROC 0.986; `reports/eval_muril_v2.md` section 2);
- false alarms (112), of which the UPI-collect family `synth_upi_0_7_1` (50 of 60) and VAM SYSTEMS (18) (summary 3; Reading);
- per source and per language, incl. Kannada AUROC (0.878; baseline 0.930);
- held-out attacks (`messages_adv_test.csv`, regenerated on the re-masked test parents; Likely recall 0.941 on v2);
- the LOSO fold's 310 `india_fraud_final` test rows together with its val rows (the section 9 comparison: genuine accuracy 0.116, AUROC 0.768).

**One pre-registered veto:** if v3 internal test F1 is more than 0.02 below the shipped model's on the same v3 text, the app is not switched,
even with all gates passed; it is written up. No other test number can change the decision.

**Final real-message test (decided by the user, 2026-10-27):** `src/eval_real.py --final` runs **once, ~5 Nov, on whichever model ships**
(the v3 bundle if the gates pass and the veto does not fire, else the shipped MuRIL), after the switch decision and never before it (rule 12,
hard rule 1; one line in `reports/real_eval_ledger.md`). Its numbers change nothing: no cut-off, no model choice.

## 5. Build order and timeline

Model and effort from the CLAUDE.md table ("anything touching splits, leakage, evaluation, calibration, augmentation or GPU training" = Sonnet
high; reruns = Haiku low; interpreting sanity, decisions and reviews = Opus high). Each high-effort step ends with a fresh-session review of the
diff for leakage and split mistakes (CLAUDE.md).

| date | step | model / effort | output / check |
|---|---|---|---|
| 28-30 Oct (before the freeze; code only, no data written) | **B0 code.** `pii.py` (v3 masks, `MASKS_V2`, `MASKS_INTAKE_V1`, `mask_version`); `intake_real.py` pinned to `MASKS_INTAKE_V1`; app mask follows the bundle's `mask_version`; `build_text.py` POOL loader + `real_group` + v2-hash lineage + company-name key + drop-and-count rules; `neardup` / `finetune.GROUP_KEYS` + `real_group`; the gate script (`src/gates_v3.py`: val only, asserts `split == "val"`, writes `reports/gates_v3.md`); `eval_loso.py --val-only`. Tests for each. Dry runs on splits-v2 data print counts only | Sonnet high | pytest green on both heads; dry-run counts |
| 31 Oct | Real-message freeze (`intake_real.py --freeze --allow-unlabelled`), hash line in CLAUDE.md | you | `real_test_v1.csv` hash, `pool.csv` |
| 1 Nov AM | Label ~100 bucket-4 `kyc-bank` / `delivery` groups, then `intake_real.py` rerun (post mode: pool only) | you; Haiku low to rerun | pool counts per stratum |
| 1 Nov AM | Phase B go / no-go; decisions D-v3.1-8 recorded in `docs/decisions/README.md` | Opus high | go / no-go line |
| 1 Nov PM | **B1** `build_text.py` (~7 min, 10 GB peak) -> `split_audit.py` -> `augment.py` -> `baseline.py` -> `sanity_checks.py`; row ledger (section 6) | Sonnet high (build), Haiku low (reruns) | 0 audit violations; every row accounted for |
| 2 Nov AM | **Review** of the B0 / B1 diff and the split audit by a fresh session; interpret sanity (shortcuts, section 3) | Opus high | go for freeze |
| 2 Nov AM | **Freeze splits-v3:** `split_map.csv` `git add -f`, tag `splits-v3`; new SHA-256 into `finetune.SPLIT_MAP_SHA256`, the notebook's `EXPECTED_SPLIT_MAP_SHA256` and CLAUDE.md; notebook `LOSO_SOURCES = ["india_fraud_final"]`, `MAX_LENS = [128]`, `USE_AUG = False`; commit; **push code + `split_map.csv` (hashes only) + the `splits-v3` tag** (approved for 2 Nov; the notebook clones from GitHub; `git push` then `git push origin splits-v3`) | Sonnet high | tag, hashes in three places agree |
| 2 Nov PM | New **private** Kaggle dataset version, masked data only (`split_map.csv`, `messages.csv`, `messages_adv_test.csv`, `messages_aug.csv` at the root; approved, both phone owners consented); smoke run; full run + LOSO fold (~23 min each, `reports/eval_muril_v2.md` section 9 training s) | you (upload); Sonnet high | bundle + fold, `split_map_sha256` = v3 |
| 3 Nov | Copy back; `calibrate_text_head.py` on v3 val; re-score the shipped bundle on v3 val; `gates_v3.py` -> G1-G5 | Sonnet high | `reports/gates_v3.md` (val only) |
| 4 Nov | If the gates pass: `eval_text_head.py` (test once) + `eval_loso.py` (full); write-up; app switch as decision D28 (demo / test locks per head, `frontend/scripts/dump_fixture.py`). If they fail: write-up, shipped bundle stays | Sonnet high; Opus high for the write-up | `reports/eval_muril_v3.md` |
| 5 Nov | Buffer (a technical re-run only, stop rule). Fallback: gates not met by today -> the shipped MuRIL stays, the report says so. Then `eval_real.py --final`, once, on whichever model ships | Sonnet high | `reports/real_eval_ledger.md` line |
| 6 Nov | Deliver | | |

**B0a (versioned masks) done 2026-10-28:** `reports/splits_v3_b0a.md`, commit "splits-v3 B0a: versioned masks". Open before B1: (1) the OTP rule gap (English "OTP for X is 123456" is not masked, its translation is; report section 3.1), (2) `finetune.py` / the notebook must write `mask_version` into `shield_meta.json`, (3) the `email_or_sms` deviation from the SMS-type channel list. B0b (POOL loader, `real_group`, company key, gates) is not started.

**Fallback if B0 is not done by 31 Oct:** the timeline does not fit. Cut in this order: the synthetic UPI family (G3 then reads only real
POOL rows, or is "not measurable" and the run cannot ship), the company-name key (VAM stays a known gap), then the ALL-CAPS name rule.
Never cut the mask harmonisation (D-v3.5): without it POOL tokens are a label shortcut.

## 6. Row ledger to expect (exact numbers at B1)

`messages.csv` 49,931 (splits-v2) -> 49,931 - (train rows dropped by new-mask joins) - (train / val rows of straddling company groups, VAM: 10)
- (POOL rows whose cluster reaches test) + (POOL rows, about 520 at freeze plus any labelled later) + (synthetic UPI family, if built) +
(investment rows, if "go"). Val gains ~half the POOL; test stays 5,711 messages (re-keyed). `messages_aug.csv` and `messages_adv_test.csv`
are regenerated (`augment.py`, seeded per (split, attack)); POOL train scam rows become augmentation parents. The app's
`text_baseline.joblib` is not refit (a separate decision, as at splits-v2).

## 7. Conflicts and tensions with CLAUDE.md and the other plans

1. **"UPI-collect template false alarms" as a gate.** That template is test-only (BUGS.md, synth_india entry). Gating on it would choose a
   model on test (hard rule 1's spirit for the internal test; every evaluation reads test once, after the cut-offs). Here G3 gates on a
   **val proxy** (D-v3.3) and the template's own count is read on test once, after.
2. **"Rerun LOSO for india_fraud_final" as a gate.** A LOSO fold scores the source's val **and test** rows (`reports/eval_muril_v2.md`
   section 9). G4 reads the 350 val rows only; the 660-row number is read with the test step.
3. **Retrain before 6 Nov** contradicts `docs/plans/data_acquisition.md` section 9 ("No retrain before 6 Nov: splits-v3 + Kaggle + evaluation
   is 6-8 sessions and does not fit") and the investment plan's estimate (6-8 sessions). This plan fits only with the B0 code written before
   the freeze, one training run and no re-runs. Not a CLAUDE.md rule, but the earlier plan said the opposite.
4. **Phase B go / no-go on 1 Nov** is a week before the date in `data_acquisition.md` section 9 (about 8 Nov).
5. **Real phone SMS on Kaggle.** CLAUDE.md makes Kaggle the main GPU route with a private dataset; the dataset has so far held public corpora
   only. v3's `messages.csv` holds the phones' messages (masked, rule 5). `data_acquisition.md` section 6 says `data/collected/` must never be
   pushed to git and contributed exports need each contributor's consent. **Resolved (user, 2026-10-27):** both phone owners consented; the
   masked data goes to the private Kaggle dataset only; `data/collected/` and `data/real/` never go to git.
6. **"Nothing reads real_test_v1.csv."** True for this plan, with two designed exceptions: `realguard` reads its `source_row_hash` column (keys
   only, the rule 12 tripwire), and `intake_real.py`'s post-freeze rerun drops POOL candidates that are near-duplicates of TEST messages. Neither
   reads a score.
7. **Rule 11 and the shipped bundle.** Changing `pii.py` changes what the app feeds the shipped MuRIL. D-v3.5 ties the mask set to the bundle's
   `mask_version`; without it the app's current model would change silently on 1 Nov.
8. **Rule 10.** All upstream changes (masks, POOL, company key, optional families) land in one `build_text.py` run before augment / baseline /
   training; nothing downstream runs on a half-built v3.
9. **Rule 4.** The synthetic UPI family and any investment templates are `is_synthetic = True` and reported apart; real-only evaluation
   excludes them.
10. **"Push code only" vs `split_map.csv`.** CLAUDE.md says `split_map.csv` is committed to git (force-added) and tagged for every splits
    version. In v3 it also holds the text hashes (md5 of masked text, no text) of the POOL rows. **Resolved (user, 2026-10-27):** push
    `split_map.csv` with the `splits-v3` tag on 2 Nov (hashes only, private repo), as for v1 / v2. No message text goes to git.

## 8. Questions answered (user, 2026-10-27)

1. POOL val / train share: **50 / 50**.
2. Bucket-4 labelling: **yes, ~100 `kyc-bank` / `delivery` groups on 1 Nov.**
3. A bank's collect-request PIN warning is **genuine** (label 0).
4. **Private Kaggle dataset, masked data only; both phone owners have consented.**
5. `eval_real.py --final` runs **once, ~5 Nov, on whichever model ships.**
6. G4 is **report-only.**
7. **Full mask set for every source.**
8. B0 code on 28-30 Oct: **yes, dry-run counts only, no data written.**
9. Push on 2 Nov: **yes, code plus `split_map.csv` (hashes only) with the `splits-v3` tag**; no data files, no message text.
10. Internal test: **frozen** (D-v3.2), confirmed.

Still open: D-v3.6 go / no-go on 1 Nov.

## Sources read for this plan

`reports/eval_muril_v2.md` (summary, Reading, sections 1-3, 8, 9); `BUGS.md` (Open: name masking, glued numbers, company grouping, synth_india,
real intake limits, investment); `docs/plans/investment_scams.md` (sections 1, 5, 6); `docs/plans/data_acquisition.md` (sections 1, 2, 4, 6, 9,
10); `docs/decisions/README.md` (D5, D5b, D20, D22 val table, D26, D27); `docs/decisions/D5_operating_point.md` (sections 1.1-1.4, 3, 4);
`reports/splits_v2.md`; `reports/real_intake_v1.md` (counts only); `src/intake_real.py` (docstring, constants, `mask`, `grouped_split`,
`to_row`); `src/pii.py`; `src/build_text.py` (loaders, masking, hash lineage, clustering, split rule); `src/realguard.py`; `src/finetune.py`
(`SPLIT_MAP_SHA256`, `GROUP_KEYS`, `LOSO_REFERENCE`); `notebooks/kaggle_finetune.ipynb` (`EXPECTED_SPLIT_MAP_SHA256`); CLAUDE.md.
