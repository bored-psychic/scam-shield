# splits-v3 B0a: versioned masks (dry run, 2026-10-28)

Code only (`docs/plans/splits_v3.md` D-v3.5). No file under `data/` or `models/` was written, no split file touched, no model retrained. Both builds below wrote
to a scratch folder with `build_text.py --out-dir`. Counts only; no val / test text was printed. Examples are from **train** rows.

## 1. v2 is unchanged

`build_text.py` (default `--mask-version v2`) rebuilt on the current inputs gives a `messages.csv` and a `split_map.csv` that are **byte-identical** (`cmp`) to the
frozen splits-v2 files (49,931 rows, SHA-256 `8263df1c...`). `tests/test_masks.py` M1-M3 also freeze `MASKS_V2` and `MASKS_INTAKE_V1` (140 golden strings made with
the pre-change code, a digest over `MASKS_V2` on every `messages.csv` row, a digest of the intake patterns and word lists).

Two things about the build script itself, both there before this change (the unmodified HEAD script fails the same way on the same files):
- Its check `fixed.isna() == is_tr` predates splits-v2: the v2 map already holds the 1,142 translations, so it could not rebuild against the v2 map. It now allows
  frozen translations.
- The one `phishing_email` train row splits-v2 dropped (a v2-mask twin of a test row) is not in the v2 map, so it came back as a "new" row. A new row whose cluster
  holds a frozen test row is now dropped and counted (the D-v3.2 rule), so the v2 rebuild stays identical. Any other new row still stops the build (the POOL loader is B1).

## 2. v3 dry run (`build_text.py --mask-version v3 --report-translation-drift`)

| | train | val | test | all |
|---|---:|---:|---:|---:|
| v2 `messages.csv` | 38,953 | 5,267 | 5,711 | 49,931 |
| v3 build | 38,889 | 5,266 | 5,702 | **49,857** |
| difference | -64 | -1 | -9 | -74 |
| rows whose text changes (v3 vs v2 masks) = rows whose `text_hash` changes | 3,755 | 467 | 639 | **4,861 (9.7 %)** |
| rows kept in their split (re-keyed, same split) | 3,755 | 467 | 639 | 4,861 |
| rows that change split | 0 | 0 | 0 | 0 |

The plan estimated ~7,377 rows (14.8 %): 4,861 is lower because the estimate counted the ALL-CAPS rule on every channel (2,153 rows; v3 runs it on SMS-type
channels only: 28 rows) and had no stoplists. Split-straddle and near-duplicate checks: **0 violations** (`neardup.assert_no_leakage` passed on the v3 build:
no cluster / family / company straddles splits, no cross-split pair at Jaccard >= 0.7 on raw or normalised text). Re-keying created these cross-split joins, all resolved by the rules in the plan:
2 frozen train `scam_ham_india` rows are the same text as a val / test row under v3 (train rows dropped), 1 train `scam_ham_india` row's cluster now reaches a val / test row (dropped); no val-test join (that would stop the build).

Where the 74 rows went (rows merged as exact duplicates under the v3 masks, because a name or id no longer tells them apart, plus the 3 rows dropped above): `synth_india` -43 (test -4, train -39), `translated_indic` -18 (train),
`india_fraud_final` -5 (test -4), `scam_ham_india` -3 (the 3 above), `phishing_email` -4 (val -1), `uci_sms_spam` -1 (test). Test loses 9 rows that are copies of other test rows. No source gains a row.

Rows changed by each v3 step, by source (a row can fire several; `any` = text differs from v2; link-phone and the final v2 sweep mostly redo v2 and are left out of the per-type columns, the sweep never fired):

| source | any | greeting name | ALL-CAPS name | card | OTP | account tail | 9+ digits |
|---|---:|---:|---:|---:|---:|---:|---:|
| fake_job_postings | 2,163 | 98 | 0 | 0 | 2 | 3 | 2,073 |
| phishing_email | 1,220 | 1,048 | 0 | 5 | 50 | 29 | 104 |
| india_fraud_final | 415 | 39 | 4 | 0 | 97 | 208 | 93 |
| translated_indic | 285 | 0 | 0 | 0 | 66 | 204 | 42 |
| synth_india | 206 | 48 | 5 | 0 | 94 | 59 | 0 |
| scam_dialogue | 205 | 184 | 0 | 0 | 1 | 20 | 4 |
| uci_sms_spam | 200 | 145 | 12 | 0 | 19 | 0 | 25 |
| scam_ham_india | 85 | 51 | 7 | 0 | 5 | 2 | 2 |
| ealvaradob_phishing | 29 | 13 | 0 | 0 | 8 | 0 | 9 |
| hinglish_conversations | 29 | 29 | 0 | 0 | 0 | 0 | 0 |
| cmu_hinglish_dog | 24 | 24 | 0 | 0 | 0 | 0 | 0 |
| web_scams | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

By split (rows that changed): greeting name 1,303 / 163 / 213 (train / val / test), ALL-CAPS name 17 / 2 / 9, card 5 / 0 / 0, OTP 240 / 40 / 62, account tail 407 / 14 / 104, 9+ digits 1,810 / 258 / 244.

## 3. Findings that need a decision

1. **The intake's OTP rule misses the commonest English form.** `OTP_RX` needs the number within a few characters of the keyword, so "Your OTP for Grapevine is 919157"
   stays unmasked while the Hindi / Kannada translation "... OTP 919157 है" is masked. The plan's own build check ("v3 masks change a translation only where they change its English parent
   the same way") therefore **fails**: 38 of 303 changed translations before the dedupe (285 after it) (33 `<OTP>`-only with an unchanged parent, 3 `acct_tail`+`otp`, 2 `link_phone`+`otp`). Run with
   `--report-translation-drift` (report only; without it the build stops). Left as the plan wrote it, `<OTP>` would then appear in
   Hindi / Kannada rows and in few English OTP SMS: a language shortcut (rule 3). Fix to choose: widen the v3 OTP rule to "otp ... is NNNN" (a v3-only change, the intake stays pinned; but then v3 would also change
   a POOL row the intake left alone, so D-v3.1's "v3 masks change no POOL text" assert has to become "v3 is idempotent on v3 output"), or leave the translations' `<OTP>` and accept the shortcut.
2. **A channel-dependent mask breaks the dedupe.** The first dry run kept 417 `ealvaradob_phishing` rows (+43 val, +40 test) that v2 had merged with their `phishing_email` originals, because the
   ALL-CAPS rule (SMS-type channels, `email_or_sms` included per the plan) masked the copy and not the original. Changed: (a) `email_or_sms` is **not** an SMS-type channel for the
   ALL-CAPS rule (deviation from D-v3.5's list), (b) `build_text.py` deduplicates and detects label conflicts on the v2 hash first, so v3 never un-merges what v2 merged. Result above: no source gains a row.
3. **The ALL-CAPS payer rule is weak.** 108 hits on 10,767 train SMS-type rows with the plan's rule, about 80 % organisations, places and terms (AJIO, BESCOM, CBI, VPA, SMS, MUMBAI). After a hand-made
   stoplist (`pii.CAPS_NOT_NAMES_V3`, by category, from train hits) about 20 train hits remain, of which about 7 are people (`SHRI RAM` x4, MANEESHA, TANUSHA, DEEPAK). It only ever masks less than the intake
   rule. Its small yield (28 rows of 49,857) means it matters little either way; "from RENU R KUMAR" is still only masked up to "RENU" (the rule needs 3-letter words: an initial ends the match).
4. **`finetune.py` / the notebook do not write `mask_version` into `shield_meta.json` yet.** A v3 bundle without it is read by the app as v2 (the masks would be wrong on input). B1 must add it (not in this step's instructions).

## 4. Rules that over-mask (3 masked examples each, train rows only)

| rule | what it masks that is not personal | examples (masked form) |
|---|---|---|
| greeting name | brands and aliases after Mr; the Hinglish particle "hi" ("only") | `... including Mr. <NAME>®, George Brazil®, and Mr. <NAME>®.` / `From: "Mr. <NAME>" To: Sent: Monday` / `are yaar, 5% hi <NAME> hai.` (53 benign Hinglish chat rows get a greeting mask, some of them on this particle) |
| ALL-CAPS name | organisations the stoplist does not know; double token when "Shri" is also a greeting title | `I NEED A BREAK FROM <NAME> 4 HRS LAST NITE` / `This message is brought to you by <NAME> Ltd.` / `via IMPS from <NAME> <NAME> (Ref: <PHONE>)` |
| OTP | prize claim codes and postal codes | `quoting claim code <OTP> standard rates apply` (14 train `uci_sms_spam` rows: a scam cue now reads as an OTP) / `Zip Code <OTP>` / `post code <OTP>` |
| 9+ digit run, account tail | tracking, GST and booking references (not personal; the plan chose to over-mask) | `Article No RD<ACCOUNT>IN booked at New Delhi GPO` / `(ARN AA<ACCOUNT>)` / `#AWB-CC<ACCOUNT>` |

Also noted: a bare `****1234` (no word boundary before `*`) and a name followed by initials stay as they are in the intake; v3 equals the intake there on purpose (so POOL text is unchanged).

## 5. What changed in the code

- `src/pii.py`: `MASKS_V2` ("v2", today's patterns; `MASKS` is its pattern list), `MASKS_INTAKE_V1` ("intake-v1", `intake_real.mask` moved here), `MASKS_V3` ("v3"); `mask_set(version)`, `mask_text(text, version=, channel=)` (default v2),
  `MASK_VERSIONS`. `UPI_HANDLES` is sorted longest first, ties alphabetical (it was `key=len`, whose order among equal lengths changed with `PYTHONHASHSEED`; same matches, now a stable pattern text).
- `src/intake_real.py`: its patterns, word lists and `mask()` are `pii` objects / a one-line call to `MASKS_INTAKE_V1`; behaviour unchanged (R1-R23 pass).
- App: `textprep.model_text(..., mask_version=)`; `router.analyse` uses the head's `mask_version`; `MurilScorer` / `TfidfLrScorer` read it from `shield_meta.json` / the joblib (missing = v2, unknown = refused, `text_head.bundle_mask_version`). The shipped heads declare v2. Tactic-tag and sender-rule masks (`mask_text(folded)`) stay v2: they are not model input.
- `src/build_text.py`: `--mask-version` (default v2), `--out-dir`, `--report-translation-drift`; writes `build_meta.json`; frozen split found through `hash_v2` (a row's own earlier hash first), else `text_hash`, else `hash_v1`; exact-duplicate and cross-split drops keep the map in step.
- `tests/test_masks.py` M1-M7.
