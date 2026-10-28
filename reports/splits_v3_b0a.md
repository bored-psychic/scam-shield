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

Final numbers, after the follow-up of section 3 (widened OTP rule, ALL-CAPS name runs, idempotence guard). The first version of this report had 49,857 rows and 4,861 changed.

| | train | val | test | all |
|---|---:|---:|---:|---:|
| v2 `messages.csv` | 38,953 | 5,267 | 5,711 | 49,931 |
| v3 build | 38,886 | 5,266 | 5,702 | **49,854** |
| difference | -67 | -1 | -9 | -77 |
| rows whose text changes (v3 vs v2 masks) = rows whose `text_hash` changes | 3,789 | 480 | 641 | **4,910 (9.8 %)** |
| rows kept in their split (re-keyed, same split) | 3,789 | 480 | 641 | 4,910 |
| rows that change split | 0 | 0 | 0 | 0 |

The plan estimated ~7,377 rows (14.8 %): 4,910 is lower because the estimate counted the ALL-CAPS rule on every channel (2,153 rows; v3 runs it on SMS-type
channels only: 27 rows) and had no stoplists. Split-straddle and near-duplicate checks: **0 violations** (`neardup.assert_no_leakage` passed on the v3 build:
no cluster / family / company straddles splits, no cross-split pair at Jaccard >= 0.7 on raw or normalised text), so the re-key creates **0 new cross-split near-duplicate pairs**. Re-keying created these cross-split joins, all resolved by the rules in the plan:
2 frozen train `scam_ham_india` rows are the same text as a val / test row under v3 (train rows dropped), 1 train `scam_ham_india` row's cluster now reaches a val / test row (dropped); no val-test join (that would stop the build). One `phishing_email` train row is not in the map (the splits-v2 drop, see section 1) and its cluster holds a test row: dropped, as in v2.

Where the 77 rows went (rows merged as exact duplicates under the v3 masks, because a name, id or OTP no longer tells them apart, plus the 3 rows dropped above): `synth_india` -43 (test -4, train -39), `translated_indic` -18 (train),
`scam_ham_india` -6 (train: the 3 above and 3 that the widened OTP rule made duplicates), `india_fraud_final` -5 (test -4, train -1), `phishing_email` -4 (train -3, val -1), `uci_sms_spam` -1 (test). Test loses 9 rows that are copies of other test rows. No source gains a row.

**Idempotence (D-v3.1 relaxed):** `build_text.py` now asserts v3(v3(x)) == v3(x) on all 14,261 rows the masks change (and a fixed point is trivially idempotent), so a POOL row the intake masked goes through v3 unchanged
except where a v3-only rule fires. The first run of this check **stopped the build** on 8 rows: the token `<OTP>` contains the word OTP, so a second pass read it as the keyword of the OTP rule and masked the number after it
(`access code + <OTP>\n52098236`). The intake's pinned rule has the same flaw; v3 uses copies that do not read a keyword right after `<` (`OTP_RX_V3`, `OTP_NEAR_RX`).

**Translation drift (`--report-translation-drift`): none.** Before the widening 38 of 303 changed translations were masked while their English parent was not; now every translation the v3 masks change (285 after the dedupe) is changed
the way its English parent is. The build ran without the flag's report line, so the plan's check would also pass without the flag.

Rows changed by each v3 step, by source (a row can fire several; `any` = text differs from v2; link-phone and the final v2 sweep mostly redo v2 and are left out of the per-type columns, the sweep never fired):

| source | any | greeting name | ALL-CAPS name | card | OTP | account tail | 9+ digits |
|---|---:|---:|---:|---:|---:|---:|---:|
| fake_job_postings | 2,163 | 98 | 0 | 0 | 2 | 3 | 2,073 |
| phishing_email | 1,226 | 1,048 | 0 | 5 | 56 | 29 | 104 |
| india_fraud_final | 452 | 39 | 4 | 0 | 138 | 208 | 93 |
| translated_indic | 285 | 0 | 0 | 0 | 66 | 204 | 42 |
| synth_india | 206 | 48 | 5 | 0 | 94 | 59 | 0 |
| scam_dialogue | 206 | 184 | 0 | 0 | 2 | 20 | 4 |
| uci_sms_spam | 199 | 145 | 11 | 0 | 19 | 0 | 25 |
| scam_ham_india | 91 | 51 | 7 | 0 | 13 | 2 | 2 |
| ealvaradob_phishing | 29 | 13 | 0 | 0 | 8 | 0 | 9 |
| hinglish_conversations | 29 | 29 | 0 | 0 | 0 | 0 | 0 |
| cmu_hinglish_dog | 24 | 24 | 0 | 0 | 0 | 0 | 0 |
| web_scams | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

By split (rows that changed): greeting name 1,303 / 163 / 213 (train / val / test), ALL-CAPS name 17 / 1 / 9, card 5 / 0 / 0, OTP 280 / 54 / 64, account tail 407 / 14 / 104, 9+ digits 1,810 / 258 / 244.

## 3. Findings and the decisions taken on them (2026-10-28)

1. **OTP rule gap: widened (decided).** The intake's `OTP_RX` needs the number right after the keyword, so "Your OTP for Grapevine is 919157" stayed unmasked while its Hindi / Kannada translation was masked: 38 of 303 translations drifted. v3 now also masks, after an OTP keyword
   (otp, passcode, one-time password / pin / code, verification / security / login / authentication / transaction / confirmation code), the 4-8 digit number after `is` / `are` / `was` / `:` / `=` within 60 characters, no sentence end in between (`pii.OTP_NEAR_RX`, v3 only; the intake stays pinned).
   Effect: translation drift 38 -> 0; OTP rows 4,861 -> 4,910 changed rows overall (+49), OTP column 280 / 54 / 64 (train / val / test). Of the 43 train hits that only this rule makes, all are one-time codes (Instahyre / Shine / Naukri login codes, bank NetBanking payee OTPs, Aadhaar-link OTPs, Digi Yatra); one is a server "passcode : 56871" in a mail, a secret that is not a phone OTP.
   D-v3.1's "v3 masks change no POOL text" became **idempotence**, asserted in the build (section 2), and the evaluation rule below.
2. **Channel-dependent mask vs dedupe: approved.** `email_or_sms` is not an SMS-type channel for the ALL-CAPS rule, and `build_text.py` deduplicates and detects label conflicts on the v2 hash first (417 extra `ealvaradob_phishing` rows otherwise).
3. **ALL-CAPS payer rule: runs of up to 4 tokens, initials included (decided).** After from / to / by / paid to / ..., a token is 3+ capitals or an initial (one capital, dot or not); a 2-letter token ends the run, an undotted initial may not end it, "A" and "I" without a dot are words, and one stoplisted
   word in the run leaves the run alone. "RENU R KUMAR" is one `<NAME>`; "AMIT I will pay" masks only AMIT; sentence-end dots stay. Re-measured on the 10,310 train SMS-type rows (v2-masked text, stored form): old rule **17 hits / 14 phrases, new rule 17 hits / 14 phrases**.
   People: `SHRI RAM` x4 and `MANEESHA V.` (the old rule masked MANEESHA and left the initial) = **5 of 17**; unclear: `STAPATI` (a lender, "loan from STAPATI") = 1; **non-names: 11** (CRL, CHA, CCNA, IVY, AOM, DLF, GMW, DABOOKS. DID, NVQ, YOR HOUSE, and `EXTREME DIRTY LIVE CHAT`, a spam heading that the 4-token window now takes whole where the 3-token window took 3 words).
   The rule still masks more non-names than people in train (about 2 : 1); its yield is 27 rows of 49,854, so it matters little either way. The stoplist is not extended (it is built from train hits already; adding words for these 11 would be tuning the list to the sample).
4. **`mask_version` into `shield_meta.json`: moved to B0b (decided).** `finetune.py` and the notebook do not write it yet; a v3 bundle without it is read as v2 by the app. Noted in the plan.
5. **Evaluation on intake-masked text (decided, tested).** `real_test_v1.csv` and the POOL are intake-masked. `eval_real.py` scores through `router.analyse`, which masks every input with the loaded head's `mask_version`, so a v3 bundle gets the v3 masks on top of the intake's and a v2 bundle the v2 ones. `score_rows(rows, live, heads=None)` takes stub heads so
   `tests/test_masks.py` M8 can check it without the real test set.

## 4. Rules that over-mask (3 masked examples each, train rows only)

| rule | what it masks that is not personal | examples (masked form) |
|---|---|---|
| greeting name | brands and aliases after Mr; the Hinglish particle "hi" ("only") | `... including Mr. <NAME>®, George Brazil®, and Mr. <NAME>®.` / `From: "Mr. <NAME>" To: Sent: Monday` / `are yaar, 5% hi <NAME> hai.` (53 benign Hinglish chat rows get a greeting mask, some of them on this particle) |
| ALL-CAPS name | organisations the stoplist does not know; double token when "Shri" is also a greeting title | `CALL <ACCOUNT> & LISTEN TO <NAME> GOING ON IN THE OFFICE` (a 4-token spam heading) / `This message is brought to you by <NAME> Ltd.` / `via IMPS from <NAME> <NAME> (Ref: <PHONE>)` (Shri Ram, a person: masked, once by each rule) |
| OTP (adjacent rule) | prize claim codes and postal codes | `quoting claim code <OTP> standard rates apply` (14 train `uci_sms_spam` rows: a scam cue now reads as an OTP) / `Zip Code <OTP>` / `post code <OTP>` |
| OTP (new, number further on) | almost nothing: 43 train hits, all one-time codes; one server "passcode : 56871" | `OTP for your Instahyre login is <OTP>. Valid for 5 m...` / `Your OTP to link Aadhaar with Punjab National Bank account is <OTP>. Do not share` / `4017 passcode : <OTP> host : mark ha...` |
| 9+ digit run, account tail | tracking, GST and booking references (not personal; the plan chose to over-mask) | `Article No RD<ACCOUNT>IN booked at New Delhi GPO` / `(ARN AA<ACCOUNT>)` / `#AWB-CC<ACCOUNT>` |

Also noted: a bare `****1234` (no word boundary before `*`) stays as it is in the intake; v3 equals the intake there on purpose. (A name followed by initials is now one `<NAME>` in the ALL-CAPS rule; the greeting rule still masks one word.)

## 5. What changed in the code

- `src/pii.py` (follow-up: `OTP_NEAR_RX` + `OTP_RX_V3` guard, `CAPS_NAME_RX_V3` runs, see section 3): `MASKS_V2` ("v2", today's patterns; `MASKS` is its pattern list), `MASKS_INTAKE_V1` ("intake-v1", `intake_real.mask` moved here), `MASKS_V3` ("v3"); `mask_set(version)`, `mask_text(text, version=, channel=)` (default v2),
  `MASK_VERSIONS`. `UPI_HANDLES` is sorted longest first, ties alphabetical (it was `key=len`, whose order among equal lengths changed with `PYTHONHASHSEED`; same matches, now a stable pattern text).
- `src/intake_real.py`: its patterns, word lists and `mask()` are `pii` objects / a one-line call to `MASKS_INTAKE_V1`; behaviour unchanged (R1-R23 pass).
- App: `textprep.model_text(..., mask_version=)`; `router.analyse` uses the head's `mask_version`; `MurilScorer` / `TfidfLrScorer` read it from `shield_meta.json` / the joblib (missing = v2, unknown = refused, `text_head.bundle_mask_version`). The shipped heads declare v2. Tactic-tag and sender-rule masks (`mask_text(folded)`) stay v2: they are not model input.
- `src/build_text.py`: `--mask-version` (default v2), `--out-dir`, `--report-translation-drift`; writes `build_meta.json`; frozen split found through `hash_v2` (a row's own earlier hash first), else `text_hash`, else `hash_v1`; exact-duplicate and cross-split drops keep the map in step.
- `src/build_text.py`: also asserts v3 idempotence on every row it changes.
- `src/eval_real.py`: `score_rows(rows, live, heads=None)` (tests only use `heads`).
- `tests/test_masks.py` M1-M8 (new cases for the OTP forms and ALL-CAPS runs, M5 relaxed to idempotence, M8 = eval_real applies the head's masks on top).
