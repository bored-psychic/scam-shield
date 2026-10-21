# splits-v2 rebuild (2026-10-21)

`data/final/split_map.csv` re-frozen as **splits-v2**: 49,931 rows, SHA-256 `8263df1c304de7154290f57f648387ddc396cab303630753aa40200619bd4e6c` (splits-v1: 48,790 rows, `89eec6f1...838c5`, tag `splits-v1` kept). Scope approved by the user in the plan of 2026-10-21. Run order: `pii.py` + `protect.py` fixes -> re-translate p00312 (`translate_indic.py run`, `translate_parents.py replace`) -> `build_text.py` -> `split_audit.py` -> `augment.py` -> `baseline.py` -> `sanity_checks.py`.

## What changed, in one table

| Change | Rows affected | Effect on splits |
|---|---|---|
| PII masks (`src/pii.py`): NPCI UPI handle list (case-insensitive) + dotless `user@host` -> `<EMAIL>` | 81 existing rows change text and hash | 80 re-keyed with the same split (train 54, val 15, test 11); 1 train row dropped (below) |
| Mask side effect: two `phishing_email` rows (1 train, 1 test) at J 0.69 under the old masks reach 0.72 (raw view) once both handles are `<EMAIL>` | 1 | the **train** row is dropped, so val / test stay exactly as frozen |
| `protect.py` time pattern bounded on both sides | p00312 only (checked: no other parent's protected spans change) | none (no split) |
| p00312 re-translated (hi, kn), same model and settings | 2 translations replaced | none |
| Hindi / Kannada translations ingested, **train only** | +1,142 rows (`translated_indic`) | all train |

`messages.csv`: 48,790 -> 49,931 = 48,790 - 1 (dropped train row) + 1,142 (translations). No existing row changed split (asserted in `build_text.py`; `split_audit.py`: **0 violations**).

## Val / test membership

| Split | v1 rows | v2 rows | same hash | re-keyed (same row, masked text changed) | added | removed |
|---|---|---|---|---|---|---|
| val | 5,267 | 5,267 | 5,252 | 15 (phishing_email 8, scam_ham_india 7) | 0 | 0 |
| test | 5,711 | 5,711 | 5,700 | 11 (phishing_email 8, scam_ham_india 2, fake_job_postings 1) | 0 | 0 |

Val and test hold exactly the same messages as in splits-v1; 26 of them have a new `text_hash` because a dotless address in them is now `<EMAIL>`. No translated row is in val or test. Test texts were not read: test rows were only counted.

## Row counts per source and language (all splits)

| Source | v1 | v2 | Change |
|---|---|---|---|
| phishing_email | 17,500 | 17,499 | -1 train (the mask-joined near-duplicate) |
| translated_indic | 0 | 1,142 | +1,142 train (Hindi 581: 508 benign + 73 scam; Kannada 561: 492 + 69) |
| every other source | | | unchanged |

| Language | train v1 -> v2 | val | test |
|---|---|---|---|
| english | 36,470 -> 36,469 | 5,165 | 4,995 |
| hindi | 189 -> 770 (scam 112 -> 185) | 0 | 205 |
| kannada | 189 -> 750 (scam 112 -> 181) | 0 | 205 |

Hindi / Kannada scam share over all splits: 58.6% -> 31.2% / 31.4%; train only: 59.3% -> 24.0% / 24.1%. **Val still has 0 Hindi and 0 Kannada rows** (synth_india has none and translations are train-only), so nothing chosen on val (epoch, max-len, cut-offs) sees either language.

## Translation ledger (every dropped translation accounted for)

| Step | Hindi benign | Hindi scam | Kannada benign | Kannada scam |
|---|---|---|---|---|
| kept by finalise (`translated_final_2026-10-21.csv` = 10-07 file with p00312 replaced) | 523 | 92 | 499 | 88 |
| English parent is a val/test row (train-only; a train translation of a val/test row would leak) | 0 | -16 (11 val, 5 test) | 0 | -16 (11 val, 5 test) |
| review exclusions (`docs/spotcheck/exclude_*.txt`) | -12 | -3 | -4 | -3 |
| D21: a digit run or link of the parent missing | -1 (p00158) | 0 | -1 (p00365) | 0 |
| PII the masks miss in the parent (rule 5) | -2 (p00066, p00533) | 0 | -2 (p00066, p00533) | 0 |
| exact duplicate / parent has a val-test twin at J >= 0.6 / bridges frozen clusters | 0 | 0 | 0 | 0 |
| **into train** | **508** | **73** | **492** | **69** |

Exclusions, Hindi (15): hi29 p00339, hi34 p00652, hi35 p00605, hi39 p00023 (D20); p00719, p00720 (lost "per"); Licious mistranslated (shubh / ashubh): p00076, p00154, p00174, p00313, p00349, p00407, p00567, p00618; p00309 ("licious items" -> "valid items", user's call). Kannada (7): p00696, p00720, p00719 (D26); Licious mistranslated: p00174 ("poisonous"), p00313, p00339, p00407 ("wicked"). Kannada p00006 matched the poison stem only through "we regret" (a correct translation) and is kept (user's call). Every listed `text_hash` was checked against the translations file.

D21 as applied: digit runs (native digits mapped to ASCII) and links, where links = `protect.py`'s url pattern **plus every link `textprep` finds, verbatim**. The second part was added because `protect.py`'s TLD list has no `.pw`: `klr.pw/ordernow` was not protected, and the model dropped it in p00158 Hindi and p00365 Kannada. After the p00312 re-translation the digit clause drops 0 rows.

PII drop: parents p00066 and p00533 hold an account-like number glued to letters (`THTHA` + 17 digits) that `<ACCOUNT>` (needs a word boundary) never masked; the Kannada translations put a space before it, so the build's new assert "the masks change no translation" caught it. All four translations of the two parents are dropped. The wider gap (glued long digit runs in existing rows) is in BUGS.md.

Scam share of the translations: 12.6% (Hindi) / 12.3% (Kannada), down from 15% because the val/test-anchored rows were all scam.

## p00312 after the fix

| | Text |
|---|---|
| English | RESEND 1:363094 is the OTP for INR 278.33 transaction on AMAZONRECHA using ICICI Bank Credit Card XX3996. OTPs are SECRET. DO NOT disclose |
| Hindi, before | RESEND 1:36 3094 OTP है INR 278.33 लेन-देन के लिए AMAZONRECHA पर ICICI बैंक क्रेडिट कार्ड XX3996 का उपयोग करके। OTPs गुप्त हैं। खुलासा न करें |
| Hindi, after | RESEND 1:363094 INR 278.33 लेन-देन के लिए OTP है जो AMAZONRECHA पर ICICI बैंक क्रेडिट कार्ड XX3996 का उपयोग करके किया जाता है। OTPs गुप्त हैं। खुलासा न करें |
| Kannada, before | RESEND 1:36 3094 ಎಂಬುದು ICICI ಬ್ಯಾಂಕ್ ಕ್ರೆಡಿಟ್ ಕಾರ್ಡ್ XX3996 ಅನ್ನು ಬಳಸಿಕೊಂಡು AMAZONRECHAಯಲ್ಲಿನ INR 278.33 ವಹಿವಾಟಿಗೆ OTP ಆಗಿದೆ. OTPs ಗಳು ರಹಸ್ಯವಾಗಿವೆ. ಬಹಿರಂಗಪಡಿಸಬೇಡಿ. |
| Kannada, after | RESEND 1:363094 ಎಂಬುದು ICICI ಬ್ಯಾಂಕ್ ಕ್ರೆಡಿಟ್ ಕಾರ್ಡ್ XX3996 ಅನ್ನು ಬಳಸಿಕೊಂಡು AMAZONRECHAಯಲ್ಲಿ ನಡೆಯುವ INR 278.33 ವಹಿವಾಟಿಗೆ OTP ಆಗಿದೆ. OTPs ಗಳು ರಹಸ್ಯವಾಗಿವೆ. ಅದನ್ನು ಬಹಿರಂಗಪಡಿಸಬೇಡಿ. |

Both passed every finalise row filter plus the D21 digit-run check (status ok, no recovery needed). Not reviewed by a native speaker.

## Masking

Miss = a word character, `@`, a letter (`pii.MISS_RX`), outside the mask tokens.

| | rows with a miss | occurrences | rows with `<EMAIL>` | `<EMAIL>` tokens | `<UPI_ID>` tokens |
|---|---|---|---|---|---|
| splits-v1 `messages.csv` | 76 (phishing_email 44, scam_ham_india 18, fake_job_postings 11, uci_sms_spam 3) | 180 | 2,631 | 5,385 | 43 |
| splits-v2 `messages.csv` | **0** | **0** | 2,704 | 5,575 | 55 |

Before deduplication the build counts 124 raw rows with a miss under the old masks and 0 under the new ones. `@axisbank` / `@indus` never occurred in `messages.csv` (only in OTP-preview parents, which `translate_parents.py` had dropped), so the UPI part of the fix changed no existing row; the 12 extra `<UPI_ID>` tokens are in translations, carried over from their already-masked parents. Most of the dotless matches are not personal addresses (shell prompts `root@host`, SMS promo tags `OFFERS@BRAND`, `SETI@Home`, junk inside encoded attachments); they are masked anyway (over-masking is the safe side of rule 5). The masks also run on app input (`textprep.model_text(mask_pii=True)`, `router`, `sender_rule`): `pytest -q` 9 passed.

## Baseline (char TF-IDF + LR, train split only; `models/text_baseline.joblib` NOT replaced)

| | splits-v1 | splits-v2 |
|---|---|---|
| val F1 / real-only | 0.925 / 0.921 | 0.923 / 0.919 |
| test F1 / real-only (scored once) | 0.893 / 0.894 | 0.900 / 0.894 |
| test, Hindi acc / scam recall (205 rows, synth_india) | 0.824 / 1.000 | 0.937 / 0.950 |
| test, Kannada acc / scam recall (205 rows, synth_india) | 0.751 / 1.000 | 0.795 / 0.891 |
| test, synth_india acc / scam recall | 0.834 / 0.987 | 0.865 / 0.943 |
| test, call channel acc / scam recall | 0.973 / 0.957 | 0.894 / 0.829 |
| test, fake_job_postings scam recall | 0.163 | 0.204 |
| adversarial scam recall, all parents (char_noise) | 0.963 | 0.942 |

Reading: the benign translations remove part of the "Hindi / Kannada script = scam" shortcut (before, every Hindi and Kannada test scam was caught and benign rows were often flagged; now accuracy rises and recall falls). The call-channel and synth_india recall drop come from the same synth_india test rows (the call-script templates in Hindi / Kannada). These Hindi / Kannada numbers are synthetic templates, not real messages; the translated rows are machine translations (label them "translated"). The baseline model the app loads still has the splits-v1 fit and cut-offs (0.423 / 0.656); replacing it is a separate step. The adversarial file was regenerated with per-(split, attack) seeds, so its variants are new random draws on the same parent pool (1,865 -> 1,862 rows; 3 char_noise draws left a text unchanged).

## Downstream files

| File | v1 | v2 |
|---|---|---|
| `messages_aug.csv` (train attacks) | 19,831 rows, 6,705 parents | 20,022 rows, 6,841 parents (+188 variants of translated scam rows) |
| `messages_adv_test.csv` (held-out attacks, test parents) | 1,865 rows, 1,195 parents | 1,862 rows, 1,189 parents |
| near-dup clusters | 29,702 (8 mixed-label) | 30,048 (11 mixed-label) |
| val/test rows with a train twin at J >= 0.6 | 363 (3.3%) | 360 (3.3%) |

The 3 new mixed clusters (all train): 12 benign translations whose English parents (OTP-preview bank alerts) were anchored as near-twins (J >= 0.6) to 7 `scam_ham_india` rows labelled scam. No leakage (one split); it is label disagreement between two sources (BUGS.md).

## Code changes

`src/pii.py` (masks, `MASKS_V1`, `MISS_RX`), `src/protect.py` (time pattern), `src/translate_parents.py` (`replace` subcommand), `src/build_text.py` (translation ingestion, train-only, D21, exclusions, splits-v1 hash carry-over, mask-join drop, asserts), `src/neardup.py` (`translation_of` in the straddle check), `src/finetune.py` (hash, `translation_of` in `GROUP_KEYS`), `src/augment.py` (per-split seeds), `src/baseline.py` (val F1 line), `src/sanity_checks.py` (a source without val/test rows is not a LOSO fold).

## Not in this rebuild (splits-v3 candidates)

Name masking (rule 5, BUGS.md); D5b promo_gray relabel; synth_india benign templates' link rate; glued long digit runs (BUGS.md).
