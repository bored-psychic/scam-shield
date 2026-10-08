# CLAUDE.md

Read this at the start of every session. README.md has the full project spec; this file has the working rules.

## Project in one line

Hybrid ML detector for India-specific scams: a text head (fine-tuned multilingual encoder) and a URL head (gradient boosting on lexical features), fused into one calibrated risk score with explanations and tactic tags. VTU Community Project 1BCP308, topic #19.

## Machines

- **Mac (M2 Air, 16GB):** source of truth. All code edits, data pipeline, baselines, URL model, sanity checks, Ollama work (`qwen2.5:7b`, `OLLAMA_CONTEXT_LENGTH=8192`), calibration, explanations, evaluation, frontend.
- **2nd laptop (RTX 5050, 8GB VRAM, Windows):** fine-tuning only (MuRIL, mDeBERTa-v3-base). No Ollama needed there. Only `git pull` on it, never edit there. It writes checkpoints and a predictions CSV, which are copied back to the Mac; all evaluation runs on the Mac.

## Hard rules

1. **Never train, tune, or look at the final test set** (real messages from real people, collected later). It is evaluated once, at the end.
2. **No leakage.** Splits are grouped (URLs by registered domain; text by near-duplicate `cluster_id`). Augmented rows must come only from parents in the same split. Assert this in code.
3. **Report honestly.** Report per-source, per-language and leave-one-source-out metrics, not just one overall F1. Flag shortcuts (length, language, source, has_ip, has_path, https).
4. **Synthetic and illustrative data never counts as real.** Keep `is_synthetic` and `provenance` (real_circulating / generic_script / illustrative / unknown) accurate. Real-only evaluation excludes everything else.
5. **Mask PII at ingestion** (phone, email, UPI, account/Aadhaar-like numbers, victim names). Only masked text is stored in `data/final/`.
6. **Keys stay in environment variables.** Never write API keys into code, files or commits.
7. **Ask before spending credits.** No Firecrawl research or crawl jobs, and no large paid API runs, without the user's explicit OK. Plain scrapes of listed URLs only.
8. **Don't visit malicious URLs.** Store them as strings only.
9. **Explain changes.** The user wants to understand the pipeline, not just run it. After each change, say what changed, why, and how it affects results. Account for every change in row counts.
10. **Before rerunning downstream steps** (augment, baseline, training), check whether an upstream step is about to change the splits. If so, do that first.
11. **Every text model reads `textprep.model_text(text)`** (`src/textprep.py`): links (including `hxxp` / `[.]` forms and `[Link]` / `[URL]` placeholders) become `<URL>`, then the text is cut to 2000 characters. `baseline.py`, `sanity_checks.py` and `app.py` use it, and the fine-tuning script on the 2nd laptop must import it (it needs `tldextract`; `git pull` brings `textprep.py`, `url_features.py`, `pii.py`), not re-implement it: a model scored with a different version silently loses accuracy. It is applied at model-input time only. `messages.csv`, `text_hash`, `neardup.py` clustering and `split_map.csv` stay on the raw text, and the URL head is unaffected. `models/text_baseline.joblib` records the token it was trained with and `app.py` refuses an older file.

## Which model and effort to use

- **Haiku, low effort:** reruns, quick lookups, small fully-specified edits.
- **Sonnet, medium effort:** most coding steps with a clear spec.
- **Sonnet, high effort:** anything touching splits, leakage, evaluation, calibration, augmentation or GPU training, where a subtle bug silently corrupts results.
- **Opus, high effort:** design decisions, confusing bugs, interpreting sanity-check results, and reviewing another session's work.

| Step | Model | Effort |
|---|---|---|
| Rerun scripts, check counts, read git history | Haiku | Low |
| Near-dup clustering + cluster split | Sonnet | High |
| Sanity checks script | Sonnet | Medium |
| Interpreting sanity results | Opus | High |
| URL head | Sonnet | Medium |
| Rule baseline | Haiku / Sonnet | Low / Medium |
| Zero-shot Ollama baseline | Sonnet | Medium |
| Fine-tuning script (2nd laptop) | Sonnet | High |
| Calibration + explanations | Sonnet | High |
| Adversarial suite (held-out attack types) | Sonnet | High |
| Fusion model (fit on validation predictions) | Sonnet | Medium |
| Frontend: Gradio prototype, then FastAPI + proper UI | Sonnet | Medium |
| Final review before freezing splits or results | Opus | High |

After any high-effort step, a fresh session should review the diff for leakage and split mistakes.

## Current status (update this section as work progresses)

- Data: `messages.csv` (48,790 rows, 25.6% scam, mostly English), `urls.csv` (~61k rows; phishing mostly from ealvaradob), `apps.csv`, `typosquat_candidates.csv`, `web_scams.csv` (20 rows: 13 illustrative, 5 real_circulating, 2 generic_script).
- Web scraping is finished. Low yield; don't extend it.
- Baseline F1 was 0.934 before the cluster split; on the frozen splits it is 0.895 (test).
- Row count: the ~485-row jump (48,288 -> 48,773) was the 39 extra `synth_india` templates added on 6 Oct (+485 synthetic rows, nothing real). The remaining +17 to 48,790 is the `web_scams` quotes (inferred: 48,773 = 48,288 + 485 was counted before they were added; no log records it; 3 of the 20 quotes were exact copies of existing rows).
- Near-dup clustering (2026-10-07, `src/neardup.py`): two rows merge if exact Jaccard >= 0.7 on char 5-grams (first 2000 chars) on the raw OR the normalised text (templated prefixes/suffixes stripped, numbers -> `<NUM>`), or >= 0.6 within `india_fraud_final`. Also grouped: `synth_india` translations (`template_family`, 32 families; the English templates are reversed in two cells, handled in `synth_india.py`) and `fake_job_postings` by `company_key` (12,884 of 15,966 posts have a profile). Result: 29,702 clusters, 3,145 multi-row (22,233 rows), 8 mixed-label (none in `india_fraud_final`).
- Splits are frozen in `data/final/split_map.csv` (text_hash -> split; 48,790 rows; SHA-256 `89eec6f1104bc671c034b7a9c66ce3f25d67d3dde1e6c809592a300487f838c5`). It is committed to git (force-added past the `data/` ignore) and tagged `splits-v1`; if it changes, update the hash here, re-add it with `git add -f` and move the tag. `build_text.py` reuses it for existing rows. Re-frozen 2026-10-07 after the clustering change (48 rows moved). If the clustering rules change again, the old map conflicts with the new clusters: delete it deliberately and say so. `build_text.py` and `augment.py` abort if any cluster / family / company straddles splits or any cross-split pair breaks the rule (independent LSH seed); `src/split_audit.py` reports it: 0 violations. Still crossing at 0.6-0.7: 3.3% of val/test rows have a train twin (phishing_email, job posts, SMS spam; none in `india_fraud_final`). See BUGS.md.
- `augment.py` splits attack families: homoglyph / leet / zero_width -> `messages_aug.csv` (19,831 rows, train parents); char_noise / url_obfuscate / spaced_keywords -> `messages_adv_test.csv` (1,865 rows, test parents, held-out attacks, 749 from real parents). Outputs have `source = augmented`, `is_synthetic = True`, plus `parent_source`, `parent_is_synthetic`, `parent_hash`. Rerun after every `build_text.py`.
- Run order: `build_text.py` (about 7 min, 7.5 GB peak) -> `split_audit.py` -> `augment.py` -> `baseline.py`.
- Hindi/Kannada translation set (2026-10-07, nothing in `messages.csv` or `split_map.csv` has changed: still 48,790 rows). Today Hindi and Kannada are 394 rows each, all `synth_india`, 58.6% scam, 0 val rows (`reports/sanity.md`). Plan: translate short English parents into both languages, both labels, ~15% scam, so the overall Hindi/Kannada scam share falls to about 30% (target <= 35%) and benign rows exist in train, val and test. No existing `synth_india` row is touched.
  - Parents: `src/translate_parents.py parents` -> `data/external/indic/translate_in/parents_2026-10-07.csv` (735 parents: 625 benign from the free 10k preview of the OTP/phishing SMS set, 110 scam from `scam_ham_india` / `india_fraud_final` that show a fraud mechanism; promotional spam is dropped) and `reports/translate_parents.md` (filter rules, row ledger, cap sweep, label cues). Cap 3 parents per template group; parents with an unmasked `@handle` are dropped. Preview provenance is `unknown`, licence MIT only as README text (`data/sources.yaml`, force-added). The shared PII masks now live in `src/pii.py` (imported by `build_text.py`).
  - Translation (Mac, `.venv-translate`, pinned in `requirements-translate.txt`; transformers must stay 4.49.0): `src/protect.py` + `src/translate_indic.py`, IndicTrans2 1B in fp16 on MPS, about 1.5 s per sentence. 50-sentence test (`reports/translate_timing.md`): placeholder markers survive in 84% (Hindi) / 90% (Kannada) of first passes; failures are mostly benign parents; the greedy single-sentence retry recovered 0 of 13.
  - Full run finished 2026-10-07 18:11 (35 min, 1.41 s per sentence, `reports/translate_run.md`): 1,470 translations, 1,291 passed the marker check (Hindi 658, Kannada 633). No translation process is running.
  - `translate_parents.py finalise` done 2026-10-07 (`reports/translate_finalise.md`; code in `src/translate_parents.py`, `protect.strip_markers`). Kept: Hindi 523 benign + 92 scam (615 of 735), Kannada 499 + 88 (587 of 735), written to `data/external/indic/translated/translated_final_2026-10-07.csv` (dropped rows with their step: `translated_dropped_2026-10-07.csv`; both git-ignored). Overall Hindi / Kannada scam share 32.0% / 32.5% (was 58.6%; target <= 35%). Drops, Hindi / Kannada: marker restore failed 77 / 102; **person name in the English parent 24 / 24** (new step for rule 5: `pii.MASKS` has no name masking and the bank-alert parents carry UPI payer names, a passenger, a rider; `NAME_RX` is curated by eye, not exhaustive, see BUGS.md); digit or mask-token mismatch 1 / 2; leftover English (< 50% target-script letters outside protected spans) 2 / 2; wrong script, exact duplicates 0; scam trim to 15% 16 / 18 (val/test scam rows never trimmed; Hindi scam by split 76 train / 11 val / 5 test). Every row balances to 735 per language. **Length / cue decision:** the gate compares cue-only AUROCs (length, digit/mask, latin + length, all cues) of the combined pool (synth_india + translations) with real short English SMS (uci_sms_spam + scam_ham_india <= 160 chars: 0.91-0.96). Pools are 0.67-0.77, no interval reaches the reference, so accept. The translations alone are higher (digit/mask 0.80 in both languages vs the synth Hindi baseline 0.58, reproduced): the benign translations are bank/OTP alerts, the scam ones prose; flag it as a shortcut when evaluating Hindi/Kannada. Length-bin sampling is a flag, `finalise --length-match`, off by default: pass B keeps only 109 of 523 Hindi and 52 of 499 Kannada benign rows and pushes the scam share to 55.5% / 61.1%. Spot-check sheets written: `reports/spotcheck_hi.csv`, `reports/spotcheck_kn.csv` (50 rows each: 25 benign, 25 scam; the user fills `meaning_ok`, `label_still_correct`, `notes`). **Next: (1) native-speaker spot-check, accept a language at >= 90% y on both columns; (2) only then rebuild:** `build_text.py` ingests `translated_indic` (is_synthetic=True, `translation_of` grouping; the 119 anchored parents inherit their anchor row's split, the rest become fresh clusters; hard asserts that no existing `split_map` entry changes), then `split_audit.py` -> `augment.py` -> `baseline.py` -> `sanity_checks.py`; tag `splits-v2` (keep `splits-v1`). **Stop before the `build_text.py` rebuild until the spot-check is back.**
  - MVP app (2026-10-09, `src/app.py`, `python src/app.py`, 127.0.0.1:7860, Gradio 6.29 installed in `.venv`): pasted text -> URLs extracted -> `models/url_head.joblib` (host-only); masked text -> `models/text_baseline.joblib` (written by `baseline.py --save`, train split only; val-chosen thresholds suspicious 0.428 / likely 0.652; test F1 unchanged at 0.895). The text head sits behind `load_text_model()` (a `TextScorer` with `score` / `explain`) so MuRIL can replace it. Fusion is a placeholder (`fuse()`: max of the two levels, both >= Suspicious -> Likely scam), not the fusion model. URL feature code moved verbatim from `url_head.py` into `src/url_features.py` (shared with the app); the rerun left `reports/url_head.md`, `url_preds.csv` and all model predictions identical, and `url_head.joblib` now also carries a `reference` benign host (occlusion breakdown) and `threshold_high` (val precision >= 0.95). Tactic tags are hand-written regexes; the Hindi / Kannada cues are unchecked.
  - `<URL>` in the text input (2026-10-09, `src/textprep.py`, rule 11, numbers and tables in `reports/url_token.md`): the baseline was retrained on it (`models/text_baseline.joblib`, suspicious 0.423 / likely 0.656): test F1 0.895 -> 0.893, real-only 0.894 -> 0.894, LOSO AUROC up for `india_fraud_final` +0.028, `scam_ham_india` +0.023, `synth_india` +0.022, `ealvaradob_phishing` +0.013, flat or -0.010 elsewhere; model input changed in 6,299 of 48,790 rows, `messages.csv` / hashes / `split_map` untouched. `[Link]` (201 `india_fraud_final` scam rows, 0 benign) maps to `<URL>`; a bare `word.tld` with no path must be lower case or all caps (without that guard 81% of bare matches were `position.You`-style typos). `url_obfuscate` in the held-out attack test is now neutralised by the preprocessing, so it no longer measures robustness. `reports/sanity.md` was regenerated; its hand-written Interpretation still quotes the old pipeline and carries a Stale warning until it is rewritten (Opus review). One Kannada template (15 test rows) regressed because `<URL>` presence is a scam cue in `synth_india` (58% vs 14% of rows).
  - App rules (2026-10-09, `src/app.py`, `tests/tricky_inputs.py`, `python tests/test_tricky_inputs.py`): scores and cut-offs are shown and compared at 3 decimals; a request to send / share / forward an OTP, PIN or CVV forces at least Suspicious and shows as its own red flag (genuine "do not share" alerts are negation-checked and do not fire; known false positive: a real delivery-OTP instruction); isolation cues now include delete-this-message and "don't tell anyone / keep this confidential" (suppressed on OTP advisories) plus unchecked Hinglish / Hindi / Kannada forms.
  - Known gap: the PII masks miss some UPI handles (`@axisbank`, `@indus`) and dotless email addresses in 70 existing rows; fixing it changes text hashes, so it belongs with `splits-v2` (BUGS.md).

## Next steps, in order

1. ~~Account for the ~485-row jump.~~ Done (see above).
2. ~~Near-duplicate clustering, `cluster_id` split, augmentation parents follow the split.~~ Done.
3. ~~Freeze splits, rerun `augment.py`.~~ Done. `baseline.py` rerun 2026-10-07 with the `parent_hash` join: test F1 0.895 (was 0.934), real-only 0.894; `fake_job_postings` scam recall 0.19.
4. ~~`src/sanity_checks.py` -> `reports/sanity.md`.~~ done 2026-10-07: Interpretation section in reports/sanity.md, commit 7c1c3df (Opus, high).
5. URL head (`src/url_head.py` -> `reports/url_head.md`, 2026-10-07): done except two parts. The domain-age comparison is **blocked**: `enrich_domains.py` has covered 0% of the training rows (it started with URLhaus / OpenPhish; about 45k domains at 0.5 s each, roughly 6 h left). The fresh-OpenPhish test is only the 300 rows of the 2026-10-05 pull (held out, never trained on); it becomes fresh after more daily `pull_urls.py` + `build_urls.py` runs. *(Sonnet, medium)*
6. Rule baseline for text and URLs. *(Haiku/Sonnet)*
7. Fine-tuning on the 2nd laptop (MuRIL main, mDeBERTa comparison, bf16, max length 128). Inputs come from `textprep.model_text` (rule 11). *(Sonnet, high)*

Later modules (only after the core is solid): apps (permission-based), UPI/payment-request checker, optional tabular fraud analysis on PaySim or IEEE-CIS (not the old `txn` file).

## Background jobs

- Run `python src/pull_urls.py` daily for fresh OpenPhish URLs (out-of-source URL test).
- Run `src/enrich_domains.py` in batches until domain age covers train, val and test.
