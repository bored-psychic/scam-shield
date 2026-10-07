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

## Next steps, in order

1. ~~Account for the ~485-row jump.~~ Done (see above).
2. ~~Near-duplicate clustering, `cluster_id` split, augmentation parents follow the split.~~ Done.
3. ~~Freeze splits, rerun `augment.py`.~~ Done. `baseline.py` rerun 2026-10-07 with the `parent_hash` join: test F1 0.895 (was 0.934), real-only 0.894; `fake_job_postings` scam recall 0.19.
4. `src/sanity_checks.py` -> `reports/sanity.md`. *(Sonnet, medium)*
5. URL head, with and without domain age, excluding `domain_conflict`, plus a fresh-OpenPhish test. *(Sonnet, medium)*
6. Rule baseline for text and URLs. *(Haiku/Sonnet)*
7. Fine-tuning on the 2nd laptop (MuRIL main, mDeBERTa comparison, bf16, max length 128). *(Sonnet, high)*

Later modules (only after the core is solid): apps (permission-based), UPI/payment-request checker, optional tabular fraud analysis on PaySim or IEEE-CIS (not the old `txn` file).

## Background jobs

- Run `python src/pull_urls.py` daily for fresh OpenPhish URLs (out-of-source URL test).
- Run `src/enrich_domains.py` in batches until domain age covers train, val and test.
