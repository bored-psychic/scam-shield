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

- Data: `messages.csv` (~48.8k rows, 25% scam, mostly English), `urls.csv` (~61k rows; phishing mostly from ealvaradob), `apps.csv`, `typosquat_candidates.csv`, `web_scams.csv` (20 rows: 13 illustrative, 5 real_circulating, 2 generic_script).
- Web scraping is finished. Low yield; don't extend it.
- Baseline F1 0.934 is **suspected inflated** (no near-dup dedupe, source confounding).
- Near-dup clustering done (2026-10-07): MinHash char 5-grams, Jaccard >= 0.8 -> 39,934 clusters, 2,958 multi-row (11,814 rows); split by `cluster_id` moved 3,585 rows (7.3%). `augment.py` asserts parents and their clusters are in the matching split. Baseline not rerun yet.
- Open question: what added ~485 rows to `messages.csv` between the 48,288 and 48,773 counts.

## Next steps, in order

1. Account for the ~485-row jump. *(Haiku, low)*
2. ~~Near-duplicate clustering, `cluster_id` split, augmentation parents follow the split.~~ Done.
3. Freeze splits, rerun `augment.py` and `baseline.py`. *(Haiku, low)*
4. `src/sanity_checks.py` → `reports/sanity.md`. *(Sonnet, medium)*
5. URL head, with and without domain age, excluding `domain_conflict`, plus a fresh-OpenPhish test. *(Sonnet, medium)*
6. Rule baseline for text and URLs. *(Haiku/Sonnet)*
7. Fine-tuning on the 2nd laptop (MuRIL main, mDeBERTa comparison, bf16, max length 128). *(Sonnet, high)*

Later modules (only after the core is solid): apps (permission-based), UPI/payment-request checker, optional tabular fraud analysis on PaySim or IEEE-CIS (not the old `txn` file).

## Background jobs

- Run `python src/pull_urls.py` daily for fresh OpenPhish URLs (out-of-source URL test).
- Run `src/enrich_domains.py` in batches until domain age covers train, val and test.
