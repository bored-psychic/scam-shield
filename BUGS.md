# Known bugs and faults

Open issues only. Delete an entry once it is fixed.

## Blocked

None.

## Open

- **Template reuse at Jaccard 0.6-0.7 still crosses splits (all sources except `india_fraud_final`).** On the normalised text 992 cross-split pairs sit at 0.6-0.7 (raw: 424); 363 val/test rows (3.3%) have a train twin at >= 0.6 (raw: 280, 2.6%). Mostly `phishing_email` spam and forwarded-reply campaigns (829 pairs; 7.5% of its val/test rows), then `fake_job_postings` (45), `scam_ham_india` (33), `scam_dialogue` (30) and SMS spam. A global 0.6 would catch them; not tried with the current pipeline (company folding already makes the biggest clusters 100-500 rows, and 0.6 will merge more scam/benign job posts).
- **Company grouping only covers job posts with a profile.** `fake_job_postings` has no company-name column; `company_key` is the first 150 chars of `company_profile`. 12,884 of 15,966 posts have one. The 3,082 without are 15.2% fraud (keyed: 1.9%), so about two thirds of the fraud posts are grouped by text similarity only.
- **`india_fraud_final` splits aren't stratified.** It is hash-split per cluster (about 30 clusters per category/label cell), so `job`/benign has 0 test rows (195 train, 5 val) and `utility`/scam has 0 val rows (13 test). Per-category scores on this source skip those cells. Fix: stratify its clusters per (category, label) like `synth_india`.
- **Held-out attack test is thin on real parents.** `messages_adv_test.csv` has 1,865 rows, 749 from real parents: 584 `char_noise`, 124 `url_obfuscate`, only 41 `spaced_keywords`. Report real-parent and all-parent numbers separately (`parent_is_synthetic`). The test uses attacks absent from training, so it can't show recovery on homoglyph / leetspeak / invisible characters; that needs the same attacks on test parents in a separate file.
- **`synth_india` has no val rows, and test (821) is larger than train (756).** Each (category, label) has only two template families, so one goes to test and one to train. Needs a third family per cell (en/hinglish/hi/kn) to fill val.
- **Val and test are lumpy.** Whole company clusters move together: two benign job-post clusters (514 and 108 rows) are 15% of val's benign rows, and val/test hold only 56/98 fraud job posts, so per-source scores on `fake_job_postings` are noisy.
- **`baseline.py` doesn't use `messages_aug.csv` yet** (the homoglyph / leet / zero-width training augmentations).
- **`src/extract_scams.py` never run end to end.** Only the masking and substring-check logic has been tested offline; the Claude call, output CSV and per-page counts are unverified.
- **Multi-line blockquotes are dropped.** A message quoted across several lines with a `>` at the start of each line is not an exact substring of the page after whitespace normalization, so the check rejects it.
- **Victim-name masking depends on the model.** Names are masked only if Claude lists them in `victim_names`; any it misses stay in the text. Spot-check `data/extracted/web_scams.csv`.
- **`--local` may silently truncate long pages.** Ollama's default context window is a few thousand tokens and its OpenAI-style endpoint can't raise it per request, so the start of a long article can be cut off without an error. Start the server with a larger window, e.g. `OLLAMA_CONTEXT_LENGTH=32768 ollama serve`.
- **`--local` never run against a real model.** Ollama wasn't running when it was added; it has only been tested against a mock server.
- **Every run re-processes all pages.** `extract_scams.py` re-calls the API for every saved page and overwrites `web_scams.csv`; there is no per-page cache.
- **No dependency file for the main `.venv`.** `anthropic` (1.11.0) was installed into `.venv` by hand; nothing records it or the other packages (`pandas`, `requests`). The translate venv (`.venv-translate`) is recorded in `requirements-translate.txt`.
