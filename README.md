# Scam Shield: Hybrid ML Detection of India-Specific Scams

VTU Community / Societal Project (1BCP308, Sem 3), topic #19: Cyber Security Awareness Platform for Phishing, Digital Arrest Scams, and Malicious Applications.

## Problem

Most scam checkers are rule-based: keyword lists, blacklists, domain reputation. They break on three things that matter in India:

1. **Message-only scams.** Digital arrest, fake KYC and parcel/customs scams usually arrive as a text or call script with no link at all.
2. **Rephrased and code-mixed text.** Hinglish and Kannada variants, typos and paraphrases evade keyword rules.
3. **Fresh infrastructure.** New domains aren't on any blacklist yet.

Reputation sites such as ScamAdviser answer "is this website trustworthy?". This project answers "is this message a scam, and which manipulation tactic is it using?"

## Objectives

1. Build a hybrid detector with a **text head** (message content) and a **URL head** (link structure), fused into one verdict with a warning-sign meter (not a probability, D4 / D24).
2. Explain every flag: rule and link-check evidence plus **tactic tags** (authority impersonation, urgency, isolation, payment redirection). Token-level attributions were planned; the code exists but the UI does not show them.
3. Beat a rule-based baseline, measured with precision, recall, F1 and **false-positive rate on legitimate bank/OTP SMS**.
4. Measure **adversarial robustness** (paraphrase, typos, homoglyphs, code-switching, URL obfuscation), then retrain with augmentation and show recovery.
5. Create a small, documented **India-specific scam message dataset** (English, Hinglish, Kannada), anonymized, with a datasheet and inter-annotator agreement.
6. Validate with people: a **user study (15-20 participants)** comparing scam-spotting accuracy with and without the explanations, plus at least one stakeholder conversation (bank or cyber cell contact).
7. Ship a minimal web UI (paste text or a link, get a score and reasons) and a reproducible repo where one command regenerates every table.

## Scope

**In scope:** scam taxonomy (digital arrest, fake KYC, parcel/customs, job offer, lottery, benign); text and URL models; fusion and calibration; explanations; adversarial evaluation; user study.

**Out of scope / cut first if time is short:** malicious-app (APK) analysis, Kannada samples, character-level URL CNN (keep gradient boosting).

**Never cut:** the India-specific dataset, the adversarial results, the user study.

## Architecture

As built (full description and decision IDs in `docs/ARCHITECTURE.md`; the decision log is `docs/decisions/README.md`):

| Component | Approach |
|---|---|
| Text head | Fine-tuned MuRIL (D27, `models/finetune/muril_len128_...`); the TF-IDF + logistic regression head stays as `SHIELD_TEXT_HEAD=baseline`. Every text model reads `textprep.model_text` |
| URL head | Gradient boosting on host-only lexical features (D8). On its own it is capped at Suspicious; Likely scam from a link needs a link-check red flag |
| Link checks | Offline lists (OpenPhish, URLhaus, Tranco), brand look-alike / homograph / raw-IP rules, gambling lookup, and live domain-only checks (RDAP, DNS-over-HTTPS, optional Safe Browsing) through one network module; no link is ever opened (D23) |
| Rules | Hard rules that only raise the verdict: OTP / PIN / CVV request, PIN-to-receive (R2), investment rules A1-A12. They match on a folded view of the text that undoes look-alike characters and leetspeak (D11); the models never see it |
| Language cap | In Hindi, Kannada and Hinglish a Likely scam that only the text head produced is shown as Suspicious with a "less tested" reason (D5 / D6) |
| Fusion | The max rule: the higher of the text and link levels, both at least Suspicious gives Likely scam. A fitted meta-model was not built |
| Calibration | Temperature scaling fitted on validation, used to set the level cut-offs. The 0-100 risk score is a warning-sign meter inside the band of the final level, **not a probability**, and no percentage is shown (D4, D24) |
| Explainability | The top three reasons come from rules, link evidence, tactic tags and then the text model, with the exact phrase underlined. Word-level occlusion exists in code but nothing calls it since Gradio was retired (BUGS.md) |
| Baseline (control) | TF-IDF text baseline exists (`src/baseline.py`). The rules-only baseline and the ablation table are not built yet (see Status) |

## Data

| Source | Use | Notes |
|---|---|---|
| OpenPhish, PhishTank | Phishing URLs | Snapshots go stale; record download date |
| URLhaus | Malware URLs | Kept as a separate class (mostly raw-IP hosts, an easy shortcut) |
| Tranco | Benign domains | Bare domains only; see the shortcut warning below |
| `msgs` dataset | Main text data | ~85% synthetic, English only; **test on real messages only** |
| `sms` dataset | Benign / generic spam text | Spam is not the same as scam; map labels carefully |
| Own collection | **Held-out test set** (TEST half) and real training / validation material (POOL half) | SMS and WhatsApp exports from family phones (the Google Form got no responses), PII masked at intake. One grouped freeze splits the labelled template groups into TEST (scored once at the end, never trained or tuned on) and POOL (used for training and validation in splits-v3); decision D-a. Advisories and news quotes are collected by hand into `data/collected/` |

`txn` (transaction-fraud tabular data) was dropped: it isn't text or URLs, and has heavy duplication and untrustworthy labels.

### Known data pitfalls (handled in the pipeline)

- **Shortcut features:** malware URLs are ~88% raw-IP hosts with paths, and benign Tranco rows are bare domains. A model can score high on `has_ip` / `has_path` alone. Main task is therefore **phishing vs. benign on host-only URLs**; malware is reported separately.
- **Leakage:** URL splits are grouped by registered domain; text splits are grouped by template/near-duplicate cluster. The test set is frozen after week 8.
- **Synthetic text:** train on synthetic + real, test only on real, and report the domain-shift gap as a finding.
- **Class imbalance:** use class weights; report precision/recall/FPR, not accuracy.
- **Small test sets:** phishing rows must reach a few thousand before test metrics are trusted.

## Evaluation

- Precision / recall / F1 and false-positive rate (legit bank/OTP SMS)
- Ablation: rules only, text only, URL only, fused (not built yet: planned after splits-v3, validation set first)
- Calibration plot and expected calibration error (not built yet, same plan)
- Adversarial suite: recall drop per attack for baseline vs. model, then recovery after augmentation
- Real-only test set vs. synthetic test set (domain-shift gap)
- User study: accuracy with vs. without explanations

## Plan (TLP weeks 7-15)

| Phase | Weeks | Work | Deliverable |
|---|---|---|---|
| 1. Scope and data | 7-8 | Approve problem statement, fix taxonomy and labelling rules, collect India-specific messages, pull public data, build rule baseline, freeze splits | Concept note + baseline numbers |
| 2. Models | 9-10 | URL head, text head, fusion, calibration, explanations, tactic tags, minimal UI | Ablation table + working prototype |
| 3. Stress test | 11 | Attack suite, augmentation retrain, FPR on legit SMS | Robustness table + calibration plot |
| 4. Field validation | 12 | User study (recruit by week 10), feedback form, stakeholder conversation, photos and attendance as evidence | Study data + feedback note |
| 5. Write-up | 13-15 | Report, one-command reproduction script, slides, mock viva, final submission, optional dataset release | Final report, deck, viva |

This table is the original plan. The dated timeline that is actually being followed (splits-v3 build, retrain, gates, final test) is in `docs/plans/splits_v3.md`.

**Risks:** fewer than ~200 India-specific samples by end of week 9 (extend collection, lean on augmentation); test-set leakage; recruiting the user-study participants late.

## Status

- [x] Topic chosen and scoped (#19)
- [x] URL pull script (`src/pull_urls.py`): URLhaus, OpenPhish, Tranco
- [x] URL build script (`src/build_urls.py`): combine, dedupe, registered-domain split, shortcut check
- [ ] PhishTank snapshot added (rate-limited by Cloudflare, retry later)
- [x] Source registry (`data/sources.yaml`) + Hugging Face puller (`src/pull_hf.py`); manual sources in `MANUAL_DOWNLOADS.md`
- [x] Text dataset normalization, PII masking, dedupe, splits (`src/build_text.py` → `data/final/messages.csv`, 49,931 rows at splits-v2)
- [x] Synthetic India templates in English / Hinglish / Hindi / Kannada, scam + benign pairs (`src/synth_india.py`)
- [x] Typosquat / IDN lookalike candidates for Indian brands (`src/gen_typosquat.py`); RDAP domain age (`src/enrich_domains.py`, partial cache)
- [x] Character-level adversarial suite: train augmentation + held-out adversarial test (`src/augment.py`)
- [x] App permissions table (`src/build_apps.py`, optional module)
- [x] TF-IDF smoke-test baseline (`src/baseline.py`)
- [ ] Rule-based baseline (rules-only control): not built; moves to the ablation item below
- [x] Real-message intake and labeller from our own phones (`src/intake_real.py`, `src/label_real.py`; the Google Form got no responses). Grouped TEST / POOL freeze (D-a) done 2026-10-30 (`real_test_v1.csv`: 988 rows / 583 groups, 98 scam; POOL 985 rows / 580 groups; single annotator, no second-labeller kappa; hash in CLAUDE.md); advisories are collected by hand (the RBI site blocks scrapers)
- [ ] More Hinglish/Hindi/Kannada templates (current splits are lumpy: e.g. no Hinglish scam in test)
- [x] Hindi / Kannada machine translations with IndicTrans2, train only (D20, D26); paraphrase / back-translation augmentation was not done
- [x] Freeze splits (`data/final/split_map.csv`, tag `splits-v1`; re-frozen with the Hindi / Kannada translations and the PII-mask fix as `splits-v2`, 2026-10-21)
- [x] URL head (`src/url_head.py`)
- [x] TF-IDF text head (`src/baseline.py`)
- [x] Fine-tuned MuRIL text head (D27, `reports/eval_muril_v2.md`: test F1 0.918 vs 0.897 for TF-IDF), leave-one-source-out run for MuRIL (section 9 of that report)
- [x] Fusion (max rule), temperature calibration for the cut-offs, rule / evidence reasons and tactic tags
- [x] Adversarial suite (held-out attack types, `messages_adv_test.csv`)
- [x] Folded view for the rules, so look-alike characters and leetspeak do not hide a rule hit (D11)
- [x] Language cap for Hindi / Kannada / Hinglish (D5 / D6, backend)
- [x] Live and offline link checks (D23) and gambling links (G1)
- [x] Investment-scam rules A1-A12 (Phase A, `docs/plans/investment_scams.md`)
- [x] Gradio MVP (`src/app.py`, retired 2026-10-28: replaced by the React frontend + FastAPI API, D9; start the app with `./run.sh`)
- [x] Screenshot input: `POST /api/ocr` (local Tesseract, D19) and the paste / drop / picker UI
- [x] splits-v3 B0 code (versioned masks, POOL loader, company key, gates; no data or model written yet, `docs/plans/splits_v3.md`)
- [ ] splits-v3 build, retrain on Kaggle, gates and re-evaluation (1-5 Nov, `docs/plans/splits_v3.md`)
- [ ] Rules-only baseline, ablation table (rules / text / URL / fused) and calibration plot with ECE: planned after splits-v3, validation set first (BUGS.md)
- [ ] Final real-message test (`src/eval_real.py --final`, once, 5 Nov)
- [ ] Hindi / Kannada reasons and advice in the UI with the "under review" mark, and the "experimental" note (D6, D17)
- [ ] User study (D13, mid / late November)
- [ ] Report, slides, viva

## Repo layout

```
data/sources.yaml   # registry of every dataset: access method, licence, verified date
data/raw/           # dated URL feed pulls only (build_urls.py globs it) (gitignored)
data/external/      # other pulls, by module: text/, indic/, urls/, apps/ (gitignored)
data/final/         # combined, deduped, split tables (gitignored)
src/
  pull_urls.py      # fetch URLhaus / OpenPhish / Tranco
  build_urls.py     # combine (+ ISCX if present), dedupe, split, domain age, shortcut check
  pull_hf.py        # fetch every `access: hf` source in sources.yaml
  synth_india.py    # template-generated multilingual India scam + benign messages
  build_text.py     # normalise, mask PII, dedupe, cluster near-duplicates, split -> messages.csv + split_map.csv
  neardup.py        # near-duplicate clustering + the cross-split leakage check (used by build_text, augment, split_audit)
  split_audit.py    # read-only: cross-split near-duplicate pairs, per-source val/test exposure, cluster sizes
  scrape_web.py     # Firecrawl every URL in data/sources.csv -> data/raw_web/ (cached)
  extract_scams.py  # verbatim scam quotes from data/raw_web/ -> data/extracted/web_scams.csv
  augment.py        # adversarial variants: train attacks -> messages_aug.csv, held-out attacks -> messages_adv_test.csv
  gen_typosquat.py  # brand lookalike domains -> typosquat_candidates.csv
  enrich_domains.py # RDAP registration dates (cached)
  build_apps.py     # Android permission table -> apps.csv
  baseline.py       # TF-IDF + logistic regression smoke test
MANUAL_DOWNLOADS.md # datasets behind forms / accounts
README.md
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
export URLHAUS_KEY=your_key_here   # never commit keys
python src/pull_urls.py
python src/enrich_domains.py 500   # optional, RDAP lookups, cached; repeat to cover more domains
python src/build_urls.py
python src/pull_hf.py
python src/synth_india.py
python src/build_text.py
python src/split_audit.py   # optional: how much near-duplicate leakage is left
python src/augment.py
python src/gen_typosquat.py
python src/build_apps.py
python src/baseline.py
```

Add a `.gitignore` containing `.venv/` and `data/`.

### Start everything

```bash
./run.sh                 # frees ports 8000 / 5173, refreshes link lists older than 24 h (120 s limit, never blocks), starts API + frontend
./run.sh --skip-update   # no list refresh
./run.sh --force-update  # refresh now
```

It prints the local URL, the phone URL (same Wi-Fi) and the list ages; Ctrl+C stops both. The URLhaus refresh needs `URLHAUS_AUTH_KEY` in the environment (never printed); without it that list is kept as it is. Downloads happen only in `src/update_link_lists.py`.

### Screenshot input (OCR)

Checking a screenshot needs [Tesseract](https://github.com/tesseract-ocr/tesseract) (open source, runs on your machine; the image is read in memory, never stored and never sent anywhere):

```bash
brew install tesseract tesseract-lang     # developed with Tesseract 5.5.3; needs the eng, hin and kan language data
tesseract --version && tesseract --list-langs | grep -E '^(eng|hin|kan)$'
uvicorn shield.api.main:app --host 127.0.0.1 --port 8000     # restart a running server after pulling: /api/ocr is a new route
curl -F image=@screenshot.png http://127.0.0.1:8000/api/ocr  # -> {"text", "lines", "dropped", "ms"}
python tests/test_ocr.py                                     # draws its own test images in memory
```

`/api/ocr` only returns the text; the page shows it so the user can check and correct it, and then posts it to `/api/analyse`. Check the amounts: Tesseract often misreads or drops the rupee sign (BUGS.md).

## Ethics and data handling

- No personal data in the dataset: phone numbers, emails, UPI IDs, account numbers and victim names are masked at ingestion.
- Scraped news/advisory text: keep only the quoted scam message, plus source URL and date; do not redistribute full articles.
- Malicious URLs are stored as strings only and never visited from a personal machine.
- Respect each source's terms of service and robots.txt.
- API keys live in environment variables, not in the repo.

## Related work

ScamAdviser and similar website-reputation tools (URL trust scoring); SMS spam collections; PhishTank / OpenPhish feeds. Gap addressed: message-level, multilingual, India-specific scam detection with explanations and measured robustness.
