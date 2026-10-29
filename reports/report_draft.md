# Scam Shield: Hybrid Machine-Learning Detection of India-Specific Scam Messages

**Project report (first draft, 2026-10-29)**

VTU Community / Societal Project 1BCP308, Semester 3, topic #19: *Cyber Security Awareness Platform for Phishing, Digital Arrest Scams, and Malicious Applications*

| | |
|---|---|
| Submitted by | [FILL: student name(s) and USN(s)] |
| Guide | [FILL: guide's name and designation] |
| Department / institution | [FILL: department, college name, VTU affiliation] |
| Academic year | [FILL: academic year] |
| Date of submission | [FILL: date] |

> **How to read this draft.** Every number is copied from a file in the repository and cited inline as *(file §section)*. `[PLACEHOLDER: ...]` marks a result that does not exist yet; `[CHECK: ...]` marks a place where two files disagree or a source is unreviewed; `[FILL: ...]` marks information only the authors can supply. "Internal test" always means the frozen internal test split of splits-v2, never the real-message test set.

---

## 1. Abstract

Scam messages in India increasingly arrive with no link at all (digital arrest, fake KYC, parcel and job scripts), are written in English, Hindi, Kannada or code-mixed Hinglish, and use domains too new to appear on any blacklist (README.md "Problem"). This project, Scam Shield, builds a local web application that reads a pasted message or a screenshot and returns one of five verdict levels, the three main reasons, and advice on what to do next. It combines a fine-tuned multilingual encoder (MuRIL) for the message text, privacy-preserving checks on each link's background (never its content), and hand-written rules that can only raise a verdict. On the frozen internal test split (5,711 messages) MuRIL reaches F1 0.918 against 0.897 for a TF-IDF baseline, AUROC 0.986 against 0.980 (reports/eval_muril_v2.md §2). Leave-one-source-out evaluation shows the main weakness: on an unseen Indian SMS source both models fail (AUROC 0.768 and 0.766), and MuRIL passes only 11.6% of genuine messages at the 0.5 cut-off (reports/eval_muril_v2.md §9). The link checks flag 72% of 96 fresh phishing links with 8% false alarms on 200 benign domains, measured with the source lists switched off (reports/eval_live_links.md §10). A once-only test on real messages from the authors' families' phones is pending. [PLACEHOLDER: one sentence with the real-message test result and the splits-v3 outcome.] [PLACEHOLDER: one sentence with the user-study result.]

---

## 2. Introduction

### 2.1 The scam problem in India

Reported cyber-financial fraud in India has grown sharply. A Lok Sabha written reply of 22 July 2025 reported losses of Rs 7,465.18 crore in 2023 and Rs 22,845.73 crore in 2024, with 36,37,288 financial-fraud incidents reported on the National Cybercrime Reporting Portal (NCRP) and the Citizen Financial Cyber Fraud Reporting and Management System (CFCFRMS) in 2024 (docs/opportunities/research_notes/Scam Shield next feature 2/india_scam_numbers.md §1). "Digital arrest" scams, in which a caller impersonates police or another agency and keeps the victim on a video call until money is transferred, rose from 39,925 cases and Rs 91.14 crore in 2022 to 1,23,672 cases and Rs 1,935.51 crore in 2024, according to a Rajya Sabha written reply of 12 March 2025 (same file, §3). In 2025, investment fraud accounted for about three quarters of the money lost (76% in MHA data reported by ThePrint; 77% in I4C data reported by the Indian Express) while digital arrest accounted for 8-9% (same file, progress log). Bengaluru police data for 2022 to June 2026 show investment (trading) cases rising from 183 in 2022 to 2,648 in 2025, and part-time job or task scams from 228 to 2,158 (same file, progress log).

[CHECK: the research note `india_scam_numbers.md` is headed "DRAFT – unfinished research notes. Not reviewed; figures and citations may be incomplete or wrong." Every figure in this subsection must be verified against the primary source (sansad.in replies, I4C) before submission. The note also gives two different 2025 totals: Rs 22,495 crore (MHA data via Free Press Journal and ThePrint) and Rs 19,812.96 crore (I4C data via the Indian Express); the report should quote one, with its source, or both with the difference explained.]

### 2.2 Why existing checkers fall short

Most scam checkers available to the public are rule-based: keyword lists, blacklists and domain reputation. The project's problem statement names three ways in which they fail in India (README.md "Problem"):

1. **Message-only scams.** Digital arrest, fake KYC and parcel / customs scams often arrive as text or a call script without a link, so a URL checker has nothing to check.
2. **Rephrased and code-mixed text.** Hinglish and Kannada variants, typing errors and paraphrases evade fixed keyword rules.
3. **Fresh infrastructure.** A newly registered domain is not yet on any blacklist.

Website-reputation services such as ScamAdviser answer the question "is this website trustworthy?". This project answers a different question: "is this message a scam, and which manipulation tactic is it using?" (README.md "Problem").

### 2.3 Why a community project

[FILL: two to four sentences on the community context, e.g. who in the authors' community receives such messages, any incident that motivated the topic, and how the tool is meant to be used (by an individual on a phone, or by a family member helping an older relative).]

The project is community-facing in four concrete ways that are already built or decided. First, the application runs locally and can be opened from a phone on the same hotspot, so it can be demonstrated to family members and study participants without hosting their messages anywhere (docs/decisions/README.md, D1). Second, every warning verdict ends with the national cyber-fraud helpline (1930) and cybercrime.gov.in, with an English / Hindi / Kannada switch (docs/ARCHITECTURE.md §6; docs/decisions/README.md, U1). Third, the real-message evaluation set comes from the authors' families' phones, with the owners' consent (docs/decisions/README.md, D-a). Fourth, a small user study with family members and classmates is planned (docs/decisions/README.md, D13). [FILL: any stakeholder conversation held, e.g. with a bank branch or the cyber cell; README objective 6 promises at least one, and D15 notes a cyber-cell reviewer is added "only if the Dean can connect one".]

### 2.4 Organisation of this report

Section 3 states the objectives. Section 4 reviews related work. Section 5 describes the system as built and Section 6 the data. Section 7 describes the models and Section 8 their evaluation. Section 9 describes the method of the real-message test. Sections 10 to 13 cover ethics, limitations, future work and conclusions.

---

## 3. Objectives

The objectives are those of the project specification (README.md "Objectives"). The status column records what the repository shows on 2026-10-29.

| # | Objective (README.md) | Status |
|---|---|---|
| 1 | A hybrid detector with a text head and a URL head, fused into one verdict with a warning-sign meter that is not a probability (D4 / D24) | Built. Text head MuRIL (D27), host-only URL head (D8), max-rule fusion (docs/ARCHITECTURE.md §2 "Fusion") |
| 2 | Explain every flag: rule and link-check evidence plus tactic tags (authority impersonation, urgency, isolation, payment redirection); token-level attributions | Rule, link and tactic reasons built. Token-level attribution code exists but nothing calls it since the Gradio app was retired (BUGS.md "MuRIL text head (D27): known limits" item 3) |
| 3 | Beat a rule-based baseline, measured with precision, recall, F1 and false-positive rate on legitimate bank / OTP SMS | Partly. The TF-IDF baseline exists and is beaten (Section 8.2). The rules-only baseline is not built (BUGS.md "Rules-only baseline and ablation table not built"). [PLACEHOLDER: rules-only baseline and false-positive rate on real genuine bank / OTP SMS] |
| 4 | Measure adversarial robustness, then retrain with augmentation and show recovery | Measured (Section 8.5). The augmented retrain did **not** recover robustness on held-out attacks (Section 7.4) |
| 5 | A small, documented India-specific scam dataset (English, Hinglish, Kannada), anonymised, with a datasheet and inter-annotator agreement | In progress. Real-message intake and labelling built (Section 6.8); [PLACEHOLDER: datasheet; inter-annotator agreement (kappa) from `src/double_label.py`] |
| 6 | A user study (15-20 participants) comparing scam-spotting accuracy with and without the explanations, plus at least one stakeholder conversation | Not run. [CHECK: README.md objective 6 says 15-20 participants; decision D13 (docs/decisions/README.md) says "about 8-10 people". The report should state the decided number.] [PLACEHOLDER: user-study results] |
| 7 | A minimal web UI (paste text or a link, get a score and reasons) and a reproducible repository | UI built (React + FastAPI, D9) with screenshot input (D19). [PLACEHOLDER: one-command reproduction script; README.md "Status" lists "Report, slides, viva" and the reproduction as open] |

---

## 4. Related work

### 4.1 Reputation services, feeds and spam corpora

The project specification places the work against three existing families of tools (README.md "Related work"): website-reputation services such as ScamAdviser, which score a URL's trustworthiness; public SMS spam collections, such as the UCI SMS Spam Collection used here; and phishing feeds such as PhishTank and OpenPhish. The gap it addresses is message-level, multilingual, India-specific scam detection with explanations and measured robustness (README.md "Related work").

Spam and scam are not the same task. The UCI collection labels marketing spam, and much of it is genuine promotion; the labelling guide for this project counts marketing from a real, registered business as genuine "because spam is not the same as scam" (docs/labelling_guide.md).

### 4.2 Warnings at the moment of risk

The project's research notes summarise several studies on whether warnings change behaviour [CHECK: from `papers_patents.md`, headed "DRAFT – unfinished research notes. Not reviewed"; verify each against the paper]:

- Lain, Kostiainen and Capkun (IEEE S&P 2022) followed 14,733 employees for 15 months. Warnings on suspicious e-mails reduced dangerous actions by about 64-70%, with no significant difference between short and detailed warnings, while embedded phishing training did not help and was associated with more dangerous actions (papers_patents.md "Primary-source checks").
- Ho et al. (IEEE S&P 2025) ran an 8-month study with 19,789 staff and found that embedded training reduced the average failure rate by only 2% (papers_patents.md "Primary-source checks").
- Akesson, Gathergood and Quispe-Torreblanca (CeDEx discussion paper 2023-08) found in an experiment with 15,888 UK adults that a risk-based warning with clear call-to-action buttons cut fraudulent payments by about 81% relative to control, while behavioural warning texts decayed with exposure (papers_patents.md "Primary-source checks").
- Parihar et al. (2024) tested prebunking videos on misinformation in India and found effects on a minority of items, with some videos backfiring (papers_patents.md "Primary-source checks").

These results support the design choice of a per-message, specific warning with concrete next steps rather than general awareness content, and they motivate the planned user study (Section 12).

### 4.3 Deployed detection and Indian interventions

Large platforms have shipped scam detection in India: Google's on-device call-scam detection (Pixel 9 and later, off by default) and Play Protect's blocking of side-loaded apps that request SMS or accessibility permissions, and Truecaller's Family Protection (papers_patents.md "Shipped detection by big players") [CHECK: unreviewed note]. Indian public interventions include the 1930 helpline and CFCFRMS, the Department of Telecommunications' Financial Fraud Risk Indicator, and NPCI's ending of UPI peer-to-peer collect requests from 1 October 2025 (papers_patents.md "India: state of play") [CHECK: unreviewed note]. None of these reads the text of a message a person has already received and explains it in their language; that is the space this project occupies.

### 4.4 Research datasets and models

Public scam-detection data for Indian languages is scarce: the research notes found only small community Hinglish sets (35 Hinglish scam rows in one Hugging Face set) (papers_patents.md "India: state of play"), and the project's own audit rejected the public candidates it could check (docs/plans/data_acquisition.md §1 item 6; reports/dataset_audit.md). Korean vishing corpora and several 2025-2026 multi-turn scam-conversation benchmarks exist (papers_patents.md "Research detection") but do not cover Indian languages.

The text model is MuRIL (`google/muril-base-cased`), a BERT-style encoder pre-trained on English and Indian languages (reports/eval_muril_v2.md §1). Hindi and Kannada training rows were produced with IndicTrans2 (`ai4bharat/indictrans2-en-indic-1B`) (data/sources.yaml, `indictrans2_en_indic`). [FILL: citations for MuRIL (Khanuja et al., 2021) and IndicTrans2 (Gala et al., 2023) in the authors' chosen reference style; these papers are not in the repository's notes.]

---

## 5. System design (as built)

The design is recorded in docs/ARCHITECTURE.md, written once after decisions D1-D18 were all taken (2026-10-28); the decision log docs/decisions/README.md is the source of truth (docs/ARCHITECTURE.md, preamble). Its target sentence is: *a person pastes or screenshots a message in English, Hindi, Kannada or Hinglish, and within a few seconds gets a correct verdict, the reasons, and what to do next, with few false alarms on normal messages* (docs/ARCHITECTURE.md, preamble).

### 5.1 Overview and message flow

The product is a Python package (`src/shield/`) behind a FastAPI JSON API, with a React + Vite + Tailwind + Motion frontend (docs/decisions/README.md, D9). The message flow is (docs/ARCHITECTURE.md §2 "Message flow"):

```
image -> local OCR (in memory) -> text the user checks and edits -> POST /api/analyse
text -> links extracted -> model_text(text) -> text head (calibrated) -> text level
     -> rules (OTP / PIN / CVV, PIN-to-receive, investment A1-A12) -> floors
     -> each link: host-only URL model + offline checks [+ live checks]
     -> fuse(text level, URL level) -> link positives P1 / P2 -> language cap
     -> level, risk score, reasons, advice
```

The page first asks for an offline analysis with no network call, shows the verdict, and then asks for the live link checks and updates the link cards, so a slow registry never delays the verdict (docs/ARCHITECTURE.md §1 principle 1).

### 5.2 Three layers

**Layer 1: the text model.** A fine-tuned MuRIL classifier reads the message after one shared preprocessing function, `textprep.model_text`, which replaces every link (including defanged `hxxp` / `[.]` forms and `[Link]` placeholders) with the token `<URL>` and cuts the text to 2,000 characters (CLAUDE.md, hard rule 11). Every text model in the project, including the TF-IDF baseline, reads this function, so a model is never scored with a different preprocessing from the one it was trained on (CLAUDE.md, hard rule 11). The TF-IDF head remains selectable with `SHIELD_TEXT_HEAD=baseline` (docs/decisions/README.md, D27).

**Layer 2: link checks.** Each link's *background* is checked, never its content (docs/decisions/README.md, D23). The signals are (docs/ARCHITECTURE.md §5.1):

- a host-only gradient-boosting URL model (D8), which on its own may raise a link to Suspicious at most (C2), with a flag threshold of 0.662 (C3);
- offline lists: OpenPhish and URLhaus (red flag R1), Tranco popularity (positive P2 for the top 10,000), a gambling lookup (G1), verified brand top-level domains and `.bank.in` (positive P1);
- offline rules: Indian brand look-alikes (R4), an exact brand name on a non-official domain (R10), IDN homographs (R3), raw IP hosts (R5);
- live, domain-only checks: RDAP registration date (R7: under 30 days), Cloudflare DNS-over-HTTPS with an offline IP-to-ASN table (R6: shares a server with listed hosts), Google Safe Browsing hash prefixes only when a key is set (R2), and the crt.sh certificate date (R8), which is off by default (C1);
- shortener expansion, only when the user presses a button (D3).

The signals are combined by a transparent ladder rather than a learned model, because a model trained on these sources would learn when each lookup happened (Tranco domains are old by construction; feed domains looked up days later have been taken down) (docs/ARCHITECTURE.md §5.2). R1, R2, R3 and two or more of R4-R8 / R10 give Likely scam; any one of R4-R8 or R10 gives Suspicious; a free-hosted or unexpanded short link with no hit gives Can't judge (docs/ARCHITECTURE.md §5.2; docs/decisions/README.md, D14, D16).

**Layer 3: raise-only rules.** Hand-written rules act as floors after the model (docs/ARCHITECTURE.md §1 principle 3; docs/decisions/README.md, D16):

- a request to send, share or forward an OTP, PIN, CVV or password forces at least Suspicious; genuine "do not share" alerts are negation-checked (CLAUDE.md "App rules");
- the PIN-to-receive rule R2: a UPI PIN asked for near a receive-money cue forces at least Suspicious, because receiving money never needs a PIN (docs/decisions/README.md, R2);
- the investment-scam rules A1-A12 (for example guaranteed returns, pay-to-withdraw, VIP tips groups, IPO pre-allotment), which only raise (reports/investment_rules_v1.md §1);
- the gambling floor: a link in the gambling class shows Suspicious with its own reason, never "scam" (docs/decisions/README.md, G1).

The only rules that can *lower* a verdict are the positive link signals P1 / P2, which apply only when there is no hard-risk signal and never against a red flag on the same link, and the language cap (Section 5.5) (docs/ARCHITECTURE.md §1 principle 3).

### 5.3 Fusion and verdict levels

The shipped fusion is the *max rule*: the higher of the text and URL levels, and both at least Suspicious gives Likely scam. The fitted logistic-regression fusion of the original plan was not built; the max rule stays unless a fitted one beats it on validation and per source (docs/ARCHITECTURE.md §2 "Fusion").

There are five verdict levels (docs/ARCHITECTURE.md §1 principle 2):

| Level | Meaning |
|---|---|
| Likely scam | Strong evidence of a scam |
| Suspicious | Some warning signs |
| No warning signs found | Nothing found; deliberately never "Safe" |
| Promotional | Only with a registered promotional sender ID, which the UI no longer asks for (D18, D22) |
| Can't judge | Fewer than 3 words once links are removed and no link that could be scored, or only links that cannot be judged |

The top three reasons come from rules, link evidence, tactic tags and then the text model, in that order, so explanations survive a change of text model (docs/ARCHITECTURE.md §1 principle 4). Warning cues are shown only when the verdict is at least Suspicious, so a genuine bank alert is not shown "authority" as a red flag (docs/ARCHITECTURE.md §6 item 5).

### 5.4 No percentage: the warning-sign meter (D4, D24)

No percentage is ever shown (docs/decisions/README.md, D4). The 0-100 `risk_score` is a warning-sign meter inside the band of the final level: No warning signs 0-29, Suspicious 30-69, Likely scam 70-100, and no score for Can't judge; the contract refuses a score outside its level's band, so the number can never contradict the verdict (docs/decisions/README.md, D24 "The risk score"). The page states under the meter: "Higher = more warning signs. Not a percentage chance." (same section). For MuRIL the score is interpolated in log-odds between the Suspicious cut-off (30) and the Likely-scam cut-off (70), with the ends at the 1st and 99th percentiles of the calibrated validation scores (reports/calibration_muril_v2.md §3). When a brand-owned link (P1) actually lowers a verdict, a calm "Lowered from..." line explains why (docs/decisions/README.md, D24).

### 5.5 Language cap (D5, D6)

There is no real Hindi or Kannada data in the training or validation sets (Section 6.6), so these languages are labelled experimental until real numbers exist (docs/decisions/README.md, D6). The backend half of this decision is built: `shield.core.lang.detect_lang` classifies a message as English, Hindi, Kannada, Hinglish or unknown by script share and a Latin-script Hindi word list, and in Hindi, Kannada and Hinglish a Likely scam that *only the text model* produced is shown as Suspicious, with the reason "This language is less tested; treat this as a warning, not a verdict." (docs/decisions/README.md, D6). Link evidence, the OTP / PIN rules and the investment rules are not capped. On validation (5,267 rows) the cap found 81 Hinglish rows, 0 Hindi or Kannada rows, and changed 0 levels (docs/decisions/README.md, D6). The cap lifts per language only by decision, once at least 150 real development templates exist in that language (docs/decisions/README.md, D5). [CHECK: docs/decisions/README.md D5 says ">= 150 real-dev templates"; docs/ARCHITECTURE.md §1 principle 3 says ">= 150 real-dev hard-legit messages". Use one wording.] The in-app "experimental" note and the Hindi / Kannada reason lines are not yet shown in the UI (docs/decisions/README.md, D6, D17).

### 5.6 The folded view for rules (D11)

Look-alike characters, invisible characters and leetspeak can hide a rule hit (for example `0TP` or a Cyrillic letter inside "OTP"). Decision D11 makes rules, tactic cues and fear cues match on a *folded view* of the text (Unicode NFKC, zero-width characters removed, homoglyphs and in-word leet folded), while the models keep reading only `textprep.model_text`, so the model input is unchanged (docs/decisions/README.md, D11). Quotes and underlines map back to the user's own characters, and a rule that fires only on the folded view adds the reason "Hidden or look-alike characters were used to disguise the wording." (CLAUDE.md, "Folded view for the rules"). Results are in Section 8.10.

### 5.7 Privacy design

Privacy is a property of the code, not only a policy:

- **Links are never visited.** Hard rule 8 forbids loading a page from a message, connecting to its server or IP, or following its redirects (CLAUDE.md, hard rule 8). Exactly one module, `src/shield/core/net.py`, may make outbound calls: HTTPS only, an exact host allowlist, IP literals refused, redirects never followed, at most 2 s per call and 4 s per message (docs/ARCHITECTURE.md §1 principle 5). A test patches sockets and checks that link-bearing input analysed offline makes zero network attempts (docs/ARCHITECTURE.md §1 principle 5, `tests/test_api.py` T7).
- **Only a registered domain leaves the machine**, never message text; Safe Browsing receives only 4-byte hash prefixes; a short link is sent to its shortener only on the user's button press (docs/ARCHITECTURE.md §5.1, §5.4).
- **Nothing is stored.** Text and images are processed in memory and never logged or written; the uvicorn access log shows method, path and status only; screenshots are re-encoded in memory and piped to Tesseract with no temporary file (docs/ARCHITECTURE.md §5.4). The live-check cache is an in-memory LRU of 2,000 entries with a time-to-live per check, gone when the server stops (docs/decisions/README.md, D12). The browser stores one item, the light / dark theme choice (docs/ARCHITECTURE.md §5.4).
- **Masking.** Phone numbers, e-mail addresses, UPI IDs and account-like numbers are masked at ingestion and on app input (CLAUDE.md, hard rule 5; reports/splits_v2.md "Masking").

### 5.8 Screenshot input (D10, D19)

Screenshots are read by local Tesseract 5.5.3 with English, Hindi and Kannada language data, in memory (docs/decisions/README.md, D19). Because the measured character error rate on real screenshots is high (Section 8.11), the OCR text always goes into an editable box that the user confirms before analysis, and the page tells the user to check amounts and links (docs/ARCHITECTURE.md §4; docs/decisions/README.md, D10).

---

## 6. Data

### 6.1 Sources

The text corpus `messages.csv` has 49,931 rows at splits-v2, 25.3% of them scam (CLAUDE.md "Current status"). Rows per source (reports/sanity.md §1):

| Source | Benign | Scam | Synthetic % | Languages | Origin (data/sources.yaml) |
|---|---|---|---|---|---|
| phishing_email | 10,976 | 6,523 | 0 | English | `zefang-liu/phishing-email-dataset` |
| fake_job_postings | 15,252 | 714 | 0 | English | EMSCAD (`victor/real-or-fake-fake-jobposting-prediction`) |
| uci_sms_spam | 4,512 | 629 | 0 | English | UCI SMS Spam Collection |
| india_fraud_final | 1,600 | 1,600 | 86 | English | `india_fraud_detection_FINAL.csv` |
| scam_ham_india | 1,345 | 895 | 0 | English | `scam_ham_india.csv` |
| scam_dialogue | 799 | 799 | 100 | English | `BothBosu/scam-dialogue` |
| synth_india | 652 | 925 | 100 | English, Hinglish, Hindi, Kannada | project templates (`src/synth_india.py`) |
| translated_indic | 1,000 | 142 | 100 | Hindi, Kannada | IndicTrans2 translations (Section 6.6) |
| ealvaradob_phishing | 168 | 405 | 0 | English | `ealvaradob/phishing-dataset` |
| cmu_hinglish_dog | 478 | 0 | 0 | Hinglish | `festvox/cmu_hinglish_dog` |
| hinglish_conversations | 500 | 0 | 100 | Hinglish | `Abhishekcr448/Hinglish-Everyday-Conversations-1M` |
| web_scams | 0 | 17 | 0 | English | quotes from news and advisory pages |

[CHECK: CLAUDE.md "Current status" says `web_scams.csv` has 20 rows; reports/sanity.md §1 counts 17 in `messages.csv`. CLAUDE.md explains the gap ("3 of the 20 quotes were exact copies of existing rows"); the report should say so in one line.] Web scraping was low-yield and has stopped (CLAUDE.md "Current status").

The URL corpus `urls.csv` has 88,818 rows: phishing from the ealvaradob set and an OpenPhish pull, malware from URLhaus, benign from Tranco, and 25,972 `gambling_spam` domains (reports/urls_gambling.md). Malware URLs are mostly raw-IP hosts with paths, so the main URL task is phishing versus benign on host-only URLs, and malware is reported separately (README.md "Known data pitfalls").

### 6.2 PII masking

Masking happens at ingestion and only masked text is stored in `data/final/` (CLAUDE.md, hard rule 5). At splits-v2 the masks in `src/pii.py` were extended with the NPCI UPI handle list and every dotless `user@host` address; rows with an unmasked e-mail-like or UPI-like token fell from 76 to 0 (reports/splits_v2.md "Masking"). Two gaps remain in the shipped data: no person-name masking, and account-like numbers glued to letters (BUGS.md, both entries). A versioned mask set `MASKS_V3` that masks every run of 9 or more digits, greeting names and ALL-CAPS payer names on SMS-type channels has been written but not yet applied to stored rows (CLAUDE.md, "Versioned masks"; reports/splits_v3_b0a.md).

### 6.3 Near-duplicate clustering

Random splits would leak: the same scam template appears many times with different numbers. `src/neardup.py` merges two rows if the exact Jaccard similarity of their character 5-grams (first 2,000 characters) is at least 0.7 on the raw text or on a normalised text (templated prefixes and suffixes stripped, numbers replaced by `<NUM>`), or at least 0.6 within `india_fraud_final` (CLAUDE.md "Near-dup clustering"). Template families of `synth_india`, translations and their English parents, and job posts of the same company (by the first 150 characters of the company profile) are also forced into one group (CLAUDE.md "Near-dup clustering"; BUGS.md "Company grouping only covers job posts with a profile"). At splits-v2 there are 30,048 clusters, 11 of them with mixed labels (reports/splits_v2.md "Downstream files").

### 6.4 Grouped, frozen splits (splits-v1, splits-v2)

Splits are grouped (URLs by registered domain, text by cluster) and frozen in `data/final/split_map.csv`, which is committed and tagged (CLAUDE.md, hard rule 2 and "Current status").

| | splits-v1 | splits-v2 |
|---|---|---|
| Rows | 48,790 | 49,931 |
| SHA-256 of `split_map.csv` | `89eec6f1...838c5` | `8263df1c304de7154290f57f648387ddc396cab303630753aa40200619bd4e6c` |
| Val / test messages | 5,267 / 5,711 | same messages (26 re-keyed by the new e-mail mask) |
| Change | | +1,142 translated rows (train only), -1 train row |

Source: reports/splits_v2.md (header, "What changed", "Val / test membership"). The train split has 38,953 rows (reports/fold_v1.md §3). The build asserts that no frozen row is lost or changes split, and `src/split_audit.py` reports 0 violations of the grouping rule (reports/splits_v2.md "What changed"). A residual remains below the clustering threshold: 360 validation and test rows (3.3%) have a training twin at Jaccard 0.6-0.7, mostly `phishing_email` campaigns (reports/splits_v2.md "Downstream files"; BUGS.md "Template reuse at Jaccard 0.6-0.7").

### 6.5 Adversarial files

`src/augment.py` splits attack families so that training attacks and test attacks differ (CLAUDE.md "Current status"):

- homoglyph, leetspeak and zero-width attacks on training parents go to `messages_aug.csv` (20,022 rows; reports/splits_v2.md "Downstream files");
- character noise, URL obfuscation and spaced keywords on test parents go to `messages_adv_test.csv`, the held-out attack test (1,862 rows from 1,189 parents; reports/splits_v2.md "Downstream files").

[CHECK: BUGS.md "Held-out attack test is thin on real parents" says 1,865 rows, 749 from real parents; reports/splits_v2.md "Downstream files" says the splits-v2 file has 1,862 rows (1,865 was splits-v1) and reports/eval_muril_v2.md §5 counts 746 real-parent variants. The BUGS.md entry predates splits-v2; use 1,862 / 746.]

### 6.6 Hindi and Kannada translations (D20, D26)

There is no real Hindi or Kannada data in the corpus (reports/sanity.md "Flags"). To give the text model some Indian-language signal, 735 English parents (625 benign bank / OTP alerts, 110 scam messages showing a fraud mechanism) were selected (reports/translate_parents.md) and translated with IndicTrans2 1B on the Mac at about 1.41 s per sentence; the full run produced 1,470 translations in 35 minutes (reports/translate_run.md). Protected spans (numbers, links, codes) were marked, and 1,291 translations passed the marker check (CLAUDE.md "Hindi/Kannada translation set"; the recovery-path counts in reports/translate_run.md sum to the same total).

Each language was spot-checked by one native reader on 50 rows (25 scam, 25 benign), of which 47 were answered:

| | Meaning the same (Q1) | Label still right (Q2) | Read as formal | Decision |
|---|---|---|---|---|
| Hindi | 43/47 = 91.5% (Wilson 95% CI 80.1-96.6%); about 88% re-weighted to the pool's 15% scam mix | 46/47 = 97.9% | 18/47 | Borderline against the 90% gate; training augmentation only (D20) |
| Kannada | 47/47 = 100% (92.4-100%) | 47/47 = 100% | 0/47 | Training augmentation only, same terms (D26) |

Sources: reports/spotcheck_hi.md "Scores"; reports/spotcheck_kn.md "Scores"; docs/decisions/README.md, D20, D26. The Kannada decision notes that 47 identical marks from one reviewer make 100% an upper estimate (D26).

After dropping known-bad rows, translations of validation or test parents (to avoid leakage), rows that lost a digit run or link of the parent (D21) and rows whose parent held unmasked PII, 581 Hindi (508 benign, 73 scam) and 561 Kannada (492 benign, 69 scam) translations entered the **training split only** (reports/splits_v2.md "Translation ledger"). Validation still has 0 Hindi and 0 Kannada rows, so no cut-off has seen either language (reports/splits_v2.md "Row counts"). Every Hindi or Kannada metric in this report is therefore on `synth_india` templates and must be read as synthetic (docs/decisions/README.md, D20).

### 6.7 Gambling links

A `gambling_spam` URL class was added for registered domains on both the UT1 and the Blocklist Project gambling lists, or decided by hand in a review sheet; it is a gambling *category*, not a scam verdict (CLAUDE.md "gambling_spam URL class"). The class has 25,972 rows (train 20,801, val 2,599, test 2,572) (reports/urls_gambling.md). The URL head was not retrained on it (CLAUDE.md "gambling_spam URL class").

### 6.8 Real-message intake (D-a, TEST / POOL freeze)

The final test set consists of real messages from the authors' families' phones (SMS backups and WhatsApp exports); the Google Form got no responses (CLAUDE.md "Frozen hashes"). Decision D-a uses the same phones for both a frozen test set and new training material, split once (docs/decisions/README.md, D-a):

1. **Intake** (`src/intake_real.py`): only received SMS; the sender address becomes a `sender_kind` and is dropped; no dates or contact names; messages are masked (phone, UPI, e-mail, card, OTP, account tails, any run of 9 or more digits, names seen in the input) and grouped into templates (digits collapsed, near-duplicate rule) (CLAUDE.md "Real-message intake").
2. **Labelling** (`src/label_real.py`): one label per template group (scam / genuine / skip), no model score shown, walked in priority buckets: the 150 largest groups, groups from a mobile-number sender (scam-enriched by design, trimmed to 400), a seeded random 150, and the rest (CLAUDE.md "Label buckets"; docs/labelling_guide.md).
3. **Freeze** (`--freeze`): the labelled groups are split 50/50 by template group, stratified by label and keyword bucket (investment, task, loan, KYC / bank, delivery, other; seed 20261026); groups with any near-duplicate pair between them move together. The TEST half becomes `real_test_v1.csv` (at most 3 messages per group); the POOL half becomes training and validation material for splits-v3. After the freeze any message of a TEST group, or near-duplicate of a TEST message, is dropped from the POOL (docs/decisions/README.md, D-a; CLAUDE.md "Label buckets").

D-a chose a template-group split on the same phones (option 3 of docs/plans/data_acquisition.md §10) rather than the recommended option of different people, because no other phones were available (docs/decisions/README.md, D-a). The consequence, the *shared-sender optimism caveat*, is discussed in Section 9.

[CHECK: the intake is running on 2026-10-29 and its counts will change; CLAUDE.md "Label buckets" records the first run (5,103 groups; buckets 150 / 400 / 150 / 4,403 after the trim). Recount from the freeze report before quoting any number.] [PLACEHOLDER: freeze date, TEST rows and groups, POOL rows and groups, `real_test_v1.csv` SHA-256 (CLAUDE.md "Frozen hashes", empty today).]

### 6.9 Planned rebuild: splits-v3

splits-v3 adds the POOL as a real source (`phones_pool`, split train / val by template group), applies one mask set (v3) to every source and to app input, and adds a company key for job posts without a profile; the internal test membership stays frozen (docs/plans/splits_v3.md §0). Its success gates were registered before any v3 model exists (docs/plans/splits_v3.md §4; see Section 8.13). [PLACEHOLDER: splits-v3 row ledger, `split_map.csv` SHA-256 and tag, sanity-check results.]

---

## 7. Models

### 7.1 TF-IDF baseline

The baseline is character TF-IDF with logistic regression, trained on the training split only (reports/splits_v2.md "Baseline"). Refitted on splits-v2 for evaluation, its validation-chosen cut-offs are 0.456 (Suspicious) and 0.661 (Likely scam) (reports/eval_muril_v2.md "Test opened"). It is fast (1.86 ms median per message on CPU) and small (8 MB) (reports/eval_muril_v2.md §7).

### 7.2 MuRIL fine-tuning

MuRIL was fine-tuned on Kaggle's free T4 GPUs with `src/finetune.py`: maximum length 128 tokens, batch 16, learning rate 2e-5, 3 epochs, seed 42, class-balanced cross-entropy, best epoch by validation F1 at 0.5, fp16 with gradient scaling on the T4 (CLAUDE.md "Reference: src/finetune.py"; reports/eval_muril_v2.md §1). The script asserts the `split_map.csv` hash, that no cluster, family or company straddles splits, and that augmented parents are in train (CLAUDE.md "Reference: src/finetune.py"). Maximum length 128 beat 256 on validation (F1 0.9514 vs 0.948) (CLAUDE.md "Next, in this order" item 4). The shipped bundle `muril_len128_20261021T135255Z` was trained at commit `06f402e`, best epoch 2 of 3 (reports/eval_muril_v2.md §1). Before test was opened, validation was re-scored on the Mac: the largest score difference from the T4 fp16 scores was 0.00769 and no validation row changed side of the Likely cut-off (reports/eval_muril_v2.md §1).

A cost of the 128-token limit: 98% of `fake_job_postings`, 88% of `scam_dialogue` and 72% of `phishing_email` test inputs are cut, so on those sources the model sees only the opening of the text (reports/eval_muril_v2.md §3).

### 7.3 Calibration and cut-offs

All choices were made on validation (5,267 rows) (reports/calibration_muril_v2.md, header).

- **Temperature scaling.** T = 1.5066; validation log-loss 0.1046 to 0.0855, Brier 0.0201 to 0.0193, 10-bin ECE 0.0176 to 0.0086 (reports/calibration_muril_v2.md §1). On test, reported only after every choice was fixed: Brier 0.0441 to 0.0420, ECE 0.0419 to 0.0266 (reports/calibration_muril_v2.md §4).
- **Cut-offs.** Likely scam = validation maximum F1; Suspicious = the highest cut-off with validation scam recall at least 0.95. On calibrated scores: Suspicious 0.1032, Likely scam 0.4365; 0 validation levels differ from the raw cut-offs (reports/calibration_muril_v2.md §2).
- **Suspicious flag policy** (fixed in advance): MuRIL may not flag more validation genuine messages at Suspicious or above than the TF-IDF baseline. MuRIL flags 1.56% (64 of 4,115) against 4.06% (167 of 4,115) for the baseline, at scam recall 0.9505 vs 0.9523, so the policy did not move the cut-off (reports/calibration_muril_v2.md §2).
- **Score shape.** MuRIL's scores are bimodal: 69.4% of test messages score below 0.01 and 26.5% at 0.99 or above (reports/eval_muril_v2.md §6). On validation 78.0% of messages land in meter range 0-29 and 21.5% in 70-100 (reports/calibration_muril_v2.md §3). A single temperature cannot correct the base-rate shift of class-weighted training (reports/calibration_muril_v2.md §1); this is why the meter is not a probability (Section 5.4).

### 7.4 Augmentation: tested and rejected

A second MuRIL run added the training attacks (`messages_aug.csv`). A rule was fixed before its test results: use the augmented model only if validation F1 is at least 0.946 **and** held-out adversarial recall is at least 0.96 (reports/eval_muril_aug_v2.md "Decision").

| | Plain MuRIL | Augmented MuRIL |
|---|---|---|
| Val F1 (at Likely) | 0.9514 | 0.9549 |
| Adversarial recall at Likely (1,862 variants) | 0.941 | 0.885 |
| spaced_keywords recall (306) | 0.967 | 0.758 |
| Test F1 / precision / recall | 0.918 / 0.929 / 0.908 | 0.891 / 0.916 / 0.868 |
| Test false alarms / missed scams | 112 / 150 | 129 / 215 |

Source: reports/eval_muril_aug_v2.md "Decision". The augmented model failed the adversarial condition; training on homoglyph, leet and zero-width attacks did not carry over to the held-out attack families, so the plain model ships. This answers objective 4 negatively: augmentation with these attack families did not show recovery.

### 7.5 Why MuRIL shipped, and its costs (D27)

| | TF-IDF baseline | MuRIL (shipped) |
|---|---|---|
| Val F1 at Likely | 0.930 | 0.951 |
| Internal test F1 / real-only F1 | 0.897 / 0.885 | 0.918 / 0.906 |
| Test false alarms / missed scams | 81 / 237 | 112 / 150 |
| Adversarial recall at Likely | 0.879 | 0.941 |
| CPU time per message / size | 2 ms / 8 MB | 59 ms / 950 MB |

Sources: docs/decisions/README.md, D27 "Choice"; reports/eval_muril_v2.md §2, §5, §7. Decision D27 records the costs that come with MuRIL: more false alarms on test (50 of the 112 from one test-only benign UPI-collect template), Kannada AUROC 0.878 vs 0.930 (synthetic rows), and long sources seen only through their first 128 tokens (docs/decisions/README.md, D27). Because the internal test split informed this choice between two heads, it is no longer an untouched comparison for these two models; the real-message test set is untouched (docs/decisions/README.md, D27). In the app, MuRIL is ready in about 12 s and uses about 1.0 GB of memory on the Mac GPU (CLAUDE.md "Text head = MuRIL").

### 7.6 URL head

The URL model is scikit-learn histogram gradient boosting on lexical features of the host only (no path or query), trained on the phishing-versus-benign population with domain-grouped splits (reports/url_head.md, header).

| View | Test AUROC | Test PR-AUC | FPR Tranco (test) | FPR ealvaradob benign (test) |
|---|---|---|---|---|
| Host-only (shipped) | 0.859 | 0.760 | 0.083 | 0.091 |
| Full URL | 0.939 | 0.886 | 0.041 | 0.100 |
| Shortcut: URL length only | 0.684 | 0.450 | 0.288 | 0.990 |

Source: reports/url_head.md "Results". The most important feature is the top-level domain (permutation importance 0.128); the brand feature is nearly unused (0.002) (reports/url_head.md "What carries the main model"). The full-URL view is better on paper, but path features partly learn the source (Tranco rows have no path at all), and in a follow-up experiment it flagged 4 of 5 genuine deep links (BUGS.md "Host-only URL head is weak"). The host-only model therefore stays, the full-URL view is the last item of the project (docs/decisions/README.md, D8), and the host-only model alone may raise a link to Suspicious at most (C2). Domain age could not be added as a feature because RDAP coverage of the training rows is 0% (reports/url_head.md "Domain age coverage").

---

## 8. Evaluation

### 8.1 Protocol

- The internal test split was scored **once** per model, after validation was re-scored on the Mac and matched the bundle; predictions are cached with SHA-256 hashes and later reports read the cache and never re-score (reports/eval_muril_v2.md "Test opened"; CLAUDE.md "Next, in this order" item 5).
- Each model uses its own validation-chosen cut-offs; nothing was tuned on test (reports/eval_muril_v2.md, header).
- Results are reported overall, real-only (`is_synthetic = False`), per source, per language and leave-one-source-out, and known shortcuts are flagged (CLAUDE.md, hard rule 3).
- The real-message test set is never trained, tuned or calibrated on and is scored once at the end (CLAUDE.md, hard rules 1 and 12; Section 9).

### 8.2 Internal test: overall

Cells read baseline / MuRIL, each at its own validation cut-offs.

| Slice | n | Scam | F1 | Precision | Recall | Recall at Suspicious | Benign FPR | AUROC |
|---|---|---|---|---|---|---|---|---|
| All test | 5,711 | 1,623 | 0.897 / 0.918 | 0.945 / 0.929 | 0.854 / 0.908 | 0.921 / 0.917 | 0.020 / 0.027 | 0.980 / 0.986 |
| Real-only | 4,396 | 942 | 0.885 / 0.906 | 0.956 / 0.948 | 0.824 / 0.867 | 0.886 / 0.873 | 0.010 / 0.013 | 0.980 / 0.986 |

Source: reports/eval_muril_v2.md §2. "Benign FPR" is the share of genuine rows at Likely scam. MuRIL's gain is at the Likely-scam level (recall 0.908 vs 0.854); at the Suspicious level the two models are level (0.917 vs 0.921), and the scams MuRIL misses it misses completely (scores around 0.002) (reports/eval_muril_v2.md "Reading").

These are in-distribution numbers on the same datasets the models trained on. Section 8.7 shows how much they overstate performance on a new source.

### 8.3 Per source

| Source | n | Scam | F1 (baseline / MuRIL) | Benign FPR | AUROC |
|---|---|---|---|---|---|
| phishing_email | 1,680 | 677 | 0.935 / 0.959 | 0.022 / 0.017 | 0.990 / 0.996 |
| fake_job_postings | 1,848 | 98 | 0.205 / 0.259 | 0.004 / 0.013 | 0.891 / 0.880 |
| synth_india (synthetic) | 821 | 477 | 0.885 / 0.917 | 0.122 / 0.180 | 0.935 / 0.933 |
| uci_sms_spam | 524 | 40 | 0.914 / 0.951 | 0.008 / 0.006 | 0.997 / 0.999 |
| india_fraud_final (86% synthetic) | 310 | 153 | 0.957 / 0.964 | 0.032 / 0.038 | 0.970 / 0.994 |
| scam_ham_india | 205 | 74 | 0.958 / 0.980 | 0.000 / 0.008 | 0.998 / 0.998 |
| scam_dialogue (synthetic) | 172 | 72 | 1.000 / 1.000 | 0.000 / 0.000 | 1.000 / 1.000 |
| ealvaradob_phishing | 49 | 31 | 0.893 / 0.949 | 0.000 / 0.000 | 0.996 / 0.995 |

Source: reports/eval_muril_v2.md §3. Fake job posts remain poor for both models (F1 0.26 vs 0.21): their fraud label is not visible in the first 128 tokens, and one test-only company accounts for 13 misses (reports/eval_muril_v2.md "Reading"). Of MuRIL's 112 false alarms, 50 are one benign "UPI collect request" alert template that exists only in test, and 18 are job posts of one company whose profile-less posts (all fraud) sit in train while its profile posts (benign) sit in test, a gap in the company grouping (reports/eval_muril_v2.md "Reading"; BUGS.md "Company grouping only covers job posts with a profile").

### 8.4 Per language

| Language | n | Scam | F1 (baseline / MuRIL) | Benign FPR | AUROC |
|---|---|---|---|---|---|
| English | 4,995 | 1,266 | 0.905 / 0.919 | 0.016 / 0.019 | 0.980 / 0.987 |
| Hinglish | 306 | 119 | 0.889 / 0.935 | 0.059 / 0.070 | 0.984 / 0.990 |
| Hindi (synthetic) | 205 | 119 | 0.908 / 0.941 | 0.000 / 0.081 | 0.991 / 0.984 |
| Kannada (synthetic) | 205 | 119 | 0.809 / 0.871 | 0.140 / 0.244 | 0.930 / 0.878 |

Source: reports/eval_muril_v2.md §4. All Hindi and Kannada test rows are `synth_india` templates and validation has none, so no cut-off saw either language; these numbers show behaviour, not real-world accuracy (reports/eval_muril_v2.md §4, "Reading"). On real benign Hinglish chat (`cmu_hinglish_dog`, 47 rows) MuRIL flags 0 (reports/eval_muril_v2.md §4 "False alarms on benign Hinglish").

### 8.5 Adversarial robustness

Recall on the held-out attack test (attacks never seen in training, applied to test scam parents), baseline / MuRIL:

| Parents | Attack | Variants | Recall at Likely | Recall at least Suspicious | Clean-parent recall at Likely |
|---|---|---|---|---|---|
| All | char_noise | 1,179 | 0.861 / 0.918 | 0.958 / 0.929 | 0.897 / 0.961 |
| All | spaced_keywords | 306 | 0.905 / 0.967 | 0.984 / 0.984 | 0.948 / 0.971 |
| All | url_obfuscate | 377 | 0.915 / 0.995 | 0.984 / 0.995 | 0.920 / 0.995 |
| All | all attacks | 1,862 | 0.879 / 0.941 | 0.967 / 0.951 | 0.910 / 0.969 |
| Real parents | all attacks | 746 | 0.881 / 0.964 | 0.962 / 0.971 | 0.913 / 0.966 |

Source: reports/eval_muril_v2.md §5. MuRIL loses about 4 points of Likely-scam recall to character noise (0.961 to 0.918); the baseline loses 3.6 (reports/eval_muril_v2.md "Reading"). URL obfuscation is neutralised by `textprep.model_text`, which turns defanged links into `<URL>`, so it measures the preprocessing, not the model (reports/eval_muril_v2.md §5). Only 41 spaced-keyword variants come from real parents (BUGS.md "Held-out attack test is thin on real parents").

### 8.6 Shortcut checks

A model that sees only the source name or only the language, with no text, sets the floor the text model must beat. On the internal test split (reports/sanity.md §4):

| Model | F1 (all test) | F1 (real-only) |
|---|---|---|
| Language only | 0.383 | 0.356 |
| Source only | 0.611 | 0.551 |
| Text TF-IDF | 0.900 | 0.894 |

Three sources are single-class (`cmu_hinglish_dog`, `hinglish_conversations`, `web_scams`), so for them a source indicator predicts the label (reports/sanity.md "Flags"). In `synth_india`, a link is present in 58% of scam rows against 14% of benign rows, so `<URL>` is itself a scam cue there (BUGS.md "`<URL>` presence is still a scam cue in `synth_india`"). The benign translations are bank / OTP alerts and the scam translations prose, which is a cue shortcut to flag when evaluating Hindi or Kannada (docs/decisions/README.md, D26). [CHECK: the hand-written Interpretation section of reports/sanity.md is marked "Stale" (it predates the `<URL>` input and splits-v2); the report quotes only its generated tables.]

### 8.7 Leave-one-source-out (cluster-strict rule)

Leave-one-source-out (LOSO) asks how a model does on a source it has never seen, which is the closest internal proxy for real messages. The first version of the rule dropped only the held-out source's own rows; a leakage review found it missed translations attached to the source's rows as near twins and other sources' near copies (for example 191 + 30 `ealvaradob_phishing` rows that repeat `uci_sms_spam` messages) (CLAUDE.md "Next, in this order" item 5). The final rule, **cluster-strict-v1**, drops every training *and* validation row in a near-duplicate cluster that holds a row of the held-out source, whatever its source (reports/eval_muril_v2.md §9). The baseline was refitted under the same rule.

| Held-out source | Val+test n | Scam rate | Baseline LOSO AUROC | MuRIL in-dist AUROC | MuRIL LOSO AUROC | MuRIL LOSO scam recall @0.5 | MuRIL LOSO benign acc @0.5 | AUROC drop MuRIL / baseline |
|---|---|---|---|---|---|---|---|---|
| uci_sms_spam | 1,032 | 0.107 | 0.901 | 0.998 | 0.974 | 0.900 | 0.919 | 0.025 / 0.086 |
| india_fraud_final | 660 | 0.467 | 0.766 | 0.995 | 0.768 | 0.964 | 0.116 | 0.227 / 0.219 |
| scam_ham_india | 428 | 0.350 | 0.969 | 0.998 | 0.960 | 0.867 | 0.924 | 0.038 / 0.028 |
| synth_india | 821 | 0.581 | 0.921 | 0.933 | 0.875 | 0.662 | 0.826 | 0.059 / 0.014 |

Source: reports/eval_muril_v2.md §9 (third table). What it found (reports/eval_muril_v2.md "Summary" point 6):

- On UK SMS spam (`uci_sms_spam`) MuRIL generalises much better than the baseline (drop 0.025 vs 0.086).
- On the Indian SMS source `india_fraud_final` **both models fail** (LOSO AUROC 0.768 vs 0.766). At the 0.5 cut-off MuRIL catches 96.4% of scams but passes only 11.6% of genuine messages: it flags almost every genuine message in a source it has not seen.
- On `synth_india` MuRIL is worse than the baseline (drop 0.059 vs 0.014).
- The `india_fraud_final` failure is the main argument for adding real Indian genuine messages in splits-v3.

The stricter rule also lowered the baseline's own LOSO numbers: on `uci_sms_spam` AUROC 0.944 to 0.901 and PR-AUC 0.810 to 0.662 (reports/eval_muril_v2.md §9, second table). Under the older rule the baseline's LOSO AUROC on the long-text sources was close to chance: `phishing_email` 0.599, `fake_job_postings` 0.570 (reports/sanity.md §5); MuRIL folds for these sources were not run. Limits: one seed per fold; 428 to 1,032 rows per source, so differences of a few hundredths in F1 are within noise; `synth_india` has no validation rows (reports/eval_muril_v2.md §9 "Limits").

### 8.8 Link checks in the honest setting

On 2026-10-22 the link checks were run on a fresh OpenPhish sample (96 phishing links, one per registered domain; the feed held no more) and 200 Tranco domains (100 from the top 10,000, 100 from ranks 100,000 to 1,000,000), through the same function the API runs (reports/eval_live_links.md §1). With all lists on, recall is 100%, which is mostly the app finding its own source list, and the top-10k false-alarm rate is 0%, which is circular because the benign domains came from Tranco (reports/eval_live_links.md "Summary"). The honest setting therefore switches OpenPhish, URLhaus and Tranco off (reports/eval_live_links.md §4).

| Variant (honest setting) | Phishing flagged (of 96) | Phishing at Likely scam | False alarms, top 10k (of 100) | False alarms, 100k-1M (of 100) |
|---|---|---|---|---|
| Before C3 (flag threshold 0.537) | 72 (75% [65-83]) | 15 | 9 (9% [5-16]) | 20 (20% [13-29]) |
| The app now (threshold 0.662 + R10 + hosting platforms) | 69 (72% [62-80]) | 16 | 4 (4% [2-10]) | 12 (12% [7-20]) |

Source: reports/eval_live_links.md §10 (95% Wilson intervals in brackets). Over all 200 benign domains the app now flags 16 (8% [5-13]) (reports/eval_live_links.md §10). Of the 29 benign false alarms before C3, 27 came from the host-only URL model alone (reports/eval_live_links.md §4). Further findings:

- **Domain age** separates well where it is available: of 60 phishing domains with a registration date the median age was 60 days and 47% were under 30 days old, against a median of 5,608 days for benign domains, none under 30 days (reports/eval_live_links.md §5). A compromised old site still looks old (same section).
- **crt.sh** gave no usable answer for 93% of requests after two retries, so the certificate check is off by default (reports/eval_live_links.md §8; docs/decisions/README.md, C1).
- **Latency:** median 529 ms and 95th percentile 2,508 ms per link with network calls; 2 of 305 exceeded the 4 s message deadline (reports/eval_live_links.md §8).
- **Can't judge** applies to 20 of the 96 phishing links (free hosting and shorteners); for a user who reads "Can't judge" as "fine" these are misses (reports/eval_live_links.md §6).

**Caveat.** Decisions C1-C3 were made after looking at this same sample; R10 and the platform additions were written after reading the list of scams that the new threshold loses, so their recovery is by construction. Only the 0.662 threshold comes from outside the sample (the URL head's validation split). The numbers must be confirmed on a fresh pull (reports/eval_live_links.md, "Read this first" and §10). [PLACEHOLDER: link-check results on a fresh OpenPhish pull.]

On validation URLs, using offline signals only, any red flag (R1, R3, R4, R5) fired on 125 of 1,851 scam URLs (6.8%) and 0 of 4,236 benign URLs (reports/link_signals_val.md (a)); the feed and Tranco rows there are partly circular by construction (same section).

### 8.9 Investment-scam rules

Investment fraud is the largest category by money lost (Section 2.1), yet the short-message training sources hold almost no investment-scam rows (CLAUDE.md "Investment / trading / task scams"). A probe set of 54 scam and 48 genuine investment messages was assembled (probe-only, refused by the training guard); 45 of its 54 scam rows and all 48 genuine rows were written by the authors from cited descriptions (reports/investment_rules_v1.md §1).

| Head | Rules | Scams flagged | Genuine flagged (false alarms) |
|---|---|---|---|
| MuRIL (the app) | off | 39/54 (72%) | 14/48 (29%) |
| MuRIL (the app) | on | 46/54 (85%) | 14/48 (29%) |
| TF-IDF baseline | off | 40/54 (74%) | 18/48 (38%) |
| TF-IDF baseline | on | 47/54 (87%) | 18/48 (38%) |

Source: reports/investment_rules_v1.md §1. On the whole validation split (4,115 genuine, 1,152 scam) no rule fired on a genuine row and validation F1 of the full app was unchanged at 0.9294 (MuRIL) and 0.8924 (baseline) (reports/investment_rules_v1.md §2, §3).

These numbers are an **upper bound**: the rules were written after reading the probe, and the "0 genuine hits" on validation is by construction, because early versions fired on 15 genuine validation rows and were tightened until none did (BUGS.md "Investment rules A1-A12: limits" items 2 and 3). The rules only raise, so the 13 genuine probe rows MuRIL calls Likely scam stay there, including SEBI's own official UPI templates (reports/investment_rules_v1.md §1). Fixing those needs genuine investment messages in training (Phase B; Section 12).

### 8.10 Folded view (D11)

On the training-attack file (homoglyph, leet and zero-width variants of training parents), the hard rules fire on 100% of the attacked rows whose clean parent fires them, against 34-54% when the raw text is read (docs/decisions/README.md, D11). For homoglyphs, for example, "any hard rule" recovers 53.6% of hits raw and 100.0% folded (reports/fold_v1.md §1). Tactic tags recover 98.8-100% folded against 75-84% raw (CLAUDE.md "Folded view for the rules"). On validation (5,267 rows) no rule hit, verdict or F1 changes for either text model (docs/decisions/README.md, D11). Separators between letters (`O.T.P`, the held-out `spaced_keywords` attack) are not folded, and disguises inside links are not undone (BUGS.md "D11 folded view: what it does not cover").

### 8.11 OCR limits

On 5 real public English screenshots the pooled character error rate (whitespace-normalised) is 24.3% (strict 25.7%), against a target of 3% (reports/ocr_cer_public.md). Per image it ranges from 2.3% (a clean full-size screenshot) to 96.5% (a small dark chat bubble on a photo wallpaper) (reports/ocr_cer_public.md; BUGS.md "OCR on real public screenshots"). The rupee sign is often misread or dropped (docs/decisions/README.md, D19). No real Hindi or Kannada screenshot was available (n = 0) (BUGS.md "OCR on real public screenshots"). The design consequence is that OCR text is always shown for the user to correct (Section 5.8).

### 8.12 Demonstration set

A fixed demonstration set of 10 scam and 4 genuine illustrative messages is locked by tests. With MuRIL, 13 of 14 pass: all 10 scams are flagged and 3 of 4 genuine messages are left unflagged (reports/demo_check.md). The miss is a genuine "Your Amazon order has been delivered" message shown as Suspicious, accepted as a known miss rather than moving a cut-off for one made-up message (docs/decisions/README.md, D27 "Demo set").

### 8.13 What has not been evaluated yet

- **Ablation and rules-only baseline.** The README promises an ablation (rules only, text only, URL only, fused); it is not built (BUGS.md "Rules-only baseline and ablation table not built"). [PLACEHOLDER: ablation table on validation, then once on test.]
- **Calibration plot.** [PLACEHOLDER: reliability plot of the fused verdict.] [CHECK: BUGS.md says "no ECE or reliability plot has been computed for the MuRIL head", but reports/calibration_muril_v2.md §1 and §4 and reports/eval_muril_v2.md §6 report 10-bin ECE and reliability tables for the MuRIL text score. What is missing is the plot and any calibration of the final fused verdict; the BUGS.md entry should be reworded.]
- **Product-level false alarms on real genuine messages at the operating point** (D5 targets: Likely scam at most 1% and Suspicious or above at most 5% of hard-legit templates) (docs/ARCHITECTURE.md §11). Validation today holds only an estimated 0-10 real Indian genuine alerts (docs/decisions/README.md D5; docs/decisions/D5_operating_point.md §1.3).
- **splits-v3 gates** (pre-registered, validation only): G1 Indian genuine alerts (at least 39 groups, Suspicious or above at most 10% and Likely scam at most 2% of groups), G2 no regression (v3 validation F1 at least shipped minus 0.005), G3 UPI-collect alerts, G4 `india_fraud_final` LOSO (report-only), G5 flag policy; one training run, and the shipped model stays if a blocking gate fails (docs/plans/splits_v3.md §4). [PLACEHOLDER: gate table from reports/gates_v3.md; v3 internal-test results if the gates pass.]
- **Latency test** of the whole pipeline (docs/ARCHITECTURE.md §11).

---

## 9. Real-message test

### 9.1 Method

The real-message test set is the TEST half of the grouped freeze described in Section 6.8. Its rules (CLAUDE.md, hard rules 1 and 12; docs/plans/splits_v3.md §4 "Final real-message test"):

1. It is never used to train, tune, calibrate or choose a threshold, and its scores are not read before the final run. `src/realguard.py` makes the training, calibration and build scripts refuse any input under `data/real/` or any row whose text hash is in `real_test_v1.csv`.
2. It is scored once by `src/eval_real.py --final`, after the model-switch decision and never before it, on whichever model ships (the splits-v3 model if its gates pass and the test veto does not fire, otherwise the shipped MuRIL). Every run is one line in `reports/real_eval_ledger.md`; a second run on the same file needs a written reason.
3. Its numbers change nothing: no cut-off and no model choice.
4. `eval_real.py` scores through the full router (the app's pipeline) and reports every metric per labelling bucket (CLAUDE.md "Label buckets"; CLAUDE.md "Versioned masks").

At most 3 messages are kept per template group, so one bank's repeated alert cannot dominate the counts (CLAUDE.md "Real-message intake"). The sample-size target is 39 independent messages per category and label cell for a 95% interval of about plus or minus 15 points, and 93 for plus or minus 10 (docs/plans/data_acquisition.md §2).

### 9.2 Results

[PLACEHOLDER: date of the run, model scored (bundle name and `mask_version`), `real_test_v1.csv` SHA-256 and row / group counts, ledger line.]

[PLACEHOLDER: table of precision, recall, F1, false-alarm rate on genuine messages (Suspicious or above, and Likely scam), and Can't-judge rate, overall and per labelling bucket, per keyword bucket (investment, task, loan, KYC / bank, delivery, other) and per language, with Wilson 95% intervals.]

[PLACEHOLDER: comparison with the internal test (domain-shift gap; README.md "Evaluation" lists "Real-only test set vs. synthetic test set").]

[PLACEHOLDER: per-group results; `eval_real.py` does not report per template group yet (BUGS.md "Real-message intake: known limits" item 5).]

### 9.3 Caveats to report beside every number

- **Shared-sender optimism (D-a).** TEST and POOL come from the same two phones and share senders. A bank whose different templates fall on both sides of the split makes the final numbers mildly optimistic; the near-duplicate rules remove copies, not a sender's shared style. This caveat must be reported beside every `eval_real.py` number (docs/decisions/README.md, D-a).
- **Scam-enriched bucket.** Labelling bucket 2 (groups from a mobile-number sender) is scam-enriched by design, so overall rates depend on the bucket mix; per-bucket figures are the fair view (CLAUDE.md "Label buckets").
- **Hinglish is undercounted.** Language for SMS and WhatsApp is guessed from the script only, so Hinglish counts as English (BUGS.md "Real-message intake: known limits" item 2).
- **One label per group.** A template group can chain related templates; groups whose examples would not get the same label are skipped (BUGS.md "Real-message intake: known limits" item 1).
- **Few scams.** [CHECK: docs/plans/splits_v3.md §1 expects a genuine-heavy set, with roughly 10 scam groups going to the POOL; confirm the TEST scam count after the freeze and state whether scam recall can be estimated at all.]

---

## 10. Ethics, consent and privacy

**Consent.** Both phone owners consented to the use of their masked messages for training, validation and the test set, and to the masked training data going to a private Kaggle dataset (docs/decisions/README.md, D-a). Collection of real Hindi, Kannada and Hinglish messages from other people waits for the Dean's answer on consent-based collection; nothing is collected until then (docs/decisions/README.md, D6). [FILL: how consent was recorded (written or verbal), and the date.] [PLACEHOLDER: user-study consent form and information sheet (D13).]

**Personal data.** Phone numbers, e-mail addresses, UPI IDs and account numbers are masked at ingestion; only masked text is stored (README.md "Ethics and data handling"; CLAUDE.md, hard rule 5). The real-message intake also drops sender addresses, dates and contact names, and masks every number and name seen in the input; before the freeze every candidate name must be reviewed (CLAUDE.md "Real-message intake"). Person-name masking in the public-source rows is incomplete (Section 11).

**Never visiting malicious links.** Malicious URLs are stored as strings only and never visited (README.md "Ethics and data handling"); in the app this is enforced by a single network module and a no-network test (Section 5.7).

**Terms of service and licences.** Only pages that show a message are fetched, once, by hand or with one request, never a crawl; social-media posts are viewed by a human only; collected images stay out of the repository and are never redistributed (docs/plans/data_acquisition.md §6). Tranco, OpenPhish and Google Safe Browsing are non-commercial sources (docs/ARCHITECTURE.md §5.1); OpenPhish permits academic and personal research only, without redistribution (data/sources.yaml, `linklists_openphish`). The repository is kept private because some reports quote message text from sources of unknown provenance (CLAUDE.md "Done").

**Not overstating the tool.** The app never says "Safe" (docs/ARCHITECTURE.md §1 principle 2), shows no percentage (D4), and caps text-only verdicts in less-tested languages (D6). The helpline numbers are to be checked against official sources and the Hindi and Kannada wording reviewed by a native speaker; neither review has been recorded yet (docs/decisions/README.md, D15). [FILL: record of the helpline check and the native-speaker review, if done before submission.]

**Local network exposure.** The development server listens on all interfaces with no login, so anyone on the same network can use the app; this is acceptable on a home network or phone hotspot but should be avoided on shared Wi-Fi (BUGS.md "The dev server is open to the local network").

**Translated data.** Machine-translated Hindi and Kannada rows are never counted as real data and are used for training only (docs/decisions/README.md, D20, D26; CLAUDE.md, hard rule 4).

---

## 11. Limitations

The following list is taken from BUGS.md and the evaluation reports.

**Data**

1. **No real Hindi or Kannada data.** Hindi and Kannada evidence is machine translation (train only) and synthetic templates; validation has none (Section 6.6). Any Hindi or Kannada number is synthetic.
2. **Out-of-source failure.** On an unseen Indian SMS source both text models fail (Section 8.7); real messages behave like a new source (docs/ARCHITECTURE.md "Context").
3. **Residual near-duplicates.** 3.3% of validation and test rows have a training twin at Jaccard 0.6-0.7 (Section 6.4).
4. **Coverage gaps in the internal test.** `synth_india` has no validation rows and its test set (821) is larger than its train set (756); a benign UPI-collect template exists only in test (BUGS.md "`synth_india` has no val rows"). `india_fraud_final` splits are not stratified, so some category cells have no test rows (BUGS.md "`india_fraud_final` splits aren't stratified").
5. **Company grouping.** Only job posts with a company profile are grouped by company; its measured cost is 18 of MuRIL's 112 test false alarms (BUGS.md "Company grouping only covers job posts with a profile").
6. **Masking gaps.** No person-name masking in the shipped data; account-like numbers glued to letters are not masked (BUGS.md, both entries).
7. **Label noise.** At least 39 stock-advisor-group chat rows in `scam_ham_india` are labelled genuine although they look like investment-scam lures (BUGS.md "Investment / trading messages" item 3).

**Models**

8. **Truncation.** MuRIL reads 128 tokens, so long job posts and e-mails are judged on their opening only (Section 7.2).
9. **Overconfidence.** MuRIL's scores are bimodal; most messages read 0-9 or 90-100 on the meter (Section 7.3).
10. **Investment messages.** MuRIL calls 13 of 48 genuine investment probe messages Likely scam, including SEBI's official templates; the training data has no genuine investment message (BUGS.md "Investment / trading messages" item 1).
11. **Delivery PIN messages.** Genuine PIN-code and delivery-PIN messages can be raised to Likely scam; on test, 50 of 65 benign PIN messages were at Likely scam (BUGS.md "MuRIL text head (D27): known limits" item 2).
12. **No token-level explanations in the UI** (BUGS.md "MuRIL text head (D27): known limits" item 3).

**Links**

13. **Weak URL head.** Host-only test AUROC 0.859; it treats free-hosting sites as phishing because no benign platform-hosted URL reached training (BUGS.md "Host-only URL head is weak"; "URL head treats free hosting as phishing").
14. **Link-check numbers were tuned on their own sample** and must be confirmed on a fresh pull (Section 8.8).
15. **Brand lists unchecked.** The official-domain lists for 41 brands were written from the authors' knowledge, not re-fetched from the brands' sites (BUGS.md "R10 exact-brand rule: known limits"; docs/decisions/README.md, C3).
16. **Safe Browsing untested** against the real API (no key) (BUGS.md "Safe link checks (D23): known limits").
17. **Gambling text without a link** is not detected (BUGS.md "Gambling / betting messages WITHOUT a link").

**Rules, input and UI**

18. **Tactic tags are untuned keyword lists**; the Hinglish, Hindi and Kannada cues were written by hand and not checked by a native speaker (BUGS.md "Tactic tags are untuned keyword lists").
19. **OTP rule language coverage.** English plus one Hinglish form only; no Devanagari or Kannada patterns (BUGS.md "OTP / PIN / CVV rule: known limits").
20. **OCR quality.** CER 24.3% on real screenshots; rupee sign unreliable (Section 8.11).
21. **Hindi / Kannada UI text.** Only the helpline row and the investment card switch language, without a "translated, under review" mark (docs/decisions/README.md, D17).
22. **The sender rule is dormant**, because the UI no longer asks for a sender (docs/decisions/README.md, D18).
23. **Privacy of the React app not re-measured.** The request audit was done on the retired Gradio app (BUGS.md "App privacy: partly checked").

**Evaluation**

24. **Rules-only baseline, ablation and calibration plot not built** (Section 8.13).
25. **The internal test informed the choice between heads**, so it is no longer an untouched comparison for MuRIL and the baseline (docs/decisions/README.md, D27).
26. **Real-message test pending**, and optimistic by design because TEST and POOL share senders (Section 9.3).

---

## 12. Future work

1. **splits-v3 and retrain.** Add the POOL's real Indian genuine messages, harmonise masks, fix the company grouping, retrain once and switch the app only if the pre-registered gates pass (docs/plans/splits_v3.md §4, §5). [PLACEHOLDER: outcome.]
2. **Ablation and calibration.** Build the rules-only baseline and the ablation table (rules only, text only, URL only, fused) and the calibration plot, on validation first and then once on test (BUGS.md "Rules-only baseline and ablation table not built").
3. **Real Hindi, Kannada and Hinglish data**, collected with consent if the Dean approves (D6); the language cap lifts per language only after at least 150 real development templates (D5).
4. **User study (D13).** About 8-10 people (family, classmates), each judging about 10 messages with and without the app, logging only their answers on prepared stimuli (docs/decisions/README.md, D13). [PLACEHOLDER: design, results, and the with / without explanations comparison of README objective 6.]
5. **Phase B for investment scams.** Relabel the stock-group chat rows and add genuine broker, exchange and depository messages so the text head stops flagging SEBI's own templates; a go / no-go is planned (docs/plans/investment_scams.md §6; BUGS.md "Investment / trading messages").
6. **Hindi / Kannada UI (D6, D17).** The "experimental" note and Hindi / Kannada reasons and advice marked "translated, under review" until a native-speaker review (docs/decisions/README.md, D17).
7. **Full-URL view (D8).** The full-URL model scored test AUROC 0.939 against 0.859 host-only, but needs benign training URLs with real paths before it can ship; it is the last item of the project (docs/decisions/README.md, D8; BUGS.md "Host-only URL head is weak").
8. **Fresh link evaluation** on a new OpenPhish pull, to confirm C1-C3 (reports/eval_live_links.md "Read this first").
9. **Modules not built:** UPI / QR transaction checks and app (APK) permission analysis (docs/ARCHITECTURE.md §7).

---

## 13. Conclusion

Scam Shield shows that a locally run, privacy-preserving checker can combine a multilingual text model, background checks on links and narrow raise-only rules into a verdict with reasons and next steps, without visiting any link or storing any message. On in-distribution data the fine-tuned MuRIL model improves on a TF-IDF baseline (internal test F1 0.918 vs 0.897; reports/eval_muril_v2.md §2) and holds up better against held-out character attacks (Likely-scam recall 0.941 vs 0.879; same report, §5). The project's most important finding, however, is a negative one: when an Indian SMS source is held out entirely, both models fail to separate scams from genuine messages and flag most genuine messages (reports/eval_muril_v2.md §9). In-distribution scores therefore overstate what a user would see, and the remedy is real Indian genuine messages in training, which the splits-v3 rebuild adds. The design reflects that uncertainty: no percentages, no "Safe" verdict, and a cap on text-only verdicts in the languages that have not been measured on real data. [PLACEHOLDER: one or two sentences on the real-message test result, the splits-v3 outcome and the user study.]

---

## 14. References

### Project documents (in the repository)

- README.md: project specification, objectives, data, evaluation plan, ethics.
- CLAUDE.md: working rules (hard rules 1-12) and project status.
- docs/ARCHITECTURE.md: product architecture as built.
- docs/decisions/README.md: decision log (D1-D27, D-a, G1, R2, C1-C3, U1, V1, G2); D5_operating_point.md, D21_preservation_filter.md, D23_link_checks.md.
- docs/plans/splits_v3.md, docs/plans/data_acquisition.md, docs/plans/investment_scams.md.
- docs/labelling_guide.md.
- BUGS.md: known bugs and limits.
- reports/eval_muril_v2.md, reports/eval_muril_aug_v2.md, reports/calibration_muril_v2.md, reports/sanity.md, reports/splits_v2.md, reports/url_head.md, reports/eval_live_links.md, reports/link_signals_val.md, reports/investment_rules_v1.md, reports/fold_v1.md, reports/ocr_cer_public.md, reports/demo_check.md, reports/spotcheck_hi.md, reports/spotcheck_kn.md, reports/translate_parents.md, reports/translate_run.md, reports/urls_gambling.md, reports/dataset_audit.md, reports/splits_v3_b0a.md.
- docs/opportunities/research_notes/Scam Shield next feature 2/india_scam_numbers.md and papers_patents.md (draft, unreviewed research notes).

### Datasets and lists (identifiers from data/sources.yaml)

- UCI SMS Spam Collection, `ucirvine/sms_spam` (CC BY 4.0).
- ealvaradob phishing dataset, `ealvaradob/phishing-dataset` (Apache-2.0).
- Phishing e-mail dataset, `zefang-liu/phishing-email-dataset` (LGPL-3.0).
- EMSCAD fake job postings, `victor/real-or-fake-fake-jobposting-prediction` (CC0-1.0).
- Scam dialogue, `BothBosu/scam-dialogue` (Apache-2.0).
- `india_fraud_detection_FINAL.csv` and `scam_ham_india.csv`. [FILL: original authors / URLs and licences; data/sources.yaml gives only the file names.]
- CMU Hinglish Document-Grounded Conversations, `festvox/cmu_hinglish_dog` (CC BY-SA 3.0).
- Hinglish Everyday Conversations, `Abhishekcr448/Hinglish-Everyday-Conversations-1M` (MIT).
- OTP / phishing SMS preview, `gandharvbakshi/SMS-dataset-sample-10k` (MIT stated in the README text only).
- Tranco list, https://tranco-list.eu (non-commercial; cite Le Pochat et al.). [FILL: full Tranco citation.]
- OpenPhish public feed (academic / personal research only, no redistribution).
- URLhaus, abuse.ch (fair-use terms).
- UT1 blacklists, gambling category (CC BY-SA 4.0); Blocklist Project gambling list (Unlicense).
- IANA RDAP bootstrap registry (RFC 9224); iptoasn.com IP-to-ASN data (PDDL 1.0).

### Models and tools

- MuRIL, `google/muril-base-cased`. [FILL: Khanuja et al., "MuRIL: Multilingual Representations for Indian Languages", 2021, full citation.]
- IndicTrans2, `ai4bharat/indictrans2-en-indic-1B` (MIT). [FILL: Gala et al., 2023, full citation.]
- Tesseract OCR 5.5.3 with Leptonica 1.87.0 (docs/decisions/README.md, D19).
- scikit-learn, PyTorch 2.14.1, Transformers 5.19.0 (CLAUDE.md "Text head = MuRIL"), FastAPI, React. [FILL: versions and citations in the required style.]

### Literature cited from the research notes [CHECK: verify each against the original before submission]

- Lain, D., Kostiainen, K., Capkun, S. (2022). Phishing in organizations: findings from a large-scale and long-term study. IEEE Symposium on Security and Privacy. arXiv:2112.07498.
- Ho, G. et al. (2025). Understanding the efficacy of phishing training in practice. IEEE Symposium on Security and Privacy. [FILL: exact title.]
- Akesson, J., Gathergood, J., Quispe-Torreblanca, E. (2023). Preventing payments fraud in the FinTech era. CeDEx Discussion Paper 2023-08, University of Nottingham.
- Parihar, Harjani, Mathur, Goldberg, van der Linden, Roozenbeek (2024). Countering misinformation in India through prebunking. PsyArXiv.
- Lok Sabha written reply, Ministry of Home Affairs, 22 July 2025 (cyber-fraud losses 2023-2024), as reported by PTI / The Week. [FILL: sansad.in question number.]
- Rajya Sabha written reply, Ministry of Home Affairs, 12 March 2025 (digital arrest cases 2022-2025), as reported by PTI / The Week. [FILL: sansad.in question number.]
