> **DRAFT – unfinished research notes.** Not reviewed; figures and citations may be incomplete or wrong.

# Scam Shield internal audit: what we already have (baseline for judging any new feature)

Status: DRAFT 2 (2026-10-22). Sections 1, 2, 3, 5, 6, 7 filled from the repo; section 4 (first-hand read of training rows) is in progress and will be replaced, and sections 3 and 7 will get the data numbers. All sources are files in the repo at /Users/kiyo/scam-project (link targets are absolute paths). Validation/test appear only as aggregate numbers taken from reports; no validation or test row was read for this audit (`reports/eval_muril_v2.md` section 8 quotes some test rows; they were not used or quoted here).

## 1. Components and maturity: what exists, its measured numbers, how it is tested

### Takeaway
A complete local pipeline exists and works end to end on a Mac (text model + URL model + link background checks + hard OTP/PIN rules + gambling lookup + screenshot OCR + FastAPI JSON API + React page), but every number is in-distribution on public or synthetic datasets: none comes from a real message sent by a real person. The fine-tuned MuRIL text head is the strongest and heaviest part (internal test F1 0.918, 950 MB, about 59 ms per message on CPU); the host-only URL model is the weakest (test AUROC 0.859, about 8% false alarms on popular domains).

### Cited Findings
**Text head: MuRIL (the app's default since 2026-10-21, decision D27)**
- `google/muril-base-cased`, max length 128 tokens, no augmentation, best epoch 2 of 3, trained on a Kaggle Tesla T4 in fp16 — [eval_muril_v2.md §1](../../../../reports/eval_muril_v2.md)
- Validation F1 at the Likely-scam cut-off 0.951 vs 0.930 for the TF-IDF baseline — [eval_muril_v2.md](../../../../reports/eval_muril_v2.md)
- Internal test split (n=5,711; 1,623 scams; scored once): F1 0.918 vs 0.897, precision 0.929 vs 0.945, recall 0.908 vs 0.854, AUROC 0.986 vs 0.980; real-only rows (n=4,396) F1 0.906 vs 0.885; share of benign rows at Likely scam 2.7% vs 2.0%; 112 false alarms vs 81 and 150 missed scams vs 237 — [eval_muril_v2.md §2, §8](../../../../reports/eval_muril_v2.md)
- "Internal test" is not the planned final real-message test set: it is a held-out slice of the same public/synthetic datasets — [eval_muril_v2.md header](../../../../reports/eval_muril_v2.md)
- Per source (test, MuRIL): scam_ham_india F1 0.980 (n=205, 74 scams); india_fraud_final 0.964 (n=310, 86% synthetic); uci_sms_spam 0.951; phishing_email 0.959; fake_job_postings 0.259 (98% of its inputs are cut at 128 tokens); synth_india 0.917 with 18.0% of its benign rows at Likely scam — [eval_muril_v2.md §3](../../../../reports/eval_muril_v2.md)
- Per language (test, baseline / MuRIL): English F1 0.905 / 0.919, AUROC 0.980 / 0.987; Hinglish F1 0.889 / 0.935; Hindi F1 0.908 / 0.941, AUROC 0.991 / 0.984, benign at Likely scam 0.0% / 8.1%; Kannada F1 0.809 / 0.871, AUROC 0.930 / 0.878, benign at Likely scam 14.0% / 24.4%. Hindi and Kannada test rows are 205 synthetic template rows each, and validation has no Hindi or Kannada row, so no cut-off saw either language — [eval_muril_v2.md §4](../../../../reports/eval_muril_v2.md)
- Real benign Hinglish chat (cmu_hinglish_dog, 47 test rows): MuRIL flags 0 of 47 — [eval_muril_v2.md §4](../../../../reports/eval_muril_v2.md)
- Held-out attack types (char_noise, spaced_keywords, url_obfuscate on test scam parents): Likely-scam recall 0.941 vs 0.879 (all parents), 0.964 vs 0.881 (real parents); `url_obfuscate` is neutralised by preprocessing so it measures `textprep`, not the model — [eval_muril_v2.md §5](../../../../reports/eval_muril_v2.md)
- Calibration: temperature T = 1.507 fitted on validation (val ECE 0.018 -> 0.009; test Brier 0.0441 -> 0.0420, ECE 0.042 -> 0.027); cut-offs Suspicious 0.103 / Likely scam 0.436; validation benign messages flagged at Suspicious or above 1.56% (64 of 4,115) vs 4.06% (167) for the app's TF-IDF head, at scam recall 0.9505 vs 0.9523 — [calibration_muril_v2.md](../../../../reports/calibration_muril_v2.md)
- Scores are extreme: 69.4% of test rows score below 0.01 and 26.5% at 0.99 or above — [eval_muril_v2.md §6](../../../../reports/eval_muril_v2.md)
- Cost: median 58.8 ms per message on CPU (p95 68.3), 28.6 ms on the Mac GPU (MPS), vs 1.86 ms for TF-IDF; size 950 MB vs 8 MB — [eval_muril_v2.md §7](../../../../reports/eval_muril_v2.md). On disk: `model.safetensors` is 950,254,592 bytes plus a 6.4 MB tokenizer (directory listing of `models/finetune/muril_len128_20261021T135255Z/model/`, 2026-10-22)
- API ready in about 12 s with MuRIL (7.5 s with the baseline); resident memory about 1.0 GB on MPS / 1.2 GB on CPU — [CLAUDE.md, Text head bullet](../../../../CLAUDE.md)
- Leave-one-source-out (LOSO) has not been run for MuRIL (8 fine-tunes) — [eval_muril_v2.md §9](../../../../reports/eval_muril_v2.md)
- The augmented MuRIL run was rejected by a rule fixed in advance: adversarial recall 0.885 < 0.96 gate; test F1 0.891 — [eval_muril_aug_v2.md](../../../../reports/eval_muril_aug_v2.md)

**Text head fallback: TF-IDF + logistic regression**
- Character 2-4-grams inside word boundaries, logistic regression with balanced class weights; links replaced by `<URL>`, text cut to 2,000 characters — [sanity.md §7](../../../../reports/sanity.md)
- The app's file is still the splits-v1 fit (cut-offs 0.423 / 0.656); `SHIELD_TEXT_HEAD=baseline` or a missing MuRIL bundle selects it — [CLAUDE.md](../../../../CLAUDE.md), [config.py](../../../../src/shield/config.py)
- 7,567,140 bytes on disk (`models/text_baseline.joblib`, directory listing 2026-10-22)
- It cannot read negation: a "never share your OTP" warning scores 0.02-0.06 higher than the same sentence as a request; 5 of 8 hand-written genuine OTP advisories were Suspicious — [BUGS.md, advisory entry](../../../../BUGS.md)
- LOSO (baseline, splits-v2; held-out source's val+test rows): AUROC phishing_email 0.599, fake_job_postings 0.570, india_fraud_final 0.776 (it calls 65% of that source's benign rows scam: benign accuracy 0.349), scam_dialogue 0.812 (F1 0.127), uci_sms_spam 0.944, scam_ham_india 0.968, synth_india 0.921 — [sanity.md §5](../../../../reports/sanity.md)

**URL head (lexical model on the link's host)**
- HistGradientBoosting on host-only lexical features; val AUROC 0.845, test AUROC 0.859; at the val threshold 0.537: false alarms on 8.3% of Tranco and 9.1% of ealvaradob benign test hosts; recall 0.618 on ealvaradob phishing, 0.767 on OpenPhish, 0.927 on URLhaus — [url_head.md](../../../../reports/url_head.md)
- Top feature is the TLD (`tld_code`, AUROC drop 0.128); the brand-lookalike feature barely matters (0.002) — [url_head.md](../../../../reports/url_head.md)
- Domain-age coverage of its training rows is 0% — [url_head.md](../../../../reports/url_head.md)
- `https://www.google.com/` scores 0.484 (flag 0.537); free-hosting sites score 0.96-0.98, so the app shows them as "Can't judge" by rule instead — [BUGS.md](../../../../BUGS.md)
- Of 18 hand-picked genuine Indian-site URLs the deployed model flags 6 as at least Suspicious (e.g. `netbanking.hdfcbank.com`, `onlinesbi.sbi`, `amazon.in/gp/your-account`) — [docs/demo/README.md §3.2](../../../../docs/demo/README.md)
- Not retrained on the current 88,818-row `urls.csv` (still the 62,969-row fit); 806,454 bytes on disk — [CLAUDE.md](../../../../CLAUDE.md), directory listing 2026-10-22
- Full-URL and www-stripped variants were measured; the rule kept the deployed host-only model — [BUGS.md, URL head entry](../../../../BUGS.md)

**Safe link checks (D23)**
- Offline: verified brand TLDs, `.bank.in`, `.gov.in`/`.nic.in` display, Indian brand lookalikes, IDN homographs, raw IPs, OpenPhish + URLhaus lists, Tranco 1M, high-abuse TLDs; live (only the registered domain leaves the machine, through `net.py`): RDAP, Cloudflare DNS-over-HTTPS, crt.sh fallback, Safe Browsing only with a key, shortener expansion only on a button press — [src/shield/links/CLAUDE.md](../../../../src/shield/links/CLAUDE.md)
- Validation `urls.csv`: any offline red flag on 6.8% of scam URLs and 0% of benign URLs; validation messages with a link: 28 of 225 scam vs 6 of 447 benign messages have a red flag; turning D23 on changed 0 scam verdicts and lowered 2 benign ones — [link_signals_val.md](../../../../reports/link_signals_val.md)
- Safe Browsing tested only against a mock; Tranco, OpenPhish and Safe Browsing are licensed for non-commercial use only — [BUGS.md D23 entry](../../../../BUGS.md), [link_signals_val.md](../../../../reports/link_signals_val.md)

**Hard rules: OTP/PIN/CVV request and PIN-to-receive (R2)**
- A request to share an OTP / PIN / CVV (English plus the Hinglish "OTP bata do") forces at least Suspicious; on validation the rule fires on 9 rows, all benign delivery-PIN messages, and on 0 scams: "the delivery false positive is the rule's whole val footprint" — [BUGS.md, OTP rule entry](../../../../BUGS.md)
- R2 (UPI PIN asked near a receive-money cue) fires on 1 validation row (a scam) and 0 benign rows; 0 validation verdicts change — [BUGS.md, R2 entry](../../../../BUGS.md)
- With MuRIL, genuine PIN-code / delivery-PIN texts in the hand-written fixtures moved to Likely scam (`postal-pin-code`, `shipping-pin`, `pin-code-delivery-received`); on the test split (reported only) 50 of 65 benign messages mentioning a PIN are at Likely scam — [otp_advisory_muril.md §1, §3](../../../../reports/otp_advisory_muril.md)
- Tested by 56 hand-written tricky inputs and contract checks A1-A15 on 363 inputs — [src/shield/messages/CLAUDE.md](../../../../src/shield/messages/CLAUDE.md)

**Gambling links (G1)**
- A link whose registered domain is in a 362,487-domain lookup (two public lists plus review decisions) or matches a Satta/Matka name rule is floored at Suspicious, never Likely scam on its own; a betting promo with no link is not detected — [CLAUDE.md](../../../../CLAUDE.md), [BUGS.md](../../../../BUGS.md)
- Validation + test messages with a matching link: 1 of 10,978 after the top-10k review — [src/shield/links/CLAUDE.md](../../../../src/shield/links/CLAUDE.md)

**Screenshot OCR (D19, D19b)**
- Local Tesseract 5.5.3 (`eng+hin+kan`, `--psm 6`) over stdin/stdout, image never stored; the user must check and correct the text before analysis — [decision log D19](../../../../docs/decisions/README.md)
- On 160 synthetic renders of the 10 demo scams: character error rate <= 0.08 in 160/160, same verdict as the typed text 160/160; the rupee sign survives in only 37 of 96 amounts (`₹5,000` can read `25,000`); Kannada screenshots not tested; only one real screenshot (the developer's own Jio SMS, link recovered in 50 of 64 re-encoded reads); iOS dark-mode sent bubbles 0 of 32 links — [BUGS.md, OCR entry](../../../../BUGS.md)

**Sender rule (D22), dormant**
- Parses TRAI DLT headers (`JM-JIOCPN-P`) and can soften a registered promotional sender to "Promotional"; the UI field was removed the same day because "users won't type a sender"; reachable only through the API — [decision log D22](../../../../docs/decisions/README.md)

**Risk meter (D24)**
- A 0-100 "warning-sign meter, not a probability", clamped inside the band of the final level; with MuRIL, 78.0% of validation messages land in 0-29, 0.5% in 30-69, 21.5% in 70-100 on their text score — [decision log D24](../../../../docs/decisions/README.md), [calibration_muril_v2.md §3](../../../../reports/calibration_muril_v2.md)

**FastAPI, React frontend, demo set, tests**
- API routes: `GET /api/health`, `POST /api/analyse` (`{text, sender?, live?, expand?}` -> Report schema "5"), `POST /api/ocr` (multipart image -> text); no docs page; CORS admits only the local Vite dev server; text is never logged — [src/shield/api/main.py](../../../../src/shield/api/main.py)
- Frontend: React + Vite + Tailwind + Motion (D9), dark/light themes, a globe, a comet/black-hole theme-switch animation; vitest 516/516 and Playwright checks — [frontend/CLAUDE.md](../../../../frontend/CLAUDE.md), [decision log D9, D25](../../../../docs/decisions/README.md)
- `./run.sh` prints a local URL and a phone URL on the same Wi-Fi — [README.md](../../../../README.md)
- Demo set: 14 made-up messages; 13 of 14 behave as expected with MuRIL (10/10 scams flagged; the genuine Amazon delivery message g03 is Suspicious) — [demo_check.md](../../../../reports/demo_check.md)
- `pytest -q` gives 9 passed on both text heads — [CLAUDE.md](../../../../CLAUDE.md)

### Inferences
- Maturity ranking (my judgement from the numbers above): rules, API, OCR plumbing and link list checks are engineering-mature (tested, privacy-guarded); the MuRIL head is the most accurate part but only in-distribution; the URL lexical model is the least trustworthy part; nothing is field-validated.
- The two text heads differ much less on India-style SMS than on email: on scam_ham_india 0.980 vs 0.958 and on india_fraud_final 0.964 vs 0.957 test F1, against a 125x size and ~30x latency cost; the clearer MuRIL wins are negation (OTP advisories) and held-out attacks.

### Gaps
- No end-to-end latency for a full analysis with live checks was found in a report (only the text-model timing and the "<= 4 s per message" design cap for live calls).
- No measurement of the React page on a real low-end phone was found.

## 2. Weak spots and open bugs, ranked by likely real-user impact; any real-world use?

### Takeaway
The biggest weak spot is not a bug: nobody except the developer (and two friends who checked 47 translated rows each) has used or judged the system, no real message from a real person has been scored, and the app only runs on the developer's Mac (reachable by a phone on the same Wi-Fi). Among measured faults, the most user-visible are false alarms on genuine Indian transactional SMS formats (UPI-collect alerts, delivery PINs, bank deep links) and the absence of real Hindi/Kannada data.

### Cited Findings
- README status: user study (15-20 participants) not done; India-specific message collection (Google Form intake) not done; report, slides, viva not done — [README.md Status](../../../../README.md)
- "Real-world accuracy has not been measured. There is no test set of real messages from real people yet" — [docs/demo/README.md §3.5](../../../../docs/demo/README.md)
- The demo guide asks a reviewer whether forwarded scam messages may be collected with consent — i.e. collection has not started — [docs/demo/README.md §4](../../../../docs/demo/README.md)
- External human input so far: one reviewer per language marked 47 machine-translated rows (Hindi: 4 failures and 18 "formal" flags; Kannada: 47/47) — [docs/spotcheck/hi_friend_v1.txt](../../../../docs/spotcheck/hi_friend_v1.txt), [kn_friend_v1.txt](../../../../docs/spotcheck/kn_friend_v1.txt), [decision log D20, D26](../../../../docs/decisions/README.md)
- The only real screenshot tested is the developer's own Android dark-mode Jio SMS — [src/shield/ocr/CLAUDE.md](../../../../src/shield/ocr/CLAUDE.md)
- D1: "Run locally (Mac + LAN, use a phone hotspot for demos/study); Hugging Face Spaces (Docker) later" — [decision log](../../../../docs/decisions/README.md)
- D5 (decided): false-alarm targets on hard-legit messages are "design targets until real-dev exists"; with ~25-35 independent English hard-legit templates in validation, even zero false alarms gives an upper bound of ~10-11%, so neither the 1% nor the 5% target can be shown — [D5_operating_point.md §1.4, decisions](../../../../docs/decisions/D5_operating_point.md)
- D5's language cap ("text model alone max Suspicious in hi/kn/Hinglish until >= 150 real-dev templates") is decided — [decision log D5](../../../../docs/decisions/README.md); a search of `src/shield/` found no code implementing it (grep for a language cap / language detection, 2026-10-22; `router.analyse()` applies no per-language rule — [router.py](../../../../src/shield/core/router.py))
- 50 of MuRIL's 112 test false alarms are one benign "UPI collect request" alert template that has no benign counterpart in training; its label is arguable (it warns "Entering your PIN will DEBIT your account") — [eval_muril_v2.md](../../../../reports/eval_muril_v2.md), [BUGS.md synth_india entry](../../../../BUGS.md)
- 18 of the 112 test false alarms come from one company's job posts (company-grouping gap) — [BUGS.md](../../../../BUGS.md)
- Hindi and Kannada: no real rows at all (sanity "real rows only" table shows 0 Hindi, 0 Kannada; all 478 real Hinglish rows are benign chat); the 1,142 Hindi/Kannada rows added at splits-v2 are machine translations, train only — [sanity.md §3](../../../../reports/sanity.md), [splits_v2.md](../../../../reports/splits_v2.md)
- MuRIL Kannada AUROC 0.878 vs 0.930 for TF-IDF (synthetic rows) — [eval_muril_v2.md §4](../../../../reports/eval_muril_v2.md)
- Genuine delivery/PIN-code texts rated Likely scam by MuRIL; the genuine Amazon delivery message g03 is Suspicious — [BUGS.md MuRIL entry](../../../../BUGS.md), [demo_check.md](../../../../reports/demo_check.md)
- At 128 tokens MuRIL reads only the start of long texts: 60.5% of train inputs are cut (job posts 97%, emails 71%), every SMS-style source <= 1% — [CLAUDE.md finetune reference](../../../../CLAUDE.md)
- OCR: rupee sign kept in 37 of 96 amounts; Kannada screenshots untested; saturated dark-mode bubbles unreadable — [BUGS.md](../../../../BUGS.md)
- No person-name masking in `pii.py` (rule 5 names victim names) — [BUGS.md](../../../../BUGS.md)
- Explanations (word occlusion, Gradio only) are empty on saturated scores (most confident scams) — [BUGS.md MuRIL entry](../../../../BUGS.md)
- Tactic tags are untuned keyword lists ("authority" fires on any "bank", "sbi", "hdfc", including the genuine HDFC alert); Hindi/Kannada/Hinglish cues unchecked by a native speaker — [BUGS.md](../../../../BUGS.md)
- Gambling or betting promos without a link are rated "No warning signs found" — [BUGS.md](../../../../BUGS.md)
- Several docs are stale: `reports/sanity.md` Interpretation carries a "Stale" warning; `docs/demo/README.md` §2-3 still say MuRIL "is not in the app yet" and the translated set "is not in the data yet" — [sanity.md](../../../../reports/sanity.md), [docs/demo/README.md](../../../../docs/demo/README.md)

### Inferences
Ranking by likely harm to a real user today (my judgement; 1 = worst):
1. **No reach and no field evidence.** Local-only deployment plus no real-message evaluation means the expected real-world hit rate and false-alarm rate are unknown; LOSO shows the TF-IDF model can fail badly on a new source (e.g. 65% of india_fraud_final's genuine messages called scam when that source is held out), and real messages behave like a new source.
2. **False alarms on genuine Indian transactional SMS** (UPI-collect alerts, delivery PINs, postal PIN codes, Amazon delivery, genuine bank deep links via the URL head). These are exactly the messages an anxious user pastes; repeated false alarms teach people to ignore warnings (D5 cites a 9-23% warning click-through study).
3. **Hindi/Kannada/Hinglish quality unknown** (synthetic test only, Kannada worse with MuRIL, language cap not built).
4. **Screenshot path errors on amounts and links** (a misread amount or host can change advice), untested on real phones.
5. **Call-only scams are invisible** unless the user types or screenshots a text (see section 3).
6. Lower: long-email truncation, name masking (privacy of stored datasets, not the app), gambling-text gap, explanation gaps, dormant sender rule, stale docs.

### Gaps
- No usage logs exist by design (nothing is stored), so there is no evidence of how people would use it (what they paste, when, on which device).
- No measurement of how many real users would understand "Suspicious" vs "Likely scam", or act on the advice.

## 3. Coverage by scam type, and what happens for a scam that runs on a phone or video call

### Takeaway
(Draft; numbers from category labels, regex counts to follow in section 4.) The India-specific training scam rows are spread evenly over eight template categories (digital arrest, courier/customs, e-challan, job, KYC, lottery, tax, utility) because they come from templated/synthetic generators, not from frequency in real traffic; investment/trading, customer-care, sextortion and loan-app scams have no category of their own. A phone/video-call scam is covered only if the user types or screenshots words from it.

### Cited Findings
- Training scam rows, India-specific sources (train split; counts from `messages.csv` joined to `split_map.csv`, computed 2026-10-22): india_fraud_final 1,292 rows in 183 near-duplicate clusters (1,109 flagged `is_synthetic`); scam_ham_india 745 rows (526 clusters, none synthetic); synth_india 448 (synthetic, 8 template clusters); translated_indic 142 (machine translations); web_scams 16 — computed from [messages.csv](../../../../data/final/messages.csv) and [split_map.csv](../../../../data/final/split_map.csv)
- india_fraud_final training scam rows by category: digital_arrest 170, courier_customs 149, echallan 169, job 152, kyc 136, lottery 174, tax 155, utility 187; by channel: sms 344, email 251, whatsapp 238, call 227, telegram 219, other 13 — same computation
- scam_ham_india scam rows carry no category (all "other") and channel sms — same computation
- scam_dialogue (synthetic English call transcripts) training scam rows: impersonation 158, lottery 153, refund 163, tech_support 163 — same computation; source marked synthetic vishing transcripts in [sources.yaml](../../../../data/sources.yaml)
- Some india_fraud_final subcategories show scam types beyond the eight categories: YouTube_Task 16, Survey_Task 13, eBay_Task 12, TikTok_Likes 11 (task scams), APK_Malware 10, Malware_Link 13, Narcotics_Claim 10, CBI_Spoof 10, NCB_Spoof 10, Fake_Warrant 10, Court_Summons 13 (top-40 list only) — same computation
- The text model reads only text; the router analyses a pasted string and links in it — [router.py](../../../../src/shield/core/router.py)
- The digital-arrest demo message (d01) is a call script typed as text; it is caught as Likely scam with reasons Authority claim, Payment ask, Secrecy — [demo_check.md](../../../../reports/demo_check.md)
- The isolation tactic includes call-control cues ("do not hang up / disconnect", "stay on the line / call / video", "digital arrest", "switch to WhatsApp / Telegram") — [tactics.py](../../../../src/shield/messages/tactics.py)
- Held-out call transcripts are poorly handled by the TF-IDF model: scam_dialogue LOSO F1 0.127 (scam recall 0.068), AUROC 0.812 — [sanity.md §5](../../../../reports/sanity.md)

### Inferences
- (to be completed with the regex and manual-coding numbers in section 4)

### Gaps
- (to be completed)

## 4. Raw training data: what Indian scam messages ask the victim to do

In progress (manual coding of >= 150 training scam rows from india_fraud_final and scam_ham_india; regex counts over all training scam rows of each India-specific source).

## 5. Project constraints: what must be delivered, and which pending decisions bear on delivery shape

### Takeaway
The VTU project is titled an *awareness platform* for phishing, digital arrest and malicious apps, but the repo has built a *detector*; the deliverables that are still open and marked "never cut" are human-facing (a 15-20 person user study, a stakeholder conversation, an India-specific dataset with real messages), plus the report, slides and viva. The architecture plan's dates (core ~6 Nov, all modules ~8 Jan) and decision D1 (local Mac + LAN, hosting later) shape what a 3-month feature can be.

### Cited Findings
- Title: "VTU Community / Societal Project (1BCP308, Sem 3), topic #19: Cyber Security Awareness Platform for Phishing, Digital Arrest Scams, and Malicious Applications" — [README.md](../../../../README.md)
- Objectives include beating a rule baseline, measuring adversarial robustness, a documented India-specific dataset with inter-annotator agreement, a user study (15-20 participants) comparing scam-spotting accuracy with and without explanations, at least one stakeholder conversation (bank or cyber cell), and a minimal web UI — [README.md Objectives](../../../../README.md)
- "Never cut: the India-specific dataset, the adversarial results, the user study"; "cut first if time is short: malicious-app (APK) analysis, Kannada samples, character-level URL CNN" — [README.md Scope](../../../../README.md)
- Plan phase 4 "Field validation": user study, feedback form, stakeholder conversation, "photos and attendance as evidence"; phase 5: report, one-command reproduction, slides, mock viva — [README.md Plan](../../../../README.md)
- Architecture draft (2026-10-09): "The core is due ~Nov 6 and all modules by ~Jan 8"; phases: Links Nov 9-27, user study late Nov / early Dec, Transactions (UPI ID / QR / collect-request checks) Nov 30-Dec 11, Apps (catalog, APK manifest, remote-access apps) Dec 14-25, freeze + final real test Dec 28-Jan 8 — [docs/ARCHITECTURE.md §8](../../../../docs/ARCHITECTURE.md)
- Never cut (architecture): Messages + OCR, FPR-on-legit-SMS evaluation, "Can't judge", the no-network gate, the final real test set (once), the user study, the adversarial results — [docs/ARCHITECTURE.md §9](../../../../docs/ARCHITECTURE.md)
- Decided: D1 local Mac + LAN (Hugging Face Spaces later; "Hosting changes the privacy statement"); D5c a dispute button that stores nothing by default, with an opt-in study/volunteer mode that saves masked text + verdict + user label locally; D9 React frontend with all assets bundled — [decision log](../../../../docs/decisions/README.md), [ARCHITECTURE.md §10](../../../../docs/ARCHITECTURE.md)
- Pending decisions (ARCHITECTURE §10): D6 Hindi/Kannada claim (collect real data or label "experimental"); D7 real-message sets (real-dev from 5-10 volunteers' inboxes + final set); D8 URL head view; D10 OCR candidates; D11 rules on a folded (NFKC/homoglyph) view; D12 live-check cache retention; D13 user study timing and build ("late Nov, on the Messages + Links build"); D14 ladder numbers; D15 advice content and helplines, who reviews them; D16 floor strength; D17 UI language (English only vs Hindi/Kannada advice); D18 sender-ID check — [docs/ARCHITECTURE.md §10](../../../../docs/ARCHITECTURE.md). D12, D14 and D16 are settled for links by D23, and D18 was built as D22 — [decision log D23, D22](../../../../docs/decisions/README.md)
- D5's real-dev target: 400+ independent English hard-legit templates and ~150 per language — [decision log D5](../../../../docs/decisions/README.md)
- Study mode was planned: "a URL flag hides the reasons and advice ... It logs only the participant's answers on prepared stimuli" — [docs/ARCHITECTURE.md §6](../../../../docs/ARCHITECTURE.md)

### Inferences
- The pending decisions that most constrain a new delivery shape are D1 (local vs hosted: any bot, share target or public site requires hosting and a new privacy statement), D7 (real data, which every accuracy claim needs), D13 (the user study must run on some build), D15/D17 (advice wording and language) and D5c (feedback storage vs "store nothing").
- The README's "awareness platform" title and the never-cut user study give room for a feature whose value is measured by people, not by F1.

### Gaps
- The README's plan uses "TLP weeks 7-15" without dates; the exact submission deadline and viva date are not in the repo.
- No record of a stakeholder (bank / cyber cell) contact was found.

## 6. Reuse in other delivery shapes (chat bot, Android app, share-sheet target, on-device model)

### Takeaway
The detection core is already shape-agnostic: one JSON call takes plain text and returns a level, reasons, evidence spans and advice, and the screenshot path is a separate OCR call. What does not travel as-is is the 950 MB MuRIL model (too large for a phone app), the Mac-only Tesseract setup, the localhost-only API, and the English-only advice.

### Cited Findings
- `POST /api/analyse {text}` returns the full Report (schema "5": level, risk score, up to 3 reasons, evidence with code-point spans, advice, link facts, model hashes); `POST /api/ocr` returns text; CORS admits only `localhost:5173` / `127.0.0.1:5173` — [main.py](../../../../src/shield/api/main.py), [decision log D24](../../../../docs/decisions/README.md)
- "Every module returns a Report, so the UI has one renderer for all four modules" — [ARCHITECTURE.md §2](../../../../docs/ARCHITECTURE.md)
- Sizes on disk: MuRIL weights 950 MB (fp32 safetensors) + 6.4 MB tokenizer; TF-IDF 7.2 MB; URL head 0.8 MB (directory listing 2026-10-22); gambling lookup 362,487 domains, load 0.4-0.8 s, 70 MB peak — [src/shield/links/CLAUDE.md](../../../../src/shield/links/CLAUDE.md); D23 link lists take ~3.5 s to load at API start-up (Tranco 1.6 s, IP table 2 s) — [BUGS.md D23 (13)](../../../../BUGS.md)
- Latency: MuRIL 58.8 ms CPU / 28.6 ms MPS; TF-IDF 1.86 ms; resident memory with MuRIL ~1.0-1.2 GB — [eval_muril_v2.md §7](../../../../reports/eval_muril_v2.md), [CLAUDE.md](../../../../CLAUDE.md)
- Language-specific parts: OTP/PIN rules are English plus a Hinglish form only, "no Devanagari or Kannada patterns, on purpose" — [BUGS.md](../../../../BUGS.md); tactic cues have unchecked Hindi/Kannada/Hinglish forms — [tactics.py](../../../../src/shield/messages/tactics.py); advice is English only — [advice.py](../../../../src/shield/core/advice.py); OCR reads `eng+hin+kan` — [decision log D19](../../../../docs/decisions/README.md)
- Advice today is generic per level (e.g. Likely scam: "Don't reply, click the link or call back"; "If you paid or shared details, call 1930 now and tell your bank"; "Report it at cybercrime.gov.in") plus one gambling line — [advice.py](../../../../src/shield/core/advice.py)
- The privacy guarantees are code-level: no request-body logging, no temp files for screenshots, all outbound calls through one allowlisted module — [main.py](../../../../src/shield/api/main.py), [ARCHITECTURE.md §1, §5.4](../../../../docs/ARCHITECTURE.md)

### Inferences
- A chat bot or share-sheet target can reuse `/api/analyse` unchanged, but only after hosting (D1) and with the privacy statement rewritten, since text would leave the user's device.
- On-device: the TF-IDF head (7.2 MB, 2 ms) and URL head (0.8 MB) are small enough to port in principle (my estimate; no port was attempted); the rules are plain regexes that could be re-implemented; MuRIL at 950 MB fp32 is not a realistic phone payload without quantisation or distillation (not measured in the repo).
- The OCR step exists because input is a screenshot on a laptop page; a phone-native share target would receive text directly for SMS/WhatsApp text shares, removing the rupee-sign and link-misread failure modes for that path (inference).

### Gaps
- No on-device experiment, quantisation or distillation measurement exists in the repo.
- No measurement of the React page's weight or speed on a phone over mobile data.

## 7. The user's three suspicions, the rupees-saved terms, and dead weight

### Takeaway
(Draft; data numbers to follow.) The repo's own evidence leans toward suspicions (b) and (c): detection on the data it has is already high, while reach is near zero (local Mac, paste-only, no users); the link-centric parts (URL model, link checks, gambling lookup) only matter for the minority of scam messages that carry a link.

### Cited Findings
- Of 1,152 validation scam messages, 225 contain a parseable link (672 val messages with a link: 225 scam / 447 benign) — [link_signals_val.md (b)](../../../../reports/link_signals_val.md), [otp_advisory_muril.md §2 (val scam n)](../../../../reports/otp_advisory_muril.md)
- README problem statement: "Digital arrest, fake KYC and parcel/customs scams usually arrive as a text or call script with no link at all" — [README.md](../../../../README.md)
- The sender field was removed because "users won't type a sender" — [decision log D22](../../../../docs/decisions/README.md)
- D5's survey of established apps: Truecaller's India SMS Fraud Protection is on-device, disables links and shows a red notification; "On-device scanners all offer a one-tap dispute" — [D5_operating_point.md §2](../../../../docs/decisions/D5_operating_point.md) (as reported there from web search snippets)
- Safety-advice cap built but off (fired on 0 of 5,267 validation rows); sender rule built then hidden from the UI; theme-switch animation built over several commits — [BUGS.md](../../../../BUGS.md), [decision log D22, D25](../../../../docs/decisions/README.md), [frontend/CLAUDE.md](../../../../frontend/CLAUDE.md)

### Inferences
- (to be completed with section 4's numbers)

### Gaps
- (to be completed)
