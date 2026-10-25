# Real Indian messages: acquisition plan, screenshot intake, pilot

**Status (2026-10-25): plan + tools built + pilot run.** Built: `src/intake_screens.py` (screenshots / quoted text -> `data/collected/`),
`src/ocr_cer.py` (A2), `src/audit_dataset.py` (public dataset audit), `src/sample_size.py` (A3), `src/double_label.py` (blind sheet + kappa),
`docs/labelling_guide.md`, tests `tests/test_intake_screens.py` S1-S8. Pilot: 5 real messages ingested (target was <= 40; why so few is
section 5). Nothing here changes the app, the models, `messages.csv` or the splits (`split_map.csv` SHA-256 unchanged). Research notes
behind this plan: `research_notes/Real Indian message sourcing/` (source inventory, both pilot logs, every web call).

Two goals: (a) grow and trust the real-message evaluation; (b) give Phase B (`docs/plans/investment_scams.md` section 6) real investment /
loan / task scams **and** genuine broker / exchange / bank / lender messages, so MuRIL stops flagging genuine broker alerts (14 / 48 false
alarms on probe v1).

## 1. Findings in one screen

1. **We need hundreds, not thousands (A3: false).** For +-10 points at 95% (Wilson, worst case p = 0.5) a category needs **93** independent
   messages, for +-15 points **39**. Six categories x (scam, genuine) = 12 cells: **1,116** messages for +-10, **468** for +-15 (section 2).
2. **Public pages are a trickle.** Measured on the two top-ranked text sources: fact-check desks gave 4 full messages from 6 pages (all 4
   from ONE composite image), PIB re-reports gave 2 full messages from 8 pages (1 of them from 2022). Estimated human yield about **7.5** and
   about **3.3 real messages per hour**: both under the 10 per hour stop rule, so **neither is a bulk source** (section 5).
3. **Article text is not verbatim.** WebFetch cuts quotes at about 125 characters and rewrites them; even outlets rewrite: LatestLY's "quote"
   of the SBI reward SMS differs from PIB's own screenshot of it (casing, amount format, missing sign-off). **The screenshot is the source of
   truth**, typed by hand.
4. **A1 (screenshots are genuine): not disproved, not proven word for word.** 9 distinct messages checked for a second independent page:
   **0 exact**, **5 near** (the same template reported by another outlet or by the bank itself; 2 confirmed on the page, 3 from search
   summaries), 4 none (3 of them 5-12 word fragments that cannot be tested). Among the 6 full messages: 5 / 6 near, 0 / 6 exact.
5. **A2 (OCR is faithful): false on real public screenshots.** CER **24.3%** pooled (normalised; strict 25.7%) on **5** real English
   screenshots, per image 2.3% to 96.5%; target <= 3% **not met**. Clean full-size light screenshots are fine (2.3%, 4.9%); images shrunk
   inside a graphic (~300 px wide), dark bubbles on a photo wallpaper and chat chrome fail. Hindi / Kannada: **n = 0** (no real Indic
   screenshot met in the pilot). So collected screenshots are **typed by hand**; OCR only measures (section 5.3).
6. **No public dataset passes** (section 4): Mendeley f45bkkt8pr (76% near-duplicates of our train split, 1.8% Indian markers), the OTP SMS
   preview (no stated real collection, 9.6% of amounts with a machine-style leading zero), and the HF "Indian scam" sets (synthetic by their
   own cards). Two IEEE DataPort sets (Hindi; Dravidian incl. Kannada) claim real collection but could not be audited (access unknown).
7. **Genuine broker / exchange / depository alerts are not published as sample text anywhere we found** (SEBI's investor page, broker help
   pages: formats only). The real source is the phones of people with demat accounts, which collides with rule 12 (the user's phones are the
   test set). That needs a decision (section 10, D-a).
8. **Investment / loan / task scams show up publicly as descriptions** (SEBI press releases, crime reports: group names, tactics), not as
   message text. Reddit / X screenshots by hand are the only public route, untested here (no automated access, by rule).

## 2. Sample-size targets (A3)

`.venv/bin/python src/sample_size.py`: smallest n whose 95% Wilson half-width is <= h.

| expected rate p | n for +-10 pts | n for +-15 pts |
|---|---|---|
| 0.1 | 37 | 17 |
| 0.3 | 78 | 33 |
| 0.5 (plan with this) | **93** | **39** |
| 0.7 | 78 | 33 |
| 0.8 | 60 | 26 |
| 0.9 | 37 | 17 |

n counts **independent** messages: one per template group (the real intake's grouping), or multiply by the design effect 1 + (m - 1) rho
when m per group are kept (m = 3, rho = 0.5 doubles n). For a false-alarm rate on genuine messages p is the false-alarm rate (probe v1:
MuRIL 0.29 -> n = 78 for +-10).

| cell | evaluation target (val / real test) | why | Phase B train target (from the investment plan) |
|---|---|---|---|
| investment / trading: scam | >= 39 now (+-15), 93 later | go / no-go condition 2 asks >= 40 val rows | >= 200 (synthetic allowed, train only) |
| investment: genuine broker / exchange / depository / fund | >= 39 now, 93 later | the 14 / 48 false alarms are this cell | >= 300 |
| loan: scam / genuine registered-lender promo | 39 / 39 | | |
| task / part-time: scam (genuine = real job alerts) | 39 / 39 | | |
| KYC / bank: scam / genuine bank alerts | 39 / 39 | | |
| delivery: scam / genuine courier updates | 39 / 39 | | |
| digital arrest: scam | 39 | no genuine counterpart; report recall only | |
| **total, +-15 everywhere** | **~470 independent messages** (11 cells x 39 + slack) | | |

## 3. Ranked source inventory

Rank = yield x trust (trust 1-5: 5 = exported from a recipient's phone; 4 = screenshot a credible third party says circulated; 3 = verbatim
text, provenance per row unclear; 2 = paraphrase / illustration). "Measured" = this pilot; everything else is an estimate, marked.
Policy URLs marked (nf) were not fetched; "no policy found" means treat as all rights reserved and quote short excerpts with citation.

| # | source | URL | scam / genuine | format | yield (real msgs / hour) | trust | ToS / licence note | how to collect |
|---|---|---|---|---|---|---|---|---|
| 1 | Own, family and volunteer phones (SMS Backup & Restore XML, WhatsApp export) | https://www.synctech.com.au/sms-backup-restore/ (nf) | both; the only real source of genuine broker / bank alerts | text | hundreds (the user's SMS export already holds 6,560 received messages, as intake_real's reader counts them) | 5 | own data + written consent of each contributor; PII masked at ingestion (rule 5); the user's phones are already the TEST set (rule 12): see D-a | `intake_real.py` (test) / a train-side phone intake after D-a |
| 2 | Reddit (r/india, r/bangalore, r/IndiaInvestments) | https://www.reddit.com/r/IndiaInvestments/ | both; best public route for investment / task / loan scams | screenshot | 10-20 (estimate, untested) | 4 | User Agreement forbids automated scraping without permission (https://redditinc.com/policies/user-agreement, nf); viewing and hand screenshots for non-commercial research, usernames masked (`u/name` -> `<NAME>`), no redistribution | human search + screenshot, crop to the bubble, type it |
| 3 | X: @PIBFactCheck, @Cyberdost | https://x.com/PIBFactCheck | scam | screenshot | 15-20 (estimate) | 4 | X terms forbid scraping / crawling without consent (https://x.com/en/tos, nf); hand screenshots only; PIB's own reuse policy below | human, screenshot each post's image |
| 4 | Fact-check desks: Decode (BOOM), The Quint WebQoof, Factly, Newschecker | https://www.decodeinternet.in/decode/scamcheck/fake-rto-e-challan-message-on-whatsapp-a-growing-apk-scam-29919 | scam | screenshots (hero composites), few text quotes | **measured: 4 full from 6 pages, ~7.5 / h human estimate** (all 4 from one image) | 4 | no policy found; Factly and Moneylife answer 403 to scripts (fine by hand) | screenshot the article's message images, type them |
| 5 | News re-reports of PIB Fact Check (India.com, LatestLY, Deccan Chronicle, Outlook, newsonair) | https://www.latestly.com/social-viral/fact-check/did-you-receive-an-sms-or-whatsapp-message-asking-you-to-download-an-app-to-redeem-sbi-reward-points-pib-fact-check-debunks-fake-message-going-viral-7253978.html | scam | text quotes (rewritten) + embedded PIB X posts | **measured: 2 full from 8 pages (1 post-2024), ~3.3 / h** | 4 | PIB: reuse free without prior approval if accurate and not misleading, third-party material excluded (https://pib.gov.in/content/102_2_Copyright-Policy.aspx); outlets: no policy found | screenshot the embedded PIB image, not the article's retyped quote |
| 6 | Bank fraud-awareness pages (SBI, HDFC, ICICI, Axis) | https://www.icici.bank.in/personal-banking/help/online-safe-banking/report-unauthorized-transaction | scam (illustrative) + genuine sender rules | text | ~5 (estimate) | 2 | no policy checked; examples are usually written by the bank: provenance `illustrative` | copy, provenance illustrative / generic_script, never real |
| 7 | Broker / depository help pages with alert formats (Fyers, Geojit, Tradejini, CDSL SMART) | https://support.fyers.in/portal/en/kb/articles/why-do-i-receive-sms-and-email-notifications-from-nse-bse-or-mcx-when-i-trade | genuine (formats) | text | a format per page | 2 | no policy checked; formats, not received messages | provenance `generic_script`: format checklist for Phase B synthetic genuine templates (train only, rule 4) |
| 8 | SEBI / NSE / BSE caution notices, SEBI @valid circular | https://www.sebi.gov.in (PR 27/2025 mirror: https://files.hdfcfund.com/s3fs-public/inline-files/2025-05-21-SEBI%20Press%20Release%20%282%29.pdf) | scam tactics, group names; genuine ID format | PDF | 0-3 messages | 2 | SEBI booklets: free for non-profit education with acknowledgement; website policy not found | keywords and tactic tags (`invest_rules.py`), not messages |
| 9 | Regional crime reports (Deccan Herald etc.) | https://www.deccanherald.com/india/karnataka/bengaluru/bengaluru-two-lose-rs-215-crore-to-stock-scams-3618323 | investment-scam group names | text (paraphrase) | < 5 | 2 | no policy found | names for rules and synthetic templates |
| 10 | Government advisories: RBI BE(A)WARE, CERT-In, I4C / cybercrime.gov.in, Sanchar Saathi, TRAI | https://website.rbi.org.in/documents/87730/39016390/BEAWARE07032022.pdf | scam (descriptions); TRAI header rules | PDF | 0-5 | 2-3 | TRAI: free after permission by e-mail (https://trai.gov.in/website-policy); Sanchar Saathi: no reproduction without DoT permission (https://www.sancharsaathi.gov.in/Home/website-policies.jsp); RBI, CERT-In, I4C: no policy found | read for tactics; TRAI -P / -S / -T / -G sender suffixes (from 6 May 2025) are a genuine-sender signal |
| 11 | IEEE DataPort Hindi spam SMS (3,894) and Dravidian spam SMS (~7,700 incl. Kannada) | https://ieee-dataport.org/keywords/multilingual-sms | both | dataset | bulk | 3 (claims real collection; unchecked) | licence and access not found; DataPort often needs a free account | request access, then `audit_dataset.py` before any use; the Kannada set matters (val has 0 Kannada rows) |
| - | Rejected datasets | section 4 | | | | | | |

The PIB Fact Check portal (https://factcheck.pib.gov.in) is a login / submission page with no public archive (fetched 2026-10-25), and
Chakshu (Sanchar Saathi) is a reporting form: neither is a source.

## 4. Public dataset audit

`.venv/bin/python src/audit_dataset.py` -> `reports/dataset_audit.md`. Same checks for every set: template repetition (the real intake's
grouping, `neardup` rule), label balance, distribution uniformity (category counts, length spread, leading-zero amounts, Benford on amounts),
stated provenance, near-duplicate overlap with our train split, share of rows with an Indian marker. Controls with known answers run
through the same checks.

| dataset | rows | in a template group | overlap with train | Indian marker | verdict and reason |
|---|---|---|---|---|---|
| uci_sms_spam (control, real) | 4,617 | 6.1% | (train) | 0.2% | control |
| india_fraud_final (control, 85.5% generated) | 2,890 | 99.6% | (train) | 49.8% | control: exact 50/50 labels, 6.8 rows per template, Benford MAD 0.045 |
| synth_india (control, generated) | 756 | 99.3% | (train) | 78.6% | control: 10.8 rows per template, Benford MAD 0.077 |
| scam_ham_india (already in training) | 2,035 | 19.1% | (train) | 26.9% | **cannot count as real**: no stated collection (rule 4); Benford MAD 0.041 (flag) |
| otp_sms_preview (HF, gandharvbakshi) | 10,000 | 59.3% | 1.8% | 43.5% | **REJECT**: no stated real collection (its card mixes real, LLM-labelled and synthetic rows); 9.6% of 4,068 amounts have a leading zero ("INR 040.27") |
| mendeley_smishing (Mishra & Soni 2022, CC BY 4.0) | 5,971 | 14.9% | **76.3%** | 1.8% | **REJECT**: three quarters are near-duplicates of our train split (its messages are credited to the UCI collection's author); not Indian |
| Shade63/scam-classification-multiclass, bolewara/hinglish-scam-text-dataset (HF) | - | - | - | - | not downloaded: their own cards say AI-generated / "written to mirror real scam patterns" (synthetic) |
| SmishTank (arXiv 2402.18430) | - | - | - | - | not audited: licence not found, likely US-centred |
| IEEE DataPort Hindi / Dravidian | - | - | - | - | not audited: access unknown (section 3, row 11) |

Benford is a flag, not a reject rule: no real Indian control with >= 100 rupee amounts exists here, so the 0.015 threshold is untested on
real Indian SMS (promo prices like 99 / 499 may break Benford on their own). Template repetition is also a flag: real inboxes are templated.

## 5. Pilot

### 5.1 Protocol and yield

Two passes over the top two text sources of the ranking (fact-check desks = A; PIB re-reports = B). Pass 1 (a research agent, WebFetch,
`pilot_log.md`): 9 pages, 4.3 agent minutes, 5 messages, 4 of them fragments cut by WebFetch. Pass 2 (main session, raw HTML with curl +
article images, `pilot_pass2.md`): 8 pages and 5 images, 5.4 agent minutes, 5 full messages. Only pass 2's 5 messages were ingested:
pass 1's text is a model's transcription, not the page.

| source | distinct pages opened | full messages | fragments | ingested | pre-2024 | human estimate (4 min per page + 2 min per message typed) |
|---|---|---|---|---|---|---|
| A: fact-check desks (The Quint x5, Decode x1) | 6 | 4 (all from one Decode hero image) | 3 | 4 | 0 | 32 min -> **~7.5 / h** |
| B: PIB re-reports (India.com, Outlook Business, Deccan Chronicle, LatestLY, newsonair, VARIndia (opened during A1); YourStory and Moneylife 403) | 8 | 2 (SBI reward 2025; SBI "documents expired" 2022) | 1 | 1 | 1 (not ingested) | 36 min -> **~3.3 / h** (~1.7 counting only 2024+) |

Agent minutes are not human minutes, so the per-hour figures are estimates from the page and message counts; the user's own timed session
(section 9) replaces them. **Stop rule (< 10 real messages per hour -> drop):** both sources fall under it as bulk sources. They stay useful
for A1 corroboration and as a small eval-only top-up of `real_circulating` scam rows.

What blocked yield: articles describe messages in their own words; message images are lazy-loaded or embedded X posts; 4 hosts answer 403
to scripts; the PIB portal has no archive; the web-search tool is US-only and finds no Indian exact phrases.

### 5.2 A1: a second independent page with the same wording

| message (source) | second page | match |
|---|---|---|
| SBI reward points APK (B) | India.com 2026-07-06 vs LatestLY 2025-12-27, both from PIB's post | near (page-confirmed; casing / amount format differ) |
| SBI "documents have expired" (B, 2022) | VARIndia vs Outlook Business | near (page-confirmed; different wording of one template) |
| PNB KYC block + APK (A) | PNB's own caution (DT Next, Newsgram 2023) | near (search summary; wording not confirmed) |
| ICICI PAN block + APK (A) | ICICI's caution (Outlook Money) | near (search summary) |
| VAHAN PARIVAHAN challan APK (A) | Deccan Herald, The Quint, Moneylife on the campaign | near (search summary) |
| J&K electricity disconnection + APK (A) | none found | none |
| 3 Quint fragments (e-challan x2, RCB reward) (A) | none | none (5-12 words: untestable) |

**A1 match rate: exact 0 / 9; exact or near 5 / 9 (56%); on full messages 5 / 6 (83%) near, 0 / 6 exact.** No item looked like a meme or an
edit, and the template recurs across independent outlets or the impersonated bank for 5 of 6 full messages, which is what real circulation
looks like. But word-for-word corroboration is 0: outlets retype messages and search engines do not index the text inside screenshots. Rows
carry `verified` (exact / near / none / unchecked); evaluation should report verified and unchecked rows separately.

### 5.3 A2: OCR character error rate (jiwer)

`src/ocr_cer.py data/collected/inbox/pilot2/a2` -> `reports/ocr_cer_public.md`. Typed by hand from the image (by Claude, before OCR ran);
4 crops of the Decode composite + the user's own dark-mode dev screenshot (`tests/fixtures/real/jio_kiwi_dark.jpg`).

| image | width px | CER strict | CER normalised | ocr_conf |
|---|---|---|---|---|
| Decode VAHAN challan (light) | 315 | 0.038 | **0.023** | 0.942 |
| user's Jio promo (dark, Android) | 683 | 0.062 | **0.049** | 0.821 |
| Decode PNB KYC (dark WhatsApp) | 308 | 0.194 | 0.180 | 0.787 |
| Decode electricity (light WhatsApp, sender header, APK card) | 308 | 0.254 | 0.231 | 0.635 |
| Decode ICICI (dark bubble on a photo wallpaper) | 289 | 0.965 | 0.965 | 0.372 |
| **pooled, English, n = 5 (1,032 reference characters)** | | **0.257** | **0.243** | |
| Hindi / Kannada | n = 0 | - | - | - |

Diagnosis (inspected after the references were fixed): resolution dominates; at 3x size the pooled CER falls to 0.145 (ICICI 0.965 ->
0.303) but the full-size Jio screenshot gets worse (0.049 -> 0.201), so no single upscale setting fixes it (a width-dependent upscale below
~400 px is a candidate for the reader, not built: it needs its own measurement). The `eng+hin+kan` language set inserts stray Devanagari and
Kannada glyphs into noisy English. In these 5, ocr_conf >= 0.82 went with CER <= 5% and <= 0.79 with CER >= 18%, hence
`intake_screens.REVIEW_CONF = 0.80` (provisional, n = 5). Real phone screenshots (~1080 px) should do better than these crops; the user's
own screenshots will show it, since every typed screenshot records its `ocr_cer`.

### 5.4 A4: recency

Ingested rows: 4 dated 2024-09-17 (the Decode image's upload date; reused in a 2025-11-05 article), 1 dated 2025-12-27. Two pass-1 rows from
2022-05-23 (Outlook Business, VARIndia) are flagged pre-2024 and were not ingested. The intake writes `date_flag` (`pre_2024` / `unknown`).

### 5.5 Collisions

0 of the 5 ingested rows is a near-duplicate of `data/real/` (6,560 texts read and masked in memory), of `data/probe/` (102) or of any split
of `messages.csv`. `tests/test_intake_screens.py` S8 re-checks `data/collected/` against `data/real/` on every pytest run.

## 6. Legal and terms (applies to every source)

- Only the page that **shows** a message is fetched, once, by hand or with one request; never a link from inside a message (rule 8), never a
  crawl. X, Reddit, Facebook, Instagram and Telegram are viewed by a human only (their terms forbid scraping without consent).
- Images and HTML stay in `data/collected/inbox/` (git-ignored) and are never redistributed. The stored row is the masked, defanged message
  text with its `source_url` (defanged) as the citation; this is a short excerpt of third-party material for non-commercial research.
- PIB's reuse permission excludes third-party material, and a forwarded scam screenshot arguably is third-party: cite, do not republish.
- Sanchar Saathi forbids reproduction without DoT permission and TRAI asks for permission by e-mail: read them, do not copy them into data.
- Contributed phone exports need each contributor's consent; names, numbers, UPI ids, e-mails and account numbers are masked at ingestion.
- Keep the repo private (CLAUDE.md already requires it); `data/collected/` must never be pushed.

## 7. The intake (built)

```
.venv/bin/python src/intake_screens.py data/collected/inbox/<batch>/          # images + sources.csv
.venv/bin/python src/intake_screens.py data/collected/inbox/<file>.csv        # quoted text only
```

`sources.csv`: `filename, source_url, date_seen, channel` (+ `text` = the message typed by hand, `label`, `category`, `verified`,
`a1_second_url`, `outlet`, `provenance`, `notes`). Per row: OCR (the app's reader) or the typed text -> mask (`intake_real.mask` = `pii.py` +
card / OTP / account-tail / digit-run masks; greeting names and `u/` / `@` handles -> `<NAME>`) -> defang -> PII and live-link checks (stop
on any) -> near-duplicate check against `data/real/`, `data/probe/` and all of `messages.csv` (any collision drops the row) ->
`data/collected/<registered domain>/collected.csv` with `source_url, channel, date_seen, collector, verified, ocr_conf, ocr_cer,
needs_review, template_group, group_sources`. One folder per source domain so a later split can keep a whole source on one side.

## 8. Labelling quality

`docs/labelling_guide.md`: scam / genuine / skip, with the loan-promo and broker-alert edge cases; the Phase B question (scam-group lines that
ask for nothing) is left to its own decision (labelled skip + `group_line` until then). `data/collected/double_label_sample.csv`: 50 rows,
blind (5 collected + 45 real val rows, 25 scam / 25 genuine by the first label; key in `double_label_key.csv`). After a second person fills
`label_2`: `.venv/bin/python src/double_label.py kappa` -> `reports/double_label_kappa.md`. kappa < 0.60 -> rewrite the edge cases first.

## 9. Plan by week

**Stop conditions.** (1) A source yielding < 10 real messages per hour over a timed human session of >= 30 minutes is dropped. (2) The
investment plan's rule: if go / no-go condition 2 (>= 40 investment-scam and >= 40 genuine investment rows for val) cannot be met within
about two weeks of collecting (by about 8 Nov), stop at Phase A and record the gap in BUGS.md. (3) kappa < 0.60 stops labelling until the
guide is fixed.

| when | what | who |
|---|---|---|
| **Week of 26 Oct** | Label and **freeze the real test set first** (`intake_real.py` -> `label_me.csv` -> `review_names.csv` -> `--freeze`), so every later collection is checked against a frozen set | user |
| | Two timed 45-minute screenshot sessions (Reddit / X searches + the URL list below), typed into `sources.csv`, run the intake; replace the yield estimates with measured ones; apply stop rule 1 | user |
| | Second person labels `double_label_sample.csv` blind; run kappa | user + 1 person |
| | Decision D-a (section 10) written as a decision record, proposal only | next session (Opus, high) |
| **2-6 Nov** | If D-a approved: genuine broker / bank / fund SMS from family demat holders into a train-side folder (not `data/real/`), near-duplicate checked against the frozen test set | user |
| | Count investment val candidates against condition 2; Phase B go / no-go | next session |
| **6 Nov** | Deliver Phase A + this plan + the pilot numbers. **No retrain before 6 Nov**: splits-v3 + Kaggle + evaluation is 6-8 sessions and does not fit | - |
| **After 6 Nov (Phase B)** | Week 1: keep only sources that passed rule 1; request IEEE DataPort access and audit both sets. Week 2: labelling decision (investment plan step 1) + relabel the 39 + 84 rows; synthetic investment templates (train only). Week 3: splits-v3 with `data/collected/` grouped by source domain and template; re-upload Kaggle. Week 4: retrain MuRIL, evaluate, probe v2 | sessions per the investment plan |

## 10. Decisions needed (not taken here)

- **D-a: phones for training vs the test set.** The real-message test set comes from the user's phones (rule 12), and genuine broker / bank
  alerts can only come from phones. Options: (1) different people: test = the phones already in `data/real/raw/`, training = family /
  volunteer phones, every row near-duplicate checked against the frozen test set (the intake already does this) and collisions dropped;
  (2) a date split on the same phones (high template overlap: the same broker sends the same alert); (3) a template-group split on the same
  phones. Recommendation: (1). It also needs a train-side phone intake (intake_real's readers + intake_screens' writer), not built yet.
- **D-b: can `real_circulating` public rows sit in val?** Proposal: yes, reported separately as "public, circulating", never mixed into
  the phone-based real-message test numbers.
- **D-c: keep the TRAI sender-suffix letter** (-P / -S / -T / -G) in phone intakes as a privacy-safe column (the full header is dropped today).

## 11. URL list to screenshot by hand (host pages only; type each message into `sources.csv`)

Expect few messages per page (section 5). Pages 1-16 should show message images or quotes; 17-26 are investment-scam pages (expect group
names and tactics, screenshot any message shown); 27-30 are genuine-format pages (provenance `generic_script`).

1. https://www.india.com/business/sbi-customers-attention-received-a-message-asking-to-download-and-install-apk-file-to-redeem-sbi-reward-over-whatsapp-sms-heres-the-truth-pib-fact-check-says-fake-8466504/ (embedded PIB post image)
2. https://deccanchronicle.com/nation/rbi-did-not-send-whatsapp-apk-notices-warns-pib-fact-check-1963061 (PIB screengrab)
3. https://factly.in/pending-traffic-challan-links-sent-via-sms-and-whatsapp-are-fake-and-fraudulent/ (403 to scripts; open by hand)
4. https://www.thequint.com/news/webqoof/gas-bill-scam-where-scammers-send-malicious-apps-and-links-via-whatsapp-to-access-victims-phones
5. https://www.thequint.com/news/webqoof/fake-doctor-appointment-app-scam-using-apk-file
6. https://www.thequint.com/amp/story/news/webqoof/e-challan-scam-where-victims-are-targeted-with-malware-via-apk-files
7. https://www.angelone.in/news/market-updates/pib-fact-check-is-the-government-giving-rs-46715-to-every-citizen
8. https://www.angelone.in/news/market-updates/pib-fact-check-free-laptop-scheme-2025-under-narendra-modi-govt-is-fake-news
9. https://mymobileindia.com/no-the-government-isnt-giving-free-acs-pm-modi-ac-yojana-2025-is-fake-says-pib/
10. https://www.outlookmoney.com/news/pib-alerts-ippb-account-holders-to-pan-card-scam
11. https://www.outlookmoney.com/news/fake-traffic-e-challan-messages-can-expose-otps-trigger-unauthorised-bank-transactions-pib-warns
12. https://www.outlookmoney.com/banking/new-cyber-threat-icici-bank-issues-cautions-heres-what-you-can-do
13. https://www.dtnext.in/news/business/pnb-cautions-customers-about-fake-message-circulating-on-digital-platforms
14. https://moneylife.in/article/fraud-alert-from-echallan-gas-bill-updates-to-apk-traps-how-malware-scams-are-draining-bank-accounts/79996.html (403 to scripts)
15. https://yourstory.com/2024/07/report-sms-scams-india-chakshu (403 to scripts)
16. https://www.sancharsaathi.gov.in/SancharSaathiDocuments/ImportantDocuments/Press%20Release-DoT%20takes%20action%20against%20Electricity%20KYC%20Update%20Scam.pdf
17. https://www.deccanherald.com/india/karnataka/bengaluru/bengaluru-two-lose-rs-215-crore-to-stock-scams-3618323
18. https://www.deccanherald.com/india/karnataka/bengaluru/retiree-private-firm-employee-lose-over-rs-1-crore-each-to-trading-scam-3546522
19. https://www.deccanherald.com/amp/story/india%2Fkarnataka%2Fmangaluru%2Fmangaluru-man-loses-rs-42-lakh-in-investment-scam-3752090
20. https://www.newsarenaindia.com/states/75-year-old-bengaluru-woman-loses-2-cr-in-investment-scam/36036
21. https://www.business-standard.com/amp/finance/personal-finance/fake-profits-to-human-trafficking-the-whatsapp-stock-market-scam-decoded-124090900416_1.html
22. https://files.hdfcfund.com/s3fs-public/inline-files/2025-05-21-SEBI%20Press%20Release%20%282%29.pdf (SEBI PR 27/2025)
23. https://www.business.hsbc.bank.in/-/media/media/india/pdf/sebi-caution-notice.pdf (SEBI PR 22/2025)
24. https://www.deccanherald.com/amp/story/india%2Fkarnataka%2Fbengaluru%2Fbengaluru-resident-loses-rs-5-6-lakh-in-traffic-fine-scam-3425345
25. https://the420.in/how-cybercriminals-are-cheating-in-the-name-of-icici-bank/ (Hindi)
26. https://www.boomlive.in/decode/kyc-scams-are-zooming-how-fraudsters-hijack-bank-accounts-26386
27. https://support.fyers.in/portal/en/kb/articles/why-do-i-receive-sms-and-email-notifications-from-nse-bse-or-mcx-when-i-trade
28. https://support.geojit.com/support/solutions/articles/89000007420-why-do-i-receive-an-email-and-sms-from-nse-bse-for-each-executed-trade-
29. https://faq.tradejini.com/?p=15873
30. https://www.cdslindia.com/Footer/Smart.html

Searches to run by hand (not URLs; human only): Reddit r/IndiaInvestments "WhatsApp group" / "SEBI registered" / "IPO allotment", r/india
and r/bangalore "scam SMS" / "part time job" / "loan app"; X `from:PIBFactCheck` and `from:Cyberdost` (2025-2026).

## 12. Limits

- The pilot is small: 14 article pages (plus the PIB portal and a 404 hub page), 5 ingested messages, A1 n = 9, A2 n = 5. Yields per hour are estimates from page counts, not timed
  human sessions.
- A2's references were typed by Claude, not a human; a human spot-check of the 5 is cheap (`data/collected/inbox/pilot2/a2/typed.csv`).
- The A2 images are crops of one composite, smaller than real phone screenshots, so 24% is pessimistic for a person's own screenshots and
  says nothing about Hindi / Kannada.
- Public scam messages skew to KYC / APK / challan / government-scheme; investment, loan and task scams and every genuine category have to
  come from phones and hand-collected posts.
- `data/collected/` rows are public messages: a message seen widely may also be in a contributor's phone later; the intake drops it only
  if that phone's export is already in `data/real/` when the intake runs.

## 13. Budget used

Web calls: **68 of 80** (WebSearch + WebFetch + curl downloads, failures counted): research agent 1, source inventory: 25 (22 searches, 3
fetches); research agent 2, pilot pass 1: 24; main session: 19 (1 dataset download, 7 page fetches, 5 image downloads, 1 failed hub fetch,
5 searches). Subagents: **2 of 2**, one at a time. No Firecrawl call, no X / Reddit fetch, no link from inside a message opened.
