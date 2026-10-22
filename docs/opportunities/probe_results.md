# Investment / task-scam probe (before D28)

Date 2026-10-22. No app code changed. Script: `scripts/investment_probe.py` (`build`, `score`). Probe set: `data/probes/investment_probe.csv` (git-ignored; SHA-256 `bb646bfb205eb75106fb2746052ba54db1b5bec9469d22a76e51514fe3ab622d`, kept in `data/probes/investment_probe.sha256`). Scored through `analyse()` with the D27 MuRIL head (temperature-scaled; no network, `live=False`). Probe set only: never training, tuning or a threshold choice.

## Short answer

**Collect data first.** I could not build the set the brief asked for: public pages almost never quote the scam message itself. The probe has **8 real scam texts** (2 quoted in a cited page, 6 from our own `scam_ham_india`), not 20-30. That is too few to prove or kill the plan, and the 3 rules were written after reading these same rows, so their hit counts are optimistic. What the probe does show is below.

## 1. brainstorm.md fixes (done)

- "77%" is now **76% of money lost, digital arrest 9%, sextortion 4%** (MHA data via [ThePrint](https://theprint.in/india/cybercrime-saw-24-spike-in-2025-indians-lost-rs-22495-crore-mainly-in-investment-scams/2859930/), Rs 22,495 cr total; I fetched it and the article says "76 percent", though its lead says "more than 75 percent"). The 77% / 8% figures stay only where they are labelled as the I4C-via-The420 basis (Rs 19,813 cr).
- "0.24 -> 0.13" **removed** (2026-10-22), with the rest of the Wen et al. 2022 (IJERPH) sentence in brainstorm.md: the rates do not reconcile with the paper's own "62.3%" improvement, and its qualitative point about generic warnings could not be re-verified, so no generic-forewarning claim is kept. The design rules after it rest on the other cited studies and are unchanged.

## 2. How the probe set was collected

I used 14 fetches (limit ~15) plus searches. Reddit is blocked for the search tool. Result per source: 7 pages paraphrased the messages and quoted nothing (Open, iQOO, Nicobar Times, The420, Careerindia, IANS, cybershitty); 4 failed (403 from Newschecker and two Business Standard pages, a timeout from Angel One); only two gave text.

| Source | What it gave |
|---|---|
| [Malwarebytes, task-scam chat](https://www.malwarebytes.com/blog/news/2025/03/i-spoke-to-a-task-scammer-heres-how-it-went) | 2 real messages (first contact is cut at 125 characters by the fetch tool; an English-language, non-India contact) |
| [scamcheck.tech](https://scamcheck.tech/scams/investment-scam-india) | 2 example messages on an advocacy page, **not shown as real**, so `illustrative_cited` |
| our `scam_ham_india` | 2 task-job SMS, plus 4 stock-group lures from rows that are **labelled 0 (ham) in our data** |
| our `india_fraud_final` | 1 synthetic template ("VIP Level 2 Task") |

Not found anywhere: a quoted message with a fee demand to withdraw (except Malwarebytes' USDT one), a trading-app link message, or a personal-UPI payment request for trading.

**Genuine side (10):** our data has no genuine broker message (the benign "investment" rows are chat about markets). So 2 are TDS bank templates from `india_fraud_final` (synthetic) and 8 are **written by me from the public format of such alerts** (`illustrative_authored`: broker fund add, CDSL debit, SIP, exchange alert, IPO mandate, withdrawal, ledger, a SEBI-style `.brk@valid...` payment line). False alarms on these are weak evidence.

**Side finding, for BUGS.md:** four `scam_ham_india` rows labelled benign are lures from a stock-tip scam group ("Add my assistant Rama's WhatsApp, and she will notify you of the stock name and buying and selling points..."). MuRIL scores them 0.014-0.017, the same as the label says. That is a label question in the training data, not a model failure; I did not change any label.

3 further **constructed** rows (c01-c03) exist only to check that each regex fires; they are excluded from every count below.

## 3. Per-row result (MuRIL level, regex hits)

Rules, as first-pass regexes on the raw text: `pay_to_withdraw` (a fee / tax / deposit / USDT demand tied to withdrawing or releasing money), `trading_upi_not_valid` (a trading word plus a UPI-style handle that is not `@valid...`), `app_in_message` (trading word plus download / install an app / `.apk`, with no "official" or store wording).

| id | label | kind | provenance / split | MuRIL score | level | rules |
|---|---|---|---|---|---|---|
| s01 | scam | task | real_cited | 0.050 | No warning signs found | - |
| s02 | scam | task_pay_to_withdraw | real_cited | 0.017 | No warning signs found | pay_to_withdraw |
| s03 | scam | invest_group | illustrative_cited | 0.988 | Likely scam | - |
| s04 | scam | invest_advisor | illustrative_cited | 0.983 | Likely scam | - |
| s05 | scam | task | real_dataset / test | 0.989 | Likely scam | - |
| s06 | scam | task | real_dataset / train | 0.989 | Likely scam | - |
| s07 | scam | invest_group | real_dataset / train | 0.017 | No warning signs found | - |
| s08 | scam | invest_group | real_dataset / train | 0.014 | No warning signs found | - |
| s09 | scam | invest_group | real_dataset / train | 0.015 | No warning signs found | - |
| s10 | scam | invest_group | real_dataset / test | 0.016 | No warning signs found | - |
| s11 | scam | task_invest | synthetic_dataset / train | 0.988 | Likely scam | - |
| c01 | scam | pay_to_withdraw | constructed | 0.988 | Likely scam | pay_to_withdraw |
| c02 | scam | personal_upi | constructed | 0.988 | Likely scam | trading_upi_not_valid |
| c03 | scam | app_in_message | constructed | 0.262 | Likely scam | app_in_message |
| g01 | genuine | tds | synthetic_dataset / train | 0.015 | No warning signs found | - |
| g02 | genuine | tds | synthetic_dataset / train | 0.015 | No warning signs found | - |
| g03 | genuine | broker_funds | illustrative_authored | 0.015 | No warning signs found | - |
| g04 | genuine | depository | illustrative_authored | 0.017 | No warning signs found | - |
| g05 | genuine | mutual_fund | illustrative_authored | 0.016 | No warning signs found | - |
| g06 | genuine | exchange_alert | illustrative_authored | 0.022 | No warning signs found | - |
| g07 | genuine | ipo | illustrative_authored | 0.015 | No warning signs found | - |
| g08 | genuine | withdrawal | illustrative_authored | 0.988 | Likely scam | - |
| g09 | genuine | app_mention | illustrative_authored | 0.014 | No warning signs found | - |
| g10 | genuine | broker_upi | illustrative_authored | 0.870 | Likely scam | - |
Cut-offs: Suspicious 0.103, Likely 0.436 (MuRIL on val).

## 4. Decision table (non-constructed rows)

Rows from `train` were seen by MuRIL in training (s06, s07-s09, s11, the TDS pair), so they flatter it. The honest column is "not seen in train".

| Subset | Scams | MuRIL flags | Rules flag | Either | Genuine | MuRIL false alarms | Rules false alarms |
|---|---|---|---|---|---|---|---|
| All non-constructed | 11 | 5 | 1 | 6 | 10 | 2 (g08, g10) | 0 |
| Real text only (cited + dataset) | 8 | 2 | 1 | 3 | 0 | - | - |
| Not seen in train (any provenance) | 6 | 3 | 1 | 4 | 8 | 2 | 0 |
| Real and not seen in train (s01, s02, s05, s10) | 4 | 1 (s05) | 1 (s02) | 2 | - | - | - |
| Constructed rule tests (c01-c03) | 3 | 3 | 3 | 3 | - | - | - |

What each tells us:

- **MuRIL alone** catches texts that look like our synthetic templates (the "earn Rs X daily" tasks, the two scamcheck examples, VIP Level 2) and misses everything phrased as conversation: the stock-group lures (0.014-0.017) and both Malwarebytes messages (0.050, 0.017). Those are exactly the messages that tell a victim to move to a group or pay a withdrawal fee.
- **Rules alone** hit 1 real scam (s02, the USDT deposit to "reset" orders) and zero false alarms on the 10 genuine messages. They hit nothing in s01 or s07-s10 because those messages contain none of the three signals; the rules cannot see a group lure. Rules 2 and 3 fired on **no real row**; they only fired on messages I constructed to trigger them, so this probe says nothing about how often real scams contain a personal UPI id or an app link.
- **Both** add up to 6 of 11 overall, 4 of 6 on rows MuRIL had not trained on, and keep the rules' 0 false alarms; MuRIL's two genuine false alarms remain (g08, a withdrawal-processed notice, 0.988; g10, a payment line with a broker handle, 0.870). Both are my own authored text, so treat them as a prompt to test real broker messages, not as a measured rate.
- The set is tiny: with 4 real unseen scams, "1 of 4" and "2 of 4" are not distinguishable. No confidence claim should be drawn.

## 5. Recommendation: collect data first, then build only the part the data supports

1. **Do not build the 3 rules as the main feature yet.** On this evidence two of three never fired on a real message, and the one that did (pay-to-withdraw) needs more phrasings than one sample.
2. **Collect first**, ~50 real investment/task messages and ~50 genuine broker/TDS/IPO messages, from sources that actually keep the text: the user's own and friends' phones (with consent, masked), an NCRP / 1930 or I4C advisory PDF with screenshots, a Telegram scam-channel export, or the planned opt-in channel (brainstorm item 6). Screenshots through the existing OCR path would work. Keep them in `data/probes/`, never in training, until the final-test plan says otherwise.
3. **The "Ask someone first" button** (brainstorm item 1) does not depend on detecting these messages well, and the probe shows MuRIL misses the conversational ones; if you want something shippable now, that is the safe pick. It needs no new data.
4. If a rule is built anyway, start with **pay-to-withdraw** only, with the genuine "withdrawal processed ... charges are in your contract note" message (g08) as a must-not-fire fixture.
5. Open item for BUGS.md: the four stock-group lines labelled benign in `scam_ham_india`.
