# Investment / trading / task-scam audit

Made by `src/audit_investment.py` (measurement only; nothing here is in the app). Plan: `docs/plans/investment_scams.md`. **No test-split row was read**: `messages.csv` is streamed and test rows are dropped before their text is used; the val numbers come from the cached `reports/eval_preds/*/predictions_val.csv`.

## 1. Data inventory (train + val; test not read)

No source has an investment, trading or crypto category. The only category route is `india_fraud_final`'s task subcategories (Instagram_Task, Investment_Task, Survey_Task, TikTok_Task, VIP_Task, YouTube_Task, eBay_Task). Everything else is keyword search: `INVEST_RX`, `CRYPTO_RX`, `TASK_RX` in the script.

| topic | source | train scam | train genuine | val scam | val genuine |
|---|---|---|---|---|---|
| invest | scam_ham_india | 1 | 104 | 0 | 19 |
| invest | translated_indic | 0 | 2 | 0 | 0 |
| invest | uci_sms_spam | 0 | 1 | 0 | 0 |
| invest | hinglish_conversations | 0 | 2 | 0 | 0 |
| invest | ealvaradob_phishing | 2 | 0 | 0 | 0 |
| invest | phishing_email (long-form) | 248 | 165 | 44 | 12 |
| invest | fake_job_postings (long-form) | 5 | 113 | 0 | 77 |
| crypto | hinglish_conversations | 0 | 1 | 0 | 0 |
| crypto | scam_dialogue | 1 | 0 | 0 | 0 |
| crypto | phishing_email (long-form) | 3 | 18 | 3 | 3 |
| crypto | fake_job_postings (long-form) | 0 | 23 | 0 | 0 |
| task | india_fraud_final | 93 | 0 | 6 | 0 |
| task | scam_ham_india | 15 | 0 | 2 | 1 |
| task | synth_india | 15 | 0 | 0 | 0 |
| task | uci_sms_spam | 0 | 1 | 0 | 0 |
| task | phishing_email (long-form) | 29 | 12 | 2 | 0 |
| task | fake_job_postings (long-form) | 46 | 165 | 2 | 15 |

Category route alone (`india_fraud_final` task subcategories): train 57 scam / 0 genuine, val 6 / 0.

Likely mislabelled (genuine label, reads as scam-group or task chat): **123 rows** -> `reports/investment_mislabel_candidates.csv` (ids only). ('stock-group chat (GROUP_RX)', 'train'): 34, ('stock-group chat (GROUP_RX)', 'val'): 5, ('uncertain: market chat in the same source, no group marker', 'train'): 70, ('uncertain: market chat in the same source, no group marker', 'val'): 14

## 2. Val subset, existing predictions

Cut-offs: each model's own val cut-offs from `scored.json` (MuRIL 0.037 / 0.405 on the uncalibrated score = the app's 0.103 / 0.436 after temperature; splits-v2 baseline 0.456 / 0.661). The app's TF-IDF head is the splits-v1 fit and has no cached val predictions, so the splits-v2 refit stands in for it here.

| val subset | model | scams | caught >= Suspicious | caught Likely | genuine | false alarms >= Suspicious | false alarms Likely |
|---|---|---|---|---|---|---|---|
| investment / stock (short-message sources) | MuRIL | 0 | 0/0 | 0/0 | 0 | 0/0 | 0/0 |
| investment / stock (short-message sources) | baseline (splits-v2) | 0 | 0/0 | 0/0 | 0 | 0/0 | 0/0 |
| task / part-time (short-message sources) | MuRIL | 8 | 8/8 (100%) | 8/8 (100%) | 1 | 0/1 (0%) | 0/1 (0%) |
| task / part-time (short-message sources) | baseline (splits-v2) | 8 | 8/8 (100%) | 8/8 (100%) | 1 | 0/1 (0%) | 0/1 (0%) |
| crypto (all sources) | MuRIL | 3 | 3/3 (100%) | 3/3 (100%) | 3 | 0/3 (0%) | 0/3 (0%) |
| crypto (all sources) | baseline (splits-v2) | 3 | 3/3 (100%) | 3/3 (100%) | 3 | 0/3 (0%) | 0/3 (0%) |
| investment keywords, phishing_email (US stock spam) | MuRIL | 44 | 41/44 (93%) | 40/44 (91%) | 12 | 0/12 (0%) | 0/12 (0%) |
| investment keywords, phishing_email (US stock spam) | baseline (splits-v2) | 44 | 41/44 (93%) | 37/44 (84%) | 12 | 0/12 (0%) | 0/12 (0%) |
| task keywords, fake_job_postings | MuRIL | 2 | 1/2 (50%) | 1/2 (50%) | 15 | 0/15 (0%) | 0/15 (0%) |
| task keywords, fake_job_postings | baseline (splits-v2) | 2 | 1/2 (50%) | 0/2 (0%) | 15 | 0/15 (0%) | 0/15 (0%) |

Val rows likely mislabelled (scam-group chat labelled genuine), left out of the genuine columns above: 5. If they are scams, this is recall on them:
- MuRIL: flagged >= Suspicious 0/5 (0%), Likely 0/5 (0%)
- baseline (splits-v2): flagged >= Suspicious 0/5 (0%), Likely 0/5 (0%)

Val rows uncertain (market chat in the same source, no group marker), left out of the genuine columns above: 14. If they are scams, this is recall on them:
- MuRIL: flagged >= Suspicious 0/14 (0%), Likely 0/14 (0%)
- baseline (splits-v2): flagged >= Suspicious 1/14 (7%), Likely 0/14 (0%)


## 3. Probe set v1 (`data/probe/investment_v1.csv`, PROBE-ONLY)

54 scam rows, 48 genuine rows; router with `live=False`. Flagged = Suspicious or Likely scam.

| set | head | scams | text head >= Suspicious | router >= Suspicious | router Likely | genuine | router false alarms >= Suspicious | router false alarms Likely |
|---|---|---|---|---|---|---|---|---|
| all | MuRIL | 54 | 39/54 (72%) | 39/54 (72%) | 39/54 (72%) | 48 | 14/48 (29%) | 13/48 (27%) |
| all | baseline (app, splits-v1) | 54 | 40/54 (74%) | 40/54 (74%) | 28/54 (52%) | 48 | 18/48 (38%) | 8/48 (17%) |
| quoted (verbatim + fragments) | MuRIL | 9 | 5/9 (56%) | 5/9 (56%) | 5/9 (56%) | - | - | - |
| quoted (verbatim + fragments) | baseline (app, splits-v1) | 9 | 7/9 (78%) | 7/9 (78%) | 3/9 (33%) | - | - | - |
| written from a cited source | MuRIL | 45 | 34/45 (76%) | 34/45 (76%) | 34/45 (76%) | - | - | - |
| written from a cited source | baseline (app, splits-v1) | 45 | 33/45 (73%) | 33/45 (73%) | 25/45 (56%) | - | - | - |

By kind:

| label | kind | rows | MuRIL router >= Suspicious | baseline router >= Suspicious |
|---|---|---|---|---|
| scam | account_handling | 1 | 1 | 1 |
| scam | app_in_message | 1 | 1 | 1 |
| scam | assured_returns | 2 | 2 | 2 |
| scam | celebrity_scheme | 2 | 2 | 2 |
| scam | crypto_invest | 1 | 1 | 1 |
| scam | crypto_task | 2 | 2 | 2 |
| scam | dabba_trading | 1 | 1 | 1 |
| scam | early_stage | 2 | 0 | 0 |
| scam | fake_registered_advisor | 2 | 2 | 2 |
| scam | fake_testimonial | 1 | 0 | 0 |
| scam | group_brand_impersonation | 3 | 2 | 1 |
| scam | group_invite | 1 | 1 | 1 |
| scam | group_ipo_app | 2 | 0 | 0 |
| scam | institutional_account | 1 | 0 | 1 |
| scam | ipo_preallotment | 2 | 1 | 1 |
| scam | pay_to_withdraw | 6 | 6 | 5 |
| scam | personal_upi | 1 | 1 | 1 |
| scam | pump_and_dump | 2 | 1 | 1 |
| scam | sms_tip_paid | 3 | 2 | 2 |
| scam | task_invite | 6 | 5 | 6 |
| scam | task_lock_in | 1 | 0 | 0 |
| scam | task_pay_more | 1 | 1 | 1 |
| scam | task_pay_to_withdraw | 1 | 0 | 1 |
| scam | task_payment | 1 | 0 | 0 |
| scam | task_prepaid | 2 | 2 | 2 |
| scam | task_withdraw_block | 3 | 3 | 3 |
| scam | telegram_tips | 2 | 2 | 2 |
| scam | vip_upgrade_fake_cert | 1 | 0 | 0 |
| genuine | amc_nfo_promo | 1 | 0 | 0 |
| genuine | broker_account_open | 1 | 0 | 0 |
| genuine | broker_add_funds | 1 | 1 | 1 |
| genuine | broker_awareness | 1 | 1 | 1 |
| genuine | broker_contract_note | 1 | 0 | 0 |
| genuine | broker_funds_added | 1 | 0 | 1 |
| genuine | broker_margin_call | 1 | 0 | 0 |
| genuine | broker_otp | 1 | 0 | 1 |
| genuine | broker_pledge | 1 | 1 | 1 |
| genuine | broker_promo | 1 | 0 | 0 |
| genuine | broker_withdrawal | 1 | 1 | 1 |
| genuine | broker_withdrawal_tax | 1 | 0 | 0 |
| genuine | depository_corp_action | 1 | 1 | 0 |
| genuine | depository_credit | 1 | 0 | 0 |
| genuine | depository_debit | 2 | 0 | 0 |
| genuine | depository_master_change | 1 | 0 | 0 |
| genuine | dividend_credit | 1 | 0 | 0 |
| genuine | edis_otp | 1 | 0 | 0 |
| genuine | exchange_awareness | 2 | 1 | 2 |
| genuine | exchange_balance | 2 | 0 | 1 |
| genuine | exchange_trade_alert | 3 | 0 | 1 |
| genuine | ipo_allotment | 1 | 1 | 1 |
| genuine | ipo_block | 1 | 0 | 0 |
| genuine | ipo_mandate | 2 | 0 | 0 |
| genuine | ipo_open | 1 | 0 | 0 |
| genuine | ipo_unblock | 1 | 0 | 0 |
| genuine | kyc_status | 1 | 1 | 1 |
| genuine | mf_redemption | 1 | 1 | 1 |
| genuine | mf_statement | 1 | 0 | 1 |
| genuine | nach_mandate | 1 | 0 | 0 |
| genuine | registered_ra_tip | 2 | 2 | 1 |
| genuine | sip_allotment | 1 | 0 | 0 |
| genuine | sip_debit | 1 | 0 | 1 |
| genuine | sip_failed | 1 | 0 | 1 |
| genuine | sip_reminder | 1 | 0 | 1 |
| genuine | tds_alert | 2 | 0 | 0 |
| genuine | tpin | 1 | 0 | 0 |
| genuine | valid_upi_template | 3 | 3 | 0 |

10 worst misses (MuRIL router):

| id | kind | provenance | MuRIL score / router | baseline score / router | text (first 90 chars) |
|---|---|---|---|---|---|
| s18 | group_ipo_app | written_from_source | 0.015 / No warning signs | 0.301 / No warning signs | Dear members of FHL Investors (Teaching Group) VIP 903, the Varyaa Creations IPO subscript |
| s52 | early_stage | written_from_source | 0.015 / No warning signs | 0.019 / No warning signs | Good morning group members. Nifty may open flat today. The teacher will share today's stoc |
| s03 | task_pay_to_withdraw | verbatim_quote | 0.016 / No warning signs | 0.658 / Likely scam | I forgot to tell you, it takes 100usdt to complete a new round of 40/40 orders to reset 40 |
| s13 | vip_upgrade_fake_cert | written_from_source | 0.017 / No warning signs | 0.278 / No warning signs | Congratulations, you have been upgraded to our VIP group. Our SEBI registration certificat |
| s16 | ipo_preallotment | written_from_source | 0.018 / No warning signs | 0.34 / No warning signs | Our FII channel has secured pre-allotment of shares in the upcoming IPO. Apply through our |
| s54 | group_brand_impersonation | written_from_source | 0.018 / No warning signs | 0.08 / No warning signs | Hi, I am an assistant from the Zerodha team. Join our private group for premium signals an |
| s28 | pump_and_dump | written_from_source | 0.022 / No warning signs | 0.329 / No warning signs | Buy A-1 Ltd now, big news coming. Target double in 2 weeks. Don't miss this chance. |
| s51 | fake_testimonial | written_from_source | 0.023 / No warning signs | 0.207 / No warning signs | Thank you teacher! I made Rs 1.2 lakh profit today following your call. Everyone please fo |
| s53 | early_stage | written_from_source | 0.023 / No warning signs | 0.084 / No warning signs | Hi, I came across your profile. Our study group discusses the Indian stock market every ev |
| s24 | group_ipo_app | written_from_source | 0.025 / No warning signs | 0.363 / No warning signs | Stock Market Research Institute: download Wells Pro to subscribe to the Konstelec IPO at a |

Genuine rows flagged by either head:

| id | kind | MuRIL score / router | baseline score / router | text (first 90 chars) |
|---|---|---|---|---|
| g01 | exchange_trade_alert | 0.023 / No warning signs | 0.627 / Suspicious | NSE: Dear Investor, trades were executed today in your account with member ABC Securities  |
| g04 | exchange_balance | 0.018 / No warning signs | 0.698 / Likely scam | BSE: Funds balance as per your broker as on 30-SEP-26: Rs 0.00. Securities: 0 ISINs. This  |
| g07 | depository_corp_action | 0.633 / Likely scam | 0.226 / No warning signs | CDSL: Credit of 20 bonus shares of EXAMPLE INDUSTRIES in your demat a/c XXXXXXXX5678 due t |
| g14 | ipo_allotment | 0.988 / Likely scam | 0.83 / Likely scam | Dear Investor, you have been allotted 1 lot (50 shares) in the EXAMPLETECH LTD IPO. Rs 14, |
| g15 | sip_debit | 0.021 / No warning signs | 0.489 / Suspicious | Your SIP instalment of Rs 5,000 in Example Flexi Cap Fund - Direct Growth, folio 1234567,  |
| g17 | sip_failed | 0.049 / No warning signs | 0.501 / Suspicious | Your SIP instalment of Rs 2,000 for folio 1234567 could not be processed due to insufficie |
| g18 | mf_redemption | 0.972 / Likely scam | 0.732 / Likely scam | Your redemption request of 100 units from Example Liquid Fund, folio 1234567, has been pro |
| g21 | valid_upi_template | 0.968 / Likely scam | 0.223 / No warning signs | We have a validated UPI ID for payment, please pay us at examplebroker.brk@validhdfc. |
| g22 | valid_upi_template | 0.978 / Likely scam | 0.398 / No warning signs | To make your payments secure, we got a validated UPI handle examplebroker.brk@validicici. |
| g23 | valid_upi_template | 0.97 / Likely scam | 0.155 / No warning signs | The market now has new validated and exclusive UPI IDs, visit our website to know more. |
| g24 | broker_add_funds | 0.838 / Likely scam | 0.905 / Likely scam | To add funds to your trading account, pay by UPI only to examplebroker.brk@validhdfc and c |
| g25 | broker_funds_added | 0.022 / No warning signs | 0.437 / Suspicious | Rs 25,000.00 has been added to your trading account via UPI on 14-Oct-2026. Available marg |
| g26 | broker_withdrawal | 0.988 / Likely scam | 0.843 / Likely scam | Your withdrawal request of Rs 10,000 from your trading account is processed. Funds will re |
| g29 | broker_pledge | 0.968 / Likely scam | 0.442 / Suspicious | CDSL: Pledge created on 15 shares of HDFCBANK in your demat a/c XXXXXXXX5678 in favour of  |
| g32 | kyc_status | 0.97 / Likely scam | 0.674 / Likely scam | Your KYC with the KRA is validated. You can now invest in mutual funds and open trading ac |
| g33 | broker_awareness | 0.117 / Suspicious | 0.676 / Likely scam | We do not offer stock tips or run WhatsApp or Telegram groups. Never share your login, pas |
| g34 | exchange_awareness | 0.934 / Likely scam | 0.783 / Likely scam | Attention Investors: Beware of unsolicited stock tips on WhatsApp, Telegram and SMS. No on |
| g35 | exchange_awareness | 0.037 / No warning signs | 0.625 / Suspicious | NSE cautions investors not to subscribe to any scheme offering indicative, assured or guar |
| g36 | registered_ra_tip | 0.44 / Likely scam | 0.195 / No warning signs | Research call: BUY EXAMPLE INDUSTRIES CMP 412, target 450, stop loss 395, horizon 3 months |
| g37 | registered_ra_tip | 0.987 / Likely scam | 0.602 / Suspicious | Intraday idea: Buy NIFTY 24500 CE above 120, target 150, SL 105. Not a guaranteed return.  |
| g40 | mf_statement | 0.038 / No warning signs | 0.425 / Suspicious | Your consolidated account statement for September 2026 has been sent to your registered em |
| g45 | broker_otp | 0.019 / No warning signs | 0.44 / Suspicious | <OTP> is your OTP to log in to ABC Securities. Valid for 5 minutes. Do not share it with a |
| g46 | sip_reminder | 0.026 / No warning signs | 0.486 / Suspicious | Reminder: your SIP of Rs 5,000 in Example Flexi Cap Fund will be debited on 05-11-2026. Ke |

## 4. Rule feasibility (regex counts only; none of these is in the app)

Val columns: the val split of the short-message sources (genuine rows minus the mislabel candidates). Val text is PII-masked, so A1 (UPI handles) cannot fire there: a UPI id is already `<UPI_ID>` / `<EMAIL>`.

| rule | probe scams caught (of 54) | probe genuine wrongly fired (of 48) | val genuine short-msg fired (of 956) | val scam short-msg fired (of 439) |
|---|---|---|---|---|
| A1 UPI id that is not @valid, in an investment context | 1 | 0 | 0 | 0 |
| A2 'SEBI registered / certified' claim with no INA/INH/INZ/INP number | 3 | 1 | 0 | 0 |
| A3 guaranteed / assured / fixed / sure-shot returns (not negated) | 8 | 1 | 0 | 9 |
| A4 pay a fee / tax / deposit to withdraw, release or unfreeze | 8 | 0 | 0 | 0 |
| A5 join / upgrade to a VIP or tips group, channel or club | 7 | 0 | 0 | 0 |
| A6 share login / password, or 'we handle your account' | 2 | 0 | 0 | 0 |
| A7 task pay: earn N per day / daily for likes, ratings, reviews, part-time | 4 | 0 | 0 | 0 |
| A8 prepaid task / deposit for a task, tier or level | 6 | 0 | 0 | 5 |
| A9 app / APK to install from a link, in an investment context | 2 | 0 | 0 | 0 |
| A10 IPO pre-allotment / institutional account / block trade / FII channel | 6 | 0 | 0 | 0 |
| A11 minister / celebrity-endorsed scheme | 2 | 0 | 0 | 0 |
| A12 crypto / USDT deposit | 3 | 0 | 0 | 0 |
| any rule (union) | 39 | 2 | 0 | 14 |

Rows each rule fires on (probe ids): A1: s34; A2: s07 s13 s33 | genuine g34; A3: s17 s20 s26 s27 s32 s48 s49 s54 | genuine g35; A4: s14 s19 s21 s23 s36 s37 s40 s47; A5: s10 s11 s13 s20 s27 s32 s54; A6: s26 s27; A7: s01 s38 s41 s43; A8: s35 s37 s39 s41 s44 s45; A9: s12 s25; A10: s12 s13 s14 s15 s16 s18; A11: s30 s31; A12: s37 s42 s50

Gain on top of the MuRIL router (a fired rule floors the level at Suspicious):

| rule | MuRIL misses it would catch | genuine rows it would newly flag |
|---|---|---|
| A1 UPI id that is not @valid, in an investment context | 0  | 0  |
| A2 'SEBI registered / certified' claim with no INA/INH/INZ/INP number | 1 s13 | 0  |
| A3 guaranteed / assured / fixed / sure-shot returns (not negated) | 1 s54 | 1 g35 |
| A4 pay a fee / tax / deposit to withdraw, release or unfreeze | 0  | 0  |
| A5 join / upgrade to a VIP or tips group, channel or club | 2 s13 s54 | 0  |
| A6 share login / password, or 'we handle your account' | 0  | 0  |
| A7 task pay: earn N per day / daily for likes, ratings, reviews, part-time | 0  | 0  |
| A8 prepaid task / deposit for a task, tier or level | 1 s39 | 0  |
| A9 app / APK to install from a link, in an investment context | 0  | 0  |
| A10 IPO pre-allotment / institutional account / block trade / FII channel | 4 s13 s15 s16 s18 | 0  |
| A11 minister / celebrity-endorsed scheme | 0  | 0  |
| A12 crypto / USDT deposit | 0  | 0  |
| all rules | 6 | 1 |

MuRIL router recall 39/54 -> 45/54 with all rules; genuine flagged 14/48 -> 15/48.

Top 10 word n-grams in probe scams (rows with it: scam / genuine):

- `group`: 11 / 0
- `members`: 10 / 0
- `pay`: 12 / 3
- `join`: 8 / 0
- `profit`: 8 / 0
- `earn`: 7 / 0
- `every`: 7 / 0
- `vip`: 7 / 0
- `month`: 7 / 1
- `today`: 7 / 1

Top 10 in probe genuine rows (genuine / scam):

- `demat`: 10 / 1
- `shares`: 11 / 3
- `cdsl`: 8 / 0
- `oct`: 8 / 0
- `ltd`: 8 / 1
- `upi`: 8 / 1
- `abc`: 7 / 0
- `fund`: 7 / 0
- `registered`: 8 / 2
- `securities`: 7 / 1

