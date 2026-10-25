# Investment-scam rules A1-A12: evaluation

`src/eval_invest_rules.py`, offline (`live=False`), 2026-10-25. Rules: `src/shield/messages/invest_rules.py`. Plan: `docs/plans/investment_scams.md`. No test-split row was read.

## 1. Probe v1 (PROBE-ONLY): the app without and with the rules

**Upper bound: the rules were written after reading the probe, and 45 of its 54 scam rows and all 48 genuine rows were written by us from cited descriptions.** Flagged = Suspicious or Likely scam. 'Without' = `analyse(..., invest_rules=False)` with the current masks (the @valid mask fix is in both columns).

| head | rules | scams flagged | scams at Likely scam | genuine flagged (false alarms) | genuine at Likely scam |
|---|---|---|---|---|---|
| MuRIL (the app) | off | 39/54 (72%) | 39 | 14/48 (29%) | 13 |
| MuRIL (the app) | on | 46/54 (85%) | 41 | 14/48 (29%) | 13 |
| TF-IDF baseline | off | 40/54 (74%) | 28 | 18/48 (38%) | 8 |
| TF-IDF baseline | on | 47/54 (87%) | 32 | 18/48 (38%) | 8 |

MuRIL + rules: scams newly flagged: 7 (s03 s13 s15 s16 s18 s39 s54); raised from Suspicious to Likely scam: 0 (); genuine rows raised: 0 (none).

SEBI's own @valid templates (g21 g22 g23): rules fire on 0 of 3 (the templates are still Likely scam from MuRIL itself; that is a text-head problem, Phase B).

What the rules catch alone:

| rule | name | scams caught /54 | genuine fired /48 | new on top of MuRIL (scams MuRIL left unflagged) |
|---|---|---|---|---|
| A1 | Non-@valid UPI | 1 | 0 | 0  |
| A2 | SEBI claim | 3 | 0 | 1 s13 |
| A3 | Guaranteed returns | 8 | 0 | 1 s54 |
| A4 | Pay to withdraw | 10 | 0 | 0  |
| A5 | VIP tips group | 7 | 0 | 2 s13 s54 |
| A6 | Login sharing | 2 | 0 | 0  |
| A7 | Task pay promise | 4 | 0 | 0  |
| A8 | Prepaid task | 7 | 0 | 1 s39 |
| A9 | Install app | 2 | 0 | 0  |
| A10 | IPO allotment | 6 | 0 | 4 s13 s15 s16 s18 |
| A11 | Celebrity scheme | 2 | 0 | 0  |
| A12 | Crypto deposit | 3 | 0 | 1 s03 |
| any | | 41 | 0 | |

Scams no rule catches (13): s02 s04 s05 s06 s08 s09 s24 s28 s29 s46 s51 s52 s53. Among them the first-stage messages that ask for nothing (s52, s53) and the fake testimonial (s51): nothing in the text to catch.

## 2. Fire counts on the whole val split (every source)

### val: 4115 genuine, 1152 scam rows

| rule | name | genuine fired | scam fired |
|---|---|---|---|
| A1 | Non-@valid UPI | 0 | 0 |
| A2 | SEBI claim | 0 | 0 |
| A3 | Guaranteed returns | 0 | 1 |
| A4 | Pay to withdraw | 0 | 10 |
| A5 | VIP tips group | 0 | 0 |
| A6 | Login sharing | 0 | 0 |
| A7 | Task pay promise | 0 | 0 |
| A8 | Prepaid task | 0 | 0 |
| A9 | Install app | 0 | 0 |
| A10 | IPO allotment | 0 | 0 |
| A11 | Celebrity scheme | 0 | 0 |
| A12 | Crypto deposit | 0 | 0 |

Genuine rows a rule fires on: none.

For information, the train split (regex only; its genuine hits were also read when the guards were written):

### train: 29079 genuine, 9874 scam rows

| rule | name | genuine fired | scam fired |
|---|---|---|---|
| A1 | Non-@valid UPI | 0 | 1 |
| A2 | SEBI claim | 0 | 0 |
| A3 | Guaranteed returns | 6 | 11 |
| A4 | Pay to withdraw | 0 | 20 |
| A5 | VIP tips group | 0 | 0 |
| A6 | Login sharing | 0 | 0 |
| A7 | Task pay promise | 0 | 12 |
| A8 | Prepaid task | 0 | 1 |
| A9 | Install app | 0 | 0 |
| A10 | IPO allotment | 0 | 0 |
| A11 | Celebrity scheme | 0 | 0 |
| A12 | Crypto deposit | 0 | 1 |

Genuine rows a rule fires on: 
- A3 phishing_email `7cea4a61`: "guaranteed income"
- A3 phishing_email `1f833bde`: "assured of a fixed income"
- A3 fake_job_postings `dcd07732`: "guaranteed return"
- A3 fake_job_postings `7156e363`: "guaranteed return"
- A3 scam_dialogue `a05cf72e`: "guaranteed payout"
- A3 scam_dialogue `56f3ef9f`: "guaranteed payout"

## 3. Val F1 of the whole app, rules off vs on

All 5267 val rows through `router.analyse` (offline). Val text is stored masked, so A1 cannot fire on it (a UPI id is `<UPI_ID>`); the A1 proxy is only in section 2. The 'off' column equals the app before this change (no stored row has a @valid id, so the mask fix changes nothing).

| head | rules | precision | recall | F1 | flagged | at Likely scam |
|---|---|---|---|---|---|---|
| MuRIL (the app) | off | 0.9108 | 0.9488 | 0.9294 | 1200 | 1135 |
| MuRIL (the app) | on | 0.9108 | 0.9488 | 0.9294 | 1200 | 1135 |
| TF-IDF baseline | off | 0.8410 | 0.9505 | 0.8924 | 1302 | 1088 |
| TF-IDF baseline | on | 0.8410 | 0.9505 | 0.8924 | 1302 | 1088 |

MuRIL (the app): 0 of 5267 val rows change level with the rules. 
TF-IDF baseline: 0 of 5267 val rows change level with the rules. 

Note (2026-10-25, after the run): link extraction was changed so a UPI id / e-mail local part is not a link (`textprep._ID_REST`). No probe row and no train / val model input changes, so the numbers above stand.
