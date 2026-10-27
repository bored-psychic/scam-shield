# D11 folded view: evaluation

`src/eval_fold.py`, offline (`live=False`), 2026-10-28. Fold: `src/shield/core/fold.py`. Rules, tactic cues and fear cues match on the folded text; the models, link extraction and the language detection read the raw text. No test-split row was read.

## 1. messages_aug.csv, train parents: rule hit rate on attacked rows, before (raw) and after (folded)

20,022 rows (homoglyph 6,589, leet 6,605, zero_width 6,828); the fold changed the text of 6,589 homoglyph, 6,508 leet, 6,828 zero_width rows. 'clean' = the unattacked parent, 'before' = the rules on the attacked text read raw (D11 off), 'after' = read folded. Rate = share of all rows of the family on which the rule fires. 'Recovered' = of the rows whose clean parent fires the rule, the share on which the attacked text fires it.

### homoglyph (6,589 rows)

| rule | clean | before | after | recovered before | recovered after |
|---|---|---|---|---|---|
| any hard rule (OTP / PIN / R2 / A1-A12) | 0.8% (56) | 0.5% (30) | 0.8% (56) | 53.6% | **100.0%** |
| OTP / PIN / CVV / password request | 0.4% (25) | 0.3% (19) | 0.4% (25) | 76.0% | **100.0%** |
| R2 PIN to receive | 0.0% (2) | 0.0% (2) | 0.0% (2) | 100.0% | **100.0%** |
| any investment rule A1-A12 | 0.4% (29) | 0.1% (9) | 0.4% (29) | 31.0% | **100.0%** |
| A4 Pay to withdraw | 0.2% (16) | 0.1% (4) | 0.2% (16) | 25.0% | **100.0%** |
| A7 Task pay promise | 0.2% (12) | 0.1% (4) | 0.2% (12) | 33.3% | **100.0%** |
| A8 Prepaid task | 0.0% (1) | 0.0% (1) | 0.0% (1) | 100.0% | **100.0%** |
| any tactic tag | 47.8% (3,152) | 40.0% (2,638) | 47.8% (3,152) | 83.7% | **100.0%** |
| tactic: authority | 18.7% (1,233) | 14.3% (944) | 18.9% (1,247) | 76.6% | **100.0%** |
| tactic: urgency | 20.6% (1,357) | 13.2% (870) | 20.6% (1,357) | 64.1% | **100.0%** |
| tactic: payment | 29.7% (1,957) | 25.6% (1,684) | 29.7% (1,956) | 86.1% | **99.9%** |
| tactic: isolation | 1.5% (102) | 0.7% (43) | 1.5% (102) | 42.2% | **100.0%** |

### leet (6,605 rows)

| rule | clean | before | after | recovered before | recovered after |
|---|---|---|---|---|---|
| any hard rule (OTP / PIN / R2 / A1-A12) | 0.8% (55) | 1.3% (88) | 0.9% (58) | 34.5% | **100.0%** |
| OTP / PIN / CVV / password request | 0.4% (25) | 0.2% (13) | 0.4% (25) | 52.0% | **100.0%** |
| R2 PIN to receive | 0.0% (2) | 0.0% (0) | 0.0% (2) | 0.0% | **100.0%** |
| any investment rule A1-A12 | 0.4% (28) | 1.1% (75) | 0.5% (31) | 21.4% | **100.0%** |
| A1 Non-@valid UPI | 0.0% (0) | 1.0% (69) | 0.0% (3) | - | **-** |
| A4 Pay to withdraw | 0.2% (16) | 0.0% (3) | 0.2% (16) | 18.8% | **100.0%** |
| A7 Task pay promise | 0.2% (11) | 0.0% (3) | 0.2% (11) | 27.3% | **100.0%** |
| A8 Prepaid task | 0.0% (1) | 0.0% (0) | 0.0% (1) | 0.0% | **100.0%** |
| any tactic tag | 47.8% (3,160) | 40.5% (2,674) | 47.3% (3,126) | 83.7% | **98.8%** |
| tactic: authority | 18.6% (1,229) | 14.3% (947) | 18.5% (1,221) | 73.7% | **98.1%** |
| tactic: urgency | 20.5% (1,355) | 13.3% (880) | 20.2% (1,331) | 64.9% | **98.2%** |
| tactic: payment | 29.8% (1,966) | 26.0% (1,714) | 29.3% (1,932) | 86.7% | **98.2%** |
| tactic: isolation | 1.6% (103) | 0.7% (49) | 1.5% (101) | 46.6% | **98.1%** |

### zero_width (6,828 rows)

| rule | clean | before | after | recovered before | recovered after |
|---|---|---|---|---|---|
| any hard rule (OTP / PIN / R2 / A1-A12) | 0.8% (56) | 0.4% (27) | 0.8% (56) | 48.2% | **100.0%** |
| OTP / PIN / CVV / password request | 0.4% (25) | 0.2% (17) | 0.4% (25) | 68.0% | **100.0%** |
| R2 PIN to receive | 0.0% (2) | 0.0% (0) | 0.0% (2) | 0.0% | **100.0%** |
| any investment rule A1-A12 | 0.4% (29) | 0.1% (10) | 0.4% (29) | 34.5% | **100.0%** |
| A4 Pay to withdraw | 0.2% (16) | 0.1% (6) | 0.2% (16) | 37.5% | **100.0%** |
| A7 Task pay promise | 0.2% (12) | 0.1% (4) | 0.2% (12) | 33.3% | **100.0%** |
| A8 Prepaid task | 0.0% (1) | 0.0% (0) | 0.0% (1) | 0.0% | **100.0%** |
| any tactic tag | 48.5% (3,312) | 37.3% (2,546) | 48.5% (3,312) | 75.6% | **100.0%** |
| tactic: authority | 18.8% (1,284) | 14.0% (953) | 19.0% (1,298) | 71.6% | **100.0%** |
| tactic: urgency | 20.8% (1,417) | 11.2% (766) | 20.8% (1,417) | 54.1% | **100.0%** |
| tactic: payment | 30.4% (2,078) | 23.1% (1,574) | 30.4% (2,077) | 74.6% | **100.0%** |
| tactic: isolation | 1.5% (103) | 0.8% (57) | 1.5% (103) | 54.4% | **100.0%** |

## 2. Val (every row)

5,267 rows (4,115 genuine / 1,152 scam). The fold changes the text of **1999** of them ([('fake_job_postings', 1715), ('phishing_email', 197), ('uci_sms_spam', 43), ('scam_ham_india', 35), ('ealvaradob_phishing', 9)]); the other rows read the same text with fold off and on.

### 2a. Rows on which each rule family fires

| rule | genuine before | genuine after | scam before | scam after |
|---|---|---|---|---|
| OTP | 10 | 10 | 2 | 2 |
| R2 | 0 | 0 | 1 | 1 |
| invest | 0 | 0 | 11 | 11 |
| A3 | 0 | 0 | 1 | 1 |
| A4 | 0 | 0 | 10 | 10 |
| tactic | 1574 | 1574 | 608 | 608 |
| tactic.authority | 1084 | 1084 | 284 | 284 |
| tactic.urgency | 519 | 519 | 260 | 260 |
| tactic.payment | 443 | 443 | 377 | 377 |
| tactic.isolation | 21 | 21 | 35 | 35 |

Rows newly hit by a family after the fold: **0** (0 genuine); rows that lose a hit: **0**.

### 2b. The whole app: flagged = Suspicious or Likely scam

| head | fold | F1 | precision | recall | flagged | levels changed vs off |
|---|---|---|---|---|---|---|
| MuRIL (the app) | off | 0.9294 | 0.9108 | 0.9488 | 1200 | 0 |
| MuRIL (the app) | on | 0.9294 | 0.9108 | 0.9488 | 1200 | 0 |
| TF-IDF baseline | off | 0.8924 | 0.8410 | 0.9505 | 1302 | 0 |
| TF-IDF baseline | on | 0.8924 | 0.8410 | 0.9505 | 1302 | 0 |

(200 rows the fold leaves unchanged were re-run with fold on: same level on all 200, both heads.)

### 2c. Rows whose level changed (0 in all, both heads)

None.

## 3. Train, clean text: what the fold does to unattacked messages

38,953 train rows; the fold changes the text of 12,819 (mostly no-break spaces, mojibake accents, ellipses and trade-mark signs in the long email sources). Rule families that fire on the folded text and did not on the raw text (label 0 = genuine, 1 = scam):

| family | genuine | scam |
|---|---|---|
| tactic.authority | 0 | 14 |
| tactic.payment | 1 | 0 |


Families that stop firing:

| family | genuine | scam |
|---|---|---|
| tactic.isolation | 0 | 1 |
| tactic.payment | 1 | 1 |

## Notes (hand-written; `eval_fold.py` appends this text)

- **The attacks.** `augment.py` attacks every letter independently (homoglyph 15%, leet 20%, zero-width 10% per letter), so a rule word is often hit more than once. Read raw, the hard rules (OTP / PIN / R2 / A1-A12) fire on 34-54% of the rows whose clean parent fires; read folded, on 100% in all three families. Tactic tags: 75-84% raw, 98.8-100% folded. The three leet cases it cannot undo: a word-initial `@` whose word the rules do not know, a `1` in a word the rules do not know (read as `i`), a run of leet digits longer than three.
- **A raw-view false alarm that the fold removes.** On the leet rows A1 (non-@valid UPI id, a Likely-scam floor) fires on 69 rows whose clean parent does not: `se@rch`, `em@il`, `incre@se` have the shape of a UPI id. Folded, 3 remain. It is not a gain in detection, but it shows the raw view was noisy on leet text.
- **Val: nothing changes.** The fold changes the text of about 2,000 val rows (mostly no-break spaces, mojibake accents, ellipses and trade-mark signs in `fake_job_postings` and `phishing_email`), and no rule family gains or loses a row, no level changes, F1 is identical for both heads. This is a statement about val, whose genuine rows hold no disguise; it does not measure how often a real scam is disguised.
- **Train, clean text.** 14 scam rows newly get the authority tag: they write `FL1PKART` (the fold reads the brand, as intended). One genuine and one scam row lose a payment cue and one scam row an isolation cue (`Secret$` becomes `Secrets`: the fold removed a `secret` word-boundary match). No hard rule fires on any train row because of the fold. Two fold rules were added after this check showed they were noisy: a `$` between hex digits (the `$` in e-mail Message-IDs) is not leet, and a short id with one digit at its end (`CB1`, `SB1`, `EH1`) is not read as `cbi` / `sbi` / `ehi`; and `Rs 151OFF` stays a number.
- **Not done on purpose.** Separators between letters (`O.T.P`, `O T P`) are the held-out `spaced_keywords` attack and are not folded here. Devanagari and Kannada are not folded (only invisible characters are dropped, ZWJ / ZWNJ kept); a Latin look-alike inside a Hindi sentence is folded like any Latin text.
