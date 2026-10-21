# D21: preservation filter for machine-translated rows

Status: **ACCEPTED 2026-10-18 (digit and URL clauses only); APPLIED 2026-10-21 at the splits-v2 rebuild** (`build_text.py`: digit runs, and links = this url pattern plus every link `textprep` finds, verbatim; `protect.py`'s TLD list has no `.pw`, so `klr.pw/ordernow` lost in two translations was invisible to the pattern alone. Dropped 1 Hindi + 1 Kannada row after p00312 was re-translated; see `reports/splits_v2.md`). Proposed and measured 2026-10-18; accepted the same day on the recommendation below. The digit and URL clauses are a **training-only drop rule**; the brand / sender clause is **not** a drop rule, it becomes a **report from a curated brand list** (no list exists yet: future work). Not applied yet: nothing in `data/`, `split_map.csv` or `models/` was changed and nothing is wired into a script; the rule is applied when translated rows are ingested at the splits-v2 rebuild. Measurement code: `src/preservation_filter.py` (measure only). Follows D20 and `reports/spotcheck_hi.md`; D20's condition refers to this decision.

## Rule as specified

Drop a translated row if any of these is missing from the translation:

1. a **digit run** of the English parent (`[0-9]+`; native digits are mapped to ASCII first),
2. a **URL** of the English parent (the pattern `protect.py` already uses, trailing punctuation stripped, case-insensitive),
3. a **Latin-script brand / sender token** of the English parent, as a whole Latin word (case-insensitive).

"Brand / sender token" had to be made operational, because the repo has no brand list. Definition used, fixed before any number was seen: a run of 3 or more Latin letters that is ALL CAPS, or Capitalised and not the first word of a sentence, and (default variant) whose lower-case form never occurs as an ordinary lower-case word in the parents. The mask tokens `<ACCOUNT>` etc. are removed first (`translate_parents.py finalise` already requires them to survive). A second variant (`--no-exempt`) drops the ordinary-word exemption, i.e. the strictest reading. The two variants bracket what any dictionary-free definition can do.

## How test-split rows were kept out

`translated_final_2026-10-07.csv` carries `anchor_split`. The loader looks at it first, and a `test` row is skipped on the spot: its text is never tokenised, matched, counted or printed, and the script has no code path that reports it. The ordinary-word list is built from the remaining rows only. The one reviewed Hindi row whose parent is in the test split was therefore **not measured** (46 of the 47 reviewed rows were; 42 of the 43 judged y/y).

**Most rows have no split yet.** Only parents that are `messages.csv` rows (the scam parents, plus 6 benign near-twins) have a frozen split. The 616 other parents (every other benign OTP-preview parent) are not in `split_map.csv`; they get a split at the splits-v2 rebuild. So "train + dev" below is 188 rows, almost all scam, and the benign side that carries 3 of the 4 known failures sits in a separate **no split yet** pool of 1,004 rows. That pool is not test today. I measured it because the benign side cannot be measured otherwise; the rule is fixed, nothing was tuned on it, and its rows' later split is a hash bucket that does not depend on this result. If you prefer it left alone, the train + dev rows alone are in the first table.

## Results

**Reviewed Hindi rows** (46 measured; hi01-hi03 were not answered, one row has a test-split parent):

| Row | What went wrong | Default variant | Strictest variant |
|---|---|---|---|
| hi29 | brand Licious translated to "auspicious" | not caught (another parent writes `licious` in lower case, which exempts it) | caught (`Licious`) |
| hi34 | pay-Rs-999 ask lost (meaning and label) | not caught | flagged, for the wrong token (`Bank`; it was correctly written in Devanagari) |
| hi35 | sender tag `-CAMS` fused into the sentence | flagged, for the wrong token (`Nominee`; `CAMS` IS in the translation) | flagged (`Nominee`, `Update`), same |
| hi39 | clause order scrambled | not caught | not caught |
| rows judged y/y flagged anyway | | **18 of 42 (43%)** | **28 of 42 (67%)** |

False flags in the default variant are mostly legitimate transliterations or ordinary capitalised words: Aadhaar, Mumbai, Ola, Reliance, Vodafone, Mahindra, URGENT, NOTICE, World Cup. The three structure failures (hi34, hi35 position, hi39) have every token present; a token-presence rule cannot see them.

**Rows it would drop** (rows / dropped; digit, URL and brand columns count rows flagged by that clause):

| Pool | Language | Label | Rows | Default variant | Strictest variant |
|---|---|---|---|---|---|
| train + dev | Hindi | scam | 87 | 36 (41.4%) | 50 (57.5%) |
| train + dev | Hindi | benign | 9 | 4 (44.4%) | 7 (77.8%) |
| train + dev | Kannada | scam | 83 | 34 (41.0%) | 49 (59.0%) |
| train + dev | Kannada | benign | 9 | 4 (44.4%) | 7 (77.8%) |
| **train + dev** | both | both | **188** | **78 (41.5%)** | **113 (60.1%)** |
| no split yet | Hindi | benign | 514 | 300 (58.4%) | 429 (83.5%) |
| no split yet | Kannada | benign | 490 | 284 (58.0%) | 410 (83.7%) |
| **no split yet** | both | benign | **1,004** | **584 (58.2%)** | **839 (83.6%)** |

Train alone 166 rows, dev 22 (default: 71 and 7 dropped). In every row of both tables the digit and URL clauses flagged **0** rows in train + dev and **1 parent (2 rows, Hindi and Kannada)** in the no-split pool; everything else is the brand clause. Distinct flagged tokens: 380 (default), 547 (strictest); most frequent in the default variant: Aadhaar 29, Express 22, SECRET 21, American 20, Ref 20, Acc 20.

**The digit clause found a real defect.** The one flagged parent is `RESEND 1:363094 is the OTP for INR 278.33 ...`: both translations read `1:36 3094`. The OTP code was cut in two by the `time` pattern in `protect.py` (checked: `protect.protect()` turns the text into `RESEND <ID51>3094 ...`, the span `1:36` is protected and `3094` is left outside the marker), and `finalise` did not notice because its digit check compares the multiset of single digit characters, which a cut in two leaves unchanged (`translate_parents.py`, step "digit or mask-token mismatch"). A check on digit RUNS, as in this rule, does see it. One parent in 1,004, but the bug is in the protection step, not the model; it is logged in `BUGS.md`.

## Reading

- The digit and URL clauses are safe and nearly redundant: `protect.py` already restores those spans verbatim and `finalise` rejects a row that loses a marker. Their value is the one OTP-code case above.
- The brand clause as specified is **not usable as a hard filter**. It drops 41-60% of the train + dev rows and 58-84% of the benign pool, flags 43-67% of rows the reviewer found fine, and catches hi29 only in the variant that flags two thirds of the good rows. Without a brand list, "brand missing" cannot be told apart from "name transliterated into Devanagari".
- Three of the four known failures (hi34, hi35 position, hi39) are structure errors that no token check sees. Only human review (or a back-translation check, not tried) finds those.

## Decision (accepted 2026-10-18; this was the recommendation)

1. **Digit and URL clauses: a drop rule, training rows only.** A translated row is left out of the training set if a digit run or a URL of its English parent is missing from the translation. It is applied at the splits-v2 rebuild, when translated rows are ingested. On today's rows it removes 0 train / dev rows and the 2 no-split rows hit by the `protect.py` bug (BUGS.md; fixing that bug means re-translating, also scheduled for the rebuild).
2. **Brand / sender clause: report only, from a curated list.** Build a small hand-checked list of the brand / sender names in the English parents (the real brands are presumably a small subset of the 380 tokens; not counted) and report misses for review; nothing is dropped on it. **No list exists yet: future work.** Until then no brand check runs.
3. `docs/spotcheck/exclude_v1.txt` (the four known-bad Hindi rows) stays; together with point 1 it is the removal D20's condition refers to.
4. **Training rows only.** Test-split translated rows stay as built (consistent with "test rows are not edited or dropped on the basis of this check"). Whether the dev rows follow train is decided at splits-v2.

Open: the Kannada sheet is with a reviewer. Its result may change point 2 (Kannada failures could be a different class).

## Reproduce

```
.venv/bin/python -I src/preservation_filter.py               # default variant
.venv/bin/python -I src/preservation_filter.py --no-exempt   # strictest variant
```

Output is English tokens and counts only (ASCII-escaped); no Hindi or Kannada text is printed.
