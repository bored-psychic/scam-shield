# data/probe/: PROBE-ONLY sets

**Eval only. Never train, tune, calibrate or choose a threshold on these files.** `src/realguard.py` refuses any input path under
`data/probe/` and any input row whose text key (md5 of the lower-cased, whitespace-collapsed text) equals a probe row
(test `R10` in `tests/test_real_intake.py`). `finetune.py`, `calibrate_text_head.py` and `build_text.py` call that tripwire.

A probe is not the real-message test set (`data/real/`): it is small, partly written by us, and it may be read and rerun during
development. Use it to find blind spots, then confirm on held-out data. **Do not tune rules on probe v1 and then report probe v1 as their
score.** The rules in `docs/plans/investment_scams.md` were written after reading v1, so a fresh probe (v2) has to judge them.

## investment_v1.csv (2026-10-24)

102 rows: 54 scam (`label` 1), 48 genuine (`label` 0). Plan and results: `docs/plans/investment_scams.md`, `reports/investment_audit.md`.

| column | meaning |
|---|---|
| `id` | s01-s54 scam, g01-g48 genuine |
| `use` | always `PROBE-ONLY` |
| `kind` | the scam / message type (e.g. `pay_to_withdraw`, `ipo_preallotment`, `exchange_trade_alert`) |
| `provenance` | `verbatim_quote` (the page quotes the message), `quote_fragments` (quoted pieces joined), `written_from_source` (written here from the specific names, amounts and steps the page reports), `written_from_format` (a genuine alert written from the published description of its fields), `official_template` (a template text from SEBI circular SEBI/HO/DEPA-II/DEPA-II_SRG/P/CIR/2025/86, Annexure E) |
| `language` | `en` or `hinglish` |
| `source_url` | the page the row comes from (every row has one) |
| `note` | what was taken from the page |
| `text` | the message |

Scam rows: 6 verbatim, 3 quote fragments, 45 written from a cited source. Genuine rows: 45 written from a format, 3 official templates.
Few fetchable pages quote scam messages word for word; most show them as screenshots. So most rows are ours, and the probe measures whether a
plainly worded version of each reported pattern is caught, not how real messages are worded.

Personal data: none. Phone numbers are `<PHONE>`, OTPs `<OTP>`, account numbers `XXXX`-style. The UPI ids, brokers (ABC Securities) and
companies (EXAMPLETECH, EXAMPLE INDUSTRIES) are invented. Victim names are not used. Company, app and group names that scammers used
(e.g. "FHL Investors (Teaching Group) VIP 903", "Goomi.apk") are taken from the cited news reports. Links in rows are strings only. Nobody
opened them (CLAUDE.md rule 8), and the one invented domain (`goomi-app.top`) is not a real address we know of.

Overlap with training data: 0 of 102 rows is a near-duplicate of a train row (`intake_real.overlap_flags`, the splits' rule, 2026-10-24).

`data/probes/` (with an s) is an older, git-ignored 24-row probe from 2026-10-22. It copied rows from `messages.csv`, two of them from
the **test** split (its rows s05 and s10). Do not use it. realguard refuses its path, but not its texts, because those are messages.csv rows.
