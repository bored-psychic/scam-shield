# Investment, trading and task scams: audit and plan

**Status: Phase A built 2026-10-25** (rules A1-A12, the SEBI advice card, the `@valid` mask fix; `reports/investment_rules_v1.md`, `src/shield/messages/CLAUDE.md`). **Phase B is still a proposal** (the go / no-go in section 6 is unchanged). The audit below (2026-10-24) added no detection code. The numbers come from `src/audit_investment.py`
(output `reports/investment_audit.md`). The probe is `data/probe/investment_v1.csv` (PROBE-ONLY, see its README).

Why this matters: investment scams are about 76% of India's scam losses (the brief's figure, MHA 2025; not re-checked here). Genuine
broker, exchange and fund messages use the same words (trade, IPO, returns, UPI, withdrawal). So a naive fix trades missed scams for false
alarms.

## 1. Findings in one screen

1. **We have almost no investment-scam training data.** Short-message sources (SMS / WhatsApp / India): 3 investment-keyword scam rows in train
   (a paid stock-tip SMS, an "assured return" property ad, a bank's demat promo) and 0 in val. Task / part-time scams are better covered (123 train, 8 val, mostly `india_fraud_final` templates). The 248 + 44 investment-scam rows
   are 2000s US penny-stock email spam (`phishing_email`), a different language and channel.
2. **The data teaches the opposite.** `scam_ham_india` has a WhatsApp "stock-advisor group" chat ("Professor Sohan Sharma", "assistant Riya",
   "recommended stocks", "internal stock ... official group") labelled **genuine**. 39 rows read clearly as that scam group (34 train, 5 val).
   84 more market-chat rows from the same source have no marker (70 train, 14 val). Ids are in `reports/investment_mislabel_candidates.csv`.
3. **Val cannot measure this.** Val has no investment scam rows and no genuine broker / exchange / depository messages, so neither recall nor
   false alarms can be measured. On the 5 val group-chat rows labelled genuine (scams, if read as such), MuRIL and the baseline flag 0 of 5.
4. **Probe v1 (54 scam, 48 genuine), full router, offline:**
   MuRIL catches 39/54 (72%) and false-alarms on 14/48 genuine (29%; 13 at Likely scam). The app's TF-IDF head catches 40/54 (74%), with
   18/48 false alarms. On the 9 quoted rows MuRIL catches 5. MuRIL misses group, VIP and IPO pitches that ask for nothing yet. It
   wrongly gives **Likely scam to SEBI's own three @valid UPI awareness templates**, BSE's "beware of stock tips" notice, an IPO allotment,
   a redemption, a withdrawal, a pledge alert and two registered-analyst research calls.
5. **Rules help recall a little and do nothing for false alarms.** The 12 regex ideas catch 39/54 probe scams and wrongly fire on 2/48 genuine
   rows (0 of 956 val genuine short messages). On top of MuRIL they would add 6 catches (39 -> 45/54) and 1 false alarm (14 -> 15/48). This is
   an upper bound: the rules were written after reading the probe, and we wrote most of the probe.

## 2. Data inventory (train + val; test never read)

Search: no source has an investment / trading / crypto category; `india_fraud_final`'s task subcategories (`VIP_Task`, `Investment_Task`,
`YouTube_Task`, `Survey_Task`, `eBay_Task`, `Instagram_Task`, `TikTok_Task`) are the only category route. Everything else is keyword search
(`INVEST_RX`: stock market / stock tips / stocks / intraday / nifty / sensex / demat / IPO / mutual fund / SIP / SEBI / trading account|group|app /
upper circuit / block deal / pre-allotment / institutional account / guaranteed|assured|fixed returns; `CRYPTO_RX`: crypto / bitcoin / BTC / USDT /
ethereum / binance / forex; `TASK_RX`: part-time job / work from home / simple|prepaid tasks / like videos / hotel reviews / grab orders / earn N
per day). Rows: scam / genuine.

| topic | source | train | val |
|---|---|---|---|
| investment | scam_ham_india | 1 / 104 (34 group-chat mislabels + 70 uncertain) | 0 / 19 (5 + 14) |
| investment | translated_indic, uci_sms_spam, hinglish_conversations | 0 / 5 | 0 / 0 |
| investment | ealvaradob_phishing | 2 / 0 | 0 / 0 |
| investment | phishing_email (long-form, US stock spam / Enron) | 248 / 165 | 44 / 12 |
| investment | fake_job_postings (long-form, keyword noise) | 5 / 113 | 0 / 77 |
| crypto | hinglish_conversations, scam_dialogue | 1 / 1 | 0 / 0 |
| crypto | phishing_email / fake_job_postings | 3 / 41 | 3 / 3 |
| task | india_fraud_final (57 + 6 by subcategory) | 93 / 0 | 6 / 0 |
| task | scam_ham_india | 15 / 0 | 2 / 1 |
| task | synth_india | 15 / 0 | 0 / 0 |
| task | uci_sms_spam | 0 / 1 | 0 / 0 |
| task | phishing_email / fake_job_postings | 75 / 177 | 4 / 15 |

Mislabel candidates: 123 rows (39 likely, 84 uncertain), ids only, in `reports/investment_mislabel_candidates.csv`. No task row
labelled genuine looked like a task scam. The 84 uncertain rows are market commentary from the same chat. Scam groups post market news to
look legitimate, so whether a line that asks for nothing is a "scam message" is a labelling policy decision (section 6), not a fact.

## 3. Current performance

**Val (existing predictions, each model's own val cut-offs; MuRIL = the app's 0.103 / 0.436 after temperature):**

| val subset | model | scams caught (>= Suspicious) | genuine false alarms |
|---|---|---|---|
| investment, short-message sources | both | no scam rows | no genuine rows once the mislabels are set aside |
| task / part-time, short-message sources | MuRIL / baseline v2 | 8/8 / 8/8 | 0/1 / 0/1 |
| crypto, all sources | MuRIL / baseline v2 | 3/3 / 3/3 | 0/3 / 0/3 |
| investment keywords, phishing_email (US stock spam) | MuRIL / baseline v2 | 41/44 / 41/44 | 0/12 / 0/12 |
| 5 val group-chat rows labelled genuine (scams, if read so) | MuRIL / baseline v2 | 0/5 / 0/5 | - |

**Probe v1 (`live=False`, flagged = Suspicious or Likely scam):**

| | MuRIL router | app baseline router |
|---|---|---|
| scams caught, all 54 | 39 (72%), all at Likely | 40 (74%), 28 at Likely |
| 9 quoted rows | 5 | 7 |
| 45 rows written from a cited source | 34 | 33 |
| genuine false alarms, 48 | 14 (29%), 13 at Likely | 18 (38%), 8 at Likely |

The 10 worst MuRIL misses (all scored 0.015-0.025, No warning signs): s18 group IPO invite on a named app; s52 "teacher will share the stock
at 2 PM" (early stage); s03 USDT "100usdt to reset 40 new orders" (verbatim; the baseline catches it); s13 VIP upgrade with a "SEBI
certificate"; s16 FII pre-allotment; s54 "assistant from the Zerodha team ... fixed monthly returns"; s28 "Buy A-1 Ltd now, target double";
s51 fake testimonial; s53 "our study group ... it is free"; s24 "download Wells Pro to subscribe to the IPO". The pattern: **MuRIL catches
the payment step (pay-to-withdraw 6/6, prepaid tasks 2/2) and misses the hook (group, VIP, IPO, tip), which is where a warning still helps.**

Most of MuRIL's false alarms are not borderline: 11 of the 14 score 0.83-0.99 (g07 0.63, g36 0.44, g33 0.12). They are: g21-g23 (SEBI's @valid templates), g24 broker add-funds via @valid, g26
withdrawal processed, g18 redemption, g14 IPO allotment, g29 pledge alert, g32 KYC validated, g34 BSE awareness, g36-g37 registered
analyst calls, g07 bonus-share credit; g33 broker awareness at Suspicious. They all mention money moving or being invested. The training data has
no genuine message of that kind, so for MuRIL "investment + money" means scam.

## 4. Rule feasibility (research only)

### (a) SEBI's @valid UPI handle

- **Rule:** SEBI circular SEBI/HO/DEPA-II/DEPA-II_SRG/P/CIR/2025/86, 11 June 2025, "Adoption of Standardised, Validated and Exclusive UPI IDs
  for Payment Collection by SEBI Registered Intermediaries from Investors". Official home: sebi.gov.in -> Legal -> Circulars (para 10).
  Read from the copy at https://files.hdfcfund.com/s3fs-public/2025-12/1749641449497.pdf (15 pages).
- **Format (para 2.1):** `<username>.<suffix>@valid<bank>`, e.g. `abc.brk@validhdfc`, `xyz.mf@validicici`. Suffixes (Annexure B): `brk` stock
  brokers, `bti` bankers to an issue, `dp` depository participants, `ra` research analysts, `ia` investment advisers, `invit`, `mf` mutual funds,
  `pms` portfolio managers, `sreit`, `reit`. Only the 52 self-certified syndicate banks in Annexure C get `@valid` handles (allocated by NPCI,
  merchant category code 6211, para 3.1). The payment app shows a white thumbs-up in a green triangle (para 2.2). "SEBI Check" verifies a UPI
  id or account + IFSC (para 5).
- **Start:** available to investors from **1 October 2025** (para 8). Intermediaries obtain handles at T+90 to T+105 days and must stop old UPI
  ids by **T+180 days** (about 8 December 2025, counted from 11 June). Existing MF SIPs may keep the old mode; new or renewed SIPs use the new
  ids (para 6.1.3).
- **Who:** mandatory for every investor-facing intermediary in Annexure B to obtain and offer. **Optional for investors**: they may pay by
  NEFT / RTGS / IMPS / cheque, but if they pay a registered intermediary by UPI, it must be to the @valid id (Annexure F, investor FAQ).
- **What a rule can use:** a request to pay a "broker / advisor / trading account" to a UPI id that is not `@valid...` is a strong sign. But
  scams mostly give bank accounts or "the account customer service gives you", and the absence of a UPI id says nothing. A message *with*
  a `@valid` id must not lower the level, because a scammer can paste the template.
- **Pipeline catch:** `pii.mask_text` turns `abc.brk@validhdfc` into `<EMAIL>` and personal handles into `<UPI_ID>`. The text heads never
  see the difference, so the rule has to read the raw text, as `rules.cred_requests` does. Val text is already masked, so the rule cannot be
  counted on val at all.

### (b) SEBI's registered-intermediary lists

- **Where:** sebi.gov.in -> Recognised Intermediaries, one HTML list per type, e.g. investment advisers
  `https://www.sebi.gov.in/sebiweb/other/OtherAction.do?doRecognisedFpi=yes&intmId=13` (1,062 records on 24 Oct 2026) and research analysts
  `...&intmId=14` (2,324). Fields: name, registration no., e-mail, telephone, address, contact person, validity.
- **Download:** no Excel / CSV / PDF export is offered. The pages have search and "Show All Records" with pagination (25 per page), and
  say "as on date" with the day's date, so they are updated continuously. A copy would mean scraping every page of every type. Plain fetches
  of listed URLs are allowed, but a crawl through Firecrawl needs the user's OK (rule 7). The app must never fetch the list live (rule 8:
  sebi.gov.in is not on the `net.py` allowlist). It would be an offline list refreshed by `update_link_lists.py`, like Tranco.
- **Licence:** not found (SEBI's copyright page returned 404). Treat it as public regulatory information that we use, not redistribute,
  until checked.
- **Number formats:** `INA` + 9 digits investment adviser (`INA000017523`; IFSC units `INAIFSC10001`), `INH` + 9 research analyst
  (`INH000002475`), `INZ` + 9 stock broker (`INZ000164132`), `INP` + 9 portfolio manager (`INP000002213`), `INM` + 9 merchant banker
  (`INM000010759`), `IN-DP-<n>-<year>` depository participant (`IN-DP-423-2019`). Older per-segment broker prefixes (INB / INF) were not
  confirmed by a source here.
- **What a rule can use:** "SEBI registered / certified" with no number (rule A2), and later "a number that is not on the list". A number
  that **is** on the list proves nothing. Scammers impersonate real registered firms (SEBI's April 2025 circular is about forged certificates).

### (c) Phrases and patterns, and what each rule would catch

Top word n-grams by the number of probe rows they occur in (scam / genuine). Scam side: `pay` 12/3, `group` 11/0, `members` 10/0,
`join` 8/0, `profit` 8/0, `earn` 7/0, `vip` 7/0, `every` 7/0, `month` 7/1, `today` 7/1. Genuine side: `shares` 11/3, `demat` 10/1, `cdsl` 8/0,
`oct` 8/0, `ltd` 8/1, `upi` 8/1, `registered` 8/2, `abc` 7/0, `fund` 7/0, `securities` 7/1. Caveat: we wrote most of the rows, so these partly
measure our own wording. `upi`, `registered` and `shares` lean genuine, which is why a "mentions UPI / SEBI / shares" rule is a bad idea.

| rule (regex in `src/audit_investment.py`, not in the app) | probe scams caught /54 | probe genuine fired /48 | val genuine short-msg fired /956 | new catches on top of MuRIL |
|---|---|---|---|---|
| A1 pay to a UPI id that is not @valid, in an investment context | 1 | 0 | n/a (masked) | 0 |
| A2 "SEBI registered / certified" with no INA/INH/INZ/INP number | 3 | 1 (g34, an awareness notice) | 0 | 1 |
| A3 guaranteed / assured / fixed / sure-shot returns, not negated | 8 | 1 (g35: the negation was 7 words away) | 0 | 1 (+1 false alarm) |
| A4 pay a fee / tax / deposit to withdraw, release or unfreeze | 8 | 0 | 0 | 0 |
| A5 join / upgrade to a VIP or tips group, channel or club | 7 | 0 | 0 | 2 |
| A6 share login / password, or "we handle your account" | 2 | 0 | 0 | 0 |
| A7 earn N per day for likes / ratings / reviews / part-time | 4 | 0 | 0 | 0 |
| A8 prepaid task / deposit for a task, tier or level | 6 | 0 | 0 | 1 |
| A9 app / APK to install from a link, in an investment context | 2 | 0 | 0 | 0 |
| A10 IPO pre-allotment / institutional account / block trade / FII | 6 | 0 | 0 | 4 |
| A11 minister / celebrity-endorsed scheme | 2 | 0 | 0 | 0 |
| A12 crypto / USDT deposit | 3 | 0 | 0 | 0 |
| any (union) | 39 | 2 | 0 | 6 (+1 false alarm) |

## 5. Phase A: rules (about 1-2 sessions, Sonnet high)

**Result (2026-10-25, `reports/investment_rules_v1.md`).** Built as planned, with the regexes tightened where the first run on the whole val split fired on 15 genuine rows (long-form emails and job posts; all hook rules except A8): the final rules fire on 0 of 4,115 genuine val rows and change 0 of 5,267 val verdicts (val F1 0.9294 before and after for MuRIL, 0.8924 for the baseline), and on 0 of 48 genuine probe rows. On the probe v1 (**upper bound**, written after reading it): MuRIL router 39/54 -> 46/54 scams flagged (7 new: s03 s13 s15 s16 s18 s39 s54), false alarms 14/48 -> 14/48; the rules alone catch 41/54. The old "+6, 45/54" estimate below was made with the audit's looser regexes. Not fixed, as planned: the 13 genuine probe rows MuRIL calls Likely scam (Phase B).

Add rules like the OTP / PIN rules: a hit **floors** the level at Suspicious, never gives Likely scam alone, and shows its own reason and
advice ("Check the UPI id ends in @valid... and use SEBI Check", "No registered adviser can promise fixed returns", "Pre-IPO allotment through a
group is not a thing"). Candidates, in order of value:

1. **A10 IPO pre-allotment / institutional account / block trade** (+4 on the probe, 0 false fires anywhere). This is the 2024-26 big-loss pattern.
2. **A5 join a VIP / tips group** (+2), with A2 **unnumbered SEBI claim** (+1). A2 needs an exclusion for advisory wording ("deal only with SEBI
   registered"), which is g34's false fire.
3. **A3 guaranteed returns** (+1, 1 false fire): only with negation handled across the clause, not just a few words back.
4. **A4 pay-to-withdraw, A8 prepaid task, A1 non-@valid UPI**: MuRIL already catches these on the probe. Add them as safety nets, because they
   are cheap and the scams' last step. A1 runs on the raw text, before masking.

**Expected gain:** on probe v1, recall 39 -> 45 of 54 (72% -> 83%) for +1 false alarm. That is optimistic: the rules were written after reading
the probe. Phase A is done only when a **probe v2** says so: at least 40 scam rows from a different writer or real submissions, and at least
40 genuine broker / exchange / depository messages, ideally real ones with personal data masked.

**What Phase A cannot fix:** the 14/48 false alarms. A rule that *lowers* the level on genuine-looking wording (`@valid`, a SEBI number,
"CDSL:") is exactly what a scammer pastes. The OTP safety-advice cap (`config.SAFETY_ADVICE_CAP`, off) shows how hard such a cap is to make
safe. Only retraining with genuine investment messages fixes false alarms. Until then, the explanation for investment-context messages
should say that MuRIL is unreliable on broker / depository messages (a wording change, not a level change).

## 6. Phase B: data, splits-v3, retrain

Steps, with their cost in sessions:

1. **Labelling policy + relabel** (1 Opus-high session + the user's review). Decide whether a scam group's lines that ask for nothing are
   scams ("message from a scam operation") or genuine ("this message alone is harmless"). Then relabel the 39 likely rows and decide the 84
   uncertain ones. Relabelling changes labels, not splits, but it still needs a new frozen map and tag.
2. **Genuine investment messages** (1-2 sessions + the user's time). The real fix for false alarms. Real broker / NSE / BSE / CDSL / NSDL / AMC /
   RTA / TDS SMS: from the user's and volunteers' phones (masked at ingestion, rule 5) and maybe the real-message Form (but its rows are TEST
   only, rule 12, and cannot be reused). Target at least 300 train + 50 val. Messages written from formats are synthetic (rule 4) and
   train-only.
3. **Investment / task scam messages** (1 session). Real ones are scarce as text, so: synthetic templates in the `synth_india` style (train
   only, `is_synthetic=True`), covering the hook stages (group invite, VIP, IPO, tips, app) and the payment stages. Plus any real ones from
   Chakshu-style reports if a source with a usable licence turns up. Target at least 200 train + 40 val, with real ones in val.
4. **splits-v3** (1 Sonnet-high session). New rows join clusters as usual. Fold in the other splits-v3 candidates in BUGS.md (PII gaps).
   Update the hash in CLAUDE.md and `finetune.py`, tag `splits-v3`, rerun augment / baseline / sanity, re-upload the Kaggle dataset.
5. **Retrain MuRIL on Kaggle + evaluate on the Mac** (1-2 sessions). Same recipe as D27. Evaluate with `eval_text_head.py`, including a
   per-topic table and probe v2. Then recalibrate (1 session).

Total: **about 6-8 sessions**, plus collection time that depends on people, not code.

**Go / no-go for Phase B.** Do it when **all three** hold:

1. After Phase A, the MuRIL router on probe v2 still gives **>= 10% false alarms on genuine investment messages** or **< 80% recall on
   investment scams**. (Probe v1 today: 29% false alarms, 72% recall, so condition 1 is met unless probe v2 disagrees sharply.)
2. **The data exists to measure the result:** at least 40 investment-scam rows and 40 genuine investment rows that can sit in **val** (real,
   or provenance-tagged and reported separately), plus the train pools in steps 2-3. Without val rows, a retrain is unmeasurable, which is the
   situation today. **This is the blocker.**
3. The labelling decision in step 1 is made.

If condition 2 cannot be met within about two weeks of collecting, stop at Phase A and the wording change, and record the gap in BUGS.md.

**2026-10-29:** provisional no-go (phones: 1 scam + 3 genuine investment groups labelled, 30 unlabelled; the gate needs 40 + 40 in val); confirmed or reversed on Nov 1 after dad's phone.

## 7. Limits

- **Scams that start innocent.** s52 ("the teacher will share today's stock at 2 PM") and s53 ("our study group ... it is free") ask for
  nothing. Neither head flags them and no rule should: the same text in a genuine club would be a false alarm. The fake testimonial (s51)
  is the same.
- **Multi-message chats.** The app judges one message. In these scams the fraud is in the sequence (invite -> tips -> app -> deposit ->
  withdraw fee), spread over weeks. A single line is often harmless. The dataset's group-chat rows are single lines labelled one by one, which
  is how the mislabels happened. Conversation-level input (paste a whole chat, or a screenshot series) would be a separate design (D-decision).
- **Fake apps and links.** The fraud often sits in an app or a web dashboard we may not open (rule 8). The URL head sees only the address.
- **Probe v1 is mostly ours.** 45 of 54 scam rows and all 48 genuine rows were written by us from cited descriptions; only 9 are quoted. Only 3
  rows are Hinglish and none are Hindi or Kannada script. The probe shows patterns; it does not estimate real-world rates.
- **Deepfake video ads and calls** (the PIB fact-check cases) are not text. Only the follow-up message reaches us.

## 8. Side findings

- MuRIL scores SEBI's official @valid awareness templates (circular Annexure E) at 0.97. If a broker sends one, the app says "Likely scam".
- `pii.mask_text` masks `@valid` handles as `<EMAIL>` (the dotless `user@host` rule from splits-v2). That is fine for privacy, but it hides the
  only structural difference between a registered intermediary's UPI id and a personal one.
- The older git-ignored `data/probes/investment_probe.csv` (2026-10-22) copied two **test-split** rows. It is not used here; delete it.
- Sources for every probe row are in its `source_url` column. The other sources used for this plan: the SEBI circular above; SEBI
  Recognised Intermediaries pages; firm disclosure pages for the registration-number examples (e.g. https://www.icici.bank.in/about-us/list-of-sebi-registrations,
  https://primeinvestor.in/regulatory/, https://www.citigroup.com/rcs/citigpa/storage/public/India/sebi-reg-details-cgm-india.pdf).
