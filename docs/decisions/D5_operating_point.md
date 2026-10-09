Status: design accepted 2026-10-10; analysis deferred until splits-v2 (rule 10)

# D5 operating point: data inventory, app research, proposal, analysis plan

## Context

D5 in `docs/ARCHITECTURE.md` sets the operating point: how many false alarms on legitimate messages are acceptable, and where the two score cut-offs sit. D1–D4 are settled. The current cut-offs (Suspicious 0.423 / Likely scam 0.656) come from `baseline.py --save`: "Suspicious" is the highest cut-off that keeps val scam recall at or above 0.95, and "Likely" is the max-F1 cut-off. Neither rule looks at false alarms on legitimate messages.

Your proposal: Likely scam ≤ 1% and Suspicious-or-above ≤ 5% of hard-legit messages, measured on the final verdict, picked on val now and on real-dev (D7) later, never on test.

Nothing was run and no file was changed. The counts below come from existing reports, read-only sample rows (`grep | head`) and arithmetic.

**Tags:** **[data]** = our files and reports; **[derived]** = arithmetic on report numbers; **[estimate]** = my estimate from reports, not counted; **[src]** = a cited web source; **[judgement]** = my opinion.

---

## 1. Data inventory

### 1.1 What counts as hard-legit, and where it is

| source | benign rows (all splits) | what the benign rows are | tier |
|---|---|---|---|
| `india_fraud_final` | 1,600 | India transactional / government notices per scam theme (OTP, Aadhaar update, GST, tax paid, cashback, CoWIN, Internshala, bill). 86% `is_synthetic` [data: sanity §1]. The suffix variants ("Thank you for choosing our service", "For queries, call our helpline") are flagged synthetic. Even the unflagged seeds use placeholder numbers (`987654`, `445566`, `URN: 1234/5678/90`) [data: sampled val rows] | **hard (all)** |
| `synth_india` | 652 | paired benign templates of each scam theme, en/hinglish/hi/kn | **hard (all)**, but **0 val rows** [data: BUGS.md] |
| translations (after `splits-v2`) | ~523 hi / ~499 kn | bank, OTP and delivery alerts from `otp_sms_preview` [data: translate_finalise.md] | **hard (all)**, synthetic |
| `uci_sms_spam` | 4,512 | personal chat (UK/SG, 2000s); a few transactional (e.g. "NEFT Transaction ... credited") | easy, except keyword+shape hits |
| `scam_ham_india` | 1,345 | personal chat and stock-market group chat [data: sampled val rows] | easy, except keyword+shape hits |
| `cmu_hinglish_dog`, `hinglish_conversations` | 978 | chat | easy |
| `phishing_email`, `ealvaradob_phishing` | 11,145 | email | other genre (reported apart) |
| `fake_job_postings` | 15,252 | long US job ads | other genre (reported apart) |
| `otp_sms_preview` (**not in messages.csv**) | 7,404 non-phishing; 2,534 English transactional 40–160 chars; ~359 template groups; 915 non-Latin rows never examined | bank / OTP / delivery SMS, provenance `unknown`, some numbers machine-randomised [data: translate_parents.md] | proxy only |

Two findings [data]:
- The sanity count found only **46** (`uci_sms_spam`) and **13** (`scam_ham_india`) benign rows of ≤ 200 chars with transactional words, against 790 in `india_fraud_final` [sanity Interpretation §1]. So nearly every hard-legit row we have is templated or synthetic.
- **The scam label contains genuine-looking ads.** 470 `scam_ham_india` scam rows of 40–160 chars are promotions with no fraud mechanism: Vi data packs, store deals, card offers [data: translate_parents.md, SCAM RULE row]. The val recall rule (≥ 0.95 of *all* scams) therefore partly asks the model to flag real brand promos. That works against any false-alarm target.

### 1.2 Tagging rule (reproducible; freeze it before any score is read)

Inputs are the stored masked `text`, `source`, `label`, `language`. It reuses the existing regexes in `src/translate_parents.py` (`benign_bucket` / `TXN`, `PROMO_AD`, `scam_bucket`, `strip_warnings`, `category`) by import, not by copy.

- **legit_tier** (label 0):
  1. `hard`: source is `india_fraud_final`, `synth_india` or `translated_indic`.
  2. `hard`: any other SMS-type source (`uci_sms_spam`, `scam_ham_india`, SMS rows of `ealvaradob_phishing`) where `benign_bucket(text)` is `transactional` **and** a shape cue is present. Shape cues: an amount (`AMOUNT_RE`), a mask token (`MASK_RE`), a run of ≥ 4 digits, a sender sign-off (`-[A-Z]{3,}$`, `- Team \w+`), or `Dear (Customer|User|Member)`. The shape guard exists because `TXN` alone matches chat such as "keep your laptop full recharge buddy" [data: sampled row].
  3. `other_genre`: `phishing_email`, `fake_job_postings`.
  4. `easy`: everything else.
- **hl_category** (hard only): `category(text)` from translate_parents (bank, kyc, upi, courier_customs, utility, echallan, lottery/rewards, job, digital_arrest = government notice, other).
- **scam_tier** (label 1): `fraud` if `scam_bucket(text)` keeps the row, otherwise `promo_gray` (promotional or no fraud mechanism). D5 recall is measured on `fraud`. `promo_gray` is reported apart.
- **Independence unit:** `cluster_id` (val/test), template group (translations), sender×template (real-dev later).

### 1.3 Hard-legit in val today

| language | hard-legit val rows | independent templates | of which real |
|---|---|---|---|
| English | ~195 from `india_fraud_final` [derived: val 350 = 660 val+test − 310 test; val scam 155 = 308 − 153] + ~0–10 from `uci_sms_spam` (val benign 438) / `scam_ham_india` (val benign 147) [estimate: 59 transactional rows in all splits × ~10%] → **~200** | **~25–35** [estimate: BUGS.md "about 30 clusters per category/label cell", ~10% of clusters in val, ~6–7 rows per cluster] | **~0–10.** About 27 `is_synthetic=False` `india_fraud_final` rows [estimate: 14% of 195], but they look author-written (placeholder numbers) [judgement] |
| Hindi | **0** now; ~52 after `splits-v2` (5th pct 35) [data: translate_finalise.md] | ~30 template groups [estimate: 326 groups × ~10%] | 0 |
| Kannada | **0** now; ~49 after `splits-v2` (5th pct 34) | ~30 | 0 |
| Hinglish | **0** (val Hinglish is 102 benign chat rows) [data: sanity §2–3] | 0 | 0 |

The exact counts by cluster are step 1 of the analysis (§4).

### 1.4 How many hard-legit messages a usable 95% interval needs

Wilson 95% intervals, counted in **independent** messages (clusters), not rows [derived by hand]:

| true rate | n | 95% CI | | zero false alarms in n: 95% upper bound |
|---|---|---|---|---|
| 1% | 100 | 0.2–5.4% | | n=30 → 11.4% |
| 1% | 300 | 0.3–2.9% | | n=75 → 4.9% |
| 1% | 800 | 0.5–2.0% | | n=300 → 1.3% |
| 1% | 1,500 | 0.6–1.6% | | n=400 → 0.95% |
| 5% | 150 | 2.5–9.7% | | |
| 5% | 300 | 3.1–8.1% | | |
| 5% | 500 | 3.4–7.3% | | |

**Usable** [judgement]: at the target rate, the interval excludes twice the target. Rule of thumb n ≈ 8 / target.
- **1% (Likely scam):** about **800 independent messages per reported group**, or ≥ 400 with zero false alarms to show "≤ 1%".
- **5% (Suspicious+):** about **150**, or ≥ 75 with zero false alarms.

**Do we have enough? No** [derived]:
- English val has ~25–35 independent templates and almost none are real. Even with zero false alarms the upper bound is ~10–11%, so neither 1% nor 5% can be shown.
- Hindi / Kannada: none now, and ~30 synthetic groups after `splits-v2`.

**What would fill the gap:**
1. **Real-dev (D7), volunteer inboxes, masked at intake:** the only source that makes the targets claims.
   - Need: ≥ 800 independent English hard-legit messages for 1% (deduped to templates, ≤ 3 per sender template; ≈ 10 volunteers × ~80 distinct templates [estimate]), and ≥ 150 per language for 5%.
   - Hindi bank and government SMS exist; Kannada is likely too rare for 1% [judgement]. So per-language 1% probably stays unmeasured.
   - Collect with volunteer id and sender id, so the split can be grouped.
2. **`otp_sms_preview` English transactional rows as a proxy** (already on disk; provenance unknown, never counts as real).
   - ~359 template groups, so it can roughly check a 5% target.
   - Leakage: on `splits-v1` the translations are not built yet, so only rows with a `messages.csv` twin at ≥ 0.6 need dropping. After `splits-v2` every group has a translated parent, so use only groups whose translations landed in val, or flag the leak.
   - Its 915 non-Latin rows may contain Hindi / Kannada transactional SMS. Examine them; they are not used today.
3. The gated full 73k set (free access request): more of the same proxy, same provenance caveat.
4. **Not** synthetic generation for the claim (rule 4).

---

## 2. Established apps (WebSearch only; no page was opened, fetched or scraped)

**Caveat on the method:** the WebSearch tool returns its own summary of the result snippets, not the pages. Wording below is "as reported". Where the search did not confirm a label, it says so. The same weak spot is recorded for the gambling review in BUGS.md.

| app | levels and wording | score / % shown? | uncertainty | dispute / feedback | published FP figures |
|---|---|---|---|---|---|
| **Google Messages Scam Detection** | Red-warning notification with a **"Likely scam"** button; spam is a separate filter ("Spam & blocked" folder) [src: [Pixel help](https://support.google.com/pixelphone/answer/16704479?hl=en), [Messages help](https://support.google.com/messages/answer/9061432?hl=en)]; English only [src: [Pixel help AU](https://support.google.com/pixelphone/answer/16704479?hl=en-AU)]. Gmail: "This message could be a scam" [src: [Gmail help](https://support.google.com/mail/answer/1074268?hl=en)] | none described | "may not catch every scam" [src: Pixel help] | **"Not a scam"** (marks it safe; turns detection off for that conversation for a while) or "Done" [src: Pixel help]; "Report spam / Report not spam" [src: [Xiaomi FAQ](https://www.mi.com/ph/support/faq/details/KA-539201)] | not published |
| **Truecaller** | SMS Fraud Protection (India, 2023): red notification telling the user not to act, stays until dismissed; **all links disabled**; thread opens only if the user **marks the sender safe**; on-device [src: [PR syndication](https://jotup.co/node/2351213), [CRN](https://www.crn.in/?p=57495)]. Scam Checker (web, Sep 2026): **"Safe" / "Potential Fraud"** [src: [TechRepublic](https://www.techrepublic.com/article/news-truecaller-scam-checker-apac-india/)]; South Africa test: Safe / Unsafe / **Unknown** [src: [MyBroadband](https://mybroadband.co.za/news/security/669556-truecaller-scam-checker-tested-in-south-africa.html)] | none described | "Unknown" does not mean unsafe; a result is a signal, not a guarantee [src: MyBroadband, TechRepublic] | "not spam" lowers a number's spam score; per-message feedback spam / non-spam / fraud [src: [Truecaller KB](https://truecaller.zohodesk.in/portal/en/kb/articles/how-does-truecallers-spam-detection-happen-on-the-app), [archived page](https://web-archive.nli.org.il/National_Library/mp_/http://www.truecaller.com/message-id/feedback-on-messages)] | **not published** [src: TechRepublic says no FP/FN figures] |
| **Sanchar Saathi – Chakshu** | No verdicts: a **reporting** facility. Categories include KYC, impersonation, fake customer care, lottery / loan / job, service disconnection, sextortion [src: [Sanchar Saathi](https://sancharsaathi.gov.in), [Factly](https://factly.in/explainer-government-launches-chakshu-to-report-sms-call-or-whatsapp-messages-attempting-to-commit-fraud)]. It is for **attempts**; if money is lost: **1930 / cybercrime.gov.in** [src: Factly, [Outlook Money](https://www.outlookmoney.com/retirement/financial-planning/how-to-report-suspected-fraud-communication-via-dots-chakshu-facility)] | n/a | n/a | n/a (OTP-verified report form) [src: Outlook Money] | not applicable / not published |
| **Scamadviser** (websites) | **Trust Score 1–100**; "a risk indicator, not a verdict" [src: [Scamadviser explainer](https://www.scamadviser.com/articles/scamadviser-algorithm-explainer)]; 2019 cut-offs: < 30 serious concerns, < 70 do an extra check [src: [Cross-Border Magazine](https://cross-border-magazine.com/?p=4421)] | **yes, a number** (the only one in this list) | the score is the uncertainty display | contact them / reply on Trustpilot [src: [FAQ](https://www.scamadviser.com/faq), [Trustpilot](https://nz.trustpilot.com/review/www.scamadviser.com)] | not published; no independent validation found [src: [Factually](https://factually.co/fact-checks/technology/do-scamadviser-scamdoc-scores-predict-online-store-reliability-128b58)] |
| **Norton Genie** | reported results: **"Not sure"** [src: [PCWorld](https://www.pcworld.com/article/2025891/nortons-free-ai-powered-genie-tool-helps-you-spot-online-scams.html)]; "It looks suspicious"; a named type: "This message contains signs of an Advance Fee Scam" [src: [iTWire](https://itwire.com/security/norton-launches-genie-scam-detector.html)]; 2026 ChatGPT version: safe / risky / likely a scam [src: [IT Brief](https://itbrief.com.au/story/norton-unveils-genie-scam-detection-assistant-in-chatgpt)] | none reported | explicit "Not sure" | not found | not published |
| **Bitdefender Scamio** | **"Safe" / "Scam"** [src: [CometChat case study](https://cometchat.com/customer-stories/bitdefender)]; "safe or risky" [src: [Scam Protection page](https://www.bitdefender.com/en-us/consumer/scam-protection)]; next steps such as delete or block [src: [press release](https://bitdefender.in/press_releases/bitdefender-launches-scamio-a-powerful-scam-detection-service-driven-by-artificial-intelligence/)]; asks follow-up questions when details are missing [src: [Scamio page](https://www.bitdefender.com/en-us/consumer/scamio)] | none reported | terms: verdicts "may contain errors"; 5 checks/day [src: [terms](https://www.bitdefender.com/en-us/site/view/subscription-agreement-and-terms-of-services-for-home-user-solutions)] | not found | not published |
| **McAfee Scam Detector** | verdict labels **not confirmed** by search. It explains *why* a message was flagged; email gets a "McAfee Alert" label; user sensitivity **High / Balanced / Low**; Android flags on arrival, iPhone filters to a folder [src: [McAfee blog](https://www.mcafee.com/blogs/mcafee-news/introducing-mcafees-scam-detector-now-included-in-all-core-plans/), [Help Net Security](https://www.helpnetsecurity.com/2025/05/14/mcafees-scam-detector/)] | none described | sensitivity setting | not found | **not published.** Vendor claims "> 99% accuracy" for the text model and ~1.5% of texts flagged (a flag rate, not an FPR) [src: same] |
| **Trend Micro ScamCheck** | ScamCheck labels **not confirmed**; a third-party listing says "safe" / "scam" [src: [listing](https://mwm.ai/apps/trend-micro-scamcheck/1566099565)]. Trend's web rating: Safe / Suspicious / Highly suspicious / Dangerous / **Untested** [src: [Trend docs](https://docs.trendmicro.com/en-us/documentation/article/trend-micro-web-security-online-help-about-web-reputation)] | none confirmed | "Untested" level | an App Store reviewer said the SMS filter blocked important messages; the developer pointed to filter settings [src: [App Store reviews](https://apps.apple.com/us/app/trend-micro-scamcheck/id1566099565?see-all=reviews&platform=iphone)] | not published |
| **Chrome / Safe Browsing** | red **"Dangerous site"** page; the user can still proceed [src: [Chrome help 99020](https://support.google.com/chrome/answer/99020?hl=en), [9890866](https://support.google.com/chrome/answer/9890866?hl=en)]; "Deceptive site ahead" [src: [Computerworld](https://www.computerworld.com/article/3403447/google-asks-chrome-users-for-help-in-spotting-deceptive-sites.html)] | none | none (a list hit, or nothing) | report an incorrect listing [src: [Safe Browsing reporting](https://developers.google.com/safe-browsing/v4/reporting), [report form](https://support.google.com/websearch/contact/safe_browsing)] | **not published.** Field study: users clicked through **9–23%** of malware / phishing warnings, and through frequent warnings faster [src: [Akhawe & Felt 2013](https://research.google/pubs/pub41323), [USENIX](https://usenix.org/conference/usenixsecurity13/technical-sessions/paper/akhawe)] |

**Patterns** [judgement drawn from the [src] rows above]:
- No message scanner shows a percentage. The one that shows a number (Scamadviser) calls it "not a verdict". This supports D4.
- Most have an explicit don't-know state (Not sure / Unknown / Untested). This supports "Can't judge".
- "Likely scam" is Google's own label.
- Apps that say "Safe" hedge it in the small print. Our "No warning signs found" says that hedge in the label itself.
- On-device scanners all offer a one-tap dispute.
- **None publishes a false-alarm rate.** An honest measured FPR would be a real point of difference, but only if it is measured as in §4.

---

## 3. Proposed D5 [judgement unless tagged]

**Keep the core of your proposal:**
- two targets (Likely scam ≤ 1%, Suspicious+ ≤ 5%);
- hard-legit messages as the denominator;
- the final verdict as the thing measured;
- val now, real-dev later, never test.

Your reason holds: people paste messages they are unsure about, so bank, OTP and KYC look-alikes are the realistic legitimate traffic.

**Changes:**

1. **Count independent messages, not rows.** Compute FPR with each cluster weighted once, and a cluster-bootstrap CI. In val `india_fraud_final`, ~195 rows are only ~25–35 templates (§1.3), so row counts overstate certainty about 7×.
2. **Targets are design targets until the data can show them.**
   - Provisional val thresholds are labelled *provisional* in the model card.
   - Reports say "x of N independent templates flagged; 95% upper bound y", never "FPR = 1%".
   - With ~30 templates, the 1% cut-off can only be set as "no hard-legit template reaches Likely scam".
3. **Pair each target with a recall floor and a precedence rule.**
   - *Likely scam:* FPR wins; raise the cut-off until ≤ 1%.
   - *Suspicious:* a recall floor wins: ≥ 0.90 on val `fraud` scams of SMS-type sources, *not* all scams.
   - 5% is the target, and > 10% on hard-legit is a **ship gate** (a MuRIL head that fails it is not promoted).
   - Why: a missed scam is the costliest error, and Suspicious advice ("check through the official app or number") costs a legitimate user one minute. But repeated false warnings train people to click through (the Chrome study above).
4. **Take promotions out of both sides.** `promo_gray` scam rows (genuine-looking ads) are not in the recall denominator. Their flag rate is reported, with no target.
   - Open label-policy question (**D5b**): is a real brand ad a "scam"? Today `scam_ham_india` and `uci_sms_spam` say yes.
5. **Give "Can't judge" its own budget** on hard-legit (report it; ≤ 10% [judgement]). This stops the verdict logic from lowering false alarms by moving messages into "Can't judge".
6. **Language cap.** One global pair of cut-offs. Where no real dev data exists (Hindi, Kannada, Hinglish), the text model alone can reach at most **Suspicious**.
   - The cap lifts once real-dev has ≥ 150 independent hard-legit messages in that language.
   - Link evidence and checked rules are unaffected.
   - This extends the existing policy that an unchecked rule may explain but never force a verdict, and it pairs with D6.
7. **Attribute every final-verdict false alarm** to what raised it: text head, URL head, OTP floor, both-Suspicious fusion, or free-host keyword rule.
   - Report hard-legit with links and without links apart. The URL head flags 8.3% of Tranco test domains [data: BUGS.md / url_head.md], so the link path may break 5% on its own until the D8 fixes land.
8. **Bracket the provisional estimate.**
   - Optimistic: in-distribution val.
   - Pessimistic: out-of-source scores. The `india_fraud_final` LOSO model calls ~70% of its benign rows scams [data: sanity §5, benign accuracy 0.295].
   - Pick on in-distribution val, report both. Real traffic will likely land in between.
9. **Real-dev protocol (D7):** dedupe to sender templates; pick cut-offs on half the volunteers and report on the other half (or leave-one-volunteer-out). Then the final test, once.

**PPV check, why 1% / 5% is reasonable** [judgement, arithmetic]:
- At a 30% scam share among pasted messages, with Likely recall 0.7 at 1% FPR, a "Likely scam" verdict is right ~97% of the time.
- Suspicious recall 0.95 at 5% FPR gives ~89%.
- At a 5% scam share these fall to ~79% and ~50%. Hard-legit FPR is what keeps the verdict trustworthy when most pasted messages are fine.

**Risks:**
- Cut-offs from ~30 templates are unstable (mitigation: report the bootstrap spread of the chosen cut-off).
- The regex tagger misses hard cases without keywords (mitigation: spot-check 100 rows).
- The 1% cap may push most scams down to Suspicious. This is acceptable, because Suspicious advice still says don't pay and don't share.
- D5 is tied to the URL head and the rules, so every component change needs a rerun. Keep the eval cheap.

**What to copy from the established apps:**
- **Wording:** keep "Likely scam" (Google) and "Suspicious" (Trend / Norton). Keep "Can't judge", and add Truecaller's clarifier: "This doesn't mean it is safe or unsafe". Keep "No warning signs found" rather than "Safe".
- **Verdict line:** name the scam type, e.g. "signs of an advance-fee scam" (Norton). The architecture already plans this.
- **Explanation:** say why it was flagged (McAfee). Already principle 4.
- **Dispute:** a one-tap "This looks wrong" / "Not a scam" (Google, Truecaller). This conflicts with principle 6 (no user content on disk). Proposal: by default it stores nothing and only shows how to report. In opt-in volunteer / study mode it saves masked text + verdict + the user's label locally for the D7 real-dev set. This needs your decision (**D5c**).
- **Next steps:** split by situation, as Chakshu does. Attempt only → report via Chakshu; money lost or OTP shared → call 1930 / cybercrime.gov.in now.
- **Links:** show them as plain text, never clickable (Truecaller disables links).
- **Not copied:** the McAfee sensitivity slider (each position would need its own measured FPR; maybe later) and the Scamadviser numeric score (D4).

---

## 4. Analysis plan (not run; Sonnet high to build, Opus high to review)

**Rule 10 first:** `splits-v2` (waiting on the spot-check) adds Hindi / Kannada hard-legit val rows. Its PII fixes rehash ~70 rows. Run the English part now on `splits-v1` as a dry run. Rerun after `splits-v2`. Write no thresholds into the app until then and until you approve.

**New and changed files:**
- `src/legit_tiers.py`: the §1.2 tagger as pure functions with a `RULE_VERSION`, importing the regexes from `src/translate_parents.py`. Output `data/final/legit_tiers.csv` (`text_hash, legit_tier, hl_category, scam_tier, rule_version`; git-ignored).
- `tests/cases/legit_tiers.yaml` + a test: about 30 hand-written examples (genuine HDFC alert → hard; "keep your laptop full recharge buddy" → easy; Vi data-pack ad → promo_gray; KYC-block threat → fraud).
- `src/eval_product.py` (the name in ARCHITECTURE §2 / §11):
  - scores val rows through `app.analyse()` (text head, URL head, OTP floor, `fuse`), keeping per-row text score, link levels, cred hits, final level and the attributed raiser;
  - sweeps the two cut-offs; writes `reports/operating_point.md`;
  - writes `reports/operating_point_rows.csv` (hashes and scores, no text) and `reports/operating_point_fa.csv` (masked text of hard-legit false alarms, for reading; private repo).
- `src/sanity_checks.py`: add `--dump-loso-scores` (per-row out-of-source scores) for the pessimistic bracket, reusing the existing fold code.
- Proposed cut-offs go to `models/thresholds_provisional.json` (split_map SHA-256, rule_version, model bundle id). The app keeps its current cut-offs until you decide.

**Steps:**
1. Ledger: every row gets exactly one tier. Counts by split × language × source × tier × `is_synthetic`, in rows **and** clusters.
2. Tagger spot-check: `reports/legit_tiers_spotcheck.csv`, 50 hard + 50 non-hard val rows. Accept at ≥ 90% agreement. Commit the tagger **before** any score is read (git order is the proof).
3. Hard-legit FPR(t) (Likely, Suspicious+) cluster-weighted, with a 1,000-resample cluster bootstrap and row-level Wilson intervals. Recall on `fraud` scams, flag rate on `promo_gray`, Can't-judge rate. Per hl_category, per language, with links / without links.
4. Apply the §3 selection rule. Show the result next to today's 0.423 / 0.656, with the bootstrap spread of each chosen cut-off.
5. Attribution table plus the top-20 false-alarm texts to read.
6. Bracket at the chosen cut-offs: in-distribution vs LOSO hard-legit FPR.
7. Proxy check: `otp_sms_preview` English transactional rows minus `messages.csv` twins at ≥ 0.6 (`neardup`). Report n_eff by template group, labelled *proxy, provenance unknown*.
8. Internal test report, **once**, behind a `--report-test` flag, after the cut-offs are frozen, never used for picking. The final real test set is untouched (rule 1).

**Checks:**
- assert the selection function receives only `split == "val"`;
- assert the split_map SHA-256 equals the CLAUDE.md value and record it;
- attribution counts sum to the total false alarms;
- at today's cut-offs, the text-level val flags reproduce the `baseline.py` numbers;
- calibration (Platt, Phase 1) is monotone, so it does not change which messages are flagged; the cut-offs are re-expressed in calibrated units when it lands;
- a real-only view (`is_synthetic=False`) is shown, however small.

**Decisions this leaves for you:**
- D5 as amended (targets, precedence, recall floor 0.90, ship gate 10%, Can't-judge ≤ 10%, language cap);
- **D5b:** are brand promos scams?
- **D5c:** feedback button vs principle 6;
- the real-dev sizes (≥ 800 English, ≥ 150 per language) as the D7 collection target.

## Verification of this plan

The plan makes no code changes. Its claims can be checked in the files cited:
- `reports/sanity.md` §1–5 (val / test splits, LOSO);
- `reports/translate_parents.md` and `translate_finalise.md` (preview counts, promo rows, expected Hindi / Kannada val rows);
- `BUGS.md` (cluster structure, URL head FPR);
- `src/baseline.py:42-48` (today's cut-off rules).

Step 1 of §4 turns every [estimate] in §1.3 into an exact count.

---

## Decisions

- **D5:** two targets (Likely scam <= 1%, Suspicious+ <= 5% of hard-legit), counted per independent template, on the final verdict; recall floor 0.90 for Suspicious; ship gate 10%; Can't-judge <= 10% on hard-legit; language cap (text model alone max Suspicious in hi/kn/Hinglish until >= 150 real-dev templates in that language). Targets are design targets until real-dev exists.
- **D5b:** brand promos separated as promo_gray (not scam, not benign); relabel in splits-v2.
- **D5c:** dispute button stores nothing by default; opt-in study/volunteer mode saves masked text + verdict + user label locally.
- **D7 target:** 400+ independent English hard-legit templates, ~150 per language.
