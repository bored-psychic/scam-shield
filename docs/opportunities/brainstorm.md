# Scam Shield: next-feature brainstorm

_Status: draft complete, 2026-10-22 (not yet reviewed by the user). Built from the seven research notes plus 14 web
checks. Jump to "Recommendation (step 5)" for the answer._

## Brief (as understood)

Pick the next feature for Scam Shield after the core detector (MuRIL text head + URL head + link checks + OCR input).
Inputs: the seven research notes in [`research_notes/Scam Shield next feature 2/`](research_notes/Scam%20Shield%20next%20feature%202/) (written earlier on 2026-10-22) plus a small
number of targeted web checks (budget: about 25 fetches) to fill gaps or confirm claims that drive the ranking.

Rules that constrain every idea (from `CLAUDE.md`): never visit a link from a message (rule 8), mask PII (rule 5),
no logging of domains/URLs, keys in env vars only, synthetic data never counts as real, ask before spending credits.

## Progress log

- [x] Step 1: read all seven research notes (internal_audit, delivery_feasibility, india_scam_numbers,
  victim_stories, india_landscape, international_interventions, papers_patents). All seven are unfinished
  drafts (TODO sections), so their numbers are carried over with their own "to verify" flags.
- [x] Step 2: gaps that change the ranking (web checks planned, in priority order):
  - W1 Truecaller Scam Checker (Sept 2026): free? free-text / Indian languages? (decides whether a paste/bot checker is redundant)
  - W2 any Indian forward-to-check WhatsApp/Telegram scam bot launched in 2025-2026
  - W3 TRAI 1600-series: did banks actually move by 2026? (decides whether "bank calls only from 1600" is a safe rule)
  - W4 SEBI `@valid` UPI handle format (official source) (decides whether the payee rule is deterministic)
  - W5 investment / trading scam modus operandi from I4C or police (share via WhatsApp/Telegram groups)
  - W6 evidence that involving a trusted person interrupts scams (beyond news anecdotes)
  - W7 RBI April 2026 paper: any final direction on the trusted person / 1-hour lag by Oct 2026
  - W8 Android restricted settings for sideloaded apps (usage access, overlay) (decides feature 8's feasibility)
  - W9 public investment-scam message data for the text head
  Repo facts checked (no web): no `.apk` rule exists (`entities.py` planned, not built); isolation cues exist in
  `src/shield/messages/tactics.py`; advice is generic per level (`src/shield/core/advice.py`, Suspicious already says
  "ask someone you trust" as plain text, with no button); ARCHITECTURE plans Transactions Nov 30-Dec 11 and Apps
  Dec 14-25, including a collect-request rule.
- [x] Step 3: web checks (results in "Web check results" below)
- [x] Step 4: score and rank candidates
- [x] Step 5: recommendation + first build slice

Web fetches used: 14 / ~25 (10 searches, 3 page fetches, 1 PDF fetch read locally). No Firecrawl credits used.

## Web check results (step 3)

- **W1 Truecaller Scam Checker** (launched in India 28 Sep 2026): free, no account for basic web checks; checks
  numbers, links and messages against Truecaller's detection + community reports; Android app in India, website
  globally; screenshot upload and iOS "planned"; no language list published (older Truecaller Assistant: English,
  Hindi, Hinglish). Reviewers: a "safe" result can be stale for new scams. — [TechCrunch, 27 Sep 2026](https://techcrunch.com/2026/09/27/truecaller-takes-its-scam-intelligence-to-the-open-web-as-it-looks-beyond-caller-id/);
  [TechRepublic](https://www.techrepublic.com/article/news-truecaller-scam-checker-apac-india/) (search summaries).
  => **A free, well-known paste-to-check tool already exists in India**, with ~350M Indian users behind it.
  Our own paste checker (or a bot that only re-hosts it) is a me-too; our edge has to be elsewhere (what happens
  *after* the verdict, coercion/investment scripts, Kannada, privacy: nothing leaves the device).
  TechCrunch full article (fetched 2026-10-22): input is "a suspicious phone number, link, or message"; for a
  message the service **picks out any phone number or link in it**; links are expanded and redirects followed,
  then checked against Truecaller's risk database; related Scamfeed community reports are shown; "no app or
  sign-in required"; no languages, verdict levels, explanations, error rates or data handling stated; free-text
  descriptions not mentioned. => As described, it is a **number / link reputation lookup**, not a reader of the
  message's words. Link-less scripts (digital arrest calls typed out, investment pitches, "pay tax to withdraw",
  task-job offers) are where Scam Shield's text head adds something Truecaller does not claim to do. 80% of our
  val scam messages have no link (225 of 1,152 do); McAfee: ~1 in 5 suspicious social messages have no link.
- **W2 forward-to-check bot in India**: still none found from police / I4C (search 2026-10-22). WhatsApp itself
  rolled out (2026) warnings on suspicious first-time messages and account age for unknown contacts, and banned
  ~9,400 digital-arrest accounts in 2026 (AG to the Supreme Court). Police advisories (Oct 2026) warn of the
  "reply NO to a fake debit alert" trick and of APK e-challans on WhatsApp ("government agencies don't send
  challans or APKs over WhatsApp"). — [Moneylife](https://moneylife.in/article/whatsapp-banned-9400-accounts-used-for-digital-arrest-scams-in-2026-ag-tells-supreme-court/80326.html);
  [Outlook Money, Hyderabad police](https://www.outlookmoney.com/news/whatsapp-scam-hyderabad-police-caution-users-against-replying-no-to-suspicious-messages);
  [The Hitavada, Jan 2026](https://www.thehitavada.com//Encyc/2026/1/20/fake-e-challan-whatsapp-scam-targeting-citizens.html) (search summaries).
- **W3 TRAI 1600-series**: deadlines passed (commercial banks 1 Jan 2026; large NBFCs / payments banks / SFBs
  1 Feb; other NBFCs, co-op banks, RRBs 1 Mar; insurers later). Adoption: ~485 entities / 2,800+ numbers (TRAI,
  Nov 2025); a vendor says 570+ / 3,000+ (Jul 2026). **No official post-deadline compliance report found.** —
  [IANS](https://ianslive.in/trai-orders-mandatory-adoption-of-1600-series-numbers-by-banks-financial-services-insurance-firms--20251119152705);
  [Outlook Business](https://www.outlookbusiness.com/news/trai-sets-firm-deadlines-for-bfsi-entities-to-adopt-1600-series-for-service-transactional-calls).
  => Usable as advice ("genuine bank service calls now come from numbers starting 1600"), **not** as a hard rule
  that calls a 10-digit-mobile caller a scam (compliance unverified; relationship managers call from mobiles).
- **W4 SEBI `@valid` UPI handles**: SEBI circular of 11 Jun 2025 (SEBI/HO/DEPA-II/DEPA-II_SPG/P/CIR/2025/86);
  live 1 Oct 2025; format `<name>.<category>@valid<bank>`, e.g. `abc.brk@validhdfc` (`.brk` brokers, `.mf` mutual
  funds); pay screen shows a thumbs-up in a green triangle. An MSEI circular (Aug 2026) is reported to say SEBI's
  7 Aug 2026 clarification requires investor-facing accounts that receive money from individual investors to be
  linked to an `@valid` UPI ID by 6 Sep 2026. — [SCC Online](https://www.scconline.com/blog/post/2025/10/04/sebi-introduces-verified-upi-handles-and-sebi-check-to-safeguard-investors/);
  [Groww](https://groww.in/blog/what-are-validated-upi-handles-and-sebi-check-tool); [MSEI circular 19545](https://www.msei.in/SX-Content/Circulars/2026/August/Circular-19545.pdf).
  **Verified in the primary text** (MSEI circular MSE/MEM/19545/2026 of 12 Aug 2026, which annexes the SEBI
  circular; read locally with pdftotext): "all investor facing bank accounts (upstreaming accounts) through which
  funds are received from individual/non-institutional investors shall be linked with a '@valid' UPI ID to ensure
  that such accounts are verifiable through SEBI Check", by 6 Sep 2026; SEBI circular §1.3: use by investors is
  optional but "it is mandatory for intermediaries to obtain and make available this structured UPI address";
  §2.1: handle = "@valid" + the bank's name, allocated by NPCI, e.g. "abc.bkr@validhdfc, xyz.mf@validhdfc" (the
  circular spells the broker suffix both `brk` and `bkr`; the full list is its Annexure D); §2.2: the green-triangle
  icon's "absence would caution investors of the risk that they are making payments to unauthorised entities";
  §3.1: `@valid` handles are exclusive to SEBI-registered intermediaries (MCC 6211); §7: old UPI IDs discontinued
  at T+180 days (T = 11 Jun 2025, so about Dec 2025).
  => A **deterministic investment-scam signal** usable as a rule: a message that asks you to pay a trading / IPO /
  stock / "investment platform" account by UPI to an ID whose handle does not start with `@valid` is not paying a
  SEBI-registered broker. Bank-account (NEFT/RTGS) payments remain allowed, so for those the advice is "check the
  account in SEBI Check before paying", not an automatic verdict. Match on the handle prefix only, never on the
  suffix list (the circular itself is inconsistent there).
- **W5 investment-scam playbook** (I4C / MHA advisory, July 2026, as reported): unsolicited WhatsApp / Telegram
  invitations -> fake "VIP stock tips" groups with fake experts or names of real firms -> app installed from a
  private link, not a store -> fake dashboard profits after a small first deposit -> pressure for more -> on
  withdrawal, demands for "taxes, processing fees, or account verification charges"; "Genuine financial
  institutions do not request extra deposits to release or withdraw existing funds". I4C also warned about fake
  investment ads on Instagram / Facebook. — [Outlook Money](https://www.outlookmoney.com/news/i4c-warns-investors-against-fake-whatsapp-stock-tips-fake-trading-apps);
  [The CSR Journal](https://thecsrjournal.in/i4c-warns-against-investment-scams-on-whatsapp-telegram-promising-guaranteed-returns/);
  [Open](https://openthemagazine.com/india/fake-profits-real-losses-the-new-investment-fraud-sweeping-whatsapp-and-telegram-groups)
  (news reports of the advisory; the I4C text itself not found). Matches all five coded INV accounts.
  => Three text-detectable moments: the group invite / stock-tip pitch, "install our app from this link",
  and "pay tax / fee to withdraw" (the last one is where victims are already doubting, so a warning there may land).
- **W6 evidence that a trusted person helps**: **no study tests "talk to someone before paying"** (search
  2026-10-22). FINRA Foundation (905 victims): loneliness is a risk factor, but social engagement or living with
  others did not on their own reduce victimisation; quality of relationships may matter more. Isolation is also a
  tactic scammers impose. — [InvestmentNews on FINRA](https://investmentnews.com/retirement-planning/loneliness-risk-taking-makes-older-americans-prime-fraud-targets-finra-says/259524);
  [Boston College CRR](https://crr.bc.edu/?p=25743) (search summaries).
  => The case for an "ask someone first" button rests on: victim accounts where a friend/relative ended the scam
  (DA-11, DA-12, DA-13, DA-01 after the fact), Singapore 1799 (84% of calls are "is this a scam?"), the AARP peer
  warning-call RCT, Akesson's call-to-action buttons (-81% in a lab), and regulators converging on a trusted person
  (RBI proposal, Singapore CPF Trusted Contact, Truecaller Family). **Plausible, not proven; it is exactly the kind
  of thing the user study can measure.**
- **W7 RBI safeguards**: still no final directions found (only the April 2026 discussion paper: 1-hour cancellable
  lag over Rs 10,000; trusted-person approval over Rs 50,000, mandatory for 70+ and persons with disabilities;
  kill switch; credit caps). — [MediaNama, Apr 2026](https://www.medianama.com/2026/04/223-safeguard-elderly-rbi-suggests-trusted-person-approval-high-value-digital-payments/);
  [Moneylife](https://moneylife.in/article/digital-payment-frauds-under-watch-rbi-proposes-1hour-delay-transaction-caps-and-kill-switch-to-counter-scams/80179.html).
  => A "trusted person" feature anticipates the regulator's direction; good material for the stakeholder talk.
- **W8 Android restricted settings**: Android 15 CDD (as reported by 9to5Google / Android Authority) restricts, for
  sideloaded apps, Accessibility, notification listener, device admin, **display over other apps, usage access**,
  dialer / SMS roles and the SMS permission, until the user opens App info and taps "Allow restricted settings".
  — [9to5Google](https://9to5google.com/2024/09/12/android-15-sideloaded-apps-restrictions/);
  [Android Authority](https://androidauthority.com/android-15-restricted-settings-sideloading-3481098) (official doc not found).
  => Candidate 8 (call + payment-app interrupt) needs exactly the two restricted permissions (usage access to see
  the payment app open, overlay to interrupt) plus phone state. For a 15-20 person study that is a hand-held setup
  per phone; for real users it needs a Play listing (12 testers x 14 days, a policy declaration). Feasible for a
  demo, not for reach before January.
- **Channel share**: MHA Annual Report 2023-24, Q1 2024 cyber-fraud complaints by platform: WhatsApp 43,797,
  Telegram 22,680 (MediaNama: 22,860), Instagram 19,800; no 2025 split found. — [Business Standard](https://www.business-standard.com/technology/tech-news/whatsapp-telegram-instagram-online-scams-mha-report-2024-125010100633_1.html);
  [MediaNama](https://www.medianama.com/2025/01/223-whatsapp-over-43000-cybercrime-complaints-january-march-2024/).
- **W9 investment-scam message data**: no public set of WhatsApp stock-tip / investment-group pitches found.
  Closest: `bolewara/hinglish-scam-text-dataset` (35 Hinglish scam rows, KYC/UPI/lottery/loan/OTP, no stock tips);
  `Shade63/scam-classification-multiclass` (~14k Indian-context rows, contents unchecked). **Surrey NetSys WhatsApp
  junk dataset** (Agarwal et al., WWW 2022; ~2.6M messages from ~5,000 public Indian WhatsApp groups, multilingual):
  by request form only, "non-profit research or education", no sharing beyond the research group, no
  re-identification; the page describes spam/ham labels "for the embeddings", so raw text availability is
  unclear. — [Surrey NetSys](https://netsys.surrey.ac.uk/datasets/whats-app) (read 2026-10-22);
  [HF bolewara](https://huggingface.co/bolewara/hinglish-scam-text-dataset).
  => Investment coverage for the text head needs new data: synthetic templates (never counted as real, rule 4),
  quotes from advisories / news, the Surrey set if granted, and the real-message collection (D7). The
  deterministic rules do not need training data, which is why they should come first.

## The user's three suspicions (reconstructed from the notes; the original brief is not in the repo)

- (a) Victims rarely open a website mid-scam (so a paste-a-link checker misses the big losses).
- (b) Placement beats accuracy: a warning only saves money if it reaches the person at the moment of risk.
- (c) Detection on our data is already high; reach is the bottleneck (local Mac, paste-only, zero users).

## What the evidence so far says (step 1, compressed)

**Where the money is (India).** NCRP reported losses: Rs 2,290 cr (2022) -> 7,465 cr (2023) -> ~22,850 cr (2024)
-> 19,813-22,931 cr (2025; two definitions; MHA via [ThePrint, from MHA data](https://theprint.in/india/cybercrime-saw-24-spike-in-2025-indians-lost-rs-22495-crore-mainly-in-investment-scams/2859930/): Rs 22,495 cr total, investment 76%, digital arrest 9%, sextortion 4%). Other shares below are I4C via The420 (Rs 19,813 cr basis): investment 77%, digital arrest 8%,
credit card 7%, sextortion 4%, e-commerce 3%, app/malware 1%. Share of complaints: investment 35-36%,
credit card 27%, sextortion 19%, e-commerce 10%, digital arrest 6%. RBI (NCRP): transfers > Rs 10,000 are ~45% of
cases but ~98.5% of value; ~92% of value is in frauds > Rs 50,000. Digital-arrest complaints fell
1,23,672 (2024) -> 58,249 (2025) -> 16,377 (H1 2026). Bengaluru police: investment/trading cases 183 (2022) ->
2,648 (2025); task/part-time job 228 -> 2,158; courier/FedEx peaked 2024 then ~0; phishing ~0 in 2026.
=> Money is concentrated in a few large, self-authorised push payments made over days or weeks, mostly
investment/trading and task scams that run in WhatsApp/Telegram groups with a fake app/site.

**How victims are reached (24 coded accounts).** Investment/task: WhatsApp/Telegram group -> fake app or site with
a fake balance -> many transfers over weeks to months -> stopped only when withdrawal is blocked by a "tax" or
"service charge". Digital arrest: call -> Skype/WhatsApp video, isolation orders ("tell no one", "stay in the
room", "delete chats"), transfers often at a branch (RTGS, FD breaks). Saves came from people, not apps: branch
staff (Kochi, Jodhpur, Jaipur, Hyderabad), a friend reached by WhatsApp mid-call (DA-12), a relative (DA-11),
an Instagram post seen during a pause (TASK-03). Nobody in the accounts looked anything up during the scam;
one checked SEBI's site (and the fake matched a real firm).

**What already exists in India.** Google: Pixel-only call Scam Detection (<1% of phones), screen-share + unknown
caller alert pilot (Google Pay, Paytm, Navi), Pixel notification Scam Detection in India (Sept 2026, English only).
Truecaller Scam Checker (Sept 2026: check links/numbers, describe a concern) + Family Protection (Mar 2026, admin
alerted, can end calls). Airtel network link blocking. PhonePe Protect (FRI Very High numbers). Sanchar Saathi
(Chakshu reporting, Trusted Contact Details directory). Kavach startup app (paste-to-check, Bengaluru pilot).
I4C Suspect Registry (search number/UPI/account). SEBI @valid UPI handles + SEBI Check. RBI April 2026 discussion
paper: 1-hour lag on push payments >= Rs 10,000, trusted person for 70+, kill switch (no final rule yet).
**Gap no one fills (per notes):** no Indian "forward a message to check" WhatsApp/Telegram bot; no open tool that
warns when a payment app opens during/after a call; nothing for the family member who notices odd behaviour.

**International lessons.** Measured saves are human or bank-side: Singapore A.S.T.R.O. (police SMS to people
mid-payment, S$267.5m averted in 2025), Taiwan teller "care questions" (NT$11.2bn intercepted 2025), Japan
staff interventions (¥15.3bn, but rate falling 49.8% -> 39.8% as payment moves to the victim's own phone), HK
bank-police upstream interventions ("nearly half" of the 2025 loss fall). Self-check apps get downloads but low
active use (ScamShield 1.61m downloads, ~76k checks/month); 84% of Singapore's 1799 helpline calls are "is this a
scam?". HK: 20-30% proceed through a generic payment-time alert. Japan NPA: "once in contact, anyone can be
deceived", so block contact. Korea: the isolation instructions are the scam's most specific, detectable part.

**What we have (internal audit).** MuRIL text head (internal test F1 0.918, real-only 0.906; nothing measured on
real users' messages), host-only URL head (weakest; AUROC 0.859), link checks, OTP/PIN rules, OCR, FastAPI +
React, local Mac only. Training scam rows are evenly spread over 8 synthetic template categories (digital arrest,
courier, e-challan, job, KYC, lottery, tax, utility); **investment/trading, task, sextortion and loan-app scams
have no category of their own**, yet investment is ~76% of the money (MHA/ThePrint). Only 225 of 1,152 val scam messages have a
link. Open never-cut deliverables: user study (15-20 people), stakeholder conversation, real India dataset.
MuRIL is 950 MB (not phone-sized); TF-IDF head 7 MB / 2 ms.

**Delivery constraints.** Play SMS/Call-log permissions need a listed exception ("anti-smishing" needs a track
record); Accessibility for non-disability apps needs a declaration; Play Protect India blocks sideloaded apps that
ask for SMS / notification-listener / accessibility; new personal Play accounts need 12 testers x 14 days.
Telegram bots are free with no verification. WhatsApp Cloud API: user-initiated chats free inside the 24 h window
(1,000 free service messages per month per number, charged beyond from 1 Oct 2026), business verification needs
GST/Udyam, and Meta's AI-provider ban covers general-purpose assistants (India not on the exempt list; a
scam-check bot is arguably "incidental" AI, unverified). Hosting: HF Docker Spaces now paid; Oracle Always Free
A1 (2 OCPU / 12 GB) is the only free box that fits MuRIL; any hosting changes the privacy statement (D1).
CallScreeningService gets only the number (no audio, no VoIP). VoIP-call detection is a system-wide audio mode,
best effort. Android 15 redacts OTP notifications from untrusted listeners.

**Warning research (papers_patents).** Warnings at the moment work, training does not: Lain et al. 2022 (14,733
staff) email warnings cut dangerous actions ~64-70%, short = detailed; embedded training made things worse.
Ho et al. 2025 (19,789 staff): training -2% at best. Jensen et al. 2024: a bank's mass awareness message had no
measurable effect. Akesson et al. 2023 (15,888, mock bank app): risk-targeted warning + salient buttons ("cancel",
"save for later", "call the bank") cut fraudulent payments 22% -> ~4% (-81%); plain behavioural warnings decayed
with exposure; cost: legit payments -14 pp. Prebunking in India (Jigsaw, N=4,272 field): weak, some items backfired.
(An Alipay field A/B result, Wen et al. 2022, was removed on 2026-10-22: its numbers did not reconcile, and its qualitative
point about generic warnings being dismissed could not be re-verified.)
=> Design rules for any new warning: specific (name the script), at the moment, with an action button that
involves another human; avoid generic awareness content as the main lever.

## Scoring frame ("rupees-saved terms")

Expected rupees saved by a feature ~ (money in the scam types it covers) x (chance it reaches the person
before/while they pay) x (chance it detects the scam) x (chance the warning changes what they do).
Plus project terms: build time before the ~8 Jan freeze (core due ~6 Nov), fit with the never-cut deliverables
(user study, real India dataset, stakeholder talk), privacy rules (rule 5, rule 8, D1 local-first), cost (zero).

## Candidate features (step 1 brainstorm, unranked)

1. **"Ask someone first" button** in every Suspicious / Likely-scam result: one tap opens WhatsApp (or the share
   sheet) with a short pre-written note to a chosen person ("Someone is asking me to pay / says I'm under arrest.
   Call me before I do anything") plus the masked message and the verdict. Breaks the isolation order.
2. **Coercion-script detector + "script spoiler"**: name the script (digital arrest, investment group, task job,
   KYC call) and show the next steps the scammer will take ("next they will ask you to move money to an 'RBI
   verification account'"), the HK 18222 "spoiler" method. Partly exists (tactics.py isolation cues).
3. **Investment / task scam coverage** (76% of money; no training category today): a short "am I in an investment
   scam?" check (joined via WhatsApp/Telegram group? app installed from a link? must pay "tax"/"fee" to withdraw?
   paying a personal UPI/bank account rather than a SEBI `@valid` handle?) plus text-model data for these scripts.
4. **Payee / UPI ID check** (offline string rules): SEBI `@valid` handles for brokers/MFs, personal-looking VPA,
   "pay to receive" QR; deep link to the I4C "Report & Check Suspect" page (user opens it, we never call it).
   Note: NPCI ended P2P collect requests on 1 Oct 2025, so the architecture's planned "collect-request check"
   is mostly obsolete.
5. **Caller check** (call-only scams are invisible today): user types the number and what the caller claimed;
   rules: banks must call from 1600-series numbers (TRAI deadlines Jan-Mar 2026), police/CBI/TRAI never conduct
   video "arrests", international number claiming an Indian agency, etc. Advice: hang up, call the official number.
6. **Forward-to-check bot** (Telegram first; WhatsApp needs business verification and has an AI-provider clause):
   reuses `/api/analyse`; needs hosting (Oracle Always Free) and a new privacy statement (D1). Doubles as the
   opt-in real-message collection channel for the never-cut dataset (D7).
7. **Android share-target app** (no special permissions; on-device TF-IDF 7 MB or calls the hosted API):
   share from WhatsApp/SMS straight into Scam Shield; removes OCR errors.
8. **Android "call + payment app" interrupt** (usage access + overlay + phone state): when a payment/banking app
   opens during or right after a call with an unknown number, show "Is someone on the phone telling you to pay?"
   with "call my person" / "wait 1 hour" buttons. Highest moment-of-risk reach, highest build and policy risk.
9. **Family guardian card**: printable / shareable card in Hindi / Kannada / English with the family member's
   number and three rules ("no agency arrests you on video", "never move money to a 'safe account'", "call me
   first"). Cheap; measurable only in the study.
10. **APK / file rule**: any message offering an `.apk`, "install this app", "wedding invite" file -> at least
    Suspicious with a specific reason. Cheap, high precision (police: genuine invites are never APKs).
11. **Hindi / Kannada advice and UI** (D17): reach for seniors; needs native-speaker review (D15).
12. **"Before you pay" pause page**: a 30-second self-check for anyone about to make a big transfer. Weak reach
    (suspicion a): victims don't open a site mid-scam unless someone sends it to them.

- **NPCI collect requests**: NPCI circular of 29 Jul 2025: "By October 1, 2025, UPI P2P Collect shall not be
  allowed to be processed in UPI"; merchant collect was kept in mid-2025 reports, but a Cashfree developer page says
  P2M collect must also be phased out in favour of intent / QR (undated; unresolved). — [MediaNama](https://www.medianama.com/2025/08/223-npci-p2p-collect-payments-oct-1-what-it-means/);
  [Business Today](https://www.businesstoday.in/amp/personal-finance/banking/story/npci-to-tighten-upi-rules-peer-to-peer-collect-feature-to-end-in-october-489244-2025-08-13);
  [Cashfree docs](https://www.cashfree.com/docs/payments/manage/payment-methods/upi-collect).
  => The planned Transactions "collect-request rule" (ARCHITECTURE §7) targets a mechanism that no longer exists
  for person-to-person payments. The QR decode ("scanning this PAYS Rs X to Y") stays useful: "scan to receive a
  refund" is the trick that replaced collect requests.

Repo facts used for the build slice: `Report` (schema "5", `src/shield/contracts.py`) already has a free-form
`category` and per-level `advice` built by `advice_for(level, category)` (`src/shield/core/advice.py`, max 5 lines),
so category-specific "what happens next" lines need no schema change. The Report carries no copy of the pasted text;
the frontend already holds it, so a share button can be frontend-only.

## Ranking (step 4)

Ratings are my judgement from the evidence above, not measurements. "Money" = the 2025 NCRP share of reported
losses for the scam types the feature addresses (investment 76%, digital arrest 9% per MHA/ThePrint; credit card 7%, sextortion 4%,
e-commerce 3%, app/malware 1%; I4C via The420 / ThePrint). Whether task / part-time-job scams sit inside
"investment" in that split is not stated.

| Rank | Feature | Money it addresses | Reach at the moment of risk | Will the warning change behaviour? | Build before the study | Project fit | Call |
|---|---|---|---|---|---|---|---|
| 1 | **Investment & task-scam check**: rules (pay-to-withdraw, non-`@valid` UPI for trading, app from a private link) + "what happens next" lines | ~76% (+ task scams) | Same paste path, but it lands where investment victims do pause: the group invite, and the fee demand at withdrawal (4 of 5 coded investment accounts ended at a "tax" / "service charge" / "loan" demand: Rs 42.96 lakh, Rs 1.33 cr, Rs 50 lakh) | Specific, names the trick (Wen et al.: a specific warning lowered the fraud case rate, see [Wen et al. 2022, IJERPH](https://www.mdpi.com/1660-4601/19/14/8294)); SEBI Check gives an official yes/no | ~1 week for rules + wording; text-model data later | New category for the India dataset; study stimuli; SEBI / police talking points | **Build (main)** |
| 2 | **"Ask someone first" button** on Suspicious / Likely scam | All types; strongest for coercion (digital arrest 8%) and older users | Inherits the paste path; also gives a family member a setup role | Plausible, unproven: saves in the victim accounts came from a friend / relative / branch staff; 1799's 84% "is this a scam?" calls; AARP peer-call RCT; call-to-action buttons -81% in a lab | 2-4 days, frontend only | Directly measurable in the user study; matches RBI's trusted-person proposal | **Build first (small)** |
| 3 | **APK / app-install rule** | 1% nationally (Telangana alone: 2,188 APK cases, Rs 779 cr, Jan-Jul 2025) | Paste path | Deterministic; police wording available ("genuine invites are never APKs") | ~1 day | Seeds the Apps module | **Build (quick win)** |
| 4 | Script spoilers for digital arrest / KYC calls (same machinery as 1) | 8% + part of 7% | Low mid-call (suspicion a), better for family and after the call | HK 18222 used "spoilers" to stop 679 scams in progress (2017-20) | Wording only | Study stimuli | **Build with 1** |
| 5 | Forward-to-check bot (Telegram first) | All | Better than a website: inside the chat app | Same as the checker | 1-2 weeks + D1 hosting + `net.py` allowlist + new privacy statement | Could be the D7 intake | **Later, after D1** |
| 6 | Caller check (number + what they said) | 8% + part of 7% | Low: needs a lookup during or after a call | 1600-series compliance unverified, so advice only | 3-5 days | Weak | **Fold the 1600 line into advice; skip the module** |
| 7 | Android share-target app | All | Small gain over paste; removes OCR errors | Same as checker | 1-2 weeks (Kotlin, distribution) | Weak before January | **Later** |
| 8 | Android "call + payment app" interrupt | Own-phone payments during a call (part of 8% + 7%); not investment, not branch RTGS / cheques | Highest of all | Google pilots the same idea with GPay / Paytm / Navi; no outcome data | 3-5 weeks + restricted settings + Play policy | Demo only | **Future work (write it up)** |
| 9 | Hindi / Kannada advice and UI | Reach for older users; Karnataka is #2 by losses (Rs 2,413 cr, 2025) | — | Needs native review (D15 / D17) | Wording + review | Kannada is "cut first" in the README | **Fold into 1-2 after review** |
| 10 | "Before you pay" page | — | Low on its own | — | — | — | **Fold into 2's message** |
| 11 | Planned collect-request rule (Transactions) | — | Mechanism ended for P2P on 1 Oct 2025 | — | — | — | **Drop; keep QR decode** |

Not worth the next weeks (from the audit): retraining the URL head (links are in only 20% of val scams, and
Truecaller / Airtel already cover link reputation), more theme / animation work, the dormant sender rule.

## Recommendation (step 5)

**Next feature: an investment & task-scam check whose warnings end in an "Ask someone first" button.**
Build it as three small pieces in this order, all inside the existing paste / screenshot flow, with no new
permissions, no hosting and no outbound calls:

1. **"Ask someone first" button** (2-4 days, frontend only; target 29 Oct). Shown on Suspicious and Likely scam.
   One tap opens WhatsApp (`https://wa.me/?text=...` to pick a contact, or `wa.me/<number>` if a person is saved),
   or `tel:` / `sms:` links. Pre-written note: the level, the top reason, and "Please call me before I pay or share
   anything." The saved person's number stays in the phone's browser storage only (a per-viewer convenience; it is
   never sent to the API). Use plain links, not `navigator.share`: the Web Share API needs HTTPS and the LAN demo is
   plain HTTP. Rule 8 is not touched: the user, not the app, opens WhatsApp.
2. **Three new floor rules** (about 1 week; target the 6 Nov core date). Like the OTP rule they can only raise a
   verdict to at least Suspicious, English + Hinglish only (Hindi / Kannada forms may explain but never force):
   - **R3 pay-to-withdraw**: a fee / tax / charge / deposit word near withdraw / release / unlock / unfreeze your
     funds or profit. Reason: "Asks you to pay to get your own money out. Real brokers and banks deduct charges;
     they never ask for a fresh deposit to release funds" (I4C advisory wording). Watch false alarms on genuine
     TDS / exit-load notices.
   - **R4 trading payment to a non-`@valid` UPI ID**: investment context (stock, IPO, trading, demat, VIP tips,
     returns) plus a UPI ID whose handle does not start with `valid`. Reason: "SEBI-registered brokers and mutual
     funds collect UPI payments only through @valid IDs (SEBI circular, 11 Jun 2025)". For bank-account payments,
     advice only: "check the account in SEBI Check first". Read the handle from the raw text in memory; nothing is
     stored (rule 5).
   - **R5 app from a message**: an `.apk` file name, or "install / download the app" with a non-store link.
     Reason: "Apps sent in a message or from a link can take over your phone. Banks, police and RTO never send apps
     on WhatsApp."
   Each rule gets the R2 treatment: val counts (fires on how many scam / benign rows, verdicts changed), fixtures in
   `tests/tricky_inputs.py`, and new demo messages.
3. **"What usually happens next" lines** per category (investment, task job, digital arrest, KYC call), added by
   `advice_for()` when a rule or tactic sets `Report.category`. Example for investment: "Next they show big profits,
   then ask for a 'tax' or 'fee' before you can withdraw. That fee is the scam."

**Why this one.** It aims at where the money is (investment ~76% of 2025 losses, MHA via ThePrint), at the moment investment victims
already doubt (the withdrawal fee), with the kind of warning that has field evidence (specific, naming the trick),
and it ends in the one action that ended scams in the victim accounts (another person). It also fills the gap
Truecaller's free checker leaves: as described, Truecaller looks up the numbers and links in a message, while these
scripts often have neither. Everything is testable in the never-cut user study before the January freeze.

**What it will not do.** It does not reach anyone who doesn't think to paste (suspicion c still holds: reach is a
D1 hosting decision, not a feature). It barely helps a victim already on a coercive video call (suspicion a). The
rules are unmeasured on real messages; the text head still has no investment training data, so its own score on
these scripts is unknown until the D7 collection or a splits-v3 rebuild adds data (rule 10: after the study, not
before).

**How the study can measure it.** Add 4-6 stimuli (investment invite, pay-to-withdraw, task job, APK "wedding
invite", digital-arrest script) next to the existing ones; record spotting accuracy with and without explanations
(the planned comparison) and whether participants would press "Ask someone first" (and who they would pick).

## Open questions for the user

1. Should the "Ask someone first" note include the pasted message text by default, or only the verdict and reason?
   (The message may contain the user's own account numbers or names.)
2. Request the Surrey NetSys WhatsApp junk dataset under its education terms, as a possible source of real
   investment-group spam? (Raw-text availability is unclear from the page.)
3. Stakeholder conversation: the RBI trusted-person proposal and the SEBI `@valid` rule are concrete topics for a
   bank branch or the Karnataka CID cyber cell.
4. The original brief and its three suspicions are reconstructed from the notes; correct them if they differ.

If approved, the next step is a decision record (D28) in `docs/decisions/` with a Status header, not code.

> **Update 2026-10-23:** the "Ask someone first" button (items above) was built on 2026-10-22 and **dropped by the user on 2026-10-23**; it is removed from the app. Do not re-add it. The app keeps only "Get help" (helpline + report on Chakshu), see `frontend/CLAUDE.md`.
