# Multi-input checks: Payment / UPI, App / APK, Email and a tabbed input (design)

**Status: APPROVED 2026-10-30 with changes (decision D29 in `docs/decisions/README.md`; the changes are listed in section 11). Design
only so far: no product code was written, and no data, model, split, threshold or frozen file was touched.** Model / effort for the design:
Opus, high. Approval starts the build in the order of section 8.4 (W1, then W5); it does not run any measurement by itself.

Rule ids in this note: **UP** = payments / UPI, **AP** = apps / APK, **EM** = email. Test ids: **PT** (payments), **AT** (apps), **ET** (email),
**UT** (UI), **CT** (contract), **ST** (safety). None of these collide with existing ids (R1-R10, A1-A12, P1 / P2, C1-C3, G1, D-series).

---

## 0. In one screen

1. **One router, one Report, one result page.** Every input kind ends in the existing `Report` contract (bumped to schema "6": two new fields,
   `input` and `details`) and the existing result page (verdict + meter + radar, Why, What to do, helpline row). Links found anywhere (email body,
   a QR's `url` field, later an APK's strings) go through the existing link ladder. No new network endpoint; `net.py` is unchanged.
2. **Payments / UPI** (`src/shield/transactions/`): rules only, no model. Inputs: a UPI ID, a payment-request text (typed, pasted or read from a
   screenshot), a QR decoded locally, and "someone sent me a payment screenshot" (always Can't judge, nothing uploaded). Three new **message hooks**
   join the message engine: scan-to-receive, approve-to-receive, credited-by-mistake (Suspicious, like R2). Core rule: entering a UPI PIN, scanning a
   QR or approving a request never receives money.
3. **Apps / APK** (`src/shield/apps/`): name / package lookup against an **official catalog that Prajval fills via adb** (empty catalog = those
   rules stay off), a no-upload questionnaire ("how did you get the file?"), and static APK analysis (manifest, permissions, components, signing
   certificate) in a **short-lived child process** with a timeout, byte budgets and a memory watchdog. Never installed, run or emulated.
4. **Email**: subject + body through the existing message engine, plus sender, header (read-only, no DNS) and attachment-name rules. Long-email
   windowing is designed and pre-registered, but chosen only on splits-v3 val, after Nov 6.
5. **Tabs**: Message / Link / Email / Payment-UPI / App-APK / Screenshot, a scrollable tab row on phones; the Message tab routes a bare link,
   UPI ID or `upi://` string with a notice.
6. **Cut-line:** MUST = contract v6 + tabs + Link tab + payment text checks + payment proof + message hooks (val-gated, merged before the 5 Nov
   real-test run, otherwise shipped OFF) + app lookup and questionnaire + email-lite + docs (~36 h). SHOULD, in this order = NPCI handle list,
   email headers, APK upload, QR decode, and the fresh-session review of the upload code (~22.5 h). LATER = windowing, embedded APK links, UPI
   IDs inside messages, Hindi / Kannada copy, Bharat QR (~19 h).
7. **Still open with Prajval** (section 9): the free-mail list (D29.13, shown for review), the cybercrime.gov.in "Check suspect" page URL, and
   the adb catalog values (later; 6 apps first, from family phones). The 14 sub-decisions are approved (section 11).

---

## 1. What exists today: built vs planned

Read for this note (2026-10-30): `CLAUDE.md`, `docs/ARCHITECTURE.md`, `docs/decisions/README.md`, `BUGS.md`, `docs/plans/investment_scams.md`,
`src/shield/messages/invest_rules.py`, `src/shield/api/main.py`, `src/shield/api/upload.py`, `src/shield/core/{router,report,advice,risk,verdict,net}.py`,
`src/shield/contracts.py`, `src/shield/config.py`, `src/shield/messages/{rules,tactics}.py`, `src/shield/links/lookalike.py`, `src/shield/ocr/reader.py`,
`src/textprep.py`, `src/pii.py`, `src/build_apps.py`, `frontend/src/{App,api}.tsx|ts`, `frontend/src/components/{Result,VerdictPanel,WhyPanel,WhatToDo,MessagePanel,LinkPanel,WebsiteDetails,PasteBox,Checking}.tsx`,
`frontend/src/lib/levels.ts`, `frontend/src/types/report.ts`, `docs/plans/splits_v3.md` section 5, the module `CLAUDE.md` files.

| Area | Built (in the app today) | Planned only / gap |
|---|---|---|
| Messages | MuRIL head (D27) with TF-IDF fallback; OTP / PIN / CVV rule, PIN-to-receive R2, investment A1-A12 (template for rule modules: a `RULES` table of code, evidence id, function, floor, radar tag, title), tactic tags, D11 folded view, D5 language cap, sender rule (dormant) | long texts read head-only (first 128 tokens of `model_text`) |
| Links | host-only URL model capped at Suspicious (C2), offline + live evidence ladder R1-R10 / P1-P2 through `net.py`, gambling G1, shortener expansion on a button | nothing new needed |
| Screenshots | `/api/ocr`: Tesseract over a pipe, image in memory (`upload.read_part`, hard cap, no temp file) | no QR decoding |
| Payments / UPI | R2 and the `payment` tactic (collect request, scan the QR) only inside messages; `pii.UPI_HANDLES` (80 handles) used **for masking only** | **no `transactions/` code or data** (ARCHITECTURE §7). `pii.UPI_HANDLES` has **no recorded source or date** (checked in `pii.py` and `reports/splits_v2.md`), so it cannot serve as the fact list |
| Apps / APK | `data/final/apps.csv` (7,299 permission sets from `android_malware_hf`, built by `src/build_apps.py` in early research; not used by the app) | **no `apps/` code, no catalog, no APK parsing** (ARCHITECTURE §7) |
| Email | none: an email pasted into the message box is analysed as a message | no sender, header or attachment checks |
| Contract | Report schema "5"; `Module` already lists `transactions` and `apps`; `Fact` rows exist for links (`LinkInfo`) | no input kind, no non-link fact sheet |
| Frontend | one input (paste box + screenshot button), one result page; copy says "message" in several places | no tabs |

---

## 2. Shared design

### 2.1 Input kinds and routing

| `Report.input` | Comes from | Engine | Base level when no rule fires |
|---|---|---|---|
| `message` | Message tab, Screenshot tab (OCR text the user confirmed) | `router.analyse` (unchanged + the three UP hooks) | as today (model decides) |
| `link` | Link tab; a bare link in the Message tab | `router.analyse` on the link alone (same engine as today's bare link) | as today |
| `email` | Email tab | `router.analyse(subject + "\n\n" + body, email=EmailMeta)` | as today |
| `upi_id` | Payment tab; a bare UPI ID in the Message tab | `transactions.check` (rules only) | **Can't judge** (D29.2) |
| `payment_request` | Payment tab (request text, typed / pasted / OCR) | `transactions.check` (rules only, plus R2 and the OTP rule) | **Can't judge**; **No warning signs found** if the user says they started it (UP15) |
| `qr` | Payment or Screenshot tab (image decoded locally); a `upi://` string in the Message tab | `transactions.check` | **Can't judge** |
| `payment_proof` | Payment tab, "a screenshot of a payment" | fixed answer, no content read | **Can't judge** always (UP19) |
| `app` | App tab: a name, a package name or a Play Store link (the `id` parameter is read as a string; nothing is fetched) | `apps.lookup` | Can't judge; **No warning signs found** for a catalog package (AP12) |
| `apk` | App tab: an APK file, or the no-upload questionnaire | `apps.check_apk` / `apps.check_context` | **Can't judge** (AP16); **No warning signs found** for a catalog match (AP1) |

**Routing from the Message tab** (`shield/core/intake.py`, `classify(text)`), only for inputs the message engine already calls Can't judge
(fewer than `router.MIN_PROSE_WORDS` = 3 prose words): a single link -> `link`; a single UPI ID -> `upi_id`; a `upi://` string -> `qr`. A
request-shaped text (`... is requesting Rs ...`) is **not** routed from the Message tab: `eval_real.py` scores `router.analyse`, so routing a
message that the real test set could contain would make the shipped app differ from what was measured (rule 12). The Payment tab runs the
payment-request rules on such text.

### 2.2 Report contract, schema "6"

Two optional fields on `Report`, `extra="forbid"` stays, so the version bumps (a v5 reader would reject them):

```python
InputKind = Literal["message", "link", "email", "upi_id", "payment_request", "qr", "payment_proof", "app", "apk"]

class Details(_Strict):            # a fact sheet for inputs that are not links; rendered like LinkInfo's facts
    kind: Literal["payment", "app", "email"]
    title: str = Field(min_length=1, max_length=40)       # "Payment details", "App details", "Sender details"
    facts: list[Fact] = []                                 # the existing Fact model (key, label, value, effect, why, status, source, sent)
    note: str | None = None                                # e.g. "The file was read on this device. It was not installed or run, and it is gone."

Report.input: InputKind | None = None      # None on child (link) Reports
Report.details: Details | None = None
```

Validator: `module` follows `input` (`messages` for message / link / email; `transactions` for upi_id / payment_request / qr / payment_proof;
`apps` for app / apk) and `details.kind` follows `module`. Evidence ids stay dotted (`rule.upi_refund_word`, `rule.apk_sms_read`, `rule.email_freemail_brand`),
module `transactions` / `apps` / `messages`. `risk_score` keeps D24: inputs without a text score get the band floor (Likely 70, Suspicious 30,
No warning signs 0) and Can't judge none, the same as a bare link today (see the clash list, 6.5). `frontend/src/types/report.ts`,
`SCHEMA_VERSION`, `tests/test_contracts.py`, the API tests and `frontend/scripts/dump_fixture.py` move together.

### 2.3 Reuse: what the new engines use instead of writing their own

| Need | Existing code reused | Change |
|---|---|---|
| Levels, labels, fusion | `core/verdict.py` (`LEVELS`, `fuse`), `contracts.Level`, `LEVEL_RANK` | none |
| Reasons (top 3, warnings only, rules -> links -> tactics -> model) | `core/report.to_report` ordering | extract `reasons_from(evidence, children, level)`; `to_report` calls it (no output change, locked by contract A1-A17 on the 363 inputs and the demo set) |
| Advice | `core/advice.advice_for` | `input=` adds the per-input lines (2.4); `MAX_ADVICE` 5 kept |
| Meter | `core/risk.risk_score` | none |
| Link checks inside any input | the link block of `router.analyse` (assess_link, URL model, gambling, `reputation.assess`, C2 cap, live checks) | extract `assess_links(urls, url_model, live, expand, offline_only)`; `analyse` calls it unchanged; APK strings use `offline_only=True` |
| Brand / name vocabulary | `links/brands_india.json` tokens, `exact_brands.json` labels, `lookalike.homograph` / `lookalike` / `exact_brand` for sender domains | a small government-body list in `shield/core/claims.py` |
| Negation, receive cues, sentence windows | `rules._negated`, `rules._RECEIVE`, `rules._near` (R2) | imported, not copied |
| Folded view | `core/fold.fold` and `FoldMap.span` | the UP hooks read the folded text like every other rule |
| Hard-risk list (blocks P1 / P2 and the dormant sender softening) | `sender_rule.hard_risks` | add `payment_rule` (UP16-UP18) and `email_rule` (EM2-EM11 hits) |
| Uploads | `api/upload.read_part` (in memory, hard cap) | return the part's file name too (memory only, never logged) |
| OCR | `ocr/reader.read_image` | none; the Screenshot tab tries a QR first (SHOULD) |
| Result page | `Result`, `VerdictPanel`, `RiskMeter`, `Radar`, `WhyPanel`, `WhatToDo`, `Helpline`, `LinkPanel`, `Tip`, `Checking` | per-input copy; `WebsiteDetails` generalised into `DetailsPanel` (renders `LinkInfo.facts` and `Report.details.facts`) |

### 2.4 Levels: raise-only, and where Can't judge is used

- Every new rule is a **floor** (raise-only), applied like the investment rules: `level = max(level, floor)`, where the base Can't judge
  (`None` in the router) counts as below Suspicious, exactly as `router.analyse` floors a Can't-judge message today. No rule lowers a level.
- **Flagged, approved 2026-10-30 (D29.4; not a lowering, but a positive fact that decides which rules run):** AP1, a verified catalog match, makes an APK's
  base level No warning signs found and skips AP4-AP11 (D29.4). Reason in 4.5.
- **Flagged, approved with the plan 2026-10-30:** UP20 turns a receipt-shaped *screenshot* from No warning signs found into Can't judge; it never touches a warning level.
  Can't judge has no rank (`LEVEL_RANK`), so this follows the existing "only unjudgeable links -> Can't judge" logic rather than raising.
- D5 language cap: unchanged. It lowers only a Likely scam that the text head alone produced; rule floors (old and new) are not capped.
- Existing message rules (OTP / PIN / CVV, R2, A1-A12, gambling G1, the link ladder): unchanged. The UP hooks are new rules beside them.
- Per-input advice (frontend shows the first as a card, matched by exact string, like the SEBI card):
  - payments, every level: **"Before you pay, check the registered name your payment app shows. Receiving money never needs your UPI PIN, a QR scan or an approved request."**
  - payment proof: "A screenshot cannot prove a payment. Check your own bank or UPI app before you hand over anything." / "Do not send back 'extra' money someone says they sent. Ask your bank instead."
  - apps, every level: **"Install apps only from the Play Store, and check the publisher's name before you install."**; on a warning: "Do not install this file. If you already did, disconnect from the internet, uninstall it and call your bank and 1930."
  - email, on a warning: "Do not open attachments or links you were not expecting. Contact the company through its official website or app."

### 2.5 Network and privacy (rule 8, ARCHITECTURE §5.4)

- **No new network endpoint.** `net.py`'s allowlists (`CHECK_HOSTS`, RDAP bootstrap hosts, shorteners on the button, `UPDATE_HOSTS` for
  `update_link_lists.py` only) are unchanged. UPI IDs, package names, certificates, email addresses and headers never leave the machine; there is
  no live lookup of any of them. URLs found in an email body or a QR go through the existing ladder (domain-only live checks on the second call);
  URLs found inside an APK get the offline checks only. A Play Store link is parsed for its `id` parameter and never requested.
- **Uploads are never stored.** Images and APKs are read by `upload.read_part` into memory (hard cap, no Starlette temp file), passed to a parse
  worker over a pipe (4.2), and dropped when the request ends. Nothing is written to disk, logged or echoed in an error message (every handler
  keeps the `from None` pattern of `/api/analyse`). The file name of an upload is used in memory for AP11 and is never logged or returned.
- **No temp files from libraries:** the parse worker refuses file writes, `tempfile` and sockets (4.2); tests ST01-ST10 check all of it.

### 2.6 Fact provenance (fail closed)

Three reference files hold external facts. Each entry carries `source` (URL or method), `retrieved` (date) and `by`. A loader refuses an entry
without them; a missing or empty file switches its rules off and the Report says "not checked" (never a silent pass).

| File (tracked) | Holds | Filled by | Rules that need it |
|---|---|---|---|
| `src/shield/transactions/npci_handles.json` | UPI handles with the app / bank behind each, from NPCI's published list | Prajval (source URL + date), or a one-off plain fetch of the page Prajval names | UP1, UP2 and the handle row of the fact sheet |
| `src/shield/apps/catalog.json` | official apps: name, publisher, package, signing-certificate SHA-256 list | Prajval via adb (4.6) + the Play Store listing | AP1, AP2, AP3, AP12 |
| `src/shield/email/freemail.json` | free e-mail provider domains | hand list in this note, reviewed by Prajval | EM2, EM5 |

---

## 3. Transactions / UPI engine (`src/shield/transactions/`)

### 3.1 Files

`vpa.py` (UPI ID grammar, local-part tokens, handle lookup), `upi_uri.py` (`upi://pay` / `upi://mandate` parser), `rules.py` (UP1-UP15,
UP19-UP20; a `RULES` table shaped like `invest_rules.RULES`), `text_rules.py` (the message hooks UP16-UP18, UP21), `check.py` (entry points
`check_text(text, started)`, `check_qr(payload)`, `payment_proof()`), `npci_handles.json`, `CLAUDE.md`. Tests `tests/test_payments.py`.

### 3.2 Parsing

- **UPI ID:** `local@handle`, case-insensitive; local `[A-Za-z0-9][A-Za-z0-9._-]{1,63}`, handle `[A-Za-z][A-Za-z0-9]{1,31}` with no dot (a dot
  after `@` makes it an e-mail address, as in `pii.py`). Read on the folded view (D11), so `ѕbi.kyc@ybl` (Cyrillic s) or a zero-width space is
  seen as `sbi.kyc@ybl`, and the quote maps back to the user's characters. Local-part tokens: split on `. _ -` and letter / digit boundaries;
  a token wholly made of lexicon words is segmented (`amazonrefund` -> `amazon` + `refund`); an impersonation word of 5+ letters also counts at
  the start or end of a longer token (`itrefund` -> `refund`); shorter words count only as whole tokens (`skincare` is not `care`).
- **Handle look-alike fold:** `0 -> o`, `1 -> l / i`, `5 -> s`, `rn -> m`, `vv -> w`, upper-case `I -> l`, then edit distance.
- **`upi://` URI** (from a QR or pasted): scheme `upi`, host `pay` or `mandate`, `urllib.parse.parse_qs` with `strict_parsing`, at most 32
  parameters of at most 512 characters each. Fields read: `pa` (payee ID), `pn` (payee name), `am` (amount), `tn` (note), `cu` (currency),
  `mc`, `tr`, `url`. Unknown parameters are shown raw and never interpreted. `pn` and `tn` are free text written by whoever made the QR.
- **QR images** (SHOULD, W10): decoded locally by `zxing-cpp` inside the parse worker (4.2), QR formats only; several codes in one image are each
  reported. Bharat QR / EMVCo merchant payloads (`000201...`) are not parsed (LATER, needs the official spec): such a QR is Can't judge.
- **Payment-request text:** request words (`is requesting`, `has requested`, `collect request`, `payment request`, `request from`) or app button
  words (`Pay` / `Decline` / `Approve` / `Reject`) near an amount. Used only in the Payment tab.
- **Money-in lexicon** (`MONEY_IN`): R2's `_RECEIVE` plus prize, reward, lottery, lucky draw, won, winning, bonus, gift, KYC, verification,
  verify, unblock, reactivate, "get your money back", "return your money", and the Hinglish `paise milenge`, `wapas milenge` (unchecked).
- **Impersonation words** (`ID_WORDS`, whole tokens): refund, cashback, reward(s), prize, lottery, lucky, kyc, ekyc, verify, verification,
  support, customercare, care, helpdesk, helpline, complaint, unblock, reactivate, claim.
- **Name tokens, three lists** (`shield/core/claims.py`), because a payment app's or aggregator's name is in ordinary shop IDs
  (`paytmqr...@paytm`, `bharatpe...@...`) and must not raise anything by itself:
  - `GOVT`: police, cyber, court, rbi, npci, uidai, aadhaar, aadhar, incometax, itr, gst, epfo, rto, challan, parivahan, customs, traffic, govt,
    gov, pmkisan.
  - `BRANDS`: `brands_india.json` tokens of 3+ letters (banks, couriers, shops, telecoms), minus `PAY_APPS`.
  - `PAY_APPS`: paytm, phonepe, gpay, googlepay, bhim, bharatpe, razorpay, payu, cashfree, mobikwik, freecharge, cred, amazonpay, pinelabs,
    instamojo (names, reviewed by Prajval, section 9).

### 3.3 Rule table

Levels: L = Likely scam, S = Suspicious, NW = No warning signs found, CJ = Can't judge, disp = a fact or evidence row with no level.

| ID | Condition | Level | User-facing reason (formal) | Tests |
|---|---|---|---|---|
| UP1 | Handle not on the NPCI list but equal to a listed handle after the look-alike fold, or within edit distance 1 of one (handles of 4+ letters) | S | "The part after @ looks like @{listed}, but it is not a real UPI handle. Check that it was typed correctly." | PT05-PT08 (genuine PT09) |
| UP2 | Handle not on the list and not UP1; or the list is not loaded | disp | "Not on NPCI's list of UPI handles (list of {date}). It may be new or mistyped." / "Handle list not loaded: not checked." | PT10, PT11 |
| UP3 | A local-part token is an impersonation word (`ID_WORDS`) | S | "The UPI ID itself uses the word '{word}'. Refunds, prizes and KYC never require you to pay to an ID." | PT12-PT16 (genuine PT17) |
| UP4 | A local-part token is in `GOVT` | S | "The ID uses the name '{body}', but a name inside a UPI ID proves nothing about who owns it. Pay government fees only through the official website or app." | PT20-PT22 |
| UP4b | A local-part token is in `BRANDS` | disp (caution evidence; counts for UP5) | "The ID uses the name '{brand}'. A name inside a UPI ID proves nothing about who owns it." | PT18, PT19, PT23 (genuine PT24: a `PAY_APPS` shop ID gets nothing) |
| UP5 | Two or more of UP1, UP3, UP4, UP4b, UP9, UP10 on one payment (the payments version of the link ladder's R9), or UP3 together with a `PAY_APPS` token (`paytm.kyc@ybl`) | L | "Several signs together: {first two reasons, shortened}." | PT25-PT27, PT39 |
| UP6 | The local part is a 10-digit Indian mobile number | disp | "This ID is linked to a phone number, so it belongs to a person's account." | PT28 |
| UP7 | A QR that holds no payment: a URL goes to the link ladder (as the Link tab), plain text to the message engine, anything else (Wi-Fi, contact card, Bharat QR) is CJ | as engine / CJ | "This QR code does not hold a UPI payment." (+ the engine's own reasons) | PT29-PT31 |
| UP8 | `upi://pay` with a prefilled `am` and a money-in word in `tn` or `pn` | L | "This QR code makes you pay Rs {am}, but its note says '{tn}'. Scanning a QR never receives money." | PT32, PT33, PT35 (genuine PT36, PT37) |
| UP9 | As UP8 without a prefilled amount | S | "This QR code makes you pay, but its note says '{tn}'. Scanning a QR never receives money." | PT34 |
| UP10 | `pn` (or a request's displayed name) contains a `GOVT` or `BRANDS` token that the UPI ID's local part does not contain | S | "The name says '{pn}', but the UPI ID ({id}) is not that organisation's. Your payment app shows the registered name: check it before you pay." | PT38, PT39 (genuine PT40, PT41) |
| UP11 | Malformed payment QR: no `pa`, two `pa`, `pa` not a UPI ID, `am` not a number, `cu` not INR | CJ | "This payment QR is malformed. A payment app may refuse it or show different details." | PT42, PT43 |
| UP12 | A `url` parameter in the QR | link ladder | (the link's own reasons; the link is a child Report) | PT44 |
| UP13 | A payment request whose text has a money-in promise (`MONEY_IN`, or R2's receive cue) | L | "Approving a payment request sends money from your account. It never receives money." | PT01-PT04 (genuine PT45) |
| UP14 | The user answered "No" to "Did you start this payment?" | S | "You did not start this request. Decline it: approving sends money from your account." | PT46 |
| UP15 | The user answered "Yes", and **no other rule fired** on the input: no UP rule, no R2 (PIN to receive), no OTP / PIN / CVV rule, no investment rule, no link rated Suspicious or higher | NW (base) | "You started this request. Nothing else in it looks wrong." | PT47 (other rule fired: PT47b) |
| UP16 | **Message hook.** An instruction to scan a QR / code with a receive cue in the same sentence or within 12 words (R2's `_near`, R2's `_negated`) | S | "Asks you to scan a QR code to receive money (scanning a QR only ever pays)." | PT48-PT50 (genuine PT51, negated PT52) |
| UP17 | **Message hook.** approve / accept / authorise (a, the, this) (collect / payment / UPI) request + a receive cue, same window | S | "Asks you to approve a payment request to receive money (approving only ever pays)." | PT53-PT55 (genuine PT56) |
| UP18 | **Message hook.** A mistake cue (by mistake, wrongly, accidentally, galti se, wrong number / account / UPI ID) + a credit cue (sent, credited, transferred, received) + a return ask (return, send back, refund it, reverse, wapas bhej) in one message, not negated | S | "Says money was sent to you by mistake and asks you to send it back. Check your own bank app first; if money did arrive, ask your bank to reverse it." | PT57-PT60 (genuine PT61; documented false positive PT62) |
| UP19 | Input kind `payment_proof` | CJ (always) | "A screenshot cannot prove a payment." | PT63, PT64 |
| UP20 | **SHOULD.** OCR text from the Screenshot tab that reads like a payment-app success screen (Payment successful / Paid to / UPI transaction ID / UTR + an amount), and no warning found | CJ (from NW only) | "This looks like a payment screenshot, and a screenshot cannot prove a payment." | PT65-PT67 |
| UP21 | **LATER, message hook.** UPI IDs found inside a message get UP1, UP3, UP4, UP4b, UP5 | as the rule | as the rule, prefixed "In the message: " | PT68 (ID parsing: PT69, PT70) |

UP13-UP15 and UP19 implement the core rule for requests; R2 (unchanged) covers "enter your PIN to receive"; UP8, UP9 and UP16 cover QRs.
UP16-UP18 count as the hard-risk signal `payment_rule` (P1 / P2 positives and the dormant sender softening cannot soften them, like A1-A12),
and the safety-advice cap (off) lists them as blockers. They are switched by `config.PAYMENT_HOOKS` (`SHIELD_PAYMENT_HOOKS=0`), so a failed
val gate (8.3) ships them off without a code change.

### 3.4 What the payments engine cannot know, and the wording

It **cannot know**: (1) who owns a UPI ID: the registered name is held by the payee's bank and shown only inside a payment app at payment time;
we never query it, because there is no public lookup and it would send the ID off the device; (2) whether an ID has fraud reports: there is no
official offline list we can use; cybercrime.gov.in's "Report & Check Suspect -> Check suspect" page is **linked** from the help row of UPI
results (approved 2026-10-30, section 11), never queried, and the ID is never sent; (3) whether a shop's
QR was replaced by a sticker; (4) whether money actually arrived: only the user's own bank app or statement shows that; (5) whether the user
started a request, unless they say so; (6) whether the name in a QR (`pn`) is true: whoever made the QR typed it.

On the result page this becomes: the payment card (2.4); a fact row **"Registered name: shown only in your payment app"** (status `skipped`,
never a value); the per-input summary line under the verdict (6.4); and, for an ID with no rule hit, Can't judge with the reason "Nothing in this
ID looks wrong, but only your payment app can show who owns it."

### 3.5 Payment fact sheet (`Report.details`, kind `payment`)

Rows: Type (UPI ID / payment request / QR code), UPI ID (as typed, the handle highlighted like a link's owner part), Handle (`@ybl` -> "{app}
({bank}), NPCI list of {date}" / "not on the list" / "not checked"), Name in the QR ("as written in the QR, not verified"), Amount, Note,
Currency, Registered name ("shown only in your payment app", skipped), Link in the QR (child Report). Nothing in the sheet is fetched.

---

## 4. Apps / APK engine (`src/shield/apps/`), static analysis only

### 4.1 Files and inputs

`catalog.py` + `catalog.json` (official apps, 4.6), `worker.py` (the parse worker, 4.2), `extract.py` (runs inside the worker: bytes ->
`ApkFacts`), `rules.py` (AP1-AP16 on `ApkFacts`, lookup rules, attachment-name rules shared with email), `check.py` (`lookup(query)`,
`check_context(context, file_name)`, `check_apk(data, file_name, context)`), `CLAUDE.md`. Tests `tests/test_apps.py` + `tests/apk_fixture.py`.

Inputs: (a) a name, package name or Play Store link; (b) an APK file (SHOULD); (c) the delivery context, asked in the App tab with or without
an upload: "How did you get this file?" (in a chat or SMS, said to be: an invitation / a bill or challan / a KYC or bank update / a parcel or
courier / a reward, cashback or refund / a job or task / other; from a website I chose; I don't know) plus the file name if known.

`ApkFacts` (JSON, what crosses back from the worker): package, label (resolved), version name / code, min / target SDK, permissions,
accessibility services, notification-listener services, SMS receivers, device-admin receivers, has-launcher, signer certificate SHA-256 list
with scheme (v1 / v2 / v3), entry count, flags (truncated, unusual compression), and later (AP13) a capped list of URLs.

### 4.2 Upload safety

| Guard | Design |
|---|---|
| Size cap | **50 MB** (D29.5, approved), enforced by `upload.read_part` while streaming; `Content-Length` over the cap is refused before reading (413). The frontend checks size and the `.apk` extension before uploading and, for a file over the cap, shows a **Can't judge** result (nothing is sent) with the reason: "This file is larger than 50 MB, so it was not checked. Files are read only in this device's memory and never saved; the limit keeps that quick and safe. Do not install an app file that someone sent you: get apps from the Play Store." The backend's 413 maps to the same result. **Why 50 MB:** the whole file is held in memory (no temp file, 2.5), the parse worker has a 10 s budget and a 768 MB watchdog, and `resources.arsc` + the manifest + the signature files are capped well below that; a larger cap would raise peak memory on the 16 GB Mac without reading more of what the rules use |
| Type by magic bytes | the first 4 bytes must be `PK\x03\x04` and the central directory must list `AndroidManifest.xml`; anything else is 415 "This is not an Android app file (.apk)." A file that starts with a DEX header (the Janus layout, CVE-2017-13156) fails here. Bundles (.xapk / .apks / .apkm: a zip of APKs) -> Can't judge "App bundles are not supported yet" |
| Isolation | parsing runs in a **short-lived child Python process** (`multiprocessing` spawn context) that receives the bytes over a pipe, handles **one** file and exits; a fresh standby worker is started for the next upload, so no state survives between files. The library code is ours and pinned (no external tool, no Java, no `aapt`) |
| Timeout | 10 s wall clock for the whole parse (QR decode: 3 s); the parent kills the worker on expiry -> Can't judge "The file took too long to read." |
| Memory limit | macOS refuses per-process limits: on this Mac (Darwin 25.6.0, Python 3.13.3, 2026-10-30) `resource.setrlimit` raised `ValueError` for `RLIMIT_AS`, `RLIMIT_DATA` and `RLIMIT_RSS`. So: (1) byte budgets by construction (below); (2) a watchdog thread inside the worker reads `resource.getrusage(RUSAGE_SELF).ru_maxrss` every 50 ms and exits at **768 MB**; (3) the parent treats any abnormal exit as Can't judge. **`ru_maxrss` has different units per platform:** bytes on macOS (`sys.platform == "darwin"`), kilobytes on Linux. The limit is written per platform in one constant, `WATCHDOG_MAXRSS = {"darwin": 768 * 1024**2, "linux": 768 * 1024}`, and any other platform refuses to start the worker (APK upload off, the App tab says so); a unit test checks both values and the refusal. `ru_maxrss` is the peak, so the watchdog stops a slow climb; one huge allocation inside native code can still pass the limit before the next 50 ms tick, which is why the byte budgets come first |
| Zip-bomb guard | only the needed members are inflated, with `zlib.decompressobj(...).decompress(chunk, max_length)` so a declared size cannot lie: `AndroidManifest.xml` <= 4 MB, `resources.arsc` <= 32 MB, each `META-INF/*.RSA|DSA|EC|SF|MF` <= 1 MB, the dex string scan (AP13) <= 64 MB in total; a member whose declared ratio exceeds 200:1 is not inflated (flag "unusual compression"); at most 50,000 central-directory entries are read |
| No execution | bytes are parsed, never loaded, installed, run or emulated; no `adb`, no emulator, no dynamic sandbox |
| No disk, no network, no logs in the worker | before importing the parser the worker replaces `builtins.open` / `os.open` with versions that refuse write modes, disables `tempfile`'s constructors and `socket.socket`, and calls `loguru.logger.remove()` (androguard logs file hashes and names at INFO / ERROR). Exceptions become a fixed status word, as in `net.NetError`. **Scope, stated honestly:** these guards act at the Python level only. Native code (lxml's libxml2, cryptography's Rust / OpenSSL, zxing-cpp) calls the C library directly and is not stopped by them; for those libraries the design relies on what they are used for (parsing bytes already in memory: none of the calls used opens a file or a socket) and on the worker being short-lived. AT56 and ST01-ST10 test the Python-level guards and say so; they do not prove that native code writes nothing |
| Delete after | the bytes live in the request handler and the worker only; the worker exits after one file; nothing references them after the response |

### 4.3 Libraries and pins (all checked 2026-10-30 against `https://pypi.org/pypi/<name>/json`)

| Package | Pin | Released | Wheel for macOS arm64 / CPython 3.13 | Licence | Why |
|---|---|---|---|---|---|
| androguard | 4.1.4 | 2026-06-01 | `py3-none-any` | Apache-2.0 | `core.apk.APK(data, raw=True)`: manifest, resources (app label), permissions, components, certificates v1 / v2 / v3. **Installed with `--no-deps`**: its metadata pulls ipython, dataset (SQLAlchemy), pydot, networkx, click, pygments, pyyaml, mutf8, used only by its CLI / decompiler. Read in the wheel's source: `core/apk` imports lxml, apkInspector, asn1crypto, cryptography, loguru; `core/androconf` adds colorama |
| apkInspector | 1.3.7 | 2026-08-28 | `py3-none-any`, no dependencies | Apache-2.0 | the zip layer androguard uses, built to read APKs with tampered zip headers |
| asn1crypto | 1.5.1 | 2022-03-15 | `py2.py3-none-any` | MIT | certificates |
| cryptography | 50.0.2 | 2026-09-30 | `cp311-abi3-macosx_11_0_arm64` | Apache-2.0 / BSD | androguard's v1 signature check (needs >= 46.0.6) |
| cffi | 2.1.1 | 2026-08-03 | `cp313-macosx_11_0_arm64` | MIT | cryptography's dependency |
| pycparser | 3.0 | 2026-01-21 | pure | BSD | cffi's dependency; 3.1-3.12 appeared in October 2026, so the older line is pinned (confirm at install) |
| lxml | 6.1.3 | 2026-09-02 | `cp313-macosx_10_13_universal2` | BSD | androguard's manifest tree |
| loguru | 0.7.3 | 2024-12-06 | `py3-none-any` | MIT | imported by androguard; silenced in the worker |
| colorama | 0.4.6 | 2022-10-25 | `py2.py3-none-any` | BSD | imported by `androconf` |
| zxing-cpp | 3.1.1 | 2026-07-29 | `cp312-abi3-macosx_11_0_arm64` (abi3: loads on 3.13) | Apache-2.0 | QR decoding (W10); runs in the parse worker because it is native code |

What androguard 4.1.4 **does not** do (read in its source, 2026-10-30): it checks the v1 SignerInfo signature against the `.SF` file, but it does
not recompute the v2 / v3 content digests over the zip. So an extracted v2 / v3 certificate is the *claimed* signer. The design relies on
Android instead: a file whose signature does not verify is refused at install (4.5, AP1). Not done: running `apksigner` (needs Java and the
Android SDK) or `apksigtool` (AGPL-3.0). Install check at build time: `pip install --no-deps` of the pinned set into `.venv`, import
`androguard.core.apk`, `zxingcpp`; record the versions in `requirements.txt` and `pyproject.toml`.

### 4.4 What is read from an APK

Permissions (`uses-permission`), services and their `android:permission` / intent filters (accessibility:
`android.permission.BIND_ACCESSIBILITY_SERVICE` or the `android.accessibilityservice.AccessibilityService` action; notification listener:
`BIND_NOTIFICATION_LISTENER_SERVICE`), receivers for `android.provider.Telephony.SMS_RECEIVED` / `SMS_DELIVER` and for device admin
(`BIND_DEVICE_ADMIN`), the launcher activity (`MAIN` + `LAUNCHER`), package, label, versions, SDK levels, signers. The permission names were
checked against the AOSP permission list bundled in androguard 4.1.4 (`core/api_specific_resources/aosp_permissions/permissions_36.json`,
2026-10-30): READ_SMS, RECEIVE_SMS, SEND_SMS, RECEIVE_MMS, RECEIVE_WAP_PUSH, SYSTEM_ALERT_WINDOW, REQUEST_INSTALL_PACKAGES,
BIND_ACCESSIBILITY_SERVICE, BIND_NOTIFICATION_LISTENER_SERVICE, BIND_DEVICE_ADMIN, CALL_PHONE, READ_CALL_LOG, PROCESS_OUTGOING_CALLS,
QUERY_ALL_PACKAGES, READ_PHONE_STATE are all there. Embedded URLs and phone numbers (AP13 / AP14) come from the dex string tables and resource
strings, capped, as text only.

### 4.5 Rule table

"Catalog match" = the package is in `catalog.json` **and** one of the APK's signer certificates is in that package's certificate list.

| ID | Condition | Level | User-facing reason | Tests |
|---|---|---|---|---|
| AP1 | Catalog match | NW (base); skips AP4-AP11 | reassuring: "Signed with the official certificate of {app} ({publisher}), recorded on {date}." | AT01-AT04 |
| AP2 | Package is a catalog package, but no signer certificate is in its list (or the file is unsigned) | L | "Uses the package name of {app}, but it is not signed by {publisher}: a modified or fake copy." | AT05-AT07 |
| AP3 | Package not in the catalog but a catalog package plus extra segments (`.update`, `.kyc`), or within edit distance 2 of one | S | "The package name {pkg} imitates the official {app} ({official})." | AT08-AT10 (genuine AT11) |
| AP4 | Label or package contains a brand or government token, or KYC / customer care / support / rewards / points / challan / bill update, and no catalog match | S | "The app calls itself '{label}', but it is not the official {brand} app." | AT12-AT15 (genuine AT16, AT17) |
| AP5 | OTP access: READ_SMS or RECEIVE_SMS, an SMS receiver, or a notification-listener service | S | "Can read your text messages or notifications, including OTPs." | AT18-AT21 (genuine AT28) |
| AP6 | An accessibility service is declared | S | "Asks for Accessibility access: it could read your screen and tap buttons for you." | AT22, AT23 |
| AP7 | Each of: SYSTEM_ALERT_WINDOW; REQUEST_INSTALL_PACKAGES; a device-admin receiver; CALL_PHONE with READ_CALL_LOG or PROCESS_OUTGOING_CALLS | S (one evidence each) | "Can draw over other apps (used to show fake login screens)." / "Can install other apps." / "Asks to be a device administrator, which makes it hard to remove." / "Can make and manage calls." | AT24-AT27 |
| AP8 | No launcher activity | disp (caution evidence; counts for AP9) | "Has no app icon, so it can run hidden." | AT29 |
| AP9 | AP5 together with AP6, the overlay or device-admin part of AP7, or AP8; or three or more distinct capabilities among AP5-AP8 | L | "Can read your OTPs and control or hide on your phone: the pattern of banking-fraud apps." | AT30-AT33 |
| AP10 | (AP3 or AP4) and AP5 | L | "Claims to be {brand} and asks to read your messages." | AT34, AT35 |
| AP11 | **(a) Questionnaire:** the delivery context the user picked is invitation, bill / challan, KYC / bank update, parcel / courier or reward / cashback / refund. **(b) File name:** a **whole token** of the file name (split on non-letters / non-digits, camelCase and letter / digit boundaries, lower-cased, extension dropped) is one of invite, invitation, wedding, shaadi, card, bill, challan, rto, kyc, courier, parcel, delivery, reward, points, cashback, refund, pmkisan, aadhaar. No substring match: `Billing` is not `bill`, `Cardiology` is not `card` | (a) L; (b) S (one evidence; (a) and (b) together give L from (a)) | (a) "Bills, challans, KYC updates, parcels and invitations never come as app files." (b) "The file name uses the word '{word}'. Bills, challans, KYC updates, parcels and invitations never come as app files." | (a) AT36, AT38; (b) AT37, AT39; genuine AT40, AT61 |
| AP12 | Lookup (input `app`): a catalog package -> NW ("This is the official {app} by {publisher}. Install it only from the Play Store and check the publisher's name."); a catalog app name -> CJ with the official package and publisher shown; a brand + KYC / rewards / update / support / refund / points / bonus name that is not a catalog app -> S ("Banks do not ask you to install a separate {word} app."); AP3 on a typed package -> S; anything else -> CJ | NW / CJ / S | as listed | AT41-AT46 |
| AP13 | **LATER.** URLs in the app's strings, offline checks only: a list hit (R1) or homograph (R3) -> L; look-alike (R4), exact brand (R10), raw IP (R5) -> S; the rest only counted | L / S | "Contains a link to {domain}, which {the link check's reason}." | AT47, AT48 |
| AP14 | **LATER.** Indian mobile numbers in the app's strings | disp | "Contains {n} phone numbers." (shown masked) | - |
| AP15 | Not readable: no manifest, a bundle, too many entries, the timeout, the memory watchdog, a parser error | CJ | "This file could not be read as an Android app." / "App bundles are not supported yet." / "The file took too long to read." | AT49-AT57, AT60 |
| AP16 | An APK, or the questionnaire, with no catalog match and no rule hit | CJ (base) | "Nothing risky is declared in this file, but a file check cannot show what an app does once it is installed." | AT11, AT40 |

**Why AP1 may skip AP4-AP11 (D29.4).** Genuine bank and UPI apps declare SMS permissions (device binding, OTP reading), so without the
exemption a genuine bank APK would be shown as risky. The exemption is safe without verifying v2 / v3 digests because a file can only claim the
bank's certificate without the bank's private key, and Android refuses to install a file whose signature does not verify; the Janus layout that
once kept an old v1 signature valid fails the magic-byte check. A certificate that matches but a package that differs (AT59) is not a match.

### 4.6 The catalog: file format and the adb steps (values come only from Prajval)

`src/shield/apps/catalog.json` (tracked; tests use `tests/fixtures/catalog_test.json` with synthetic packages and a test-generated certificate,
never real values):

```json
{
  "schema": 1,
  "about": "Official Android apps that Scam Shield can recognise. Every value was read by Prajval from an app installed from the Play Store (adb) and from its Play Store page. Never edit a value from memory.",
  "apps": [
    {
      "app": "<name as shown on the Play Store>",
      "publisher": "<developer name as shown on the Play Store page>",
      "brand": "<key in links/brands_india.json, or null>",
      "category": "bank | payment | government | courier | telecom | shopping",
      "package": "<from adb shell pm list packages>",
      "names": ["<lower-case names users type>"],
      "certs": [
        {"sha256": "<64 hex, no colons>", "scheme": "v2 | v3 | v1", "version_name": "<from dumpsys>", "version_code": 0,
         "collected": "YYYY-MM-DD", "device": "<model, Android version>", "installer": "com.android.vending",
         "method": "adb pull of base.apk + apksigner verify --print-certs (or scripts/apk_cert.py)", "by": "Prajval"}
      ],
      "listing": {"url": "https://play.google.com/store/apps/details?id=<package>", "checked": "YYYY-MM-DD", "by": "Prajval"}
    }
  ]
}
```

The loader refuses an app without `publisher`, `package`, a 64-hex `sha256`, `collected`, `method` and `by` (fail closed, AT58). Several
certificates per package are allowed (key rotation, a second signer).

**adb steps (Mac, phone with USB debugging on; one app at a time; the APK is a genuine app from your own phone and is deleted afterwards):**

1. Use an app **already installed** on the family phone (nothing is installed for the catalog); updating it from the Play Store first is fine.
   Check that the Play Store installed it, and find the package:
   `adb shell pm list packages -i | grep -i <brand word>` (a line reads `package:<pkg>  installer=com.android.vending`).
2. Version: `adb shell dumpsys package <pkg> | grep -E "versionName|versionCode"`.
3. Path of the base APK: `adb shell pm path <pkg>` (the first line ends in `base.apk`; `split_config.*.apk` lines are splits, signed with the same key).
4. Copy it into a scratch folder outside the repo: `adb pull <path-to-base.apk> ~/apk_scratch/<pkg>.apk`.
5. Certificate SHA-256, either with the Android SDK build-tools: `apksigner verify --print-certs --verbose ~/apk_scratch/<pkg>.apk` (read the
   "Signer #1 certificate SHA-256 digest" line and the "Verified using v2 / v3 scheme: true" lines), or, once androguard is installed in `.venv`,
   with a small script written at build time (`scripts/apk_cert.py <file>`, prints the scheme and SHA-256 of each signer). Do both for the first
   two apps; they must agree.
6. Open the Play Store page of the app in your browser (`https://play.google.com/store/apps/details?id=<pkg>`), read the publisher name exactly
   as shown, and note the date.
7. Write the entry (lower-case hex without colons), then delete the APK: `rm ~/apk_scratch/<pkg>.apk`. Never commit or upload an APK.

Target list (names only; every package, publisher and certificate is a value Prajval collects): banks: YONO SBI, HDFC Bank, ICICI iMobile Pay,
Axis Mobile, Kotak, PNB ONE, bob World, Canara ai1, Union Bank, IDFC FIRST; payments: Google Pay, PhonePe, Paytm, BHIM, Amazon (Amazon Pay);
government: mAadhaar, DigiLocker, UMANG, mParivahan / NextGen mParivahan, Income Tax (AIS), IRCTC Rail Connect, Sanchar Saathi; couriers:
India Post (IPPB), Blue Dart, Delhivery, DTDC; telecom: MyJio, Airtel Thanks, Vi. **Decided 2026-10-30:** Prajval collects the values later,
**6 apps first, and only apps already installed on family phones** (nothing is installed for the catalog). Which 6 is Prajval's choice; the
most impersonated (SBI, HDFC, ICICI, Axis, PNB, Google Pay, PhonePe, Paytm, BHIM, mParivahan, mAadhaar, India Post) are the useful ones if they
are on a family phone. Until the catalog has entries, AP1-AP3 and AP12's catalog answers stay off and the Report says "not checked" (2.6).

### 4.7 What the apps engine cannot know, and the wording

It **cannot know** what an app does once installed (code paths, downloaded payloads, pages a WebView loads from a server), whether a non-catalog
app is safe (no malware database: VirusTotal would take the file or its hash off the machine), whether a v2 / v3 signature verifies (4.3), or
which file the user will finally install. The page says: "The file was read on this device. It was not installed or run, and it is gone." Base
Can't judge reason: AP16's sentence. Advice: 2.4.

**Evaluation hook (SHOULD):** AP5 and AP7 can be counted on `data/final/apps.csv` **val** (459 benign / 244 malware permission sets; 86 permission
strings; no accessibility, notification-listener or device-admin columns, so AP6 / AP8 / AP9 cannot be measured there), fire rates by label,
counts only. Its provenance is the `android_malware_hf` dataset of unknown age and origin: not Indian, not 2025-26 banking malware. Report it
with that caveat; tune nothing on its test split.

---

## 5. Email

### 5.1 Inputs and flow

Subject + body (required); From address, display name, Reply-To and attachment file names (optional); optional pasted headers (Gmail: ⋮ >
Show original; the header block up to the first blank line, at most 64 KB). When headers are pasted, From / Reply-To / display name are read
from them (`email.parser.HeaderParser`, `policy.default`, stdlib; nothing decoded beyond headers). The body is capped like a message (20,000
characters).

Flow: `router.analyse(subject + "\n\n" + body, ..., email=EmailMeta)`. Everything the message engine does applies (model on `model_text`,
OTP / R2 / A1-A12 / UP hooks, tactic tags, links with live checks on the second call, fold, language cap). The email rules run after the
investment rules and before the D23 positives, as floors, and count as the hard-risk signal `email_rule`.

### 5.2 Long emails: 128-token windows (LATER; protocol fixed now)

Today MuRIL reads the first 128 tokens of `model_text(text)` (which keeps 2,000 characters). Design: a method `TextScorer.score_long(prepared,
mode)` on the output of `model_text` (rule 11: `model_text` stays the only text preprocessing; the windowing is part of how the scorer reads
its input, and the same method serves the app and every evaluation):

- `head` (today): the first 126 content tokens.
- `headtail`: the first 63 + the last 63 content tokens.
- `max`: windows of 126 content tokens, stride 63, over the whole prepared text (at most 2,000 characters, about 6 windows); score = the maximum
  calibrated window score.

For a text of 126 content tokens or fewer all three are identical (asserted). **Selection, pre-registered:** after splits-v3, on **val only**
(email-like sources: `phishing_email`, `ealvaradob_phishing` emails; never TEST, never `real_test_v1.csv`): cut-offs refitted per mode with
`calibrate_text_head.py`'s rule; adopt `headtail` or `max` only if its val AUROC on email rows beats `head` by >= 0.005 **and** its benign
Suspicious-or-above rate on those rows is not higher; otherwise keep `head`. Applies to the Email tab only; messages keep `head` until a separate
decision. Cost: about 6 forward passes per long email (59 ms each on CPU, D27).

### 5.3 Rule table

| ID | Condition | Level | User-facing reason | Tests |
|---|---|---|---|---|
| EM1 | subject + body through the message engine | as messages | (the message reasons) | ET37-ET39, ET46 |
| EM2 | The display name contains a brand or government token and the From address is on a free-mail domain (`freemail.json`) | S | "Says it is from {brand}, but it was sent from a free {provider} address." | ET01-ET04 (genuine ET05) |
| EM3 | The display name contains an e-mail address or domain that differs from the real From address | S | "The sender's name shows {shown}, but the real address is {actual}." | ET06, ET07 (genuine ET08) |
| EM4 | The From domain is an IDN homograph of a brand or Tranco top-10k name (R3 logic) | L | "The sender's address imitates {brand} with look-alike letters." | ET09 |
| EM4b | The From domain is a brand look-alike (R4) or an exact brand label on a domain the brand does not own (R10) | S | "The sender's address uses the name {brand}, but it is not {brand}'s." | ET10-ET12 (genuine ET13) |
| EM5 | Reply-To's registered domain differs from From's, is not owned by the claimed brand (`brands_india.json` `owned`), and the display name, From domain or subject claims a brand | S (else a neutral fact) | "Replies would go to {reply domain}, not to {from domain}." | ET14-ET16 (genuine ET17) |
| EM6 | The **topmost** `Authentication-Results` header says `dmarc=fail`; with the From domain owned by a brand (or EM2 / EM4) | S; L with a brand | "This email failed its sender check (DMARC) for {domain}." / "... It is probably forged." | ET18-ET21 |
| EM7 | `spf=fail` or `softfail`, no `dkim=pass`, no DMARC result | disp; S with a brand claim | "The sender check (SPF) failed and the email is not signed (DKIM)." | ET22-ET24 |
| EM8 | `spf`, `dkim` and `dmarc` all pass and DKIM's `d=` aligns with From | disp, reassuring, never lowers | "Your mail provider's sender checks passed for {domain}." | ET25, ET26 |
| EM9 | An attachment name ends in `.apk` (case-insensitive; the last extension decides) | L | "An Android app file (.apk) is attached. Banks, couriers and offices never send apps by email." | ET27, ET28, ET36 |
| EM10 | An attachment name ends in `.html`, `.htm`, `.zip`, `.iso` or `.exe` | S | "A {ext} file is attached, a type often used to deliver fake login pages or malware." | ET29-ET33, ET35 (genuine ET34) |
| EM11 | A double extension (`invoice.pdf.exe`) | adds a reason; level from EM9 / EM10 | "The file name hides its real type ({name})." | ET35, ET36 |
| EM12 | Windowing (5.2) | - | - | ET41-ET43 |

Header reading rules: only the first `Authentication-Results` header in the pasted block is read (the one the user's own provider added;
lower ones can be planted by a sender); `spf`, `dkim`, `dmarc` and `header.from` / `header.d` / `smtp.mailfrom` are parsed with a regex per
RFC 8601's result syntax; no DNS lookup, no ARC evaluation. No header -> the fact row "Sender checks: not provided".

Free-mail list (`freemail.json`, hand-written, **shown to Prajval for review on 2026-10-30 (D29.13); final OK pending**; needed by W7 only).
Every entry is a domain where anyone can open a personal mailbox; a company would not send official mail from it. Written from general
knowledge, not fetched, so each row carries a status:

| Group | Domains | Status |
|---|---|---|
| India (named by Prajval) | rediffmail.com, yahoo.co.in | named by Prajval |
| India (proposed) | yahoo.in, zohomail.in, rediff.com, sify.com, bsnl.in, vsnl.net (the last two: old ISP mailboxes) | proposed, needs Prajval's OK |
| India (unverified country variants) | hotmail.co.in, outlook.in, live.in | **not sure these were ever offered as mailboxes**: kept out unless Prajval confirms |
| Global | gmail.com, googlemail.com, yahoo.com, ymail.com, rocketmail.com, outlook.com, hotmail.com, live.com, msn.com, icloud.com, me.com, mac.com, aol.com, proton.me, protonmail.com, zohomail.com, gmx.com, mail.com, yandex.com, tutanota.com, tuta.io | proposed (unchanged from the first draft) |
| Left out on purpose | indiatimes.com (the Times group sends its own newsletters from it, so a brand-like display name there can be genuine) | - |

A wrong entry costs a false Suspicious only when the display name also claims a brand (EM2) or for the Reply-To check (EM5); a missing
entry only loses those two rules for that provider.

### 5.4 What the email engine cannot know, and the report line

It cannot know whether the sender really sent it without the headers; it cannot verify a header the user pasted (it trusts only the topmost
`Authentication-Results`, and forwarding breaks SPF); display names are free text; attachments are judged by name only, never opened. The
report and the limits section will carry: **"Email checks were validated on public email datasets (val split), not on real Indian email."**

---

## 6. UI: tabs, widgets, one result page

### 6.1 Tab row

Six tabs in this order: **Message · Link · Email · Payment / UPI · App / APK · Screenshot**. WAI-ARIA tabs pattern: `role="tablist"`, each tab a
`<button role="tab" aria-selected aria-controls>`, panels `role="tabpanel"`, arrow keys move between tabs, Home / End jump, the active tab is
scrolled into view. Phone (<= 640 px): one horizontally scrolling row (`overflow-x: auto`, scroll-snap, edge fades as the scroll hint, no page
scroll sideways), pills 40 px tall with 14 px text (the existing phone floors), the active pill filled. Desktop: all six fit in one row. The
tab is not stored (the browser keeps only the theme, ARCHITECTURE §5.4); Message is the default.

Hero line per tab (formal register): Message keeps today's hero; Link: "Check a link before you open it."; Email: "Check an email before you
reply or click."; Payment: "Check a payment request, UPI ID or QR code before you pay."; App: "Check an app before you install it.";
Screenshot: "Check a screenshot of a message, a payment request or a QR code."

### 6.2 Widgets

| Tab | Widget |
|---|---|
| Message | today's `PasteBox` unchanged (text, screenshot button, drop, paste, detection chips) |
| Link | one-line `<input type="text" inputmode="url" autocapitalize="off" spellcheck="false">` with a visible label and a Check button; a pasted message with prose is routed to Message with a notice |
| Email | Subject (one line) and Body (textarea), both required; a closed "More details (optional)" disclosure with From, Display name, Reply-To, Attachment names (comma-separated), and Headers (textarea, "Gmail: ⋮ > Show original, then copy the part above the message") |
| Payment / UPI | a three-way segmented control: **UPI ID or request** (textarea that accepts a UPI ID, a `upi://` string or the request text; for a request, the optional question "Did you start this payment?" Yes / No / Not sure), **QR code** (SHOULD: picker / drop / paste of an image; the decoded fields are shown read-only before the check), **Payment screenshot** (no upload: the explanation "A screenshot cannot prove a payment, so there is nothing to upload" and a "Show me what to do" button). The payment card line (2.4) is shown under the control |
| App / APK | a two-way segmented control: **Name or link** (one line: app name, package or Play Store link) and **App file** (the questionnaire "How did you get this file?" + an optional file name field; SHOULD: a file picker `accept=".apk,application/vnd.android.package-archive"`, 50 MB, checked before upload) with the note "The file is read on this device. It is never installed or run." |
| Screenshot | a large drop zone + picker + paste (PNG / JPEG / WEBP, 8 MB). SHOULD: a QR is looked for first; if found, its fields are shown and checked as a payment. Otherwise the OCR text goes into an editable box with today's notice ("check amounts and links") and is checked as a message |

### 6.3 Routing notice

When the Report's `input` differs from the tab used, one calm line above the verdict: "This looks like a UPI ID, so it was checked as a
payment ID." / "This looks like a link, so it was checked as one." / "This looks like a message, so it was checked as one." / "This QR code
holds a link, so the link was checked." The frontend owns these fixed lines (like `LEVEL_SUMMARY`); the backend only sets `input`.

### 6.4 The shared result page

Unchanged: `VerdictPanel` (word + icon + colour, meter, radar), `WhyPanel`, `WhatToDo` with the helpline row (1930, cybercrime.gov.in, EN / HI /
KN switch) on Suspicious and Likely scam, `LinkPanel` for every child link, the investment card, `Tip`. Changes:

- `LEVEL_SUMMARY[input][level]` (fixed, frontend-owned) instead of one line per level. Payments: Likely "This payment has strong signs of a
  scam." / Suspicious "Something about this payment is risky. Check before you pay." / No warning signs "Nothing in it looks wrong. Only your
  payment app can show who you would pay." / Can't judge "Only your payment app can show who owns this ID." Apps: Likely "This app has strong
  signs of a fraud app." / Suspicious "Parts of this app are risky. Do not install it yet." / No warning signs "It carries the official app's
  signature. Install apps from the Play Store all the same." / Can't judge "A file check cannot tell what this app does once installed."
  Links and emails follow the message wording with "link" / "email".
- The input panel: message and email use `MessagePanel` (underlines; email shows From / display name above the text); payments show the UPI ID
  split like a link address (handle highlighted) plus amount and note; apps show label, package and file size. `Report.details` renders in
  `DetailsPanel`, the generalised `WebsiteDetails` (same rows, icons, "why" lines, "sent off this device" note).
- `Checking` steps per input (e.g. payments: "Reading the payment details", "Checking the UPI ID and its name", "Looking for refund and prize
  tricks").
- "← Check another message" becomes "← Check something else"; "Checked on this device · nothing was stored" stays (true for every input).

### 6.5 Clashes with the current result page

1. Message-specific copy in `Result.tsx` ("← Check another message"), `MessagePanel` ("Your message"), `WhyPanel` ("No warning signs were found
   in this message."), `LEVEL_SUMMARY`, `Checking` steps, the hero and the examples: all become per-input (6.4).
2. The layout assumes a text with underlines. An APK has no text: its result has no underline panel and no pointable reasons; the radar still
   works (it reads evidence).
3. **Meter without a text score** (D24): payments and apps show only band floors (70 / 30 / 0). Recommendation for 6 Nov: keep D24 as it is
   (the same as a bare link today) and list it as a limit; alternative (D29.12): show the zone without a number for inputs with no text score.
4. `App.tsx` re-checks live by re-posting the same text (`analyse(sent, {live: true})`); it becomes `check(request, {live: true})` for every input
   that has links.
5. Schema "6": `api.ts` rejects any other version; fixtures (`dump_fixture.py`, 94 reports) are regenerated. **Timing:** land v6 before the
   D28 app switch (4 Nov) so the fixtures are regenerated once.
6. `PasteBox`'s "UPI ID" chip uses its own 10-handle regex; it stays a cosmetic hint and never decides routing (the backend does).
7. Register: existing copy uses contractions ("Don't reply ..."); new copy is formal without them. Aligning the old copy is a later choice.
8. `MAX_TEXT_CHARS` 20,000 also caps an email body; a longer email is refused with "Paste the part with the request and the links (at most
   20,000 characters)."

### 6.6 Languages

English for 6 Nov. Hindi and Kannada versions of the new reasons, advice, tab labels and summaries are LATER (W17): string tables keyed by the
English line (like `lib/investment.ts`), each language with a `NEEDS_REVIEW` flag shown as "translated, under review" (D17), reviewed by a native
speaker (D15). The helpline row's switch keeps working on every input.

---

## 7. Tests (design only)

### 7.1 Conventions

One wrapper per file in `tests/` (`test_payments.py`, `test_apps.py`, `test_email.py`, plus additions to `test_contracts.py`, `test_api.py`),
each running its numbered checks like the existing files, on **both text heads**. Inputs are synthetic and written in the test files; APKs are
built **in memory** by `tests/apk_fixture.py` (a small binary-AXML writer for the manifest, a zip, and an APK Signing Block holding a
certificate generated by the test with `cryptography`); QR images are drawn in memory with zxing-cpp's writer; nothing is saved to disk. **No
real APK, no malware sample, no real catalog value** is used: genuine cases are synthetic look-alikes of genuine permission sets and requests.
Rule tests assert the rule's hit and its floor; final levels are asserted only where a rule floor decides them (model-dependent levels are
not locked). Frontend: vitest + the existing Playwright scripts.

### 7.2 Payments: PT01-PT70

| ID | Input (synthetic) | Expected | Rule |
|---|---|---|---|
| PT01 | request "Rahul is requesting Rs 4,999. Note: refund for cancelled order. Pay / Decline" | L | UP13 |
| PT02 | request "Collect request Rs 1 from kyc.verify@ybl. Approve to receive Rs 10,000 cashback" | L | UP13, UP3 |
| PT03 | request "Rs 2,000 cashback paane ke liye request approve karein" | L | UP13 |
| PT04 | OCR-style noisy request "Paytm · Request from Lucky Draw Team Rs 999 Prize money PAY DECLINE" | L | UP13 |
| PT05 | `ramesh.k@okaxls` | S | UP1 |
| PT06 | `ramesh.k@ybI` (capital I) | S | UP1 (fold) |
| PT07 | `ramesh.k@paytrn` | S | UP1 (rn -> m) |
| PT08 | `ramesh.k@0kaxis` | S | UP1 (0 -> o) |
| PT09 | `ramesh.k@okaxis` (listed in the fixture list) | CJ + handle fact | genuine |
| PT10 | `ramesh.k@zzbank` | CJ + "not on the list" | UP2 |
| PT11 | any ID with the handle list missing | CJ + "not checked"; UP1 / UP2 / UP4 silent | fail closed |
| PT12-PT16 | `refund.desk@ybl`, `kyc-update@ibl`, `customercare24x7@axl`, `lucky.prize.2026@okicici`, `bijli.helpdesk@ybl` | S each | UP3 |
| PT17 | `skincare.studio@okhdfcbank` | CJ | genuine (partial token) |
| PT18, PT19 | `sbi.payments@ybl`, `irctc-tatkal@axl` | CJ + caution evidence | UP4b |
| PT20-PT22 | `uidai.aadhaar@ybl`, `rto.challan.pay@okicici`, `cyber.police@ybl` | S each | UP4 |
| PT23 | `amazon@apl` | CJ + caution evidence, no level | UP4b alone |
| PT24 | `paytmqr2810050501011abc@paytm` (shop QR style) | CJ, no name evidence | genuine (`PAY_APPS` alone) |
| PT25-PT27 | `sbi.kyc.update@ybl` (UP3 + UP4b), `amazonrefund@axl` (UP3 + UP4b), `paytm-cashback-desk@okaxis` (UP3 + a `PAY_APPS` name) | L each | UP5 |
| PT28 | `9876543210@ybl` | CJ + "linked to a phone number" | UP6 |
| PT29 | QR payload `https://sbi-kyc-update.top/login` | link ladder (R4 -> S) | UP7 |
| PT30 | QR text "Send OTP to receive prize" | message engine (OTP rule -> S) | UP7 |
| PT31 | QR `WIFI:S:Home;T:WPA;P:x;;` | CJ | UP7 |
| PT32 | `upi://pay?pa=shop1@ybl&pn=Prize%20Dept&am=4999&tn=Claim%20your%20prize` | L | UP8 |
| PT33 | `...&am=10&tn=KYC%20verification%20refund` | L | UP8 |
| PT34 | `...&tn=cashback` (no amount) | S | UP9 |
| PT35 | `pn=Refund%20Desk&am=1` | L | UP8 (pn) |
| PT36 | `upi://pay?pa=ramesh.kirana@okicici&pn=Ramesh%20Kirana` | CJ | genuine |
| PT37 | shop QR with `am=250&tn=Order%201234` | CJ | genuine |
| PT38 | `pn=State%20Bank%20of%20India&pa=rk1990@ybl` | S | UP10 |
| PT39 | `pn=Income%20Tax%20Department&pa=itrefund@okaxis` | L | UP10 + UP3 -> UP5 |
| PT40 | `pn=HDFC%20Bank&pa=hdfcbank.merchant@hdfcbank` (the name is in the ID) | CJ + UP4b caution, no UP10 | genuine |
| PT41 | `pn=Ramesh%20Kirana&pa=ramesh.k@okicici` | CJ | genuine |
| PT42 | `upi://pay?pn=Shop&am=50` (no `pa`) | CJ | UP11 |
| PT43 | `upi://pay?pa=shop@ybl&am=abc&cu=USD` | CJ | UP11 |
| PT44 | QR with `url=https://bit.ly/x` | child link CJ (shortener); payment CJ | UP12 |
| PT45 | request "Swiggy is requesting Rs 349 for order #5521", no answer | CJ | genuine |
| PT46 | PT45 + started = No | S | UP14 |
| PT47 | PT45 + started = Yes | NW | UP15 |
| PT47b | request "Swiggy is requesting Rs 349. Share the OTP to confirm" + started = Yes | >= S (the OTP rule fired, so UP15 does not apply) | UP15 scope |
| PT48-PT50 | message "Scan this QR code to receive your refund of Rs 2,000" / "Scan karke apna cashback receive karein" / "To get the prize money, scan the code below" | UP16 fires (>= S) | UP16 |
| PT51 | message "Scan the QR at the counter to pay" | UP16 silent | genuine |
| PT52 | message "You never need to scan a QR code to receive money" | UP16 silent | negation |
| PT53-PT55 | "Approve the collect request to receive Rs 5,000 refund" / "Accept the payment request and the cashback will be credited to you" / "Please authorise the request on PhonePe to get your money back" | UP17 fires | UP17 |
| PT56 | "Approve the mandate request to start your SIP of Rs 500" | UP17 silent | genuine |
| PT57-PT60 | "I sent Rs 5,000 to your number by mistake, please send it back" / "Rs 10,000 credited to your account wrongly. Kindly return the amount" / "Galti se aapke account mein 2000 bhej diye, please wapas bhej do" / "Amount transferred by mistake. Return immediately or police complaint" | UP18 fires | UP18 |
| PT61 | bank alert "Rs 500 wrongly debited from your a/c XX1234 has been reversed" | UP18 silent | genuine |
| PT62 | friend "sorry, sent 200 to you by mistake, can you send it back" | UP18 fires (documented false positive; the advice is harmless) | known FP |
| PT63 | `{"kind": "payment_proof"}` | CJ, fixed reason and advice | UP19 |
| PT64 | payment_proof with any extra field | 422 (nothing accepted) | UP19 |
| PT65 | OCR "Payment Successful Rs 5,000 Paid to Rahul UPI transaction ID 123456789012" | CJ | UP20 |
| PT66 | PT65 + "send back the extra Rs 4,000" | S (UP18; UP20 never lowers) | UP18 |
| PT67 | the same text pasted (not a screenshot) | UP20 not applied | scope |
| PT68 | `sbi​.kyc@ybl` (zero-width) inside a message | UP5 on the folded view, quote maps back | UP21, D11 |
| PT69 | `SBI.KYC@YBL` | same as lower case | parsing |
| PT70 | a 300-character "UPI ID" | CJ "not a valid UPI ID" | parsing |

### 7.3 Apps: AT01-AT62

F = rule test on an `ApkFacts` object; B = a synthetic APK built in memory and parsed in the worker; H = through the API; K = catalog / lookup.

| ID | Case | Expected | Rule |
|---|---|---|---|
| AT01 (B) | fixture package `in.example.bank` signed with the fixture certificate listed in the test catalog | NW | AP1 |
| AT02 (F) | catalog match that also has READ_SMS, SEND_SMS, READ_PHONE_STATE (a genuine bank app's set) | NW | AP1 exemption |
| AT03 (F) | catalog match, context "KYC update" | NW + Play Store advice | AP1 exemption |
| AT04 (F) | catalog match on the second listed certificate (rotation) | NW | AP1 |
| AT05 (B) | catalog package, signed with another test certificate | L | AP2 |
| AT06 (F) | catalog package, unsigned | L | AP2 |
| AT07 (F) | catalog package, v1-only signer not in the list | L | AP2 |
| AT08-AT10 (F) | `in.example.bank.update`, `in.exampel.bank`, `in.example.bonk` | S | AP3 |
| AT11 (F) | `org.example.notes`, harmless permissions | CJ | AP16 |
| AT12-AT15 (F) | labels "SBI Rewards", "RTO Challan", "PM Kisan Yojana", "Customer Support" + package `com.help.kyc` | S | AP4 |
| AT16 (F) | label "Kirana Billing" | CJ | genuine |
| AT17 (F) | label not resolvable | no AP4; fact "name could not be read" | AP4 scope |
| AT18-AT21 (F) | READ_SMS; RECEIVE_SMS; an SMS_RECEIVED receiver; a notification listener | S | AP5 |
| AT22, AT23 (F) | accessibility service by permission; by intent filter only | S | AP6 |
| AT24-AT27 (F) | SYSTEM_ALERT_WINDOW; REQUEST_INSTALL_PACKAGES; device-admin receiver; CALL_PHONE + READ_CALL_LOG | S | AP7 |
| AT28 (F) | a UPI-app-like set (INTERNET, CAMERA, SEND_SMS, READ_PHONE_STATE, READ_CONTACTS), not in the catalog | CJ (SEND_SMS alone is not OTP access) | genuine |
| AT29 (F) | no launcher activity, nothing else | CJ + caution evidence | AP8 |
| AT30-AT33 (F) | READ_SMS + accessibility; RECEIVE_SMS + overlay; notification listener + no icon; overlay + install + admin | L | AP9 |
| AT34, AT35 (F) | label "HDFC Bank KYC" + READ_SMS; AP3 package + RECEIVE_SMS | L | AP10 |
| AT36, AT38 (H) | harmless file with context "wedding invitation"; context "parcel / courier" | L | AP11 (a) |
| AT37, AT39 (H) | harmless file named `RTO_Challan_2026.apk` (tokens rto, challan, 2026); `Wedding Card.apk` (tokens wedding, card); no context given | S | AP11 (b) |
| AT40 (H) | harmless file, context "a website I chose" | CJ | genuine |
| AT41 (K) | query `in.example.bank` | NW | AP12 |
| AT42 (K) | query "Example Bank" | CJ + official package and publisher | AP12 |
| AT43 (K) | query "Example Bank Rewards" | S | AP12 |
| AT44 (K) | query `in.example.bank.kyc` | S | AP3 |
| AT45 (K) | query `https://play.google.com/store/apps/details?id=in.example.bank&hl=en`, sockets patched | NW, 0 connection attempts | AP12 |
| AT46 (K) | query "Some Game" | CJ | AP12 |
| AT47, AT48 (F, LATER) | strings with a fixture-listed URL; with `sbi-kyc.top` | L; S | AP13 |
| AT49 (H) | `%PDF` bytes named `.apk` | 415, nothing stored | magic bytes |
| AT50 (H) | a zip without `AndroidManifest.xml` | 415 | magic bytes |
| AT51 (H) | manifest member declared 1 KB that inflates past 4 MB | CJ, inflation stopped at the cap | zip bomb |
| AT52 (H) | a file starting with `dex\n035` | 415 | Janus layout |
| AT53 (H) | 51 MB body | 413 before the body is read in full | size cap |
| AT54 (H) | worker made slow (patched `extract`) | CJ "took too long", worker killed, the next upload works | timeout |
| AT55 (H) | worker made to allocate 1 GB (patched) | CJ, worker exits, API unaffected | watchdog |
| AT56 (H) | normal parse with `open` / `os.open` / `tempfile` / `socket` instrumented in the worker, stderr captured | 0 Python-level writes, 0 Python-level sockets, 0 log lines. **Python level only:** native code (libxml2, OpenSSL, zxing-cpp) is not instrumented, so this test does not show that native code writes nothing (4.2) | no disk / network / logs (Python level) |
| AT57 (H) | a zip of two APKs (`.apks`) | CJ "bundles not supported" | AP15 |
| AT58 (K) | catalog entry without `collected` or `method` | refused at load; app starts with that entry dropped and says so | provenance |
| AT59 (F) | the catalog certificate on a different package | not AP1; fact "signed with {publisher}'s certificate" (display) | AP1 scope |
| AT60 (H) | a zip with duplicate names and a central directory that disagrees with the local headers | parsed via apkInspector or CJ; never a crash | robustness |
| AT61 (F + H) | harmless file named `Kirana Billing.apk` (tokens kirana, billing), no context | AP11 silent (`billing` is not the token `bill`); CJ from AP16 | AP11 whole tokens |
| AT62 (unit) | `WATCHDOG_MAXRSS` on `darwin` = 768 * 1024**2 (bytes), on `linux` = 768 * 1024 (KB); any other platform refuses to start the worker | as stated | watchdog units |

### 7.4 Email: ET01-ET46

| ID | Case | Expected | Rule |
|---|---|---|---|
| ET01-ET03 | display "SBI Alerts" <sbi.alerts2026@gmail.com>; "Income Tax Department" <refund.itd@outlook.com>; "Amazon" <amazon.support@yahoo.co.in> | S | EM2 |
| ET04 | "HDFC Bank" <x@rediffmail.com> + an OTP request in the body | >= S (EM2 + OTP rule) | EM2 |
| ET05 | "Priya Sharma" <priya.s@gmail.com> | EM2 silent | genuine |
| ET06 | display "support@sbi.co.in" <random123@gmail.com> | S | EM3 |
| ET07 | display "Amazon.in" <orders@amaz0n-in.top> | S (EM3) + EM4b | EM3 |
| ET08 | "Flipkart" <no-reply@flipkart.com> | EM3 silent | genuine |
| ET09 | From domain with a Cyrillic `ѕ` imitating sbi.co.in | L | EM4 |
| ET10-ET12 | `sbi-netbanking-alerts.com`, `hdfc.top`, `paytm-kyc.in` | S | EM4b |
| ET13 | `alerts@sbi.co.in` | EM4 silent | genuine |
| ET14 | display "HDFC Bank", From noreply@hdfcbank.com, Reply-To claims@refunds-desk.com | S | EM5 |
| ET15 | display "ICICI", From and Reply-To on free mail, different providers | S | EM2 + EM5 |
| ET16 | Reply-To elsewhere, no brand claim | neutral fact only | EM5 scope |
| ET17 | From news@amazon.in, Reply-To no-reply@amazon.com (both owned by Amazon) | EM5 silent | genuine |
| ET18 | topmost `Authentication-Results: mx.example; dmarc=fail header.from=sbi.co.in` | L | EM6 |
| ET19 | `dmarc=fail` for a non-brand domain | S | EM6 |
| ET20 | topmost says `dmarc=fail`, a lower planted header says `dmarc=pass` | the topmost wins (fail) | EM6 |
| ET21 | `dmarc=fail`, no From field given | `header.from` used | EM6 |
| ET22 | `spf=fail dkim=none`, no DMARC, no brand | fact only | EM7 |
| ET23 | `spf=softfail dkim=fail` + brand display name | S | EM7 |
| ET24 | `spf=pass dkim=none` | nothing | EM7 scope |
| ET25 | all pass and aligned + an OTP request in the body | still >= S (EM8 never lowers) | EM8 |
| ET26 | all pass + a list-hit link in the body | L (link R1) | EM8 |
| ET27, ET28 | attachments `KYC_Update.apk`, `invitation.APK` | L | EM9 |
| ET29-ET33 | `invoice.html`, `statement.htm`, `docs.zip`, `setup.iso`, `update.exe` | S | EM10 |
| ET34 | `invoice.pdf` | nothing | genuine |
| ET35 | `invoice.pdf.exe` | S + the hidden-type reason | EM10 + EM11 |
| ET36 | `photo.jpg.apk` | L + the hidden-type reason | EM9 + EM11 |
| ET37 | body link on the fixture OpenPhish list | L | EM1 (R1) |
| ET38 | body link on `.bank.in`, no hard risk | P1 behaviour unchanged | EM1 |
| ET39 | body with a shortener | the link CJ; level from the text | EM1 |
| ET40 | headers of 70 KB / binary garbage | 422 / a "could not read the headers" fact | limits |
| ET41 | text of <= 126 content tokens | identical score in head / headtail / max | EM12 (LATER) |
| ET42 | long benign newsletter with a scam paragraph at the end | `max` scores it higher than `head` (mechanism only, synthetic) | EM12 (LATER) |
| ET43 | the same long text twice | identical windows and scores | EM12 (LATER) |
| ET44 | subject only, empty body | 422 | inputs |
| ET45 | every field set, log records / stdout / stderr captured, sockets patched | 0 matches of any field, 0 network attempts offline | privacy |
| ET46 | Hindi body, text-only Likely | Suspicious (D5 cap unchanged) | EM1 |

### 7.5 UI, contract and safety tests

- **UT01-UT18** (vitest + Playwright): tab keyboard (arrows, Home / End), `aria-selected` / `aria-controls`; phone row scrolls with no page
  overflow at 360-430 px and the active tab in view (`e2e/overlap.mjs` extended); the routing notice for each (tab, input) pair; per-input
  `LEVEL_SUMMARY`; the payment card on every payment result; the APK picker refuses > 50 MB and non-`.apk` before any request; "More details"
  closed by default; a file over 50 MB shows the Can't judge result with the size reason (4.2) and sends nothing; the payment-screenshot mode sends `{"kind": "payment_proof"}` and no image; `DetailsPanel` renders `Report.details`;
  APK results have no underline panel; axe 0 violations and the rendered-pixel contrast check on every new screen in both themes; helpline row
  on warnings for every input.
- **CT01-CT08** (`test_contracts.py`): v6 fields; `input` literal; module <-> input and details.kind <-> module consistency; child Reports
  have `input` null; band-floor scores for inputs without a text score; Can't judge has no score; `extra="forbid"` on the new request bodies;
  the 363 contract inputs give the same level and reasons as v5 apart from `input` and the version (the refactor of `reasons_from` and
  `assess_links` changes nothing).
- **ST01-ST10** (`test_api.py`): T7's zero-network gate extended to every new offline path; live calls only to `net.py`'s hosts; no disk write
  in the API process or the worker (patched `open` / `os.open` / `tempfile`); T12's log capture extended to the new endpoints, including failing
  analyses; the upload caps act before the body is read; a worker per job; fixed error messages, never a file name or content. **What they do
  not prove:** the write and socket checks patch Python functions, so they catch Python-level writes and sockets only; native libraries (libxml2,
  OpenSSL, zxing-cpp) call the C library directly and are not observed (4.2). The test names and docstrings say "Python-level".

### 7.6 Coverage

Every rule row above names its tests; every test names its rule. A test helper asserts that each `RULES` table entry (payments, apps, email)
is hit by at least one must-fire and one must-stay-quiet case, the same discipline as `test_invest_rules.py`.

---

## 8. Plan, dependencies and cut-line

### 8.1 Pieces

Hours = build session including tests and fixes; Prajval's own hours are listed separately.

| W | Piece | Hours | Needs | Tier |
|---|---|---|---|---|
| W1 | Contract v6, `/api/check`, `core/intake.classify`, `reasons_from` / `assess_links` refactor (no output change), per-input advice; contract + API tests | 5 | D29 approved | MUST |
| W2 | Tab row, Link tab, per-input copy, `check()` + generalised live re-check, `DetailsPanel`, routing notice; vitest + e2e at phone widths | 8 | W1 | MUST |
| W3 | Payments core: UPI ID parsing, UP3-UP5, UP13-UP15, UP19, fact sheet, payment card (UP1 / UP2 wait for W9) | 5 | W1 | MUST |
| W4 | Payment tab widget (ID / request text, "Did you start it?", payment-screenshot mode) | 3 | W2, W3 | MUST |
| W5 | Message hooks UP16-UP18 + `tricky_inputs.py` entries + the val gate (8.3) + `config.PAYMENT_HOOKS` (off by default) | 4 | W1 (build order only); splits-v3 val (B1, 1 Nov PM) for the gate | MUST, **merged by 4 Nov**; ships OFF if the gate cannot run by the end of 3 Nov or fails (8.3) |
| W6 | App lookup (AP12, AP3, AP4 on names), catalog format + fail-closed loader, App tab name field + the no-upload questionnaire (AP11, AP16) | 4 | W1, W2 | MUST |
| W7 | Email-lite: Email tab, EM1-EM5, EM9-EM11 through `analyse(..., email=)` | 5 | W1, W2 | MUST |
| W8 | Docs and limits: ARCHITECTURE §2 / §7 / §10, module `CLAUDE.md` files, BUGS.md entries, README evaluation line for email | 2 | the rest | MUST |
| W9 | NPCI handle file + UP1, UP2 and the handle row | 2 | the sourced list (section 9) | SHOULD |
| W10 | `/api/image` (QR first, then OCR), zxing-cpp in the parse worker, UP7-UP12, Screenshot tab QR path, UP20 | 7 | W3, the worker (shared with W11) | SHOULD |
| W11 | APK upload: worker, guards, minimal androguard install, extraction, AP1-AP10, AP15, App tab file picker | 10 | W6 | SHOULD |
| W12 | Fresh-session review (Opus, high) of the upload / worker code and the contract change | 1.5 | W11 (and W10 if landed) | required if W11 lands; covers W10 too |
| W13 | Email headers: EM6-EM8 | 2 | W7 | SHOULD |
| W14 | Catalog values via adb (Prajval, later): 6 apps first, only apps already installed on family phones | (3, Prajval) | approval | SHOULD |
| W15 | AP13 embedded links (dex strings, offline ladder) | 4 | W11 | LATER |
| W16 | Email windowing: `score_long`, val experiment, decision | 6 | splits-v3 head and val | LATER |
| W17 | Hindi / Kannada copy for the new lines, marked under review (D15 / D17) | 3 + review | W2-W7 | LATER |
| W18 | Bharat QR (EMVCo) parsing | 3 | the official spec | LATER |
| W19 | UP21 (UPI IDs inside messages) + its val gate | 3 | W5 | LATER |

Totals: **MUST 36 h** (W1-W8), **SHOULD 22.5 h** (W9, W10, W11, W13 and the W12 review they require) + 3 h of Prajval's adb time,
**LATER 19 h**. Prajval's time: approval and decisions ~1 h, NPCI list ~0.5 h, adb catalog ~3 h, UI review ~1 h.

### 8.2 Timeline against the ML work (splits-v3, `docs/plans/splits_v3.md` §5)

| Date | ML track (Prajval + Sonnet high) | This build (Sonnet medium / high; Opus for the review) |
|---|---|---|
| 31 Oct | (real-message freeze already done 30 Oct) | Prajval approves D29 and answers section 9; W1 starts |
| 1 Nov | bucket-4 labelling, Phase B go / no-go, B1 build | W1, W3 |
| 2 Nov | review, freeze splits-v3, Kaggle runs | W2 |
| 3 Nov | calibration, gates G1-G5 on v3 val | W4, W5's val gate (splits-v3 val, incl. POOL-val; **no v3 val by the end of 3 Nov = hooks ship OFF**), W6 |
| 4 Nov | test once, write-up, app switch D28 (fixtures regenerated once, after W1 / W2) | W7, W8; **message path frozen at the end of 4 Nov** |
| 5 Nov | `eval_real.py --final`, once, on the shipped router | only SHOULD items that do not touch the message path (W9, W13, W10, W11 + W12) |
| 6 Nov | deliver | deliver |

**Why the message path freezes on 4 Nov:** `eval_real.py --final` scores `router.analyse`. The UP hooks (W5) change it; if they landed after the
real-test run, the reported real numbers would not describe the shipped app. Every non-message engine (payments, apps, email rules, tabs) can
still land on 5 Nov because the real test set never reaches it.

### 8.3 Val gate for the message hooks (pre-registered, val only)

On splits-v3 val (all sources, including POOL-val's real genuine messages; never TEST, never `real_test_v1.csv`, never anything under
`data/real/`), counts only: fires by label and source for UP16, UP17, UP18; verdict changes. Ship a hook ON if it fires on **at most 2 genuine
val rows and 0 genuine POOL-val rows**, each read and accepted as a documented false positive; otherwise it ships OFF and the limit goes into
BUGS.md. Also run `tests/tricky_inputs.py`, the 363 contract inputs and the demo set (levels must not change except where a hook fires, each
listed).

**Fallback (approved 2026-10-30, D29):** if splits-v3 val is **not available by the end of 3 Nov**, or a hook **fails** the gate, that hook
ships **switched OFF**. Mechanism, so that the fallback needs no action: the W5 code lands with every hook off by default (`config.PAYMENT_HOOKS`
empty; `SHIELD_PAYMENT_HOOKS=0` also forces all off), and a hook is switched on only by a separate commit that cites the gate report and is
made by the end of 4 Nov. No gate report, no switch-on commit: the hooks stay off, `router.analyse` is unchanged, and the limit goes into BUGS.md.

### 8.4 Cut-line, ranked (ship in this order; stop where the time ends)

1. W1 contract v6 + `/api/check` — MUST
2. W2 tabs + Link tab — MUST
3. W3 + W4 payment text checks, payment-proof answer, Payment tab — MUST
4. W5 message hooks (val-gated, by 4 Nov) — MUST
5. W6 app lookup + the no-upload questionnaire — MUST
6. W7 email-lite — MUST
7. W8 docs and limits — MUST
   **— MUST line (~36 h) —**
8. W9 NPCI handle file (the official page was fetched once on 2026-10-30, section 11) — SHOULD
9. W13 email headers — SHOULD
10. W11 APK upload — SHOULD. Not started after noon on 5 Nov: untrusted-file parsing is not shipped without a review
11. W10 QR decode + Screenshot QR path — SHOULD
12. W12 fresh-session review of the upload / worker code — **required if W11 lands** (W11 does not ship without it); it also covers W10 if
    W10 has landed
    **— SHOULD line —**
13. LATER: W19, W16, W15, W17, W18, AP14.

If time runs short inside the MUST block, cut from the bottom: W7's EM5, then W6's questionnaire wording, never W1, W5's gate, or W8.

**Build order (approved 2026-10-30):** W1, then **W5** (the message path freezes at the end of 4 Nov, 8.2), then W2, W3, W4, W6, W7, W8, then
the SHOULD items in the order above. One commit per work item; nothing is pushed without the user's word. W5 does not need W3: the hooks
import R2's helpers (`rules._near`, `rules._negated`, `rules._RECEIVE`) and live in `src/shield/transactions/text_rules.py`, the first file of
that package.

---

## 9. Needs Prajval

**Answered 2026-10-30:** every item below has an answer recorded in section 11 (the approval record). The list is kept as asked, so the
questions and the answers can be read side by side.

Decisions (the recommended option first; these are D29.1-D29.14 in the decision log):

1. Approve the scope and the cut-line (8.4).
2. Base level for a payment input with no rule hit: **Can't judge** (recommended: only a payment app can show who owns an ID), or No warning
   signs found.
3. Floors of the message hooks UP16-UP18: **Suspicious**, consistent with R2 (D16), or Likely scam.
4. AP1: a verified catalog match is **No warning signs found and skips AP4-AP11** (recommended, reason in 4.5), or permission rules always run.
5. APK size cap **50 MB**; app bundles (.xapk / .apks) out of scope.
6. Parse uploads in a **short-lived child process** instead of strictly in-process (macOS refuses `setrlimit`, measured 2026-10-30).
7. New dependencies (4.3), installed with `--no-deps` where stated: androguard 4.1.4, apkInspector 1.3.7, asn1crypto 1.5.1, cryptography 50.0.2,
   cffi 2.1.1, pycparser 3.0, lxml 6.1.3, loguru 0.7.3, colorama 0.4.6; zxing-cpp 3.1.1.
8. Report schema **"6"** (`input`, `details`), landed before the D28 switch on 4 Nov.
9. Attachment types beyond the brief's list: `.svg`, `.lnk`, `.js`, `.vbs`, `.scr`, `.msi`, `.img`, `.vhd`, `.rar`, `.7z`, `.jar`, `.bat`, `.cmd`,
   `.ps1`, macro Office files (`.docm`, `.xlsm`) as Suspicious: yes / **no for 6 Nov** (recommended: keep the brief's list).
10. Email windowing: approve the protocol in 5.2 and **keep head-only for 6 Nov** (recommended).
11. The "Did you start this payment?" question in the Payment tab: **yes** / no.
12. Meter for inputs without a text score: **keep D24's band floor** (recommended for 6 Nov) or show the zone without a number.
13. The free-mail list in 5.3: approve or edit.
14. The Screenshot tab and the paste box's screenshot button: **keep both** (recommended) or one only.

Values (never guessed; each needs a source URL or method and a date):

15. **NPCI UPI handle list** with the app / bank behind each handle: the official npci.org.in page that lists them (URL) and the date read, or
    your OK for a one-off plain fetch of the page you name. The 80 handles in `pii.UPI_HANDLES` have no recorded source or date.
16. **Catalog values via adb** (4.6): package, publisher (Play Store page), version, certificate SHA-256, date, for the target apps; the 12 MUST
    apps first.
17. Whether NPCI's discontinuation of person-to-person collect requests (reported for 1 Oct 2025) is in force: the circular's URL and date. If it
    is, a collect request from a personal ID is itself a red flag (a new rule, not designed in until confirmed).
18. Whether cybercrime.gov.in offers an official citizen page to check a suspect UPI ID or number: URL and date. If it does, the payment advice
    links to it (no API call).
19. The official Bharat QR / EMVCo merchant QR specification, if Bharat QR support is wanted (LATER).
20. The word lists (3.2, 4.5): `GOVT`, the `PAY_APPS` exclusions (names that appear in ordinary shop QRs), and additions such as state
    electricity boards and couriers for app labels.
21. The native speakers for the Hindi / Kannada review of the new lines (D15), when W17 starts.

---

## 10. Hard rules: how the design keeps them

| Rule (brief / CLAUDE.md) | How | Flag |
|---|---|---|
| Rules raise-only; levels unchanged | every UP / AP / EM rule is a floor; same four levels; Promotional unused | AP1's positive gate and UP20's NW -> CJ, both flagged in 2.4, approved 2026-10-30 |
| D5 language cap and existing message rules unchanged | the cap and R2 / OTP / A1-A12 / G1 / R1-R10 untouched; the UP hooks are new rules beside them | the hooks change message verdicts: val-gated, merged before the real-test run |
| No URL visited except through `net.py`; no page loads | QR / email links through the existing ladder; APK links offline only; Play Store links parsed, never fetched | none |
| No APK downloaded, installed, executed or emulated; no sandbox; no malware samples | static parsing only, synthetic test APKs | the adb steps copy a **genuine app from Prajval's own phone** to read its certificate, at his request; deleted after, never committed |
| No new network endpoint | none added; `net.py` unchanged | none |
| Uploads never stored | in-memory reader, pipe to the worker, write / tempfile guards, tests ST | "in-process" became a child process (D29.6) |
| Real test set and frozen files untouched; `model_text` the only preprocessing; no training | no data or model step; the val gate reads val only; windowing lives inside the scorer on `model_text`'s output and is LATER | none |
| Facts only from official sources or Prajval | three provenance files, fail closed; every value in section 9 | `pii.UPI_HANDLES` cannot be reused as a fact list |

---

## 11. Approval record (2026-10-30)

Prajval approved D29 on 2026-10-30 with the changes below. Each is folded into the section named.

**Fixes to the proposal (from the read-through):**

1. AP11 matches **whole tokens** only; a file-name hit is **Suspicious**; **Likely scam only from the questionnaire answer** (invitation, bill /
   challan, KYC / bank update, parcel / courier, reward / cashback / refund). Test AT61: `Kirana Billing.apk` is not flagged by AP11 (4.5, 7.3).
2. The watchdog limit is written per platform (`ru_maxrss` is bytes on macOS, kilobytes on Linux; other platforms refuse to start the worker,
   AT62); AT56 and ST01-ST10 are worded as **Python-level** checks that do not cover native libraries (4.2, 7.3, 7.5).
3. UP15 needs **no other rule** to have fired (any rule, R2 and the OTP rule included); test PT47b (3.3, 7.2).
4. W5 fallback: if splits-v3 val is not available by the end of 3 Nov, or a hook fails the val gate, the hooks ship **OFF**; the code lands
   off by default and only a gate-citing commit switches a hook on (8.1-8.3).

**Decisions:**

| # | Decided |
|---|---|
| D29.1 | MUST (W1-W8) approved. SHOULD order: **W9, W13, W11, W10, W12**; W12 is required if W11 lands (8.4). Build order: W1, then W5 |
| D29.2 | Can't judge for a payment input with no rule hit; No warning signs found only for a request the user says they started (UP15) |
| D29.3 | UP16-UP18 floor at Suspicious |
| D29.4 | A verified catalog match makes an APK No warning signs found and skips AP4-AP11 |
| D29.5 | **50 MB**, and the Can't judge reason says why (4.2); app bundles out of scope |
| D29.6 | Uploads parsed in a short-lived child process per file |
| D29.7 | The dependency set of 4.3 |
| D29.8 | Report schema "6", landed before the D28 switch on 4 Nov |
| D29.9 | No attachment types beyond the brief's list for 6 Nov |
| D29.10 | Windowing protocol approved; head-only for 6 Nov |
| D29.11 | "Did you start this payment?" in the Payment tab: yes |
| D29.12 | D24's band floor kept for inputs without a text score |
| D29.13 | Free-mail list **shown for review with Indian providers added** (5.3); final OK pending (needed by W7 only) |
| D29.14 | Keep both the Screenshot tab and the paste box's screenshot button |

**Values:**

- **NPCI circular on P2P collect requests** (Prajval's reference: NPCI/UPI/OC/220/2025-26, 29 Jul 2025, effective 1 Oct 2025, person-to-person
  collect discontinued): OK given to fetch the official PDF from npci.org.in **once**, record URL + date, and use it in the UP13 / UP14
  wording. If the official text differs from that reference, the work stops and Prajval is told. Result: pending the fetch.
- **cybercrime.gov.in "Report & Check Suspect -> Check suspect (mobile, email etc)":** a **link** in the help row, **for UPI results only**.
  The app never queries the page and never sends the ID; nothing is fetched to build the link. The exact page URL is to be copied by Prajval
  from the browser (not guessed, not fetched).
- **NPCI UPI handle list:** OK given to fetch the official NPCI page **once**; record URL + date (the snapshot is kept so W9 does not fetch
  again). Result: pending the fetch. BUGS.md now records that `pii.UPI_HANDLES` has no source.
- **adb catalog:** Prajval, later; 6 apps first, only apps already on family phones (4.6, W14).

## Sources (read 2026-10-30)

- PyPI JSON API, `https://pypi.org/pypi/<name>/json` for androguard, apkInspector, asn1crypto, cryptography, cffi, pycparser, lxml, loguru,
  colorama, zxing-cpp, opencv-python-headless (considered, not chosen: larger), pyaxmlparser (considered: last release 2024-03-20).
- androguard 4.1.4 wheel, source read without installing (scratch directory): `androguard/core/apk/__init__.py` (imports; v1 SignerInfo
  verification; v2 / v3 parsing without content-digest recomputation), `androguard/core/androconf.py`,
  `androguard/core/api_specific_resources/aosp_permissions/permissions_36.json` (permission names).
- Measured on this Mac: `resource.setrlimit` for `RLIMIT_AS`, `RLIMIT_DATA`, `RLIMIT_RSS` raises `ValueError` (Darwin 25.6.0, Python 3.13.3).
- `data/final/apps.csv`: 7,299 rows; val 459 benign / 244 malware; 86 permission strings (counts only).
- Repository files listed in section 1; decisions R2, D16, D23, D24, D27, C2, D5 / D6, D11, D17, D-a; `docs/plans/splits_v3.md` §5.
- The core payment fact ("receiving money never needs a UPI PIN, a QR scan or an approved request"): the user's brief (2026-10-30) and decision
  R2 (2026-10-17).
