ARCHITECTURE.md is updated once, after D1-D18 are all decided. Until then this log is the source of truth for decisions.

# Decision log

| ID | Decision | Date | Detail file |
|---|---|---|---|
| D1 | Run locally (Mac + LAN, use a phone hotspot for demos/study); Hugging Face Spaces (Docker) later | 2026-10-10 | - |
| D2 | Live checks on: RDAP + local blocklists; Safe Browsing only with a key; crt.sh fallback only | 2026-10-10 | - |
| D3 | Shortener expansion only on button press | 2026-10-10 | - |
| D4 | No % shown; 4-zone meter that can never contradict the verdict; "Why this score" + "Website details" panels; exact score in Details | 2026-10-10 | - |
| D5 | Two targets: Likely scam <= 1%, Suspicious+ <= 5% of hard-legit, counted per independent template, on the final verdict; recall floor 0.90 for Suspicious; ship gate 10%; Can't-judge <= 10% on hard-legit; language cap (text model alone max Suspicious in hi/kn/Hinglish until >= 150 real-dev templates in that language). Design targets until real-dev exists. D7 target: 400+ independent English hard-legit templates, ~150 per language | 2026-10-10 | [D5_operating_point.md](D5_operating_point.md) |
| D5b | Brand promos separated as promo_gray (not scam, not benign); relabel in splits-v2 | 2026-10-10 | [D5_operating_point.md](D5_operating_point.md) |
| D5c | Dispute button stores nothing by default; opt-in study/volunteer mode saves masked text + verdict + user label locally | 2026-10-10 | [D5_operating_point.md](D5_operating_point.md) |
| G1 | Gambling: a domain in the `gambling_spam` class (or the gambling lookup) gives the verdict **Suspicious** with its own reason (gambling / betting promotion), never "scam". Tranco popularity never lowers it. Built 2026-10-17 (`src/shield/links/gambling.py`); platform roots match only at host level. Top-10k review 2026-10-17: 8 hosting roots host-level only, 13 non-gambling (ISPs, CDNs, onelink.me, okta.com, media, 4 sports-score sites) exempt; 96 operators stay flagged (`GAMBLING_PLATFORM_ROOTS`, `GAMBLING_NOT_GAMBLING` in `gambling.py`). 150m.com added to hosting roots 2026-10-17 | 2026-10-10 | - |
| D9 | Frontend: React + Vite + Tailwind + Motion; FastAPI serves the `Report` contract as JSON; Gradio is retired once the new UI reaches parity. Replaces the HTMX + Jinja plan in ARCHITECTURE §3. All assets bundled or self-hosted (no CDN or Google Fonts at runtime) | 2026-10-17 | [design/README.md](../design/README.md) |
| V1 | Visual direction: dark stage with a dotted 3D globe (India highlighted with its official outline), transparent glass panels, bento result layout, radar meter with labelled blips (meter option 8b). Keeps D4: no percentage, meter never contradicts the verdict, grey Can't judge. Approved prototype: `docs/design/prototype-globe.html` | 2026-10-17 | [design/README.md](../design/README.md) |
| G2 | Globe animation is a simulation weighted by real published rankings (World Cybercrime Index 2024; Cloudflare DDoS report Q4 2025), always labelled "not live". Live data via the Cloudflare Radar API (backend, token, non-commercial licence) is a later option | 2026-10-17 | [design/README.md](../design/README.md) |
| R2 | PIN-to-receive rule (receiving money never needs a PIN) forces >= Suspicious: a UPI PIN / MPIN asked for (enter, type, put, give, share, approve ...) near a receive-money cue (receive, get the refund, cashback, collect request ...) is a red flag like the OTP / PIN / CVV rule; `rules.pin_to_receive`, evidence `rule.pin_to_receive`; Report schema unchanged | 2026-10-17 | - |
| D19 | Screenshot input = local Tesseract OCR through stdin / stdout (**Tesseract 5.5.3**, Leptonica 1.87.0; languages `eng+hin+kan`, `--psm 6`; `brew install tesseract tesseract-lang`); the user confirms the text before analysis; the image is never stored or sent anywhere. `POST /api/ocr` (multipart field `image`; PNG / JPEG / WEBP by magic bytes, <= 8 MB, <= 6000 px) -> `{text, lines, dropped, ms}`, read in memory by `shield/ocr/reader.py` (Pillow: EXIF, grayscale, invert if dark, no upscaling (x1 measured better than x2); no temp file, no pytesseract) and `shield/api/upload.py` (a hard-capped in-memory multipart reader, because Starlette spills uploads over 1 MB to a temp file); the text goes back to the page, which posts the user-checked text to the unchanged `/api/analyse`; Report schema "2" unchanged. Known limit: the rupee sign is mostly misread or dropped (BUGS.md), so the UI must tell the user to check amounts. Part B = the UI | 2026-10-17 | - |
| D19b | Two narrow OCR link repairs in `shield.ocr.reader.repair_links`, next to the existing `https:/Awww.` one (2026-10-17). **(1) Spaced colon:** `https :/Awww.bet365.com/` and `http : /Aexample.in/x` become scheme + `://`. Only when a space sits next to the colon, a `www.` or a lower-case host (a dot, an alphabetic ending) follows at once, and the single stray character is one Tesseract draws for a slash (`A ( [ | ! \`); a capitalised host such as `https :/Example.in` therefore keeps its `E`. It stays narrow because the unspaced `https:/sbi.top/x` is still left alone (one slash and a host cannot be told from a misread inside a name), and a bare `https :/A` or `ratio 3 :/A` is never rewritten. **(2) Space after a dot inside a host:** `https://t. jio/TIOCPN/x` becomes `https://t.jio/TIOCPN/x`. Only inside a token that already starts with `scheme://`, only when 2-24 lower-case letters (dotted names allowed) follow the space and then `/` or the end of the token; and, added beyond the first spec, without a `/` only when the part before the space is a single label (`https://t.`, `https://www.`), so a sentence-final link followed by a lower-case word (`https://ok.com. then pay`) is not glued into `ok.com.then`. Both stay narrow for the same reason as the first repair: a wrong-but-plausible host is worse than a visibly broken one, because the user checks the OCR text and a silent edit of a host would hide the error. **Not repaired** (seen on 16 re-encodings of the real Jio screenshot x 2 Tesseract builds x 2 language sets, 14 of 64 reads of the final code, and in `reports/ocr_sweep.md`): the dot read as a space (`t jio`), `t.` read as `1,`, the colon dropped (`https//`) or read as `t` (`httpst//`), `w` read as `v` (`Avww`), a space after the first slash of the path, and a link wrapped over two lines; earlier runs also gave `https‘//` and `htt ps://`. In each a repair would guess a host or a path. Tests: `tests/test_ocr.py` O10 | 2026-10-17 | - |
| D20 | Hindi machine translations: BORDERLINE vs the 90% gate (Q1 91.5% on the 50/50 sheet, ≈88% re-weighted to the 15%-scam pool, CI ±12). Failures concentrate on benign OTP/bank alerts. Accepted as TRAINING augmentation only, conditional on dropping the 4 known-bad rows (docs/spotcheck/exclude_v1.txt) and on the D21 digit/URL check. The brand check is report-only. Not evidence of real-Hindi performance (≈27% re-weighted judged too formal). Any Hindi metric labelled 'translated'. MuRIL/splits-v2 still gated on the Kannada spot-check. | 2026-10-17 (reworded 2026-10-18) | [spotcheck_hi.md](../../reports/spotcheck_hi.md), [exclude_v1.txt](../spotcheck/exclude_v1.txt) |
| D22 | **Built (user request); tightening B (fear-cue families + plain passwords as hard-risk) accepted and built, tightening A rejected, 2026-10-18. UI input removed (product decision, 2026-10-18); backend kept dormant for future screenshot sender extraction.** The sender as a signal. An optional "Sender" input is classified as a TRAI DLT header with or without its P / S / T / G type letter (`dlt`), the 6-character header alone (`dlt_bare`), an Indian mobile number, or other (`shield.messages.sender.parse_sender`). A rule layer runs after the existing pipeline (`shield.core.sender_rule`): a promotional header (P) with no hard-risk signal gives the new level **Promotional**; any other registered header with no hard-risk signal caps the level at Suspicious; a hard-risk signal blocks all softening and adds a "registered IDs can still be misused" reason; a mobile number adds a reason at Suspicious and above and never changes the level. A header is a hint, not proof. Models, thresholds, data and splits are unchanged; Report schema "3" (`sender` block, level `promotional`); with no sender the Report is unchanged except `"sender": null`. Decision table, evidence and limits: section below | 2026-10-18 | [D22 section below](#d22-the-sender-as-a-signal) |
| D21 | **ACCEPTED (digit/URL only), not yet applied.** Preservation check for translated rows. **Digit and URL clauses = a training-only drop rule:** a translated row is left out of training if a digit run or a URL of its English parent is missing from the translation (applied when translated rows are ingested at the splits-v2 rebuild; whether dev follows train is decided then; test-split translated rows stay as built). **The brand/sender clause is NOT a drop rule:** it becomes a report from a curated brand list; no list exists yet (future work), so no brand check runs until one does. Why: measured, the digit and URL clauses flag 0 train/dev rows and 1 parent (2 rows, 1 Hindi + 1 Kannada, no split yet): an OTP code cut in two by `protect.py`'s time pattern (BUGS.md); the brand clause drops 41-60% of train/dev rows and 58-84% of the no-split benign pool, flags 43-67% of rows the reviewer judged fine, and catches 1 of the 4 known-bad rows (default) or 3 of 4 (strictest), mostly for the wrong token | 2026-10-18 | [D21_preservation_filter.md](D21_preservation_filter.md) |

---

## D22: the sender as a signal

**Status: built 2026-10-18, at the user's request** (request + addendum for the bare header). **UI input removed (product decision, 2026-10-18); backend kept dormant for future screenshot sender extraction.** Users won't type a sender, so the field was clutter: the page no longer has the sender field, its hint, the P / S / T / G explainer or the sender chip, and never sends a sender. The parser, the decision table, `threats.py`, the optional `sender` field of `POST /api/analyse` and their tests are unchanged, and the level Promotional stays in the schema (reachable only through the API). See Frontend below. Rule layer only: no model was retrained, no threshold, data file or split changed (`data/final/split_map.csv` SHA-256 still `89eec6f1…7c5`, model file hashes unchanged).

**Why.** A real Jio promo SMS ("You've earned Lifetime Free Kiwi UPI Credit Card … Claim now: https://t.jio/… T&C*") is rated Likely scam: the text model scores it 0.928 (Likely scam from 0.656), with the cues "claim now" and "upi". The wording alone cannot tell a genuine offer from a scam that copies offer wording. Who sent it can.

### The TRAI format

Since the TCCCPR amendment of 12 February 2025 (the suffixes appeared on phones from about 6 May 2025), a business SMS header reads `[prefix]-[header]-[type]`, e.g. `JM-JIOCPN-P`, `VM-HDFCBK-T`, `KA-ZOMATO-S`:

- **prefix:** 2 letters for the operator and circle that delivered it (`AD-` = Airtel, Delhi);
- **header:** the 6-character ID the business registered on the DLT platform (letters for service / transactional; the older promotional headers were 6 digits);
- **type:** `P` promotional, `S` service, `T` transactional, `G` government. It is added automatically from the category of the registered message template.

Older messages show no type letter (`AD-SBIINB`), and some Android phones show only the header (`JIOCPN`; the user's own phone, 2026-10-18). Sources: TRAI press release 11/2025 (not opened here), MediaNama (May and July 2025) and Storyboard18 on the suffixes, Exotel's and MSG91's DLT documentation on the 6-character header and the 2-letter prefix. The secondary sources disagree on whether the 6 characters include the prefix. The parser follows the displayed form, prefix + dash + 6.

### Parser (`parse_sender`, pure, tests P1: 46 cases)

Strip. Empty → `none`. More than 40 characters → `other`. Unicode dashes become `-` and whitespace runs one space; anything still non-ASCII → `other` (a Cyrillic `Ј` or a Devanagari digit never passes).

| kind | rule | examples | why exactly this |
|---|---|---|---|
| `dlt` | `[A-Z]{2} ?- ?[A-Z0-9]{6}( ?- ?[PSTG])?` on the upper-cased string | `JM-JIOCPN-P`, `jm-jiocpn-p`, `AD-SBIINB` (suffix None), `VM-612345` | the prefix is always 2 letters; headers are 6 characters, and digits are allowed because the old promotional headers were numeric (prefix + dash already make the shape unambiguous); only TRAI's four letters count (`JM-JIOCPN-X` is other); a space beside a dash is tolerated because people retype what they see |
| `dlt_bare` | `[A-Z0-9]{6}` with at least one letter, **case-sensitive**, no spaces or dashes | `JIOCPN`, `HDFCBK`, `JIO123` | phones print headers in capitals, while a person typing a brand types `Amazon` / `Jio`, so case separates a header from a word (`Amazon` is 6 letters and stays other). At least one letter, because 6 bare digits are as likely a shortcode or an OTP. Known overlap: `AMAZON` in capitals counts, which is also how a phone shows AX-AMAZON-S. The input field has `autoCapitalize="off"` so a phone keyboard does not turn a typed brand into capitals |
| `mobile` | `(\+91\|91\|0)?[6-9][0-9]{9}` on the string with spaces and dashes removed | `+91 98765 43210`, `09876543210`, `98765-43210` | the 6-9 start is India's mobile range; 5-digit shortcodes and 1800 numbers are not in it |
| `other` | anything else that is not empty | `56767`, `Jio`, `Amazon`, `jiocpn`, an email, garbage, 41+ characters | |

### Hard-risk signals (existing signals of `analyse()`'s result only)

| key | signal | the misuse reason says |
|---|---|---|
| `otp_request` | `r["cred_request"]`, the OTP / PIN / CVV rule (`rules.cred_requests`). **Since tightening B it also covers plain passwords:** password / passcode, alone or after login / net banking / internet, online or mobile banking / bank / account / UPI / email; UPI PIN and MPIN were already covered. Same verbs and negation, so "Never share your password with anyone" and "Your password was changed successfully" are not requests. The Report shows a password hit as "Asks you to share a password" (tag "Password request"); every other hit keeps its old title | it asks for your OTP, PIN, CVV or password |
| `pin_to_receive` | `r["pin_to_receive"]`, rule R2 | it asks for your UPI PIN to receive money |
| `phishing_link` | a link the URL model rates at its scam level: kind `model`, `base_level` 2 (`threshold_high`) | its link looks like a phishing link |
| `lookalike_link` | a free-hosted link with a brand or scam word in its name: kind `free`, `base_level` 1. **Added beyond the request:** free-hosted links never reach the URL model, so without it `sbi-kyc-update.weebly.com` from a P header would be softened | its link is a lookalike site on free hosting |
| `gambling` | a G1 match on any link | it links to a gambling or betting site |
| `legal_threat` | **tightening B**, `shield.messages.threats`. *Reused:* the isolation tactic's "digital arrest" and "national security"; the authority tactic's law-enforcement words as agencies. *New:* the threat: arrest(ed), (non-bailable / arrest) warrant, FIR, legal action / proceedings / notice / consequences / trouble (also "to avoid legal consequences": "avoid" is in the shared negation list, so the avoid-forms are matched whole), court notice / summons / case / order, summons, a case registered / filed / booked / lodged, money laundering; a seizure / complaint / investigation / illegal goods / drugs counts only with an agency (police, CBI, ED in capitals, NCB, customs, cyber crime, court ...) or, for a seizure, a parcel in the same sentence. A bare agency name never counts ("Report fraud to the cyber crime police at 1930") | it threatens arrest or legal action |
| `secrecy` | **tightening B**. *Reused, unchanged:* the isolation tactic (tactics.TACTICS["isolation"] + tactics._SECRECY) via `tactics.tactic_matches()`, with that tag's own exemptions (an OTP advisory's "Do not share it with anyone", "delete this message" in an email disclaimer): tell no one, don't tell / inform / disclose ... anyone, keep this confidential / secret / between us, don't contact your family / bank / police, delete this message, don't hang up / disconnect, stay on the line / call, plus the unchecked Hinglish / Hindi / Kannada forms. *Left out:* the WhatsApp / Telegram cues ("join our WhatsApp channel" is a genuine promo), a bare "secret" ("secret sale") | it tells you to keep it secret |
| `cutoff_threat` | **tightening B**. *Adapted from* the urgency tactic's "will be blocked / suspended / deactivated / disconnected ..." and "avoid penalty / disconnection / suspension". *New:* the threat must be about to happen ("will / may / is going to be ...", "is being blocked") and name the service in the same sentence, within 80 characters before it (account, SIM, card, connection, electricity, power, service, number, wallet, UPI, KYC, PAN, Aadhaar, net banking ...). An after-the-fact "has (now) been blocked / put on hold" counts only with an update / verify / KYC / PAN / click demand in the message ("To unblock, call 1800 ..." does not). Also "... will result in / lead to (account) suspension", "suspension of your account / SIM ...", and a KYC that is pending / expired / not updated when the message has a deadline (today, tonight, within N hours, by a date ...). "cancelled" is not a verb here (orders get cancelled) | it threatens to block or cut off a service |
| `earning_promise` | **tightening B**, all new (no tactic covers it): guaranteed (N%) returns / profit / income; N% returns every day / week / month; double / triple your money; a stock / trading / crypto / forex tips (or signals) group or channel; task-based earning ("VIP task", simple / daily tasks + earn, earn per like / review / video, liking / subscribing to videos + earn); work from home or a part-time job + earn / income / salary; "earn Rs N per day / hour" | it promises guaranteed or easy earnings |
| `payment_demand` | one of 17 cues of the payment tactic that **demand** money: processing / registration fee, customs duty, challan, penalty, send money, wire, western union, gift card, bitcoin, crypto, usdt, collect request, approve (the) request, scan (the) qr. The whole tactic is searched again without `tactic_tags()`' cap of 4 cues (test H2). Left out because genuine promos and bank alerts mention them: pay, payment, transfer, deposit, upi, wallet names, refund, cashback, recharge, pin, otp, cvv, card / account number, ifsc, a masked UPI ID or account, an amount (val SMS-length rows, benign / scam: otp 45 / 0, a masked account 8 / 53, pay 14 / 45, cashback 10 / 14; kept: processing fee 0 / 5, gift card 0 / 2, challan 5 / 7) | it asks for a payment or fee |

### Decision table (`shield/core/sender_rule.py`, last step of `router.analyse()`)

| sender | hard-risk signal | level | reason (place among the 3) | evidence |
|---|---|---|---|---|
| `dlt` + `P` | none | **Promotional**, whatever the text level was | "Sent from a registered business ID (promotional)" (**first**) | `sender.registered`, reassuring; `model.text` and the tactics become neutral (neutral titles) |
| `dlt` + `S` / `T` / `G` / no suffix | none | **capped at Suspicious**: Likely scam → Suspicious; Suspicious, No warning signs and Can't judge stay | "Sent from a registered business ID (service / transactional / type unknown)", "Sent from a registered government sender ID" (in a free place, see below) | `sender.registered`, reassuring |
| `dlt_bare` | none | capped at Suspicious, as `dlt` without a suffix (**not** Promotional: that needs the P) | "Sent from a registered business ID (type unknown)" (in a free place) | `sender.registered`, reassuring |
| `dlt` or `dlt_bare` | any | **unchanged** (no softening) | "Registered sender, but <the risky thing>. Registered IDs can still be misused." (in a free place; the first signal in the table above is named, the detail lists all) | `sender.registered_misused`: caution on a warning verdict, neutral on a verdict without one (a payment demand alone sets no level) |
| `mobile` | not checked | unchanged | at Suspicious or Likely scam only: "Sent from a personal mobile number; businesses use registered IDs like JM-JIOCPN-P" (in a free place) | `sender.mobile`, caution |
| `other` / `none` | not checked | unchanged | none | none; `none` → `Report.sender` null |

**Reason places (changed with tightening B).** The sender reason never pushes a warning out of the three reasons. The reasons without a sender come first and are unchanged, so the wording model's "very similar to known scam messages" (always the last warning) stays where it was. The sender reason is added only into a free place (fewer than three warnings), or first on Promotional, where the message carries no warning of its own. With three warnings already there, it is shown under the sender chip, right below the verdict word (`frontend/src/lib/sender.ts` `senderNote`). So it is always on screen, but not in the "Why" list. Why this and not "the sender reason takes the third place": the reasons explain the verdict and the warnings carry it; the sender is context next to the verdict. Where the sender IS the verdict (Promotional) it is the first reason. Checked by contract A17 (all 363 inputs x 8 senders) and `test_sender.py` R1.

Advice for Promotional (`ADVICE[Level.PROMOTIONAL]`): "This is likely genuine marketing from a registered business." / "Only click the link if you expected this offer." / "Never share an OTP or PIN, even with a registered sender."

A Promotional Report may still show a link that the URL model rates Suspicious, as caution in the link panel and as a radar blip, because only the model's scam level is a hard-risk signal. Contract check A7 allows that; it allows no caution on the message itself and no danger anywhere. A8: no Likely-scam child, no gambling category, no rule hit.

### Why the sender is a hint, not proof

- It is typed by the user, and nothing checks it. It can be mistyped, guessed, or copied from a different message.
- A registered header proves that a registered business sent the SMS. It does not prove the content is honest: headers and their sending accounts get misused.
- It cannot be checked offline or without a network call, and this checker makes none.

So a header only softens a message with **none** of the hard-risk signals. Only P can go below Suspicious, and only to Promotional, which still tells the user to click only what they expected and never to share an OTP or PIN. Every hard-risk signal blocks the softening and says why (test H1, each signal alone, with P, T and bare).

### Why a mobile number does not raise the level (yet)

- No sender data has been measured: `messages.csv` has no sender column.
- Genuine messages come from personal numbers all the time: friends, small shops, delivery agents.
- Raising the level on it would add false alarms of unknown size to every chat message.

It therefore only adds a reason where the verdict is already a warning (test D12: on all 14 demo messages the level with a mobile sender equals the level without). Revisit once a real-dev set has senders, never on the final test set.

### Measured exposure (val what-if; the test split was not used)

No message in the corpus carries a sender, so this measures only what the rule *could* do if a registered header were given, not what it does on real traffic. Val, 5,267 rows:

| | rows | with a hard-risk signal | flagged without a sender | of those, no hard-risk signal (could be softened) | Likely scam with no signal (a T / S / G / bare header caps them) |
|---|---|---|---|---|---|
| scam | 1,152 | **96 (8.3%)**: payment demand 54, phishing link 41, PIN to receive 1; the OTP rule fires on 0 val scams | 1,097 | **1,001 (91.2%)** | 950 |
| scam, SMS-length (≤ 320 chars) | 460 | 30 | 446 | 416 (93.3%) | 401 |
| benign | 4,115 | 62 (1.5%): payment demand 41, phishing link 12, OTP rule 9 (the delivery-PIN family) | 258 | 231 | 44 |
| benign, SMS-length | 1,092 | 14 | 95 | 82 | 27 |

The 62 benign rows with a signal would get the misuse reason under a registered header.

The table above is the first measurement (hard-risk set of 2026-10-18 morning, commit 330ea1d). It showed the softening rests almost entirely on the header being genuine: a mistyped or misused P header would turn about nine in ten flagged scams into Promotional, including three of the ten demo scams (d01 digital arrest, d05 electricity, d07 investment).

**User decisions (2026-10-18):**
- **Tightening A** (Promotional only lowers Suspicious): **rejected**. It would make the Jio case impossible (the Jio promo is Likely scam on its wording).
- **Tightening B** (fear tactics as hard-risk): **accepted**, built as the four families `legal_threat`, `secrecy`, `cutoff_threat`, `earning_promise` in the hard-risk table above, plus plain passwords in the OTP rule.

**After tightening B** (same val rows, before = commit 330ea1d, after = this version; measured with `rules.py` of 330ea1d loaded side by side):

| | before | after |
|---|---|---|
| flagged val scams a P header would soften | **1,001 of 1,097** | **901 of 1,097** (100 now blocked) |
| SMS-length (≤ 320 chars) | 416 of 446 | 338 of 446 |
| `india_fraud_final` (Indian SMS scams) | 137 (88 distinct templates) | 63 (42 distinct templates) |

The 100 blocked, by family (a row can carry several): cut-off threat 56, legal / arrest threat 29, earning promise 18, secrecy 3, password request 2. By exactly one signal: cut-off 53, legal 22, earning 14, password 2, secrecy 1 (8 rows carry two or more).

False hard-risk on val benign: **11 newly marked rows, 0 of them SMS-length.** All 11 are long texts (1,900-9,900 characters): legal threat 8, cut-off 1, secrecy 1, password 1. They are news emails about an arrest, business emails mentioning legal action, warrants or a seizure, a compliance job post about money laundering, a "keep it strictly confidential" business email, and an email with "has been disconnected" and a click link. The pattern, in synthetic examples:
- "Police said the suspect was arrested near the station on Monday."
- "If the supplier does not pay by Friday, our lawyers will take legal action."
- "The analyst will review accounts for money-laundering risk."
- "Please keep it strictly confidential until the launch."
- "Your old line has been disconnected; click here to update your new address."

Password rule on val: requests found on benign rows 9 → 10, on scam rows 0 → 2. Exactly one level change, a benign row from No warning signs to Suspicious ("send them copies of the password" inside a long email); 0 scam level changes. The same false-positive class exists for OTPs ("We will send you a new password" counts as a request, like "send you an OTP").

How the patterns were set: written from the user's cue list; then the SMS-length scams that a P header would still soften were read (val only). That reading showed cut-off and legal wordings the first version missed: "is being blocked", "has been blocked ... update your PAN", "put on hold", "will result in account suspension", "to avoid legal consequences", "VIP task". They were added as wordings, not row copies, and re-measured. This is tuning on val; the final test set stays untouched.

Hard-risk cue phrases were tuned on val (dev) SMS scams that slipped through, so the val softening numbers (1,001→901 overall, 137→63 india_fraud_final) are optimistic; the true rate on unseen messages will be higher. Test split untouched.

What the 901 still softenable are:
- 594 `phishing_email` rows: English spam emails (pharma, adult, loans, 419 letters). They never arrive with a DLT header.
- 70 `scam_ham_india` rows, almost all genuine brand promotions labelled scam (JioMart, Airtel, Vi, Shoppers Stop). These are D5b's `promo_gray`, relabel pending, so a P header softening them is right.
- 63 `india_fraud_final` SMS: prize / lottery ("pay Rs 500 tax to receive"), parcel address-update, job-fee and tax-refund scams.
- 59 UK marketing spam SMS (`uci_sms_spam`).
- 47 `ealvaradob_phishing` rows, 47 `scam_dialogue` call transcripts, and 21 `fake_job_postings`.

Of the 901, 338 are SMS-length.

**Residual risk, in one sentence:** a scam sent from a misused or mistyped registered P header is still shown as Promotional when it uses none of the hard-risk wordings, which on val means most prize, parcel-redelivery, job-fee and tax-refund SMS scams.

### With no sender, nothing changes

Method: the Reports of HEAD 1049a1a (before D22) were dumped as JSON for the 363 contract inputs and the 2 probes with the safety-advice cap off and on, the 2 Jio texts, the 14 demo messages, and the HTTP responses of the 56 tricky inputs and the 14 demo messages (`meta.ms` removed): 818 Reports. They were dumped again with the new code three times: no sender argument (HTTP: no field), `""`, and `"   "`. In every new Report, and every child, `sender` must be null and `schema_version` "3"; both are then normalised away (sender removed, version set to "2"). The rest must be equal as parsed JSON. Result: **818 × 3 compared, 0 differences.** In the repo: contract A16 (`sender="   "` == no argument, all 363 inputs, cap off and on), `test_sender.py` E1 (demo set, None / "" / "   "), `test_api.py` T10 (absent / null / "" / "   " over HTTP).

### Contract (schema "3")

`contracts.py`: "Bump SCHEMA_VERSION on any change a consumer would notice". A v2 reader rejects both an unknown level value and an unknown field (`extra="forbid"`; the frontend checks `LEVEL_VALUES` and the version), hence "3".
- `Report.sender: Sender | None`, where `Sender = {kind: dlt | dlt_bare | mobile | other, suffix: P | S | T | G | null, header: 6 characters | null, label}`. The header is set only for `dlt` / `dlt_bare`, a business ID and not personal data. A mobile number is never echoed; `other` is kind only, because it may be a name or an email.
- `Level.PROMOTIONAL = "promotional"`, label "Promotional". It has no rank in `LEVEL_RANK`, like Can't judge: it says who sent the message, not how risky the words are. Internally `router.analyse()` sets `r["level"] = "promotional"`, a string, so comparing it with 0-2 raises an error instead of quietly ranking it.

Privacy: the sender is handled like the text. It lives in memory for one request; `r["sender"]` keeps only kind, prefix, header and suffix. It is never logged (T12 captures every log record and stdout / stderr, including a failing analysis; a live uvicorn at `--log-level debug` plus the Vite proxy, 98 requests: 0 matches for any text, sender or number), never written to disk, and parsing it makes no network call (T7 with a sender).

### Frontend

**Changed 2026-10-18 (product decision): the sender input is removed from the UI.** Removed: the sender field under the message box ("Sender (optional)", placeholder "e.g. JM-JIOCPN-P or +91 98…"), its hint line, the ⓘ explainer of P / S / T / G, and the sender chip on the verdict panel (with the sender line shown under it when it was not one of the reasons). `api.analyse()` sends only `{text}`, so every Report the page gets has `sender: null`; the 363 contract inputs give the same Reports as before (in process, cap off and on, and over HTTP with the page's body: 1,089 Reports, 0 differences).

What stays:
- Promotional verdict (reachable only through the API): blue (`--blue` `#5AB0FF`), price-tag icon, summary "Marketing from a registered business ID. Likely genuine, but not proof.", radar caption "Scanned · registered promotional sender".
- The tip, for awareness: with no sender (always, now), a warning verdict and a link, What to do shows "Check who sent it: real businesses send from IDs like JM-JIOCPN-P; scams usually come from ordinary phone numbers." (reworded so it no longer suggests typing a sender). This is the one piece of what-to-do copy in the frontend: in the backend it would break the empty-sender identity.

Before the removal (built earlier the same day): the field took 40 characters max with no auto-capitals, under it the hint "If your phone shows the full sender ID (like JM-JIOCPN-P), enter that: the last letter tells us the message type.", and the chip showed the API's label and, for a business ID, its header.

### Not built

Reading the sender from a screenshot (BUGS.md).
