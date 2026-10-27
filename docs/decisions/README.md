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
| D20 | **Applied 2026-10-21 at splits-v2** (train only; Hindi 581 rows in; 15 rows excluded: the 4 known-bad + 11 from `reports/translation_suspects.md`; `reports/splits_v2.md`). Hindi machine translations: BORDERLINE vs the 90% gate (Q1 91.5% on the 50/50 sheet, ≈88% re-weighted to the 15%-scam pool, CI ±12). Failures concentrate on benign OTP/bank alerts. Accepted as TRAINING augmentation only, conditional on dropping the 4 known-bad rows (docs/spotcheck/exclude_v1.txt) and on the D21 digit/URL check. The brand check is report-only. Not evidence of real-Hindi performance (≈27% re-weighted judged too formal). Any Hindi metric labelled 'translated'. MuRIL/splits-v2 still gated on the Kannada spot-check. | 2026-10-17 (reworded 2026-10-18) | [spotcheck_hi.md](../../reports/spotcheck_hi.md), [exclude_v1.txt](../spotcheck/exclude_v1.txt) |
| D22 | **Built (user request); tightening B (fear-cue families + plain passwords as hard-risk) accepted and built, tightening A rejected, 2026-10-18. UI input removed (product decision, 2026-10-18); backend kept dormant for future screenshot sender extraction.** The sender as a signal. An optional "Sender" input is classified as a TRAI DLT header with or without its P / S / T / G type letter (`dlt`), the 6-character header alone (`dlt_bare`), an Indian mobile number, or other (`shield.messages.sender.parse_sender`). A rule layer runs after the existing pipeline (`shield.core.sender_rule`): a promotional header (P) with no hard-risk signal gives the new level **Promotional**; any other registered header with no hard-risk signal caps the level at Suspicious; a hard-risk signal blocks all softening and adds a "registered IDs can still be misused" reason; a mobile number adds a reason at Suspicious and above and never changes the level. A header is a hint, not proof. Models, thresholds, data and splits are unchanged; Report schema "3" (`sender` block, level `promotional`); with no sender the Report is unchanged except `"sender": null`. Decision table, evidence and limits: section below | 2026-10-18 | [D22 section below](#d22-the-sender-as-a-signal) |
| D23 | **Built 2026-10-18 (user-approved design + answers).** Safe link checks: each link's background, never its content. Offline: verified .brand TLDs and `.bank.in` (P1), `.gov.in` / `.nic.in` (display), Indian brand lookalikes, IDN homographs, raw IPs, OpenPhish + URLhaus, Tranco, high-abuse TLDs (display). Live, domain only, through `shield/core/net.py` (allowlist, https, no redirects, <= 2 s per call, <= 4 s per message): RDAP, Cloudflare DoH + offline ASN, crt.sh only without an RDAP date, Safe Browsing v5 hash prefixes only with a key, shortener expansion on a button press (implements D2, D3, D4; settles D12, D14, D16 for links). Red flags R1-R9 only raise (R1-R3, R9 -> Likely scam; R4-R8 -> Suspicious); positives P1 / P2 only without a hard-risk signal (P1 caps the message at Suspicious). Report schema "4". Jio promo Likely scam -> Suspicious; demo set unchanged | 2026-10-18 | [D23_link_checks.md](D23_link_checks.md) |
| D24 | **Built 2026-10-18 (user request).** Risk score 0-100 as a warning-sign meter, not a probability (implements the green-to-red meter of D4), plus a calm "Lowered from..." line when a brand-owned link (P1) actually lowers the verdict. `Report.risk_score` (int, inside the band of the FINAL level: No warning signs / Promotional 0-29, Suspicious 30-69, Likely scam 70-100; null for Can't judge): the text score mapped piecewise-linearly through (0 -> 0, Suspicious cut-off 0.423 -> 30, Likely cut-off 0.656 -> 70, 1 -> 100) (TF-IDF head; since D27 the MuRIL head maps in log-odds with its own cut-offs and val-percentile ends), rounded half up, then clamped into the band. `Report.lowered` ({from_level, text}). Report schema "5". No level, threshold, model, data or split changed (0 level differences on 363 contract inputs + 14 demo messages). Also: What to do is a numbered list (no tick boxes); type scale, self-hosted display font behind one `--display` variable, Noto Sans Devanagari / Kannada for Hindi / Kannada text; text colours lifted to WCAG AA | 2026-10-18 | [D24 section below](#d24-risk-score-meter-lowered-from-line-typography) |
| D21 | **ACCEPTED (digit/URL only); APPLIED 2026-10-21 at splits-v2** (`build_text.py`; links = `protect.py`'s url pattern plus every link `textprep` finds, verbatim, because `protect.py`'s TLD list missed `klr.pw`; dropped 1 Hindi + 1 Kannada row; translations are train-only, so no dev / test question remains; `reports/splits_v2.md`). Preservation check for translated rows. **Digit and URL clauses = a training-only drop rule:** a translated row is left out of training if a digit run or a URL of its English parent is missing from the translation (applied when translated rows are ingested at the splits-v2 rebuild; whether dev follows train is decided then; test-split translated rows stay as built). **The brand/sender clause is NOT a drop rule:** it becomes a report from a curated brand list; no list exists yet (future work), so no brand check runs until one does. Why: measured, the digit and URL clauses flag 0 train/dev rows and 1 parent (2 rows, 1 Hindi + 1 Kannada, no split yet): an OTP code cut in two by `protect.py`'s time pattern (BUGS.md); the brand clause drops 41-60% of train/dev rows and 58-84% of the no-split benign pool, flags 43-67% of rows the reviewer judged fine, and catches 1 of the 4 known-bad rows (default) or 3 of 4 (strictest), mostly for the wrong token | 2026-10-18 | [D21_preservation_filter.md](D21_preservation_filter.md) |
| D26 | **Applied 2026-10-21 at splits-v2** (train only; Kannada 561 rows in; 7 rows excluded: the 3 listed + 4 Licious mistranslations; `reports/splits_v2.md`). Kannada machine translations: ACCEPTED on the same terms as Hindi in D20: **training augmentation only**, never counted as real data, never added to val or test, any Kannada metric labelled 'translated'. Spot-check (`reports/spotcheck_kn.md`, export `docs/spotcheck/kn_friend_v1.txt`): 47 of 50 rows answered (24 scam, 23 benign; kn01-kn03 not answered), Q1 meaning 47/47 and Q2 label 47/47 as marked (Wilson 95% CI 92.4% to 100%), formal 0/47; pool-weighted to the 15.0%-scam pool 100%; if kn22 is counted as an n on Q1 because of its note, 46/47 = 97.9% on the sheet and about 99.4% pool-weighted, still above the 90% gate. One note, kn22 (`p00696`): "Salary is 23,00/month" became "salary 23,00 months", the "per" is lost. Sibling check: 10 kept Kannada rows state a pay rate, 7 keep the "per", 3 lose it: kn22 and two slash-rate rows not on the sheet (`p00720` "/month", `p00719` "/day", found by my check, not by the reviewer). All three (frozen train rows, scam) are left out of TRAINING at the splits-v2 rebuild (`docs/spotcheck/exclude_kn_v1.txt`, not applied): Kannada augmentation set 587 -> 584 rows (scam 88 -> 85, benign 499 unchanged). Also conditional on the D21 digit/URL check. No translated text was edited by hand. Caveats: one reviewer, 47-row sample (8.0% of 587; 540 rows unchecked); 47 of 47 identical marks with no formal flag, against 4 failures and 18 formal flags on the Hindi sheet, so the 100% is an upper estimate (defects exist in unreviewed rows, e.g. `p00174` "Licious" -> "poisonous"); the benign translations are bank/OTP alerts and the scam ones prose (cue shortcut, flag it). This clears the Kannada part of the blocker on the translation rebuild and splits-v2; it does not run them. Splits, `split_map.csv` (SHA-256 89eec6f1...838c5), models and the test set untouched | 2026-10-19 | [spotcheck_kn.md](../../reports/spotcheck_kn.md), [exclude_kn_v1.txt](../spotcheck/exclude_kn_v1.txt) |
| D27 | **Built 2026-10-21 (user request).** The app's text head is the plain fine-tuned MuRIL (`models/finetune/muril_len128_20261021T135255Z`, splits-v2, max_len 128, no aug), temperature-scaled on val (T = 1.507), cut-offs 0.103 / 0.436 (same val rule), risk meter interpolated in log-odds (ends = 1st / 99th val percentile). Chosen over the TF-IDF baseline (val F1 0.951 vs 0.930; internal test F1 0.918 vs 0.897, real-only 0.906 vs 0.885) and over the augmented MuRIL (pre-set rule: aug only if val F1 >= 0.946 AND adversarial recall >= 0.96; aug got 0.955 / **0.885**). `SHIELD_TEXT_HEAD=baseline` keeps the baseline; a missing bundle falls back to it. Demo: g03 becomes a known miss | 2026-10-21 | [D27 section below](#d27-muril-as-the-apps-text-head) |
| C1 | **Built 2026-10-23 (user request, after `reports/eval_live_links.md`).** The crt.sh certificate-age check (R8) is **off by default** (`config.CRTSH_CHECK`, `SHIELD_CRTSH=1` turns it on) because crt.sh gave no usable answer for 93% of requests; short-link, dynamic-DNS and site-builder domains added to `platforms.py`; the 8 BUGS.md gambling sites added to the gambling lookup | 2026-10-23 | C1 below |
| C2 | **DECIDED (b) and built 2026-10-23 (user pick).** The host-only URL model alone may raise a link to Suspicious at most; Likely scam needs a link-check red flag (`config.URL_ALONE_MAX_LEVEL`, `router.analyse`). Same change: the maintained shortener list (PeterDaveHello/url-shorteners) is downloaded by `update_link_lists.py` and merged into `platforms.SHORTENERS` | 2026-10-23 | C2 below |
| C3 | **DECIDED (e) and built 2026-10-23 (user pick).** The URL model's flag threshold is 0.662 (the lowest at which the URL head's own validation split has <= 5% benign flagged), restorable with `SHIELD_URL_FLAG=0.537`. Same change: R10, an exact-brand-name rule (the registered domain's label is a brand's name but the domain is not in the brand's official list), and nine more hosting platforms in `platforms.py`. Age gate (d) not chosen | 2026-10-23 | C3 below |
| D-a | **Decided by the user 2026-10-27 (built in `src/intake_real.py`).** Phones for training vs the test set: the same two phones serve both, split **once**, 50 / 50 by template group (`--freeze`), stratified by label x keyword bucket (seed 20261026), groups with any near-duplicate pair between them moved together. TEST half -> `data/real/real_test_v1.csv` (frozen, realguard, rule 12); POOL half -> `data/collected/phones/pool.csv` (training and validation, splits-v3); after the freeze any message of a TEST group or near-duplicate of a TEST message is dropped from the pool. This is option (3) of `docs/plans/data_acquisition.md` section 10 (template-group split on the same phones), not that plan's recommended option (1) (different people), because no other phones were available. **Optimism caveat:** TEST and POOL share senders, so a bank whose different templates fall on both sides makes the final real-test numbers mildly optimistic; the near-duplicate rules remove copies, not a sender's shared style. Report this beside every `eval_real.py` number. Both phone owners consented to the use of their masked messages for training, validation and the test set, and to the masked training data going to the private Kaggle dataset | 2026-10-27 | [plans/splits_v3.md](../plans/splits_v3.md) (D-v3.8) |

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

## D24: risk score meter, "Lowered from..." line, typography

Status: built 2026-10-18 on the user's request. Models, thresholds, data and splits are untouched; `split_map.csv` SHA-256 and both model files' hashes are unchanged.

### The risk score (`src/shield/core/risk.py`, `Report.risk_score`)

A warning-sign meter, **not a probability**. The text model's score is not calibrated (D5 operating point is a design target, there is no real-message dev set yet), so "82" must not be read as "82% chance of a scam", and the page says so under the meter: "Higher = more warning signs. Not a percentage chance." D4 said "no % shown"; this keeps that (the number is never written with a % sign and a test checks it) and adds an integer score the user asked for.

Mapping, in two steps, deterministic:

1. `base` = the text score p through a piecewise-linear curve with the model's own cut-offs (read from the Report, so a retrained head moves the curve with its thresholds): (0, 0), (0.423, 30), (0.656, 70), (1.0, 100). Rounded half up (not Python's banker's rounding).
2. Clamped into the band of the **final** level.

| Final level | Band | Why this band |
|---|---|---|
| No warning signs | 0-29 | below the Suspicious cut-off (30) |
| Suspicious | 30-69 | |
| Likely scam | 70-100 | |
| Promotional (dormant, API only) | 0-29 | only the sender rule sets it, and only when no hard-risk signal exists, so it is a no-warning verdict whose sender says "registered marketing". Not 0 (the wording may still look like a scam, as many genuine offers do, so the model score still moves it inside the band); not above 29 (it must never look like a warning) |
| Can't judge | none (`null`) | nothing to measure; the page shows no meter |

Consequences, all intended: a rule or link signal that raised the level above what the text score says (OTP / PIN rule, a scam list, a red flag, gambling) lifts the number to the band floor through the clamp; a P1 lowering holds it at the ceiling (the Jio promo: p 0.928 would be 95, shown 69). A bare link with no readable text has no p and gets the band floor (0 for "No warning signs": a limit, the page cannot tell it from a message the model read and liked). The contract (`Report` validator) refuses a score outside its level's band, so a producer cannot contradict the level. Child (link) Reports have `risk_score: null`. Measured on 363 contract inputs + 14 demo messages: No warning signs 0-28, Suspicious 30-69, Likely scam 70-100, 3 Can't judge (null); within each level the score never decreases as p grows (`tests/test_risk.py` K1-K4; the whole 0-1 range in steps of 0.001 in K2). Demo set: d01 98, d02 99, d03 93, d04 96, d05 99, d06 92, d07 89, d08 98, d09 69 (Suspicious), d10 94, g01 11, g02 15, g03 20, g04 7.

Limits: the number inherits the text model's weaknesses (language, long texts, the shortcuts in BUGS.md); two Suspicious messages 20 points apart are not "twice as risky". Live link checks can only raise the level, and the score follows the final level.

### The "Lowered from..." line (`router.apply_positives`, `Report.lowered`)

D23's P1 rule (a verified .brand ending or a `.bank.in` address) can lower a message from Likely scam to Suspicious. The reason it gives ("Belongs to Jio...") only takes a free reason slot (D22 rule), so on the Jio promo, whose three slots are warnings, a user could not see why the verdict was not Likely scam. Now `Report.lowered = {from_level: "likely_scam", text}` is set, and the page shows the text in a calm grey panel directly under the verdict, whatever the reason slots hold: "Lowered from Likely scam: the link belongs to Jio (only Reliance can register .jio addresses)." Rules:

- Set only when the level really fell below what it was before the positives were applied **and** P1 is what lowered it: either the P1 cap did it, or overriding only the P2 links would have left the level higher. P2 alone lowering a verdict sets nothing (the request covers P1; P2, a popular website, gets no note: a limit); P1 firing with no change sets nothing (Jio + a mobile number in the text, Jio + an OTP request stay Likely scam, no note); nothing on any demo message.
- Dropped if a later step moved the level again (the sender rule, the dormant safety cap): then the sentence would no longer describe the verdict shown.
- The brand and the operator's short name come from the link's own positive signal; a short link whose revealed destination is P1 says "the link's destination ...". `.bank.in`: "the link ends in .bank.in (only banks can register these addresses)".
- This resolves BUGS.md D23 limit (9).

### Schema

"5": two new fields on `Report` (`risk_score`, `lowered`). A v4 reader would reject them (`extra="forbid"`), hence the bump (SCHEMA_VERSION, the frontend type, API tests and fixtures move together).

### Frontend

- Meter (`RiskMeter.tsx`): "Risk score 82 / 100" (the number in Geist Mono with tabular figures, in the verdict's colour), a green > amber > red bar with the band edges 30 and 70 drawn as ticks, numbers 0 / 30 / 70 / 100 and the three zone names under it, so colour is never the only signal; `role="meter"` with `aria-valuemin/max/now` and an `aria-valuetext` ("69 out of 100, in the suspicious range"). Reduced motion: no knob animation.
- What to do now: a numbered `<ol>` (CSS counters), same steps in the same order as `Report.advice`; the "Check who sent it" tip is unchanged.
- Typography: body 16 px; a type scale (`--fs-body` 16, `--fs-small` 14, `--fs-label` 12, hero up to 62, verdict 46 / 36 px on phones at weight 800, score 58 px); section labels small, upper-case, tracked. *(Superseded by D25 on 2026-10-18: Libre Baskerville + Lexend, the switch removed.)* **Heading font behind ONE variable, `--display`**, chosen at build time: `DISPLAY_FONT=bricolage` (default, Bricolage Grotesque variable) `| space` (Space Grotesk variable) `| fraunces` (Fraunces variable), all from `@fontsource-variable` packages; only the chosen one is bundled. Body stays Geist (already loaded, clean at 16 px, has tabular figures; a more legible alternative such as Atkinson Hyperlegible Next is possible if older users prove to struggle). Numbers and codes: Geist Mono. Hindi / Kannada: Noto Sans Devanagari / Kannada, regular weight, script subsets only (`src/fonts/indic.css`; @fontsource's own per-subset CSS has no `unicode-range` and made an English page download them for the arrows and ticks of the result screen). No CDN: `e2e/fonts.mjs`.
- Contrast: `--faint` was 2.6:1 on the stage; now `--faint` #8590A3, `--muted` #9AA5B8, `--grey` #98A2B3, panels tinted darker, the home subtitle lighter. `e2e/contrast.mjs` samples the real rendered background behind each text box: 116 of 116 text elements on the home and Jio result screens at 390 and 1440 px pass AA (lowest 5.1:1).

### Tests

`tests/test_risk.py` K1-K9; vitest `src/lib/d24.test.tsx` (A the note: shown for the Jio fixture, not for Jio + mobile number, Jio + OTP, any demo message; B score band, monotonicity, meter markup, no percentage; C numbered list, no inputs, steps and order, the tip); `frontend/e2e/fonts.mjs` and `contrast.mjs` on the built site; `overlap.mjs` unchanged in scope.

## D25: fonts locked in, light theme

Status: decided by the user and built 2026-10-18. Frontend only: no model, threshold, data, split or contract change (`split_map.csv` SHA-256 and both model files' hashes unchanged).

### Fonts (supersede the D24 display-font choice)

- Headings: **Libre Baskerville** 400 / 700 (`@fontsource/libre-baskerville`), behind `--display`, light tracking (-.01em). Used for the logo, the hero, the verdict word, the risk score number, the panel titles (Your message, Why, Link, Website details, What to do now, Risk score) and the "Lowered from <level>:" lead-in. The old upper-case mono section labels are gone. Weight 800 is no longer used (the verdict word is 700).
- Body and UI: **Lexend** variable (`@fontsource-variable/lexend`), replacing Geist; buttons, chips, reasons, the message and the advice. It has the rupee sign. Codes, link addresses and data stay Geist Mono; Hindi / Kannada stay Noto Sans Devanagari / Kannada with the script-only unicode ranges.
- Removed: Bricolage Grotesque, Space Grotesk, Fraunces, `@fontsource/geist`, their CSS files and the `DISPLAY_FONT` switch in `vite.config.ts`.
- Type scale for the pair: body 15 px (Lexend reads about a size larger than Geist), small 13.5, panel titles 18 px serif, hero up to 54, verdict 40 / 32 px on phones, score 50 px; the paste box stays 16 px (iOS zooms into smaller fields). Long text is capped at about 65 characters a line in the wide column (message 31em, steps and the tip 35em; measured 65 / 64 on the longest demo message at 1280 and 1440 px).
- Fonts downloaded (built site, `e2e/fonts.mjs`): home 88.9 -> 68.6 KB, Jio result 98.9 -> 78.5 KB, Hindi 138.2 -> 117.8 KB, Kannada 116.0 -> 95.7 KB; woff2 in `dist/` 341.6 KB (38 files) -> 340.4 KB (27 files).

### Light theme

- Every colour is a token in `styles.css`: `:root` (dark, the design's literal values moved there unchanged) and `:root[data-theme="light"]`. The globe reads its `--globe-*` / `--arc-*` tokens with `getComputedStyle` and recolours on a theme change without rebuilding the scene; the light theme draws it with normal blending (additive light vanishes on a light page). The radar sweep mixes the level colour with transparent (`color-mix`, 40% = the old `66` alpha). The only literal left outside the token blocks is the black of the glass rim's CSS mask, which is alpha-only. A vitest guard (Y5) fails on any colour literal in components, `lib/` or the rules of `styles.css`.
- Light look (first version, replaced the same day, see the next point): page #F3F3F1 with a black dot grid (1.25 px dots every 22 px at 14% opacity, `--dot-d` / `--dot-gap` / `--dot-alpha`), solid white panels with a soft border and shadow, darker verdict colours (red #C62828, amber #9A5B00, green #18794A, grey #5F6978, blue #1F66B8: 5.4-5.8:1 on white).
- Light look, reworked (2026-10-18, user rejected the first one as flat and "paper coloured"; references `docs/design/light-landing.html` and `light-result.html`): cool grey page #F2F3F5 with a 1 px dot every 22 px at 7% (rgba(22,24,29,.07)); hero halo `0 1px 18px var(--bg), 0 0 2px var(--bg)`; a soft wash of the page colour behind the hero, none on the result screen. Globe `--globe-style: shaded` (dark stays `flat`, pixel-identical): a shader on a full-radius core sphere (#F1F3F6 -> #E4E7EC at 70% -> #CDD2DA at 93% -> #B8BEC8 at the rim, by the sine of the view angle, plus a band of rgb(120,128,142) up to 42% along the top rim), a red glow #C8222A (.34 at the rim, .14 a third of the way out, 0 at 1.28 radii) worn by the same rim sphere as a second material measured in screen space, round land dots #111317 on a 15,000-point golden-angle spiral kept on land (1-degree grid from land.json, widened one cell), none inside India's outline, India's own dots in #C1121F, no outline lines, no ocean dots. Both dot sets are built once; the theme's is shown, so the toggle needs no reload. Result panels: verdict `color-mix(level 5%, #FBFBFC)` with a 24% border (`--lvl` from VerdictPanel), Why #F6F7F9, message #FFFFFF, Link #F3F6FA, What to do #F3F7F4, "Lowered from..." box rgba(255,255,255,.7). `--faint` #5D6573 -> #535A67 (the "try" label over the now darker globe was 4.25:1 at 390 px). **Known difference from the reference:** at 1280x800 the globe's top edge is about 8-10 px lower and its sides 8-18 px wider than the reference; at 390x844 within 1 px. The app keeps the camera unchanged and three.js draws the exact perspective outline (computed top 265 px, left 272 px), while the reference paints a circle (top 255, left 280) that only approximates it; the reference's own dots follow the exact outline and spill past its disc. The reference also tips the globe the other way (its rotX sign), so India sits lower there; the app keeps its own rotation.
- Dark look unchanged apart from the fonts: with the old fonts, the token move changed no text pixel against screenshots of the previous build; the globe's rim differs by at most 2/255 (its colour is now a shader uniform), less than two runs of the old build differ on the result screen.
- Toggle: a sun / moon button in the header. First visit: `prefers-color-scheme` (dark when the system has no preference). The choice is stored in `localStorage` (`scam-shield-theme`, every access in try/catch; with storage blocked the button works for the visit and the next visit follows the system). Without a stored choice the page follows system changes live. No flash: an inline script in `index.html` sets `data-theme` before the stylesheet and the app load. Switching cross-fades colours for 0.3 s, not at all with reduced motion. *(Replaced the same day by the theme-switch animation, below.)*
- Theme-switch animation (approved prototype `docs/design/theme-switch.html`, built 2026-10-18): dark -> light, a comet flies from the top-right to the bottom-left inside a bow shock (Billig hyperbola, nose radius 34 px, standoff 16 px) and the light theme exists only inside the shock; its cone opens 34 degrees in total and, once the comet has left (80% of 2.4 s), opens out to ~88 degrees each side. Light -> dark, 2.6 s: a black hole opens by the switch (at least 110 px from the edges), the lit area shrinks into it along the prototype's wobbling `edgeR()` edge (radius = farthest corner x (1 - k^3)), ~320 light streaks fall in, the ring brightens as it feeds, a flash at 86-98%, and the hole closes. Both: a hexagon shield (1.1 x the globe's radius) flares as the edge passes. Built on View Transitions with the real page and the real three.js globe (held still while it runs, so it changes along the page's edge with no lag); details in `frontend/CLAUDE.md`. Reduced motion or no View Transitions: instant. "Paste it here." in the hero subtitle turned red at the same time (`--paste-red`): dark `--red` #FF3B3B; light #B91C1C, not `--red` #C62828, which measured 4.31-4.49:1 over the light globe at desktop sizes (AA needs 4.5:1; 4.57-4.70:1 counting the subtitle's halo, which `e2e/contrast.mjs` strips): the user chose the darker red (4.9:1 there).

### Checks

vitest `src/lib/theme.test.tsx` (Y1-Y5) and `src/lib/themeSwitch.test.ts` (W1-W4, the switch's geometry); `frontend/e2e/theme.mjs` (T1-T6: system setting both ways, toggle + reload, no flash with the app's JS and CSS blocked, blocked storage, reduced motion (instant; with motion it animates), the globe repaints); `frontend/e2e/switch.mjs` (S1-S8: durations, frame times, the edge through the globe and the 34 degree cone under Playwright's clock, double clicks, a hidden tab, a resize, nothing left behind, no errors or requests); `e2e/axe.mjs` (axe-core 4.13.0 colour-contrast, both themes, home + Jio result at 390 / 1440: 0 violations; it judges 60-61 of the ~71 result-screen texts in light and treats the dark glass over the globe as "incomplete"); `e2e/contrast.mjs` (rendered-pixel AA, now both themes: 238 / 238); `e2e/overlap.mjs` (both themes: 42 / 42 runs).

## D27: MuRIL as the app's text head

**Status: built 2026-10-21 (user request; plan approved with one change, the Suspicious flag policy below).**

### Choice

| | TF-IDF baseline | MuRIL plain (chosen) | MuRIL aug |
|---|---|---|---|
| val F1 at Likely | 0.930 (splits-v2 refit) | 0.951 | 0.955 |
| internal test F1 / real-only F1 | 0.897 / 0.885 | **0.918 / 0.906** | 0.891 / - |
| test false alarms / missed scams | 81 / 237 | 112 / 150 | 129 / 215 |
| adversarial recall at Likely (1,862 held-out variants) | - | 0.941 | **0.885** |
| CPU per message / size | 2 ms / 8 MB | 59 ms / 950 MB | same as plain |

Sources: `reports/eval_muril_v2.md`, `reports/eval_muril_aug_v2.md`. The augmented model fails the rule fixed before its test results (aug only if val F1 >= 0.946 AND adversarial recall >= 0.96). The internal test split informed this choice between heads, so it is no longer an untouched comparison for these models; the final real-message test set is untouched.

Costs that come with MuRIL: more false alarms on test (50 of the 112 from one test-only benign UPI-collect template); Kannada AUROC 0.878 vs 0.930 (synthetic rows); long sources only seen through their first 128 tokens.

### Calibration, cut-offs, meter (all fitted on val; `src/calibrate_text_head.py`, `reports/calibration_muril_v2.md`)

- **Temperature** T = 1.507 (val log-loss 0.105 -> 0.086, Brier 0.0201 -> 0.0193, ECE 0.018 -> 0.009). Test, reported only from the cached predictions: Brier 0.0441 -> 0.0420, ECE 0.042 -> 0.027.
- **Cut-offs**: the same rule on calibrated val scores: Suspicious 0.103, Likely scam 0.436 (raw 0.037 / 0.405); 0 val levels change.
- **Suspicious flag policy** (fixed on val before the demo was re-run): MuRIL may not flag more val benign messages at Suspicious-or-above than the app's TF-IDF baseline. Baseline 4.06% (scam recall at Suspicious 0.952), MuRIL 1.56% (0.951): the policy did not move the cut-off.
- **Meter** (`risk.curve` with `meter_ends`): Suspicious cut-off -> 30, Likely -> 70, linear in log-odds, calibrated p 0.0140 -> 0 and 0.9885 -> 100. With percentile ends the meter does not depend on T. On val 78.0% / 0.5% / 21.5% of messages land in 0-29 / 30-69 / 70-100 on their text score: the scores are bimodal, so middle values only appear where the model is unsure or where a rule / link lifts the level to a band floor. The baseline keeps D24's linear curve.
- Stored in the bundle's `shield_meta.json` (`calibration` block); `MurilScorer` refuses a bundle without it, a smoke / `--limit` run or another `textprep`.

### Demo set (illustrative; `reports/demo_check.md`, locked per head in `tests/test_demo.py`)

| id | TF-IDF: verdict / score / meter | MuRIL: verdict / score / meter |
|---|---|---|
| d01 digital arrest | Likely scam / 0.982 / 98 | Likely scam / 0.988 / 100 |
| d02 KYC link | Likely scam / 0.986 / 99 | Likely scam / 0.989 / 100 |
| d03 UPI refund | Likely scam / 0.916 / 93 | Likely scam / 0.988 / 100 |
| d04 job task | Likely scam / 0.956 / 96 | Likely scam / 0.988 / 100 |
| d05 electricity | Likely scam / 0.986 / 99 | Likely scam / 0.988 / 100 |
| d06 delivery fee | Likely scam / 0.909 / 92 | Likely scam / 0.987 / 99 |
| d07 investment | Likely scam / 0.879 / 89 | Likely scam / 0.988 / 100 |
| d08 lottery | Likely scam / 0.974 / 98 | Likely scam / 0.988 / 100 |
| d09 Hinglish OTP | Suspicious / 0.651 / 69 | Suspicious / 0.373 / 65 |
| d10 gambling promo | Likely scam / 0.927 / 94 | Likely scam / 0.988 / 100 |
| g01 bank debit | No warning signs / 0.162 / 11 | No warning signs / 0.014 / 0 |
| g02 OTP alert | No warning signs / 0.210 / 15 | No warning signs / 0.014 / 0 |
| **g03 delivery done** | No warning signs / 0.282 / 20 | **Suspicious / 0.162 / 41 (known miss)** |
| g04 friend chat | No warning signs / 0.094 / 7 | No warning signs / 0.014 / 0 |

g03 ("Your Amazon order has been delivered. Rate your delivery experience in the Amazon app.") is accepted as a known miss under the policy above rather than moving a cut-off for one made-up message.

### App

- `shield.messages.text_head.MurilScorer`: loaded once; device `SHIELD_TEXT_DEVICE` (auto = MPS if available, else CPU); one forward pass at a time (lock); a warm-up call at load. `explain` is leave-one-word-out occlusion, only computed for the Gradio app (`analyse(..., explain=True)`); the API never pays for it.
- `SHIELD_TEXT_HEAD=muril` (default) or `baseline`. With the bundle (git-ignored) or torch / transformers missing, one line on stderr and the baseline: Reports are then identical to before D27.
- `Report.meta.models["text"]` = `muril <sha8 of model.safetensors>`. Report schema unchanged ("5").
- Dependencies: torch 2.14.1, transformers 5.19.0, tokenizers 0.23.2, safetensors 0.8.0 in `.venv`; huggingface_hub 2.1.1 -> 1.33.0 (tokenizers 0.23.2 requires < 2), the same set as `.venv-finetune`.

## U1: helpline row, Chakshu copy flow dropped (2026-10-23)

Status: decided by the user, built (frontend + the Likely scam advice text).

- On Suspicious and Likely scam, What to do now ends with one always-visible helpline row: label, `Call 1930` (`tel:1930`), `cybercrime.gov.in` (new tab), and a compact EN / हिंदी / ಕನ್ನಡ switch on the right (`components/Helpline.tsx`, strings in `lib/helpline.ts`). The "Get help" toggle is gone. The "call within one hour" hint is only the Call button's aria-label and title. `HELP_NEEDS_REVIEW`: Hindi true (not checked by a native speaker), Kannada false.
- **The "Copy & report on Chakshu" flow was dropped by the user. Do not re-add it**, nor the TS PII-mask port (`maskPii`) and link defanging (`defang`) that only it used, nor "Ask someone first".
- Backend advice (`src/shield/core/advice.py`), Likely scam: step 3 is "If you paid or shared details, call 1930 now."; the "Report it at cybercrime.gov.in." step is removed because the row has it. Suspicious never had that step. Report schema unchanged.

## C1: crt.sh off by default, platform lists, gambling additions (2026-10-23)

Status: built on the user's instruction after the live evaluation (`reports/eval_live_links.md`, commit 231db07). Edition 2 of that report re-scores the same sample offline (no network call: 0 names resolved, 0 connects, 3,228 logical calls all answered from `data/eval_live/netcache_2026-10-22.jsonl.gz`). **The "after" numbers were tuned on that same sample; they must be confirmed on a fresh pull, which is a separate task.**

**crt.sh (D2 / D23 fallback for R8).** In the evaluation crt.sh was asked 68 times (only for domains whose RDAP gave no date) and gave a usable answer 5 times: 66 of 68 failed on the first try (HTTP 429 34, timeout 32) and **63 of 68 (93%) were still unavailable after two retries**; R8 fired 0 times; the median call took 735 ms and the p95 2,531 ms, against a 2 s call limit and a 4 s message limit, so the check added delay and no signal. `live.registration()` now asks crt.sh only when `config.CRTSH_CHECK` is true (default false, env `SHIELD_CRTSH=1`). With it off a domain with no RDAP date shows no certificate row at all (it used to show "couldn't verify"). R8, its flag code and its tests stay in place; `tests/test_links_live.py` L5 checks both states. Verdicts of the 321 evaluation items: none changed because of this switch (R8 never fired).

**Platform lists** (`src/shield/links/platforms.py`, sources in the comments there). 12 shorteners (the 3 seen in the eval, `zd.lc`, `g5.lu`, `lnk.ink`, plus 9 well-known ones added from memory, not checked against a list because this task was offline); 19 dynamic-DNS suffixes and 5 site-builder domains (all but `craftum.io` are in the private section of the Public Suffix List bundled with tldextract, checked by L15). Shorteners follow D3: the destination is shown only after the expand button, and the 12 hosts are now also allowed for that one button request (`net.add_expand_hosts(SHORTENERS)`). Dynamic-DNS and site-builder domains become free hosting: "Can't judge by domain", with the subdomain checked for brands and scam keywords. **Effect on the 10 misses: 0 become flagged, 6 move from "No warning signs" to "Can't judge", 4 are unchanged** (old ordinary domains with no signal). One phishing link that the URL model used to flag as Suspicious is now "Can't judge" (recall 73 -> 72 of 96). A maintained shortener list (github.com/PeterDaveHello/url-shorteners via raw.githubusercontent.com, already in `net.UPDATE_HOSTS`) can be wired into `update_link_lists.py`; not done, it needs a network run.

**Gambling.** The 8 sites BUGS.md names (`sportpesa.com`, `msport.com`, `bingoplus.com`, `tippmix.hu`, `skyvegas.com`, `pocketoption.com`, `szerencsejatek.hu`, `juan365.com`) are `GAMBLING_ADDED` in `shield/links/gambling.py`, merged into the lookup at load time (basis `list`) so a rebuild of the git-ignored TSV keeps them. Source: BUGS.md "Gambling lookup: known gaps (1)", found by eye and never opened; the user's instruction of 2026-10-23. `pocketoption.com` is a binary-options broker that BUGS.md counts with the betting sites; `szerencsejatek.hu` is the Hungarian state lottery operator: G1 counts licensed operators. Result: 8 of 8 unlisted sites Suspicious in the honest setting (7 changed; `szerencsejatek.hu` was already Suspicious). `tests/test_gambling.py` G21.

## C2: what the URL model alone may do (decided (b), 2026-10-23)

Status: **decided by the user: variant (b), built 2026-10-23** (tests L16 / L17 in `tests/test_links_live.py`). It was proposed on the 96 + 200 links of the 2026-10-22 evaluation, honest setting (OpenPhish, URLhaus, Tranco off), `reports/eval_live_links.md` section 10. Not confirmed on a fresh pull.

| Variant | Phishing flagged (of 96) | Phishing Likely scam | Benign flagged top 10k / 100k-1M | Benign Likely scam (of 200) |
|---|---:|---:|---:|---:|
| (a) pre-C2 | 72 | 35 | 9 / 20 | 3 |
| **(b) URL model alone: at most Suspicious (the app)** | 72 | 15 | 9 / 20 | 0 |
| (c) URL model alone: nothing, weight only with a link-check flag (not chosen) | 29 | 15 | 1 / 1 | 0 |

What was built. In `router.analyse`, after a link's background checks: a link of kind "model" (scored by the URL model) with no red flag (R1-R9) and a model level above `config.URL_ALONE_MAX_LEVEL` (1; `SHIELD_URL_ALONE_MAX=2` restores the old behaviour) gets `base_level = level = 1`, `verdict = "Suspicious"`, `url_capped = True`; the report adds the sentence "The website-name check rates this link higher, but no other check agreed, so it is shown as Suspicious." to the link's `model.url` evidence (contract unchanged). A link with a red flag keeps the model's level, so flag + model can still reach Likely scam. The cap is per link; the fusion is unchanged, so a message whose text head also says Suspicious is still Likely scam (two heads agreeing), which is not the URL model alone. The live checks run after the offline answer, so a link that is capped in the first answer is uncapped when a live check raises a flag ("Raised after the website checks").

Shortener list. `src/update_link_lists.py --only shorteners` downloads `raw.githubusercontent.com/PeterDaveHello/url-shorteners/master/list` through the update path (host already in `net.UPDATE_HOSTS`; CC BY-SA 4.0, credit the repository; the file `data/final/linklists/url_shorteners.txt` is git-ignored and not redistributed). Run once on 2026-10-23: 1,454 domains (log: `data/eval_live/run_log_shorteners_update_2026-10-23.txt`). `platforms.load_downloaded_shorteners()` merges them into `SHORTENERS` at import and keeps the hand-added ones (10 of the 36 hand-listed shorteners were not on the list, e.g. `zd.lc`, `g5.lu`, `lnk.ink`); 9 entries that are already user-content / free-hosting platforms (`youtu.be`, `t.me`, `wa.me`, `fb.me`, `lnkd.in`, `on.fb.me`, `forms.gle`, `discord.gg`, `1drv.ms`) and 2 that are whole websites (`dw.com`, `ibb.co`) are excluded (`SHORTENERS_EXCLUDED`). 44 of the list's domains are in the Tranco top 10k, so some benign brand short links (e.g. `apple.news`) now read "Can't judge" instead of "No warning signs" (1 of the 321 eval items). Short links stay under D3: nothing is expanded except on the user's button press. With the file missing the app knows only the hand-written lists.

## C3: cutting the URL-model false alarms further (decided (e), 2026-10-23)

Status: **decided by the user: (e), built 2026-10-23** (tests L18 / L19 in `tests/test_links_live.py`; `reports/eval_live_links.md` section 10, `reports/exact_brand_scan.md`). **Numbers come from the same sample the changes were looked at on and must be confirmed on a fresh pull.**

Why (e): it removed 13 of the 29 benign false alarms (29 -> 16 of 200; top 10k 9 -> 4, 100k-1M 20 -> 12) for 9 lost scams, against 16 lost for the age gate (d) at the same 16 false alarms; and its parameter, 0.662, was picked on the URL head's own validation split (4.97% benign flagged there; the old 0.537 had 9.5%), not on this sample. The age gate fails on pages hosted on platforms, whose registered domain is the platform's old one.

| Honest setting, 96 phishing + 200 benign | Phishing recall | Likely scam | False alarms top 10k / 100k-1M | Scams lost vs (b) |
|---|---:|---:|---:|---:|
| (b) the app before C3 (threshold 0.537) | 72 (75%) | 15 | 9 / 20 | 0 |
| (e) threshold 0.662 | 63 (66%) | 15 | 4 / 12 | 9 |
| (e) + R10 | 69 (72%) | 16 | 4 / 12 | 3 |
| (e) + R10 + nine platforms as FREE_HOSTING (the first C3 commit) | 61 (64%) | 16 | 4 / 12 | 11 |
| (e) + R10 + nine platforms as USER_CONTENT (the app now) | 69 (72%) | 16 | 4 / 12 | 3 |

R10 (`lookalike.exact_brand`, `exact_brands.json`, flag `R10`, floor Suspicious; counts with R4-R8 for R9): fires when the registered domain's first label (tldextract `top_domain_under_public_suffix`, as `link_domain`) equals a brand label exactly and the domain is not in that brand's `official` list. Exact label only: `robloxfans.com`, `pineapple.com` never fire (the substring / near-miss rule is R4 and is unchanged); a link R4 already flags is not flagged twice. 41 brands: Roblox, Amazon (25 country sites), the main Indian banks, UPI / payment apps (Paytm, PhonePe, BHIM, Razorpay, MobiKwik, Freecharge, BharatPe), delivery and shopping brands (India Post, Delhivery, Blue Dart, DTDC, Ecom Express, Xpressbees, Shadowfax, Ekart, Flipkart, Myntra, Meesho, Swiggy, Zomato, Blinkit, BigBasket) and IRCTC. **The official lists were written from the author's knowledge and the repo's `brands_india.json` and were not re-fetched from the brands' sites (offline task, no credits): re-check them.** User-facing sentence: "Uses the name <Brand> but is not <Brand>'s official website." Switch: `SHIELD_EXACT_BRAND=0`. It recovers 6 of the 9 scams (e) loses (the six `roblox.<other TLD>` pages); the other 3 (`skinsaway.lol`, `proboss.be`, `schwarzteam.eu`, scores 0.55-0.58) stay lost. False-alarm scan: 0 of the 200 benign eval domains, 0 of the Tranco top 10k (first run: `amazon.dev`, Amazon's own, added), 18 of the top 100k (other TLDs of Roblox, Zomato, Blinkit, BharatPe and `amazon.work`; ownership unverifiable offline, left flagged).

**Follow-up the same day (user request):** the eight platforms (edgeone.dev, 4everland.app, azurestaticapps.net, cloudworkstations.dev, crabdance.com, flazio.online, typedream.app, teleporthq.app) were first added to FREE_HOSTING, which cost 8 caught scams ("Can't judge", no benign false alarm removed), so they were **moved to USER_CONTENT** with backblazeb2.com (`platforms.PLATFORMS_C3_USER_CONTENT`): the URL model keeps its vote and the 8 scams are flagged again. Final row of the table above: (e) + R10 + platforms = **69 (72%) recall, 16 Likely scam, false alarms 4 / 12, 3 scams lost vs (b)**. The 18 Tranco-100k hits of R10 were checked in RDAP and DNS through `net.py` (`reports/exact_brand_official_check.md`, `scripts/verify_official_domains.py`): 7 added to the official lists (amazon.work, roblox.net / .us / .co.uk / .vn, zomato.durban, zomato.joburg), 1 clearly someone else's (roblox.com.bz), 10 unclear and still flagged (eight Zomato gTLD / ccTLD domains, bharatpe.in, blinkit.to; most likely the brands' own), waiting for the user.

