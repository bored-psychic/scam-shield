# Scam Shield: product architecture

The design of the product as built, and of the parts still to come. Decision IDs (D1-D27, G1, R2, C1-C3, D-a) are in `docs/decisions/README.md`, which is the source of truth: this document was written once, after D1-D18 were all decided (2026-10-28), and changes only when a decision there changes the design. Per-module detail lives next to the code (`src/shield/*/CLAUDE.md`, `frontend/CLAUDE.md`); numbers live in `reports/`.

The target: *a person pastes or screenshots a message in English, Hindi, Kannada or Hinglish, and within a few seconds gets a correct verdict, the reasons, and what to do next, with few false alarms on normal messages.* Each design choice is tagged with the part of that sentence it serves: **[fast]**, **[correct]**, **[reasons]**, **[next]**, **[few-FA]**.

## Context: what the design has to work around

- **Out-of-distribution failure.** Models trained on one source do badly on another. Leave-one-source-out AUROC for the fine-tuned MuRIL drops 0.227 on `india_fraud_final` (benign accuracy 0.116 at 0.5), the main argument for real Indian genuine messages in splits-v3 (`reports/eval_muril_v2.md` §9). Real messages behave like a new source.
- **No real Hindi or Kannada data.** The Hindi / Kannada rows are machine translations, train only (D20, D26), plus `synth_india` templates. Those languages are labelled experimental (D6).
- **The URL head is weak on its own.** Host-only test AUROC 0.859 (`reports/url_head.md`); it flags free-hosting sites. So it cannot give Likely scam alone (C2) and link checks carry the weight (D23).
- **Rules and tactic tags are hand-written** and unchecked in Hindi and Kannada.

---

## 1. Design principles

1. **Verdict first, details later [fast].** The page asks for an offline analysis first (no network call), shows the verdict, then asks for the live link checks and updates the link cards. A slow registry never delays the verdict (`src/shield/api/main.py`: `AnalyseRequest.live`).
2. **Five verdict levels [correct, few-FA]:** `Likely scam` / `Suspicious` / `No warning signs found` / `Promotional` (D22) / `Can't judge`. Can't judge is returned when there is too little text to read (fewer than 3 words once links are removed, `router.MIN_PROSE_WORDS`) and no link that could be scored, or when the only links cannot be judged (a free-hosted site, a shortener not expanded). Never "Safe". Promotional exists only with a sender (D22), which the UI no longer asks for (D18).
3. **Rules and link checks only raise a verdict, with narrow exceptions [few-FA].** Hard rules act as floors after the model (`src/shield/messages/rules.py`, `core/router.py`): the OTP / PIN / CVV request rule and the PIN-to-receive rule (R2) force at least Suspicious; the gambling floor (G1) forces Suspicious on a link. The exceptions lower: positive link evidence P1 / P2 (D23) applies only without a hard-risk signal, and P1 can take a Likely scam message to Suspicious ("Lowered from..." line, D24). The other exception is the language cap (D5 + D6, `core/lang.py`, `router.apply_language_cap`): in Hindi, Kannada and Hinglish a Likely scam that only the text head produced is shown Suspicious, with a reason line saying the language is less tested; link evidence, checked rules and the investment rules are not capped, and the cap lifts per language only by decision (>= 150 real-dev hard-legit messages). Floor strengths are in D16.
4. **Reasons do not depend on the model [reasons].** The top three reasons come from rules, link evidence, tactic tags and then the text model, in that order (`core/report.py`), so explanations survive a text-head swap.
5. **Exactly one code path may touch the network.** `src/shield/core/net.py`: https only, exact host allowlist, IP literals refused, redirects never followed, no cookies or proxies, at most 2 s per call and 4 s per message. This turns CLAUDE.md rule 8 (never visit a link from a message) into a property of the code. `tests/test_api.py` T7 patches sockets and checks that link-bearing input analysed offline makes zero attempts. List downloads belong to `src/update_link_lists.py`; the API process calls `net.forbid_updates()` at start-up.
6. **No user content touches the disk or the logs.** Details in §5.4.
7. **`textprep.model_text` stays the only model-input preprocessing (rule 11).** OCR output is plain text as a person would type it (reading order, joined lines, link repairs, D19b); that is OCR post-processing, not model preprocessing. D11 adds a *folded view* for rules and the lexicon only (NFKC, zero-width characters removed, homoglyphs folded); models never see it, so rule 11 holds.

---

## 2. Code layout and shared core

`src/` holds the research scripts and the single copies of `textprep.py`, `url_features.py` and `pii.py` (importable from anywhere after `pip install -e .`, `pyproject.toml`). The product is the package `src/shield/` plus the React app in `frontend/`.

```
src/shield/
  contracts.py        # pydantic Report contract, SCHEMA_VERSION "5" (Level, Evidence, LinkInfo, Fact, ...)
  config.py           # paths, active text head, switches (SAFETY_ADVICE_CAP, CRTSH_CHECK, URL_ALONE_MAX_LEVEL, URL_FLAG_THRESHOLD, INVEST_RULES)
  examples.py
  api/       main.py (FastAPI: /api/health, /api/analyse, /api/ocr), upload.py (hard-capped in-memory multipart reader)
  core/      router.py (analyse(): entities -> engines -> levels), lang.py (detect_lang + the D5 cap line in en / hi / kn), verdict.py (level_of, fuse), report.py (router result -> Report: evidence,
             top-3 reasons, advice), risk.py (0-100 warning-sign meter, D24), advice.py (what to do, per level), sender_rule.py (D22),
             net.py (the only outbound HTTP)
  messages/  text_head.py (TextScorer: MurilScorer, TF-IDF baseline), rules.py (OTP / PIN / CVV, PIN-to-receive, advisory phrases),
             invest_rules.py (A1-A12, raise only), tactics.py, threats.py, sender.py
  links/     lexical.py (host-only URL model), platforms.py (shorteners, free hosts), lookalike.py (brands, homographs, R10), lists.py (OpenPhish,
             URLhaus, Tranco, RDAP bootstrap, IP -> ASN), live.py (RDAP, DoH, crt.sh, Safe Browsing, shortener expansion; in-memory cache),
             reputation.py (the evidence ladder), gambling.py (G1)
  ocr/       reader.py (local Tesseract, D19)
frontend/    React + Vite + Tailwind + Motion (D9); src/update_link_lists.py and src/pull_urls.py are the refresh jobs
tests/       test_*.py wrappers (contract, API, OCR, links, gambling, risk, sender, demo, investment rules), tricky_inputs.py
```

**Not built:** a lexicon in YAML, `transactions/` and `apps/` engines (§7), study mode (D13).

### Stable interfaces

| Interface | Methods | Now | Later |
|---|---|---|---|
| text head (`TextScorer`) | `score`, `explain`, thresholds, `textprep` marker | `MurilScorer` on `models/finetune/muril_len128_...` (D27); `SHIELD_TEXT_HEAD=baseline` loads the TF-IDF head | the splits-v3 retrain |
| URL model | `score_many`, `breakdown` | host-only gradient boosting (D8) | the full-URL view, last (D8) |
| OCR | `read_image(bytes) -> text, lines` | Tesseract `eng+hin+kan` (D10) | |
| link checks | pure functions over a link plus the lists and live results (`reputation.py`) | offline ladder, live checks | |

**The Report contract.** Every response is a `Report` (`src/shield/contracts.py`): level, risk score, reasons, advice, evidence, a child `Report` per link with a `LinkInfo` fact sheet (each fact carries `effect`, `why`, `source`, and `sent`, the registered domain sent to a service), `lowered`, `meta`. Detection stays in Python; the frontend renders one `Report` and holds no detection or advice logic. A schema change a consumer would notice bumps `SCHEMA_VERSION`; `frontend/scripts/dump_fixture.py` regenerates the frontend fixtures.

**Model swap.** Each bundle carries `shield_meta.json`: the `textprep` marker, the `split_map` SHA-256, temperature and cut-offs fitted on val by `src/calibrate_text_head.py`, git commit. The loader refuses a bundle without a calibration block, a smoke or LOSO bundle, or a wrong marker (D27). Gates for a new head (per source, LOSO, adversarial, false alarms on genuine messages at the operating point, calibration) are in D5 and `docs/plans/splits_v3.md`; the final real-message test set is run once, at the end (rule 12).

### Message flow

```
image --OCR (local Tesseract, in memory)--> text the user checks and edits --> POST /api/analyse (text, live?, expand?)
text --> links extracted (textprep) --> model_text(text) --> text head (calibrated) --> text level
      --> rules (OTP / PIN / CVV, PIN-to-receive, investment A1-A12) --> floors
      --> each link: host-only URL model + offline checks (lists, lookalike, homograph, gambling) [+ live checks when live=true]
      --> fuse(text level, URL level) --> link positives P1 / P2 --> language cap (hi / kn / hinglish) --> optional sender rule (dormant) --> level, risk score, reasons, advice
```

**Fusion.** The shipped fusion is the max rule (`core/verdict.py` `fuse`): the higher of the text and URL levels, and both at least Suspicious gives Likely scam. The host-only URL model alone is capped at Suspicious; Likely scam from the URL side needs a link-check red flag R1-R9 (C2). The draft's fitted logistic-regression fusion was not built; the max rule stays unless a fitted one beats it on val and per source.

---

## 3. Backend and frontend stack

- **Backend: FastAPI + uvicorn**, one process, bound to 127.0.0.1:8000. Models and link lists load at start-up (`lifespan`). No request-body logging, no docs or OpenAPI page, CORS only for the Vite dev server.
- **Frontend: React + Vite + Tailwind + Motion (D9)**, replacing the draft's server-rendered HTMX + Jinja plan. FastAPI serves the `Report` as JSON; the approved design is `docs/design/` (V1: dark stage with a dotted globe, bento result layout, radar meter; light theme and fonts D25). Every asset is bundled or self-hosted: no CDN or Google Fonts at runtime. The globe animation is simulated from published rankings and labelled "not live" (G2).
- **Where it runs (D1):** on the Mac, `./run.sh` starts the API and the Vite dev server; the dev server listens on all interfaces so a phone on the same hotspot can open the page, while the API stays on 127.0.0.1 behind the dev server's `/api` proxy. Hosting (Hugging Face Spaces) is a later option and would change the privacy statement.
- **Gradio** was retired on 2026-10-28 as D9 says: `src/app.py` is deleted and Gradio is out of `requirements.txt` and `pyproject.toml`. `./run.sh` is the only way to start the app.

---

## 4. OCR (D10, D19, D19b)

**Tesseract 5 only.** `src/shield/ocr/reader.py` re-encodes the image in memory with Pillow (EXIF, grayscale, invert if dark, no upscaling) and pipes it to `tesseract stdin stdout` with `eng+hin+kan`, `--psm 6`; no temp file and no pytesseract (which writes temp files). `src/shield/api/upload.py` reads the multipart body with a hard cap in memory, because Starlette spills uploads over 1 MB to disk. Accepted: PNG / JPEG / WEBP by magic bytes, at most 8 MB and 6000 px.

The draft's other candidates (EasyOCR, IndicPhotoOCR) were never built, so the multi-engine evaluation and its decision rule were not run; Apple Vision was dropped (no evidence of Hindi / Kannada). Measured quality (`reports/ocr_cer_public.md`, `src/ocr_cer.py`): 24.3% character error rate on 5 real public English screenshots (target 3%, not met); the rupee sign is often misread, and a link can come out with one wrong character.

**UI consequence, the design rule that follows from the measurement:** the OCR text always goes into an editable box and the user confirms it before analysis; the image is never stored or sent, and the page tells the user to check amounts and links. Two narrow link repairs (D19b) exist; the rest are left visibly broken, because a wrong-but-plausible host is worse than a broken one.

---

## 5. Links engine: reputation design (D2, D3, D12, D14, D16, D23)

### 5.1 Signals

| Signal | Offline / live | What leaves the machine | Level effect |
|---|---|---|---|
| Host-only URL model (`links/lexical.py`) | offline | nothing | Suspicious at most when alone (C2); flag threshold 0.662 (C3) |
| Platform knowledge (shorteners incl. the maintained list, free hosts, user-content hosts; `links/platforms.py`) | offline | nothing | a platform is never judged by its registered domain; unexpanded shortener -> Can't judge |
| Brand lookalike R4, exact brand name on a non-official domain R10, IDN homograph R3 (`links/lookalike.py`) | offline | nothing | R4 / R10 Suspicious, R3 Likely scam |
| Raw IP host R5 | offline | nothing | Suspicious |
| OpenPhish + URLhaus (R1) | offline lookup of a list downloaded by `update_link_lists.py` | nothing at lookup time; the UI shows the list's age | Likely scam; a list older than 7 days reads "couldn't verify" |
| Tranco 1M | offline | nothing | top 10k, not a platform / shortener / gambling site: P2, link "No warning signs"; popularity otherwise display only |
| Gambling lookup (G1, `links/gambling.py`) | offline | nothing | Suspicious, never Likely scam on its own |
| `.bank.in`, verified `.brand` TLDs | offline | nothing | P1 (can lower, see §1.3); `.gov.in` / `.nic.in` and high-abuse TLDs are display only |
| **RDAP domain age** | live | the registered domain, straight to the TLD registry through the IANA bootstrap | R7: registered < 30 days -> Suspicious |
| Cloudflare DNS-over-HTTPS + offline IP -> ASN | live | the registered domain; the IP is never contacted | R6: shares a server with listed hosts (CDNs excluded) -> Suspicious |
| Google Safe Browsing v5 | live, only if `SAFE_BROWSING_KEY` is set | 4-byte hash prefixes | R2 -> Likely scam; non-commercial use, attributed in the UI |
| Shortener expansion | live, **on a button press only (D3)** | the short link, to its shortener, no redirects followed, at most 3 hops | the destination is then judged like any link |
| crt.sh first certificate | live, **off by default (C1)** | the registered domain | R8: first certificate < 7 days, only when no RDAP date, Suspicious |

Never done: any request to the target host or its IP, screenshots of the target, VirusTotal (it takes the full URL), phone-number reputation. Tranco, OpenPhish and Safe Browsing are non-commercial sources; replacements are listed in `docs/decisions/D23_link_checks.md`.

### 5.2 Combining signals: a transparent ladder, not a learned model

A learned combination cannot be trained honestly here: Tranco domains are old and popular by construction, and feed domains looked up days later were taken down, so a model would learn when the lookup happened. The ladder in `src/shield/links/reputation.py` (header comment is the rule list; D14, D16):

- **Likely scam:** R1 (list), R2 (Safe Browsing), R3 (homograph); R9, two or more of R4-R8 / R10 on one link.
- **Suspicious:** R4 lookalike, R5 raw IP, R6 shared listed server, R7 registered < 30 days, R8 first certificate < 7 days (only when the date cannot be checked), R10 exact brand name on a non-official domain.
- **Display only:** domain age 30-179 days, registration length, registrar, RDAP status, provider, country, popularity outside the top 10k, abuse TLD, international address.
- **Positive (P1, P2):** only without a hard-risk signal in the message and never against a red flag on the same link; wording is "a well-known website", never "safe".
- **Can't judge:** a free-hosted or shortened link with no hit and no expansion.
- A failed live check shows "Couldn't verify (...)" and is never cached or read as a good sign.

Evaluation: `reports/link_signals_val.md` (flags on val URLs and messages) and `reports/eval_live_links.md` (a live run, which is why crt.sh is off, C1).

### 5.3 How it is shown

The link panel breaks the address into parts and highlights the registered domain, then a checklist of facts (lists with their age, registered N ago, popularity, lookalike, short-link destination), each with a plain "why". Each fact that came from a live call records what was sent (its `sent` field, the registered domain and the service). Pending checks show a spinner; a timeout shows "couldn't verify (timed out)". A verdict raised by the live checks says "Raised after the website checks". The page states that the link was not opened.

### 5.4 Privacy (what never leaves or persists)

- **Image bytes stay in memory** (D19): re-encoded with Pillow and piped to Tesseract; no temp file.
- **No content in URLs or logs.** `/api/analyse` and `/api/ocr` are POST; text, sender and image are never logged or written; uvicorn's access log shows method, path and status only. Only a registered domain (or the one short link on the button press) leaves the machine, never message text (rule 8).
- **The live-check cache (D12)** is in memory only: a 2,000-entry LRU in `links/live.py` with a TTL per check (RDAP 24 h, DNS 1 h, crt.sh 24 h, Safe Browsing 30 min, expansion 1 h). Failures are never cached. It is gone when the server stops, so there is no on-disk cache and no clear button; this replaced the draft's SQLite cache with 30-day hashed keys.
- **The browser** loads no third-party assets and stores one thing in `localStorage`: the light / dark choice (`frontend/src/lib/theme.ts`, every access in try/catch). This relaxes the draft's "nothing in localStorage".
- **Disagreeing with a verdict (D5c)** must store nothing by default; only an opt-in study / volunteer mode may save masked text, verdict and the user's label locally. No dispute button or study mode exists yet.

---

## 6. Result screens

**One result layout** (`docs/design/`, V1, D4, D24):
1. **Verdict panel:** level word, icon, one line, and the radar meter. No percentage (D4): the 0-100 `risk_score` is a warning-sign meter inside the band of the final level, not a probability, and never contradicts the verdict; Can't judge shows no score and a grey meter. A calm "Lowered from..." line appears only when a brand-owned link (P1) really lowered the level.
2. **Why (top 3):** plain sentences, the exact phrase underlined in the message. Order: rules, link evidence, tactic tags, model.
3. **Link panel:** §5.3.
4. **What to do now:** from `core/advice.py` per level (the frontend owns no advice copy), plus an investment card ("Before you invest", SEBI) when an investment rule fired. On Suspicious and Likely scam a helpline row follows: call 1930 and cybercrime.gov.in, with an EN / हिंदी / ಕನ್ನಡ switch (`frontend/src/lib/helpline.ts`).
5. Warning cues are shown only when the verdict is at least Suspicious; on No warning signs they stay neutral so a genuine bank alert is not shown "authority" as a red flag [few-FA].

**Input:** a paste box with live detection chips, or a screenshot (paste, drop, picker); the OCR text is shown for the user to correct (§4). The optional sender field was removed from the UI (D18); the backend keeps the sender rule.

**Languages (D6, D17).** The UI is English. Reasons and advice are to be offered also in Hindi and Kannada, marked "translated, under review" until a native speaker has reviewed them (D15); the Hindi / Kannada / Hinglish results carry an "experimental" note until real numbers exist (D6). The backend half of D6 is built: `Report.meta.lang` is set on every Report and the language cap (§1.3) lowers a text-only Likely scam to Suspicious with the English reason line; the Hindi and Kannada versions of that line are in `core/lang.py` (marked needs-review) but not in the Report, so the UI cannot show them yet. Today only the helpline row and the investment card and reasons switch language, with no review mark, and the rest is English. This is frontend work scheduled after splits-v3 and the backend.

**Study mode (D13).** A small user study in mid / late November (about 8-10 people, about 10 messages each, with and without the app). Its design, including a way to hide the reasons and advice and what is logged (only the participant's answers on prepared stimuli, never pasted content), is a later session. Not built.

---

## 7. Modules not built

The draft's Transactions (UPI ID and PSP-handle checks, collect-request rules, QR decode, receipt checks) and Apps (package catalog, APK manifest parse, permissions) engines have no code, no data and no decision beyond "only after the core is solid". Their design notes from the draft stand as intent: deterministic rules and advice first, ML only where data exists; a QR that pays when a message promises a refund would be the case D16 left open; "a screenshot can't prove a payment" stays a fixed line. The investment-scam rules (A1-A12, `invest_rules.py`, `docs/plans/investment_scams.md`) are the one new message-level module since the draft.

---

## 8. Status and what remains

**Built:** the Messages path with OCR; MuRIL text head with calibration (D27); host-only URL model; the link evidence ladder with live checks (D23, C1-C3); gambling (G1); OTP / PIN / CVV, PIN-to-receive (R2) and investment rules; sender rule (backend, dormant, D22); the risk meter (D24); the React frontend; real-message intake with the frozen TEST / POOL split (D-a).

**Next, in order:** (1) splits-v3 and the retrain (`docs/plans/splits_v3.md`; POOL-val is the real-dev set, D7); (2) D6 and D17 frontend work: the experimental note, Hindi / Kannada reasons and advice with the "under review" mark, after the D15 reviews; (3) the user study (D13); (4) the freeze: models and thresholds, then the final real-message test set **once** (rule 12), with per-language, per-source, LOSO, adversarial and false-alarm tables; (5) the full-URL view of the URL head, the last item (D8).

## 9. What to cut if time runs short (first cut first)

crt.sh is already off (C1). Then: Safe Browsing (keep the local lists); shortener expansion (keep "can't verify: hidden destination"); model highlights for MuRIL; Hindi / Kannada advice beyond the helpline row; the full-URL view (D8, already last). Transactions and Apps are outside the core.

**Never cut:** Messages + OCR, the false-alarm evaluation on genuine messages, "Can't judge", the no-network gate, the final real test set (once), the user study, and the adversarial results.

---

## 10. Decisions

All decided; the log (`docs/decisions/README.md`) has the full text, dates and evidence.

| ID | Decision | How |
|---|---|---|
| D1 | Run locally on the Mac, reachable over a phone hotspot; Hugging Face Spaces later | user |
| D2 | Live checks on: RDAP and local lists; Safe Browsing only with a key; crt.sh fallback only (now off by default, C1) | user; built (D23) |
| D3 | Shortener expansion only on a button press | user; built |
| D4 | No percentage; four-zone meter that never contradicts the verdict | user; built (D24) |
| D5 (+b, c) | Operating-point targets (Likely scam <= 1%, Suspicious+ <= 5% of hard-legit templates), promo_gray, dispute button stores nothing by default | user; design targets until real-dev exists |
| D6 | Hindi / Kannada / Hinglish "experimental" in the app and the report until real numbers exist; consent-based collection asked of the Dean | user 2026-10-28; cap built in the backend, UI note not built |
| D7 | Real-dev and final sets: TEST / POOL grouped freeze (D-a), POOL-val = real-dev (splits-v3 D-v3.1) | by build |
| D8 | URL head stays host-only; the full-URL view is the last item | user 2026-10-28 |
| D9 | React + Vite + Tailwind + Motion on FastAPI JSON; Gradio retired (done 2026-10-28) | user; built |
| D10 | OCR: Tesseract only; user checks amounts and links (CER 24.3%) | by build (D19, D19b) |
| D11 | Rules and lexicon match on a folded view; models read only `model_text` | user 2026-10-28; built 2026-10-28 (`shield.core.fold`) |
| D12 | Live-check cache in memory only, TTL per check, failures never cached | by build (D23) |
| D13 | Small user study mid / late November | user 2026-10-28; design later |
| D14 | Ladder numbers as in `reputation.py` (< 30 days; 30-179 display; cert < 7 days fallback; Tranco top 10k) | by build (D23) |
| D15 | Helplines checked against official sources; Hindi / Kannada reviewed by a native speaker; cyber-cell reviewer if the Dean can connect one | user 2026-10-28; reviews not recorded yet |
| D16 | Floors: lists, Safe Browsing, homograph -> Likely scam; gambling, OTP, PIN-to-receive -> Suspicious | by build |
| D17 | English UI; reasons and advice also in Hindi / Kannada, marked "translated, under review" | user 2026-10-28; partly built |
| D18 | Sender-ID check built in the backend, removed from the UI, dormant | by build (D22) |
| Also | G1 gambling, R2 PIN-to-receive, D19 / D19b OCR, D20 / D26 translated rows (train only), D21, D23 link checks, D24 meter, D25 fonts and light theme, D27 MuRIL head, C1-C3 link tuning, V1 / G2 visual direction, D-a phones for training and test | see the log |

---

## 11. Verification

- **Tests:** `.venv/bin/python -m pytest -q` runs one wrapper per test file (contract, API, OCR, links, gambling, risk, sender, demo and others); each wrapper runs its numbered checks. Run it on both text heads (`SHIELD_TEXT_HEAD=baseline`). `tests/test_api.py` T7 is the no-network gate. The demo set `docs/demo/` is locked by `tests/test_demo.py` (`reports/demo_check.md`). Frontend: vitest and the Playwright checks in `frontend/e2e/` (`frontend/CLAUDE.md`).
- **Evaluations** (each writes `reports/`): `src/eval_text_head.py` (one command per model: bundle check, val re-score on the Mac, test scored once, cached), `src/eval_loso.py`, `src/eval_real.py` (the real-message TEST set, once, logged in `reports/real_eval_ledger.md`), live link evaluation (`reports/eval_live_links.md`), `src/ocr_cer.py`.
- **Not yet built:** a product-level evaluation of the final verdict on genuine messages at the operating point (D5 targets, `docs/plans/splits_v3.md` gate G1), and a latency test.

## 12. Where the pieces live

Research scripts stay in `src/` and keep working with `python src/x.py`: `build_text.py`, `augment.py`, `finetune.py`, `calibrate_text_head.py`, `baseline.py`, `url_head.py`, `intake_real.py`, `eval_*.py`. The product imports from the single shared copies `src/textprep.py` (`model_text`, `extract_urls`), `src/url_features.py` and `src/pii.py`; never re-implement them (rule 11).
