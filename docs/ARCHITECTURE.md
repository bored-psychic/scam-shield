DRAFT - not yet approved. Decisions D1-D18 pending.

# Scam Shield: product architecture plan (plan only, no code until approved)

## Context

The research pipeline is in good shape: frozen splits, a TF-IDF text baseline (test F1 0.893), a host-only URL head, and a Gradio MVP (`src/app.py`) with an OTP/PIN/CVV rule, tactic tags and a placeholder `fuse()`. It is not a product yet. The reports show what has to be designed around:

- **Out-of-distribution failure.** LOSO AUROC is 0.57–0.59 on `phishing_email` and `fake_job_postings`. On `india_fraud_final` the model calls 70% of benign messages scams (`reports/sanity.md`). Real messages will behave like a new source.
- **No real Hindi or Kannada data.** All 394 rows per language are synthetic. The translations are still waiting on the native-speaker spot-check, and `splits-v2` is blocked on that.
- **The URL head is weak.** Test AUROC 0.859, 8% false alarms on Tranco domains. `google.com` scores 0.484. It flags free-hosting sites (BUGS.md). Domain-age coverage is 0%.
- **Rules and tactic tags are untuned.** The `authority` tag fires on genuine HDFC alerts.

The target, as you wrote it: *a person pastes or screenshots a message in English, Hindi, Kannada or Hinglish, and within a few seconds gets a correct verdict, the reasons, and what to do next, with few false alarms on normal messages.* Below, each design choice is tagged with the part of that sentence it serves: **[fast]**, **[correct]**, **[reasons]**, **[next]** and **[few-FA]**.

Today is Fri 2026-10-09. Week 1 starts Mon Oct 12. The core is due ~Nov 6 and all modules by ~Jan 8.

---

## 1. Design principles (they follow from the sentence)

1. **Verdict first, details later [fast].** The offline verdict comes back in ≤ 3 s. Live link checks (RDAP, Safe Browsing, shortener expansion) run asynchronously, are cached, and update their card when they finish. A slow registry never delays the verdict.
2. **Four verdict levels, not three [correct, few-FA]:** `Likely scam` / `Suspicious` / `No warning signs found` / `Can't judge`. "Can't judge" is used when the language is unsupported, the OCR is unreadable, the text is too short, or the only link is free-hosted or shortened. Never say "Safe".
3. **Rules can only raise a verdict, never lower it.** Hard rules (an OTP request, a blocklist hit, a QR that pays when the message promises a refund) act as *floors*, applied after the model and its calibration. They are not features inside the fitted model, so its probability stays interpretable. Rules that are unchecked in a language may explain, but never force a verdict (the policy the OTP rule already follows).
4. **Reasons do not depend on the model [reasons].** The top reasons come from rules, link evidence, payment evidence and the lexicon. Model highlights are a secondary "why the model thinks so". So the explanations, and the user study, survive a text-head swap.
5. **Exactly one code path may touch the network.** `shield/core/net.py` holds a host allowlist (RDAP registries, Safe Browsing, crt.sh, known shorteners, and the feed hosts for refresh jobs only). Redirects are never followed. A test asserts that offline mode makes zero network calls. This turns rule 8 ("never visit suspicious URLs") into an enforced property of the code rather than a convention.
6. **No user content touches the disk or the logs.** Details in §5.4.
7. **`textprep.model_text` stays the only model-input preprocessing (rule 11).** OCR adapters output plain text the way a person would type it (reading order, joined lines). That is OCR post-processing, not model preprocessing.

---

## 2. Folder structure and shared core

Keep `src/` as it is (research scripts, plus the single copies of `textprep.py`, `url_features.py` and `pii.py`). Add the product as a package inside it, and a `pyproject.toml` that installs both:

```
pyproject.toml            # pip install -e .[ocr,apps,dev]; py-modules = textprep, url_features, pii; packages = shield
                          #   also fixes BUGS.md "no dependency file"; the laptop uses pip install -e .[train]
src/
  textprep.py url_features.py pii.py      # unchanged, still the single copies (rule 11); importable from anywhere after install
  baseline.py url_head.py ...             # research scripts unchanged; `python src/x.py` still works
  shield/
    contracts.py          # pydantic: Level, Evidence, Report, OcrResult, LinkFacts, ModelCard (the data contracts, versioned)
    config.py             # paths, active models, live-check switches, timeouts, thresholds file
    core/
      router.py           # analyse(input) -> Report; extracts entities and routes them to the engines
      entities.py         # URLs (textprep.extract_urls), UPI IDs, phones, amounts, UTR-like numbers, .apk / app mentions (raw text, in memory)
      lang.py             # script counts + Hinglish function-word check -> en / hi / kn / hinglish / other
      ocr/                # base.py (OcrEngine protocol), tesseract.py, easyocr.py, indicphoto.py, qr.py
      verdict.py          # calibrated score -> level, rule floors, child reports, can't-judge, top-3 reasons
      advice.py + advice.yaml   # what to do next, keyed by scam category and rule id
      lexicon/*.yaml      # tactic and category cues per language, each with checked_by_native: true/false
      net.py              # the only outbound HTTP: allowlist, timeouts, no redirects; records "what was sent" per call
      cache.py            # SQLite TTL cache for live checks
    messages/  text_head.py (TextScorer, TfidfLrScorer, MurilScorer), rules.py, tactics.py, category.py, engine.py
    links/     lexical.py (UrlScorer), platforms.py, lookalike.py, blocklists.py, tranco.py, rdap.py, safebrowsing.py,
               shortener.py, crtsh.py, engine.py (evidence ladder)
    transactions/ upi.py (+ psp_handles.csv), qr_pay.py, receipt.py, rules.py, engine.py
    apps/      catalog.py (+ catalog.csv), apk.py (subprocess parse), permissions.py, engine.py
    api/       main.py (FastAPI), routes_ui.py (HTMX partials), routes_api.py (JSON, for tests and eval)
    web/       templates/ (Jinja: base, one page per module, shared result partials), static/ (css, vendored htmx.min.js, paste.js)
    jobs/      refresh_feeds.py (OpenPhish, URLhaus, full Tranco 1M, IANA RDAP bootstrap); replaces pull_urls.py's daily role
tests/         tricky_inputs.py -> tests/cases/{messages,links,payments,apps}.yaml; contract, no-network, no-disk-write, latency tests
src/eval_*.py  eval_ocr.py, eval_product.py (verdict-level FPR / per language / can't-judge rate), eval_links.py
```

Moved from `src/app.py` without behaviour change, so `tests/tricky_inputs.py` passes unchanged: `TextScorer` / `TfidfLrScorer` → `messages/text_head.py`; `cred_requests`, `_NEG_*` → `messages/rules.py`; `TACTICS` / `tactic_tags` → `messages/tactics.py` (regexes become lexicon YAML later); `UrlScorer` and its occlusion `breakdown` → `links/lexical.py`; `SHORTENERS`, `FREE_HOSTING`, `assess_link` → `links/platforms.py`; `level_of`, `fuse` → `core/verdict.py`. Once the new UI covers everything the Gradio app does, `app.py` is deleted.

### Stable interfaces (swap a model or engine without touching anything else)

| Interface | Methods | Now | Later |
|---|---|---|---|
| `TextScorer` | `name`, `version`, `textprep_marker`, `thresholds`; `score_batch(texts) -> probs` (calibrated) | `TfidfLrScorer` | `MurilScorer` (HF dir + `shield_meta.json`) |
| text explainer | generic **word occlusion** over `score_batch` (one batched pass, model-agnostic); the TF-IDF scorer keeps its exact n-gram contributions | | integrated gradients only if occlusion proves too coarse |
| `UrlLexicalScorer` | `score_many(urls)`, `breakdown(url)` | host-only HGB | fixed host-only or full-URL view (D8) |
| `OcrEngine` | `read(image, lang_hint) -> OcrResult(text, lines[{text, conf, box, script}], ms)` | winner of §4 | |
| `LinkCheck` | `name`, `live: bool`, `sends: str`; `run(link, ctx) -> Evidence` | blocklist, Tranco, lookalike, platform, lexical | RDAP, Safe Browsing, shortener, crt.sh |
| `Engine` | `assess(item, ctx) -> Report` | messages, links | transactions, apps |

**Contracts.**
- `Evidence{id, module, effect: danger|caution|neutral|reassuring|unknown, title (one plain sentence), detail, quote/span, source ("OpenPhish feed, 2026-10-09"), sent ("domain xyz.in → rdap.nixiregistry.in" or None)}`.
- `Report{schema_version, module, level, score|None, category, evidence[], reasons[3], advice[], children[Report], pending[check ids], meta{lang, ocr_conf, model versions, ms}}`.

Every module returns a `Report`, so the UI has one renderer for all four modules. That is what makes it possible to build one component at a time.

**Model swap.** Each bundle carries a model card: textprep marker, `split_map` SHA-256, val-chosen thresholds, calibration parameters, git commit. `config.py` names the active head, and the loader refuses a bundle whose marker doesn't match (it extends today's `url_token` check). Promotion gates for MuRIL:
- per-source and LOSO table at least as good as the baseline in `reports/sanity.md`
- adversarial recall
- FPR on legitimate SMS at the chosen operating point
- ECE (calibration error)
- ≤ 300 ms per message on the M2

Results go in `reports/gates_<model>.md`. The final real test set is still run only once, at the end.

### Router flow (Messages)

```
image ──ocr──> text (+ line confidences) ──┐        qr.decode(image) ──> upi://pay or URL entities
text ──────────────────────────────────────┴─> lang.detect ─> entities.extract (raw text, in memory)
   ├─ messages.engine: model_text(text, mask_pii=True) -> TextScorer; rules; lexicon tactics; category
   ├─ each URL   -> links.engine.offline()   (live checks returned as `pending`; the UI fetches them)
   ├─ UPI / QR   -> transactions.engine
   └─ .apk / remote-access app mention -> apps.engine (catalog)
verdict.combine(parent, children) -> calibrated text score -> level; rule floors; max over children; top-3 reasons; advice
```

**Fusion.**
- **Phase 1:** calibrate the text head (Platt scaling on val; temperature scaling for MuRIL), then keep today's level rule: the max of the levels, both ≥ Suspicious → Likely scam.
- **Phase 2:** fit a small logistic-regression fusion on **val messages that contain links**. 6,745 rows contain a link; the URL head can score the extracted links offline. Features: text logit, max link logit, shortener / free-host flags, n_links. Live signals stay out of the fitted fusion, because historical message URLs have no trustworthy live values. They act as floors and reasons instead.
- **Gate:** test and per-source results versus the max rule. Keep whichever is better.

---

## 3. Backend and frontend stack

- **Backend: FastAPI + uvicorn** (already in `.venv`: fastapi 0.143, uvicorn 0.54). One process. Models load at startup. OCR and model calls run in the threadpool. Live checks use async httpx with per-host timeouts.
- **Frontend (recommended): server-rendered Jinja templates + HTMX, with no build step and no Node.**
  - Each result card is one template partial.
  - "Fill in the live checks" is `hx-get` on load or polling.
  - Screenshot paste is ~20 lines of `paste.js` (paste and drag-drop events → POST).
  - Mobile-first CSS, colour plus icon plus word for each level (not colour alone).
  - All assets vendored, so the page makes zero third-party requests. That closes the BUGS.md "Gradio footer / browser storage" question by construction.
  - Why: each component is a small, self-contained file that an AI can write and you can read (rule 9). A React SPA adds state management, a build chain and a second language of bugs, for no gain here.
- **JSON API** (`/api/...`, POST only, never user content in a URL or query string) for tests and the `eval_*` scripts.
- **The Gradio app** stays as a dev console until the new UI reaches parity (end of Phase 1), then it is deleted.

---

## 4. OCR: options and a small evaluation

| Candidate | Fit for chat screenshots | Hindi / Kannada | Mac / install | Note |
|---|---|---|---|---|
| **Tesseract 5** (`brew install tesseract tesseract-lang`) | good on clean UI text; poor on dark mode unless the image is inverted | `hin`, `kan`; `eng+hin+kan` works in one call | tiny, CPU, fast | call the CLI via **stdin/stdout** (pytesseract writes temp files, which breaks "not stored") |
| **EasyOCR** (torch) | good on screenshots | `hi`, `kn` (Kannada since v1.2, an "experimental lite" model); **one Reader per script** (`['hi','en']`, `['kn','en']`), so it needs script routing | ~100 MB of models, torch on CPU or MPS | takes numpy arrays in memory |
| **IndicPhotoOCR** (Bhashini-IITJ, *not AI4Bharat*; released with the Bharat Scene Text paper) | built for **scene text** (signboards), not dense screenshots | English + 11 Indic languages, with its own script-identification step | `setup.sh`, pinned torch; may not install on Python 3.13, so give it its own venv | its built-in script ID is the attraction |
| Apple Vision | — | no evidence of Hindi / Kannada support | Mac-only | **dropped** |

**Evaluation (about 3 days, Phase 1 week 2):**
- **Screenshot set:** `data/ocr_eval/`, git-ignored. 80 screenshots: 20 per language (en, hi, kn, Hinglish), WhatsApp + SMS app, half light and half dark mode, plus 10 phone photos of a screen.
  - **Ground truth without PII:** you send yourself existing masked or synthetic dataset rows and translated rows, then screenshot them. The ground truth is exactly the text you sent.
  - At least 30 of the 80 contain a link, a UPI ID or an amount.
- **Metrics** (`src/eval_ocr.py`):
  1. **Exact recovery of links, UPI IDs and numbers.** One wrong character in a URL breaks the Links engine, and can even create a fake "lookalike", e.g. `onIinesbi.sbi`.
  2. **Verdict agreement:** the Messages pipeline on the OCR text versus the ground-truth text.
  3. **CER** of the best-aligned match per language (screenshots include UI chrome, so ground truth is aligned, not compared whole).
  4. **Latency p50 / p95 on the M2**, cold and warm.
  5. Install footprint and licence.
- **Variants:** Tesseract with and without dark-mode inversion and 2× upscale. EasyOCR with script routing (run Tesseract's script detection first, or try both readers and keep the higher confidence).
- **Proposed decision rule (D10):** highest verdict agreement subject to ≥ 95% exact link recovery and p95 ≤ 2.5 s. Ties go to lower Hindi / Kannada CER, then to the simpler install. A hybrid is allowed (Tesseract for Latin script, another engine for Indic).
- **UI consequence:** the OCR text is always shown in an editable box ("We read this. Fix any mistakes and re-check"). Links that came from OCR carry a "check the link text" note on lookalike evidence.

---

## 5. Links engine: reputation design

### 5.1 Signals

| Signal | Offline / live | What leaves the machine | Cache TTL | Earns its place? |
|---|---|---|---|---|
| Lexical model (`url_features` + HGB) | offline | nothing | — | yes, but fix BUGS.md first: strip `www.`, add benign platform-hosted sites, choose a view (D8) |
| Platform knowledge (24 shorteners, 36 free hosts; extend) | offline | nothing | — | yes [few-FA]: stops judging `pages.dev` sites by their domain |
| Lookalike / brand: `BRANDS` + `gen_typosquat` seeds, Unicode confusables skeleton, punycode display, "claims police/court/ministry but the link isn't `.gov.in` / `.nic.in`" | offline | nothing | — | yes [correct, reasons]: the clearest explanation of all ("this link belongs to kyc-verify.xyz, not SBI") |
| Local blocklists: OpenPhish + URLhaus (daily refresh job); PhishTank when reachable | offline lookup, daily download | nothing at lookup time | refreshed daily; the UI shows "list updated N h ago" | yes; match host / exact URL, and **registered domain only when it is not a platform** |
| Tranco rank (full top-1M list; today only the top 20k is pulled) | offline | nothing | monthly | yes [few-FA]: popular registered domain → reassuring. **Never** for platform or shortener domains; never overrides a danger signal |
| **RDAP domain age** (+ status such as `serverHold`) | live | the **registered domain** only, sent straight to the TLD registry via the cached IANA bootstrap file (e.g. `.in` → `rdap.nixiregistry.in`), not via rdap.org | found: 30 d; not found or error: 1 h | yes [correct]: fresh infrastructure is README problem #3. Skipped for platform domains |
| Google Safe Browsing v5 | live | **4-byte hash prefixes** only (needs `SAFE_BROWSING_KEY` in the environment) | per the response's cache duration | yes, if you want it (D2). Non-commercial use only; the UI must attribute Google and say the check can be wrong |
| Shortener expansion | live | the short URL, to the **shortener company** only (HEAD request, redirects off; repeated only while the next hop is also a listed shortener, max 3 hops; the destination is never requested) | 7 d | yes [correct], but the hit may show up in the scammer's click count (D3) |
| crt.sh first-certificate date | live | registered domain to crt.sh | 7 d | **weak**: the current cert's age means nothing with 90-day certificates, "first cert ever" mostly duplicates RDAP, and crt.sh allows about 5 requests/min per IP with frequent 502s. Proposed: fallback only when RDAP has no date; first item to cut |

**Not included:** DNS lookups or HTTP requests to the target, screenshots of the target, VirusTotal (sends the full URL), phone-number reputation (no open data).

### 5.2 Combining signals: a transparent evidence ladder, not a learned model

A learned combination of reputation signals can't be trained honestly here, for two reasons:
- Tranco domains are popular and old by construction.
- Feed domains looked up days later return "not found" because they were taken down. A model would learn *when the lookup happened*, not *what the domain is*.

So the link level comes from a ladder (the numbers are for you to set, D14):
- **Danger → Likely scam:** a blocklist or Safe Browsing hit; an IDN homograph of a known brand; a brand or government claim on a domain that doesn't own it **and** (domain age < 90 d or a high lexical score).
- **Caution → Suspicious:** domain age < 30 d; lexical score ≥ the val threshold; a brand or keyword in a free-hosted subdomain; the shortener's destination hits any of the above.
- **Reassuring (can lower only the lexical model's flag, never a danger row):** registered domain in the Tranco top 100k, and not a platform, and no brand mismatch; or domain age > 5 years. It is worded as "a well-known website", never "safe", because compromised sites exist.
- **Can't judge:** a free-hosted site without hits; a shortener not expanded or the expansion failed.

**Evaluation (`src/eval_links.py`):**
- Phishing: fresh OpenPhish, **enriched on the day it is pulled** (avoids the takedown artefact).
- Benign groups: links from real benign messages, Tranco ranks 100k–1M, benign platform-hosted sites.
- Report recall and FPR per group, with live checks on and off (ablation).

### 5.3 How it is shown

- The URL is shown with its **registered domain highlighted**.
- Then an evidence checklist, one plain row each with an icon:
  - "Reported as phishing? Not on OpenPhish / URLhaus (updated 5 h ago)"
  - "Registered 3 days ago (registry: .in)"
  - "Not among the top 1 million websites"
  - "Looks like sbi.co.in (1 letter changed)"
  - "Short link → goes to kyc-verify.xyz"
- The lexical model is one row, with its score and threshold under "Details".
- A **"Sent off this machine"** line lists every live call made.
- Pending checks show a spinner; a check that times out shows "not checked (timed out)".

### 5.4 Privacy (what never leaves or persists)

- **Image bytes stay in memory.** Read the request body with a size cap rather than through `UploadFile`, which spools parts over 1 MB to a temp file (check this in the installed Starlette). Tesseract runs via stdin. EasyOCR gets numpy arrays. APKs are parsed from bytes in a subprocess.
- **No content in URLs.** POST only. uvicorn access logs record paths, so user content in a query string would be logged. The app logger never logs inputs.
- **The live-check cache** stores signal values keyed by SHA-256 of the domain, and there is a "clear cache" button. How long to keep it is D12.
- **The browser** keeps nothing in localStorage and loads no third-party assets.

---

## 6. Result screens

**Shared layout (one renderer for all four modules):**
1. **Verdict banner:** level word + icon + one line ("Looks like a 'digital arrest' scam"). No percentage by default (D4).
2. **Why (top 3):** plain sentences with the exact phrase quoted. Order: rules, then link and payment evidence, then lexicon, then model.
3. **What to do now (2–4 steps):** from `advice.yaml` by category or rule. "Don't pay / don't share OTP / don't install" plus helplines where they fit (1930, cybercrime.gov.in, Sanchar Saathi *Chakshu*); the exact wording needs a review (D15).
4. **Details (collapsed):** highlighted text, model score and cut-offs, detected language, OCR text (editable, re-check), child cards, "sent off this machine".

**Warning cues are shown only when the verdict is ≥ Suspicious.** On "No warning signs found" they become neutral notes, so a genuine HDFC alert isn't shown "authority: hdfc" as if it were a red flag [few-FA].

**Per module:**

| Module | Input | Result specifics |
|---|---|---|
| **Messages** | Text \| Screenshot (paste, drag, file picker; gallery on a phone); optional "who sent it?" field | link cards inline with live checks filling in; a payment card if a UPI ID or QR is found; scam category; a "less tested in this language" note for hi / kn until real data exists (D6) |
| **Links** | one URL | §5.3 checklist; "where it really goes" (registered domain, shortener destination) |
| **Transactions** | request text / UPI ID / QR or receipt screenshot | QR: **"Scanning this PAYS ₹5,000 to xyz@ybl (name 'SBI Refund')"**. UPI ID: known PSP handle? brand or government name in a personal ID? Receipt: extracted fields, format checks, and the fixed line "A screenshot can't prove a payment; check your own bank app or SMS for the credit" |
| **Apps** | app name / package / Play Store link (package parsed from `id=`, never fetched) / APK | identity: label and package, matches the official app?; "who asked you to install it?" (remote-access apps such as AnyDesk or TeamViewer QuickSupport); permissions in plain language grouped by risk (READ_SMS = can read OTPs, Accessibility = can control the phone, overlay = fake login screens) |

**Study mode:** a URL flag hides the reasons and advice, for the never-cut user study (README objective 6). It logs only the participant's answers on prepared stimuli, never pasted content.

---

## 7. Transactions and Apps engines (rules first; ML only where data exists)

**Transactions** (no labelled data, so deterministic checks plus advice):
- **UPI ID format and PSP handle list:** curated `psp_handles.csv` with a verified-on date. It also fixes the incomplete UPI list in `pii.py`, which is a splits-v2 item.
- **Impersonation:** a brand, government body or "refund / kyc / customs" in the local part of the ID.
- **Collect-request rule:** money-to-receive wording plus "enter PIN / approve / scan QR".
- **QR decode** (OpenCV, local): a `upi://pay` payload is decoded; a URL payload goes to the Links engine.
- **Receipt OCR:** amount, UTR / RRN, date; format checks, using templates built from **your own receipts** before they are trusted.
- **Not attempted:** detecting forged screenshots, and any query to UPI systems.

**Apps:**
- **Catalog:** `catalog.csv` of official Indian bank / payment / government package IDs, plus remote-access apps.
- **Lookalike check:** package or label edit distance against the catalog.
- **APK parsing:** manifest only (androguard from bytes, in a subprocess with time and size limits and a zip-bomb guard; never installed or run).
- **Permission explainer.**
- **"Any APK sent over WhatsApp or SMS is risky"** rule.
- A permission-set model on `apps.csv` (7,299 rows, permission-only, a known shortcut risk) is optional and cut first.

---

## 8. Roadmap (demo at the end of each phase)

Running in parallel the whole time:
- **Kaggle fine-tuning** (CLAUDE.md step 7). Do a MuRIL *smoke run* on `splits-v1`. The **shipped** MuRIL is trained after `splits-v2` (rule 10), which waits on your spot-check.
- **Real-message collection**, starting week 1 (D7).
- **Daily** `refresh_feeds`.

| Phase | Dates | Work (model / effort per CLAUDE.md) | Demo milestone |
|---|---|---|---|
| **0. Foundations** | Oct 12–16 | `pyproject.toml` + pinned dependencies; `contracts.py`; move the `app.py` logic into engines unchanged (tricky_inputs still pass); `net.py` + no-network test; FastAPI + HTMX skeleton rendering a Messages `Report`; you start making OCR screenshots *(Sonnet medium; Opus high to review the contracts)* | the MVP's checks in the new UI; no-network and no-disk-write tests green |
| **1. Messages + OCR (core)** | Oct 19–Nov 6 | OCR evaluation → engine choice → screenshot input; `lang.py`; lexicon YAML; category + `advice.yaml`; calibration; operating point chosen for the FPR target (D5); can't-judge rules; study mode; `eval_product.py` (FPR on legit SMS, per language, can't-judge rate); MuRIL behind `TextScorer` **only if the gates pass** *(Sonnet high for calibration / eval / OCR eval)* | **"Core usable" (Nov 6):** paste or screenshot an en / hi / kn / Hinglish message → verdict, top-3 reasons, what to do, offline link cards; FPR report on legitimate SMS |
| **2. Links** | Nov 9–27 | BUGS.md URL-head fixes + D8; blocklists, full Tranco, confusables, `.gov.in` rule; RDAP via the IANA bootstrap + cache; shortener expansion; Safe Browsing (if D2); evidence ladder; Links page + live cards; fusion LR on val; `eval_links.py` with same-day enrichment *(Sonnet medium; Sonnet high for eval / fusion)* | paste a link or a message with a link → checklist with domain age, blocklist status, lookalike, shortener destination, "sent off this machine" |
| *(user study, D13)* | late Nov / early Dec | runs on the Messages + Links build | |
| **3. Transactions** | Nov 30–Dec 11 | PSP handles, impersonation, collect rules, QR decode, receipt fields + format checks, payment advice; `tests/cases/payments.yaml` *(Sonnet medium)* | QR or payment-request screenshot → "this pays ₹X to Y" / "a screenshot is not proof" |
| **4. Apps** | Dec 14–25 | catalog, remote-access list, package lookalike, sandboxed manifest parse, permission explainer *(Sonnet medium)* | upload an APK → "not the real SBI app; can read your SMS" |
| **5. Freeze + final evaluation** | Dec 28–Jan 8 | freeze models and thresholds; **final real test set, run once**; per-language / per-source / LOSO / adversarial / FPR tables; README + CLAUDE.md *(Opus high to review before freezing)* | the full product + the honest results table |

---

## 9. What to cut if time runs short (first cut first)

1. crt.sh (weak, slow, rate-limited)
2. Permission-set ML for apps
3. APK upload (keep the name / package catalog check; the README already lists APK analysis as cut-first)
4. Receipt OCR field and UTR checks (keep the QR decode, collect rules, UPI ID checks and advice)
5. Safe Browsing (keep the local blocklists)
6. Shortener expansion (keep "Can't verify: hidden destination")
7. Model highlights for MuRIL (reasons come from rules, links and lexicon anyway)
8. The third OCR candidate
9. The fusion LR (keep the max rule on top of the calibrated text score)

**Never cut:** Messages + OCR, the FPR-on-legit-SMS evaluation, "Can't judge", the no-network gate, the final real test set (once), the user study, and the adversarial results.

---

## 10. Decisions that are yours (my recommendation in brackets)

- **D1. Where it runs.** Mac only / Mac served over LAN to participants' phones / hosted (HF Spaces or a VPS). *[Mac + LAN: the realistic "screenshot on my phone" flow while processing stays on your machine. Hosting changes the privacy statement.]*
- **D2. Live checks by default.** All off (opt-in) / on with the "sent off this machine" line / RDAP only. Get a Safe Browsing key or not? *[RDAP + blocklists on; Safe Browsing on if you get a key; crt.sh fallback only.]*
- **D3. Shortener expansion.** Automatic, or on a button press (it may register as a click for the scammer). *[Button press.]*
- **D4. Show a percentage to users?** *[No. Levels plus reasons; the calibrated score sits in Details. LOSO shows calibration shifts per source.]*
- **D5. Operating point.** Target FPR on legitimate bank / OTP / delivery SMS (1% / 2% / 5%), traded against recall. *[2%, picked on val / real-dev, never test.]*
- **D6. Hindi / Kannada claim.** Collect real hi / kn / Hinglish messages for the dev and final sets, or label those languages "experimental" in the UI and the report. *[Both: collect, and keep the note until real numbers exist.]*
- **D7. Real-message sets.** Split the collection into **real-dev** (thresholds, calibration, OCR checks) and **final** (once). Legitimate SMS from 5–10 volunteers' inboxes, masked at intake, are the cheap, high-value FPR set. *[Yes to both.]*
- **D8. URL head view.** Fixed host-only, or the full-URL view (test AUROC 0.939 vs 0.859). *[Decide after the BUGS.md fixes are measured.]*
- **D9. Frontend.** HTMX + Jinja / React / stay on Gradio. *[HTMX + Jinja.]*
- **D10. OCR candidates and decision rule** (§4). Add Surya or PaddleOCR as an extra candidate? *[The three you named, minus Apple Vision; no extras unless all three fail.]*
- **D11. Rule matching.** May rules and the lexicon match on a folded view (NFKC, zero-width removed, homoglyphs folded) while models read only `model_text`? *[Yes. Otherwise homoglyphs evade the rules. Say so if you read rule 11 more strictly.]*
- **D12. Live-check cache retention.** *[Hashed keys, 30 days, plus a clear button.]*
- **D13. User study timing and build.** *[Late Nov, on the Messages + Links build.]*
- **D14. Ladder numbers.** Domain-age cut-offs (30 / 90 d, 5 y), Tranco cut-off (top 100k).
- **D15. Advice content and helplines.** Who reviews them (your bank or cyber-cell contact)?
- **D16. Floor strength.** May a blocklist hit, or a QR that pays when the message promises a refund, force "Likely scam", or only "Suspicious"? *[Likely scam for both; keep the OTP rule at Suspicious.]*
- **D17. UI language.** English only, or reasons and advice also in Hindi / Kannada (a large content and review job)? *[English UI in phases 0–2; translated advice in phase 5 if there is time.]*
- **D18. Sender-ID check.** Add an optional "who sent it?" field that enables a check like "a bank SMS comes from a header such as XX-HDFCBK, not a mobile number"? The TRAI header and suffix rules must be verified first. *[Yes, Phase 1 stretch.]*

---

## 11. Verification (how each phase is checked)

- **Tests:**
  - `python -m pytest tests/`: tricky inputs per module (YAML cases), contract tests (every engine returns a valid `Report`).
  - **No-network test:** socket monkeypatched; offline mode makes zero calls.
  - **No-disk-write test:** temp dir and `data/` untouched during an analysis with a 3 MB screenshot.
  - Latency test: p95 ≤ 3 s for a screenshot.
- **Evals** (each writes a report under `reports/`):
  - `eval_ocr.py` (§4)
  - `eval_product.py`: FPR on legit SMS at the operating point, per-language, per-source, can't-judge rate, ECE
  - `eval_links.py`: same-day OpenPhish recall, FPR per benign group, live on/off
  - MuRIL gate report
- **Demo scripts:** each milestone has 6–10 fixed inputs (in `tests/cases`), run end to end in the browser via the run skill, with screenshots in the phase write-up.
- **Docs:** after approval, update CLAUDE.md (status, next steps, model / effort rows for the new steps) and the README architecture section; open BUGS.md entries for any decision left open.

## 12. Existing code to reuse (don't rewrite)

- `src/textprep.py`: `model_text`, `extract_urls`, `refang`
- `src/url_features.py`: `parse_url`, `host_features`, `BRANDS`, `SUSPICIOUS`, `lev`
- `src/pii.py`: `mask_text`
- `src/app.py`: `TextScorer`, `TfidfLrScorer.explain`, `UrlScorer.breakdown`, `assess_link`, `cred_requests`, `tactic_tags`, `level_of`, `fuse`
- `src/enrich_domains.py`: RDAP event parsing (point it at the IANA bootstrap instead of rdap.org)
- `src/gen_typosquat.py`: `SEEDS`, `ASCII_LOOK`, `UNI_LOOK`
- `src/pull_urls.py`: feed pulls (fold into `jobs/refresh_feeds.py`; pull the full Tranco list)
- `data/final/apps.csv`
- `tests/tricky_inputs.py` + runner
- `models/*.joblib` bundle checks
