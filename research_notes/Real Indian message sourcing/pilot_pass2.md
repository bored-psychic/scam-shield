# Pilot pass 2: raw HTML and article images (main session, 2026-10-25)

Why a second pass: pass 1 (`pilot_log.md`, WebFetch) returned 5 messages, 4 of them fragments. WebFetch's summarising model cuts quotes at about
125 characters and may change casing and punctuation, so its "verbatim" text is not trustworthy. Pass 2 fetched the host pages' raw HTML
with curl (one request per page, no crawling, no link from inside a message, no X / Reddit / Facebook / Telegram page or image) and the
article-hosted images that show messages. Images and HTML are in `data/collected/inbox/pilot2/` (git-ignored). No message link was opened.

## What each fetch gave

| call | what | result |
|---|---|---|
| 26 | Mendeley f45bkkt8pr v1 zip (public API download) | 200; `Dataset_5971.csv` (5,971 rows), SHA-256 of the zip `c2b5a89d...fb75`; audited in `reports/dataset_audit.md` |
| 51 | The Quint, e-challan / fake Parivahan (2025-12-22) | 200; 1 body image = a screenshot of the fake **website** (not a message); 0 quoted messages in the HTML |
| 52 | The Quint, KYC phishing (2025-03-26) | 200; hero art only; 1 quoted line ("Update your KYC now, or your bank account will be frozen!") that the article presents as typical wording, not a received message: not collected |
| 53 | The Quint, fake WhatsApp tax notices (2026-08-02) | 200; hero art + an author photo; 0 messages |
| 54 | Decode (BOOM), fake RTO e-challan APK (2025-11-05) | 200; hero composite `h-upload/2024/09/17/1033408-apk-011.webp` |
| 55 | LatestLY, SBI reward points, PIB fact check (2025-12-27) | 200; the full message quoted in the HTML (180 characters; WebFetch had cut it at about 120) |
| 56 | newsonair.gov.in, PIB fake RBI message | 200; the only image is the PIB Fact Check logo |
| 57 | factcheck.pib.gov.in | 200 but a login / submission page: no public archive of debunks |
| 58 | Quint body image (call 51) | the fake Parivahan website: not a message |
| 59 | Deccan Chronicle screengrab (from `pilot_images.csv`) | PIB's SBI-reward graphic, text partly under a FAKE stamp |
| 60 | newsonair image | PIB logo: not a message |
| 61 | Decode hero composite (call 54) | **4 real phone screenshots**: PNB KYC + APK, ICICI PAN + APK, J&K electricity disconnection + APK (WhatsApp), VAHAN PARIVAHAN challan APK |
| 62 | LatestLY featured image | PIB's SBI-reward graphic (same as call 59), FAKE stamp over parts of the text |
| 63 | decodeinternet.in/decode/scamcheck (hub) | 404, no article list |
| 64 | WebSearch for Decode ScamCheck articles | only unrelated Panda Security pages (the search tool is US-only) |
| 65-68 | WebSearch, A1 phrases of the 4 Decode messages | PNB: PNB's own caution on the KYC-block template (DT Next, Newsgram 2023); ICICI: ICICI's caution (Outlook Money); VAHAN: the Vahan Parivahan APK campaign (Deccan Herald, The Quint, Moneylife); electricity: nothing. Search summaries only: the exact wording was not confirmed on a page |

## Findings

- **Outlets rewrite "verbatim" quotes.** LatestLY prints "Dear Valued Customer, Your SBI NetBanking reward points (Rs 9,980) will expire today!
  Now redeem through SBI Reward App. ..."; PIB's own image of the same message reads "Dear Value Customers, Your SBI NetBanking Reward Points
  (Rs 9980.00) will expire today! Now Redeem through SBI REWARD App Install & claim your reward by cash deposit in your account. Thankyou
  Team -SBI". The screenshot is the source of truth, not the article text.
- **Fact-check hero composites can be dense** (4 messages in one image), but it was the only one of 6 fact-check pages that had any message
  image; the Quint ScamGuard explainers carry hero art, not screenshots.
- **PIB items reach news pages as embedded X posts** (`pic.twitter.com`), which we do not fetch; a human can screenshot them on the page.
- Agent time for pass 2, from the first fetch to the last transcription: 324 s for 5 ingested messages (both sources together; the
  calls were not timed per source). Agent time is not human time; see the plan for the human estimate.

## Transcription (A2)

The 4 Decode panels were cropped from the composite and typed by hand from the image (by Claude, from the image, before any OCR was run),
plus the user's own dev fixture `tests/fixtures/real/jio_kiwi_dark.jpg`. Rule: every legible character in the crop except what the reader drops
by design (a time on its own line, Forwarded), icons and characters cut off at the crop edge. Result: `reports/ocr_cer_public.md`.
