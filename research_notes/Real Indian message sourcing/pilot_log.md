# Pilot: verbatim scam messages from public pages (2026-10-25)

Run by an agent with WebFetch / WebSearch only (no Firecrawl, curl or browser). Budget 25 web calls; **used 24** (3 failed with HTTP 403, 1 returned only a redirect). Every link inside a message is defanged. No link from a message and no image was opened.

Output files:
- `data/collected/inbox/pilot_quotes.csv`: 7 rows (5 from Part 1, plus 2 found while checking A1)
- `data/collected/inbox/pilot_images.csv`: 2 rows, both unverified
- this log

**Headline: the yield is far below the estimates.** Part 1 opened 9 pages (10 fetches) and found 5 messages: 1 full verbatim message and 4 fragments. The 40-message target was nowhere near. The fact-check desks mostly describe messages in their own words. The PIB re-reports quote the text more often but put the message itself in an image of the PIB X post. Also, WebFetch only returns quotes up to about 125 characters, so long messages come back cut off (see Problems).

## Part 1: per-page table

Times are `date +%s` stamps taken before and after each page. They are agent seconds (tool wait plus model time), not human minutes. Part 1 ran from 1792913700 to 1792913959, **259 s (4.3 agent minutes)**. All Part 1 rows were written to the CSV in one batch at the end. That writing time (about 30 s) falls inside page 9's seconds, because page 9's end stamp was taken after the rows had been drafted.

| # | URL | Outlet | Date | Src | Text msgs | Image-only msgs | Seconds |
|---|---|---|---|---|---|---|---|
| 1 | https://www.thequint.com/news/webqoof/gas-bill-scam-where-scammers-send-malicious-apps-and-links-via-whatsapp-to-access-victims-phones | The Quint WebQoof | 2025-08-01 | A | 0 (one "representative" line, "Please download the new app to access your updated gas bill", left out as illustrative) | 0 (images lazy-loaded: only a 1x1 placeholder was visible) | 23 |
| 2 | https://www.india.com/business/sbi-customers-attention-received-a-message-asking-to-download-and-install-apk-file-to-redeem-sbi-reward-over-whatsapp-sms-heres-the-truth-pib-fact-check-says-fake-8466504/ | India.com (PIB re-report) | 2026-07-06 | B | 1 (fragment: cut at the 125-character quote cap) | 0 new (the embedded PIB X post links a picture, probably the same message; not seen) | 38 |
| 3 | https://www.boomlive.in/decode/scamcheck/fake-rto-e-challan-message-on-whatsapp-a-growing-apk-scam-29919 -> 301 to https://www.decodeinternet.in/decode/scamcheck/fake-rto-e-challan-message-on-whatsapp-a-growing-apk-scam-29919 | BOOM Decode (now decodeinternet.in) | 2025-11-05 | A | 0 (paraphrase only; quotes only the APK file names) | 0 | 28 (2 calls) |
| 4 | https://yourstory.com/2024/07/report-sms-scams-india-chakshu | YourStory | n/a (HTTP 403) | B | n/a | n/a | 12 |
| 5 | https://www.outlookbusiness.com/amp/story/news/govt-alerts-about-fake-sms-fraud-targeting-sbi-customers-know-what-to-do-if-you-are-a-victim-news-198037 | Outlook Business (Outlook Money Team) | 2022-05-23 (updated 2023-07-07) **PRE-2024** | B | 1 verbatim (SMS) (+1 PIB tweet left out: an advisory, not a message) | 0 | 26 |
| 6 | https://www.thequint.com/news/webqoof/echallan-scam-using-fake-parivahan-website | The Quint WebQoof | 2025-12-22 | A | 2 fragments (5 and 6 words, quoted inside a paraphrase) | 0 (images not visible) | 21 |
| 7 | https://deccanchronicle.com/nation/rbi-did-not-send-whatsapp-apk-notices-warns-pib-fact-check-1963061 | Deccan Chronicle (ANI) | 2026-06-12 | B | 0 (paraphrase; only PIB's advice is quoted) | 0 confirmed (1 screengrab of the PIB X post, which may show the message: in the images CSV) | 33 |
| 8 | https://www.thequint.com/news/webqoof/fraudulent-link-about-receiving-5000-rupees-upon-rcb-ipl-win-fact-check | The Quint WebQoof | 2025-06-10 | A | 1 fragment (Facebook poster text, first ~110 of ~148 characters) | 0 | 31 |
| 9 | https://moneylife.in/article/fraud-alert-stay-away-from-dangerous-links-in-bank-sms/70038.html | Moneylife | n/a (HTTP 403) | B | n/a | n/a | 46 (includes the batch row writing) |

### Totals per source (Part 1 only)

| Source | Pages tried (opened) | Fetch calls | Messages (verbatim / fragment) | Agent minutes | Messages per agent-hour | Messages per page tried (per page opened) |
|---|---|---|---|---|---|---|
| A: fact-check desks | 4 (4) | 5 | 3 (0 / 3) | 1.72 (103 s) | 105 (verbatim: 0) | 0.75 (0.75) |
| B: PIB / bank-alert re-reports | 5 (3) | 5 | 2 (1 / 1) | 2.58 (155 s) | 46 (verbatim: 23) | 0.40 (0.67) |
| Total | 9 (7) | 10 | 5 (1 / 4) | 4.32 (259 s) | 69 | 0.56 (0.71) |

How to read these numbers:
- The per-hour figures come from tiny samples (3 and 2 messages) and agent seconds. Treat them as noise. The figure that transfers to a human is **messages per page: about 0.5-0.75, and almost all are fragments**.
- At about 0.6 messages per page, 40 messages would take about 70 pages.
- Source A gave more items per page, but all of them were short fragments inside paraphrase. Source B gave the only full verbatim message, and it is from 2022.
- Images: the page screenshots of the scam messages were invisible to WebFetch. The Quint shows only a lazy-load placeholder GIF. The PIB re-reports show the PIB X post, as a pic.twitter.com link or as a screengrab of the post. So the image-only column is 0 because the images could not be seen, not because the pages have no screenshots.

### Screenshot images listed (`pilot_images.csv`): 2, both unverified

1. India.com page: `pic.twitter.com/VyE4RLK7k4`. This is the picture link in the embedded PIB Fact Check post, probably the fake SBI reward message. It resolves to x.com, which this pilot must not fetch.
2. Deccan Chronicle page: `https://www.deccanchronicle.com/h-upload/2026/06/12/2050920-pibfactchecknovember3202417306143817301730614400109.jfif`. A screengrab of a PIB Fact Check X post about fake RBI APK messages. It may contain the message image. English.

Left out: the Decode hero image `1050404-brushing-scam-1.webp`, a generic illustration according to its file name. The 25-image target was not reachable from WebFetch output.

## Part 2: A1 verification

Part 2 ran from 1792913971 to 1792914121, **150 s**, and used calls 11-24: 9 searches and 5 confirmation fetches, 1 of which failed. Only 5 messages were collected, so **n = 5, not 15**. Every Part 1 message was checked. Two phrases were tried where the first found nothing.

One limitation shaped how the checks were done. The search tool returns titles, URLs and a summary written by a model, never the exact-text snippet. A quoted-phrase search therefore does not prove the phrase is on another page, and each candidate match needed one more fetch to confirm.

| # | Message (start) | Src | Phrase(s) searched | a1_second_url | a1_match | Note |
|---|---|---|---|---|---|---|
| 1 | "Dear Value Customers, Your SBI NETBanking Reward Points(Rs 9980.00)..." | B | "will expire today! Now Redeem through SBI Reward App"; "Your SBI NETBanking Reward Points"; then a broader search | https://www.latestly.com/social-viral/fact-check/did-you-receive-an-sms-or-whatsapp-message-asking-you-to-download-an-app-to-redeem-sbi-reward-points-pib-fact-check-debunks-fake-message-going-viral-7253978.html/amp | **near** | LatestLY 2025-12-27, own byline, not wire copy. Same wording and the same Rs 9,980 amount, but casing and punctuation differ ("Dear Valued Customer", "NetBanking", "Rs 9,980"). Counted as near because the characters differ. One of the two outlets, or the fetch tool, changed the text. The two quoted-phrase searches found nothing; the match came from the broader search. |
| 2 | "Dear Customer, Your SBI bank documents have expired, please click here to update it." | B | "Your SBI bank documents have expired, please click here to update"; "Your SBI bank documents have expired" | https://varindia.com/news/govt-warns-sbi-users-to-delete-scam-messages-immediately-to-avoid-losing-money | **near** | VARIndia 2022-05-23 quotes the same template with different wording ("Dear A/c holder SBI BANK documents has expired A/c will be blocked Now Click ... Update by NetBanking."). Both re-report the same PIB tweet. Outlook Business's tidier version is probably the outlet's own rewording. The outlookmoney.com hit was not counted: same publisher group. |
| 3 | "traffic violation fine remains unpaid" | A | that phrase; "fine remains unpaid" + challan | (none) | **none** | Only foreign unpaid-fine news. The Fact Crescendo challan explainer (2025-10-01) quotes different wording ("Your traffic challan is pending, pay immediately to avoid penalty", probably an illustrative example). The fragment is too short (5 words) for a real test. |
| 4 | "speeding offence linked to your vehicle" | A | that phrase | (none) | **none** | Only unrelated UK / AU / NZ speeding pages. Fact Crescendo: no. The Business Standard PIB challan story returned 403. |
| 5 | "A reward of ₹5000 to the people of India in celebration of the Royal Challengers Bangalore (RCB)'s victory," | A | "to the people of India in celebration of the Royal Challengers Bangalore"; "click to receive money in your account" | (none) | **none** | Only The Quint itself (the AMP copy of the same page). |

**Match rate: exact 0 / near 2 / none 3 / syndicated-only 0, out of n = 5.** That is 2/5 (40%) with exact and near counted together, and 0/5 exact. By source: B 2/2 near, A 0/3. The A items were all short fragments, which is the main reason they failed.

Two more rows came out of the A1 fetches and are in the CSV with `FOUND DURING A1` in `a1_note`. They are **not** counted in the Part 1 yield:
- VARIndia 2022-05-23 (pre-2024): the "SBI BANK documents has expired" SMS. The link is defanged. Marked fragment, because the fetch tool said the link text was shortened.
- LatestLY 2025-12-27: the "Dear Valued Customer ... Rs 9,980" message. Only the first ~120 of ~180 characters; the tool returned the rest as a separate quote, so the two parts were not joined.

## Flagged: older than 2024

- Outlook Business row (published 2022-05-23, updated 2023-07-07).
- VARIndia row (2022-05-23).

The SBI reward template appears on 2025-12-27 (LatestLY) and again on 2026-07-06 (India.com), so it has circulated for at least 6 months.

## Problems met

1. **The quote cap in WebFetch.** WebFetch's summarising model limits verbatim quotes to about 125 characters. Long messages come back cut off or split into pieces. Those rows are marked `fragment`. Full text needs a person copying from the page, or a raw-page fetch: curl was not allowed in this brief, and Firecrawl is paid and needs the user's OK.
2. **The text is a model's transcription, not the raw HTML.** Casing, punctuation and spacing may be changed. The SBI-reward pair shows this: we cannot tell whether an outlet or the tool changed the text. Check every row against the page by hand before ingestion.
3. **The fact-check desks paraphrase.** The Quint (3 pages) and BOOM Decode (1 page) describe the lure in their own words, with at most short quoted phrases. The Quint's images are lazy-loaded (a `data:image/gif` placeholder), so its screenshots are invisible to a fetch. BOOM Decode has moved to decodeinternet.in (301).
4. **The PIB re-reports put the message in an image.** The text sits inside the embedded PIB X post or a screengrab of it. Text is quoted only sometimes (India.com, Outlook Business, VARIndia, LatestLY did; Deccan Chronicle did not).
5. **HTTP 403 to automated fetches:** YourStory, Moneylife and Business Standard (Factly too, in the earlier research pass).
6. **The search tool gives no exact-text snippets,** so A1 needs a confirmation fetch per candidate: about 2 calls per verified item.
7. **Fragments of 5-6 words cannot be A1-checked** in any meaningful way.
8. The quoted channel is often vague ("SMS or WhatsApp"), so `channel = unknown` on 4 of 7 rows.

## Leads not opened (from the search results; message counts unknown)

- SBI reward APK: outlookmoney.com/banking/sbi-reward-scam-govt-urges-state-bank-of-india-customers-to-be-vigilant-check-details; outlookmoney.com/banking/sbi-cautions-customers-against-fake-reward-apk-scam-pib-fact-check-flags-fraud-message; newsable.asianetnews.com/gallery/business/sbi-rewards-scam-government-warns-customers-about-fake-apk-download-rba-sq7uug; digitalterminal.in/amp/story/trending/government-issued-alert-to-sbi-customers-against-fake-internet-banking-reward-scam; cybersecuritynews.com/beware-fake-sbi-reward-apk-attacking-users/amp/; thetechoutlook.com/news/security/fraudsters-target-sbi-customers-with-fake-yono-rewards-message/
- SBI KYC / PAN (2022): businesstoday.in (PAN-update SMS, 2022-08-30 and 2022-11-11); republicworld.com fact-check; freepressjournal.in (YONO Aadhaar).
- E-challan: keralakaumudi.com/en/news/news.php?id=1574164; au.bank.in/blogs/check-fake-traffic-challan; indianbank.bank.in/en/that-challan-message-on-your-phone; thehitavada.com (2025-06-09); m.greaterkashmir.com/article/authorities-raise-red-flag-over-fake-online-challan-messages-in-srinagar/474282; onmanorama.com/news/business/2025/01/22/kollam-fake-e-challan-whatsapp-scam.html

## Web-call log (final count: 24 of 25; 3 failed with 403, 1 redirect only, all counted)

1. WebFetch: https://www.thequint.com/news/webqoof/gas-bill-scam-where-scammers-send-malicious-apps-and-links-via-whatsapp-to-access-victims-phones
2. WebFetch: https://www.india.com/business/sbi-customers-attention-received-a-message-asking-to-download-and-install-apk-file-to-redeem-sbi-reward-over-whatsapp-sms-heres-the-truth-pib-fact-check-says-fake-8466504/
3. WebFetch: https://www.boomlive.in/decode/scamcheck/fake-rto-e-challan-message-on-whatsapp-a-growing-apk-scam-29919 (301 redirect, no content)
4. WebFetch: https://www.decodeinternet.in/decode/scamcheck/fake-rto-e-challan-message-on-whatsapp-a-growing-apk-scam-29919
5. WebFetch: https://yourstory.com/2024/07/report-sms-scams-india-chakshu (FAILED, 403)
6. WebFetch: https://www.outlookbusiness.com/amp/story/news/govt-alerts-about-fake-sms-fraud-targeting-sbi-customers-know-what-to-do-if-you-are-a-victim-news-198037
7. WebFetch: https://www.thequint.com/news/webqoof/echallan-scam-using-fake-parivahan-website
8. WebFetch: https://deccanchronicle.com/nation/rbi-did-not-send-whatsapp-apk-notices-warns-pib-fact-check-1963061
9. WebFetch: https://www.thequint.com/news/webqoof/fraudulent-link-about-receiving-5000-rupees-upon-rcb-ipl-win-fact-check
10. WebFetch: https://moneylife.in/article/fraud-alert-stay-away-from-dangerous-links-in-bank-sms/70038.html (FAILED, 403)
11. WebSearch: "will expire today! Now Redeem through SBI Reward App"
12. WebSearch: "Your SBI bank documents have expired, please click here to update"
13. WebSearch: "traffic violation fine remains unpaid"
14. WebSearch: "speeding offence linked to your vehicle"
15. WebSearch: "to the people of India in celebration of the Royal Challengers Bangalore"
16. WebSearch: "Your SBI NETBanking Reward Points" expire today
17. WebSearch: "Your SBI bank documents have expired"
18. WebSearch: "click to receive money in your account" RCB 5000
19. WebSearch: "fine remains unpaid" challan scam message WhatsApp India
20. WebFetch: https://varindia.com/news/govt-warns-sbi-users-to-delete-scam-messages-immediately-to-avoid-losing-money
21. WebFetch: https://www.business-standard.com/india-news/fake-traffic-challan-scam-pib-warning-whatsapp-sms-links-126071000400_1.html (FAILED, 403)
22. WebSearch: "NETBanking Reward Points" SBI scam message APK expire today
23. WebFetch: https://english.factcrescendo.com/?p=28503
24. WebFetch: https://www.latestly.com/social-viral/fact-check/did-you-receive-an-sms-or-whatsapp-message-asking-you-to-download-an-app-to-redeem-sbi-reward-points-pib-fact-check-debunks-fake-message-going-viral-7253978.html/amp
