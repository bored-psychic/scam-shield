# OCR sweep: colour step off vs on

> **SYNTHETIC renders.** Theme colours are **assumed** (written from memory) except **Google Messages dark (MEASURED)**, whose page, bubble, text and link colours were
> measured from one real screenshot (`tests/fixtures/real/jio_kiwi_dark.jpg`; its timestamp colour is still assumed). Text = the 14 demo messages only.
> This is a regression guard for the dark-mode colour step, **not evidence of real-world accuracy.**

- Generated 2026-10-17 by `python src/ocr_sweep.py` at commit ad24cb8 + uncommitted changes in src/ or tests/; 389 s; seed 0 (fixes the job order only: the renders are deterministic).
- Tesseract: tesseract 5.5.3 (/opt/homebrew/bin/tesseract), languages `eng+hin+kan`, `--psm 6`.
- 15 themes x 8 conditions (png40, png28, png34, png48, jpg80, w900, w720, w540) x 14 messages = 1680 reads per configuration. A condition is a font size, a JPEG at quality 80, or a shrink to a narrower width.
- **before** = `reader._coloured_ink` switched off by a monkeypatch in this script (the plain inverted-luma conversion; digest `3f3d977ae0c6`). **after** = production code (digest `d18f24d2d9a1`).
- *links kept* = renders of the 4 messages that contain a link whose link text survives (spaces ignored, after `repair_links`). *CER* = mean character error rate over all 14 messages. *better / same / worse* count single renders: a link gained or lost decides first, then the CER.

| Theme | kind | links kept (before -> after) | mean CER (before -> after) | better | same | worse |
|---|---|---|---|---|---|---|
| WhatsApp light (colours assumed) | light | 29 -> 29 of 32 | 0.004 -> 0.004 | 0 | 112 | 0 |
| WhatsApp dark (colours assumed) | dark | 28 -> 31 of 32 | 0.004 -> 0.004 | 3 | 108 | 1 |
| iOS Messages light (colours assumed) | light | 27 -> 27 of 32 | 0.004 -> 0.004 | 0 | 112 | 0 |
| iOS Messages dark (colours assumed) | dark | 9 -> 31 of 32 | 0.084 -> 0.013 | 23 | 88 | 1 |
| Google Messages dark (assumed) (colours assumed) | dark | 28 -> 31 of 32 | 0.021 -> 0.012 | 3 | 108 | 1 |
| **>> Google Messages dark (MEASURED) (colours measured)** | **dark** | **4 -> 31 of 32** | **0.069 -> 0.004** | **28** | **83** | **1** |
| Telegram dark (colours assumed) | dark | 28 -> 30 of 32 | 0.004 -> 0.005 | 4 | 103 | 5 |
| plain blue on dark grey (colours assumed) | dark | 0 -> 30 of 32 | 0.080 -> 0.004 | 32 | 80 | 0 |
| plain blue on light grey (colours assumed) | light | 32 -> 32 of 32 | 0.003 -> 0.003 | 0 | 112 | 0 |
| iOS sent, light page (white on blue) (colours assumed) | saturated | 29 -> 29 of 32 | 0.006 -> 0.006 | 0 | 112 | 0 |
| iOS sent, dark page (white on blue) (colours assumed) | saturated | 0 -> 0 of 32 | 0.998 -> 0.998 | 0 | 112 | 0 |
| WhatsApp dark outgoing (teal) (colours assumed) | saturated | 21 -> 21 of 32 | 0.262 -> 0.262 | 0 | 112 | 0 |
| WhatsApp light outgoing (pale green) (colours assumed) | light | 29 -> 29 of 32 | 0.004 -> 0.004 | 0 | 112 | 0 |
| Telegram dark outgoing (blue) (colours assumed) | saturated | 12 -> 12 of 32 | 0.503 -> 0.503 | 0 | 112 | 0 |
| Google Messages light (colours assumed) | light | 29 -> 29 of 32 | 0.003 -> 0.003 | 0 | 112 | 0 |

**Total: better 93, same 1578, worse 9** of 1680 renders.

## Guards

- Light themes (the step is never called there): 0 of 560 renders read differently. Must be 0.
- Saturated bubbles, white text on a saturated colour (iOS sent, WhatsApp / Telegram outgoing): 0 of 448 renders worse.

## Every worse case (9)

- **WhatsApp dark**, w540, d07: CER 0.000 -> 0.008
    - before `https://bit.ly/vip-stock-tips`  /  after `https://bit.ly/vip-stock-tips.`
- **iOS Messages dark**, w540, d07: CER 0.000 -> 0.008
    - before `https://bit.ly/vip-stock-tips`  /  after `https://bit.ly/vip-stock-tips.`
- **Google Messages dark (assumed)**, w540, d07: CER 0.000 -> 0.008
    - before `https://bit.ly/vip-stock-tips`  /  after `https://bit.ly/vip-stock-tips.`
- **Google Messages dark (MEASURED)**, w540, d10: CER 0.000 -> 0.034, link True -> False
    - before `https://www.bet365.com/`  /  after `https:/Avww.bet365.com/`
- **Telegram dark**, w540, d02: CER 0.000 -> 0.029
    - before `Dear Customer, your SBI account will be blocked`  /  after `Toda`
    - before `today due to pending KYC. Update now:`  /  after `Dear Customer, your SBI account will be blocked`
    - before `sbi-kyc-update.top/login Share the OTP sent to your`  /  after `today due to pending KYC. Update now:`
- **Telegram dark**, w540, d06: CER 0.000 -> 0.035
    - before `India Post: Your package is held at our warehouse`  /  after `706%`
    - before `due to an incomplete address. Update within 24`  /  after `India Post: Your package is held at our warehouse`
    - before `hours: https://indiapost-redelivery.top/track`  /  after `due to an incomplete address. Update within 24`
- **Telegram dark**, w540, d07: CER 0.000 -> 0.008
    - before `https://bit.ly/vip-stock-tips`  /  after `https://bit.ly/vip-stock-tips.`
- **Telegram dark**, w540, d10: CER 0.000 -> 0.034, link True -> False
    - before `https://www.bet365.com/`  /  after `https:/Avww.bet365.com/`
- **Telegram dark**, w720, d10: CER 0.000 -> 0.034, link True -> False
    - before `https://www.bet365.com/`  /  after `https:/Avww.bet365.com/`
