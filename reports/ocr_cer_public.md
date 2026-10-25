# OCR character error rate on real public screenshots (A2)

Written by `src/ocr_cer.py`: hand-typed text vs the app's OCR (`shield.ocr.reader` via `intake_screens.ocr`), jiwer CER = character edits / reference characters, pooled over the images of a language. No message text in this report.

| language | images | reference chars | CER strict | CER normalised (white space) | target |
|---|---|---|---|---|---|
| en | 5 | 1032 | 0.257 | 0.243 | <= 3%: NOT met |

| image | language | reference chars | CER strict | CER normalised | ocr_conf |
|---|---|---|---|---|---|
| boom_pnb.png | en | 211 | 0.194 | 0.180 | 0.787 |
| boom_icici.png | en | 142 | 0.965 | 0.965 | 0.372 |
| boom_electricity.png | en | 268 | 0.254 | 0.231 | 0.635 |
| boom_vahan.png | en | 265 | 0.038 | 0.023 | 0.942 |
| jio_kiwi_dark.jpg | en | 146 | 0.062 | 0.049 | 0.821 |
