# Labelling guide: scam / genuine / skip

For every message collected into `data/collected/` (`src/intake_screens.py`), for the real-message test set (`data/real/label_me.csv`), and for
the blind double-label sheet (`data/collected/double_label_sample.csv`). Written 2026-10-25 with `docs/plans/data_acquisition.md`.

One label per message, from three:

| label | when |
|---|---|
| **scam** | The message tries to get money, credentials, an OTP / PIN, remote access or an app install from the reader **by deceiving them**: a false identity (bank, police, courier, SEBI, a company), a false promise (prize, guaranteed returns, job, loan without checks), or false urgency (account blocked, arrest, disconnection tonight). |
| **genuine** | Sent by the organisation it claims to be, and asks for nothing it would not normally ask for. This includes marketing from a real, registered business, even pushy marketing, because spam is not the same as scam (README, D22). |
| **skip** | You cannot tell, or it is not a message. Skipped rows are dropped at ingestion, counted, and never trained on. When in doubt, skip: one wrong label costs more than one missing row. |

Judge the message as the reader would receive it: its words, its link (as a string; **never open it**, CLAUDE.md rule 8), its sender line if
the screenshot shows one, and what the page that shows it says about it (a PIB fact-check, a bank advisory, a news report). Do not use any
model's score to decide.

## What the page tells you

| the page says | label | provenance column |
|---|---|---|
| A fact-check / advisory / news report says this message circulated and is fake (PIB Fact Check, a bank, the police, BOOM, The Quint) | scam | real_circulating |
| A person posts a message **they received** (Reddit, X) and it is clearly fraudulent | scam | real_circulating |
| A person posts a message they received and asks "is this real?" with no answer you can check | skip, unless the message alone is clearly scam or clearly genuine by the rules below | real_circulating |
| The outlet made the example itself ("a message like this", a mock chat, a drawn illustration, BOOM's ScamCheck hub banner) | **skip** (or keep with provenance `illustrative`: it never counts as real) | illustrative |
| A bank / broker / exchange page shows a sample of its own genuine alert | genuine, provenance `generic_script` (a published format, not a received message) | generic_script |
| Only a paraphrase ("the message asked victims to pay a fee") | not a message: do not record it | - |
| A meme, a headline, an edited or composited image, a screenshot of a screenshot with the text cut off | skip | - |

## Edge cases

### Loan promotions

| example pattern | label | why |
|---|---|---|
| A bank or RBI-registered NBFC offers a loan from a DLT business header (ending `-P` for promotional, `-S` / `-T` for service), names itself, links to its own domain, says "T&C apply", asks for no fee before approval | genuine | marketing from a registered lender |
| "Pre-approved loan of Rs 5 lakh, no CIBIL, no documents", pay a processing / file / insurance fee first, to a UPI id or a personal number | scam | advance-fee fraud; registered lenders deduct charges from the loan and show a Key Fact Statement |
| An instant-loan app link (APK, unknown domain, short link) from a 10-digit mobile number or WhatsApp, or asking for contacts / gallery permission | scam | illegal digital lending pattern (RBI Digital Lending Directions 2025) |
| A loan message from an unknown lender that asks for nothing yet and shows no fraud cue | skip | cannot tell a small registered NBFC from an illegal app by wording alone |
| Recovery threats ("we will send your photos to your contacts") | scam | harassment by illegal loan apps |

### Broker, exchange, depository and fund messages

| example pattern | label | why |
|---|---|---|
| Exchange trade confirmation for a client code / UCC (NSE / BSE send these for every executed trade), CDSL / NSDL demat debit or pledge alert, margin or pledge OTP the reader asked for, IPO allotment status from the registrar, mutual-fund redemption / SIP confirmation, contract note notice | genuine | the regulated alerts SEBI requires; they inform and ask for nothing |
| SEBI / exchange / broker awareness notices: "beware of fake stock tips", "use only @valid UPI ids" (circular SEBI/HO/DEPA-II/DEPA-II_SRG/P/CIR/2025/86), "do not share your OTP" | genuine | the probe v1 false alarms (MuRIL flagged SEBI's own @valid templates): these are exactly the rows Phase B needs |
| A research call from an analyst who gives a SEBI registration number (INH...) and asks for no payment to a personal UPI id | genuine | registered research analyst; whether the call is good advice is not the question |
| "Join our VIP / study / teaching group", "guaranteed / assured / fixed daily returns", "institutional account", "IPO pre-allotment at a discount", a trading app by link or APK, "pay tax / fee / deposit to withdraw your profit" | scam | the investment / trading scam stages (docs/plans/investment_scams.md) |
| A message that copies a broker alert but tells you to click to avoid suspension / to "re-KYC" via a link or a phone number | scam | genuine KYC reminders point to the broker's own app or site and do not threaten immediate suspension through a link |
| A line from a scam stock group that asks for nothing ("the teacher will share today's stock at 2 PM") | **skip, with note `group_line`** | the Phase B labelling decision (investment plan section 6, step 1) is not made yet; do not decide it here |
| A paid stock-tip SMS from an unregistered sender promising returns | scam | guaranteed returns from an unregistered adviser |

### Other frequent cases

- **OTP messages**: a plain OTP the reader requested ("482913 is your OTP, do not share") is genuine; a message asking the reader to **send / share / forward** an OTP is scam.
- **Bank transaction alerts**: genuine debit / credit alerts are genuine even if the amount is alarming; a "debit alert" that asks you to call a number or click to cancel is scam.
- **Delivery**: a courier's real tracking update is genuine; "your parcel is held, pay Rs 25 redelivery / customs fee at <link>" is scam.
- **Digital arrest / police / customs**: any message saying you are under investigation and must pay, stay on a video call, or keep it secret is scam.
- **Government schemes**: messages promising free money / laptops / ACs under a scheme name, with a link to register, are scam when PIB or the ministry says so; skip if no one has checked them.
- **Language**: label Hindi, Kannada and Hinglish by the same rules. If you cannot read it, skip (do not guess from the script).

## Columns you fill

In `sources.csv` (intake input): `label` (scam / genuine / skip / blank = not decided yet), `category` (investment / loan / task / kyc_bank /
delivery / digital_arrest / govt_scheme / challan / utility / reward / job / other), `provenance` if not `real_circulating`, `verified`
(A1: `exact` / `near` / `none` if you found a second independent page with the same wording; blank if you did not look), `notes`
(e.g. `group_line`).

In `double_label_sample.csv`: `label_2` only (scam / genuine / skip), without looking at the key file, at any model output, or at the
first labeller's answer. Then run `.venv/bin/python src/double_label.py kappa`.
