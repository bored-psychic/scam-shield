# Scam Shield: demo guide and honest limits

This is for whoever shows the app (the project team) and for a reviewer who wants to know what it can and cannot do.

**Every message in the demo set is made up.** The 14 messages in [`demo_set.json`](demo_set.json) were written for the demo. The numbers, phone numbers, names and links are fictional, and none of it is real data. Whether the app handles them correctly says little about how it will do on real messages, so read the limits in section 3 before drawing any conclusion.

What was checked: on 2026-10-17 all 14 behave as expected (10 scams flagged, 4 genuine messages left alone), recorded in [`reports/demo_check.md`](../../reports/demo_check.md) and locked by `python tests/test_demo.py`. A change that moves any verdict makes that test fail on purpose.

## 0. Before you start

Two terminals, from the project root, with the `.venv` active:

```
uvicorn shield.api.main:app --host 127.0.0.1 --port 8000     # the checker (the models are loaded once at start)
cd frontend && npm run dev                                    # the web page, open http://localhost:5173
```

Fallback if the web page misbehaves: `python src/app.py` (a plainer page at http://127.0.0.1:7860, same checker). Nothing needs the internet.

Paste the texts below into the box, or open `demo_set.json` and copy from it (the JSON is the source if they ever differ).

## 1. The 5-minute demo script

Order: d01, d02, g01, d03, d10, then one honest limit. About one minute each. Say the verdict out loud first, then point.

**Step 1 (d01, a "digital arrest" call script).**
> This is Inspector Rakesh Sharma from Mumbai Cyber Crime. A parcel in your name with illegal items was seized by customs. You are now under digital arrest. Do not disconnect this call or tell anyone. Transfer ₹49,999 to clear your name.

- **Verdict:** *Likely scam*.
- **Radar:** four blips: *Authority claim*, *Payment ask*, *Secrecy*, *Scam wording*.
- **Underlined phrases:** "Cyber Crime", "Transfer", "digital arrest". Hover one to see why it is underlined.
- **Why:** three plain reasons, each tied to a phrase.
- **No link panel**, because there is no link in the message.
- **What to do now:** the steps, including the helpline 1930 and cybercrime.gov.in.
- **Footer:** point at "Checked on this device · nothing was stored".

**Step 2 (d02, a fake KYC message with a link and an OTP request).**
> Dear Customer, your SBI account will be blocked today due to pending KYC. Update now: sbi-kyc-update.top/login Share the OTP sent to your number to complete verification.

- **Verdict:** *Likely scam*.
- **Radar:** *OTP request*, *Risky link*, *Authority claim*, *Urgency*.
- **Underlined:** "Share the OTP" in the danger colour. This is a fixed rule: any request to share an OTP, PIN or CVV is at least Suspicious, whatever the wording model thinks.
- **Link panel:** the address is split into parts with the owner part set apart, and it says the link looks like known phishing links. Say "The link was not opened": links are only read as text, never visited.

**Step 3 (g01, a genuine bank debit alert). This is the one that shows it does not cry wolf.**
> Rs.2,500.00 debited from A/c XX4821 on 14-10-26 to VPA swiggy@ybl. If this was not you, call the number on the back of your card. Never share your OTP with anyone. -HDFC Bank

- **Verdict:** *No warning signs found*. It never says "Safe": that only means nothing strong was found.
- **Radar:** empty.
- **Underlined:** only faint dotted marks on "HDFC" and "Rs.2,500.00", which are the usual words of a bank alert and not accusations.
- Point out that "Never share your OTP" did not trigger the OTP rule: the rule checks for a *request* and ignores a warning.

**Step 4 (d03, a refund trick).**
> Hello sir, I sent ₹5,000 to your number by mistake. Please return it. I have sent a collect request, just enter your UPI PIN to receive the refund.

- **Verdict:** *Likely scam*; radar *PIN to receive*, *Payment ask* and *Scam wording*; "enter your UPI PIN to receive" (danger colour) and "₹5,000" underlined.
- **Say this honestly:** caught by the PIN-to-receive rule. Receiving money on UPI never needs a PIN (a PIN is only entered to pay), so asking for one "to receive the refund" is a fixed red flag: at least *Suspicious*, whatever the wording model thinks. The rule did not change the level here: the *Likely scam* is still the wording model's (score 0.916), and the rule alone only guarantees *Suspicious*. Details in `reports/demo_check.md`, "Reading notes".

**Step 5 (d10, a betting promotion).**
> Get a 500% welcome bonus, play now: https://www.bet365.com/

- **Verdict:** *Likely scam*, with category "gambling". The first line under "What to do now" is the gambling advice.
- **Link panel:** two cautions, "looks somewhat like phishing links" and "Gambling or betting site" (the domain is on two public gambling lists).
- **Say this honestly:** the gambling rule alone only ever reaches *Suspicious*. The *Likely scam* here comes from the wording model (score 0.927). The app says "betting site", not "this operator is a fraud": a licensed operator is on the list too.

**Step 6 (the honest limit).** The demo set has **no miss** (14 of 14), so there is no failing entry to show. Show this documented one instead; I re-ran it on 2026-10-17 and it is *Suspicious* (score 0.440), although it is a genuine warning:
> Never share your OTP, PIN or CVV with anyone, including bank staff.

Explain: the wording model cannot see "never". A sentence with the negation removed scores about 0.02 to 0.07 lower than the warning (`reports/otp_advisory.md`, section 1), so a genuine safety warning can look suspicious. A fix exists but is switched off (see section 3). The demo's own g02 ("Your OTP is 482913. Do not share it with anyone. -SBI") comes out clean, so this depends on the wording.

Optional extras if there is time:
- **d07** (stock tips with a `bit.ly` link): the link panel says "Can't verify - hidden destination". The app does not follow shortened links.
- **d09** (Hinglish: "Aapka bank account aaj band ho jayega. Abhi apna OTP bata do verify karne ke liye."): *Suspicious*, not *Likely scam*. The wording score is 0.651, just under the 0.656 *Likely scam* cut-off (and well above the 0.423 *Suspicious* one); the OTP rule would also guarantee at least *Suspicious*.

## 2. What it can do

Facts from the code, not promises:

- **OTP / PIN / CVV rule** (`src/shield/messages/rules.py`): a request to send, share or forward an OTP, PIN or CVV forces at least *Suspicious* and shows as its own red flag. Genuine "do not share" alerts are checked for negation and do not fire. Known false positive: a real delivery-OTP instruction.
- **UPI PIN to receive money rule** (`rules.pin_to_receive`, R2): a UPI PIN / MPIN asked for (enter, type, put, give, share, approve ...) near a receive-money cue (receive, get the refund, cashback, collect request, accept the payment ...) forces at least *Suspicious* and shows as its own red flag, because receiving money never needs a PIN. Warnings ("You never need to enter your UPI PIN to receive money", "No need to enter your UPI PIN to receive money") do not fire, and neither does a delivery PIN ("give PIN 5566 to the agent only if you receive the order": "receive the order" is not money; the OTP rule above still flags that one). Known false positive: a payment message whose next sentence mentions a cashback you will receive (BUGS.md).
- **Tactic cues** (`src/shield/messages/tactics.py`): hand-written patterns for four tactics: pretending to be a bank, government body or company (*Authority claim*), *Urgency*, *Payment ask*, and *Secrecy* (keep this secret, delete this message, don't tell anyone). English plus a few Hinglish, Hindi and Kannada words; the Hindi and Kannada ones have not been checked by a native speaker. On a message with no warning they are shown with neutral wording, because genuine alerts use the same words.
- **Text model** (`models/text_baseline.joblib`, kind `tfidf-lr`): TF-IDF character n-grams plus logistic regression, trained on the training split only. Cut-offs from the validation split: *Suspicious* from 0.423, *Likely scam* from 0.656. This is a baseline: the fine-tuned multilingual model (MuRIL) is not in the app yet.
- **Link checks** (`src/shield/links/`): a gradient-boosting model reads the link's host (the part before the first `/`) and scores how much it looks like known phishing hosts. Link shorteners and free hosting are handled by rule and shown as "can't verify". Links are never opened or fetched.
- **Gambling rule** (`src/shield/links/gambling.py`): a local lookup of 362,487 registered domains plus a name rule for Satta/Matka sites. A hit raises a link to at least *Suspicious* with its own reason and a gambling advice line. It never gives *Likely scam* on its own. A betting promotion with no link is not detected.
- **One answer shape** (Report v2, `src/shield/contracts.py`): the verdict, up to three plain reasons, the evidence with exact positions in the message, and the advice, so the screen only draws what the checker returns. The report also records which model files made it.
- **Local only**: the message is analysed in memory, not logged or written to disk, and the analysis makes no outbound network call (`src/shield/api/main.py`; the code under `src/shield/` contains no network library). The page says "Checked on this device · nothing was stored".

## 3. Honest limits

1. **Text model: 0.893 F1 on an internal test set that is mostly not Indian SMS.** Test F1 is 0.893 on 5,711 internal test messages, and 0.894 on the 4,396 that are not synthetic (`reports/url_token.md`). But 3,528 of those 5,711 (62%) are emails (1,680) and job postings (1,848); only 205 come from the one non-synthetic Indian SMS set (`scam_ham_india`), plus 310 from `india_fraud_final`, a set that is 86% synthetic (`reports/sanity.md`, section 4 source table). The score is **in-distribution**: the test messages come from the same datasets the model trained on. When a whole dataset is held out, the same kind of model does much worse: F1 0.860 on the Indian SMS set (`scam_ham_india`), 0.684 on `india_fraud_final`, 0.387 on phishing emails, 0.088 on job postings (`reports/sanity.md`, section 5, leave-one-source-out). Real messages from real people will look like a new source, so treat 0.893 as an upper bound, not as expected accuracy.
2. **URL model: test AUROC 0.859, and it reads only the host.** Test AUROC is 0.859 (validation 0.845), `reports/url_head.md`. Because it ignores the path, **genuine inner pages of real sites can be flagged**: of 18 hand-picked genuine Indian-site URLs, the deployed model flags 6 as at least Suspicious, among them `netbanking.hdfcbank.com`, `onlinesbi.sbi`, `amazon.in/gp/your-account` and two `npci.org.in` pages (`reports/url_experiments.md`, "Probes"). Real-bank-link false alarms are the likely complaint. Related: in a re-fit, benign hosts with a subdomain are flagged 22% of the time against 7% without one (`reports/url_experiments.md`, "Subdomain / www bias"; a mix of subdomain and data-source effects). Models that read the whole URL score higher overall (test AUROC 0.939, `reports/url_head.md`), but in the same probes the full-URL variants flagged *more* of the genuine pages (10 of 18, variants D and E), so the host-only model was kept. None of the 14 demo messages is a genuine message with a link, so the demo does not show this.
3. **Genuine OTP warnings can be flagged *Suspicious*.** 5 of 8 genuine "never share your OTP" style notices in `tests/tricky_inputs.py` come out *Suspicious* (`reports/otp_advisory.md`, section 1), because the wording model cannot read negation. A cap that would lower these exists but is **off**: on the validation split it fired on 0 of 5,267 messages, so it cannot yet be shown to help (`reports/otp_advisory.md`). Step 6 above is one of the 5.
4. **Hindi and Kannada have no real data.** All 394 Hindi and all 394 Kannada rows are templated synthetic messages, and neither language has a validation row (`reports/sanity.md`, sections 2 and 3). Their scores measure template matching, not real understanding. Real Hinglish *scams* are absent too: the real Hinglish data is benign conversations. A translated Hindi/Kannada set exists but is waiting for a native-speaker check and is not in the data yet. The demo has one Hinglish message (d09) and none in Devanagari or Kannada script.
5. **Real-world accuracy has not been measured.** There is no test set of real messages from real people yet; it will be collected later and evaluated once at the end. Every number above comes from public datasets and templated or synthetic messages.
6. **Demo misses** (`reports/demo_check.md`): **none**, 14 of 14 behave as expected. That is not a performance claim: the set was hand-written, so it is easy by construction. What the same report notes: d03's PIN request is caught by the PIN-to-receive rule (step 4), though its *Likely scam* is still the wording model's; d10's *Likely scam* is the wording model's, not the gambling rule's (step 5); d09 is *Suspicious*, 0.005 under the *Likely scam* cut-off; and the *Likely scam* on d03, d04, d07 and d08 rests on the wording model alone (d03's rule only guarantees *Suspicious*; d04, d07 and d08 have no rule or link verdict behind them).

## 4. What we'd like from a reviewer

1. **Which scam types do you see most often locally?** The demo set covers digital arrest, fake KYC, refund tricks, part-time jobs, electricity cut-off, India Post fees, stock tips, lottery, Hinglish OTP and betting. What is missing or ranked wrong for your area and languages?
2. **Would you review 10 verdicts?** We will bring 10 messages with the app's verdict and reasons (made up or already public, none from a victim); please mark each as right or wrong, and say whether the reasons are clear to an ordinary person.
3. **May we collect forwarded scam messages with consent for a final test set?** Messages would be shared voluntarily, with phone numbers, UPI IDs, account numbers and names masked before storage, used only to test the app once at the end, never to train it. Is there a way you would be comfortable arranging that, and what should the consent look like?

## Files

| file | what |
|---|---|
| `docs/demo/demo_set.json` | the 14 messages (id, kind, type, text) |
| `src/demo_check.py` | runs them through the checker, writes `reports/demo_check.md` |
| `tests/test_demo.py` | locks the set (hash) and each verdict level |
| `reports/demo_check.md` | the latest result, per message |
