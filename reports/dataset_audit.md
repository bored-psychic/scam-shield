# Public dataset audit (synthetic / contamination)

Written by `src/audit_dataset.py` (no network, nothing ingested). Method and reject rules: the script's docstring and `docs/plans/data_acquisition.md` section 4. Controls are train + val rows of `data/final/messages.csv` (test rows never read).

| dataset | role | rows | exact dup | in a template group | rows / template | largest template | positive | categories (max/min) | length CV | amounts | leading-zero amounts | Benford MAD | Indian marker | overlap with train | verdict | flags |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| uci_sms_spam | control_real | 4617 | 0.0% | 6.1% | 1.04 | 0.3% | 12.8% | 1 (n/a) | 0.74 | 1 | 0.0% | n/a | 0.2% | n/a | control |  |
| india_fraud_final | control_synthetic | 2890 | 0.0% | 99.6% | 6.77 | 0.6% | 50.1% | 244 (45.50) | 0.23 | 915 | 0.0% | 0.045 | 49.8% | n/a | control | labels exactly 50/50; 6.8 rows per template; amount first digits off Benford (MAD 0.045) |
| synth_india | control_synthetic | 756 | 0.0% | 99.3% | 10.80 | 2.0% | 59.3% | 8 (1.88) | 0.20 | 412 | 0.0% | 0.077 | 78.6% | n/a | control | 10.8 rows per template; amount first digits off Benford (MAD 0.077) |
| scam_ham_india | in_use | 2035 | 0.0% | 19.1% | 1.15 | 0.8% | 40.3% | 1 (n/a) | 0.86 | 440 | 0.0% | 0.041 | 26.9% | n/a | in training already; no stated real collection: cannot count as real (rule 4) | amount first digits off Benford (MAD 0.041) |
| otp_sms_preview | candidate | 10000 | 14.8% | 59.3% | 1.99 | 5.4% | 26.0% | 9 (23.33) | 0.72 | 4068 | 9.6% | 0.062 | 43.5% | 1.8% | REJECT: no stated real collection: cannot count as real (rule 4); 9.6% of amounts have a leading zero (machine-made numbers) | amount first digits off Benford (MAD 0.062) |
| mendeley_smishing | candidate | 5971 | 0.4% | 14.9% | 1.11 | 0.3% | 18.9% | 0 (n/a) | 0.70 | 65 | 0.0% | n/a | 1.8% | 76.3% | REJECT: 76.3% of rows are near-duplicates of our train split |  |

## Provenance as stated

- **uci_sms_spam**: real: SMS Spam Collection v.1 (Almeida et al. 2011), collected from Grumbletext (UK), the NUS SMS Corpus (Singapore) and a PhD thesis; https://archive.ics.uci.edu/dataset/228/sms+spam+collection
- **india_fraud_final**: mostly generated: the file's own is_synthetic column marks 2,737 of 3,200 rows (85.5%) synthetic; data/sources.yaml
- **synth_india**: generated: src/synth_india.py templates (is_synthetic=True)
- **scam_ham_india**: unknown: a local CSV (text, label ham / spam) with no card, author or collection method (data/sources.yaml has none); already in training
- **otp_sms_preview**: mixed: the card says 'collected from real-world sources' plus LLM-labelled rows and synthetic augmentation (classification_status 'synthetic' on 794 of the first 5,000 rows); no source licences, no collection method; https://huggingface.co/datasets/gandharvbakshi/SMS-dataset-sample-10k
- **mendeley_smishing**: stated: 'collected by converting the images obtained from the Internet to text using Python code' (OCR), messages credited to T. A. Almeida (UCI SMS Spam co-author) and G. Sonowal; Mishra & Soni, v1 2022-06-20, CC BY 4.0; https://data.mendeley.com/datasets/f45bkkt8pr/1
