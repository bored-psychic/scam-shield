# Manual downloads

These need a form, an account or an author request. Drop the files where shown and re-run the build script.

| Dataset | Where to request | Drop files in | Picked up by |
|---|---|---|---|
| ISCX-URL2016 | https://www.unb.ca/cic/datasets/url-2016.html (form) | `data/external/urls/iscx/` (the per-class URL lists, e.g. `phishing_dataset.csv`) | `src/build_urls.py` |
| CICMalDroid 2020 | https://www.unb.ca/cic/datasets/maldroid-2020.html (form) | `data/external/apps/cicmaldroid/` | needs a reader in `src/build_apps.py` |
| Drebin | https://drebin.mlsec.org/ (email the authors) | `data/external/apps/drebin/` | needs a reader in `src/build_apps.py` |
| India OTP/phishing SMS | https://huggingface.co/datasets/gandharvbakshi/SMS-dataset-OTP-OTP_INTENT_Phishing (click "request access"), then `export HF_TOKEN=...` | change `access: manual` to `hf` in `data/sources.yaml`, run `src/pull_hf.py` | needs a block in `src/build_text.py` |
| Mendeley smishing (Mishra & Soni 2022) | https://data.mendeley.com/datasets/f45bkkt8pr | `data/external/text/mendeley_smishing/` | needs a block in `src/build_text.py` |
| PhishTank | https://phishtank.org/ (app key; registration is often closed) | set `PHISHTANK_KEY` | not wired yet |
| Bhashini | https://bhashini.gov.in/ (API key) | set `BHASHINI_KEY` | for back-translation, not wired yet |
| Kaggle (optional) | https://www.kaggle.com/settings → API token | `~/.kaggle/kaggle.json` | only needed if a source moves off Hugging Face |
