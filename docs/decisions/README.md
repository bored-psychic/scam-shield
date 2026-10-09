ARCHITECTURE.md is updated once, after D1-D18 are all decided. Until then this log is the source of truth for decisions.

# Decision log

| ID | Decision | Date | Detail file |
|---|---|---|---|
| D1 | Run locally (Mac + LAN, use a phone hotspot for demos/study); Hugging Face Spaces (Docker) later | 2026-10-10 | - |
| D2 | Live checks on: RDAP + local blocklists; Safe Browsing only with a key; crt.sh fallback only | 2026-10-10 | - |
| D3 | Shortener expansion only on button press | 2026-10-10 | - |
| D4 | No % shown; 4-zone meter that can never contradict the verdict; "Why this score" + "Website details" panels; exact score in Details | 2026-10-10 | - |
| D5 | Two targets: Likely scam <= 1%, Suspicious+ <= 5% of hard-legit, counted per independent template, on the final verdict; recall floor 0.90 for Suspicious; ship gate 10%; Can't-judge <= 10% on hard-legit; language cap (text model alone max Suspicious in hi/kn/Hinglish until >= 150 real-dev templates in that language). Design targets until real-dev exists. D7 target: 400+ independent English hard-legit templates, ~150 per language | 2026-10-10 | [D5_operating_point.md](D5_operating_point.md) |
| D5b | Brand promos separated as promo_gray (not scam, not benign); relabel in splits-v2 | 2026-10-10 | [D5_operating_point.md](D5_operating_point.md) |
| D5c | Dispute button stores nothing by default; opt-in study/volunteer mode saves masked text + verdict + user label locally | 2026-10-10 | [D5_operating_point.md](D5_operating_point.md) |
| G1 | Gambling: a domain in the `gambling_spam` class (or the gambling lookup) gives the verdict **Suspicious** with its own reason (gambling / betting promotion), never "scam". Tranco popularity never lowers it. Not built yet: `src/app.py` has no gambling logic | 2026-10-10 | - |
