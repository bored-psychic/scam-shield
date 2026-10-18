# D23: safe link checks (implements D2, D3, D4)

Status: **APPROVED and BUILT 2026-10-18.** Proposed the same day (the design below, §0-§10, unchanged except §10's answers); the user approved it with the answers below; built, tested and measured the same day. It also settles D12 (cache: memory only), D14 (age / popularity cut-offs) and D16 (a blocklist hit forces Likely scam) for links. Models, thresholds, data and splits are untouched (`split_map.csv` SHA-256 `89eec6f1…7c5`; `text_baseline.joblib` cf8bac33, `url_head.joblib` a8f6d9cc, as before).

The rule behind every choice: we check a link's background (registry, DNS, certificate logs, lists) and never its content. Nothing here loads the destination page or connects to the site's server or IP.

## User decision (2026-10-18)

1. Level tables approved as written (R1-R9, P1 with the mobile-number guard, P2).
2. URLhaus: yes, `URLHAUS_AUTH_KEY` from the environment only (never printed, logged or written); without it, OpenPhish only and "couldn't verify (no URLhaus key)".
3. DNS: Cloudflare DNS-over-HTTPS.
4. crt.sh: fallback only (when RDAP has no registration date).
5. `.bank.in` = P1 (verified from RBI / IDRBT sources, cited in `src/shield/links/restricted_zones.json`); `.gov.in` / `.nic.in` = display-only reassuring reason, never a level change.
6. Commit this note with the build, add a D23 row to the decision table, note the non-commercial licences and what a commercial version needs (§ Commercial use below), commit the Playwright overlap scripts.

## As built: where it differs from the proposal, and why

- **The network-rule sentence was not in CLAUDE.md** (§0): rule 8 of CLAUDE.md was rewritten (§7), and the two places that held the sentence (`src/shield/api/main.py`, `docs/demo/README.md`) were updated too.
- **URLhaus download host** is `urlhaus-api.abuse.ch` (`/v2/files/exports/<key>/recent.csv`: URLs added in the past 30 days, 33,208 on 2026-10-18), not `urlhaus.abuse.ch`; the key sits in the URL path, so the manifest records the placeholder `<URLHAUS_AUTH_KEY>` and a failure prints only a status word. The app itself never calls URLhaus: it reads the downloaded file, so "couldn't verify (no URLhaus key)" appears when that file is missing (or older than 7 days) and the key is not set; with the key set it says "list not downloaded".
- **Update redirects**: `openphish.com/feed.txt` redirects to OpenPhish's own GitHub mirror (`raw.githubusercontent.com/openphish/public_feed`), and Tranco redirects within its own host. The updater follows a redirect only to a host on `net.UPDATE_HOSTS` (`raw.githubusercontent.com` added there, updater only). The checks never follow a redirect.
- **Brand TLDs, verified 2026-10-18 (15):** .jio .reliance .ril (Reliance Industries), .sbi, .hdfcbank and .hdfc (ICANN names HDFC Bank, IANA still Housing Development Finance Corporation: both accepted, after the 2023 merger), .airtel .bharti, .tatamotors, .amazon, .google .youtube, .microsoft, .apple, .netflix. Dropped: .icici, .tata, .flipkart, .lic (not delegated), .star and .goog (not Specification 13).
- **High-abuse TLDs** come from Interisle's May-July 2026 table (top 20 by phishing domains per 10,000, zones >= 30,000 names). `.top` is not among them (a huge zone), so the demo `.top` links get no "risky ending" line.
- **R6 (shared server)** compares against the 6,537 IPs that appear literally as hosts in the OpenPhish / URLhaus entries. The IPs of listed host NAMES are not known: resolving ~40,000 listed names would send them all through DNS at every update. Exempt networks (one IP, thousands of sites): CDNs and shared web hosting only; VPS providers are not exempt (one IP is usually one customer).
- **Blocklist matching**: besides platform roots, a listed host that is itself a popular site (a Tranco top-100k registered domain or its `www.`) matches only the listed page. Found in the live smoke test: URLhaus carries `http://example.com/test_drop_check`, which made `example.com` Likely scam with host matching.
- **R7 / R8 never fire on a P1 link** (.brand TLD or .bank.in): those names are registered by the owner, so a new name means nothing (Jio's own `t.jio` would otherwise be flagged the week a campaign name is registered). The date is still shown.
- **P2 exclusions**: besides shorteners and free hosting, a list of 45 user-content hosts (`platforms.USER_CONTENT`: t.me, wa.me, docs.google.com, forms.gle, amazonaws.com, youtube.com ...), and no P2 for a gambling link or a lookalike.
- **Lookalike details**: edit distance is OSA (a swap of two neighbours counts 1: `patym`), digit swaps are undone first (`amaz0n`), tokens of 4 letters or fewer match only whole or at a token's start / end, and `bhim` and `efiling` were dropped as tokens (ordinary words in other names). On a user-content platform only the uploader's part is read (`sbi-kyc.s3.amazonaws.com`).
- **Platform hosts** get no RDAP / DNS / crt.sh (those facts would describe the platform), only Safe Browsing; the sheet says why.
- **Safe Browsing** is v5 `hashes:search` with the 4-byte prefixes of the host-level expressions (no path). There is no key on this machine, so it is tested against a mock only; the JSON response shape is the documented one.
- **Hard-risk**: the new key `link_red_flag` (any R1-R9) also blocks the dormant D22 sender softening; its misuse wording is "its link has a red flag (see the link panel)" (the long form overflowed the 120-character title).
- **Flow**: the page shows the offline verdict first and then asks for the live checks. Since all positive checks are offline, a live answer can only raise the level; the verdict panel then says "Raised after the website checks." If the live call fails, every pending row becomes "Couldn't verify (offline)".
- **Contract v4**: `Report.link` (`LinkInfo` + `Fact` rows) on each link's child Report; message `Report.pending == ["links"]` while live checks are due.
- **Files** (§8): `brands.py` was folded into `lookalike.py`; the tracked reference files are `brand_tlds.json` (written by the updater's verification), `brands_india.json`, `restricted_zones.json` and `abuse_tlds.json` beside the code (not under `data/`, which git ignores). Tests: `tests/test_links_live.py` L1-L14 with the committed fixture lists in `tests/fixtures/linklists/`; the other suites read the downloaded lists on disk, like the gambling lookup. `playwright-core` 1.63.0 is a pinned frontend dev dependency for `frontend/e2e/overlap.mjs`.
- **Startup**: the API now reads the lists at start-up (Tranco 1M as hashed arrays, about 1.6 s and 19 MB; the IP table about 2 s), so the first request does not pay for them.

## Results (2026-10-18)

- **Jio** (`tests/fixtures/real/jio_kiwi_dark.jpg` and the typed text): the link is recognised as Jio's own ("Belongs to Jio: only Reliance Industries Limited can register .jio addresses"); no hard-risk signal, no mobile number, so **Likely scam → Suspicious**. The reasons stay the three warnings (urgency, payment, the wording), so the brand line is on the link panel. Live (real network): registered 19 Mar 2019, registrar Synergy Wholesale, server Reliance Jio Infocomm (AS55836, India), 0.37 s. With a mobile number in the text, or an OTP request, it stays Likely scam (tests L2).
- **Demo set (14)**: 0 level changes, offline and live (real network). d02 and d06 gain "Uses the name SBI / India Post, but the site isn't theirs" (already Likely scam; their names have no registry record); d10 (bet365) is gambling, so no P2; d07's bit.ly button asked bit.ly only: "Couldn't reveal (the shortener didn't say)".
- **Val, offline signals** (`reports/link_signals_val.md`): on `urls.csv` val, any red flag 125 / 1,851 scam URLs (6.8%) vs 0 / 4,236 benign; the brand lookalike 28 vs 0; raw IP 93 vs 0; R1 67 vs 0 (circular: 63 URLhaus + 4 OpenPhish rows came from those feeds). On links in val messages: any red flag 40 / 408 scam links vs 10 / 920 benign (all 10 raw IPs, in 6 benign emails). Verdict changes on the 672 val messages with a link, offline D23 on vs off: 0 scam messages change; 2 benign go Suspicious → No warning signs (P2).

## Commercial use

This is a student project; three sources are **non-commercial only**: the Tranco list (built partly from Cloudflare Radar, CC BY-NC 4.0), the OpenPhish community feed (research / personal use, no redistribution), and the Google Safe Browsing API. A commercial version would replace them with a commercially usable popularity list (e.g. Majestic Million, CC BY 3.0, or the Chrome UX Report top sites, CC BY-SA 4.0), OpenPhish's paid feed (or another licensed feed), and Google Web Risk (paid). Also to re-check: URLhaus (commercial use may need abuse.ch's paid plan), the Interisle TLD table (all rights reserved), crt.sh (no stated terms), and OpenPhish's no-redistribution clause for any hosted server (D1). iptoasn.com (PDDL 1.0) and the IANA / ICANN data have no such limit.

## 0. Two facts that shape the design

- **The Jio link is not what makes the Jio promo Likely scam.** The URL model scores `t.jio` 0.080 (not flagged). The message is Likely scam because the text head scores it 0.928 (Likely scam from 0.656), and no D22 hard-risk signal fires (measured today). So a positive signal that only resets the link's own rating changes nothing for Jio. To move it, a verified brand link has to be allowed to cap the message (P1 below).
- **The sentence "analysis makes no outbound network call" is not in CLAUDE.md.** It is in the `src/shield/api/main.py` docstring and in `docs/demo/README.md:86`. CLAUDE.md has rule 8 ("Don't visit malicious URLs"). §7 rewrites all three.

## 1. Signals

**Offline** (no network at check time; lists downloaded by `src/update_link_lists.py`):

| # | Signal | Rule |
|---|---|---|
| 1 | Brand-owned TLD | The link's TLD is on a curated list (`.jio .reliance .ril .sbi .hdfcbank .airtel .bharti .tata .amazon .google` …). The updater keeps an entry only if ICANN's `gtlds.json` has `specification13: true` (brand TLD: only the owner, its affiliates and licensees can register), the contract isn't terminated, and `registryOperator` is the expected owner, **and** IANA's root zone lists it as delegated. Checked by hand today: `.jio` = Reliance Industries Limited, `.sbi` = State Bank of India, `.hdfcbank` = HDFC Bank Limited (IANA); `.airtel` = Bharti Airtel, `.amazon` (spec 13, ICANN). |
| 2 | High-abuse TLD | A small cited list of TLD names (see §4). Display-only. |
| 3 | Tranco rank | Full top 1M, looked up by registered domain. |
| 4 | Blocklists | OpenPhish community feed. URLhaus needs an account (§10). PhishTank needs an app key, so it is skipped. Matching: exact URL or host. On a platform (free host, shortener, user-content site) only the listed URL prefix counts, so one bad page on `sites.google.com` doesn't flag Google. |
| 5 | Indian brand lookalike | Curated `brands_india.json`: brand → tokens → registered domains it owns + its brand TLDs. A host label contains a brand token: whole token, or prefix / suffix of a token (`sbikyc`, `onlinesbi`, but not `lesbian`), or anywhere for tokens of 5+ letters. Near misses after folding confusables (`0→o`, `1→l`, `rn→m`): edit distance ≤ 1 for 5–7 letters, ≤ 2 for 8+, none for ≤ 4 (`sbi` vs `abc` is distance 2). Flagged when the registered domain isn't the brand's, isn't under its brand TLD, isn't in the Tranco top 100k, and isn't a platform (free hosts keep their existing rule). `url_features.BRANDS` is **not** touched: it is a model feature. |
| 6 | IDN homograph / raw IP | `xn--` labels are decoded. A homograph is a label mixing scripts (Latin + Cyrillic/Greek), or one whose confusable skeleton equals a brand token or a Tranco top-10k name. A plain single-script IDN (e.g. Devanagari `.भारत`) is display-only. Raw IP: IPv4 / IPv6 literals, also integer and hex forms. |

**Network** (domain only, all through `net.py`, in parallel, ≤ 2 s per call, ≤ 4 s per message). Skipped for platform hosts, because their facts describe the platform, not the page:

| # | Check | What leaves the machine | To |
|---|---|---|---|
| 7 | RDAP: created / expires / registrar / status | the registered domain | the TLD's registry, taken from IANA's RDAP bootstrap file (`.jio .sbi .hdfcbank` → `rdap.identitydigital.services`). Never rdap.org, never the registrar's server. |
| 8 | DNS A record → IP → ASN, provider, country (offline iptoasn table); IP in the list IPs → shared server | the registered domain (never the full host: a per-victim subdomain such as `x7f3a.scam.top` would tell the scammer's nameserver who is checking) | Cloudflare DNS-over-HTTPS. The IP is never contacted. |
| 9 | crt.sh first certificate date | the registered domain | crt.sh (the CT log, not the site). **D2 says "fallback only"**, so it runs only when RDAP gave no creation date. Then RDAP followed by crt.sh still fits in 4 s. crt.sh is slow and rate-limited, so expect many "couldn't verify". |
| 10 | Google Safe Browsing v5 `hashes:search` | 4-byte SHA-256 prefixes of the host-level expressions only (no path), never the domain in clear | `safebrowsing.googleapis.com`, only if `SAFE_BROWSING_KEY` is set; otherwise silently skipped |
| 11 | Shortener expansion (button only, D3) | the short URL | that shortener only (the 24 in `platforms.SHORTENERS`). A HEAD request, falling back to GET with headers only and the body unread. Redirects off, no cookies, no Referer. Read `Location`. If the next hop is also a listed shortener, repeat (max 3 hops); otherwise stop. The destination is never requested, and 1–10 then run on the revealed domain. |

## 2. Level rules (for your OK)

The link's model rating (`base_level`) is kept. Its phishing-side level = max(model level, red-flag floor). That level feeds `url_level` and the existing fusion (max of text and URL; both ≥ Suspicious → Likely scam). Unlike gambling, these flags **do** count as the URL side.

**Red flags: raise only, never lower**

| | Signal | Link floor |
|---|---|---|
| R1 | On OpenPhish / URLhaus | Likely scam (D16) |
| R2 | Safe Browsing match | Likely scam |
| R3 | IDN homograph | Likely scam |
| R4 | Brand lookalike | Suspicious |
| R5 | Raw IP host | Suspicious |
| R6 | Shares a server (IP) with listed scam sites; not for IPs of big CDN / cloud networks (Cloudflare, Akamai, Fastly, Google, Amazon, Microsoft), where one IP serves thousands of sites | Suspicious |
| R7 | Registered < 30 days ago | Suspicious |
| R8 | First certificate < 7 days ago (only when R7 can't be checked; never both) | Suspicious |
| R9 | Two or more of R4–R8 on the same link (e.g. `sbi-kyc.top` registered 3 days ago) | Likely scam |

**Positive signals: only when there is no hard-risk signal, and never against an R flag on the same link**

| | Signal | Effect |
|---|---|---|
| P1 | Brand-owned TLD (verified owner) | Link → No warning signs (overrides the URL model). **Message: Likely scam → Suspicious**, only if every link in it is P1 or P2 and the text has no Indian mobile number. That number guard is my addition: a prize scam can copy a real `t.jio` link and say "call 98…". It never goes below Suspicious, which mirrors D22's cap for registered senders. |
| P2 | Tranco top 10k, not a platform / shortener / user-content host (`t.me`, `wa.me`, `chat.whatsapp.com`, `docs.google.com`, `forms.gle`, `sites.google.com` …), no gambling hit | Link → No warning signs. The message changes only through the fusion, with no cap, because anyone can paste `google.com` into a scam. |
| — | P1 / P2 when a hard-risk signal is present | Reassuring line in Website details only; no level change |

**Hard-risk** is D22's list (OTP / PIN / CVV / password, R2 PIN-to-receive, URL-model scam-level link, free-hosted lookalike, gambling, legal threat, secrecy, cut-off threat, earning promise, payment demand), **plus R1–R9 on any link**. The positive link's own model rating is left out of "phishing link"; otherwise a brand link the model disliked would block itself. The dormant D22 sender rule gets R1–R9 as hard-risk too.

**Display-only (Website details, never the level):** abuse TLD (caution, neutral on a no-warning verdict so contract A7 holds), age 30–180 days (caution), registration length, registrar, RDAP status (e.g. `serverHold`), provider / ASN, country, Tranco rank or "not in the top 1M", certificate date ≥ 7 days, plain IDN.

**Predicted outcomes.** Jio: P1 "Belongs to Jio: only Reliance can register .jio addresses", no hard-risk, no mobile number → **Suspicious** (was Likely scam). The three warning reasons stay (urgency, payment, wording), and the brand line goes in a free reason slot, else in the link panel (D22 rule: never push a warning out). Demo set: d02 and d06 gain R4 (+ the abuse-TLD line) but are already Likely scam; d07 (bit.ly) only on the button; d10 (bet365) is gambling, so no P2; g01–g04 have no links. **Expected level changes: 0.**

## 3. `net.py` (`src/shield/core/net.py`, the only module that may import an HTTP / DNS library)

- **Check allowlist:** the RDAP hosts in IANA's bootstrap file (loaded from the downloaded file), `cloudflare-dns.com`, `crt.sh`, `safebrowsing.googleapis.com` (key set only), and the 24 shortener hosts (expansion only).
- **Update allowlist** (used only by `update_link_lists.py`, refused inside the API process): `tranco-list.eu`, `openphish.com`, `urlhaus.abuse.ch`, `data.iana.org`, `www.iana.org`, `www.icann.org`, `iptoasn.com`.
- **Every call:** https only, exact host match, no IP literals, redirects off, no cookies, a fixed User-Agent, 2 s timeout, a response size cap, and a per-message 4 s deadline. Every call adds a "sent" record (`domain x → host`) for the UI's "sent off this machine" line (`Evidence.sent` already exists).
- The httpx / httpcore loggers are silenced; exceptions become a fixed status, never their text, which contains the URL. The cache is an in-process LRU (about 2,000 domains, 1–24 h TTL by check, failures not cached). Nothing is written to disk.

## 4. Data sources and licences

| Data | Source | Terms (checked 2026-10-18) | Stored |
|---|---|---|---|
| Tranco top 1M | tranco-list.eu | No licence for the list itself; inputs include Cloudflare Radar (CC BY-NC 4.0), CrUX (CC BY-SA 4.0), Majestic (CC BY 3.0). Non-commercial use; cite Le Pochat et al., NDSS 2019. Already used by the project. | git-ignored |
| OpenPhish community feed | openphish.com/feed.txt | Research / personal use allowed; no commercial use; **no redistribution** without permission | git-ignored; re-check before any public hosting (D1) |
| URLhaus | urlhaus.abuse.ch | Free under abuse.ch fair use; **bulk downloads need an Auth-Key from a free account** | git-ignored |
| RDAP bootstrap, root zone, brand-TLD data | data.iana.org/rdap/dns.json, iana.org root DB, icann.org `gtlds.json` | public registry data | bootstrap git-ignored; brand-TLD list tracked |
| IP → ASN / country | iptoasn.com `ip2asn-v4.tsv.gz` | PDDL 1.0 (per two secondary sources; confirmed on the site at download) | git-ignored |
| High-abuse TLDs | Interisle Cybercrime Information Center phishing-per-TLD tables (fallback: Spamhaus TLD stats) | © Interisle; we store only ~15 TLD names + quarter + URL as cited facts | tracked, small |
| Safe Browsing | Google | Non-commercial only; UI attributes Google | nothing stored |

Each download records URL, licence, date and SHA-256 in `data/sources.yaml` (tracked) and a git-ignored manifest. The UI shows "lists updated N h ago". If a list is older than 7 days, its "not listed" becomes "couldn't verify (list out of date)".

## 5. Failure behaviour

- Every failed, timed-out, rate-limited, unsupported (no RDAP for the TLD) or offline check gives an `unknown` row, "Couldn't verify (offline)" or "(timed out)" or "(no public registry for .xx)". It is never reassuring and never moves the level.
- RDAP 404 shows as "The registry has no record (it may have been taken down)": unknown, no level change.
- A missing list file disables that signal with the same message. The app still runs.
- With live checks off (`config.LIVE_CHECKS`, default on per D2), all network rows say "not checked".

## 6. Flow, contract, UI

- **Flow:**
  - `POST /api/analyse {text}`: offline only (unchanged T7: zero network) → Report with link facts and `pending` check ids.
  - Then the page calls `POST /api/analyse {text, live: true}` → the final Report. The text goes only to our own localhost server; only domains leave. Live checks can only raise (all positives are offline), so a verdict can go **up**, never down, after it is shown, with the line "Raised after the website checks".
  - The button sends `{text, live: true, expand: [short_url]}`. The URL must be in the text and on the shortener list.
- **Contract v4:** a child Report gets `facts`: rows of {key, label, value, effect, why, status ok / pending / failed / skipped, source, sent}. New evidence ids `link.listed`, `link.safe_browsing`, `link.homograph`, `link.lookalike`, `link.raw_ip`, `link.shared_server`, `link.new_domain`, `link.new_cert`, `link.brand_owned`, `link.popular`, `link.abuse_tld`. A red flag's "why it matters" goes in `detail`, e.g. "Scam sites are usually days or weeks old; bank sites are years old."
- **UI:**
  - A "Website details" fact sheet per link, open by default when a red flag fires. Each row has an icon, a label, a value and a why-line.
  - Pending rows show a small "Checking…"; failed rows say "Couldn't verify (offline)".
  - Shorteners get a "Where does this short link go?" button with the note "Asks bit.ly only; bit.ly may count it as a click. The destination is not opened."
  - Checked at 360 / 390 / 430 px and 1280 / 1440 desktop. The earlier Playwright overlap scripts were never committed (scratchpad), so I'll rewrite them and commit them this time (`frontend/e2e/`).

## 7. Network rule wording

**CLAUDE.md rule 8, old:** "**Don't visit malicious URLs.** Store them as strings only."

**New:** "**Never visit a link from a message or a dataset.** Never load its page, connect to its server or IP, or follow its redirects; links are stored and analysed as strings. The app's only outbound calls go through `src/shield/core/net.py` (host allowlist, https, no redirects, ≤ 2 s per call, ≤ 4 s per message): domain-only lookups at the TLD registry (RDAP), Cloudflare DNS-over-HTTPS (the IP is never contacted), crt.sh, and Google Safe Browsing (hash prefixes, only if `SAFE_BROWSING_KEY` is set); and, on the user's button press only, one no-redirect request to a known link shortener. Only a registered domain (or the short link) leaves the machine, never message text. Results stay in memory; domains, URLs and IPs are never logged. List downloads run only in `src/update_link_lists.py`."

**`api/main.py` docstring and `docs/demo/README.md:86`, old:** "an analysis makes no outbound network call (links are parsed as strings, never fetched)". **New:** "the first, offline analysis makes no outbound network call; the live link checks send only a registered domain to the allowlisted services in `net.py` (CLAUDE.md rule 8), and no link is ever fetched."

## 8. Files

- **New:**
  - `src/shield/core/net.py`
  - `src/shield/links/lists.py` (offline lists, loaded once)
  - `brands.py` + `brands_india.json`
  - `lookalike.py` (5, 6)
  - `live.py` (7–11, parallel, cache)
  - `reputation.py` (the §2 table)
  - `src/update_link_lists.py`
  - `src/link_signals_val.py` → `reports/link_signals_val.md`
  - `tests/test_links_live.py`
  - frontend `WebsiteDetails.tsx`, `lib/facts.ts` (+ vitest), `frontend/e2e/`
- **Changed:**
  - `router.py`: flags, P1 cap, `live` / `expand`
  - `report.py`
  - `contracts.py` (v4)
  - `sender_rule.py` (hard-risk += R1–R9; exclude the positive link)
  - `api/main.py`
  - `config.py`
  - `LinkPanel.tsx`, `Result.tsx`, `api.ts`, `types/report.ts`, `styles.css`
  - `tests/test_contracts.py` (v4)
  - CLAUDE.md (rule 8 + status)
  - `docs/demo/README.md`
  - `docs/decisions/README.md` (D23 row; D2–D4 built)
  - `data/sources.yaml`
  - BUGS.md
  - `pyproject.toml` (httpx moves from dev to main)
- **Untouched:** models, `url_features.py`, `textprep.py`, data, `split_map.csv`.
- **The grep check covers `src/shield/` + `update_link_lists.py`.** The old research scripts (`pull_urls.py`, `enrich_domains.py`, `pull_gambling.py`, `scrape_web.py`) still import `requests`. They never run in the app, so they are listed as exceptions, not rewritten.

## 9. Measurement (val only, offline signals only, no live calls on bulk data)

- **(a) `urls.csv` val, 8,686 rows, per source × label.** Circular sources are flagged: the Tranco benign rows come from Tranco, and the openphish (18) / urlhaus (63) rows come from those feeds. The independent slice is ealvaradob (2,186 benign / 1,770 phishing), whose old phishing domains are mostly gone from today's feeds (a staleness effect, not a miss). `gambling_spam` (2,599) is reported separately.
- **(b) Links in val messages:** 1,328 links in 672 messages (447 benign / 225 scam), labelled by their message (an approximation), per source.

## 10. Needs your answer (answered 2026-10-18: see "User decision" at the top)

1. Approve the §2 table, especially P1 capping the message at Suspicious (with the mobile-number guard), and R9.
2. **URLhaus now needs a free abuse.ch account** (Auth-Key, verified on urlhaus.abuse.ch/api today). OK to use it? If yes, create the key and set `URLHAUS_AUTH_KEY`. Without it, R1 is OpenPhish-only and R6 has almost no IPs.
3. DNS via Cloudflare DoH (recommended: one allowlisted host, mockable, no client-subnet forwarding; Cloudflare sees the domain) or the system resolver.
4. crt.sh as fallback only (D2, recommended) or always.
5. Optional, beyond your list: show `.bank.in` (RBI-mandated, IDRBT-only registrar) and `.gov.in` / `.nic.in` as restricted-registry facts, as display-only reasons, because hacked `gov.in` sites do host scams.
