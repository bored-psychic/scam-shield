# Scam Shield design reference

Approved by the user on 2026-10-17. Decisions D9, V1 and G2 in `docs/decisions/README.md` point here.

| File | What it is |
|---|---|
| `prototype-globe.html` | The approved look. Open it in a browser. Home screen, checking state and result screen, with three example messages. |
| `meter-options.html` | The 12 meter designs that were compared. **8b "Labelled blips" (radar) was chosen.** |
| `theme-switch.html` | The theme-switch animation, approved 2026-10-18: the comet (dark -> light, 2.4 s, 34 degree light cone) and the black hole (light -> dark, 2.6 s). Its Tuner panel is for design only. Built into the app as `frontend/src/lib/themeSwitch.ts`. |
| `tabs-home.html` | The four-tab home screen (D29.15, 2026-11-03): SMS / Email, Link, Payment / UPI, App / APK, with the exact headlines, sub-lines, boxes and sample chips. Built as `frontend/src/components/Home.tsx` and `lib/tabs.ts`. |
| `tabs-result.html` | The result page with the four tabs on top (D29.15): column widths, per-tab minimum heights. Built as `frontend/src/components/Result.tsx`. |
| `tabs-home-themeswitch.html` | The four-tab main page with the theme switch (title "Scam Shield main page, theme switch"). A reference only. |
| `tabs-glass-demo.html` | The glass / pointer-light demo for the tabs (title "Scam Shield metal demo", a self-contained 1.6 MB bundle). A reference only; the app's version is `components/Light.tsx` + `lib/pointerLight.ts`. |
| `motion-demo/` (`Demo.tsx`, `demo.css`) | The GSAP motion reference (D30): the globe rise on load and the tab switch. A reference only, not built by `npm run build`. |

**This is a design prototype, not the app.** Verdicts in it are written by hand for the three examples, and the globe attacks are simulated. The real frontend must reproduce this look, but:

- **Frontend stack (D9):** React + Vite + Tailwind + Motion. The backend is FastAPI serving the `Report` contract (`src/shield/contracts.py`) as JSON. Detection stays in Python.
- **No third-party requests at runtime** (ARCHITECTURE §1, privacy). The prototype loads three.js from cdnjs and Geist from Google Fonts. The app must bundle or self-host both.
- **Everything shown comes from a `Report`.** Nothing is hard-coded per message.

## Design tokens

| Token | Value | Use |
|---|---|---|
| `--bg` | `#04060A` | page background (single dark theme) |
| `--ink` | `#EDF1F7` | main text |
| `--muted` / `--faint` | `#8A94A6` / `#4A5363` | secondary text / labels |
| `--green` | `#3DD68C` | No warning signs found |
| `--amber` | `#F2B13B` | Suspicious, caution evidence |
| `--red` | `#FF3B3B` | Likely scam, danger evidence, cybercrime-hub arcs |
| orange | `#FF8A3B` | DDoS-source arcs |
| `--grey` | `#7C8696` | Can't judge |
| `--blue` | `#5AB0FF` | Promotional (D22, added 2026-10-18): calm, neither the green of No warning signs nor the amber of Suspicious; price-tag icon |
| fonts | Geist (UI), Geist Mono (labels, data) | self-hosted |

**Glass panel recipe:** background `rgba(8,11,17,.05)` plus a very faint white top sheen; `backdrop-filter: blur(4px) saturate(140%)`; 1px edge highlight (gradient, brightest at top-left); inset top highlight `rgba(255,255,255,.14)`; shadow `0 12px 40px rgba(0,0,0,.35)`. Radii: panels 26px, reason rows 22px, buttons 14px, chips 999px.

## Screens

1. **Home.**
   - Full-screen dark stage. A dotted 3D globe rises from the bottom, slowly rotates and can be dragged.
   - **India:** denser bright dots plus a pulsing red outline, drawn from India's official boundaries (Natural Earth `ne_10m_admin_0_countries_ind`, India point of view).
   - **Attack arcs:** see Globe data below.
   - **Header:** logo and the "Checked on this device" pill.
   - **Hero:** "Got a message that feels off?"
   - **Glass paste box:** live detection chips as you type (links, UPI IDs, phone numbers, amounts, OTP/PIN mentions), a Check button, and Ctrl/Cmd+Enter.
   - *Removed 2026-10-18 (product decision, D22):* the optional Sender row under the box (input, hint, ⓘ explainer of P / S / T / G). The API keeps its optional sender field, dormant.
   - **Example chips** below the box.
   - **Footer:** a "Simulated from real rankings · not live ⓘ" button that opens the sources, and a feed of the last 4 simulated hits. On phones (640px and under) the footer is part of the page and follows the content (it rests at the bottom of the screen when the content is short), so it never covers the example chips; the feed is hidden there.
2. **Checking.** A three-step checklist ticks through (reading the message → checking links and payment IDs → OTP requests and pressure tricks). No spinner.
3. **Result (bento grid).**
   - The globe stays visible at 70% behind the panels.
   - **Top bar:** "← Check another message" and "nothing was stored".
   - **Verdict panel:** icon, verdict word and one-line summary, plus the radar meter. *The sender chip (D22) was removed on 2026-10-18 with the sender input.*
   - **Message panel:** as tall as its text (a long message scrolls inside it, at most 480px). Risky phrases are underlined in their severity colour, with a tooltip on hover or tap. *Changed 2026-10-18:* it used to span two grid rows, which stretched it to the height of the verdict and why panels and left a large empty area under a short message.
   - **Why panel:** at most 3 reasons. Tapping one pulses its phrase in the message.
   - **Link panel:** the domain broken into parts with the suspicious part highlighted, a list of checks, and "The link was not opened."
   - **What to do now:** steps you can tick off, plus "Copy helpline 1930" and cybercrime.gov.in. When the verdict is a warning and the message has a link, a blue "Tip" note: "Check who sent it: real businesses send from IDs like JM-JIOCPN-P; scams usually come from ordinary phone numbers." (D22; reworded 2026-10-18 when the sender input was removed).
   - **Wide screens (901px and up), changed 2026-10-18:** two columns, each panel as tall as its content: left, verdict then why; right, message, link, what to do now.
   - **Phones:** the panels stack: verdict → message → why → link → what to do.

## Radar meter (option 8b)

- The sweep is in the verdict colour.
- **One blip per warning sign** (DANGER or CAUTION evidence), at most 4. Each blip has a short tag ("OTP request", "Fake link", "Secrecy") coloured by severity.
- Tapping a tag pulses the matching phrase in the message.
- **No warning signs found:** green sweep, no blips, caption "Scanned · no warning signs found".
- **Can't judge:** grey, sweep stopped.
- **Promotional (D22):** blue sweep, caption "Scanned · registered promotional sender"; a blip only for a caution on a link (a link the URL model rates Suspicious is not a hard-risk signal).
- **Keeps D4:** no percentage anywhere, the meter can never contradict the verdict word, and the verdict is always word + icon + colour.

## Globe data (G2)

The globe is a simulation weighted by real published rankings, always labelled "not live":

- **Red origins:** World Cybercrime Index (Bruce et al., PLOS ONE, 2024). Russia 58.39, Ukraine 36.44, China 27.84, US 25.01, Nigeria 21.28 as published. Ranks 6–10 (Romania, North Korea, UK, Brazil, India) are in the published order with estimated weights.
- **Orange origins:** Cloudflare DDoS threat report Q4 2025, top-10 sources, weighted by rank.
- **Targets:** the same report's top-10 most attacked locations, weighted by rank.
- **Upgrade path:** the Cloudflare Radar API, called from the backend. It needs a token, and its licence is non-commercial.

## Accessibility and performance

- Respects reduced motion: no rotation, no arcs, no pulsing.
- Colour is never the only signal.
- The globe caps the pixel ratio at 1.75 and pauses when the tab is hidden.
- Test on a budget Android phone, and reduce the blur if scrolling stutters.

## What the backend still has to provide (contract v2)

- **Phrase positions:** start and end character offsets for each evidence quote, so phrases can be underlined inside the message.
- **Tags:** a short label for each evidence item, for the radar.
