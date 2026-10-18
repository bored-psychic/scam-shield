# Scam Shield frontend

The web app (decision D9: React + Vite + TypeScript + Tailwind v4 + Motion, three.js for the globe). It ports the approved prototype
`docs/design/prototype-globe.html` (spec: `docs/design/README.md`) and gets every verdict from the local API: nothing is decided here.

Part 1: home screen, globe, checking state, API wiring. Part 2: the result screen (`src/components/Result.tsx`): a bento grid of
the verdict with the radar meter (8b), the message with its underlined parts, why, the links and what to do now.

Screenshot input (D19, part B; `src/components/PasteBox.tsx`, `src/lib/screenshot.ts`, `ocr()` in `src/api.ts`): the Screenshot
button (file picker), a drop onto the box, or an image pasted from the clipboard (a paste with plain text stays a text paste). The
file is checked here first (PNG / JPEG / WEBP, at most 8 MB, not empty; a browser may report a network error instead of the API's
413, so nothing too big is ever uploaded), shown as a thumbnail while `POST /api/ocr` reads it, and its text goes into the box,
after asking if the box already held the user's own text. A notice above the box asks the user to check the text, especially
amounts (₹) and links (the rupee sign is often misread, BUGS.md); the check only runs when they press Check. The image lives only in
memory: the File and an object URL for the thumbnail, revoked when the screenshot is replaced or removed or the box goes away.

## Run it

First time only: `cd frontend && npm ci` (Node 20.19+ or 22.12+).

Terminal 1, the API (from the repo root, with `.venv` active):

    uvicorn shield.api.main:app --host 127.0.0.1 --port 8000

Terminal 2, the dev server:

    cd frontend && npm run dev

Open http://127.0.0.1:5173. The page calls the relative path `/api/...` and Vite forwards it to 127.0.0.1:8000, so the browser only
talks to 127.0.0.1:5173. If the API is not running, the page says "Couldn't reach the checker. Is the API running?" and offers Retry.

## Check, test and build

    npx tsc --noEmit    # type check (TypeScript 7)
    npm test            # vitest: the display logic in src/lib/ (U1-U9 in src/lib/lib.test.ts) and the screenshot input
                        # (V1-V4 in src/lib/screenshot.test.ts: file checks, api.ocr() error words with fetch mocked, the notice, paste)
    npm run build       # type check + production build into dist/

The tests read real Reports: `src/lib/__fixtures__/reports.json`, written by `scripts/dump_fixture.py` (every input of
`tests/tricky_inputs.py` plus four extras, through the same `analyse()` + `to_report()` as the API). Rerun it after a change to the
adapter or the models, from the repo root with the project venv:

    .venv/bin/python frontend/scripts/dump_fixture.py

## Fonts and themes (D24, D25)

Headings Libre Baskerville (400 / 700, behind `--display`), body and UI Lexend (variable), codes and data Geist Mono, Hindi / Kannada
Noto Sans Devanagari / Kannada (`src/fonts/indic.css`). All are npm `@fontsource` packages, self-hosted (no CDN).

Two themes, dark (the default design) and light, from one set of colour tokens per theme in `src/styles.css`; nothing else names a colour
(the globe reads its colours from the tokens). The sun / moon button in the header switches them (`src/lib/theme.ts`); the first visit
follows the system setting, the choice is kept in `localStorage`, and an inline script in `index.html` sets the theme before the first paint.

Checks on the built site (`npm run build` first):

    node e2e/fonts.mjs      # no font CDN, no third-party request, font KB per screen (--shots DIR --label NAME saves screenshots)
    node e2e/theme.mjs      # toggle, reload, system setting, no flash, blocked storage, reduced motion, the globe repaints
    node e2e/axe.mjs        # axe-core colour contrast, both themes
    node e2e/contrast.mjs   # WCAG AA on the real rendered backgrounds (glass over the globe), both themes
    node e2e/overlap.mjs    # layout of the result screen, phones and desktop, both themes

## Rules this code keeps

- **No third-party requests at runtime** (docs/ARCHITECTURE.md §1): three.js and the fonts come from npm and are bundled; the globe
  data is bundled JSON (`src/data/`, copied byte for byte from the prototype). The only outside URLs are links the user clicks.
- **The message text is never logged**: no `console.*` calls; it goes only into the POST body. A screenshot goes only into the
  body of `POST /api/ocr` (under a fixed part name, not its file name) and is never put in localStorage, sessionStorage or IndexedDB. The only thing stored is the theme choice (`scam-shield-theme`).
- **Everything shown comes from the `Report`**: `src/types/report.ts` mirrors `src/shield/contracts.py` (schema v5); an answer with
  another `schema_version` is shown as an error. No percentage anywhere (D4): the risk score (D24) is a 0-100 warning-sign meter, never written as a percentage.
- **Globe**: pixel ratio capped at 1.75, paused while the tab is hidden, fully disposed on unmount; with reduced motion it is a static
  globe (no rotation, arcs or pulse) that can still be dragged.

## How the result screen reads a Report (`src/lib/`, pure functions, unit-tested)

- `allEvidence()`: the Report's evidence plus every link's (`report.children[].evidence`), in the order reasons are picked
  (rule -> links -> tactics -> model).
- `segments()`: the message cut at the evidence spans. Spans count Unicode **code points**, so it indexes `Array.from(text)`, never
  `text.slice()`. Overlapping spans form one underlined **cluster** (e.g. "share the PIN" around "PIN"), coloured by its most severe
  member (danger > caution > unknown > neutral); its tooltip lists every member's title. Reassuring evidence is never underlined;
  neutral evidence (dotted) only on a "No warning signs found" verdict.
- `blips()`: the radar's blips, one per tag of the danger / caution evidence, at most 4, none on a no-warning verdict.
- `reasonTargets()`: the evidence each reason was copied from, so tapping a reason pulses its part of the message.
- `linkParts()` / `linkBlocks()`: the link panel; the owner part (registrable domain) is a display approximation, never a verdict.
- The line under the verdict word is fixed per level (`LEVEL_SUMMARY` in `lib/levels.ts`); the advice is `Report.advice` as sent.
  No score, threshold or timing is ever shown (D4).

## Notes

- Tailwind is imported **without Preflight** (`src/styles.css` explains why): new elements keep browser defaults until styled. Its
  utilities are generated from words found in the source, so a class name like `static`, `fixed` or `hidden` gets a utility's styles:
  don't use those as component class names.
- The tooltip is rendered into `<body>`: inside a panel, the panel's `backdrop-filter` would become the containing block of its
  `position: fixed`.
