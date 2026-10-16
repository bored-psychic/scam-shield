# Scam Shield frontend

The web app (decision D9: React + Vite + TypeScript + Tailwind v4 + Motion, three.js for the globe). It ports the approved prototype
`docs/design/prototype-globe.html` (spec: `docs/design/README.md`) and gets every verdict from the local API: nothing is decided here.

Part 1 (now): home screen, globe, checking state, API wiring. The result screen is a **temporary placeholder**
(`src/components/ResultPlaceholder.tsx`); part 2 replaces it with the bento grid and the radar meter.

## Run it

First time only: `cd frontend && npm ci` (Node 20.19+ or 22.12+).

Terminal 1, the API (from the repo root, with `.venv` active):

    uvicorn shield.api.main:app --host 127.0.0.1 --port 8000

Terminal 2, the dev server:

    cd frontend && npm run dev

Open http://127.0.0.1:5173. The page calls the relative path `/api/...` and Vite forwards it to 127.0.0.1:8000, so the browser only
talks to 127.0.0.1:5173. If the API is not running, the page says "Couldn't reach the checker. Is the API running?" and offers Retry.

## Check and build

    npx tsc --noEmit    # type check (TypeScript 7)
    npm run build       # type check + production build into dist/

## Rules this code keeps

- **No third-party requests at runtime** (docs/ARCHITECTURE.md §1): three.js and the fonts come from npm and are bundled; the globe
  data is bundled JSON (`src/data/`, copied byte for byte from the prototype). The only outside URLs are links the user clicks.
- **The message text is never logged**: no `console.*` calls; it goes only into the POST body.
- **Everything shown comes from the `Report`**: `src/types/report.ts` mirrors `src/shield/contracts.py` (schema v2); an answer with
  another `schema_version` is shown as an error. No percentage anywhere (D4).
- **Globe**: pixel ratio capped at 1.75, paused while the tab is hidden, fully disposed on unmount; with reduced motion it is a static
  globe (no rotation, arcs or pulse) that can still be dragged.

## Notes for part 2

- Tailwind is imported **without Preflight** (`src/styles.css` explains why): new elements keep browser defaults until styled.
- Evidence `span` offsets count Unicode code points: index the message with `Array.from(text)`, never `text.slice()`.
- Link evidence is in `report.children[].evidence`, not in `report.evidence`.
