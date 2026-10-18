import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// Fonts are bundled from npm (@fontsource), never fetched from Google Fonts or any CDN: no third-party request at runtime (D9).
//   body: Geist; numbers and codes: Geist Mono (tabular figures); headings: the display font behind --display (vite.config.ts: DISPLAY_FONT).
//   Hindi and Kannada message text: Noto Sans Devanagari / Kannada, only their own script subsets (Geist covers Latin), regular weight (src/fonts/indic.css says why it is not @fontsource's own file).
//   @fontsource splits every family by unicode-range, so a browser downloads a subset only when the page shows one of its characters.
import "@fontsource/geist/400.css";
import "@fontsource/geist/500.css";
import "@fontsource/geist/600.css";
import "@fontsource/geist-mono/400.css";
import "@fontsource/geist-mono/500.css";
import "@fontsource/geist-mono/600.css";
import "@display-font";
import "./fonts/indic.css";
import "./styles.css";
import App from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
