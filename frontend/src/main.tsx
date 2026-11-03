import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// Fonts are bundled from npm (@fontsource), never fetched from Google Fonts or any CDN: no third-party request at runtime (D9).
//   body and UI: Lexend (variable, weight axis); headings: Libre Baskerville 400 / 700 behind --display (styles.css); numbers, codes and website
//   facts: Geist Mono (tabular figures). Hindi and Kannada message text: Noto Sans Devanagari / Kannada, only their own script subsets (Lexend
//   covers Latin only), regular weight (src/fonts/indic.css says why it is not @fontsource's own file).
//   @fontsource splits every family by unicode-range, so a browser downloads a subset only when the page shows one of its characters.
import "@fontsource-variable/lexend/wght.css";
import "@fontsource/libre-baskerville/400.css";
import "@fontsource/libre-baskerville/700.css";
import "@fontsource/libre-baskerville/700-italic.css";   // the accent word of the home headline (D29.15)
import "@fontsource/geist-mono/400.css";
import "@fontsource/geist-mono/500.css";
import "@fontsource/geist-mono/600.css";
import "./fonts/indic.css";
import "./styles.css";
import App from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
