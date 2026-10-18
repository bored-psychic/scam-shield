import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The display (heading) font is behind ONE CSS variable, --display. Which font file sets it is chosen when the app is built or started:
//   DISPLAY_FONT=bricolage (default) | space | fraunces   e.g.  DISPLAY_FONT=fraunces npm run dev
// Only the chosen font is bundled; the others cost nothing. All three come from @fontsource packages (self-hosted, no CDN).
const FONTS = ["bricolage", "space", "fraunces"];

// Dev server on loopback only. The app calls the relative path /api/...; Vite forwards it to the FastAPI app
// (uvicorn shield.api.main:app --host 127.0.0.1 --port 8000), so the browser only ever talks to 127.0.0.1:5173.
// strictPort: if 5173 is taken, fail instead of moving to another port (the API's CORS list names 5173).
export default defineConfig(({ mode }) => {
  const display = loadEnv(mode, ".", "DISPLAY_").DISPLAY_FONT || "bricolage";   // loadEnv also reads the process environment
  if (!FONTS.includes(display)) throw new Error(`DISPLAY_FONT=${display}: choose one of ${FONTS.join(", ")}`);
  return {
    plugins: [react(), tailwindcss()],
    resolve: { alias: { "@display-font": decodeURIComponent(new URL(`./src/fonts/${display}.css`, import.meta.url).pathname) } },
    // Keep font files as files: inlined into the CSS, the small Geist Mono subsets (cyrillic-ext, symbols, vietnamese) tripled the size of
    // the render-blocking stylesheet, and as files the browser fetches a subset only when the page shows one of its characters.
    build: { assetsInlineLimit: (file) => (/\.woff2?$/.test(file) ? false : undefined) },
    server: {
      host: "127.0.0.1",
      port: 5173,
      strictPort: true,
      proxy: { "/api": "http://127.0.0.1:8000" },
    },
  };
});
