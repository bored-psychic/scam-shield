import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Dev server on loopback only. The app calls the relative path /api/...; Vite forwards it to the FastAPI app
// (uvicorn shield.api.main:app --host 127.0.0.1 --port 8000), so the browser only ever talks to 127.0.0.1:5173.
// strictPort: if 5173 is taken, fail instead of moving to another port (the API's CORS list names 5173).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Keep font files as files: inlined into the CSS, the small Geist Mono subsets (cyrillic-ext, symbols, vietnamese) tripled the size of
  // the render-blocking stylesheet, and as files the browser fetches a subset only when the page shows one of its characters.
  build: { assetsInlineLimit: (file) => (/\.woff2?$/.test(file) ? false : undefined) },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
});
