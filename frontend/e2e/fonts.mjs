// Font checks on a BUILT site (D24; fonts since 2026-10-18: Lexend, Libre Baskerville, Geist Mono, Noto Devanagari / Kannada): no font CDN, no
// third-party request, and what the fonts cost.
//
//   cd frontend && npm run build && node e2e/fonts.mjs [--dist DIR] [--shots DIR --label NAME] [--schema 4]
//
// 1. Static: dist/index.html and every dist CSS / JS file contain no http(s):// or protocol-relative URL (XML namespaces aside), nothing from
//    fonts.googleapis.com / fonts.gstatic.com, and every @font-face src is a relative file.
// 2. Browser: the INSTALLED Google Chrome (playwright-core) loads the built site from Vite's preview server on 127.0.0.1; /api/analyse is answered
//    from the real Reports in src/lib/__fixtures__/reports.json, so no backend and no network are needed. EVERY request the page makes is logged
//    and must be to 127.0.0.1:PORT. Home, the Jio result, Hindi text and Kannada text are loaded at 390x844 and 1440x1150.
// 3. It prints the font files each flow downloaded (KB), and the woff2 total in dist. --shots DIR + --label NAME also saves screenshots
//    (home and the Jio result, at both sizes) as DIR/NAME_<screen>_<width>.png; they are not committed. --schema 4 serves the fixture as a schema-4
//    Report, to measure a build from before D24. Exit code 1 on any failure.
import { readdirSync, readFileSync, mkdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { preview } from "vite";

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (name, dflt = null) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : dflt; };
const DIST = resolve(arg("--dist", join(HERE, "..", "dist")));
const SHOTS = arg("--shots"), LABEL = arg("--label", "site"), SCHEMA = arg("--schema", "6"), PORT = Number(arg("--port", "4174"));
const FIXTURES = JSON.parse(readFileSync(join(HERE, "..", "src", "lib", "__fixtures__", "reports.json"), "utf8"));
const jio = FIXTURES.find((x) => x.label === "jio-no-sender");
const report = SCHEMA === "6" ? jio.report : (() => { const r = JSON.parse(JSON.stringify(jio.report)); r.schema_version = SCHEMA; delete r.risk_score; delete r.lowered; return r; })();
const HINDI = "आपका बैंक खाता आज बंद हो जाएगा। तुरंत अपना OTP साझा करें।";
const KANNADA = "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆಯನ್ನು ಇಂದು ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ. ತಕ್ಷಣ ನಿಮ್ಮ OTP ಹಂಚಿಕೊಳ್ಳಿ.";
const problems = [];
const kb = (n) => (n / 1024).toFixed(1);

// 1. static scan
function files(dir) { return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)])); }
const all = files(DIST);
for (const f of all.filter((x) => /\.(html|css|js)$/.test(x))) {
  const text = readFileSync(f, "utf8").replace(/http:\/\/www\.w3\.org\/\d{4}\/[a-z0-9]+/gi, "").replace(/https?:\/\/(?:www\.)?(?:reactjs\.org|react\.dev|github\.com)[^\s"'`)]*/gi, "");
  // third-party URLs inside the JS bundle can only be error-message links of libraries (React's, three.js); a font URL never is
  for (const m of text.matchAll(/(?:https?:)?\/\/[a-z0-9.-]+\.[a-z]{2,}[^\s"'`)]*/gi)) {
    if (/\.(css|html)$/.test(f) || /font|gstatic|googleapis|typekit|bunny|cdn/i.test(m[0])) problems.push(`${f.slice(DIST.length + 1)}: external URL ${m[0].slice(0, 80)}`);
  }
  if (/fonts\.(googleapis|gstatic)\.com/.test(text)) problems.push(`${f.slice(DIST.length + 1)}: mentions Google Fonts`);
}
for (const f of all.filter((x) => x.endsWith(".css"))) {
  for (const m of readFileSync(f, "utf8").matchAll(/@font-face\s*{[^}]*}/g)) {
    const src = [...m[0].matchAll(/url\(([^)]+)\)/g)].map((u) => u[1].replace(/["']/g, ""));
    if (!src.length || src.some((u) => /^(?:https?:)?\/\//.test(u))) problems.push(`@font-face with a non-local src: ${m[0].slice(0, 100)}`);
  }
}
const woff2 = all.filter((x) => x.endsWith(".woff2"));
console.log(`static scan: ${all.length} files in dist, no external URL${problems.length ? "  <-- PROBLEMS BELOW" : ""}; woff2 files: ${woff2.length}, ${kb(woff2.reduce((n, f) => n + statSync(f).size, 0))} KB on disk`);

// 2. browser
const server = await preview({ root: join(HERE, ".."), build: { outDir: DIST }, preview: { host: "127.0.0.1", port: PORT, strictPort: true }, logLevel: "silent" });
const browser = await chromium.launch({ channel: "chrome", headless: true });
const rows = [];
try {
  for (const [w, h] of [[390, 844], [1440, 1150]]) {   // 1150 px tall: the result fits without fullPage, which loses panels over the WebGL globe in headless Chrome
    for (const flow of ["home", "result", "hindi", "kannada"]) {
      const ctx = await browser.newContext({ viewport: { width: w, height: h }, reducedMotion: "reduce", deviceScaleFactor: 1 });
      const page = await ctx.newPage();
      const seen = [], fontBytes = [];
      page.on("request", (r) => seen.push(r.url()));
      page.on("response", async (r) => { if (/\.woff2?(\?|$)/.test(r.url())) fontBytes.push([r.url().split("/").pop(), (await r.body().catch(() => Buffer.alloc(0))).length]); });
      await page.route("**/api/analyse", (route) => route.fulfill({ json: report }));
      await page.goto(`http://127.0.0.1:${PORT}/`);
      await page.waitForSelector("#msg");
      if (flow === "hindi") await page.fill("#msg", HINDI);
      if (flow === "kannada") await page.fill("#msg", KANNADA);
      if (flow === "result") {
        await page.fill("#msg", jio.text);
        await page.click("button.go");
        await page.waitForSelector(".result .vword");
        await page.waitForFunction(() => !document.querySelector(".frow.pending") || true);
      }
      await page.evaluate(() => document.fonts.ready);
      await page.waitForTimeout(700);
      const used = await page.evaluate(({ flow, HINDI, KANNADA }) => ({
        devanagari: document.fonts.check('16px "Noto Sans Devanagari"', HINDI), kannada: document.fonts.check('16px "Noto Sans Kannada"', KANNADA),
        loaded: [...document.fonts].filter((f) => f.status === "loaded").map((f) => f.family.replace(/["']/g, "")).filter((v, i, a) => a.indexOf(v) === i),
      }), { flow, HINDI, KANNADA });
      for (const u of seen) if (!u.startsWith(`http://127.0.0.1:${PORT}/`) && !u.startsWith("data:") && !u.startsWith("blob:")) problems.push(`${w}px ${flow}: request outside the page: ${u}`);
      if (flow === "hindi" && !(used.loaded.includes("Noto Sans Devanagari"))) problems.push(`${w}px hindi: Noto Sans Devanagari was not loaded (${used.loaded.join(", ")})`);
      if (flow === "kannada" && !(used.loaded.includes("Noto Sans Kannada"))) problems.push(`${w}px kannada: Noto Sans Kannada was not loaded (${used.loaded.join(", ")})`);
      if (flow === "home" && (used.loaded.some((f) => /Noto/.test(f)))) problems.push(`${w}px home: a Noto face was downloaded for an English page`);
      const total = fontBytes.reduce((n, [, b]) => n + b, 0);
      rows.push({ w, flow, files: fontBytes.length, kb: kb(total), loaded: used.loaded.join(", "), names: fontBytes.map(([n]) => n.replace(/-[A-Za-z0-9_-]{6,}\.woff2?$/, "")).join(" ") });
      if (SHOTS && (flow === "home" || flow === "result")) {
        mkdirSync(SHOTS, { recursive: true });
        await page.screenshot({ path: join(SHOTS, `${LABEL}_${flow === "home" ? "home" : "jio-result"}_${w}.png`), fullPage: w < 600 });
      }
      await ctx.close();
    }
  }
} finally {
  await browser.close();
  await new Promise((res) => server.httpServer.close(res));
}
console.log("\nfont files downloaded per flow (every request was to 127.0.0.1 only):");
for (const r of rows) console.log(`  ${String(r.w).padStart(4)}px ${r.flow.padEnd(7)} ${String(r.files).padStart(2)} files ${r.kb.padStart(6)} KB   ${r.loaded}`);
for (const p of problems) console.log("FAIL " + p);
console.log(problems.length ? `\n${problems.length} problem(s)` : "\nno font CDN and no third-party request: ok");
console.log("ROWS " + JSON.stringify(rows.map(({ w, flow, files, kb }) => ({ w, flow, files, kb }))));
process.exit(problems.length ? 1 : 0);
