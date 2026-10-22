// Phone screenshots (390x844) of the full result page for Likely scam (demo-d01) with the Get help panel open, light and dark.
//   cd frontend && npm run build && node e2e/phoneshots.mjs OUT_DIR PREFIX      e.g. before / after
// Serves dist/ with Vite preview, answers /api/analyse from src/lib/__fixtures__/reports.json, makes no other request, opens no link.
import { readFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { preview } from "vite";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = JSON.parse(readFileSync(join(HERE, "..", "src", "lib", "__fixtures__", "reports.json"), "utf8"));
const [OUT, PREFIX = "shot"] = process.argv.slice(2);
if (!OUT) { console.error("usage: node e2e/phoneshots.mjs OUT_DIR PREFIX"); process.exit(2); }
const PORT = 4175;
mkdirSync(OUT, { recursive: true });
const server = await preview({ root: join(HERE, ".."), preview: { host: "127.0.0.1", port: PORT, strictPort: true }, logLevel: "silent" });
const browser = await chromium.launch({ channel: "chrome", headless: true });
try {
  for (const theme of ["light", "dark"]) {
    const f = FIXTURES.find((x) => x.label === "demo-d01");
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, reducedMotion: "reduce", colorScheme: theme });
    const page = await ctx.newPage();
    await page.route("**/api/analyse", (route) => route.fulfill({ json: f.report }));
    await page.route((url) => !url.href.startsWith(`http://127.0.0.1:${PORT}/`), (route) => route.abort());
    await page.goto(`http://127.0.0.1:${PORT}/`);
    await page.fill("#msg", f.text);
    await page.click("button.go");
    await page.waitForSelector(".result .box");
    await page.click("button.helpbtn, button.askbtn");
    await page.waitForTimeout(1200);   // the result boxes fade in (rise animation with a delay)
    const file = join(OUT, `${PREFIX}_likely_${theme}_390x844.png`);
    await page.screenshot({ path: file, fullPage: true });
    const h = await page.evaluate(() => document.documentElement.scrollHeight);
    console.log(file, "page height", h);
    await ctx.close();
  }
} finally { await browser.close(); await server.close(); }
