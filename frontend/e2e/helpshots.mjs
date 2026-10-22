// Screenshots of the open "Get help" panel: Likely scam (demo-d01) and Suspicious (otp-share-kyc), light and dark, phone and desktop, English.
//   cd frontend && npm run build && node e2e/helpshots.mjs [OUT_DIR]      (default ~/Desktop/getHelp)
// Serves dist/ with Vite preview, answers /api/analyse from src/lib/__fixtures__/reports.json, makes no other request, opens no link.
import { readFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { preview } from "vite";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = JSON.parse(readFileSync(join(HERE, "..", "src", "lib", "__fixtures__", "reports.json"), "utf8"));
const OUT = process.argv[2] ?? join(homedir(), "Desktop", "getHelp");
const PORT = 4174;
const CASES = [["demo-d01", "likely"], ["otp-share-kyc", "suspicious"]];
const VIEWPORTS = [["phone", 390, 844], ["desktop", 1280, 800]];
mkdirSync(OUT, { recursive: true });
const server = await preview({ root: join(HERE, ".."), preview: { host: "127.0.0.1", port: PORT, strictPort: true }, logLevel: "silent" });
const browser = await chromium.launch({ channel: "chrome", headless: true });
try {
  for (const [label, verdict] of CASES)
    for (const theme of ["light", "dark"])
      for (const [vname, w, h] of VIEWPORTS) {
        const f = FIXTURES.find((x) => x.label === label);
        const ctx = await browser.newContext({ viewport: { width: w, height: h }, reducedMotion: "reduce", colorScheme: theme });
        const page = await ctx.newPage();
        await page.route("**/api/analyse", (route) => route.fulfill({ json: f.report }));
        await page.route((url) => !url.href.startsWith(`http://127.0.0.1:${PORT}/`), (route) => route.abort());
        await page.goto(`http://127.0.0.1:${PORT}/`);
        await page.fill("#msg", f.text);
        await page.click("button.go");
        await page.waitForSelector(".result .box");
        await page.click("button.askbtn");
        await page.waitForSelector(".askpanel");
        await page.waitForTimeout(1200);   // the result boxes fade in (rise animation with a delay)
        await page.locator(".askpanel").scrollIntoViewIfNeeded();
        const file = join(OUT, `getHelp_${verdict}_${theme}_${vname}.png`);
        await page.screenshot({ path: file, fullPage: true });
        console.log(file);
        await ctx.close();
      }
} finally { await browser.close(); await server.close(); }
