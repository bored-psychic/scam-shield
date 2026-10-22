// axe-core colour-contrast audit (WCAG 2 AA) of the home and Jio result screens, in BOTH themes (2026-10-18).
//
//   cd frontend && npm run build && node e2e/axe.mjs
//
// axe-core (devDependency, injected from node_modules: no network) runs its color-contrast rule in the INSTALLED Google Chrome on the built site.
// /api/analyse is answered from src/lib/__fixtures__/reports.json; every "Website details" sheet is opened. A violation fails the run.
// axe reports text it cannot judge (text over the WebGL globe, a gradient or a translucent panel) as "incomplete"; those are listed, not failed:
// e2e/contrast.mjs measures them on the rendered pixels instead. Exit code 1 on any violation.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { preview } from "vite";

const HERE = dirname(fileURLToPath(import.meta.url));
const AXE = createRequire(import.meta.url).resolve("axe-core/axe.min.js");
const jio = JSON.parse(readFileSync(join(HERE, "..", "src", "lib", "__fixtures__", "reports.json"), "utf8")).find((x) => x.label === "jio-no-sender");
const PORT = 4179;

const server = await preview({ root: join(HERE, ".."), preview: { host: "127.0.0.1", port: PORT, strictPort: true }, logLevel: "silent" });
const browser = await chromium.launch({ channel: "chrome", headless: true });
let violations = 0, runs = 0;
try {
  for (const theme of ["dark", "light"])
    for (const [w, h] of [[390, 844], [1440, 1150]])
      for (const screen of ["home", "result"]) {
        const ctx = await browser.newContext({ viewport: { width: w, height: h }, reducedMotion: "reduce", colorScheme: theme });
        const page = await ctx.newPage();
        await page.route("**/api/analyse", (r) => r.fulfill({ json: jio.report }));
        await page.goto(`http://127.0.0.1:${PORT}/`);
        if (screen === "result") {
          await page.fill("#msg", jio.text); await page.click("button.go"); await page.waitForSelector(".result .vword");
          await page.evaluate(() => document.querySelectorAll("details.facts").forEach((d) => { d.open = true; }));
          if (await page.locator("button.askbtn").count()) { await page.click("button.askbtn"); await page.check(".askcheck input"); await page.click(".asklang label:has-text(\"ಕನ್ನಡ\")"); }
        }
        await page.evaluate(() => document.fonts.ready); await page.waitForTimeout(600);
        const got = await page.evaluate(() => document.documentElement.dataset.theme);
        await page.addScriptTag({ path: AXE });
        const r = await page.evaluate(() => window.axe.run(document, { runOnly: { type: "rule", values: ["color-contrast"] } }));
        const v = r.violations.flatMap((x) => x.nodes), inc = r.incomplete.flatMap((x) => x.nodes), pass = r.passes.flatMap((x) => x.nodes);
        runs++; violations += v.length + (got === theme ? 0 : 1);
        console.log(`${v.length || got !== theme ? "FAIL" : "ok  "} ${theme.padEnd(5)} ${String(w).padStart(4)}px ${screen.padEnd(6)} ${pass.length} pass, ${v.length} violations, ${inc.length} incomplete${got === theme ? "" : ` (page theme ${got})`}`);
        for (const n of v) console.log(`      VIOLATION ${n.target.join(" ")}: ${n.any.map((a) => a.message).join("; ").slice(0, 160)}`);
        for (const n of inc) console.log(`      incomplete ${n.target.join(" ")}: ${(n.any[0]?.data?.messageKey ?? n.any[0]?.message ?? "").toString().slice(0, 80)}`);
        await ctx.close();
      }
} finally {
  await browser.close();
  await new Promise((res) => server.httpServer.close(res));
}
console.log(`\n${runs} audits, ${violations} colour-contrast violation(s)`);
process.exit(violations ? 1 : 0);
