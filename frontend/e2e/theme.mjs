// Light / dark theme checks on a BUILT site (2026-10-18).
//
//   cd frontend && npm run build && node e2e/theme.mjs
//
// The INSTALLED Google Chrome (playwright-core) loads dist/ from Vite's preview server on 127.0.0.1; no backend, no network.
//   T1 first visit follows the system setting: prefers-color-scheme light -> light, dark -> dark, no preference -> dark
//   T2 the sun / moon button switches the theme (attribute, page background, button label) and the choice survives a reload, also against the
//      system setting
//   T3 no flash: with the app's JS and CSS blocked, <html> already has the right data-theme and background colour (the inline script and
//      style in index.html run before anything else is painted)
//   T4 localStorage blocked (its getter throws): the page loads in the system theme, the button still switches, nothing throws, a reload
//      follows the system again
//   T5 reduced motion: switching adds no cross-fade class; with motion it does, briefly
//   T6 the globe follows the theme: its canvas pixels change when the theme does
// Exit code 1 on any failure.
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { preview } from "vite";

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = 4178, URL = `http://127.0.0.1:${PORT}/`;
const BG = { dark: "rgb(4, 6, 10)", light: "rgb(242, 243, 245)" };
const results = [];
const check = (name, ok, detail = "") => { results.push([name, ok, detail]); };

// the reduced-motion rule in styles.css makes every change a 0.01 ms transition: let frames pass before reading computed colours (two real
// animation frames, not a fixed 50 ms: a frame can take longer than that in headless Chrome, and T2 / T4 then read the old background)
const state = async (page) => { await page.waitForTimeout(50); await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
  return page.evaluate(() => ({
  theme: document.documentElement.dataset.theme,
  bg: getComputedStyle(document.documentElement).backgroundColor,
  label: document.querySelector(".themebtn")?.getAttribute("aria-label") ?? null,
  stored: (() => { try { return localStorage.getItem("scam-shield-theme"); } catch { return "blocked"; } })(),
})); };

async function context(browser, opts = {}) {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, reducedMotion: "reduce", ...opts });
  await ctx.route((u) => !u.href.startsWith(URL), (r) => { check(`no request outside the page (${r.request().url()})`, false); r.abort(); });
  return ctx;
}

const server = await preview({ root: join(HERE, ".."), preview: { host: "127.0.0.1", port: PORT, strictPort: true }, logLevel: "silent" });
const browser = await chromium.launch({ channel: "chrome", headless: true });
try {
  // T1
  for (const [scheme, want] of [["light", "light"], ["dark", "dark"], ["no-preference", "dark"]]) {
    const ctx = await context(browser, { colorScheme: scheme });
    const page = await ctx.newPage();
    const errors = []; page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(URL); await page.waitForSelector(".themebtn");
    const s = await state(page);
    check(`T1 system ${scheme} -> ${want}`, s.theme === want && s.bg === BG[want] && s.stored === null && !errors.length, JSON.stringify(s));
    await ctx.close();
  }

  // T2
  for (const scheme of ["dark", "light"]) {
    const other = scheme === "dark" ? "light" : "dark";
    const ctx = await context(browser, { colorScheme: scheme });
    const page = await ctx.newPage();
    await page.goto(URL); await page.waitForSelector(".themebtn");
    check(`T2 (${scheme} system) button names the other theme`, (await state(page)).label === `Switch to the ${other} theme`);
    await page.click(".themebtn");
    let s = await state(page);
    check(`T2 (${scheme} system) click -> ${other}`, s.theme === other && s.bg === BG[other] && s.stored === other && s.label === `Switch to the ${scheme} theme`, JSON.stringify(s));
    await page.reload(); await page.waitForSelector(".themebtn");
    s = await state(page);
    check(`T2 (${scheme} system) reload keeps ${other}`, s.theme === other && s.bg === BG[other], JSON.stringify(s));
    await page.click(".themebtn");
    s = await state(page);
    check(`T2 (${scheme} system) click again -> ${scheme}, stored`, s.theme === scheme && s.stored === scheme, JSON.stringify(s));
    await ctx.close();
  }

  // T3: block the app's script and stylesheet; only index.html runs
  for (const [scheme, stored, want] of [["dark", null, "dark"], ["light", null, "light"], ["dark", "light", "light"], ["light", "dark", "dark"]]) {
    const ctx = await context(browser, { colorScheme: scheme });
    if (stored) await ctx.addInitScript((t) => { try { localStorage.setItem("scam-shield-theme", t); } catch {} }, stored);
    const page = await ctx.newPage();
    await page.route(/\/assets\/.*\.(js|css)$/, (r) => r.abort());
    await page.goto(URL, { waitUntil: "domcontentloaded" });
    const s = await page.evaluate(() => ({ theme: document.documentElement.dataset.theme, bg: getComputedStyle(document.documentElement).backgroundColor, app: !!document.querySelector(".themebtn") }));
    check(`T3 before the app loads (system ${scheme}, stored ${stored ?? "none"}) -> ${want}`, s.theme === want && s.bg === BG[want] && !s.app, JSON.stringify(s));
    await ctx.close();
  }

  // T4: storage blocked
  for (const scheme of ["dark", "light"]) {
    const other = scheme === "dark" ? "light" : "dark";
    const ctx = await context(browser, { colorScheme: scheme });
    await ctx.addInitScript(() => { Object.defineProperty(window, "localStorage", { configurable: true, get() { throw new DOMException("blocked", "SecurityError"); } }); });
    const page = await ctx.newPage();
    const errors = []; page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(URL); await page.waitForSelector(".themebtn");
    let s = await state(page);
    check(`T4 storage blocked, system ${scheme}: loads ${scheme}`, s.theme === scheme && s.stored === "blocked", JSON.stringify(s));
    await page.click(".themebtn");
    s = await state(page);
    check(`T4 storage blocked: the button still switches to ${other}`, s.theme === other && s.bg === BG[other], JSON.stringify(s));
    await page.reload(); await page.waitForSelector(".themebtn");
    s = await state(page);
    check(`T4 storage blocked: a reload follows the system (${scheme}) again`, s.theme === scheme, JSON.stringify(s));
    check(`T4 storage blocked: no page error`, !errors.length, errors.join("; "));
    await ctx.close();
  }

  // T5: the cross-fade class
  for (const motion of ["reduce", "no-preference"]) {
    const ctx = await context(browser, { colorScheme: "dark", reducedMotion: motion });
    const page = await ctx.newPage();
    await page.goto(URL); await page.waitForSelector(".themebtn");
    const had = await page.evaluate(() => { document.querySelector(".themebtn").click(); return document.documentElement.classList.contains("theming"); });
    await page.waitForTimeout(500);
    const after = await page.evaluate(() => document.documentElement.classList.contains("theming"));
    check(`T5 ${motion === "reduce" ? "reduced motion: no cross-fade" : "motion: a cross-fade, then removed"}`, (motion === "reduce" ? !had : had) && !after, `had ${had}, after ${after}`);
    await ctx.close();
  }

  // T6: the globe repaints
  {
    const ctx = await context(browser, { colorScheme: "dark", viewport: { width: 1280, height: 800 } });
    const page = await ctx.newPage();
    await page.goto(URL); await page.waitForSelector(".stage canvas"); await page.waitForTimeout(500);
    const shot = async () => (await page.locator(".stage").screenshot()).toString("base64");
    const a = await shot();
    await page.click(".themebtn"); await page.waitForTimeout(500);
    const b = await shot();
    check("T6 the globe repaints in the other theme", a !== b);
    await ctx.close();
  }
} finally {
  await browser.close();
  await new Promise((res) => server.httpServer.close(res));
}
let failed = 0;
for (const [name, ok, detail] of results) { console.log(`${ok ? "ok  " : "FAIL"} ${name}${ok ? "" : `  ${detail}`}`); failed += ok ? 0 : 1; }
console.log(`\n${results.length - failed}/${results.length} theme checks pass`);
process.exit(failed ? 1 : 0);
