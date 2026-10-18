// WCAG AA contrast of every visible text element on the home and Jio result screens (D24 typography), in BOTH themes (2026-10-18; the theme
// is picked through prefers-color-scheme, which the first visit follows). axe-core cannot judge text over the glass and the globe (e2e/axe.mjs
// lists it as incomplete); this measures it on the rendered pixels.
//
//   cd frontend && npm run build && node e2e/contrast.mjs
//
// The panels are glass over a moving globe, so a token-vs-token calculation would be a guess. Instead: the page is screenshot with all text made
// transparent, and for each element with text of its own the pixels behind its box are averaged (the globe's dots are tiny and the text has a dark halo, so the mean colour is the fair backdrop; the
// lightest-decile worst case is reported too as `worst`, for information).
// Contrast = (L1 + .05) / (L2 + .05) with the element's computed colour (alpha blended on that background). Needs 4.5:1, or 3:1 for large text
// (>= 24 px, or >= 18.66 px and bold). Disabled controls and placeholders are exempt (WCAG 1.4.3). /api/analyse is answered from the fixtures; no backend.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { preview } from "vite";

const HERE = dirname(fileURLToPath(import.meta.url));
const jio = JSON.parse(readFileSync(join(HERE, "..", "src", "lib", "__fixtures__", "reports.json"), "utf8")).find((x) => x.label === "jio-no-sender");
const PORT = 4177;

async function audit(page) {
  // 1. what is on screen, with the colours as the page really draws them (before anything is hidden)
  const items = await page.evaluate(() => {
    const out = [], seen = new Set(), walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n; (n = walker.nextNode()); ) {
      const el = n.parentElement, t = n.textContent.trim();
      if (!t || seen.has(el) || ["SCRIPT", "STYLE", "CANVAS"].includes(el.tagName) || el.closest("[hidden], .sr-only") || el.closest("button:disabled, .tip")) continue;
      const cs = getComputedStyle(el); if (cs.visibility === "hidden" || cs.display === "none" || +cs.opacity === 0) continue;
      const r = document.createRange(); r.selectNodeContents(n); const b = r.getBoundingClientRect();
      if (b.width < 2 || b.height < 2 || b.bottom < 0 || b.top > innerHeight || b.right < 0 || b.left > innerWidth) continue;
      seen.add(el);
      out.push({ text: t.slice(0, 40), tag: el.tagName.toLowerCase() + (el.className ? "." + String(el.className).split(" ")[0] : ""), color: cs.color, px: parseFloat(cs.fontSize), weight: +cs.fontWeight,
                 box: [b.left, b.top, b.right, b.bottom], vw: innerWidth, vh: innerHeight });
    }
    return out;
  });
  // 2. the same page with all text transparent: only the background is left to sample
  await page.addStyleTag({ content: "*, *::before, *::after { color: transparent !important; text-shadow: none !important; -webkit-text-fill-color: transparent !important; } textarea::placeholder { color: transparent !important; } svg { visibility: hidden !important; }" });
  await page.waitForTimeout(400);
  const b64 = (await page.screenshot({ fullPage: false })).toString("base64");
  return page.evaluate(async ({ b64, items }) => {
    const img = new Image(); img.src = "data:image/png;base64," + b64; await img.decode();
    const cv = document.createElement("canvas"); cv.width = img.width; cv.height = img.height;
    const cx = cv.getContext("2d", { willReadFrequently: true }); cx.drawImage(img, 0, 0);
    const lum = (r, g, b) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
    return items.flatMap((it) => {
      const [l, t, r, b] = it.box, x0 = Math.max(0, Math.floor(l)), y0 = Math.max(0, Math.floor(t)), w = Math.min(it.vw, Math.ceil(r)) - x0, h = Math.min(it.vh, Math.ceil(b)) - y0;
      if (w < 1 || h < 1) return [];
      const d = cx.getImageData(x0, y0, w, h).data, ls = [], rgb = [];
      for (let i = 0; i < d.length; i += 4) { ls.push(lum(d[i], d[i + 1], d[i + 2])); rgb.push([d[i], d[i + 1], d[i + 2]]); }
      const bg = [0, 1, 2].map((k) => rgb.reduce((n, p) => n + p[k], 0) / rgb.length);
      const m = it.color.match(/[\d.]+/g).map(Number), a = m[3] ?? 1, fg = [0, 1, 2].map((i) => m[i] * a + bg[i] * (1 - a));
      const L1 = lum(...fg), L2 = lum(...bg), ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
      const large = it.px >= 24 || (it.px >= 18.66 && it.weight >= 700);
      return [{ text: it.text, tag: it.tag, ratio: +ratio.toFixed(2), need: large ? 3 : 4.5, px: it.px }];
    });
  }, { b64, items });
}

const server = await preview({ root: join(HERE, ".."), preview: { host: "127.0.0.1", port: PORT, strictPort: true }, logLevel: "silent" });
const browser = await chromium.launch({ channel: "chrome", headless: true });
let fails = 0, total = 0;
try {
  for (const theme of ["dark", "light"])
  for (const [w, h] of [[390, 844], [1440, 1150]])
    for (const screen of ["home", "result"]) {
      const ctx = await browser.newContext({ viewport: { width: w, height: h }, reducedMotion: "reduce", colorScheme: theme });
      const page = await ctx.newPage();
      await page.route("**/api/analyse", (r) => r.fulfill({ json: jio.report }));
      await page.goto(`http://127.0.0.1:${PORT}/`);
      if (screen === "result") { await page.fill("#msg", jio.text); await page.click("button.go"); await page.waitForSelector(".result .vword"); await page.evaluate(() => document.querySelectorAll("details.facts").forEach((d) => { d.open = true; })); }
      await page.evaluate(() => document.fonts.ready); await page.waitForTimeout(800);
      const rows = await audit(page);
      const bad = rows.filter((r) => r.ratio < r.need);
      total += rows.length; fails += bad.length;
      console.log(`${bad.length ? "FAIL" : "ok  "} ${theme.padEnd(5)} ${w}px ${screen}: ${rows.length} text elements, lowest ${Math.min(...rows.map((r) => r.ratio))}:1`);
      if (process.env.CONTRAST_ALL) for (const r of [...rows].sort((a, b) => a.ratio / a.need - b.ratio / b.need).slice(0, 4)) console.log(`      lowest: ${r.ratio}:1 (needs ${r.need}) <${r.tag}> ${r.px}px "${r.text}"`);
      for (const r of bad) console.log(`      ${r.ratio}:1 (needs ${r.need}) <${r.tag}> ${r.px}px "${r.text}"`);
      await ctx.close();
    }
} finally { await browser.close(); await new Promise((res) => server.httpServer.close(res)); }
console.log(`\n${total - fails}/${total} text elements meet WCAG AA`);
process.exit(fails ? 1 : 0);
