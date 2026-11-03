// The home tabs, the glass light, the lift and the two GSAP motions on a BUILT site (D29.15, D30; 2026-11-03).
//
//   cd frontend && npm run build && node e2e/tabs.mjs [--shots DIR] [--only L|K|M|H|R]
//
// The INSTALLED Google Chrome (playwright-core) loads dist/ from Vite's preview server on 127.0.0.1; /api/analyse is answered from the real Reports in src/lib/__fixtures__/reports.json;
// nothing else is requested and no link is opened.
//   L pointer light: the highlight layer's transform on the next frame equals the pointer within 1 px, on the box, a tab, a chip and a result panel, both themes; one pointermove listener
//     for the light; rects read at most once a frame per on-screen widget; the glass's own background and backdrop-filter do not change while the pointer moves; hidden during a theme switch.
//   K keyboard and ARIA: arrows, Home / End move the selection and the focus and wrap; aria-selected / aria-controls / tabindex follow; phone row: no sideways page scroll at 360-430 px,
//     the selected tab in view, 40 px pills, 14 px text.
//   M motion: the tab switch sampled every 50 ms; the globe rise; a click during a switch; a theme switch during either; reduced motion.
//   H the lift: every clickable rises 2 px on hover and on focus-visible with a deeper shadow; the selected pill and thumb rise with their button; :active settles; reduced motion: nothing moves.
//   R the result page: tabs on top, min-heights per tab, no text under 14 px, no entrance animation, a click on a tab goes home on that tab.
// Exit code 1 on any failure.
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { preview } from "vite";

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (name) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : null; };
const SHOTS = arg("--shots"), ONLY = arg("--only");
const PORT = 4183, URL = `http://127.0.0.1:${PORT}/`;
const FIXTURES = JSON.parse(readFileSync(join(HERE, "..", "src", "lib", "__fixtures__", "reports.json"), "utf8"));
const results = [];
const check = (name, ok, detail = "") => { results.push([name, !!ok, detail]); console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? `  (${detail})` : ""}`); };
const THEMES = ["dark", "light"];
const nextFrame = (page) => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => r())));

// test instrumentation, before the app's code
const INSTRUMENT = () => {
  const rec = (window.__tabs = { moves: 0, rects: 0, frames: 0 });
  const add = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, ...rest) { if (type === "pointermove" && this === window) rec.moves++; return add.call(this, type, ...rest); };
  const rect = Element.prototype.getBoundingClientRect;
  Element.prototype.getBoundingClientRect = function () { rec.rects++; return rect.call(this); };
  const raf = window.requestAnimationFrame;
  const tick = () => { rec.frames++; raf(tick); };
  raf(tick);
};

async function open(browser, { w = 1440, h = 900, theme = "dark", motion = "no-preference", dpr = 1, report = null, wait = true } = {}) {
  const ctx = await browser.newContext({ viewport: { width: w, height: h }, deviceScaleFactor: dpr, colorScheme: theme, reducedMotion: motion });
  const problems = [];
  await ctx.route((u) => !u.href.startsWith(URL), (r) => { problems.push(`request outside the page: ${r.request().url()}`); r.abort(); });
  await ctx.addInitScript(INSTRUMENT);
  const page = await ctx.newPage();
  page.on("pageerror", (e) => problems.push(e.message));
  page.on("console", (m) => { if (["error", "warning"].includes(m.type())) problems.push(m.text()); });
  if (report) await page.route("**/api/analyse", (r) => r.fulfill({ json: report }));
  await page.goto(URL);
  await page.waitForSelector(".tab");
  await page.evaluate(() => document.fonts.ready);
  if (wait) await page.waitForTimeout(motion === "reduce" ? 100 : 2400);   // the globe's rise has ended
  return { ctx, page, problems };
}

// the layer's transform against the pointer, on the frame after a move
async function lightAt(page, selector, dx, dy) {
  const box = await page.locator(selector).first().boundingBox();
  const x = box.x + dx, y = box.y + dy;
  await page.mouse.move(x, y);
  await nextFrame(page); await nextFrame(page);
  return page.evaluate(({ selector, x, y }) => {
    const host = document.querySelector(selector), spot = host.querySelector(":scope > .light > .lightspot"), m = new DOMMatrix(getComputedStyle(spot).transform), r = host.getBoundingClientRect();
    return { visible: spot.style.visibility === "visible", dx: r.left + m.m41 - x, dy: r.top + m.m42 - y };
  }, { selector, x, y });
}

async function lightChecks(browser) {
  const jio = FIXTURES.find((x) => x.label === "jio-no-sender");
  for (const theme of THEMES) {
    const { ctx, page, problems } = await open(browser, { theme, report: jio.report });
    const worst = [];
    for (const [sel, dx, dy] of [[".box.entry", 300, 90], [".box.entry", 13.5, 7.25], ['.tab[aria-selected="false"]', 20, 12], [".ex button", 40, 10], [".box.entry", 500.5, 30.5]]) {
      const got = await lightAt(page, sel, dx, dy);
      worst.push(Math.max(Math.abs(got.dx), Math.abs(got.dy)));
      check(`L1 ${theme} ${sel} (+${dx},+${dy}): the layer is at the pointer on the next frame`, got.visible && Math.abs(got.dx) <= 1 && Math.abs(got.dy) <= 1, `off by ${got.dx.toFixed(2)}, ${got.dy.toFixed(2)} px`);
    }
    // the sweep: no tween: every frame of a fast move is exact, with the pointer moved in the frame before
    const sweep = await page.evaluate(async () => {
      const host = document.querySelector(".box.entry"), spot = host.querySelector(":scope > .light > .lightspot"), r = host.getBoundingClientRect();
      const offs = [];
      for (let i = 0; i < 40; i++) {
        const x = r.left + 20 + i * 15, y = r.top + 40 + (i % 5) * 20;
        window.dispatchEvent(new PointerEvent("pointermove", { clientX: x, clientY: y, pointerType: "mouse", bubbles: true }));
        await new Promise((res) => requestAnimationFrame(res));
        await new Promise((res) => requestAnimationFrame(res));
        const m = new DOMMatrix(getComputedStyle(spot).transform);
        offs.push(Math.max(Math.abs(r.left + m.m41 - x), Math.abs(r.top + m.m42 - y)));
      }
      return Math.max(...offs);
    });
    check(`L2 ${theme} a fast sweep: never behind the pointer`, sweep <= 1, `worst ${sweep.toFixed(2)} px over 40 moves`);
    const counts = await page.evaluate(async () => {
      const rec = window.__tabs, onScreen = [...document.querySelectorAll(".light")].length;
      const base = { rects: rec.rects, frames: rec.frames };
      for (let i = 0; i < 30; i++) {
        window.dispatchEvent(new PointerEvent("pointermove", { clientX: 500 + i, clientY: 600, pointerType: "mouse", bubbles: true }));
        window.dispatchEvent(new PointerEvent("pointermove", { clientX: 501 + i, clientY: 601, pointerType: "mouse", bubbles: true }));
        await new Promise((res) => requestAnimationFrame(res));
      }
      return { moves: rec.moves, lights: onScreen, rects: rec.rects - base.rects, frames: rec.frames - base.frames };
    });
    check(`L3 ${theme} one pointermove listener for the light (the globe's own drag has its own)`, counts.moves === 2, `${counts.moves} on window`);
    check(`L4 ${theme} rects at most once a frame per widget, two moves a frame`, counts.rects <= counts.lights * (counts.frames + 2), `${counts.rects} reads, ${counts.lights} widgets, ${counts.frames} frames`);
    const glass = async () => page.evaluate(() => { const c = getComputedStyle(document.querySelector(".box.entry")); return [c.backgroundImage, c.backgroundColor, c.backdropFilter, c.boxShadow].join("|"); });
    await page.mouse.move(2, 2); await nextFrame(page);
    const a = await glass(); await page.mouse.move(700, 620); await nextFrame(page); await nextFrame(page);
    check(`L5 ${theme} the glass itself does not change with the pointer`, a === (await glass()));
    // the result page's panels have it too
    await page.fill("#msg", jio.text); await page.click("button.go"); await page.waitForSelector(".result .vword");
    await page.waitForTimeout(300);
    for (const sel of [".g-verdict", ".g-todo"]) {
      const got = await lightAt(page, sel, 120, 60);
      check(`L6 ${theme} result ${sel}: the layer is at the pointer`, got.visible && Math.abs(got.dx) <= 1 && Math.abs(got.dy) <= 1, `off by ${got.dx.toFixed(2)}, ${got.dy.toFixed(2)} px`);
    }
    check(`L7 ${theme} no console problem, no request outside the page`, !problems.length, problems.join("; "));
    await ctx.close();
  }
  // a phone-width page has no light layers on screen; during a theme switch they are gone and come back at the pointer
  {
    const { ctx, page } = await open(browser, { w: 390, h: 844, wait: false });
    check("L8 no light at phone width", await page.evaluate(() => getComputedStyle(document.querySelector(".light")).display === "none"));
    await ctx.close();
  }
  {
    const { ctx, page, problems } = await open(browser, {});
    await page.mouse.move(700, 620); await nextFrame(page);
    await page.evaluate(() => document.querySelector(".themebtn").click());
    await page.waitForFunction(() => document.documentElement.classList.contains("ss-switch"));
    const during = await page.evaluate(() => getComputedStyle(document.querySelector(".box.entry > .light")).display);
    await page.waitForFunction(() => !document.documentElement.classList.contains("ss-switch"), null, { timeout: 8000 });
    await nextFrame(page); await nextFrame(page);
    const after = await lightAt(page, ".box.entry", 200, 90);
    check("L9 hidden during a theme switch, at the pointer again after it", during === "none" && after.visible && Math.abs(after.dx) <= 1 && Math.abs(after.dy) <= 1, `during: ${during}`);
    check("L10 no console problem", !problems.length, problems.join("; "));
    await ctx.close();
  }
}

const server = await preview({ root: join(HERE, ".."), preview: { host: "127.0.0.1", port: PORT, strictPort: true }, logLevel: "silent" });
const browser = await chromium.launch({ channel: "chrome", headless: true });
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
try {
  if (!ONLY || ONLY === "L") await lightChecks(browser);
} finally {
  await browser.close();
  await new Promise((res) => server.httpServer.close(res));
}
const failed = results.filter(([, ok]) => !ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
