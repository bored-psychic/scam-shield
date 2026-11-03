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
  rec.stage = [];   // the globe's stage, every frame of the first 3 s
  const t0 = performance.now();
  const tick = () => {
    rec.frames++;
    const st = document.querySelector(".stage"), t = performance.now() - t0;
    if (st && t < 3200) { const cs = getComputedStyle(st), m = new DOMMatrix(cs.transform); rec.stage.push({ t, inline: st.getAttribute("style") ?? "", y: m.m42 / innerHeight * 100, op: +cs.opacity, tr: cs.transitionDuration }); }
    raf(tick);
  };
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

// ---- M the two motions ----
const HEAD = { message: "Is this message a scam?", link: "Is this link safe?", payment: "Is this payment genuine?", app: "Is this app real?" };
const SUB = { message: "Paste it or add a screenshot.", link: "Checked without opening it.", payment: "Check a UPI ID or a screenshot.", app: "Check it before you install." };
const clean = (x) => x.replace(/\s+/g, " ").trim();
// in the page, every 50 ms: the headlines, each word's opacity and how much of it shows through its mask, the sub-line, the pill and the box; and each word's opacity when React removes it
const startSampling = (page) => page.evaluate(() => {
  const rec = (window.__sw = { samples: [], removed: [], t0: performance.now() });
  const h = document.querySelector(".hero h1");
  rec.mo = new MutationObserver((list) => {
    for (const m of list) for (const n of m.removedNodes) if (n.nodeType === 1)
      for (const w of n.matches(".hwi") ? [n] : n.querySelectorAll(".hwi")) rec.removed.push({ t: performance.now() - rec.t0, word: w.textContent, op: w.style.opacity });
  });
  rec.mo.observe(h, { childList: true, subtree: true });
  rec.timer = setInterval(() => {
    const heads = [...document.querySelectorAll(".hero h1")], el = heads[0];
    const words = [...el.querySelectorAll(".hwi")].map((w) => {
      const r = w.getBoundingClientRect(), box = w.parentElement.getBoundingClientRect();
      const seen = el.classList.contains("masking") ? Math.max(0, Math.min(r.bottom, box.bottom) - Math.max(r.top, box.top)) / Math.max(1, r.height) : 1;
      return { op: +getComputedStyle(w).opacity, seen };
    });
    const sub = document.querySelector(".hero .sub"), thumb = document.querySelector(".tabthumb"), box = document.querySelector('[role="tabpanel"]:not([hidden]) .box.entry');
    rec.samples.push({ t: performance.now() - rec.t0, heads: heads.length, text: el.textContent.replace(/\s+/g, " ").trim(),
      showing: words.filter((w) => w.op > .05 && w.seen > .02).length, subOp: +getComputedStyle(sub).opacity, subText: sub.textContent,
      thumb: thumb.getBoundingClientRect().left, boxH: box?.getBoundingClientRect().height ?? 0 });
  }, 50);
});
const stopSampling = (page) => page.evaluate(() => { const r = window.__sw; clearInterval(r.timer); r.mo.disconnect(); return { samples: r.samples, removed: r.removed }; });
const leftovers = (page) => page.evaluate(() => {
  const out = [], h = document.querySelector(".hero h1");
  if (h.classList.contains("masking")) out.push("still masking");
  for (const w of h.querySelectorAll(".hwi")) if (w.getAttribute("style")) out.push(`word style ${w.getAttribute("style")}`);
  const sub = document.querySelector(".hero .sub"); if (sub.getAttribute("style")) out.push(`sub style ${sub.getAttribute("style")}`);
  const box = document.querySelector('[role="tabpanel"]:not([hidden]) .box.entry'); if (box.style.height || box.style.overflow) out.push(`box style ${box.getAttribute("style")}`);
  const on = document.querySelector('.tab[aria-selected="true"]').getBoundingClientRect(), th = document.querySelector(".tabthumb").getBoundingClientRect();
  if (Math.abs(on.left - th.left) > .6 || Math.abs(on.width - th.width) > .6) out.push(`pill at ${th.left.toFixed(1)}+${th.width.toFixed(1)}, tab at ${on.left.toFixed(1)}+${on.width.toFixed(1)}`);
  return out;
});
const finalIs = (page, k) => page.evaluate(() => ({ text: document.querySelector(".hero h1").textContent.replace(/\s+/g, " ").trim(), sub: document.querySelector(".hero .sub").textContent, sel: document.querySelector('.tab[aria-selected="true"]').id, count: document.querySelectorAll(".hero h1").length }))
  .then((g) => g.text === HEAD[k] && g.sub === SUB[k] && g.sel === `tab-${k}` && g.count === 1);
const lastChange = (samples, key) => { let t = 0; for (let i = 1; i < samples.length; i++) if (Math.abs(samples[i][key] - samples[i - 1][key]) > .3) t = samples[i].t; return t; };

async function motionChecks(browser) {
  for (const [theme, w, h] of [["dark", 1440, 900], ["light", 1440, 900], ["dark", 390, 844], ["light", 390, 844]]) {
    const { ctx, page, problems } = await open(browser, { theme, w, h });
    const tag = `${theme} ${w}`;
    for (const [from, to] of [["message", "link"], ["link", "payment"], ["payment", "app"], ["app", "message"]]) {
      await startSampling(page);
      await page.evaluate((k) => document.getElementById(`tab-${k}`).click(), to);
      await page.waitForTimeout(1900);
      const { samples, removed } = await stopSampling(page);
      const both = samples.filter((x) => x.heads !== 1 || ![HEAD[from], HEAD[to]].includes(x.text));
      const firstNew = samples.findIndex((x) => x.text === HEAD[to]), oldAfter = samples.slice(firstNew).some((x) => x.text === HEAD[from]);
      const lastOldShowing = samples.filter((x) => x.text === HEAD[from] && x.showing > 0).at(-1)?.t ?? 0, firstNewShowing = samples.find((x) => x.text === HEAD[to] && x.showing > 0)?.t ?? -1;
      const removedOp = removed.length ? Math.max(...removed.map((x) => +x.op)) : -1, swapAt = removed.length ? removed[0].t : -1;
      check(`M1 ${tag} ${from} -> ${to}: ${samples.length} samples, one heading at a time, old headline gone before the new one shows`,
        !both.length && firstNew > 0 && !oldAfter && lastOldShowing < firstNewShowing, `old last seen at ${lastOldShowing.toFixed(0)} ms, new first seen at ${firstNewShowing.toFixed(0)} ms`);
      // about 312 ms, measured headed @2x and headless; a fresh browser's first click can take a cold-start frame on top (one 217 ms frame in 6 runs), hence the upper bound
      check(`M2 ${tag} ${from} -> ${to}: the old words' opacity was 0 when they were removed, after the .3 s`, removedOp === 0 && swapAt >= 270 && swapAt < 700, `${removed.length} words, max opacity ${removedOp}, at ${swapAt.toFixed(0)} ms`);
      const noSubGap = samples.filter((x) => x.subText === SUB[to] && x.subOp > .05).at(0)?.t ?? -1;
      const headIn = samples.filter((x) => x.text === HEAD[to] && x.showing > 0).at(0)?.t ?? 0;
      check(`M3 ${tag} ${from} -> ${to}: the sub-line fades out with the old headline and comes back after the new one`,
        samples.some((x) => x.subOp <= .05) && noSubGap > headIn && !samples.some((x) => x.subText === SUB[from] && x.text === HEAD[to]), `new sub-line first seen at ${noSubGap.toFixed(0)} ms, headline at ${headIn.toFixed(0)} ms`);
      const pillEnd = lastChange(samples, "thumb"), boxEnd = lastChange(samples, "boxH");
      const pillMoved = samples[0].thumb !== samples.at(-1).thumb, boxMoved = Math.abs(samples[0].boxH - samples.at(-1).boxH) > 1;
      check(`M4 ${tag} ${from} -> ${to}: the pill moves over about .55 s, the box eases over about .45 s, while the headline changes`,
        pillMoved && pillEnd > 200 && pillEnd < 760 && (!boxMoved || (boxEnd > 150 && boxEnd < 650)), `pill's last move at ${pillEnd.toFixed(0)} ms, box's at ${boxEnd.toFixed(0)} ms${boxMoved ? "" : " (same height)"}`);
      check(`M5 ${tag} ${from} -> ${to}: ends right and clean`, (await finalIs(page, to)) && !(await leftovers(page)).length, (await leftovers(page)).join("; "));
    }
    // a click during a switch: at 150 ms (old leaving), and at 550 ms (new entering): cleanly to the newest tab
    for (const delay of [150, 550]) {
      await startSampling(page);
      await page.evaluate((k) => document.getElementById(`tab-${k}`).click(), "link");
      await page.waitForTimeout(delay);
      await page.evaluate((k) => document.getElementById(`tab-${k}`).click(), "payment");
      await page.waitForTimeout(120);
      await page.evaluate((k) => document.getElementById(`tab-${k}`).click(), "app");
      await page.waitForTimeout(1900);
      const { samples } = await stopSampling(page);
      const stray = samples.filter((x) => x.heads !== 1);
      const lastOther = samples.filter((x) => x.text !== HEAD.app && x.showing > 0).at(-1)?.t ?? 0, firstApp = samples.find((x) => x.text === HEAD.app && x.showing > 0)?.t ?? -1;
      check(`M6 ${tag} two more clicks ${delay} ms into a switch: the newest tab, clean, never two headlines`, !stray.length && lastOther < firstApp && (await finalIs(page, "app")) && !(await leftovers(page)).length, (await leftovers(page)).join("; "));
      await page.evaluate((k) => document.getElementById(`tab-${k}`).click(), "message");
      await page.waitForTimeout(1900);
    }
    // a theme switch starting during a tab switch: everything at its end at once, before the switch measures the page
    await page.evaluate((k) => document.getElementById(`tab-${k}`).click(), "payment");
    await page.waitForTimeout(150);
    const at = await page.evaluate(() => { document.querySelector(".themebtn").click(); return document.documentElement.classList.contains("ss-switch"); });
    const during = await leftovers(page);
    check(`M7 ${tag} a theme switch during a tab switch: the tab switch jumps to its end`, at && !during.length && (await finalIs(page, "payment")), during.join("; "));
    // a click on a tab during the theme switch: instant, nothing starts
    await page.evaluate((k) => document.getElementById(`tab-${k}`).click(), "app");
    await page.waitForTimeout(60);
    const started = await leftovers(page);
    check(`M8 ${tag} a tab chosen during a theme switch: nothing starts, it is simply there`, (await finalIs(page, "app")) && !started.length, started.join("; "));
    await page.waitForFunction(() => !document.documentElement.classList.contains("ss-switch"), null, { timeout: 8000 });
    await page.evaluate((k) => document.getElementById(`tab-${k}`).click(), "message");
    await page.waitForTimeout(1900);
    check(`M9 ${tag} no console problem, no request outside the page`, !problems.length, problems.join("; "));
    await ctx.close();
  }
  // the globe's rise
  for (const theme of THEMES) {
    const { ctx, page, problems } = await open(browser, { theme, wait: false });
    await page.waitForTimeout(3300);
    const st = await page.evaluate(() => window.__tabs.stage);
    const moving = st.filter((x) => x.inline.includes("transform") || x.inline.includes("opacity"));
    const first = moving[0], last = moving.at(-1), end = st.find((x, i) => i > 0 && st[i - 1].inline && !x.inline);
    const dur = last && first ? last.t - first.t : 0;
    const mono = moving.every((x, i) => !i || (x.y <= moving[i - 1].y + .01 && x.op >= moving[i - 1].op - .01));
    check(`M10 ${theme} the rise: from 45 % and opacity 0, down to rest over 2.2 s, expo.out`, first && first.y > 30 && first.y <= 45.01 && first.op < .35 && mono && dur > 1900 && dur < 2500, `first frame y ${first?.y.toFixed(1)} %, opacity ${first?.op.toFixed(2)}, ${moving.length} frames over ${dur.toFixed(0)} ms`);
    const quarter = moving.find((x) => x.t - first.t >= 220), want = 45 * 2 ** (-10 * (quarter.t - first.t) / 2200);
    check(`M11 ${theme} the rise follows expo.out (at ${(quarter.t - first.t).toFixed(0)} ms)`, Math.abs(quarter.y - want) < 6, `y ${quarter.y.toFixed(1)} %, expected about ${want.toFixed(1)} %`);
    check(`M12 ${theme} the stage's transition is off during it; every inline style goes after it`, moving.every((x) => x.tr === "0s") && !!end && !(await page.evaluate(() => document.querySelector(".stage").getAttribute("style"))), `after: "${await page.evaluate(() => document.querySelector(".stage").getAttribute("style"))}"`);
    check(`M13 ${theme} no console problem`, !problems.length, problems.join("; "));
    await ctx.close();
    // a theme switch during the rise jumps it to its end
    const b = await open(browser, { theme, wait: false });
    await b.page.waitForFunction(() => document.querySelector(".stage")?.getAttribute("style")?.includes("opacity"));
    await b.page.waitForTimeout(200);
    const mid = await b.page.evaluate(() => { const was = document.querySelector(".stage").getAttribute("style"); document.querySelector(".themebtn").click(); return { was, now: document.querySelector(".stage").getAttribute("style"), on: document.documentElement.classList.contains("ss-switch") }; });
    check(`M14 ${theme} a theme switch during the rise: the stage is at rest at once`, mid.was && !mid.now && mid.on, `was "${mid.was?.slice(0, 40)}", now "${mid.now}"`);
    await b.page.waitForFunction(() => !document.documentElement.classList.contains("ss-switch"), null, { timeout: 8000 });
    check(`M15 ${theme} no console problem after it`, !b.problems.length, b.problems.join("; "));
    await b.ctx.close();
    // reduced motion: no rise, no switch motion
    const r = await open(browser, { theme, motion: "reduce", wait: false });
    await r.page.waitForTimeout(500);
    const inlines = await r.page.evaluate(() => window.__tabs.stage.filter((x) => x.inline).length);
    check(`M16 ${theme} reduced motion: no rise`, inlines === 0, `${inlines} frames with an inline style`);
    await startSampling(r.page);
    const instant = await r.page.evaluate(() => new Promise((res) => {
      document.getElementById("tab-payment").click();
      requestAnimationFrame(() => res({ text: document.querySelector(".hero h1").textContent.replace(/\s+/g, " ").trim(), sub: document.querySelector(".hero .sub").textContent, masking: document.querySelector(".hero h1").classList.contains("masking") }));
    }));
    await r.page.waitForTimeout(400);
    const rec = await stopSampling(r.page);
    check(`M17 ${theme} reduced motion: the tab change is instant`, instant.text === HEAD.payment && instant.sub === SUB.payment && !instant.masking && rec.samples.every((x) => x.subOp === 1) && rec.samples.every((x) => x.text === HEAD.payment) && !(await leftovers(r.page)).length,
      `${rec.samples.length} samples, all the new headline at full opacity`);
    await r.ctx.close();
  }
}

// ---- K keyboard, ARIA, phone row ----
async function keyboardChecks(browser) {
  const { ctx, page, problems } = await open(browser, { motion: "reduce" });
  const state = () => page.evaluate(() => ({ sel: document.querySelector('.tab[aria-selected="true"]').id, focus: document.activeElement?.id, tabs: [...document.querySelectorAll(".tab")].map((t) => t.tabIndex), panel: document.querySelector('[role="tabpanel"]:not([hidden])').id }));
  await page.focus("#tab-message");
  const walk = [["ArrowRight", "link"], ["ArrowRight", "payment"], ["ArrowLeft", "link"], ["End", "app"], ["ArrowRight", "message"], ["ArrowLeft", "app"], ["Home", "message"]];
  for (const [key, k] of walk) {
    await page.keyboard.press(key);
    const s = await state();
    check(`K1 ${key} -> ${k}: selected, focused, the only tab in the Tab order, its panel shown`, s.sel === `tab-${k}` && s.focus === `tab-${k}` && s.tabs.filter((x) => x === 0).length === 1 && s.panel === `panel-${k}`, JSON.stringify(s));
  }
  check("K2 no console problem", !problems.length, problems.join("; "));
  await ctx.close();
  for (const w of [360, 390, 430]) {
    const p = await open(browser, { w, h: 800, motion: "reduce" });
    for (const k of ["message", "link", "payment", "app"]) {
      await p.page.click(`#tab-${k}`);
      await p.page.waitForTimeout(120);
      const m = await p.page.evaluate((k) => {
        const row = document.querySelector(".tabs").getBoundingClientRect(), on = document.getElementById(`tab-${k}`).getBoundingClientRect(), th = document.querySelector(".tabthumb").getBoundingClientRect(), cs = getComputedStyle(document.getElementById(`tab-${k}`));
        return { over: document.documentElement.scrollWidth - innerWidth, inView: on.left >= row.left - 1 && on.right <= row.right + 1, height: on.height, font: parseFloat(cs.fontSize), rowScrolls: getComputedStyle(document.querySelector(".tabs")).overflowX, pillOn: Math.abs(th.left - on.left) < 1 };
      }, k);
      check(`K3 ${w} px ${k}: no sideways page scroll, the tab in view, 40 px, 14 px text, one scrolling row, the pill on it`, m.over <= 0 && m.inView && m.height === 40 && m.font === 14 && m.rowScrolls === "auto" && m.pillOn, JSON.stringify(m));
    }
    await p.ctx.close();
  }
  const d = await open(browser, { motion: "reduce" });
  const all = await d.page.evaluate(() => { const row = document.querySelector(".tabs").getBoundingClientRect(); return [...document.querySelectorAll(".tab")].every((t) => { const r = t.getBoundingClientRect(); return r.left >= row.left && r.right <= row.right; }); });
  check("K4 desktop: all four tabs fit in one row", all);
  await d.ctx.close();
}

// ---- H the lift ----
// every CSS transition on the page has ended (a fixed wait is too short when headless frames are slow: the software-drawn globe takes most of them)
const settle = (page) => page.evaluate(async () => {
  await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  for (let i = 0; i < 4; i++) {
    const running = document.getAnimations().filter((x) => x instanceof CSSTransition);
    if (!running.length) break;
    await Promise.allSettled(running.map((x) => x.finished));
    await new Promise((r) => requestAnimationFrame(r));
  }
});
const metrics = (page, sel, nth = 0) => page.evaluate(({ sel, nth }) => {
  const el = document.querySelectorAll(sel)[nth], r = el.getBoundingClientRect(), cs = getComputedStyle(el);
  return { top: r.top, shadow: cs.boxShadow };
}, { sel, nth });
// the home clickables, one per kind; each is [name, selector, nth, its pill or thumb behind it or null]
const HOME_LIFT = [
  ["tab (not selected)", '.tab[aria-selected="false"]', 0, null],
  ["tab (selected)", '.tab[aria-selected="true"]', 0, ".tabthumb"],
  ["toggle (not selected)", '.segbtn[aria-pressed="false"]', 0, null],
  ["toggle (selected)", '.segbtn[aria-pressed="true"]', 0, ".segthumb"],
  ["sample chip", ".ex button", 0, null],
  ["Check", "button.go", 0, null],
  ["the footer's not-live button", ".srcbtn", 0, null],
];
async function liftOne(page, tag, [name, sel, nth, behind], motion) {
  await page.mouse.move(2, 2); await page.evaluate(() => document.activeElement?.blur?.()); await settle(page);
  const a = await metrics(page, sel, nth), pill = behind ? await metrics(page, behind) : null;
  const box = await page.evaluate(({ sel, nth }) => { const r = document.querySelectorAll(sel)[nth].getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2]; }, { sel, nth });
  await page.mouse.move(box[0], box[1]); await settle(page);
  const b = await metrics(page, sel, nth), pillB = behind ? await metrics(page, behind) : null;
  const rise = a.top - b.top, want = motion === "reduce" ? 0 : 2;
  const shadowChange = behind ? pill.shadow !== pillB.shadow : a.shadow !== b.shadow;
  check(`H1 ${tag} hover ${name}: rises ${want} px`, Math.abs(rise - want) < .06, `${rise.toFixed(2)} px`);
  check(`H2 ${tag} hover ${name}: ${want ? "a deeper shadow" : "same shadow"}`, want ? shadowChange : !shadowChange);
  if (behind) {
    const pr = pill.top - pillB.top;
    check(`H3 ${tag} hover ${name}: its pill rises with it`, Math.abs(pr - want) < .06, `${pr.toFixed(2)} px`);
  }
  if (motion !== "reduce") {   // pressed: back at the rest position, the transition a fast one. Released elsewhere, so nothing is clicked.
    await page.mouse.down();
    const took = await page.evaluate(({ sel, nth }) => { const t = document.querySelectorAll(sel)[nth].getAnimations().find((x) => x instanceof CSSTransition && x.transitionProperty === "translate"); return t ? t.effect.getTiming().duration : null; }, { sel, nth });
    await settle(page);
    const c = await metrics(page, sel, nth);
    check(`H4 ${tag} pressed ${name}: settles in 60 ms`, Math.abs(c.top - a.top) < .06 && (took === null || took === 60), `${(a.top - c.top).toFixed(2)} px up, transition ${took} ms`);
    if (behind) { const pc = await metrics(page, behind); check(`H4 ${tag} pressed ${name}: its pill settles`, Math.abs(pc.top - pill.top) < .06, `${(pill.top - pc.top).toFixed(2)} px up`); }
    await page.mouse.move(2, 2);
    await page.mouse.up();
  }
  // keyboard focus: the same rise
  await page.mouse.move(2, 2); await settle(page);
  await page.keyboard.press("Shift");   // the last input is the keyboard, so a focus shows as :focus-visible
  const fv = await page.evaluate(({ sel, nth }) => { const el = document.querySelectorAll(sel)[nth]; el.focus(); return el.matches(":focus-visible"); }, { sel, nth });
  await settle(page);
  const f = await metrics(page, sel, nth), pillF = behind ? await metrics(page, behind) : null;
  check(`H5 ${tag} focus-visible ${name}: rises ${want} px`, fv && Math.abs(a.top - f.top - want) < .06, `${(a.top - f.top).toFixed(2)} px, :focus-visible ${fv}`);
  if (behind) check(`H6 ${tag} focus-visible ${name}: its pill rises with it`, Math.abs(pill.top - pillF.top - want) < .06, `${(pill.top - pillF.top).toFixed(2)} px`);
}
async function liftChecks(browser) {
  for (const theme of THEMES) for (const motion of ["no-preference", "reduce"]) {
    const { ctx, page, problems } = await open(browser, { theme, motion });
    const tag = `${theme}${motion === "reduce" ? " reduced" : ""}`;
    await page.fill("#msg", "Dear Customer, your account will be blocked today");   // Check is enabled
    for (const item of HOME_LIFT) await liftOne(page, tag, item, motion);
    await page.click('.segbtn:has-text("Screenshot")'); await page.mouse.move(2, 2);
    await liftOne(page, tag, ["screenshot drop area", ".dropbtn", 0, null], motion);
    await page.click('.segbtn:has-text("Paste text")');
    // a disabled Check does not rise
    await page.click("#tab-payment"); await settle(page);
    const a = await metrics(page, "button.go"), box = await page.locator("button.go").boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2); await settle(page);
    check(`H7 ${tag} a disabled Check does not rise`, Math.abs(a.top - (await metrics(page, "button.go")).top) < .06);
    check(`H8 ${tag} no console problem`, !problems.length, problems.join("; "));
    await ctx.close();
  }
}

const server = await preview({ root: join(HERE, ".."), preview: { host: "127.0.0.1", port: PORT, strictPort: true }, logLevel: "silent" });
const browser = await chromium.launch({ channel: "chrome", headless: true });
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
try {
  if (!ONLY || ONLY === "L") await lightChecks(browser);
  if (!ONLY || ONLY === "H") await liftChecks(browser);
  if (!ONLY || ONLY === "M") await motionChecks(browser);
  if (!ONLY || ONLY === "K") await keyboardChecks(browser);
} finally {
  await browser.close();
  await new Promise((res) => server.httpServer.close(res));
}
const failed = results.filter(([, ok]) => !ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
