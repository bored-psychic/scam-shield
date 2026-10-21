// The theme-switch animation on a BUILT site (2026-10-18; lib/themeSwitch.ts, approved prototype docs/design/theme-switch.html).
//
//   cd frontend && npm run build && node e2e/switch.mjs [--shots DIR] [--no-perf]
//
// The INSTALLED Google Chrome (playwright-core, headless) loads dist/ from Vite's preview server on 127.0.0.1; no backend, no network. The page
// is opened with window.__ssTest defined, so Globe.tsx publishes a read-only probe of the globe (its spin, arcs and landings; and a repaint).
//   S1 durations, real time: from the first animated frame (the root's clip animation is created) to the end (<html> loses .ss-switch); comet
//      2400 ms, black hole 2600 ms, +-50 ms. The time from the click is printed too.
//   S2 smoothness: requestAnimationFrame frame times while each animation runs, at 1280x800 and 390x844 (two runs of each): average <= 17 ms and
//      95th percentile <= 25 ms at both sizes (the globe is drawn twice a frame during the switch). --no-perf skips the gate (still printed).
//      Printed too: the main-thread time of all rAF callbacks per frame (the switch's frame, which draws the globe twice, the recorder), and the
//      same at 1280x800 with deviceScaleFactor 2 (a Retina screen; not gated).
//   S3 the edge, under Playwright's clock (time stopped at 25 / 50 / 75 % of each animation, both sizes; one page per frame): with the effects
//      layer hidden, every pixel of the frame is classed as the light or the dark page by comparing it with the two still pages AT THE SAME
//      MOMENT (the transition is skipped right after the frame, the clock still stopped, and the page is drawn in each theme in turn: the
//      globe has not moved). That must agree with the clip polygon for >= 99.9 % of the globe's pixels and of the rest, more than 4 px from the
//      edge, outside the switch (its own snapshot). At 50 % of the comet the shock's half-angle is fitted to the boundary: 34 degrees (+-1.5).
//   S4 a double click and a click mid-animation are ignored: one switch, ending in the other theme.
//   S5 a hidden tab mid-animation ends at once in the new theme (headless Chrome cannot hide a page, so document.hidden is overridden and
//      visibilitychange fired: this exercises the page's own handler).
//   S6 a resize mid-animation ends at once in the new theme.
//   S7 after every switch: nothing left (no effects canvas, no glass pane, no .ss-* class, no view-transition-name on the switch, no animation on
//      a pseudo-element) and the page looks like a fresh load in that theme, to 2/255 per channel (raster noise; globe and footer hidden: they
//      move on their own).
//   S8 no console error or warning, no page error, no request outside the page, in any of the above.
//   S9 the spin, under the clock: the globe's angle at 0 / 25 / 50 / 75 / 100 % of the switch and just before and after it grows at the normal
//      0.035 rad/s in every interval (+-1 %); and in real time, no gap over 50 ms between two of the globe's frames during the switch.
//   S10 a drag during the switch turns the globe (120 px -> 0.6 rad) and the turn shows in the next frame.
//   S11 the arcs, under the clock and a seeded Math.random (the same arcs every run): none starts during the switch; every arc in flight moves
//      between the 0 / 25 / 50 / 75 % frames (some still fly from 25 to 50 %), at 1.5 x its normal speed (+-10 %), and lands once (one ripple,
//      one hit, one new line in the footer feed) when 1.5 x predicts.
//   S12 arcs start again within 1 s after a switch ends, after a hidden tab ended one, and after an instant switch (no View Transitions).
//   S14-S16 (2026-10-21, a headed Chrome; --frames-only runs S14-S16, --perf-only S16 alone): see the comments above frameSweep() and headedPerf().
//   S13 layering and glass, in the S3 frames: the hero text, the paste box and the example chips are never covered by the globe, and look as
//      on the still page of their side of the edge (the dark side: the box's glass blurs the live globe as outside the switch). Tolerance:
//      <= 1 % of their pixels more than 4/255 off, none more than 16/255 (raster noise of a snapshot), more than 4 px from the edge; on the
//      dark side the 8 px after that are reported apart (the dark glass there blurs the light page just across the edge).
// Exit code 1 on any failure.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { preview } from "vite";

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (name) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : null; };
const SHOTS = arg("--shots"), PERF = !process.argv.includes("--no-perf");
const PORT = 4180, URL = `http://127.0.0.1:${PORT}/`;
const T = { comet: 2400, hole: 2600 }, FROM = { comet: "dark", hole: "light" }, TO = { comet: "light", hole: "dark" };
const SIZES = [[1280, 800], [390, 844]];
const SPIN = 0.035;   // rad/s, Globe.tsx
const results = [];
const check = (name, ok, detail = "") => { results.push([name, ok, detail]); };
const problems = [];   // S8

// test instrumentation, before the app's code: the probe switch, the time the root's clip animation is created (the animation's t0), the time
// <html> loses .ss-switch, and every line the footer feed gains
const INSTRUMENT = () => {
  window.__ssTest = {};
  const rec = (window.__sw = { starts: [], ends: [], frames: null, spins: null, work: null, hits: [] });
  const raf = window.requestAnimationFrame;   // main-thread time of every rAF callback, while rec.work is on (the real-time runs)
  window.requestAnimationFrame = (cb) => raf((ts) => { const t = performance.now(); try { cb(ts); } finally { rec.work?.push([ts, performance.now() - t]); } });
  const animate = Element.prototype.animate;
  Element.prototype.animate = function (k, o) { if (o?.pseudoElement?.endsWith("(root)")) rec.starts.push(performance.now()); return animate.call(this, k, o); };
  addEventListener("DOMContentLoaded", () => {
    let on = false;
    new MutationObserver(() => { const now = document.documentElement.classList.contains("ss-switch"); if (on && !now) rec.ends.push(performance.now()); on = now; })
      .observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    new MutationObserver((list) => { for (const m of list) for (const n of m.addedNodes) if (n.nodeType === 1 && n.classList.contains("ev")) rec.hits.push(performance.now()); })
      .observe(document.body, { childList: true, subtree: true });
  });
};

// seed: Math.random from a fixed seed (mulberry32), so the arcs in flight are the same every run (S11 needs some still flying at 25-75 %)
const SEED = (seed) => { let a = seed >>> 0; Math.random = () => { a = (a + 0x6D2B79F5) >>> 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; };
async function open(browser, { w, h, theme, motion = "no-preference", clock = false, noVT = false, dpr = 1, seed = 0 }) {
  const ctx = await browser.newContext({ viewport: { width: w, height: h }, deviceScaleFactor: dpr, colorScheme: theme, reducedMotion: motion });
  await ctx.route((u) => !u.href.startsWith(URL), (r) => { problems.push(`request outside the page: ${r.request().url()}`); r.abort(); });
  await ctx.addInitScript(INSTRUMENT);
  if (noVT) await ctx.addInitScript(() => { delete Document.prototype.startViewTransition; });
  if (seed) await ctx.addInitScript(SEED, seed);
  const page = await ctx.newPage();
  page.on("console", (m) => { if (m.type() === "error" || m.type() === "warning") problems.push(`console ${m.type()}: ${m.text()}`); });
  page.on("pageerror", (e) => problems.push(`page error: ${e.message}`));
  if (clock) await page.clock.install({ time: 0 });
  await page.goto(URL);
  await page.waitForSelector(".themebtn");
  await page.evaluate(() => document.fonts.ready);
  return [ctx, page];
}
const leftovers = (page) => page.evaluate(() => {
  const out = [], root = document.documentElement;
  if (document.querySelector(".ss-fx")) out.push("effects canvas still there");
  if (document.querySelector(".ss-vigc")) out.push("vignette canvas still there");
  if (document.querySelector(".ss-pane, .ss-glassed")) out.push("a glass pane (or its panel's class) still there");
  if ([...root.classList].some((c) => c.startsWith("ss-"))) out.push(`classes ${root.className}`);
  const vtn = getComputedStyle(document.querySelector(".themebtn")).viewTransitionName;
  if (vtn !== "none") out.push(`switch view-transition-name ${vtn}`);
  if (document.getAnimations().some((a) => a.effect?.pseudoElement)) out.push("an animation on a pseudo-element");
  if (document.activeViewTransition) out.push("a view transition is still active");
  return out;
});
const state = (page) => page.evaluate(() => ({ theme: document.documentElement.dataset.theme, label: document.querySelector(".themebtn").getAttribute("aria-label"),
  stored: localStorage.getItem("scam-shield-theme") }));
const globe = (page) => page.evaluate(() => window.__ssTest.globe.state());
// polled from here, not with waitForFunction: that polls on the page's requestAnimationFrame, which Playwright's stopped clock never fires
async function until(page, fn, ms = 8000) {
  for (const t0 = Date.now(); Date.now() - t0 < ms; await new Promise((r) => setTimeout(r, 20))) if (await page.evaluate(fn)) return;
  throw new Error(`timed out: ${fn}`);
}
const ended = (page) => until(page, () => window.__sw.ends.length > 0 && !document.documentElement.classList.contains("ss-switch"));
const begun = (page) => until(page, () => document.getAnimations().some((a) => a.effect?.pseudoElement));
// the frame's clip polygon, from the root's light view; unclipped (2026-10-21) while the whole screen is on one side of it: opaque = all
// light (the screen, +20 px), hidden = all dark (no polygon)
const rootClip = (page) => page.evaluate(() => {
  const k = document.getAnimations().find((a) => a.effect?.pseudoElement?.endsWith("(root)")).effect.getKeyframes()[0], W = innerWidth + 20, H = innerHeight + 20;
  if (k.clipPath !== "none") return k.clipPath;
  return k.opacity === "0" ? "polygon(0 0, 0 0, 0 0)" : `polygon(-20px -20px, ${W}px -20px, ${W}px ${H}px, -20px ${H}px)`;
});
const NOFX = ":root::view-transition-group(ss-fx) { visibility: hidden; }";
const png = async (page) => (await page.screenshot()).toString("base64");

// pixel work happens in a blank page of the same browser (canvas decoding of PNG screenshots)
let lab;
const pixels = (fn, data) => lab.evaluate(async ({ src, data }) => {
  const load = async (b64) => { const img = new Image(); img.src = "data:image/png;base64," + b64; await img.decode();
    const c = document.createElement("canvas"); c.width = img.width; c.height = img.height; const x = c.getContext("2d", { willReadFrequently: true });
    x.drawImage(img, 0, 0); return x.getImageData(0, 0, img.width, img.height); };
  return new Function("load", "data", `return (${src})(load, data);`)(load, data);
}, { src: fn.toString(), data });

// the final page against a fresh load in the same theme, with the globe and the footer feed hidden
const HIDE = ".stage, .vignette ~ footer, footer { visibility: hidden !important; }";
async function samePage(browser, page, w, h, theme, label) {
  const [ctx2, fresh] = await open(browser, { w, h, theme });
  await fresh.waitForTimeout(700);   // the switch icon's turn-in has finished
  const shot = async (p) => { await p.addStyleTag({ content: HIDE }); await p.waitForTimeout(150); return png(p); };
  const [a, b] = [await shot(page), await shot(fresh)];
  await ctx2.close();
  const diff = await pixels(async (load, { a, b }) => {
    const A = await load(a), B = await load(b), at = []; let n = 0, one = 0;
    for (let i = 0; i < A.data.length; i += 4) {
      const d = Math.max(Math.abs(A.data[i] - B.data[i]), Math.abs(A.data[i + 1] - B.data[i + 1]), Math.abs(A.data[i + 2] - B.data[i + 2]));
      if (d > 2) { n++; if (at.length < 4) at.push(`(${(i / 4) % A.width},${Math.floor(i / 4 / A.width)}) ${[...A.data.slice(i, i + 3)]} vs ${[...B.data.slice(i, i + 3)]}`); } else if (d) one++;
    }
    return { n, one, at };
  }, { a, b });
  // up to 2/255 is allowed: after a few switches Chrome may re-raster the light theme's hero wash (a radial gradient) with other dithering
  // (1/255) and the anti-aliased edge of a glass chip (2/255); anything left behind by the switch differs by far more
  check(`S7 ${label}: same as a fresh ${theme} page${diff.one ? ` (${diff.one} pixels off by 1-2/255)` : ""}`, diff.n === 0, `${diff.n} pixels differ by more than 2/255: ${diff.at.join("; ")}`);
}

// S3 + S13: one frame of a switch, classed pixel by pixel against the two still pages of the same moment
function classify(load, { mid, dark, light, poly, circle, kind, f, w, h, btn, regions }) {
  return (async () => {
    const [M, D, L] = [await load(mid), await load(dark), await load(light)];
    const pts = [...poly.matchAll(/(-?[\d.]+)px (-?[\d.]+)px/g)].map((m) => [+m[1], +m[2]]);
    const inPoly = (x, y) => { let c = false; for (let i = 0, j = pts.length - 1; i < pts.length; j = i++)
      if ((pts[i][1] > y) !== (pts[j][1] > y) && x < (pts[j][0] - pts[i][0]) * (y - pts[i][1]) / (pts[j][1] - pts[i][1]) + pts[i][0]) c = !c; return c; };
    const segDist = (x, y) => { let best = 1e9; for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
      const [ax, ay] = pts[j], [bx, by] = pts[i], dx = bx - ax, dy = by - ay, l = dx * dx + dy * dy, t = l ? Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / l)) : 0;
      best = Math.min(best, Math.hypot(x - ax - t * dx, y - ay - t * dy)); } return best; };
    const inside = (x, y) => pts.length > 2 && inPoly(x + .5, y + .5), nearEdge = (x, y) => pts.length > 2 && segDist(x + .5, y + .5) < 4;
    // light (true), dark (false), or null where the two pages look alike there
    const cls = (x, y) => { const i = (y * w + x) * 4, d = M.data, l = L.data, k = D.data;
      const dl = (d[i] - l[i]) ** 2 + (d[i + 1] - l[i + 1]) ** 2 + (d[i + 2] - l[i + 2]) ** 2, dd = (d[i] - k[i]) ** 2 + (d[i + 1] - k[i + 1]) ** 2 + (d[i + 2] - k[i + 2]) ** 2;
      const ld = (l[i] - k[i]) ** 2 + (l[i + 1] - k[i + 1]) ** 2 + (l[i + 2] - k[i + 2]) ** 2;
      return ld < 60 * 60 ? null : dl < dd; };
    const inBtn = (x, y) => x > btn.x - 4 && x < btn.x + btn.width + 4 && y > btn.y - 4 && y < btn.y + btn.height + 4;
    const tally = { globe: [0, 0], page: [0, 0] };
    for (let y = 1; y < h; y += 2) for (let x = 1; x < w; x += 2) {
      const c = cls(x, y); if (c === null || inBtn(x, y) || nearEdge(x, y)) continue;
      const t = Math.hypot(x - circle.cx, y - circle.cy) < circle.r ? tally.globe : tally.page;
      t[0]++; if (c === inside(x, y)) t[1]++;
    }
    const out = { globe: tally.globe[1] / tally.globe[0], page: tally.page[1] / tally.page[0], n: tally, regions: {} };
    // S13: each region against the still page of its side, pixel by pixel; the edge's 4 px are left out, and the next 8 on the dark side
    // (the band, up to 3 blur radii of the glass) are counted apart: there the dark glass blurs the live page behind it, already light across
    // the edge, where the still dark page is dark
    for (const [name, rs] of Object.entries(regions)) {
      let n = 0, over4 = 0, max = 0, lightN = 0, darkN = 0, at = "", bandN = 0, bandMax = 0;
      for (const r of rs) for (let y = Math.max(0, Math.ceil(r.y)); y < Math.min(h, Math.floor(r.y + r.height)); y++) for (let x = Math.max(0, Math.ceil(r.x)); x < Math.min(w, Math.floor(r.x + r.width)); x++) {
        const dist = pts.length > 2 ? segDist(x + .5, y + .5) : 1e9;
        if (dist < 4) continue;
        const lit = inside(x, y), S = lit ? L.data : D.data, i = (y * w + x) * 4, d = M.data;
        const e = Math.max(Math.abs(d[i] - S[i]), Math.abs(d[i + 1] - S[i + 1]), Math.abs(d[i + 2] - S[i + 2]));
        if (!lit && dist < 12) { bandN++; bandMax = Math.max(bandMax, e); continue; }
        n++; if (lit) lightN++; else darkN++;
        if (e > 4) over4++;
        if (e > max) { max = e; at = `${x},${y} ${lit ? "light" : "dark"} ${[...d.slice(i, i + 3)]} vs ${[...S.slice(i, i + 3)]}`; }
      }
      out.regions[name] = { n, lightN, darkN, over4: n ? over4 / n : 0, max, at, bandN, bandMax };
    }
    if (kind === "comet" && f === .5) {   // fit the shock's half-angle to the measured boundary, both sides, 250..1200 px behind the head
      const A = [w + 90, -90], B = [-90, h + 90], len = Math.hypot(B[0] - A[0], B[1] - A[1]), dv = [(B[0] - A[0]) / len, (B[1] - A[1]) / len], n = [-dv[1], dv[0]];
      const k = f / .8, travel = k * k * (3 - 2 * k) * .3 + k * .7, hd = [A[0] + dv[0] * travel * (len + 260), A[1] + dv[1] * travel * (len + 260)];
      const obs = [];
      for (let s = 250; s <= 1200; s += 10) for (const side of [1, -1]) {
        let run = 0;
        for (let r = 0; r < 1500; r++) {
          const x = Math.round(hd[0] - dv[0] * s + n[0] * side * r), y = Math.round(hd[1] - dv[1] * s + n[1] * side * r);
          if (x < 0 || y < 0 || x >= w || y >= h) break;
          if (cls(x, y) === false) { if (++run === 8) { obs.push([s, r - 7]); break; } } else run = 0;
        }
      }
      const half = (s, beta) => { const tb = Math.tan(beta); return 34 / tb * Math.sqrt((1 + (16 + s) * tb * tb / 34) ** 2 - 1); };
      let best = [1e18, 0];
      for (let deg = 8; deg <= 30; deg += .02) { const b = deg * Math.PI / 180; let e = 0; for (const [s, r] of obs) e += (half(s, b) - r) ** 2; if (e < best[0]) best = [e, deg]; }
      out.cone = { deg: 2 * best[1], rms: Math.sqrt(best[0] / obs.length), samples: obs.length };
    }
    return out;
  })();
}

async function edgeFrame(browser, w, h, kind, f) {
  const [ctx, page] = await open(browser, { w, h, theme: FROM[kind], clock: true });
  await page.clock.runFor(1500);
  await page.clock.pauseAt(4000);   // a multiple of the fake clock's 16 ms frame: frames then land on 25 / 50 / 75 % exactly
  const btn = await page.locator(".themebtn").boundingBox();   // the switch has its own snapshot, in its new state: not part of either page
  const regions = await page.evaluate(() => {
    const rects = (sel) => [...document.querySelectorAll(sel)].map((e) => e.getBoundingClientRect().toJSON());
    return { hero: rects(".hero h1, .hero .sub"), box: rects(".box"), chips: rects(".ex button") };
  });
  await page.click(".themebtn");
  await begun(page);
  await page.clock.runFor(Math.round(f * T[kind]));
  const at = (Math.floor((4000 + Math.round(f * T[kind])) / 16) * 16 - 4000) / T[kind];
  const circle = await page.evaluate(() => window.__ssTest.globe.circle());
  const hide = await page.addStyleTag({ content: NOFX });
  const mid = await png(page);
  await hide.evaluate((el) => el.remove());
  const poly = await rootClip(page);
  // the still pages of this moment: skip the transition (the page is then the new theme), draw the globe, then the old theme the same way
  await page.evaluate(() => document.activeViewTransition.skipTransition());
  await until(page, () => !document.documentElement.classList.contains("ss-switch"));
  await page.evaluate(() => window.__ssTest.globe.paint());
  await page.waitForTimeout(150);
  const still = { [TO[kind]]: await png(page) };
  await page.addStyleTag({ content: "*, *::before, *::after { transition: none !important; }" });   // straight to the old theme's colours (some have delays)
  await page.evaluate((t) => { document.documentElement.dataset.theme = t; window.__ssTest.globe.paint(); }, FROM[kind]);
  await page.waitForTimeout(300);   // the globe does not move meanwhile (the clock is stopped)
  still[FROM[kind]] = await png(page);
  const r = await pixels(classify, { mid, dark: still.dark, light: still.light, poly, circle, kind, f, w, h, btn, regions });
  const pct = (x) => (100 * x).toFixed(2), label = `${kind} ${w}x${h} at ${(at * 100).toFixed(1)}%`;
  check(`S3 ${label}: the edge agrees with the clip, ${pct(r.globe)}% of the globe's pixels, ${pct(r.page)}% of the rest`, r.globe >= .999 && r.page >= .999, JSON.stringify(r.n));
  if (r.cone) check(`S3 comet ${w}x${h} at 50%: cone opens ${r.cone.deg.toFixed(1)} deg (fit rms ${r.cone.rms.toFixed(1)} px, ${r.cone.samples} edge points)`,
    Math.abs(r.cone.deg - 34) <= 1.5 && r.cone.samples > 40);
  for (const [name, q] of Object.entries(r.regions))
    check(`S13 ${label}: ${name} (${q.lightN} light, ${q.darkN} dark px) as on the still page: ${pct(q.over4)}% over 4/255, max ${q.max}/255${q.bandN ? `; dark band by the edge ${q.bandN} px, max ${q.bandMax}/255` : ""}`,
      q.n > 0 && q.over4 <= .01 && q.max <= 16, q.at);
  await ctx.close();
  return r;
}

// S9 + S11 (+ the frames for --shots): one switch under the clock, sampled before, at 0 / 25 / 50 / 75 / 100 % and after
async function timeline(browser, w, h, kind) {
  const [ctx, page] = await open(browser, { w, h, theme: FROM[kind], clock: true, seed: 7 });
  await page.clock.runFor(3000);   // arcs in flight
  await page.clock.pauseAt(5760);
  const samples = [["-10%", await globe(page)]];
  await page.clock.runFor(240);   // 6000: the switch starts here (a multiple of 16 ms)
  samples.push(["0%", await globe(page)]);
  const t0 = await page.evaluate(() => performance.now());
  await page.click(".themebtn");
  await begun(page);
  let done = 0;
  const shots = [];
  for (const f of [.25, .5, .75]) {
    const ms = Math.round(f * T[kind]) - done; await page.clock.runFor(ms); done += ms;
    samples.push([`${f * 100}%`, await globe(page)]);
    shots.push(await page.screenshot());
  }
  await page.clock.runFor(Math.ceil((t0 + T[kind]) / 16) * 16 + 1 - (t0 + done));   // through the switch's last frame
  samples.push(["100%", await globe(page)]);
  await ended(page);
  const tEnd = await page.evaluate(() => window.__sw.ends[0]);
  await page.clock.runFor(256);
  samples.push(["+10%", await globe(page)]);
  await page.clock.runFor(1500);   // arcs start again
  const last = await globe(page), hits = await page.evaluate(() => window.__sw.hits);
  if (SHOTS) {
    mkdirSync(SHOTS, { recursive: true });
    shots.forEach((b, i) => writeFileSync(join(SHOTS, `switch_${kind}_${w}x${h}_${[25, 50, 75][i]}.png`), b));
    await sideBySide(shots, join(SHOTS, `switch_${kind}_${w}x${h}_25-50-75.png`), w, h, kind);
  }
  await ctx.close();
  const label = `${kind} ${w}x${h}`;

  // S9: the spin in every interval, from the globe's own clock (the time of its last frame)
  const rates = [];
  for (let i = 1; i < samples.length; i++) {
    const [n0, a] = samples[i - 1], [n1, b] = samples[i];
    rates.push([`${n0}..${n1}`, (b.rotY - a.rotY) / ((b.time - a.time) / 1000), b.time - a.time]);
  }
  const off = rates.filter(([, r]) => Math.abs(r / SPIN - 1) > .01);
  check(`S9 ${label}: spin ${rates.map(([n, r]) => `${n} ${(r * 1000).toFixed(2)}`).join(", ")} mrad/s (normal ${SPIN * 1000})`, !off.length, JSON.stringify(off));

  // S11: arcs
  const ev = last.events, at0 = samples[1][1], inFlight = at0.arcs.filter((a) => a.t < 1);
  const born = ev.filter(([e, , t]) => e === "born" && t > t0 && t <= tEnd);
  const reborn = ev.filter(([e, , t]) => e === "born" && t > tEnd).map(([, , t]) => t - tEnd);
  check(`S11 ${label}: no arc starts during the switch (${inFlight.length} in flight at its start)`, !born.length && inFlight.length > 0, JSON.stringify(born));
  const moved = [], paces = [], per = [];
  for (let i = 1; i < 4; i++) {   // the intervals 0-25, 25-50 and 50-75 %
    const a = samples[i][1], b = samples[i + 1][1];
    per.push(a.arcs.filter((x) => x.t < 1 && b.arcs.some((y) => y.id === x.id && y.t < 1)).length);
    for (const x of a.arcs) {
      const y = b.arcs.find((q) => q.id === x.id);
      if (!y || x.t >= 1) continue;
      moved.push(Math.hypot(y.head[0] - x.head[0], y.head[1] - x.head[1]) > .5 && y.t > x.t);
      if (y.t < 1) paces.push((y.t - x.t) * x.dur / ((b.time - a.time) / 1000));
    }
  }
  const stillOnes = moved.filter((m) => !m).length;
  check(`S11 ${label}: every arc in flight moves between the 0/25/50/75% frames (${moved.length} arc-intervals; still flying across 0-25 / 25-50 / 50-75 %: ${per.join(" / ")})`,
    moved.length > 0 && per[1] > 0 && !stillOnes, `${stillOnes} did not move`);
  const pmin = Math.min(...paces), pmax = Math.max(...paces);
  check(`S11 ${label}: in flight at ${paces.length ? `${pmin.toFixed(3)}-${pmax.toFixed(3)}` : "-"} x the normal speed (${paces.length} samples)`, paces.length > 0 && pmin >= 1.35 && pmax <= 1.65);
  const bad = [];
  let timed = 0;
  for (const a of inFlight) {
    const lands = ev.filter(([e, id]) => e === "land" && id === a.id), rip = ev.filter(([e, id]) => e === "ripple" && id === a.id), hit = ev.filter(([e, id]) => e === "hit" && id === a.id);
    if (lands.length !== 1 || rip.length !== 1 || hit.length !== 1) { bad.push(`arc ${a.id}: ${lands.length} landings, ${rip.length} ripples, ${hit.length} hits`); continue; }
    const want = t0 + (1 - a.t) * a.dur / 1.5 * 1000;   // its remaining flight at 1.5 x, if it lands before the switch ends
    if (want <= tEnd - 32) { timed++; const err = lands[0][2] - want; if (err < -1 || err > Math.max(17, .1 * (want - t0))) bad.push(`arc ${a.id}: landed ${err.toFixed(0)} ms off`); }
  }
  const hitEv = ev.filter(([e]) => e === "hit").length;
  check(`S11 ${label}: each lands once, when 1.5 x predicts (${timed} timed): one ripple, one hit, one footer line (${hits.length} lines for ${hitEv} hits)`,
    !bad.length && hits.length === hitEv, bad.slice(0, 4).join("; "));
  check(`S12 ${label}: arcs start again ${reborn.length ? `${Math.round(reborn[0])} ms` : "never"} after the switch ends`, reborn.length > 0 && reborn[0] <= 1000);
}

// --shots: the three frames side by side (scaled), and under them the same band of the globe at 1:1 (below the paste box: dots, arcs, ripples)
async function sideBySide(shots, out, w, h, kind) {
  const b64 = await lab.evaluate(async ({ shots, w, h, kind }) => {
    const s = w > 800 ? .5 : .9, pad = 12, top = 30, cw = Math.round(w * s), ch = 150, c = document.createElement("canvas");
    c.width = 3 * cw + 4 * pad; c.height = Math.round(h * s) + ch + 2 * top + 2 * pad;
    const g = c.getContext("2d"); g.fillStyle = "#888"; g.fillRect(0, 0, c.width, c.height);
    g.fillStyle = "#fff"; g.font = "16px sans-serif";
    for (let i = 0; i < 3; i++) {
      const img = new Image(); img.src = "data:image/png;base64," + shots[i]; await img.decode();
      const x = pad + i * (cw + pad), y2 = top + Math.round(h * s) + pad + top;
      g.drawImage(img, x, top, cw, h * s);
      g.fillText(`${kind} ${w}x${h} at ${[25, 50, 75][i]}%`, x, 21);
      g.drawImage(img, Math.round((w - cw) / 2), h - ch - 10, cw, ch, x, y2, cw, ch);
      g.fillText(`the globe below the box, 1:1 (y ${h - ch - 10}-${h - 10})`, x, y2 - 9);
    }
    return c.toDataURL().split(",")[1];
  }, { shots: shots.map((b) => b.toString("base64")), w, h, kind });
  writeFileSync(out, Buffer.from(b64, "base64"));
}

// S14 every 5 % of both animations (0..95 %, under the clock) at four screen sizes, two of them Retina-like, in a HEADED Chrome: headless Chrome
// drew the clip right where a real window lost it (2026-10-21: on a 1710x1073 @2x screen the black hole's light page vanished for ~1.3 s but
// for a top-left tile, the comet's late frames showed dark rectangles). Each frame (effects layer hidden) is sampled every 8 px and each sample
// classed light or dark by the nearer of the two themes' --bg tokens (read from the page, so no colour literal); a sample counts only where
// the still pages of both themes (before the click, after the end) are clear about it (text, dots and the moving globe's edges drop out),
// and not within 8 px of the edge or by the switch. It must be on the polygon's side. Fail: more than 0.5 % of the samples on the wrong
// side, or 25 wrong samples touching (40 x 40 px). --frames-only runs S14 alone; --frame-runs N repeats it; --frame-sizes 1710x1073@2,... other sizes; --frames-json FILE writes it.
const FRAME_SIZES = arg("--frame-sizes")?.split(",").map((z) => z.split(/[x@]/).map(Number)) ?? [[1710, 1073, 2], [1440, 900, 2], [1280, 800, 1], [390, 844, 3]];
const FRAMES_ONLY = process.argv.includes("--frames-only"), FRAME_RUNS = +(arg("--frame-runs") ?? 1), FRAMES_JSON = arg("--frames-json");
function sideOf(load, { shots, stillFrom, stillTo, polys, bgFrom, bgTo, lightFrom, w, h, btn, circle }) {
  return (async () => {
    const step = 8, F = await load(stillFrom), Tt = await load(stillTo), hex = (c) => [1, 3, 5].map((i) => parseInt(c.slice(i, i + 2), 16));
    const A = hex(bgFrom), B = hex(bgTo), d2 = (D, i, c) => (D[i] - c[0]) ** 2 + (D[i + 1] - c[1]) ** 2 + (D[i + 2] - c[2]) ** 2;
    const isFrom = (D, i) => d2(D, i, A) < d2(D, i, B);   // the pixel is nearer the old theme's background than the new one's
    const gw = Math.floor(w / step), gh = Math.floor(h / step), use = new Uint8Array(gw * gh);
    for (let gy = 0; gy < gh; gy++) for (let gx = 0; gx < gw; gx++) {
      const x = gx * step + step / 2, y = gy * step + step / 2, i = (Math.floor(y) * w + Math.floor(x)) * 4;
      const inBtn = x > btn.x - 6 && x < btn.x + btn.width + 6 && y > btn.y - 6 && y < btn.y + btn.height + 6;
      use[gy * gw + gx] = !inBtn && isFrom(F.data, i) && !isFrom(Tt.data, i) ? 1 : 0;
    }
    const out = [];
    for (let k = 0; k < shots.length; k++) {
      const M = await load(shots[k]), pts = [...polys[k].matchAll(/(-?[\d.]+)px (-?[\d.]+)px/g)].map((m) => [+m[1], +m[2]]);
      const inPoly = (x, y) => { let c = false; for (let i = 0, j = pts.length - 1; i < pts.length; j = i++)
        if ((pts[i][1] > y) !== (pts[j][1] > y) && x < (pts[j][0] - pts[i][0]) * (y - pts[i][1]) / (pts[j][1] - pts[i][1]) + pts[i][0]) c = !c; return c; };
      const near = (x, y) => { for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
        const [ax, ay] = pts[j], [bx, by] = pts[i], dx = bx - ax, dy = by - ay, l = dx * dx + dy * dy, t = l ? Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / l)) : 0;
        if (Math.hypot(x - ax - t * dx, y - ay - t * dy) < 8) return true; } return false; };
      const wrong = new Uint8Array(gw * gh);
      let n = 0, bad = 0, lightN = 0;
      for (let gy = 0; gy < gh; gy++) for (let gx = 0; gx < gw; gx++) {
        if (!use[gy * gw + gx]) continue;
        const x = gx * step + step / 2, y = gy * step + step / 2;
        if (pts.length > 2 && near(x, y)) continue;
        const lit = pts.length > 2 && inPoly(x, y), wantFrom = lit === lightFrom, i = (Math.floor(y) * w + Math.floor(x)) * 4;
        n++; if (lit) lightN++;
        if (isFrom(M.data, i) !== wantFrom) { bad++; wrong[gy * gw + gx] = 1; }
      }
      // the largest group of wrong samples that touch (8-neighbours), and its box
      let blob = 0, box = null;
      const seen = new Uint8Array(gw * gh);
      for (let s0 = 0; s0 < wrong.length; s0++) {
        if (!wrong[s0] || seen[s0]) continue;
        const st = [s0]; seen[s0] = 1; let size = 0, x0 = 1e9, y0 = 1e9, x1 = -1, y1 = -1;
        while (st.length) {
          const c = st.pop(), cx = c % gw, cy = (c - cx) / gw; size++;
          x0 = Math.min(x0, cx); x1 = Math.max(x1, cx); y0 = Math.min(y0, cy); y1 = Math.max(y1, cy);
          for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
            const nx = cx + dx, ny = cy + dy, q = ny * gw + nx;
            if (nx >= 0 && ny >= 0 && nx < gw && ny < gh && wrong[q] && !seen[q]) { seen[q] = 1; st.push(q); }
          }
        }
        if (size > blob) { blob = size; box = [x0 * step, y0 * step, (x1 - x0 + 1) * step, (y1 - y0 + 1) * step]; }
      }
      out.push({ n, lightN, bad, frac: n ? bad / n : 0, blob, box });
      // the first frame (all on the old side) against the still old page, the last (all on the new side) against the still new page, every
      // pixel but the switch's; the last one away from the globe's reach too (it has turned on meanwhile): the vignette, painted on its own
      // canvas during the switch, must look like the page's own
      if (k === 0 || k === shots.length - 1) {
        const S = k ? Tt : F, far = k ? circle.r * 1.6 : -1;
        let m = 0, over = 0, max = 0;
        for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
          if (x > btn.x - 6 && x < btn.x + btn.width + 6 && y > btn.y - 6 && y < btn.y + btn.height + 6) continue;
          if (far > 0 && Math.hypot(x - circle.cx, y - circle.cy) < far) continue;
          const i = (y * w + x) * 4, e = Math.max(Math.abs(M.data[i] - S.data[i]), Math.abs(M.data[i + 1] - S.data[i + 1]), Math.abs(M.data[i + 2] - S.data[i + 2]));
          m++; if (e > 4) over++; if (e > max) max = e;
        }
        out.at(-1).still = { n: m, over4: over / m, max };
      }
    }
    return out;
  })();
}
// S16 smoothness in the headed window at 1710x1073 @2x (the screen of the bug): rAF frame times through two comets and two black holes, real
// time, overall and per 10 % of the animation (a frame counts in the bucket of the progress at its end). Reported, not gated.
// --perf-only runs S16 alone; --perf-runs N switches N times each way.
const stats = (xs) => { const d = [...xs].sort((a, b) => a - b);
  return { frames: d.length, avg: d.reduce((a, b) => a + b, 0) / (d.length || 1), p95: d[Math.min(d.length - 1, Math.floor(d.length * .95))] ?? 0, max: d.at(-1) ?? 0 }; };
const PERF_ONLY = process.argv.includes("--perf-only"), PERF_RUNS = +(arg("--perf-runs") ?? 2);
async function headedPerf(browser, w, h, dpr) {
  const [ctx, page] = await open(browser, { w, h, theme: "dark", dpr });
  await page.waitForTimeout(800);
  const out = [];
  for (let run = 0; run < 2 * PERF_RUNS; run++) {
    const kind = run % 2 ? "hole" : "comet";
    await page.evaluate(() => { const r = window.__sw, id = (r.id = (r.id || 0) + 1); r.frames = []; r.starts.length = 0; r.ends.length = 0;
      (function loop() { if (r.id !== id) return; r.frames.push(performance.now()); requestAnimationFrame(loop); })(); });
    await page.evaluate(() => document.querySelector(".themebtn").click());
    await ended(page);
    await page.waitForTimeout(300);
    const r = await page.evaluate(() => { const s = window.__sw; s.id++; return { start: s.starts[0], end: s.ends[0], frames: s.frames }; });
    const dts = [], buckets = Array.from({ length: 10 }, () => []);
    for (let i = 1; i < r.frames.length; i++) if (r.frames[i - 1] >= r.start && r.frames[i] <= r.end) {
      const dt = r.frames[i] - r.frames[i - 1];
      dts.push(dt); buckets[Math.min(9, Math.floor((r.frames[i] - r.start) / T[kind] * 10))].push(dt);
    }
    out.push({ kind, run: (run >> 1) + 1, ...stats(dts), buckets: buckets.map(stats) });
  }
  await ctx.close();
  return out;
}

async function frameSweep(browser, w, h, dpr, kind) {
  const [ctx, page] = await open(browser, { w, h, theme: FROM[kind], clock: true, dpr });
  await page.clock.runFor(1500);
  await page.clock.pauseAt(4000);
  const shot = async () => (await page.screenshot({ scale: "css" })).toString("base64");
  const bg = () => page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--bg").trim());
  const btn = await page.locator(".themebtn").boundingBox(), bgFrom = await bg(), stillFrom = await shot(), circle = await page.evaluate(() => window.__ssTest.globe.circle());
  // S15: the page's background and vignette alone, on the still page and in the switch (where the vignette is painted on its own canvas)
  const alone = async (css) => { const t = await page.addStyleTag({ content: css }); const b = await shot(); await t.evaluate((el) => el.remove()); return b; };
  const VIG_PAGE = ".stage, #root > main, #root > header, #root > footer, .themebtn { visibility: hidden !important; }";
  const VIG_SWITCH = ":root::view-transition-group(*) { visibility: hidden; } :root::view-transition-group(root), :root::view-transition-group(ss-vigc) { visibility: visible; }";
  const vig = { from: await alone(VIG_PAGE) };
  await page.click(".themebtn");
  await begun(page);
  await page.addStyleTag({ content: NOFX });
  const shots = [], polys = [], ats = [];
  let done = 0;
  for (let k = 0; k < 20; k++) {
    const ms = Math.round(k * .05 * T[kind]) - done;
    if (ms) await page.clock.runFor(ms);
    done += ms;
    shots.push(await shot()); polys.push(await rootClip(page)); ats.push(k * 5);
    if (k === 0) vig.first = await alone(VIG_SWITCH);
    if (k === 10) vig.mid = await alone(VIG_SWITCH);
    if (k === 19) vig.last = await alone(VIG_SWITCH);
  }
  await page.clock.runFor(T[kind] - done + 64);
  await ended(page);
  await page.waitForTimeout(150);
  const bgTo = await bg(), stillTo = await shot();
  vig.to = await alone(VIG_PAGE);
  await ctx.close();
  // compared on that theme's side of the frame's polygon only (more than 4 px from it): the black hole's wobbling edge can already leave a
  // corner of a small screen dark in its first frame
  const vd = await pixels(async (load, { pairs, btn, w, h }) => {
    const out = {};
    for (const [name, a, b, poly, wantLit] of pairs) {
      const A = await load(a), B = await load(b), pts = [...poly.matchAll(/(-?[\d.]+)px (-?[\d.]+)px/g)].map((m) => [+m[1], +m[2]]);
      const inPoly = (x, y) => { let c = false; for (let i = 0, j = pts.length - 1; i < pts.length; j = i++)
        if ((pts[i][1] > y) !== (pts[j][1] > y) && x < (pts[j][0] - pts[i][0]) * (y - pts[i][1]) / (pts[j][1] - pts[i][1]) + pts[i][0]) c = !c; return c; };
      const near = (x, y) => { for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
        const [ax, ay] = pts[j], [bx, by] = pts[i], dx = bx - ax, dy = by - ay, l = dx * dx + dy * dy, t = l ? Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / l)) : 0;
        if (Math.hypot(x - ax - t * dx, y - ay - t * dy) < 4) return true; } return false; };
      let over = 0, max = 0, n = 0;
      for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
        if (x > btn.x - 6 && x < btn.x + btn.width + 6 && y > btn.y - 6 && y < btn.y + btn.height + 6) continue;
        if (pts.length > 2 && (inPoly(x + .5, y + .5) !== wantLit || near(x + .5, y + .5))) continue;
        if (pts.length < 3 && wantLit) continue;
        const i = (y * w + x) * 4, e = Math.max(Math.abs(A.data[i] - B.data[i]), Math.abs(A.data[i + 1] - B.data[i + 1]), Math.abs(A.data[i + 2] - B.data[i + 2]));
        n++; if (e > 2) over++; if (e > max) max = e;
      }
      out[name] = { n, over2: n ? over / n : 0, max };
    }
    return out;
  }, { pairs: [["old theme", vig.first, vig.from, polys[0], FROM[kind] === "light"], ["new theme", vig.last, vig.to, polys.at(-1), TO[kind] === "light"]], btn, w, h });
  const r = await pixels(sideOf, { shots, stillFrom, stillTo, polys, bgFrom, bgTo, lightFrom: FROM[kind] === "light", w, h, btn, circle });
  const out = r.map((q, i) => ({ ...q, pct: ats[i], ok: q.frac <= .02 && q.blob < 150 }));
  out.vignette = vd;
  if (SHOTS) {   // the failing frames, with the wrong samples' largest patch outlined
    mkdirSync(SHOTS, { recursive: true });
    out.forEach((q, i) => { if (!q.ok) writeFileSync(join(SHOTS, `frames_${kind}_${w}x${h}@${dpr}_${q.pct}.png`), Buffer.from(shots[i], "base64")); });
    const keep = { still_from: stillFrom, first: shots[0], last: shots.at(-1), still_to: stillTo, vig_from: vig.from, vig_first: vig.first, vig_mid: vig.mid, vig_last: vig.last, vig_to: vig.to };
    for (const [n, b] of Object.entries(keep)) writeFileSync(join(SHOTS, `frames_${kind}_${w}x${h}@${dpr}_${n}.png`), Buffer.from(b, "base64"));
  }
  return out;
}

const server = await preview({ root: join(HERE, ".."), preview: { host: "127.0.0.1", port: PORT, strictPort: true }, logLevel: "silent" });
const browser = await chromium.launch({ channel: "chrome", headless: true });
lab = await (await browser.newContext()).newPage();
const perf = [];
try {
  // S14: the frame sweep, in a headed Chrome of its own (a window opens)
  const headed = await chromium.launch({ channel: "chrome", headless: false });
  const sweeps = [];
  try {
    if (!PERF_ONLY) for (let run = 1; run <= FRAME_RUNS; run++) for (const [w, h, dpr] of FRAME_SIZES) for (const kind of ["comet", "hole"]) {
      const fr = await frameSweep(headed, w, h, dpr, kind), bad = fr.filter((q) => !q.ok), label = `${kind} ${w}x${h} @${dpr}x${FRAME_RUNS > 1 ? ` run ${run}` : ""}`;
      sweeps.push({ kind, w, h, dpr, run, frames: fr, vignette: fr.vignette });
      for (const [side, q] of Object.entries(fr.vignette))
        check(`S15 ${label}: the vignette canvas, ${side}, as the page's own vignette: ${(100 * q.over2).toFixed(3)}% of ${q.n} pixels over 2/255, max ${q.max}/255`, q.n > w * h / 2 && q.over2 <= .001 && q.max <= 8);
      const worst = fr.reduce((m, q) => (q.frac > m.frac ? q : m));
      check(`S14 ${label}: ${fr.length - bad.length}/${fr.length} frames on the right side (worst ${worst.pct}%: ${(100 * worst.frac).toFixed(2)}% of ${worst.n} samples wrong, largest wrong patch ${worst.blob})`,
        !bad.length, bad.map((q) => `${q.pct}%: ${(100 * q.frac).toFixed(1)}% wrong, patch ${q.blob} samples at ${q.box}`).join("; "));
    }
    for (const p of await headedPerf(headed, 1710, 1073, 2)) {
      const label = `S16 ${p.kind} 1710x1073 @2x headed run ${p.run}: ${p.frames} frames, avg ${p.avg.toFixed(2)} ms (${(1000 / p.avg).toFixed(1)} fps), p95 ${p.p95.toFixed(2)} ms, max ${p.max.toFixed(1)} ms`;
      sweeps.push({ perf: p });
      console.log(label);
      console.log(`      per 10 %: ${p.buckets.map((b, i) => `${i * 10}-${i * 10 + 10}% ${b.avg.toFixed(1)}/${b.p95.toFixed(1)}`).join(", ")} (avg/p95 ms)`);
    }
  } finally {
    await headed.close();
    if (FRAMES_JSON) writeFileSync(FRAMES_JSON, JSON.stringify(sweeps, null, 1));
  }
  if (!FRAMES_ONLY && !PERF_ONLY) {
    // S1 + S2 + S7 + S9 (real time): both animations, both sizes, two runs each (comet, black hole, comet, black hole)
    for (const [w, h, dpr] of [...SIZES, [1280, 800, 2]]) {
      const [ctx, page] = await open(browser, { w, h, theme: "dark", dpr });
      await page.waitForTimeout(800);
      for (let run = 0; run < (dpr === 2 ? 2 : 4); run++) {
        const kind = run % 2 ? "hole" : "comet";
        await page.evaluate(() => { const r = window.__sw, id = (r.id = (r.id || 0) + 1); r.frames = []; r.spins = []; r.work = []; r.starts.length = 0; r.ends.length = 0;
          (function loop() { if (r.id !== id) return; r.frames.push(performance.now()); r.spins.push(window.__ssTest.globe.spin()); requestAnimationFrame(loop); })(); });   // one recorder at a time
        const clicked = await page.evaluate(() => { const t = performance.now(); document.querySelector(".themebtn").click(); return t; });
        await ended(page);
        await page.waitForTimeout(100);
        const r = await page.evaluate(() => { const s = window.__sw; s.id++; const out = { starts: s.starts, ends: s.ends, frames: s.frames, spins: s.spins, work: s.work }; s.work = null; return out; });
        const start = r.starts[0], end = r.ends[0], dur = end - start, label = `${kind} ${w}x${h}${dpr === 2 ? " @2x" : ""} run ${(run >> 1) + 1}`;
        const perFrame = new Map();
        for (const [ts, ms] of r.work) if (ts >= start && ts <= end) perFrame.set(ts, (perFrame.get(ts) || 0) + ms);
        const work = [...perFrame.values()].sort((a, b) => a - b);
        check(`S1 ${label}: ${Math.round(dur)} ms (from the click ${Math.round(end - clicked)} ms)`, Math.abs(dur - T[kind]) <= 50, `want ${T[kind]} +-50`);
        const dts = [];
        for (let i = 1; i < r.frames.length; i++) if (r.frames[i - 1] >= start && r.frames[i] <= end) dts.push(r.frames[i] - r.frames[i - 1]);
        dts.sort((a, b) => a - b);
        const avg = dts.reduce((a, b) => a + b, 0) / dts.length, p95 = dts[Math.min(dts.length - 1, Math.floor(dts.length * .95))];
        perf.push({ kind, size: `${w}x${h}${dpr === 2 ? "@2x" : ""}`, run: (run >> 1) + 1, frames: dts.length, avg: +avg.toFixed(2), p95: +p95.toFixed(2), max: +dts.at(-1).toFixed(2),
          work: { avg: +(work.reduce((a, b) => a + b, 0) / work.length).toFixed(2), p95: +work[Math.floor(work.length * .95)].toFixed(2), max: +work.at(-1).toFixed(2) } });
        if (dpr === 2) continue;   // reported only
        if (PERF) check(`S2 ${label}: frame time avg ${avg.toFixed(1)} ms, p95 ${p95.toFixed(1)} ms`, avg <= 17 && p95 <= 25, "target avg <= 17, p95 <= 25");
        // the globe's own frames (the time it last moved) from the click to the end: the longest gap, and the spin over the whole switch
        const sp = r.spins.filter(([t], i) => i === 0 || t !== r.spins[i - 1][0]).filter(([t]) => t >= clicked - 20 && t <= end + 20);
        let gap = 0; for (let i = 1; i < sp.length; i++) gap = Math.max(gap, sp[i][0] - sp[i - 1][0]);
        const rate = (sp.at(-1)[1] - sp[0][1]) / ((sp.at(-1)[0] - sp[0][0]) / 1000);
        check(`S9 ${label}, real time: the globe moved in ${sp.length} frames, longest gap ${gap.toFixed(1)} ms, spin ${(rate * 1000).toFixed(2)} mrad/s`, gap <= 50 && Math.abs(rate / SPIN - 1) <= .02);
        const s = await state(page);
        check(`S7 ${label}: ends in ${TO[kind]}, nothing left`, s.theme === TO[kind] && s.stored === TO[kind] && !(await leftovers(page)).length,
          JSON.stringify({ ...s, left: await leftovers(page) }));
        if (run >= 2) await samePage(browser, page, w, h, TO[kind], `${kind} ${w}x${h}`);
      }
      await ctx.close();
    }

    // S3 + S13: one page per frame
    for (const [w, h] of SIZES) for (const kind of ["comet", "hole"]) for (const f of [.25, .5, .75]) await edgeFrame(browser, w, h, kind, f);

    // S9 + S11 + S12: the spin and the arcs through one switch, under the clock
    for (const [w, h] of SIZES) for (const kind of ["comet", "hole"]) await timeline(browser, w, h, kind);

    // S10: drag during the switch, both directions
    for (const kind of ["comet", "hole"]) {
      const [ctx, page] = await open(browser, { w: 1280, h: 800, theme: FROM[kind], clock: true });
      await page.clock.runFor(1000);
      await page.clock.pauseAt(2000);
      await page.click(".themebtn");
      await begun(page);
      await page.clock.runFor(Math.round(.4 * T[kind]));
      const a = await globe(page), before = await png(page);
      await page.mouse.move(900, 700);
      await page.mouse.down();
      await page.mouse.move(1020, 700, { steps: 6 });
      await page.mouse.up();
      const b = await globe(page);
      await page.clock.runFor(32);
      const c = await globe(page), after = await png(page);
      const changed = await pixels(async (load, { a, b }) => { const A = await load(a), B = await load(b); let n = 0;
        for (let y = 560; y < 800; y += 2) for (let x = 300; x < 1000; x += 2) { const i = (y * A.width + x) * 4; if (Math.abs(A.data[i] - B.data[i]) + Math.abs(A.data[i + 1] - B.data[i + 1]) + Math.abs(A.data[i + 2] - B.data[i + 2]) > 30) n++; }
        return n; }, { a: before, b: after });
      const turned = b.rotY - a.rotY;
      await page.clock.runFor(T[kind]);
      await ended(page);
      const s = await state(page);
      check(`S10 ${kind}: a 120 px drag at 40% turns the globe ${turned.toFixed(3)} rad (want 0.600), it keeps turning (${(c.rotY - b.rotY).toFixed(4)} rad in 2 frames), ${changed} globe pixels change; ends in ${s.theme}`,
        Math.abs(turned - .6) < .005 && c.rotY > b.rotY && changed > 200 && s.theme === TO[kind] && b.switching);
      await ctx.close();
    }

    // S4: double click, and a click in the middle
    {
      const [ctx, page] = await open(browser, { w: 1280, h: 800, theme: "dark" });
      const b = await page.locator(".themebtn").boundingBox();
      await page.mouse.dblclick(b.x + b.width / 2, b.y + b.height / 2);
      await page.waitForTimeout(1000);
      await page.evaluate(() => document.querySelector(".themebtn").click());
      await page.mouse.click(b.x + b.width / 2, b.y + b.height / 2);
      await ended(page);
      await page.waitForTimeout(300);
      const s = await state(page), n = await page.evaluate(() => window.__sw.starts.length);
      check("S4 double click + clicks mid-animation: one switch, ends light", s.theme === "light" && s.stored === "light" && s.label === "Switch to the dark theme" && n === 1 && !(await leftovers(page)).length,
        JSON.stringify({ ...s, animations: n, left: await leftovers(page) }));
      await ctx.close();
    }

    // S5: hidden tab; S6: resize, each in both directions
    for (const kind of ["comet", "hole"]) {
      for (const what of ["hidden", "resize"]) {
        const [ctx, page] = await open(browser, { w: 1280, h: 800, theme: FROM[kind] });
        await page.click(".themebtn");
        await page.waitForTimeout(900);
        const t0 = Date.now();
        if (what === "hidden") await page.evaluate(() => {
          Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
          Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
          document.dispatchEvent(new Event("visibilitychange"));
        });
        else await page.setViewportSize({ width: 1000, height: 700 });
        await ended(page);
        const ms = Date.now() - t0;
        let back = 0;
        if (what === "hidden") back = await page.evaluate(() => {
          delete document.hidden; delete document.visibilityState; document.dispatchEvent(new Event("visibilitychange"));
          return performance.now();
        });
        await page.waitForTimeout(what === "hidden" ? 1100 : 300);
        const s = await state(page), left = await leftovers(page);
        check(`S${what === "hidden" ? 5 : 6} ${kind}: ${what} mid-animation -> ended after ${ms} ms in ${TO[kind]}, nothing left`, s.theme === TO[kind] && s.stored === TO[kind] && !left.length && ms < 500,
          JSON.stringify({ ...s, left }));
        if (what === "hidden") {
          const first = (await globe(page)).events.find(([e, , t]) => e === "born" && t > back);
          check(`S12 ${kind}: arcs start again ${first ? `${Math.round(first[2] - back)} ms` : "never"} after the tab is back`, !!first && first[2] - back <= 1000);
        }
        if (what === "resize") await samePage(browser, page, 1000, 700, TO[kind], `${kind} after a resize`);
        await ctx.close();
      }
    }

    // S12: the instant switch (no View Transitions here)
    {
      const [ctx, page] = await open(browser, { w: 1280, h: 800, theme: "dark", noVT: true });
      await page.waitForTimeout(500);
      const clicked = await page.evaluate(() => { document.querySelector(".themebtn").click(); return performance.now(); });
      await page.waitForTimeout(1100);
      const s = await state(page), first = (await globe(page)).events.find(([e, , t]) => e === "born" && t > clicked);
      check(`S12 instant switch (no View Transitions): ${s.theme} at once, arcs start ${first ? `${Math.round(first[2] - clicked)} ms` : "never"} after`,
        s.theme === "light" && !!first && first[2] - clicked <= 1000 && !(await leftovers(page)).length);
      await ctx.close();
    }
  }
} finally {
  await browser.close();
  await new Promise((res) => server.httpServer.close(res));
}
check("S8 no console error or warning, no page error, no request outside the page", !problems.length, problems.slice(0, 5).join(" | "));
console.log("frame times (ms):");
for (const p of perf) console.log(`  ${p.kind.padEnd(5)} ${p.size.padEnd(11)} run ${p.run}: ${p.frames} frames, avg ${p.avg}, p95 ${p.p95}, max ${p.max}; rAF work per frame avg ${p.work.avg}, p95 ${p.work.p95}, max ${p.work.max}`);
let failed = 0;
for (const [name, ok, detail] of results) { console.log(`${ok ? "ok  " : "FAIL"} ${name}${ok ? "" : `  ${detail}`}`); failed += ok ? 0 : 1; }
console.log(`\n${results.length - failed}/${results.length} switch checks pass`);
process.exit(failed ? 1 : 0);
