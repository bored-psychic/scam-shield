// The theme-switch animation on a BUILT site (2026-10-18; lib/themeSwitch.ts, approved prototype docs/design/theme-switch.html).
//
//   cd frontend && npm run build && node e2e/switch.mjs [--shots DIR] [--no-perf]
//
// The INSTALLED Google Chrome (playwright-core, headless) loads dist/ from Vite's preview server on 127.0.0.1; no backend, no network.
//   S1 durations, real time: from the first animated frame (the clip animation is created) to the end (<html> loses .ss-switch); comet 2400 ms,
//      black hole 2600 ms, +-50 ms. The time from the click is printed too.
//   S2 smoothness: requestAnimationFrame frame times while each animation runs, at 1280x800 and 390x844 (two runs of each). Average and 95th
//      percentile are printed; the target (average <= 17 ms, p95 <= 25 ms) is checked at the desktop size. --no-perf skips it.
//   S3 the edge, under Playwright's clock (time stopped at 25 / 50 / 75 % of each animation, both sizes; --shots DIR saves those frames): with
//      the effects layer hidden, every pixel of the frame is classed as the light or the dark page by comparing it with the page before and after
//      the switch; that must agree with the clip polygon, inside the globe's circle and outside it, for 99.5 % of the pixels more than 4 px from
//      the edge, outside the switch (its own snapshot) (the globe changes along the same edge as the page). At 50 % of the comet, the shock's half-angle is fitted to the measured
//      light / dark boundary: the cone must open 34 degrees in total (+-1.5).
//   S4 a double click and a click mid-animation are ignored: one switch, ending in the other theme.
//   S5 a hidden tab mid-animation ends at once in the new theme (headless Chrome cannot hide a page, so document.hidden is overridden and
//      visibilitychange fired: this exercises the page's own handler).
//   S6 a resize mid-animation ends at once in the new theme.
//   S7 after every switch: nothing left (no effects canvas, no .ss-* class, no view-transition-name on the switch, no animation on a pseudo-element)
//      and the page looks like a fresh load in that theme, to 2/255 per channel (raster noise; globe and footer feed hidden: they move on their own).
//   S8 no console error or warning, no page error, no request outside the page, in any of the above.
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
const results = [];
const check = (name, ok, detail = "") => { results.push([name, ok, detail]); };
const problems = [];   // S8

// test instrumentation, before the app's code: the time the clip animation is created (the animation's t0) and the time <html> loses .ss-switch
const INSTRUMENT = () => {
  const rec = (window.__sw = { starts: [], ends: [], frames: null });
  const animate = Element.prototype.animate;
  Element.prototype.animate = function (k, o) { if (o && o.pseudoElement) rec.starts.push(performance.now()); return animate.call(this, k, o); };
  addEventListener("DOMContentLoaded", () => {
    let on = false;
    new MutationObserver(() => { const now = document.documentElement.classList.contains("ss-switch"); if (on && !now) rec.ends.push(performance.now()); on = now; })
      .observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
  });
};

async function open(browser, { w, h, theme, motion = "no-preference", clock = false }) {
  const ctx = await browser.newContext({ viewport: { width: w, height: h }, deviceScaleFactor: 1, colorScheme: theme, reducedMotion: motion });
  await ctx.route((u) => !u.href.startsWith(URL), (r) => { problems.push(`request outside the page: ${r.request().url()}`); r.abort(); });
  await ctx.addInitScript(INSTRUMENT);
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
  if ([...root.classList].some((c) => c.startsWith("ss-"))) out.push(`classes ${root.className}`);
  const vtn = getComputedStyle(document.querySelector(".themebtn")).viewTransitionName;
  if (vtn !== "none") out.push(`switch view-transition-name ${vtn}`);
  if (document.getAnimations().some((a) => a.effect?.pseudoElement)) out.push("an animation on a pseudo-element");
  if (document.activeViewTransition) out.push("a view transition is still active");
  return out;
});
const state = (page) => page.evaluate(() => ({ theme: document.documentElement.dataset.theme, label: document.querySelector(".themebtn").getAttribute("aria-label"),
  stored: localStorage.getItem("scam-shield-theme") }));
// polled from here, not with waitForFunction: that polls on the page's requestAnimationFrame, which Playwright's stopped clock never fires
async function until(page, fn, ms = 8000) {
  for (const t0 = Date.now(); Date.now() - t0 < ms; await new Promise((r) => setTimeout(r, 20))) if (await page.evaluate(fn)) return;
  throw new Error(`timed out: ${fn}`);
}
const ended = (page) => until(page, () => window.__sw.ends.length > 0 && !document.documentElement.classList.contains("ss-switch"));

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
  const shot = async (p) => { await p.addStyleTag({ content: HIDE }); await p.waitForTimeout(150); return (await p.screenshot()).toString("base64"); };
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

const server = await preview({ root: join(HERE, ".."), preview: { host: "127.0.0.1", port: PORT, strictPort: true }, logLevel: "silent" });
const browser = await chromium.launch({ channel: "chrome", headless: true });
lab = await (await browser.newContext()).newPage();
const perf = [];
try {
  // S1 + S2 + S7: real time, both animations, both sizes, two runs each (comet, black hole, comet, black hole)
  for (const [w, h] of SIZES) {
    const [ctx, page] = await open(browser, { w, h, theme: "dark" });
    await page.waitForTimeout(800);
    for (let run = 0; run < 4; run++) {
      const kind = run % 2 ? "hole" : "comet";
      await page.evaluate(() => { const r = window.__sw, id = (r.id = (r.id || 0) + 1); r.frames = []; r.starts.length = 0; r.ends.length = 0;
        (function loop() { if (r.id !== id) return; r.frames.push(performance.now()); requestAnimationFrame(loop); })(); });   // one recorder at a time
      const clicked = await page.evaluate(() => { const t = performance.now(); document.querySelector(".themebtn").click(); return t; });
      await ended(page);
      await page.waitForTimeout(100);
      const r = await page.evaluate(() => { window.__sw.id++; return { starts: window.__sw.starts, ends: window.__sw.ends, frames: window.__sw.frames }; });
      const start = r.starts[0], end = r.ends[0], dur = end - start;
      check(`S1 ${kind} ${w}x${h} run ${(run >> 1) + 1}: ${Math.round(dur)} ms (from the click ${Math.round(end - clicked)} ms)`, Math.abs(dur - T[kind]) <= 50, `want ${T[kind]} +-50`);
      const dts = [];
      for (let i = 1; i < r.frames.length; i++) if (r.frames[i - 1] >= start && r.frames[i] <= end) dts.push(r.frames[i] - r.frames[i - 1]);
      dts.sort((a, b) => a - b);
      const avg = dts.reduce((a, b) => a + b, 0) / dts.length, p95 = dts[Math.min(dts.length - 1, Math.floor(dts.length * .95))];
      perf.push({ kind, size: `${w}x${h}`, run: (run >> 1) + 1, frames: dts.length, avg: +avg.toFixed(2), p95: +p95.toFixed(2), max: +dts.at(-1).toFixed(2) });
      if (PERF && w === 1280) check(`S2 ${kind} ${w}x${h} run ${(run >> 1) + 1}: frame time avg ${avg.toFixed(1)} ms, p95 ${p95.toFixed(1)} ms`, avg <= 17 && p95 <= 25, "target avg <= 17, p95 <= 25");
      const s = await state(page);
      check(`S7 ${kind} ${w}x${h} run ${(run >> 1) + 1}: ends in ${TO[kind]}, nothing left`, s.theme === TO[kind] && s.stored === TO[kind] && !(await leftovers(page)).length,
        JSON.stringify({ ...s, left: await leftovers(page) }));
      if (run >= 2) await samePage(browser, page, w, h, TO[kind], `${kind} ${w}x${h}`);
    }
    await ctx.close();
  }

  // S3: frames under the clock
  for (const [w, h] of SIZES)
    for (const kind of ["comet", "hole"]) {
      const [ctx, page] = await open(browser, { w, h, theme: FROM[kind], clock: true });
      await page.clock.runFor(1500);
      await page.clock.pauseAt(4000);   // a multiple of the fake clock's 16 ms frame: frames then land on 25 / 50 / 75 % exactly
      const before = (await page.screenshot()).toString("base64");
      const circle = await page.evaluate(() => {   // the globe's circle as Globe.tsx computes it (camera at 0, 62 | 95, 300 | 440, fov 42)
        const w = innerWidth, h = innerHeight, z = w < 640 ? 440 : 300, lift = w < 640 ? 95 : 62, f = (h / 2) / Math.tan(21 * Math.PI / 180);
        return { cx: w / 2, cy: h / 2 + f * lift / z, r: f * 100 / Math.sqrt(z * z + lift * lift - 100 * 100) };
      });
      const btn = await page.locator(".themebtn").boundingBox();   // the switch has its own snapshot, in its new state: not part of either page
      await page.click(".themebtn");
      await until(page, () => document.getAnimations().some((a) => a.effect?.pseudoElement));
      const mids = [];
      let done = 0;
      for (const f of [.25, .5, .75]) {
        const ms = Math.round(f * T[kind]) - done; await page.clock.runFor(ms); done += ms;
        const png = await page.screenshot();
        if (SHOTS) { mkdirSync(SHOTS, { recursive: true }); writeFileSync(join(SHOTS, `app_${kind}_${w}x${h}_${f * 100}.png`), png); }
        // the same frame without the effects (the comet, the hole, the streaks and the shield are drawn over both pages): only the clip's edge is left
        const hide = await page.addStyleTag({ content: ":root::view-transition-group(ss-fx) { visibility: hidden; }" });
        const bare = await page.screenshot();
        await hide.evaluate((el) => el.remove());
        const poly = await page.evaluate(() => document.getAnimations().find((a) => a.effect?.pseudoElement).effect.getKeyframes()[0].clipPath);
        mids.push({ f, at: (Math.floor((4000 + done) / 16) * 16 - 4000) / T[kind], png: bare.toString("base64"), poly });
      }
      // through the first frame at or after the end (the fake clock's frames fall every 16 ms): the globe is released then and has not moved yet
      await page.clock.runFor(Math.ceil((4000 + T[kind]) / 16) * 16 + 1 - (4000 + done));
      await ended(page);
      const after = (await page.screenshot()).toString("base64");
      for (const m of mids) {
        const r = await pixels(async (load, { before, after, mid, poly, circle, kind, f, w, h, btn }) => {
          const [D, L, M] = [await load(kind === "comet" ? before : after), await load(kind === "comet" ? after : before), await load(mid)];
          const pts = [...poly.matchAll(/(-?[\d.]+)px (-?[\d.]+)px/g)].map((m) => [+m[1], +m[2]]);
          const inPoly = (x, y) => { let c = false; for (let i = 0, j = pts.length - 1; i < pts.length; j = i++)
            if ((pts[i][1] > y) !== (pts[j][1] > y) && x < (pts[j][0] - pts[i][0]) * (y - pts[i][1]) / (pts[j][1] - pts[i][1]) + pts[i][0]) c = !c; return c; };
          const segDist = (x, y) => { let best = 1e9; for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
            const [ax, ay] = pts[j], [bx, by] = pts[i], dx = bx - ax, dy = by - ay, l = dx * dx + dy * dy, t = l ? Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / l)) : 0;
            best = Math.min(best, Math.hypot(x - ax - t * dx, y - ay - t * dy)); } return best; };
          // light (true), dark (false), or null where the two pages look alike there
          const cls = (x, y) => { const i = (y * w + x) * 4, d = M.data, l = L.data, k = D.data;
            const dl = (d[i] - l[i]) ** 2 + (d[i + 1] - l[i + 1]) ** 2 + (d[i + 2] - l[i + 2]) ** 2, dd = (d[i] - k[i]) ** 2 + (d[i + 1] - k[i + 1]) ** 2 + (d[i + 2] - k[i + 2]) ** 2;
            const ld = (l[i] - k[i]) ** 2 + (l[i + 1] - k[i + 1]) ** 2 + (l[i + 2] - k[i + 2]) ** 2;
            return ld < 60 * 60 ? null : dl < dd; };
          const tally = { globe: [0, 0], page: [0, 0] };
          for (let y = 1; y < h; y += 2) for (let x = 1; x < w; x += 2) {
            const c = cls(x, y); if (c === null) continue;
            if (x > btn.x - 4 && x < btn.x + btn.width + 4 && y > btn.y - 4 && y < btn.y + btn.height + 4) continue;
            const inside = pts.length > 2 && inPoly(x + .5, y + .5); if (pts.length > 2 && segDist(x + .5, y + .5) < 4) continue;
            const t = Math.hypot(x - circle.cx, y - circle.cy) < circle.r ? tally.globe : tally.page;
            t[0]++; if (c === inside) t[1]++;
          }
          const out = { globe: tally.globe[1] / tally.globe[0], page: tally.page[1] / tally.page[0], n: tally };
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
        }, { before, after, mid: m.png, poly: m.poly, circle, kind, f: m.f, w, h, btn });
        const pct = (x) => (100 * x).toFixed(2);
        check(`S3 ${kind} ${w}x${h} at ${(m.at * 100).toFixed(1)}%: the edge agrees with the clip, ${pct(r.globe)}% of the globe's pixels, ${pct(r.page)}% of the rest`,
          r.globe >= .995 && r.page >= .995, JSON.stringify(r.n));
        if (r.cone) check(`S3 comet ${w}x${h} at 50%: cone opens ${r.cone.deg.toFixed(1)} deg (fit rms ${r.cone.rms.toFixed(1)} px, ${r.cone.samples} edge points)`,
          Math.abs(r.cone.deg - 34) <= 1.5 && r.cone.samples > 40);
      }
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
      if (what === "hidden") await page.evaluate(() => {
        delete document.hidden; delete document.visibilityState; document.dispatchEvent(new Event("visibilitychange"));
      });
      await page.waitForTimeout(300);
      const s = await state(page), left = await leftovers(page);
      check(`S${what === "hidden" ? 5 : 6} ${kind}: ${what} mid-animation -> ended after ${ms} ms in ${TO[kind]}, nothing left`, s.theme === TO[kind] && s.stored === TO[kind] && !left.length && ms < 500,
        JSON.stringify({ ...s, left }));
      if (what === "resize") await samePage(browser, page, 1000, 700, TO[kind], `${kind} after a resize`);
      await ctx.close();
    }
  }
} finally {
  await browser.close();
  await new Promise((res) => server.httpServer.close(res));
}
check("S8 no console error or warning, no page error, no request outside the page", !problems.length, problems.slice(0, 5).join(" | "));
console.log("frame times (ms):");
for (const p of perf) console.log(`  ${p.kind.padEnd(5)} ${p.size.padEnd(8)} run ${p.run}: ${p.frames} frames, avg ${p.avg}, p95 ${p.p95}, max ${p.max}`);
let failed = 0;
for (const [name, ok, detail] of results) { console.log(`${ok ? "ok  " : "FAIL"} ${name}${ok ? "" : `  ${detail}`}`); failed += ok ? 0 : 1; }
console.log(`\n${results.length - failed}/${results.length} switch checks pass`);
process.exit(failed ? 1 : 0);
