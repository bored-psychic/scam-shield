import { globeCircle, holdGlobe, repaintGlobe, type GlobeCircle } from "../components/Globe";
import type { Theme } from "./theme";

/* The theme-switch animation (2026-10-18), from the approved prototype docs/design/theme-switch.html: its comet(), hole(), shield() and
   toScreen() are ported here with the same shapes, colours and timings, and the tuner's approved values fixed (comet 2.4 s with a 34 degree
   light cone, black hole 2.6 s). Everything inside an animation runs on its progress t (0..1), so it scales with the total time, as there.
     Dark -> light: a comet flies from the top-right to the bottom-left inside a bow shock; the light theme exists only inside the shock.
     Light -> dark: a black hole opens by the switch and the lit area shrinks into it along a wobbling, spiralling edge.
     Both: a hexagon shield wraps the globe and flares as the edge passes.
   The real page is used, not copies: a View Transition (document.startViewTransition) snapshots the page in the old theme, the theme changes in
   its callback, and the two root snapshots are clipped every frame: the comet clips the new (light) one to the shock, the black hole puts the
   old (light) one on top and clips it to the lit area. The globe's canvas is in both snapshots (held still, see Globe.tsx), so it changes along
   the same edge as the page. The comet, the hole, the streaks and the shield are drawn on one full-screen canvas with its own
   view-transition-name, so its live view sits above the page; the switch has its own too, so it flips at once and stays on top, as in the
   prototype. The clip is a paused Web Animation on the pseudo-element whose keyframes are replaced every frame: it keeps the transition alive
   until the animation is finished, and the time comes from performance.now() alone (so Playwright's clock can stop it at any moment).
   No View Transitions, reduced motion or a hidden tab: playSwitch() returns false and the caller switches at once. A resize or a hidden tab
   mid-animation skips the transition: the page is already in the new theme, and everything is cleared. CSS: the "theme switch" block in styles.css. */

export const COMET_MS = 2400;   // dark -> light
export const HOLE_MS = 2600;    // light -> dark
export const CONE_DEG = 34;     // the light cone behind the comet, full opening (17 degrees each side of its path)

export type Pt = [number, number];
type Kind = "comet" | "hole";
type Draw = (t: number, now: number) => Pt[];   // draws one frame of the effects and returns the clip polygon (screen px)

const D2R = Math.PI / 180;
const ease = (x: number) => (x < .5 ? 2 * x * x : 1 - Math.pow(-2 * x + 2, 2) / 2);
const cl = (x: number) => Math.max(0, Math.min(1, x));

/** Cuts a polygon down to the screen plus a 20 px margin (Sutherland-Hodgman). Chrome mis-draws clip-path polygons whose points lie
    thousands of px off-screen. */
export function toScreen(pts: Pt[], W: number, H: number): Pt[] {
  const m = 20, edges: [0 | 1, number, number][] = [[0, -m, 1], [0, W + m, -1], [1, -m, 1], [1, H + m, -1]];
  for (const [ax, v, s] of edges) {
    const out: Pt[] = [], inside = (p: Pt) => s * (p[ax] - v) >= 0;
    for (let i = 0; i < pts.length; i++) {
      const a = pts[i], b = pts[(i + 1) % pts.length], ia = inside(a), ib = inside(b);
      if (ia) out.push(a);
      if (ia !== ib) { const k = (v - a[ax]) / (b[ax] - a[ax]); out.push([a[0] + (b[0] - a[0]) * k, a[1] + (b[1] - a[1]) * k]); }
    }
    pts = out;
  }
  return pts;
}

/** The comet's path and bow shock, in screen px: the head at progress t, the shock's half-angle, and its outline (a Billig hyperbola with nose
    radius 34 px standing 16 px ahead of the head, flaring into a cone; closed far behind). */
export function cometShape(t: number, W: number, H: number) {
  const A: Pt = [W + 90, -90], B: Pt = [-90, H + 90], len = Math.hypot(B[0] - A[0], B[1] - A[1]);
  const d: Pt = [(B[0] - A[0]) / len, (B[1] - A[1]) / len], n: Pt = [-d[1], d[0]];
  const k = cl(t / .8), travel = (k * k * (3 - 2 * k)) * .3 + k * .7;   // the head crosses in the first 80%, close to a steady speed
  const head: Pt = [A[0] + d[0] * travel * (len + 260), A[1] + d[1] * travel * (len + 260)];
  const half0 = CONE_DEG / 2, beta = (half0 + (88 - half0) * ease(cl((t - .6) / .35))) * D2R;   // after the comet leaves, the cone opens to ~88 degrees
  const shockX = (r: number) => { const tb = Math.tan(beta); return SO - RC / (tb * tb) * (Math.sqrt(1 + (r * tb / RC) * (r * tb / RC)) - 1); };
  const pt = (x: number, r: number): Pt => [head[0] + d[0] * x + n[0] * r, head[1] + d[1] * x + n[1] * r];
  const outline: Pt[] = [];
  for (let i = -40; i <= 40; i++) { const u = i / 40, r = Math.sign(u) * u * u * BIG; outline.push(pt(shockX(r), r)); }   // dense near the nose
  const xe = shockX(BIG) - BIG; outline.push(pt(xe, BIG), pt(xe, -BIG));
  return { k, head, beta, d, n, len, shockX, pt, outline };
}
const RC = 34, SO = 16, CORE = 9, BIG = 5000;

/** The black hole: its centre (at the switch, at least 110 px from the screen edges), and the lit area's reach at progress t: the farthest
    corner (+40 px) x (1 - k^3), shrinking faster and faster, gone from t = .82. */
export function holeShape(W: number, H: number, button: Pick<DOMRect, "left" | "top" | "width" | "height"> | null) {
  const bx = button ? button.left + button.width / 2 : W, by = button ? button.top + button.height / 2 : 0;
  const P: Pt = [Math.min(bx, W - 110), Math.max(by, 110)];
  const far = Math.max(...[[0, 0], [W, 0], [0, H], [W, H]].map((c) => Math.hypot(c[0] - P[0], c[1] - P[1]))) + 40;
  const radius = (t: number) => { const k = cl((t - .1) / .72); return far * (1 - k * k * k); };
  const edgeR = (R: number, a: number, t: number) => Math.max(0, R * (1 + .14 * Math.sin(3 * a + 9 * t) + .07 * Math.sin(5 * a - 14 * t)));
  const lit = (t: number): Pt[] => {   // the lit region: a wobbling, spiral-edged blob around the hole
    const R = radius(t), pts: Pt[] = [];
    for (let i = 0; i < 96; i++) { const a = i / 96 * 6.283 + 2.2 * (1 - R / far), rr = edgeR(R, a, t); pts.push([P[0] + Math.cos(a) * rr, P[1] + Math.sin(a) * rr]); }
    return pts;
  };
  return { P, far, radius, edgeR, lit };
}

// The effects' colours: r, g, b triplets from the --fx-* tokens in styles.css (the prototype's values), mixed with each frame's alpha here.
const TOKENS = ["white", "light", "shock-mid", "shock-end", "shock-glow", "warm-glow", "layer-end", "tail-1", "tail-2", "tail-3", "spark", "spark-hot",
  "head", "head-mid", "head-edge", "edge", "streak-warm", "halo", "halo-red", "ring-hot", "ring", "ring-red", "ring-glow", "void", "void-glow", "flash",
  "shield-dark", "shield-light"] as const;
type Ink = (name: (typeof TOKENS)[number], alpha?: number) => string;
function inks(): Ink {
  const cs = getComputedStyle(document.documentElement), rgb = new Map(TOKENS.map((k) => [k, cs.getPropertyValue(`--fx-${k}`).trim()]));
  return (k, a = 1) => `rgba(${rgb.get(k)}, ${a})`;
}

// The hexagon shield: a bubble 1.1 x the globe's radius, its lattice mostly near the rim, flaring with `pulse`.
function shield(f: CanvasRenderingContext2D, g: GlobeCircle, a: number, pulse: number, tint: (alpha: number) => string) {
  if (a <= 0) return;
  const R = g.r * 1.1;
  f.save(); f.beginPath(); f.arc(g.cx, g.cy, R, 0, 6.283); f.clip();
  const body = f.createRadialGradient(g.cx, g.cy, R * .7, g.cx, g.cy, R);
  body.addColorStop(0, tint(0)); body.addColorStop(.85, tint(.06 * a)); body.addColorStop(1, tint((.22 + .3 * pulse) * a));
  f.fillStyle = body; f.fillRect(g.cx - R, g.cy - R, 2 * R, 2 * R);
  const hs = Math.max(16, R / 11), w = hs * Math.sqrt(3);
  f.lineWidth = 1; f.strokeStyle = tint((.16 + .4 * pulse) * a); f.beginPath();
  for (let row = -14; row <= 14; row++) for (let col = -14; col <= 14; col++) {
    const x = g.cx + col * w + (row & 1 ? w / 2 : 0), y = g.cy + row * hs * 1.5, d = Math.hypot(x - g.cx, y - g.cy) / R;
    if (d > 1.05 || d < .55) continue;   // the lattice shows mostly near the rim, like a curved surface
    for (let k = 0; k < 6; k++) { const an = Math.PI / 6 + k * Math.PI / 3, px = x + hs * Math.cos(an), py = y + hs * Math.sin(an); if (k) f.lineTo(px, py); else f.moveTo(px, py); }
    f.closePath();
  }
  f.stroke(); f.restore();
  f.beginPath(); f.arc(g.cx, g.cy, R, 0, 6.283); f.lineWidth = 1.5 + 2 * pulse; f.strokeStyle = tint((.55 + .45 * pulse) * a);
  f.shadowColor = tint(.9); f.shadowBlur = 18 + 30 * pulse; f.stroke(); f.shadowBlur = 0;
}

// ---- dark -> light: the comet and its bow shock (the prototype's comet()) ----
function comet(f: CanvasRenderingContext2D, W: number, H: number, g: GlobeCircle | null, ink: Ink): Draw {
  let seen = 0;   // how far the shock front has passed the globe: the shield turns to its light colour after
  const s0 = cometShape(0, W, H), tail = Math.max(220, s0.len * .24);
  const dark = (a: number) => ink("shield-dark", a), light = (a: number) => ink("shield-light", a);
  return (t, now) => {
    const { k, head: h, d, n, shockX, pt, outline } = cometShape(t, W, H);
    f.clearRect(0, 0, W, H);
    const fade = 1 - cl((t - .78) / .22);
    if (fade > 0) {
      // the shock front: bright at the nose, fading along both arms
      const far = pt(-Math.min(900, s0.len * .7), 0), nose = pt(SO, 0), sg = f.createLinearGradient(nose[0], nose[1], far[0], far[1]);
      sg.addColorStop(0, ink("light", fade)); sg.addColorStop(.3, ink("shock-mid", .5 * fade)); sg.addColorStop(1, ink("shock-end", 0));
      f.strokeStyle = sg; f.lineWidth = 2.4; f.shadowColor = ink("shock-glow", fade); f.shadowBlur = 16; f.beginPath();
      for (let i = -60; i <= 60; i++) { const r = i / 60 * 1200, p = pt(shockX(r), r); if (i === -60) f.moveTo(p[0], p[1]); else f.lineTo(p[0], p[1]); }
      f.stroke(); f.shadowBlur = 0;
      // compressed hot gas between the shock and the comet (the glowing shock layer)
      const c0 = pt(SO * .4, 0), lay = f.createRadialGradient(c0[0], c0[1], 0, c0[0], c0[1], RC * 1.8);
      lay.addColorStop(0, ink("white", .9 * fade)); lay.addColorStop(.35, ink("warm-glow", .55 * fade)); lay.addColorStop(1, ink("layer-end", 0));
      f.fillStyle = lay; f.beginPath(); f.arc(c0[0], c0[1], RC * 1.8, 0, 6.283); f.fill();
    }
    if (k < 1) {
      // the wake: a narrow tail that frays into turbulence further back
      const tl = pt(-tail, 0), tg = f.createLinearGradient(h[0], h[1], tl[0], tl[1]);
      tg.addColorStop(0, ink("white", .9)); tg.addColorStop(.15, ink("tail-1", .75)); tg.addColorStop(.6, ink("tail-2", .3)); tg.addColorStop(1, ink("tail-3", 0));
      const a1 = pt(0, CORE * .9), a2 = pt(0, -CORE * .9), b1 = pt(-tail * .45, CORE * .5), b2 = pt(-tail * .45, -CORE * .5), c1 = pt(-tail, 22), c2 = pt(-tail, -22);
      f.fillStyle = tg; f.beginPath(); f.moveTo(a1[0], a1[1]); f.quadraticCurveTo(b1[0], b1[1], c1[0], c1[1]); f.lineTo(c2[0], c2[1]); f.quadraticCurveTo(b2[0], b2[1], a2[0], a2[1]); f.fill();
      for (let j = 0; j < 26; j++) {   // turbulent puffs and sparks behind
        const u = .35 + .65 * ((j * 37) % 100) / 100, wob = Math.sin(now / 90 + j * 1.7) * 9 * u, q = pt(-tail * u, wob + ((j * 53) % 21 - 10) * 1.6 * u);
        f.globalAlpha = .5 * (1 - u) + .05; f.fillStyle = j % 3 ? ink("spark") : ink("spark-hot");
        f.beginPath(); f.arc(q[0], q[1], 1 + 3.5 * u * (j % 3 ? .4 : 1), 0, 6.283); f.fill();
      }
      f.globalAlpha = 1;
      const hg = f.createRadialGradient(h[0], h[1], 0, h[0], h[1], CORE * 2.4);   // the comet itself, white-hot
      hg.addColorStop(0, ink("white")); hg.addColorStop(.42, ink("head")); hg.addColorStop(.6, ink("head-mid", .9)); hg.addColorStop(1, ink("head-edge", 0));
      f.fillStyle = hg; f.beginPath(); f.arc(h[0], h[1], CORE * 2.4, 0, 6.283); f.fill();
    }
    if (g) {
      // shield: up before the comet arrives, flares as the shock front crosses the globe, gone at the end
      const gx = (g.cx - h[0]) * d[0] + (g.cy - h[1]) * d[1], gr = (g.cx - h[0]) * n[0] + (g.cy - h[1]) * n[1];
      const margin = shockX(gr) - gx;
      seen = Math.max(seen, cl(margin / (g.r * .9) + .2));
      const hit = Math.exp(-Math.pow(margin / (g.r * .35), 2)) * fade;
      shield(f, g, cl(t / .1) * cl((1 - t) / .12), Math.max(hit, .15), seen > .5 ? light : dark);
    }
    return toScreen(outline, W, H);
  };
}

// ---- light -> dark: the black hole (the prototype's hole()) ----
function hole(f: CanvasRenderingContext2D, W: number, H: number, g: GlobeCircle | null, ink: Ink, button: DOMRect | null): Draw {
  const { P, far, radius, edgeR, lit } = holeShape(W, H, button);
  const maxR = Math.min(64, W * .11), gd = g ? Math.hypot(g.cx - P[0], g.cy - P[1]) : 0, light = (a: number) => ink("shield-light", a);
  const parts = Array.from({ length: 320 }, () => ({ ts: .06 + .8 * Math.random(), dur: .2 + .2 * Math.random(), a0: Math.random() * 6.283, w: .5 + Math.random() }));
  return (t, now) => {
    const open = ease(cl(t / .14)) * (1 - ease(cl((t - .88) / .12))), R = radius(t), feed = cl((t - .1) / .7), edge = lit(t);
    f.clearRect(0, 0, W, H);
    // the retreating edge of the light glows as it is pulled
    if (R > 2) {
      f.beginPath(); edge.forEach((p, i) => (i ? f.lineTo(p[0], p[1]) : f.moveTo(p[0], p[1]))); f.closePath();
      f.strokeStyle = ink("edge", .25 + .5 * feed); f.lineWidth = 2; f.shadowColor = ink("warm-glow", .9); f.shadowBlur = 22; f.stroke(); f.shadowBlur = 0;
    }
    // streams of light spiralling in: they start on the edge, speed up and narrow as they fall
    f.lineCap = "round";
    for (let i = 0; i < parts.length; i++) {
      const q = parts[i], u = (t - q.ts) / q.dur;
      if (u <= 0 || u >= 1) continue;
      const r0 = Math.min(edgeR(radius(q.ts), q.a0, q.ts), far * .8);
      const pos = (v: number): Pt => { const rr = r0 * Math.pow(1 - v, 1.8) + maxR * .5 * open, a = q.a0 + 3.2 * v * v; return [P[0] + Math.cos(a) * rr, P[1] + Math.sin(a) * rr]; };
      const p1 = pos(Math.max(0, u - .09)), p2 = pos(u);
      f.globalAlpha = .85 * Math.sin(Math.PI * Math.min(1, u * 1.2)); f.strokeStyle = i % 4 ? ink("light") : ink("streak-warm"); f.lineWidth = q.w * (1.6 - u);
      f.beginPath(); f.moveTo(p1[0], p1[1]); f.lineTo(p2[0], p2[1]); f.stroke();
    }
    f.globalAlpha = 1;
    const R0 = maxR * open;
    if (R0 > .5) {
      // lensing glow, an accretion ring that brightens as it feeds, and the event horizon
      const halo = f.createRadialGradient(P[0], P[1], R0 * .8, P[0], P[1], R0 * (3 + 1.5 * feed));
      halo.addColorStop(0, ink("halo", .35 + .4 * feed)); halo.addColorStop(.4, ink("halo-red", .12 + .2 * feed)); halo.addColorStop(1, ink("void", 0));
      f.fillStyle = halo; f.beginPath(); f.arc(P[0], P[1], R0 * (3 + 1.5 * feed), 0, 6.283); f.fill();
      f.save(); f.translate(P[0], P[1]); f.rotate(-.35); f.scale(1, .38); f.rotate(now / 220);
      const ring = f.createConicGradient(0, 0, 0);
      ring.addColorStop(0, ink("ring-hot")); ring.addColorStop(.25, ink("ring", .8)); ring.addColorStop(.5, ink("ring-red", .3)); ring.addColorStop(.75, ink("ring", .8)); ring.addColorStop(1, ink("ring-hot"));
      f.strokeStyle = ring; f.lineWidth = R0 * (.25 + .3 * feed); f.shadowColor = ink("ring-glow", .9); f.shadowBlur = 10 + 20 * feed;
      f.beginPath(); f.arc(0, 0, R0 * 1.6, 0, 6.283); f.stroke(); f.restore(); f.shadowBlur = 0;
      f.fillStyle = ink("void"); f.shadowColor = ink("void-glow", .9); f.shadowBlur = R0 * .5; f.beginPath(); f.arc(P[0], P[1], R0, 0, 6.283); f.fill(); f.shadowBlur = 0;
    }
    if (t > .86 && t < .98) { const fl = 1 - Math.abs(t - .92) / .06; f.fillStyle = ink("flash", .6 * fl); f.beginPath(); f.arc(P[0], P[1], 6 + 46 * fl, 0, 6.283); f.fill(); }
    // the shield holds the globe steady and shudders as the light is torn from around it
    if (g) {
      const pass = Math.exp(-Math.pow((R - gd) / (g.r * .6), 2));
      shield(f, g, cl(t / .1) * cl((1 - t) / .12), .2 + .6 * pass * (.6 + .4 * Math.sin(now / 40)), light);
    }
    return R > 2 ? toScreen(edge, W, H) : [];
  };
}

const polygon = (pts: Pt[]) => (pts.length > 2 ? `polygon(${pts.map((p) => `${p[0].toFixed(1)}px ${p[1].toFixed(1)}px`).join(",")})` : "polygon(0 0, 0 0, 0 0)");

type Run = { raf: number; anim: Animation | null; canvas: HTMLCanvasElement | null; vt: ViewTransition | null; over: boolean; skip: () => void; hidden: () => void };
let active: Run | null = null;

/** True while an animation runs: clicks on the switch are ignored then. */
export const switching = () => active !== null;

/** Animates the switch to `to`. `apply` switches the theme's attribute; it is called once the page has been snapshotted in the old theme. Returns
    false, without calling `apply`, when it cannot animate (no View Transitions, reduced motion, a hidden tab, one already running): the caller
    then switches at once. */
export function playSwitch(to: Theme, apply: () => void, button: HTMLElement | null): boolean {
  if (active || typeof document.startViewTransition !== "function" || document.hidden || matchMedia("(prefers-reduced-motion: reduce)").matches) return false;
  const kind: Kind = to === "light" ? "comet" : "hole", root = document.documentElement;
  const run: Run = { raf: 0, anim: null, canvas: null, vt: null, over: false,
    skip: () => run.vt?.skipTransition(), hidden: () => { if (document.hidden) run.skip(); } };
  active = run;
  root.classList.add("ss-switch", `ss-${kind}`);   // before the old snapshot: the switch gets its own view-transition-name
  holdGlobe(true);
  addEventListener("resize", run.skip);
  document.addEventListener("visibilitychange", run.hidden);
  let vt: ViewTransition;
  try {
    vt = document.startViewTransition(() => {
      apply();
      repaintGlobe();
      const c = document.createElement("canvas");   // the effects layer, in the new page only (so it has no old view)
      c.className = "ss-fx"; c.setAttribute("aria-hidden", "true");
      document.body.appendChild(c);
      run.canvas = c;
    });
  } catch {
    end(run);
    return false;
  }
  run.vt = vt;
  vt.ready.then(() => start(run, kind, button), () => {});   // rejected when skipped before it began; `finished` still cleans up
  vt.finished.then(() => end(run), () => end(run));
  return true;
}

function start(run: Run, kind: Kind, button: HTMLElement | null) {
  const c = run.canvas, f = c?.getContext("2d");
  if (run.over || !c || !f) { run.skip(); return; }
  const W = innerWidth, H = innerHeight, dpr = Math.min(devicePixelRatio || 1, 2);
  c.width = Math.round(W * dpr); c.height = Math.round(H * dpr); f.setTransform(dpr, 0, 0, dpr, 0, 0);
  const g = globeCircle(), ink = inks(), T = kind === "comet" ? COMET_MS : HOLE_MS;
  const draw = kind === "comet" ? comet(f, W, H, g, ink) : hole(f, W, H, g, ink, button?.getBoundingClientRect() ?? null);
  const t0 = performance.now();
  let anim: Animation | null = null;
  const step = () => {
    run.raf = 0;
    if (run.over) return;
    const now = performance.now(), t = cl((now - t0) / T), clip = polygon(draw(t, now)), frames = [{ clipPath: clip }, { clipPath: clip }];
    if (!anim) {
      anim = run.anim = document.documentElement.animate(frames, { duration: T, fill: "forwards",
        pseudoElement: kind === "comet" ? "::view-transition-new(root)" : "::view-transition-old(root)" });
      anim.pause();
    } else (anim.effect as KeyframeEffect).setKeyframes(frames);
    if (t < 1) run.raf = requestAnimationFrame(step);
    else { f.clearRect(0, 0, W, H); anim.finish(); }   // the transition ends with the next frame, on the final clip
  };
  step();
}

function end(run: Run) {
  if (run.over) return;
  run.over = true;
  cancelAnimationFrame(run.raf);
  run.anim?.cancel();
  run.canvas?.remove();
  document.documentElement.classList.remove("ss-switch", "ss-comet", "ss-hole");
  removeEventListener("resize", run.skip);
  document.removeEventListener("visibilitychange", run.hidden);
  holdGlobe(false);
  if (active === run) active = null;
}
