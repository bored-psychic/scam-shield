import { beginGlobeSwitch, clipGlobe, endGlobeSwitch, globeCircle, rethemeGlobe, type GlobeCircle } from "../components/Globe";
import type { Theme } from "./theme";

/* The theme-switch animation (2026-10-18), from the approved prototype docs/design/theme-switch.html: its comet(), hole(), shield() and
   toScreen() are ported here with the same shapes, colours and timings, and the tuner's approved values fixed (comet 2.4 s with a 34 degree
   light cone, black hole 2.6 s). Everything inside an animation runs on its progress t (0..1), so it scales with the total time, as there.
     Dark -> light: a comet flies from the top-right to the bottom-left inside a bow shock; the light theme exists only inside the shock.
     Light -> dark: a black hole opens by the switch and the lit area shrinks into it along a wobbling, spiralling edge.
     Both: a hexagon shield wraps the globe and flares as the edge passes.
   The real page is used, not copies: a View Transition (document.startViewTransition) snapshots the page in the old theme, the theme changes in
   its callback, and every frame one clip polygon (the light side: the comet's shock, the black hole's lit area) cuts the snapshots. The page is
   split into layers, each its own snapshot group (bottom to top; CSS: the "theme switch" block in styles.css):
     root        only the page background now. The comet clips the new (light) one to the polygon; the black hole puts the old (light) one on
                 top and clips it so.
     ss-globe    the globe's stage, its live (new) view only: the globe keeps turning, and draws itself in both themes through a stencil cut
                 from the same polygon (clipGlobe, Globe.tsx), the light look inside and the dark one outside.
     ss-vig      the vignette, then
     .ss-pane    one empty pane per glass panel over the globe (anything with a backdrop-filter in the dark theme that is not inside another):
                 its group wears the panel's backdrop-filter and shape on the dark side, so it blurs the live globe beneath as the panel itself
                 does outside the switch (a panel's own snapshot has nothing behind it to blur); the light theme's panels are solid.
     ss-head, ss-main, ss-foot, ss-tip   the header, main, footer and tooltip: these have transparent parts, so both views are clipped, the
                 light one to the polygon and the dark one to the rest of the screen (an even-odd polygon with the light side as its hole).
     ss-fx       the effects: the comet, the hole, the streaks and the shield, drawn on one full-screen canvas (new view only).
     ss-btn      the switch itself, in its new state from the first frame, on top, as in the prototype.
   Each clip is a paused Web Animation on its pseudo-element whose keyframes are replaced every frame (cut to the screen first, offset to the
   layer's own box): the animations keep the transition alive until they are finished, and the time comes from performance.now() alone (so
   Playwright's clock can stop it at any moment). The globe is drawn by the same frame with the same polygon. During the transition every
   pointer event goes to <html>; Globe.tsx turns the globe for a drag there.
   No View Transitions, reduced motion or a hidden tab: playSwitch() returns false and the caller switches at once. A resize or a hidden tab
   mid-animation skips the transition: the page is already in the new theme, and everything is cleared. CSS: the "theme switch" block in styles.css. */

export const COMET_MS = 2400;   // dark -> light
export const HOLE_MS = 2600;    // light -> dark
export const CONE_DEG = 34;     // the light cone behind the comet, full opening (17 degrees each side of its path)

export type Pt = [number, number];
export type Side = "in" | "out" | "across";   // a box against the clip polygon: all inside it, all outside, or across its edge
type Kind = "comet" | "hole";
type Draw = (t: number, now: number, g: GlobeCircle | null) => Pt[];   // draws one frame of the effects round the globe g and returns the clip polygon (screen px)

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
function comet(f: CanvasRenderingContext2D, W: number, H: number, ink: Ink): Draw {
  let seen = 0;   // how far the shock front has passed the globe: the shield turns to its light colour after
  const s0 = cometShape(0, W, H), tail = Math.max(220, s0.len * .24);
  const dark = (a: number) => ink("shield-dark", a), light = (a: number) => ink("shield-light", a);
  return (t, now, g) => {
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
function hole(f: CanvasRenderingContext2D, W: number, H: number, ink: Ink, button: DOMRect | null): Draw {
  const { P, far, radius, edgeR, lit } = holeShape(W, H, button);
  const maxR = Math.min(64, W * .11), light = (a: number) => ink("shield-light", a);
  const parts = Array.from({ length: 320 }, () => ({ ts: .06 + .8 * Math.random(), dur: .2 + .2 * Math.random(), a0: Math.random() * 6.283, w: .5 + Math.random() }));
  return (t, now, g) => {
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
      const pass = Math.exp(-Math.pow((R - Math.hypot(g.cx - P[0], g.cy - P[1])) / (g.r * .6), 2));
      shield(f, g, cl(t / .1) * cl((1 - t) / .12), .2 + .6 * pass * (.6 + .4 * Math.sin(now / 40)), light);
    }
    return R > 2 ? toScreen(edge, W, H) : [];
  };
}

// Clip paths, offset to a layer's own box (dx, dy: its top left on screen). Inside: the polygon. Outside: the rest of the screen (+20 px) as an
// even-odd polygon with the polygon as its hole (the bridge to the hole and back cancels out).
const NONE = "polygon(0 0, 0 0, 0 0)";
const at = (p: Pt, dx: number, dy: number) => `${(p[0] - dx).toFixed(2)}px ${(p[1] - dy).toFixed(2)}px`;
export function clipInside(pts: Pt[], dx = 0, dy = 0) {
  return pts.length > 2 ? `polygon(${pts.map((p) => at(p, dx, dy)).join(",")})` : NONE;
}
export function clipOutside(pts: Pt[], W: number, H: number, dx = 0, dy = 0) {
  const box: Pt[] = [[-20, -20], [W + 20, -20], [W + 20, H + 20], [-20, H + 20]], ring = pts.length > 2 ? [...box, box[0], ...pts, pts[0]] : box;
  return `polygon(evenodd, ${ring.map((p) => at(p, dx, dy)).join(",")})`;
}

/** Where the box [x0, x1] x [y0, y1] lies against the clip polygon `pts`: all inside, all outside (also when there is no polygon), or across
    its edge (an edge of the polygon meets the box). */
export function boxSide(pts: Pt[], x0: number, y0: number, x1: number, y1: number): Side {
  if (pts.length < 3) return "out";
  for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {   // Liang-Barsky: does the edge j -> i meet the box?
    const a = pts[j], dx = pts[i][0] - a[0], dy = pts[i][1] - a[1];
    let t0 = 0, t1 = 1, meets = true;
    for (const [p, q] of [[-dx, a[0] - x0], [dx, x1 - a[0]], [-dy, a[1] - y0], [dy, y1 - a[1]]]) {
      if (p === 0) { if (q < 0) { meets = false; break; } continue; }
      const r = q / p;
      if (p < 0) { if (r > t1) { meets = false; break; } t0 = Math.max(t0, r); } else { if (r < t0) { meets = false; break; } t1 = Math.min(t1, r); }
    }
    if (meets) return "across";
  }
  const cx = (x0 + x1) / 2, cy = (y0 + y1) / 2;   // no edge meets it: its centre says which side it is on (even-odd)
  let lit = false;
  for (let i = 0, j = pts.length - 1; i < pts.length; j = i++)
    if ((pts[i][1] > cy) !== (pts[j][1] > cy) && cx < (pts[j][0] - pts[i][0]) * (cy - pts[i][1]) / (pts[j][1] - pts[i][1]) + pts[i][0]) lit = !lit;
  return lit ? "in" : "out";
}

// The layers whose two views are both clipped, bottom to top (their view-transition-names are in styles.css); the root, the globe, the glass
// panes, the effects and the switch are handled apart. (Not body as one layer: Chrome draws body's fixed children, the footer and the
// vignette, about 35 px low in its old view.)
const LAYERS: [string, string][] = [["ss-vig", ".vignette"], ["ss-main", "#root > main"], ["ss-head", "#root > header"], ["ss-foot", "#root > footer"], ["ss-tip", ".tip"]];
// The globe's reach on screen, in its radii: the dark rim (1.12), the light glow (1.28), the arcs (up to 1.4). Glass beyond it has only the
// page's flat background colour behind it, so it needs no pane.
const GLOBE_REACH = 1.6;

type Pane = { el: Element; r: DOMRect; radius: string; filter: string; opacity: number };
/** The glass panels over the globe: each element of a layer with a backdrop-filter that is not inside another one (nor inside anything else
    that makes its own backdrop: a filter or opacity), is not a snapshot of its own (the switch) and reaches the globe. Measured while the page
    is in the dark theme. Away from the globe a panel's blur of the flat background is that colour again (within 1/255), so it is left alone. */
function glassPanes(): Pane[] {
  const out: Pane[] = [], g = globeCircle();
  if (!g) return out;   // no globe, nothing behind the glass to blur
  const reach = g.r * GLOBE_REACH, near = (r: DOMRect) => Math.hypot(Math.max(r.left - g.cx, 0, g.cx - r.right), Math.max(r.top - g.cy, 0, g.cy - r.bottom)) < reach;
  const visit = (el: Element, top: boolean) => {
    const cs = getComputedStyle(el);
    if (cs.display === "none" || (!top && cs.viewTransitionName !== "none")) return;
    if (cs.backdropFilter && cs.backdropFilter !== "none") {
      const r = el.getBoundingClientRect(), o = +cs.opacity;
      if (o > 0 && cs.visibility === "visible" && r.width >= 1 && r.height >= 1 && r.right > 0 && r.bottom > 0 && r.left < innerWidth && r.top < innerHeight && near(r))
        out.push({ el, r, radius: cs.borderRadius, filter: cs.backdropFilter, opacity: o });
      return;   // what is inside it reads its backdrop from it, in its snapshot as on the page
    }
    if (!top && (cs.filter !== "none" || +cs.opacity < 1)) return;   // the same for any other backdrop root
    for (const c of el.children) visit(c, false);
  };
  for (const [, sel] of LAYERS) { const el = document.querySelector(sel); if (el) visit(el, true); }
  return out;
}
// The panes, in the new page only, so they have no old view (like the effects canvas). The panel itself loses its own backdrop-filter while
// the switch runs (.ss-glassed): in its snapshot it would filter what lies under it there (a neighbour's shadow, nothing of the globe) and draw
// that over the same again, darkening it twice.
function addPanes(panes: Pane[]): HTMLElement[] {
  return panes.map(({ r }, i) => {
    const d = document.createElement("div");
    d.className = "ss-pane"; d.setAttribute("aria-hidden", "true");
    Object.assign(d.style, { left: `${r.left}px`, top: `${r.top}px`, width: `${r.width}px`, height: `${r.height}px` });
    d.style.setProperty("view-transition-name", `ss-pane-${i}`);
    document.body.appendChild(d);
    return d;
  });
}

// What gets clipped each frame: a pseudo-element and its style for the frame's polygon.
type View = { pseudo: string; frame: (pts: Pt[]) => Keyframe };
function views(kind: Kind, panes: Pane[], W: number, H: number): View[] {
  const light = kind === "comet" ? "new" : "old", dark = kind === "comet" ? "old" : "new";
  const out: View[] = [{ pseudo: `::view-transition-${light}(root)`, frame: (pts) => ({ clipPath: clipInside(pts) }) }];
  for (const [name, sel] of LAYERS) {
    const r = document.querySelector(sel)?.getBoundingClientRect();
    if (!r) continue;
    out.push({ pseudo: `::view-transition-${light}(${name})`, frame: (pts) => ({ clipPath: clipInside(pts, r.left, r.top) }) },
             { pseudo: `::view-transition-${dark}(${name})`, frame: (pts) => ({ clipPath: clipOutside(pts, W, H, r.left, r.top) }) });
  }
  // a pane wears its panel's glass on the dark side: unclipped while all of it is dark, hidden while all of it is light, clipped only while the
  // edge crosses it (each clip is a mask the compositor draws every frame)
  panes.forEach(({ r, filter, radius, opacity }, i) => out.push({ pseudo: `::view-transition-group(ss-pane-${i})`, frame: (pts) => {
    const side = boxSide(pts, r.left - 2, r.top - 2, r.right + 2, r.bottom + 2);
    return { backdropFilter: filter, borderRadius: radius, opacity: side === "in" ? "0" : String(opacity), clipPath: side === "across" ? clipOutside(pts, W, H, r.left, r.top) : "none" };
  } }));
  return out;
}

type Run = { raf: number; anims: Animation[]; canvas: HTMLCanvasElement | null; panes: Pane[]; paneEls: HTMLElement[]; vt: ViewTransition | null; over: boolean;
  skip: () => void; hidden: () => void };
let active: Run | null = null;

const glass = () => { const p = glassPanes(); p.forEach(({ el }) => el.classList.add("ss-glassed")); return p; };

/** True while an animation runs: clicks on the switch are ignored then. */
export const switching = () => active !== null;

/** Animates the switch to `to`. `apply` switches the theme's attribute; it is called once the page has been snapshotted in the old theme. Returns
    false, without calling `apply`, when it cannot animate (no View Transitions, reduced motion, a hidden tab, one already running): the caller
    then switches at once. */
export function playSwitch(to: Theme, apply: () => void, button: HTMLElement | null): boolean {
  if (active || typeof document.startViewTransition !== "function" || document.hidden || matchMedia("(prefers-reduced-motion: reduce)").matches) return false;
  const kind: Kind = to === "light" ? "comet" : "hole", root = document.documentElement;
  const run: Run = { raf: 0, anims: [], canvas: null, panes: [], paneEls: [], vt: null, over: false,
    skip: () => run.vt?.skipTransition(), hidden: () => { if (document.hidden) run.skip(); } };
  active = run;
  root.classList.add("ss-switch", `ss-${kind}`);   // before the old snapshot: the layers get their view-transition-names
  beginGlobeSwitch(kind === "comet");
  if (kind === "comet") run.panes = glass();   // the dark page's glass, measured while it is the page (the black hole's once it is)
  addEventListener("resize", run.skip);
  document.addEventListener("visibilitychange", run.hidden);
  let vt: ViewTransition;
  try {
    vt = document.startViewTransition(() => {
      apply();
      rethemeGlobe();
      if (kind === "hole") run.panes = glass();
      run.paneEls = addPanes(run.panes);
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
  const W = innerWidth, H = innerHeight, dpr = Math.min(devicePixelRatio || 1, 2), root = document.documentElement;
  c.width = Math.round(W * dpr); c.height = Math.round(H * dpr); f.setTransform(dpr, 0, 0, dpr, 0, 0);
  const ink = inks(), T = kind === "comet" ? COMET_MS : HOLE_MS;
  const draw = kind === "comet" ? comet(f, W, H, ink) : hole(f, W, H, ink, button?.getBoundingClientRect() ?? null);
  const vs = views(kind, run.panes, W, H);
  const t0 = performance.now();
  const step = () => {
    run.raf = 0;
    if (run.over) return;
    const now = performance.now(), t = cl((now - t0) / T), g = globeCircle(), pts = draw(t, now, g), reach = g ? g.r * GLOBE_REACH : 0;
    // the globe, on the same polygon in the same frame (drawn once while all of it is on one side)
    clipGlobe(now, pts, g ? boxSide(pts, g.cx - reach, g.cy - reach, g.cx + reach, g.cy + reach) : "across");
    const frames = vs.map((v) => { const k = v.frame(pts); return [k, k]; });
    if (!run.anims.length) run.anims = vs.map((v, i) => {
      const a = root.animate(frames[i], { duration: T, fill: "forwards", pseudoElement: v.pseudo });
      a.pause();
      return a;
    });
    else run.anims.forEach((a, i) => (a.effect as KeyframeEffect).setKeyframes(frames[i]));
    if (t < 1) run.raf = requestAnimationFrame(step);
    else { f.clearRect(0, 0, W, H); run.anims.forEach((a) => a.finish()); }   // the transition ends with the next frame, on the final clip
  };
  step();
}

function end(run: Run) {
  if (run.over) return;
  run.over = true;
  cancelAnimationFrame(run.raf);
  run.anims.forEach((a) => a.cancel());
  run.canvas?.remove();
  run.paneEls.forEach((d) => d.remove());
  run.panes.forEach((p) => p.el.classList.remove("ss-glassed"));
  document.documentElement.classList.remove("ss-switch", "ss-comet", "ss-hole");
  removeEventListener("resize", run.skip);
  document.removeEventListener("visibilitychange", run.hidden);
  endGlobeSwitch();   // one look again, and arcs again (also after a skipped or interrupted switch)
  if (active === run) active = null;
}
