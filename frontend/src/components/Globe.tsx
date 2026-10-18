import { useEffect, useEffectEvent, useRef } from "react";
import { useReducedMotion } from "motion/react";
import {
  AdditiveBlending, AlwaysStencilFunc, BackSide, type Blending, BufferAttribute, BufferGeometry, CanvasTexture, Color, ColorManagement, DoubleSide, EqualStencilFunc, Group, InvertStencilOp, Line,
  LineBasicMaterial, LineLoop, LinearSRGBColorSpace, type Material, Mesh, MeshBasicMaterial, NormalBlending, PerspectiveCamera, Points,
  PointsMaterial, RingGeometry, Scene, ShaderMaterial, SphereGeometry, Vector2, Vector3, WebGLRenderer,
} from "three";
import type { Theme } from "../lib/theme";
import type { Pt, Side } from "../lib/themeSwitch";
import LAND from "../data/land.json";     // land dots, flat [lat, lon, lat, lon, ...]
import INDIA from "../data/india.json";   // India's official outline (Natural Earth, India point of view): { rings, dots }

// The dotted globe from the prototype (docs/design/prototype-globe.html, "globe"), ported as is: same geometry, colours, timings and
// weights. Changes: everything it creates is disposed on unmount, one animation loop at most (the prototype could start a second one
// when a tab came back), pointercancel ends a drag, and with reduced motion the static globe is drawn only when it is dragged or resized.
// Colours (2026-10-18): read from the theme's --globe-* / --arc-* tokens in styles.css (the dark values are the prototype's) and re-read when
// the theme changes, without rebuilding the scene. The light theme draws with normal blending: additive light vanishes on a light page.
// Two globe styles (2026-10-18), picked by --globe-style; both are built once and the theme's is shown, so a theme switch needs no reload:
//   flat (dark): the prototype's globe as above.
//   shaded (light, docs/design/light-landing.html): a sphere darkening to its edge with a darker band on the top rim (a shader on the core), a
//   red glow measured in screen space like the reference's 2D gradient, evenly spaced round land dots (a golden-angle spiral kept on land) and
//   India's own dots in red only, with no land dot inside India's outline and no outline lines. Same camera, size, spin, drag, arcs and ripples.
// The theme switch (lib/themeSwitch.ts) shows the globe live in both themes at once, each on its side of the switch's edge: see above Globe().

export type Hit = { src: string; tgt: string; kind: "wci" | "ddos" };   // a simulated hit, country names, for the footer feed

/* Simulation driven by real published rankings (a snapshot, not live; decision G2):
   red    = cybercrime hubs, World Cybercrime Index (Bruce et al., PLOS ONE, 2024). Scores 1-5 as published; ranks 6-10 in published order, weights estimated.
   orange = top-10 DDoS source countries, Cloudflare DDoS threat report Q4 2025 (ranked, no shares published -> weight 10..1).
   every line lands in Cloudflare's top-10 most attacked locations, Q4 2025 (ranked -> weight 10..1). */
const P = {
  CN: [[39.9, 116.4], [31.23, 121.47], [23.13, 113.26]], US: [[40.71, -74.0], [37.77, -122.42], [41.88, -87.63], [29.76, -95.37]],
  RU: [[55.75, 37.62], [59.94, 30.31], [56.84, 60.6]], UA: [[50.45, 30.52], [49.99, 36.23], [46.48, 30.72]], NG: [[6.52, 3.38], [9.08, 7.4]],
  RO: [[44.43, 26.1], [46.77, 23.6]], KP: [[39.03, 125.75]], GB: [[51.51, -0.13], [53.48, -2.24]], BR: [[-23.55, -46.63], [-22.91, -43.17], [-15.79, -47.88]],
  IN: [[28.61, 77.21], [19.08, 72.88], [12.97, 77.59], [22.57, 88.36]], BD: [[23.81, 90.41]], EC: [[-0.18, -78.47], [-2.19, -79.89]],
  ID: [[-6.2, 106.85], [-7.25, 112.75]], AR: [[-34.6, -58.38]], HK: [[22.32, 114.17]], VN: [[21.03, 105.85], [10.82, 106.63]],
  TW: [[25.03, 121.56]], SG: [[1.35, 103.82]], PE: [[-12.05, -77.04]], DE: [[52.52, 13.4], [50.11, 8.68]], AZ: [[40.41, 49.87]],
} satisfies Record<string, [number, number][]>;
type Code = keyof typeof P;
const NAME: Record<Code, string> = { CN: "China", US: "United States", RU: "Russia", UA: "Ukraine", NG: "Nigeria", RO: "Romania", KP: "North Korea", GB: "UK", BR: "Brazil", IN: "India",
  BD: "Bangladesh", EC: "Ecuador", ID: "Indonesia", AR: "Argentina", HK: "Hong Kong", VN: "Vietnam", TW: "Taiwan", SG: "Singapore", PE: "Peru", DE: "Germany", AZ: "Azerbaijan" };
const WCI: [Code, number][] = [["RU", 58.39], ["UA", 36.44], ["CN", 27.84], ["US", 25.01], ["NG", 21.28], ["RO", 15], ["KP", 11], ["GB", 9], ["BR", 8.5], ["IN", 6]];
const ranked = (codes: Code[]): [Code, number][] => codes.map((c, i) => [c, 10 - i]);
const CF_SRC = ranked(["BD", "EC", "ID", "AR", "HK", "UA", "VN", "TW", "SG", "PE"]);
const CF_TGT = ranked(["CN", "HK", "DE", "BR", "US", "GB", "VN", "AZ", "IN", "SG"]);

const R = 100;   // globe radius
const N = 72;    // points per arc

function vec(lat: number, lon: number, r = R) {
  const phi = (90 - lat) * Math.PI / 180, th = (lon + 180) * Math.PI / 180;
  return new Vector3(-r * Math.sin(phi) * Math.cos(th), r * Math.cos(phi), r * Math.sin(phi) * Math.sin(th));
}
function pick(list: [Code, number][]): Code {
  const tot = list.reduce((a, [, w]) => a + w, 0); let r = Math.random() * tot;
  for (const [c, w] of list) { if ((r -= w) <= 0) return c; }
  return list[0][0];
}
function spot(c: Code) {
  const p = P[c][Math.floor(Math.random() * P[c].length)];
  return vec(p[0] + (Math.random() - .5) * 2.2, p[1] + (Math.random() - .5) * 2.2).normalize();
}
// The shaded style's dots, built once per page. Land: 15,000 points of a golden-angle spiral (evenly spaced over the sphere), kept where a 1-degree
// grid made from land.json (widened by one cell) has land and outside India's official outline. India: every dot of india.json. Both as
// in docs/design/light-landing.html.
function inIndia(lat: number, lon: number) {
  if (lat < 5 || lat > 38 || lon < 67 || lon > 99) return false;
  let hit = false;
  for (const r of INDIA.rings)
    for (let i = 0, j = r.length - 2; i < r.length; j = i, i += 2)
      if ((r[i] > lat) !== (r[j] > lat) && lon < (r[j + 1] - r[i + 1]) * (lat - r[i]) / (r[j] - r[i]) + r[i + 1]) hit = !hit;
  return hit;
}
let spiral: { land: Float32Array; india: Float32Array } | null = null;
function spiralDots() {
  if (spiral) return spiral;
  const D2R = Math.PI / 180, cell = (lat: number, lon: number) => lat * 1000 + ((lon + 540) % 360), grid = new Set<number>();
  for (let i = 0; i < LAND.length; i += 2) {
    const la = Math.round(LAND[i]), lo = Math.round(LAND[i + 1]), rl = Math.min(6, Math.ceil(1 / Math.max(.2, Math.cos(LAND[i] * D2R))));
    for (let a = -1; a <= 1; a++) for (let b = -rl; b <= rl; b++) grid.add(cell(la + a, lo + b));
  }
  const land: number[] = [], n = 15000, ga = Math.PI * (3 - Math.sqrt(5));
  for (let k = 0; k < n; k++) {
    const lat = Math.asin(1 - 2 * (k + .5) / n) / D2R, lon = ((k * ga) % (2 * Math.PI) - Math.PI) / D2R;
    if (inIndia(lat, lon) || !grid.has(cell(Math.round(lat), Math.round(lon)))) continue;
    const v = vec(lat, lon, R * 1.003); land.push(v.x, v.y, v.z);
  }
  const india: number[] = [];
  for (let i = 0; i < INDIA.dots.length; i += 2) { const v = vec(INDIA.dots[i], INDIA.dots[i + 1], R * 1.004); india.push(v.x, v.y, v.z); }
  return (spiral = { land: new Float32Array(land), india: new Float32Array(india) });
}

// Shaders of the shaded style. Round dots sized like three's attenuated points (uSize x half the buffer height / depth, so a size of 2k is the
// reference's k), fading from 1 to .45 towards the globe's edge and gone on the far side, as in the reference.
const DOT_VS = `uniform float uSize; uniform float uScale; varying float vA; varying float vR;
void main(){
  vec4 wp = modelMatrix * vec4(position, 1.0);
  float facing = dot(normalize(wp.xyz), normalize(cameraPosition - wp.xyz));
  vA = facing <= 0.0 ? 0.0 : 0.45 + 0.55 * min(1.0, facing * 1.6);
  vec4 mv = viewMatrix * wp;
  vR = 0.5 * uSize * uScale / -mv.z;
  gl_PointSize = 2.0 * vR + 1.0;
  gl_Position = projectionMatrix * mv;
}`;
const DOT_FS = `uniform vec3 uColor; uniform float uOpacity; varying float vA; varying float vR;
void main(){
  if (vA <= 0.0) discard;
  float r = length(gl_PointCoord - 0.5) * (2.0 * vR + 1.0);
  float a = vA * uOpacity * clamp(vR - r + 0.5, 0.0, 1.0);
  if (a <= 0.0) discard;
  gl_FragColor = vec4(uColor, a);
}`;
// The sphere: s = the sine of the view angle (0 in the middle, 1 at the silhouette: the radial position on the disc), through the four stops;
// then the top band: a ring around a point .22 radii below the middle, so it is thickest along the top rim (the reference's second gradient).
const SPHERE_VS = `varying vec3 vN; varying vec3 vV;
void main(){ vN = normalize(normalMatrix * normal); vec4 mv = modelViewMatrix * vec4(position, 1.0); vV = mv.xyz; gl_Position = projectionMatrix * mv; }`;
const SPHERE_FS = `uniform vec3 uS0; uniform vec3 uS1; uniform vec3 uS2; uniform vec3 uS3; uniform vec3 uShade; uniform float uShadeA;
varying vec3 vN; varying vec3 vV;
void main(){
  vec3 n = normalize(vN), v = normalize(-vV);
  vec3 p = n - dot(n, v) * v;   // the normal's part across the line of sight: its length is the radial position, its xy the screen direction
  vec2 q = p.xy;
  float s = clamp(length(p), 0.0, 1.0);
  vec3 c = s < 0.7 ? mix(uS0, uS1, clamp((s - 0.05) / 0.65, 0.0, 1.0)) : s < 0.93 ? mix(uS1, uS2, (s - 0.7) / 0.23) : mix(uS2, uS3, (s - 0.93) / 0.07);
  float u = (length(q - vec2(0.0, -0.22)) - 0.55) / 0.67;
  c = mix(c, uShade, uShadeA * clamp((u - 0.62) / 0.38, 0.0, 1.0));
  gl_FragColor = vec4(c, 1.0);
}`;

function dispose(o: Mesh | Points | Line) {
  o.geometry.dispose();
  (Array.isArray(o.material) ? o.material : [o.material]).forEach((m) => m.dispose());
}

type Arc = { id: number; line: Line<BufferGeometry, LineBasicMaterial>; head: Points<BufferGeometry, PointsMaterial>; headAt: Float32Array; headPos: BufferAttribute;
  pts: Float32Array; b: Vector3; kind: Hit["kind"]; t: number; dur: number; hit: boolean; ev: [Code, Code, Hit["kind"]] };
type Ripple = { m: Mesh<RingGeometry, MeshBasicMaterial>; t: number; kind: Hit["kind"] };

// The theme's globe colours, from the tokens on <html> (styles.css). Colours are "#rrggbb" or CSS rgb() with percentages, which three's Color reads.
function readPalette() {
  const cs = getComputedStyle(document.documentElement), v = (name: string) => cs.getPropertyValue(name).trim();
  const color = (name: string) => new Color().setStyle(v(name)), shaded = v("--globe-style") === "shaded";
  return {
    core: color("--globe-core"), land: color("--globe-land"), landOpacity: parseFloat(v("--globe-land-opacity")), india: color("--globe-india"),
    outline: color("--globe-outline"), rim: color("--globe-rim"), rimGain: parseFloat(v("--globe-rim-gain")),
    blending: (v("--globe-blend") === "normal" ? NormalBlending : AdditiveBlending) as Blending,
    shaded, outlineShow: v("--globe-outline-show") !== "0",
    // the shaded style's own tokens (only the light theme defines them), parsed here once: the theme switch uses a palette twice a frame
    sphere: shaded ? ["0", "1", "2", "3"].map((k) => color(`--globe-sphere-${k}`)) : [], shade: shaded ? color("--globe-shade") : new Color(),
    shadeAlpha: parseFloat(v("--globe-shade-alpha")) || 0,
    rimMid: parseFloat(v("--globe-rim-mid")) || 0, rimReach: parseFloat(v("--globe-rim-reach")) || 1,
    arc: { wci: color("--arc-wci"), ddos: color("--arc-ddos") } as Record<Hit["kind"], Color>, arcOpacity: parseFloat(v("--arc-opacity")),
    head: [v("--arc-head-core"), v("--arc-head-mid"), v("--arc-head-edge")],
  };
}
type Palette = ReturnType<typeof readPalette>;
type Look = { pal: Palette; dot: CanvasTexture };   // a theme's palette and its arc-head sprite
// Blending is GL state that three reads at every draw; only an opaque material's shader depends on it (three's "opaque" program parameter), and
// needsUpdate would make three look the shader up again. The theme switch changes the blending twice a frame, so it is set without it here.
function blend(m: Material, b: Blending) {
  if (m.blending !== b) { m.blending = b; if (!m.transparent) m.needsUpdate = true; }
}

type Props = { dim?: boolean; onHit?: (hit: Hit) => void; theme?: Theme };

// The theme switch (lib/themeSwitch.ts) talks to the mounted globe through these; with no globe (no WebGL) they return null / do nothing.
// The switch clips snapshots of the page (View Transitions) along a moving edge. The globe is not in those snapshots: its stage has a group of
// its own whose live view shows in both themes, and while the switch runs the globe draws itself twice a frame through a stencil cut from the
// page's clip polygon, the old theme's look on one side and the new theme's on the other. So it keeps turning (and can be dragged) and still
// changes along exactly the page's edge. The switch draws those frames itself (clipGlobe), so the globe and the page use the same polygon in
// the same frame. No arc starts during a switch; the ones in flight hurry (1.5 x) and land as usual.
export type GlobeCircle = { cx: number; cy: number; r: number };   // CSS px from the top left of the screen
let link: { circle: () => GlobeCircle; begin: (newInside: boolean) => void; retheme: () => void; clip: (now: number, pts: Pt[], side: Side) => void; end: () => void } | null = null;
/** The globe's circle on screen (centre and radius), from its camera. */
export const globeCircle = (): GlobeCircle | null => link?.circle() ?? null;
/** A switch begins, before the old page is snapshotted: the globe keeps the old theme's look, starts no new arcs and speeds up the ones in
    flight. newInside: the new theme is the one inside the clip polygon (the comet), else the old one is (the black hole). */
export const beginGlobeSwitch = (newInside: boolean) => link?.begin(newInside);
/** The theme has changed (in the switch's callback): reads the new theme's look. */
export const rethemeGlobe = () => link?.retheme();
/** One frame of the switch at `now` (performance.now()): moves the globe on and draws it, the inside theme within `pts` (the page's clip polygon,
    screen px) and the other one outside; `side`: where the globe's reach lies against it (drawn once when all of it is on one side). From the
    first call on, the switch draws every frame and the globe's own loop waits. */
export const clipGlobe = (now: number, pts: Pt[], side: Side) => link?.clip(now, pts, side);
/** The switch is over: one look again, new arcs again, and the globe's own loop again, counting the time since the switch's last frame. */
export const endGlobeSwitch = () => link?.end();

export default function Globe({ dim = false, onHit, theme }: Props) {
  const stageRef = useRef<HTMLDivElement>(null);
  const repaint = useRef<(() => void) | null>(null);   // re-reads the palette; set while the scene exists
  const reduced = useReducedMotion() ?? false;   // read once at mount, like the prototype's RM
  const emitHit = useEffectEvent((hit: Hit) => onHit?.(hit));

  useEffect(() => {
    const stage = stageRef.current;
    if (!stage) return;
    // Colour handling as in three r128, the prototype's version: hex colours and the canvas sprite are used as they are, with no
    // sRGB conversion. r152+ converts by default, and would treat the untagged arc-head sprite as linear and brighten it.
    ColorManagement.enabled = false;
    let renderer: WebGLRenderer;
    try {
      renderer = new WebGLRenderer({ antialias: true, alpha: true, stencil: true });   // the stencil: the theme switch's two sides
    } catch {
      return;   // no WebGL: the page works without the globe
    }
    renderer.outputColorSpace = LinearSRGBColorSpace;
    const canvas = renderer.domElement, html = document.documentElement;
    stage.appendChild(canvas);
    const scene = new Scene();
    const camera = new PerspectiveCamera(42, 1, 1, 2000);
    const globe = new Group();
    scene.add(globe);

    // A theme's look: its palette, and the glowing head of an arc drawn in its three --arc-head-* colours (a radial gradient)
    function makeLook(): Look {
      const p = readPalette(), c = document.createElement("canvas"); c.width = c.height = 32;
      const g2 = c.getContext("2d");
      if (g2) {
        const r = g2.createRadialGradient(16, 16, 0, 16, 16, 16);
        r.addColorStop(0, p.head[0]); r.addColorStop(.35, p.head[1]); r.addColorStop(1, p.head[2]);
        g2.fillStyle = r; g2.fillRect(0, 0, 32, 32);
      }
      return { pal: p, dot: new CanvasTexture(c) };
    }
    let look = makeLook(), pal = look.pal;   // the current theme's look, and the palette last put on the scene
    // core sphere (dark in the dark theme) so back-side dots are hidden
    const coreMat = new MeshBasicMaterial({ color: pal.core });
    const core = new Mesh(new SphereGeometry(R * 0.985, 64, 64), coreMat);
    globe.add(core);
    // the shaded style's sphere: full radius, so its edge is where the reference draws it (its dots sit just above, at R * 1.003)
    const shadedMat = new ShaderMaterial({ vertexShader: SPHERE_VS, fragmentShader: SPHERE_FS, uniforms: {
      uS0: { value: new Color() }, uS1: { value: new Color() }, uS2: { value: new Color() }, uS3: { value: new Color() }, uShade: { value: new Color() }, uShadeA: { value: 0 } } });
    const shadedCore = new Mesh(new SphereGeometry(R, 96, 96), shadedMat);
    globe.add(shadedCore);
    // atmosphere rim. Dark (uLight 0): exactly the prototype's vec4(1.0,0.25,0.25,1.0)*i*0.55, added. Light (uLight 1): the rim colour itself,
    // blended normally with alpha i*gain, so it shows as a soft tint on a light page.
    const rimMat = new ShaderMaterial({
      transparent: true, side: BackSide, depthWrite: false, blending: pal.blending,
      uniforms: { uColor: { value: pal.rim }, uGain: { value: pal.rimGain }, uLight: { value: pal.blending === NormalBlending ? 1 : 0 } },
      vertexShader: "varying vec3 vN; void main(){ vN = normalize(normalMatrix*normal); gl_Position = projectionMatrix*modelViewMatrix*vec4(position,1.0); }",
      fragmentShader: "uniform vec3 uColor; uniform float uGain; uniform float uLight; varying vec3 vN; void main(){ float i = pow(0.62 - dot(vN, vec3(0,0,1.0)), 3.0); gl_FragColor = vec4(uColor * mix(i * uGain, 1.0, uLight), i * uGain); }",
    });
    // the shaded style's glow, worn by the same rim sphere: the rim colour blended normally, its alpha by the distance from the globe's centre on
    // screen in globe radii (uCenter, uRadius in buffer pixels, set in resize()), uGain from 0.96 radii, uMid a third of the way out, 0 at uReach
    // (the reference's 2D gradient); the sphere is scaled up so its back faces reach that far, and drawn first, under the dots.
    const glowMat = new ShaderMaterial({
      transparent: true, side: BackSide, depthWrite: false,
      uniforms: { uColor: { value: new Color() }, uGain: { value: 0 }, uMid: { value: 0 }, uReach: { value: 1 }, uCenter: { value: new Vector2() }, uRadius: { value: 1 } },
      vertexShader: "void main(){ gl_Position = projectionMatrix*modelViewMatrix*vec4(position,1.0); }",
      fragmentShader: `uniform vec3 uColor; uniform float uGain; uniform float uMid; uniform float uReach; uniform vec2 uCenter; uniform float uRadius;
void main(){
  float u = clamp((distance(gl_FragCoord.xy, uCenter) / uRadius - 0.96) / (uReach - 0.96), 0.0, 1.0);
  gl_FragColor = vec4(uColor, u < 0.35 ? mix(uGain, uMid, u / 0.35) : mix(uMid, 0.0, (u - 0.35) / 0.65));
}`,
    });
    const rim = new Mesh<SphereGeometry, ShaderMaterial>(new SphereGeometry(R * 1.12, 64, 64), rimMat);
    scene.add(rim);

    // land dots
    const pos = new Float32Array(LAND.length / 2 * 3);
    for (let i = 0; i < LAND.length; i += 2) { const v = vec(LAND[i], LAND[i + 1], R); pos.set([v.x, v.y, v.z], i / 2 * 3); }
    const g = new BufferGeometry(); g.setAttribute("position", new BufferAttribute(pos, 3));
    const landMat = new PointsMaterial({ color: pal.land, size: 1.15, sizeAttenuation: true, transparent: true, opacity: pal.landOpacity });
    const landPts = new Points(g, landMat);
    globe.add(landPts);
    // India: dense dots inside India's official outline plus the outline itself
    const ip: number[] = [];
    for (let i = 0; i < INDIA.dots.length; i += 2) { const v = vec(INDIA.dots[i], INDIA.dots[i + 1], R * 1.002); ip.push(v.x, v.y, v.z); }
    const gi = new BufferGeometry(); gi.setAttribute("position", new BufferAttribute(new Float32Array(ip), 3));
    const indiaDotMat = new PointsMaterial({ color: pal.india, size: 0.9, transparent: true, opacity: 1 });
    const indiaPts = new Points(gi, indiaDotMat);
    globe.add(indiaPts);
    // highlighted outline: a sharp red line plus a softer copy just above it, both pulsing gently (see advance)
    const indiaMats = [new LineBasicMaterial({ color: pal.outline, transparent: true, opacity: .95, blending: pal.blending, depthWrite: false }),
                       new LineBasicMaterial({ color: pal.outline, transparent: true, opacity: .35, blending: pal.blending, depthWrite: false })];
    for (const outline of INDIA.rings) {
      ([[1.004, 0], [1.012, 1]] as const).forEach(([lift, m]) => {
        const p: number[] = [];
        for (let i = 0; i < outline.length; i += 2) { const v = vec(outline[i], outline[i + 1], R * lift); p.push(v.x, v.y, v.z); }
        const gl = new BufferGeometry(); gl.setAttribute("position", new BufferAttribute(new Float32Array(p), 3));
        globe.add(new LineLoop(gl, indiaMats[m]));
      });
    }

    // the shaded style's dots: round, land in --globe-land, India in --globe-india
    const sd = spiralDots(), dotMats: ShaderMaterial[] = [], shadedDots: Points[] = [];
    for (const [at, size] of [[sd.land, 1.7], [sd.india, 1.2]] as const) {
      const m = new ShaderMaterial({ vertexShader: DOT_VS, fragmentShader: DOT_FS, transparent: true, depthWrite: false,
        uniforms: { uColor: { value: new Color() }, uOpacity: { value: 1 }, uSize: { value: size }, uScale: { value: 1 } } });
      const gs = new BufferGeometry(); gs.setAttribute("position", new BufferAttribute(at, 3));
      const pts = new Points(gs, m); dotMats.push(m); shadedDots.push(pts); globe.add(pts);
    }
    const flat = [core, landPts, indiaPts], outlines: LineLoop[] = [];
    globe.children.forEach((o) => { if (o instanceof LineLoop) outlines.push(o); });

    // face India
    const india = vec(20, 79);
    globe.rotation.order = "XYZ";
    globe.rotation.y = -Math.atan2(india.x, india.z);
    globe.rotation.x = -14 * Math.PI / 180;   // India sits high on the visible face, just below the input

    const arcs: Arc[] = [], ripples: Ripple[] = [];
    // e2e/switch.mjs reads the globe through window.__ssTest, which only that test defines (before the page loads); nothing here otherwise
    const probe = (window as unknown as { __ssTest?: Record<string, unknown> }).__ssTest;
    const events: [string, number, number][] | null = probe ? [] : null;   // [what, arc id, time]: born, land, ripple, hit
    let nextId = 0;

    function spawn() {
      const kind = Math.random() < 0.5 ? "wci" : "ddos";
      const src = pick(kind === "wci" ? WCI : CF_SRC);
      let tgt = pick(CF_TGT), guard = 0; while (tgt === src && guard++ < 8) tgt = pick(CF_TGT);
      if (tgt === src) return;
      const a = spot(src), b = spot(tgt);
      const ang = a.angleTo(b); if (ang < 0.25) return;
      const pts = new Float32Array(N * 3), h = R * (0.08 + 0.32 * ang / Math.PI);
      for (let i = 0; i < N; i++) {
        const t = i / (N - 1), s = Math.sin(ang);
        const p = a.clone().multiplyScalar(Math.sin((1 - t) * ang) / s).add(b.clone().multiplyScalar(Math.sin(t * ang) / s));
        p.multiplyScalar(R + h * Math.sin(Math.PI * t)); pts.set([p.x, p.y, p.z], i * 3);
      }
      const lg = new BufferGeometry(); lg.setAttribute("position", new BufferAttribute(pts, 3)); lg.setDrawRange(0, 0);
      const line = new Line(lg, new LineBasicMaterial({ color: pal.arc[kind], transparent: true, opacity: pal.arcOpacity, blending: pal.blending, depthWrite: false }));
      const headAt = new Float32Array(3), headPos = new BufferAttribute(headAt, 3), hg = new BufferGeometry(); hg.setAttribute("position", headPos);
      const head = new Points(hg, new PointsMaterial({ map: look.dot, size: 7, transparent: true, blending: pal.blending, depthWrite: false }));
      globe.add(line, head);
      const id = ++nextId;
      arcs.push({ id, line, head, headAt, headPos, pts, b, kind, t: 0, dur: 1.4 + ang * 0.6, hit: false, ev: [src, tgt, kind] });
      events?.push(["born", id, performance.now()]);
    }

    // the expanding ring where an arc lands (the prototype's ring())
    function ripple(at: Vector3, kind: Hit["kind"]) {
      const m = new Mesh(new RingGeometry(0.9, 1.5, 40), new MeshBasicMaterial({ color: pal.arc[kind], transparent: true, side: DoubleSide, blending: pal.blending, depthWrite: false }));
      // aimed before it joins the globe (as in the prototype), so lookAt works in the globe's own coordinates and the ring faces outwards
      const p = at.clone().multiplyScalar(R * 1.004); m.position.copy(p); m.lookAt(at.clone().multiplyScalar(R * 2));
      globe.add(m); ripples.push({ m, t: 0, kind });
    }

    let raf = 0, last = performance.now(), running = !document.hidden, dragging = false, vel = 0;
    let sw: { from: Look; to: Look | null; pts: Pt[] | null; side: Side; newInside: boolean } | null = null;   // a theme switch is running
    let driven = false;   // the switch draws the frames (clipGlobe); the globe's own loop waits

    // A look onto the scene: every colour, blending mode and texture, arcs and ripples in flight included. Cheap (no parsing, no shader
    // change), so the theme switch can put on its two looks in turn every frame.
    function use(l: Look) {
      const p = pal = l.pal;
      coreMat.color.copy(p.core);
      rimMat.uniforms.uColor.value = p.rim; rimMat.uniforms.uGain.value = p.rimGain; rimMat.uniforms.uLight.value = p.blending === NormalBlending ? 1 : 0;
      blend(rimMat, p.blending);
      const gu = glowMat.uniforms;
      gu.uColor.value.copy(p.rim); gu.uGain.value = p.rimGain; gu.uMid.value = p.rimMid; gu.uReach.value = p.rimReach;
      // which style shows; the shaded glow is drawn first (under the dots, as in the reference) and reaches 1.32 R
      for (const o of flat) o.visible = !p.shaded;
      for (const o of outlines) o.visible = !p.shaded && p.outlineShow;
      shadedCore.visible = p.shaded;
      for (const o of shadedDots) o.visible = p.shaded;
      rim.material = p.shaded ? glowMat : rimMat; rim.scale.setScalar(p.shaded ? 1.32 / 1.12 : 1); rim.renderOrder = p.shaded ? -1 : 0;
      if (p.shaded) {
        const u = shadedMat.uniforms;
        p.sphere.forEach((c, i) => u[`uS${i}`].value.copy(c));
        u.uShade.value.copy(p.shade); u.uShadeA.value = p.shadeAlpha;
        dotMats[0].uniforms.uColor.value.copy(p.land); dotMats[0].uniforms.uOpacity.value = p.landOpacity;
        dotMats[1].uniforms.uColor.value.copy(p.india);
      }
      landMat.color.copy(p.land); landMat.opacity = p.landOpacity;
      indiaDotMat.color.copy(p.india);
      for (const m of indiaMats) { m.color.copy(p.outline); blend(m, p.blending); }
      for (const a of arcs) {
        a.line.material.color.copy(p.arc[a.kind]); a.line.material.opacity = p.arcOpacity; blend(a.line.material, p.blending);
        blend(a.head.material, p.blending); a.head.material.map = l.dot;
      }
      for (const r of ripples) { r.m.material.color.copy(p.arc[r.kind]); blend(r.m.material, p.blending); }
    }
    // a theme change outside the switch: the new tokens become the look
    function retheme() {
      const old = look;
      look = makeLook(); use(look); old.dot.dispose();
    }

    // The switch's stencil: the page's clip polygon as a triangle fan whose triangles each invert the stencil's lowest bit, so a pixel ends at 1
    // inside the polygon and 0 outside (even-odd, any polygon); then the scene is drawn twice, its materials testing for 0 and then for 1. With
    // antialias the stencil is per sample, so the two sides meet on a smooth edge, as the page's clip-path does.
    const MAX_PTS = 512, fan = new Float32Array((MAX_PTS - 2) * 9), fanAt = new BufferAttribute(fan, 3), maskGeo = new BufferGeometry();
    maskGeo.setAttribute("position", fanAt);
    const maskMat = new ShaderMaterial({ vertexShader: "void main(){ gl_Position = vec4(position.xy, 0.0, 1.0); }", fragmentShader: "void main(){ gl_FragColor = vec4(0.0); }",
      side: DoubleSide, colorWrite: false, depthWrite: false, depthTest: false,
      stencilWrite: true, stencilFunc: AlwaysStencilFunc, stencilWriteMask: 1, stencilZPass: InvertStencilOp });
    const maskMesh = new Mesh(maskGeo, maskMat), maskScene = new Scene();
    maskMesh.frustumCulled = false; maskScene.add(maskMesh);
    let vw = innerWidth, vh = innerHeight;   // the canvas in CSS px (resize())
    function cut(pts: Pt[]) {
      const n = Math.min(pts.length, MAX_PTS), X = (i: number) => pts[i][0] / vw * 2 - 1, Y = (i: number) => 1 - pts[i][1] / vh * 2;
      let k = 0;
      for (let i = 1; i < n - 1; i++, k += 9) { fan[k] = X(0); fan[k + 1] = Y(0); fan[k + 3] = X(i); fan[k + 4] = Y(i); fan[k + 6] = X(i + 1); fan[k + 7] = Y(i + 1); }
      maskGeo.setDrawRange(0, k / 3); fanAt.needsUpdate = true;
    }
    let masked = false;
    function stencil(ref: 0 | 1 | null) {   // every material tests the stencil for `ref` and writes nothing to it; null: no stencil test
      if (ref === null && !masked) return;
      masked = ref !== null;
      const set = (m: Material) => {
        m.stencilWrite = masked; m.stencilWriteMask = masked ? 0 : 0xff; m.stencilFunc = masked ? EqualStencilFunc : AlwaysStencilFunc;
        m.stencilRef = ref ?? 0; m.stencilFuncMask = masked ? 1 : 0xff;
      };
      scene.traverse((o) => { const m = (o as Partial<Mesh>).material; if (m) (Array.isArray(m) ? m : [m]).forEach(set); });
      set(rimMat); set(glowMat);   // the rim wears one of the two: the other is not in the scene now
    }

    // One frame on the canvas: the current look; during a switch, the old look until the switch's first frame, then the two looks either side
    // of its clip polygon (comet: the new one inside; black hole: the old one inside).
    function draw() {
      const s = sw;
      if (!s || !s.pts || !s.to) { stencil(null); use(s ? s.from : look); renderer.render(scene, camera); return; }
      const inner = s.newInside ? s.to : s.from, outer = s.newInside ? s.from : s.to;
      if (s.side !== "across") { stencil(null); use(s.side === "in" ? inner : outer); renderer.render(scene, camera); return; }   // all on one side
      cut(s.pts);
      renderer.autoClear = false;
      renderer.clear();
      renderer.render(maskScene, camera);
      use(outer); stencil(0); renderer.render(scene, camera);
      use(inner); stencil(1); renderer.render(scene, camera);
      renderer.autoClear = true;
    }

    // moves everything on to `now`: the spin, the arcs (1.5 x during a switch), the ripples and the outline's pulse; nothing if no time has
    // passed (the switch's first frame can come in the same moment as the globe's last one)
    function advance(now: number) {
      if (now <= last) return;
      const dt = Math.min(0.05, (now - last) / 1000); last = now;
      if (!dragging) { globe.rotation.y += dt * 0.035 + vel; vel *= 0.94; }
      const pace = sw ? 1.5 : 1;
      for (let i = arcs.length - 1; i >= 0; i--) {
        const a = arcs[i]; a.t += dt * pace / a.dur;
        const head = Math.min(1, a.t) * (N - 1), tail = Math.max(0, a.t - 0.55) / 0.45 * (N - 1);
        a.line.geometry.setDrawRange(Math.floor(tail), Math.max(0, Math.ceil(head - tail) + 1));
        const hi = Math.min(N - 1, Math.round(head)); a.headAt.set(a.pts.subarray(hi * 3, hi * 3 + 3)); a.headPos.needsUpdate = true;
        a.head.material.opacity = a.t < 1 ? 1 : 0;
        if (a.t >= 1 && !a.hit) {
          a.hit = true; ripple(a.b, a.kind); emitHit({ src: NAME[a.ev[0]], tgt: NAME[a.ev[1]], kind: a.ev[2] });
          events?.push(["land", a.id, now], ["ripple", a.id, now], ["hit", a.id, now]);
        }
        if (tail >= N - 1) { globe.remove(a.line, a.head); dispose(a.line); dispose(a.head); arcs.splice(i, 1); }
      }
      for (let i = ripples.length - 1; i >= 0; i--) {
        const r = ripples[i]; r.t += dt / 1.3; const s = 1 + r.t * 5; r.m.scale.set(s, s, s); r.m.material.opacity = Math.max(0, 1 - r.t);
        if (r.t >= 1) { globe.remove(r.m); dispose(r.m); ripples.splice(i, 1); }
      }
      const k = 0.5 + 0.5 * Math.sin(now / 650); indiaMats[0].opacity = .7 + .3 * k; indiaMats[1].opacity = .12 + .3 * k;
    }
    function frame(now: number) {
      raf = 0;
      if (!running || driven) return;
      advance(now); draw();
      raf = requestAnimationFrame(frame);
    }
    // start the loop unless it is running, the tab is hidden or the switch draws the frames; keep: count the time since the last frame
    function animate(keep = false) {
      if (!raf && running && !driven) { if (!keep) last = performance.now(); raf = requestAnimationFrame(frame); }
    }
    function redraw() {    // reduced motion: one frame, on demand
      if (!raf) raf = requestAnimationFrame(() => { raf = 0; draw(); });
    }
    const wake = reduced ? redraw : animate;
    repaint.current = () => { if (!sw) { retheme(); redraw(); } };   // during a switch the switch reads the new look (retheme below)
    link = {
      circle: () => {   // the centre projected through the camera; the radius from the angle the sphere fills (the glow's uRadius, in CSS px)
        camera.updateMatrixWorld();
        const c = new Vector3().project(camera), d = camera.position.length(), f = (innerHeight / 2) / Math.tan(camera.fov * Math.PI / 360);
        return { cx: (c.x + 1) / 2 * innerWidth, cy: (1 - c.y) / 2 * innerHeight, r: f * R / Math.sqrt(d * d - R * R) };
      },
      begin: (newInside) => { sw = { from: look, to: null, pts: null, side: "out", newInside }; },
      retheme: () => { if (sw && !sw.to) sw.to = look = makeLook(); },
      clip: (now, pts, side) => {
        if (!sw) return;
        if (!driven) { driven = true; cancelAnimationFrame(raf); raf = 0; }
        sw.pts = pts; sw.side = side; advance(now); draw();
      },
      end: () => {
        if (!sw) return;
        const { from, to } = sw;
        sw = null;
        look = makeLook(); stencil(null); use(look);   // the tokens of the theme the page ended in
        from.dot.dispose(); to?.dot.dispose();
        if (driven) { driven = false; animate(true); }   // the canvas keeps the switch's last frame (all in the new theme) until then
      },
    };
    if (probe) probe.globe = {
      circle: () => link?.circle(),
      spin: () => [last, globe.rotation.y],
      paint: () => { if (!sw) { retheme(); draw(); } },   // the theme's tokens again, and one frame now, without moving on
      state: () => {   // the spin, and each arc's progress and head on screen (CSS px)
        const at = (a: Arc) => { const v = new Vector3().fromArray(a.headAt).applyMatrix4(globe.matrixWorld).project(camera); return [(v.x + 1) / 2 * vw, (1 - v.y) / 2 * vh]; };
        return { time: last, rotX: globe.rotation.x, rotY: globe.rotation.y, switching: !!sw, driven, ripples: ripples.length, events,
          arcs: arcs.map((a) => ({ id: a.id, t: a.t, dur: a.dur, head: at(a) })) };
      },
    };

    function resize() {
      const w = innerWidth, h = innerHeight;
      vw = w; vh = h;
      renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 1.75));
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      const z = w < 640 ? 440 : 300, lift = w < 640 ? 95 : 62;   // look above the globe: it rises from the bottom of the screen
      camera.position.set(0, lift, z);
      camera.lookAt(0, lift, 0);
      camera.updateProjectionMatrix();
      // the shaded style: the globe's silhouette on screen (centre and radius, in buffer pixels: gl_FragCoord counts from the bottom left), and
      // three's point scale (half the buffer height)
      const buf = renderer.getDrawingBufferSize(new Vector2()), f = (h / 2) / Math.tan(21 * Math.PI / 180), d2 = z * z + lift * lift;
      glowMat.uniforms.uCenter.value.set(buf.x / 2, (h / 2 - f * lift / z) * buf.y / h);
      glowMat.uniforms.uRadius.value = f * R / Math.sqrt(d2 - R * R) * buf.y / h;
      for (const m of dotMats) m.uniforms.uScale.value = buf.y / 2;
      if (reduced) redraw();
      else if (driven) draw();   // setSize cleared the canvas and the switch (which a resize ends) may not draw again
    }
    function onVisibility() {   // pause while the tab is hidden
      running = !document.hidden;
      if (running) wake();
      else { cancelAnimationFrame(raf); raf = 0; }
    }

    let px = 0, py = 0;
    function onDown(e: PointerEvent) { dragging = true; px = e.clientX; py = e.clientY; if (e.target === canvas) canvas.setPointerCapture(e.pointerId); }
    // during a theme switch the view transition lies over the page and every pointer event goes to <html>: a press there turns the globe
    function onRootDown(e: PointerEvent) { if (sw && e.target === html) onDown(e); }
    function onMove(e: PointerEvent) {
      if (!dragging) return;
      const dx = e.clientX - px, dy = e.clientY - py; px = e.clientX; py = e.clientY;
      globe.rotation.y += dx * 0.005; vel = dx * 0.0004;
      globe.rotation.x = Math.max(-0.9, Math.min(0.9, globe.rotation.x + dy * 0.004));
      if (reduced) redraw();
    }
    function onUp() { dragging = false; }

    // Every shader up front, both styles' and the stencil's: the theme switch draws the other theme's style from its first frames, and three
    // compiles a shader on its first draw (compile() only sees what is visible, so everything is shown for it, the rim in both materials)
    function warm() {
      const all = [...flat, ...outlines, shadedCore, ...shadedDots], was = all.map((o) => o.visible), wore = rim.material;
      all.forEach((o) => (o.visible = true));
      for (const m of [rimMat, glowMat]) { rim.material = m; renderer.compile(scene, camera); }
      renderer.compile(maskScene, camera);
      all.forEach((o, i) => (o.visible = was[i])); rim.material = wore;
    }

    use(look);
    resize();
    warm();
    addEventListener("resize", resize);
    document.addEventListener("visibilitychange", onVisibility);
    canvas.addEventListener("pointerdown", onDown);
    html.addEventListener("pointerdown", onRootDown);
    addEventListener("pointermove", onMove);   // on the window: a drag that began on <html> (see onRootDown) moves over <html> too
    addEventListener("pointerup", onUp);
    addEventListener("pointercancel", onUp);
    let spawner = 0;
    if (!reduced) {   // reduced motion: no rotation, no arcs, no pulse
      spawn();
      spawner = window.setInterval(() => { if (running && !sw && arcs.length < 30) spawn(); }, 300);   // none during a theme switch
    }
    wake();

    return () => {
      repaint.current = null;
      link = null;
      if (probe) delete probe.globe;
      clearInterval(spawner);
      cancelAnimationFrame(raf);
      removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", onVisibility);
      canvas.removeEventListener("pointerdown", onDown);
      html.removeEventListener("pointerdown", onRootDown);
      removeEventListener("pointermove", onMove);
      removeEventListener("pointerup", onUp);
      removeEventListener("pointercancel", onUp);
      scene.traverse((o) => { if (o instanceof Mesh || o instanceof Points || o instanceof Line) dispose(o); });   // arcs and ripples in flight too
      rimMat.dispose(); glowMat.dispose();   // the rim sphere wears one of the two; the other is not in the scene
      maskGeo.dispose(); maskMat.dispose();
      look.dot.dispose(); sw?.from.dot.dispose(); sw?.to?.dot.dispose();
      renderer.dispose();
      renderer.forceContextLoss();
      canvas.remove();
    };
  }, [reduced]);

  // the attribute on <html> has already changed (lib/theme.ts sets it before the state), so the tokens read here are the new theme's
  useEffect(() => { repaint.current?.(); }, [theme]);

  return (
    <>
      <div ref={stageRef} className={dim ? "stage dim" : "stage"} aria-hidden="true" />
      <div className="vignette" aria-hidden="true" />
    </>
  );
}
