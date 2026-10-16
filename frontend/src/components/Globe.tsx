import { useEffect, useEffectEvent, useRef } from "react";
import { useReducedMotion } from "motion/react";
import {
  AdditiveBlending, BackSide, BufferAttribute, BufferGeometry, CanvasTexture, ColorManagement, DoubleSide, Group, Line, LineBasicMaterial,
  LineLoop, LinearSRGBColorSpace, Mesh, MeshBasicMaterial, PerspectiveCamera, Points, PointsMaterial, RingGeometry, Scene, ShaderMaterial,
  SphereGeometry, Vector3, WebGLRenderer,
} from "three";
import LAND from "../data/land.json";     // land dots, flat [lat, lon, lat, lon, ...]
import INDIA from "../data/india.json";   // India's official outline (Natural Earth, India point of view): { rings, dots }

// The dotted globe from the prototype (docs/design/prototype-globe.html, "globe"), ported as is: same geometry, colours, timings and
// weights. Changes: everything it creates is disposed on unmount, one animation loop at most (the prototype could start a second one
// when a tab came back), pointercancel ends a drag, and with reduced motion the static globe is drawn only when it is dragged or resized.

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
function dispose(o: Mesh | Points | Line) {
  o.geometry.dispose();
  (Array.isArray(o.material) ? o.material : [o.material]).forEach((m) => m.dispose());
}

type Arc = { line: Line<BufferGeometry, LineBasicMaterial>; head: Points<BufferGeometry, PointsMaterial>; headAt: Float32Array; headPos: BufferAttribute;
  pts: Float32Array; b: Vector3; col: number; t: number; dur: number; hit: boolean; ev: [Code, Code, Hit["kind"]] };
type Ripple = { m: Mesh<RingGeometry, MeshBasicMaterial>; t: number };

type Props = { dim?: boolean; onHit?: (hit: Hit) => void };

export default function Globe({ dim = false, onHit }: Props) {
  const stageRef = useRef<HTMLDivElement>(null);
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
      renderer = new WebGLRenderer({ antialias: true, alpha: true });
    } catch {
      return;   // no WebGL: the page works without the globe
    }
    renderer.outputColorSpace = LinearSRGBColorSpace;
    const canvas = renderer.domElement;
    stage.appendChild(canvas);
    const scene = new Scene();
    const camera = new PerspectiveCamera(42, 1, 1, 2000);
    const globe = new Group();
    scene.add(globe);

    // dark core so back-side dots are hidden
    globe.add(new Mesh(new SphereGeometry(R * 0.985, 64, 64), new MeshBasicMaterial({ color: 0x070A10 })));
    // atmosphere rim
    scene.add(new Mesh(new SphereGeometry(R * 1.12, 64, 64), new ShaderMaterial({
      transparent: true, side: BackSide, depthWrite: false, blending: AdditiveBlending,
      vertexShader: "varying vec3 vN; void main(){ vN = normalize(normalMatrix*normal); gl_Position = projectionMatrix*modelViewMatrix*vec4(position,1.0); }",
      fragmentShader: "varying vec3 vN; void main(){ float i = pow(0.62 - dot(vN, vec3(0,0,1.0)), 3.0); gl_FragColor = vec4(1.0,0.25,0.25,1.0)*i*0.55; }",
    })));

    // land dots
    const pos = new Float32Array(LAND.length / 2 * 3);
    for (let i = 0; i < LAND.length; i += 2) { const v = vec(LAND[i], LAND[i + 1], R); pos.set([v.x, v.y, v.z], i / 2 * 3); }
    const g = new BufferGeometry(); g.setAttribute("position", new BufferAttribute(pos, 3));
    globe.add(new Points(g, new PointsMaterial({ color: 0x5B6B85, size: 1.15, sizeAttenuation: true, transparent: true, opacity: .85 })));
    // India: dense dots inside India's official outline plus the outline itself
    const ip: number[] = [];
    for (let i = 0; i < INDIA.dots.length; i += 2) { const v = vec(INDIA.dots[i], INDIA.dots[i + 1], R * 1.002); ip.push(v.x, v.y, v.z); }
    const gi = new BufferGeometry(); gi.setAttribute("position", new BufferAttribute(new Float32Array(ip), 3));
    globe.add(new Points(gi, new PointsMaterial({ color: 0xF4F7FB, size: 0.9, transparent: true, opacity: 1 })));
    // highlighted outline: a sharp red line plus a softer copy just above it, both pulsing gently (see frame)
    const indiaMats = [new LineBasicMaterial({ color: 0xFF4D4D, transparent: true, opacity: .95, blending: AdditiveBlending, depthWrite: false }),
                       new LineBasicMaterial({ color: 0xFF4D4D, transparent: true, opacity: .35, blending: AdditiveBlending, depthWrite: false })];
    for (const outline of INDIA.rings) {
      ([[1.004, 0], [1.012, 1]] as const).forEach(([lift, m]) => {
        const p: number[] = [];
        for (let i = 0; i < outline.length; i += 2) { const v = vec(outline[i], outline[i + 1], R * lift); p.push(v.x, v.y, v.z); }
        const gl = new BufferGeometry(); gl.setAttribute("position", new BufferAttribute(new Float32Array(p), 3));
        globe.add(new LineLoop(gl, indiaMats[m]));
      });
    }

    // face India
    const india = vec(20, 79);
    globe.rotation.order = "XYZ";
    globe.rotation.y = -Math.atan2(india.x, india.z);
    globe.rotation.x = -14 * Math.PI / 180;   // India sits high on the visible face, just below the input

    // glowing head of an arc
    const DOT = (() => {
      const c = document.createElement("canvas"); c.width = c.height = 32;
      const g2 = c.getContext("2d");
      if (g2) {
        const r = g2.createRadialGradient(16, 16, 0, 16, 16, 16);
        r.addColorStop(0, "rgba(255,255,255,1)"); r.addColorStop(.35, "rgba(255,140,140,.9)"); r.addColorStop(1, "rgba(255,59,59,0)");
        g2.fillStyle = r; g2.fillRect(0, 0, 32, 32);
      }
      return new CanvasTexture(c);
    })();

    const arcs: Arc[] = [], ripples: Ripple[] = [];

    function spawn() {
      const kind = Math.random() < 0.5 ? "wci" : "ddos";
      const src = pick(kind === "wci" ? WCI : CF_SRC);
      let tgt = pick(CF_TGT), guard = 0; while (tgt === src && guard++ < 8) tgt = pick(CF_TGT);
      if (tgt === src) return;
      const a = spot(src), b = spot(tgt), col = kind === "wci" ? 0xFF3B3B : 0xFF8A3B;
      const ang = a.angleTo(b); if (ang < 0.25) return;
      const pts = new Float32Array(N * 3), h = R * (0.08 + 0.32 * ang / Math.PI);
      for (let i = 0; i < N; i++) {
        const t = i / (N - 1), s = Math.sin(ang);
        const p = a.clone().multiplyScalar(Math.sin((1 - t) * ang) / s).add(b.clone().multiplyScalar(Math.sin(t * ang) / s));
        p.multiplyScalar(R + h * Math.sin(Math.PI * t)); pts.set([p.x, p.y, p.z], i * 3);
      }
      const lg = new BufferGeometry(); lg.setAttribute("position", new BufferAttribute(pts, 3)); lg.setDrawRange(0, 0);
      const line = new Line(lg, new LineBasicMaterial({ color: col, transparent: true, opacity: .9, blending: AdditiveBlending, depthWrite: false }));
      const headAt = new Float32Array(3), headPos = new BufferAttribute(headAt, 3), hg = new BufferGeometry(); hg.setAttribute("position", headPos);
      const head = new Points(hg, new PointsMaterial({ map: DOT, size: 7, transparent: true, blending: AdditiveBlending, depthWrite: false }));
      globe.add(line, head);
      arcs.push({ line, head, headAt, headPos, pts, b, col, t: 0, dur: 1.4 + ang * 0.6, hit: false, ev: [src, tgt, kind] });
    }

    // the expanding ring where an arc lands (the prototype's ring())
    function ripple(at: Vector3, col = 0xFF3B3B) {
      const m = new Mesh(new RingGeometry(0.9, 1.5, 40), new MeshBasicMaterial({ color: col, transparent: true, side: DoubleSide, blending: AdditiveBlending, depthWrite: false }));
      // aimed before it joins the globe (as in the prototype), so lookAt works in the globe's own coordinates and the ring faces outwards
      const p = at.clone().multiplyScalar(R * 1.004); m.position.copy(p); m.lookAt(at.clone().multiplyScalar(R * 2));
      globe.add(m); ripples.push({ m, t: 0 });
    }

    let raf = 0, last = performance.now(), running = !document.hidden, dragging = false, vel = 0;

    function frame(now: number) {
      raf = 0;
      if (!running) return;
      const dt = Math.min(0.05, (now - last) / 1000); last = now;
      if (!dragging) { globe.rotation.y += dt * 0.035 + vel; vel *= 0.94; }
      for (let i = arcs.length - 1; i >= 0; i--) {
        const a = arcs[i]; a.t += dt / a.dur;
        const head = Math.min(1, a.t) * (N - 1), tail = Math.max(0, a.t - 0.55) / 0.45 * (N - 1);
        a.line.geometry.setDrawRange(Math.floor(tail), Math.max(0, Math.ceil(head - tail) + 1));
        const hi = Math.min(N - 1, Math.round(head)); a.headAt.set(a.pts.subarray(hi * 3, hi * 3 + 3)); a.headPos.needsUpdate = true;
        a.head.material.opacity = a.t < 1 ? 1 : 0;
        if (a.t >= 1 && !a.hit) { a.hit = true; ripple(a.b, a.col); emitHit({ src: NAME[a.ev[0]], tgt: NAME[a.ev[1]], kind: a.ev[2] }); }
        if (tail >= N - 1) { globe.remove(a.line, a.head); dispose(a.line); dispose(a.head); arcs.splice(i, 1); }
      }
      for (let i = ripples.length - 1; i >= 0; i--) {
        const r = ripples[i]; r.t += dt / 1.3; const s = 1 + r.t * 5; r.m.scale.set(s, s, s); r.m.material.opacity = Math.max(0, 1 - r.t);
        if (r.t >= 1) { globe.remove(r.m); dispose(r.m); ripples.splice(i, 1); }
      }
      const k = 0.5 + 0.5 * Math.sin(now / 650); indiaMats[0].opacity = .7 + .3 * k; indiaMats[1].opacity = .12 + .3 * k;
      renderer.render(scene, camera);
      raf = requestAnimationFrame(frame);
    }
    function animate() {   // start the loop unless it is running or the tab is hidden
      if (!raf && running) { last = performance.now(); raf = requestAnimationFrame(frame); }
    }
    function redraw() {    // reduced motion: one frame, on demand
      if (!raf) raf = requestAnimationFrame(() => { raf = 0; renderer.render(scene, camera); });
    }
    const wake = reduced ? redraw : animate;

    function resize() {
      const w = innerWidth, h = innerHeight;
      renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 1.75));
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      const z = w < 640 ? 440 : 300, lift = w < 640 ? 95 : 62;   // look above the globe: it rises from the bottom of the screen
      camera.position.set(0, lift, z);
      camera.lookAt(0, lift, 0);
      camera.updateProjectionMatrix();
      if (reduced) redraw();
    }
    function onVisibility() {   // pause while the tab is hidden
      running = !document.hidden;
      if (running) wake();
      else { cancelAnimationFrame(raf); raf = 0; }
    }

    let px = 0, py = 0;
    function onDown(e: PointerEvent) { dragging = true; px = e.clientX; py = e.clientY; canvas.setPointerCapture(e.pointerId); }
    function onMove(e: PointerEvent) {
      if (!dragging) return;
      const dx = e.clientX - px, dy = e.clientY - py; px = e.clientX; py = e.clientY;
      globe.rotation.y += dx * 0.005; vel = dx * 0.0004;
      globe.rotation.x = Math.max(-0.9, Math.min(0.9, globe.rotation.x + dy * 0.004));
      if (reduced) redraw();
    }
    function onUp() { dragging = false; }

    resize();
    addEventListener("resize", resize);
    document.addEventListener("visibilitychange", onVisibility);
    canvas.addEventListener("pointerdown", onDown);
    canvas.addEventListener("pointermove", onMove);
    canvas.addEventListener("pointerup", onUp);
    canvas.addEventListener("pointercancel", onUp);
    let spawner = 0;
    if (!reduced) {   // reduced motion: no rotation, no arcs, no pulse
      spawn();
      spawner = window.setInterval(() => { if (running && arcs.length < 30) spawn(); }, 300);
    }
    wake();

    return () => {
      clearInterval(spawner);
      cancelAnimationFrame(raf);
      removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", onVisibility);
      canvas.removeEventListener("pointerdown", onDown);
      canvas.removeEventListener("pointermove", onMove);
      canvas.removeEventListener("pointerup", onUp);
      canvas.removeEventListener("pointercancel", onUp);
      scene.traverse((o) => { if (o instanceof Mesh || o instanceof Points || o instanceof Line) dispose(o); });   // arcs and ripples in flight too
      DOT.dispose();
      renderer.dispose();
      renderer.forceContextLoss();
      canvas.remove();
    };
  }, [reduced]);

  return (
    <>
      <div ref={stageRef} className={dim ? "stage dim" : "stage"} aria-hidden="true" />
      <div className="vignette" aria-hidden="true" />
    </>
  );
}
