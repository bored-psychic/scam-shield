import { onSwitchEnd } from "./motion";

/* The light on the glass (2026-11-03, the correction to docs/design/motion-demo): each widget has its own highlight layer, moved only with transform: translate3d, written directly in one
   requestAnimationFrame from the latest pointer position. No tweening, no smoothing: the layer is exactly where the pointer is, and changing a transform paints nothing, so the widget's own
   glass is left alone (the demo changed the glass's background each frame, which repainted it and lagged). One pointermove listener for the page; each widget's rect is read once a frame, all
   reads before all writes, only for widgets on screen. A layer stays hidden (and costs nothing) until the pointer comes within its reach. Mouse and pen only, and none on a phone-width page.
   The spot on the edge: a second layer inside a 1 px ring, a wedge turned to face the pointer, also only a transform; its strength falls with the distance, by opacity. */
export const REACH = 247;   // px: the gradient's radius (the demo's 380 px circle reaches nothing at 65 %)

type Widget = { host: HTMLElement; spot: HTMLElement; rim: HTMLElement; wedge: HTMLElement; shown: boolean; size: number };
const byHost = new Map<HTMLElement, Widget>();
const onScreen = new Set<Widget>();
let seen: IntersectionObserver | null = null, stopEnd: (() => void) | null = null;
let px = 0, py = 0, have = false, queued = 0;

const enabled = () => matchMedia("(hover: hover) and (min-width: 641px)").matches;
const schedule = () => { if (!queued) queued = requestAnimationFrame(frame); };

function hide(w: Widget) {
  if (!w.shown) return;
  w.shown = false;
  w.spot.style.visibility = w.rim.style.visibility = "hidden";
}

function frame() {
  queued = 0;
  if (!have || document.documentElement.classList.contains("ss-switch") || !enabled()) return;
  const rects = [...onScreen].map((w) => [w, w.host.getBoundingClientRect()] as const);   // reads first: a write here would force the next read to lay out again
  for (const [w, r] of rects) {
    const x = px - r.left, y = py - r.top;
    const away = Math.hypot(Math.max(-x, 0, x - r.width), Math.max(-y, 0, y - r.height));
    if (away >= REACH) { hide(w); continue; }
    w.spot.style.transform = `translate3d(${x}px, ${y}px, 0)`;
    // the angle from the widget's centre to the pointer, 0 = up, clockwise: the wedge is drawn pointing up. Its square covers the widget at any angle.
    const size = Math.ceil(Math.hypot(r.width, r.height)) + 2;
    if (size !== w.size) { w.size = size; w.wedge.style.width = w.wedge.style.height = `${size}px`; w.wedge.style.margin = `${-size / 2}px 0 0 ${-size / 2}px`; }
    w.wedge.style.transform = `rotate(${Math.atan2(x - r.width / 2, r.height / 2 - y)}rad)`;
    w.rim.style.opacity = `${1 - away / REACH}`;
    if (!w.shown) { w.shown = true; w.spot.style.visibility = w.rim.style.visibility = "visible"; }
  }
}

function onMove(e: PointerEvent) {
  if (e.pointerType === "touch") return;
  px = e.clientX; py = e.clientY; have = true;
  schedule();
}
const onLeave = () => { have = false; onScreen.forEach(hide); };

/** Adds a widget's light (`layer`: its .light span, `rim`: its .rimspot span; the widget is their parent). Returns the function that removes it. */
export function addLight(layer: HTMLElement, rim: HTMLElement) {
  const host = layer.parentElement!;
  if (byHost.size === 0) {
    addEventListener("pointermove", onMove, { passive: true });
    addEventListener("scroll", schedule, { capture: true, passive: true });   // the widget moved under a still pointer
    addEventListener("resize", schedule);
    document.documentElement.addEventListener("pointerleave", onLeave);
    stopEnd = onSwitchEnd(schedule);   // moves during the switch were not drawn
    seen = new IntersectionObserver((list) => {
      for (const it of list) {
        const w = byHost.get(it.target as HTMLElement);
        if (!w) continue;
        if (it.isIntersecting) onScreen.add(w); else { hide(w); onScreen.delete(w); }
      }
      schedule();
    });
  }
  const w: Widget = { host, spot: layer.firstElementChild as HTMLElement, rim, wedge: rim.firstElementChild as HTMLElement, shown: false, size: 0 };
  byHost.set(host, w);
  seen!.observe(host);
  return () => {
    seen?.unobserve(host);
    byHost.delete(host);
    onScreen.delete(w);
    if (byHost.size > 0) return;
    removeEventListener("pointermove", onMove);
    removeEventListener("scroll", schedule, { capture: true });
    removeEventListener("resize", schedule);
    document.documentElement.removeEventListener("pointerleave", onLeave);
    stopEnd?.(); stopEnd = null;
    seen?.disconnect(); seen = null;
  };
}
