import { switching } from "./themeSwitch";

/* What every new motion must respect (D30): none starts while the theme switch runs or with reduced motion, and a running one jumps to its end the moment a switch starts,
   so the switch snapshots the page at rest. The theme switch itself is not touched: <html> gets .ss-switch when it starts and loses it when it ends, and that is all this reads.
   A click on the theme button is also caught in the capture phase, before the switch measures the page (its glass panes), which the class alone would be too late for. */
const starts = new Set<() => void>(), ends = new Set<() => void>();
let watching = false, on = false;

const isOn = () => document.documentElement.classList.contains("ss-switch");

function watch() {
  if (watching || typeof MutationObserver === "undefined") return;
  watching = true;
  on = isOn();
  new MutationObserver(() => {
    const now = isOn();
    if (now === on) return;
    on = now;
    (now ? starts : ends).forEach((f) => f());
  }).observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
  document.addEventListener("click", (e) => {
    if (!switching() && e.target instanceof Element && e.target.closest(".themebtn")) starts.forEach((f) => f());
  }, true);
}

/** Calls `f` when a theme switch starts. Returns the function that stops it. */
export function onSwitchStart(f: () => void) { watch(); starts.add(f); return () => { starts.delete(f); }; }
/** Calls `f` when a theme switch has ended. Returns the function that stops it. */
export function onSwitchEnd(f: () => void) { watch(); ends.add(f); return () => { ends.delete(f); }; }

export const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
/** May a new motion start now? */
export const mayAnimate = () => !reducedMotion() && !switching() && !isOn();
