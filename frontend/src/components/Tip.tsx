import { useEffect, useLayoutEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { tipLines, type Cluster } from "../lib/evidence";
import { EFFECT_COLOR, EFFECT_ICON } from "../lib/levels";

export type TipAt = { cluster: Cluster; anchor: HTMLElement; show: boolean };   // show: false keeps the text while it fades out

const HIDE_AFTER_MS = 4000;   // as the prototype

// Placed as the prototype's showTip(): under the mark, or above it when there is no room below, kept 16px inside the viewport.
// Returns false when the mark is out of view (scrolled off the page or out of the message panel), so the tip can hide instead.
function place(el: HTMLElement, anchor: HTMLElement): boolean {
  if (!anchor.isConnected) return false;
  const r = anchor.getBoundingClientRect(), box = anchor.closest("[data-scroll]")?.getBoundingClientRect();
  if (r.bottom <= 0 || r.top >= innerHeight || (box && (r.bottom <= box.top || r.top >= box.bottom))) return false;
  const w = Math.min(260, innerWidth - 32);
  el.style.maxWidth = `${w}px`;
  el.style.left = `${Math.max(16, Math.min(innerWidth - w - 16, r.left))}px`;
  const below = r.bottom + 8 + el.offsetHeight < innerHeight;
  el.style.top = `${below ? r.bottom + 8 : r.top - el.offsetHeight - 8}px`;
  return true;
}

/* The tooltip of an underlined part: the title of every piece of evidence in it. Visual only (aria-hidden): each mark has the same
   titles as its accessible description. Rendered into <body>: inside a panel, the panel's backdrop-filter would become the containing
   block of this position: fixed box. Follows its mark while anything scrolls (the prototype hid it on any scroll) and hides when the mark
   leaves the view, after 4 s, or on Escape. */
export default function Tip({ at, onHide }: { at: TipAt | null; onHide: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const show = !!at?.show;

  useLayoutEffect(() => {
    if (at?.show && ref.current && !place(ref.current, at.anchor)) onHide();
  }, [at, onHide]);

  useEffect(() => {
    if (!at?.show) return;
    let frame = 0;
    const follow = () => { cancelAnimationFrame(frame); frame = requestAnimationFrame(() => { if (ref.current && !place(ref.current, at.anchor)) onHide(); }); };
    const key = (e: KeyboardEvent) => { if (e.key === "Escape") onHide(); };
    const timer = setTimeout(onHide, HIDE_AFTER_MS);
    addEventListener("scroll", follow, { capture: true, passive: true });   // capture: the message panel's own scrolling too
    addEventListener("resize", onHide);
    addEventListener("keydown", key);
    return () => {
      cancelAnimationFrame(frame); clearTimeout(timer);
      removeEventListener("scroll", follow, { capture: true });
      removeEventListener("resize", onHide);
      removeEventListener("keydown", key);
    };
  }, [at, onHide]);

  return createPortal(
    <div ref={ref} className={show ? "tip show" : "tip"} aria-hidden="true">
      {at && tipLines(at.cluster).map((l) => (
        <div key={l.title} className="tl"><i style={{ color: EFFECT_COLOR[l.effect] }}>{EFFECT_ICON[l.effect]}</i><span>{l.title}</span></div>
      ))}
    </div>,
    document.body,
  );
}
