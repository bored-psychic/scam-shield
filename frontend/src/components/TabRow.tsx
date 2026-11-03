import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import gsap from "gsap";
import { mayAnimate, onSwitchStart } from "../lib/motion";
import { TAB_NAME, TABS, type TabKey } from "../lib/tabs";
import Light from "./Light";
import TabIcon from "./TabIcon";

type Props = { tab: TabKey; onSelect: (k: TabKey) => void };

/* The four tabs, the WAI-ARIA tabs pattern (plan 6.1): a tablist of buttons with aria-selected and aria-controls, arrow keys move between the tabs
   and select them, Home / End jump, only the selected tab is in the Tab order. The selected pill is one element behind the buttons, moved with a
   transform. Phone (<= 640 px): one scrolling row with scroll-snap and edge fades as the scroll hint, the selected tab kept in view. */
export default function TabRow({ tab, onSelect }: Props) {
  const row = useRef<HTMLDivElement>(null), thumb = useRef<HTMLSpanElement>(null);
  const [edges, setEdges] = useState({ left: false, right: false });
  const shown = useRef(tab), slide = useRef<gsap.core.Timeline | null>(null);

  const button = (k: TabKey) => row.current?.querySelector<HTMLElement>(`#tab-${k}`) ?? null;
  const readEdges = () => {
    const el = row.current;
    if (!el) return;
    const left = el.scrollLeft > 1, right = el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
    setEdges((e) => (e.left === left && e.right === right ? e : { left, right }));   // called every frame while the row scrolls: re-render only on a change
  };
  const inView = (on: HTMLElement) => { const el = row.current!; return Math.max(0, Math.min(on.offsetLeft - (el.clientWidth - on.offsetWidth) / 2, el.scrollWidth - el.clientWidth)); };
  const placeNow = (k: TabKey) => {   // no motion: the first paint, the fonts arriving, a new width
    const on = button(k), el = row.current;
    if (!thumb.current || !on || !el) return;
    slide.current?.kill(); slide.current = null;
    gsap.set(thumb.current, { x: on.offsetLeft, width: on.offsetWidth, height: on.offsetHeight });
    if (el.scrollWidth > el.clientWidth) el.scrollLeft = inView(on);
    el.style.scrollSnapType = "";
    readEdges();
  };

  useLayoutEffect(() => {
    const was = shown.current;
    shown.current = tab;
    const on = button(tab), el = row.current;
    if (was === tab || !on || !el || !mayAnimate()) { placeNow(tab); return; }
    // the pill's part of the tab switch: it slides over .55 s, from wherever it is; the phone's row scrolls with it, its snapping off until then
    slide.current?.kill();
    const scrolls = el.scrollWidth > el.clientWidth;
    if (scrolls) el.style.scrollSnapType = "none";
    slide.current = gsap.timeline({ onComplete: () => { slide.current = null; el.style.scrollSnapType = ""; readEdges(); } })
      .to(thumb.current, { x: on.offsetLeft, width: on.offsetWidth, height: on.offsetHeight, duration: .55, ease: "power4.out" }, 0);
    if (scrolls) slide.current.to(el, { scrollLeft: inView(on), duration: .55, ease: "power4.out" }, 0);
  }, [tab]);

  useEffect(() => {
    const el = row.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => placeNow(shown.current));   // the fonts or the width change the tabs' sizes
    ro.observe(el);
    for (const b of el.querySelectorAll(".tab")) ro.observe(b);
    const off = onSwitchStart(() => { if (slide.current) placeNow(shown.current); });   // a theme switch starting: straight to the end
    return () => { ro.disconnect(); off(); slide.current?.kill(); };
  }, []);

  const onKeyDown = (e: KeyboardEvent, i: number) => {
    const next = e.key === "ArrowRight" ? TABS[(i + 1) % TABS.length] : e.key === "ArrowLeft" ? TABS[(i - 1 + TABS.length) % TABS.length]
      : e.key === "Home" ? TABS[0] : e.key === "End" ? TABS[TABS.length - 1] : null;
    if (!next) return;
    e.preventDefault();
    onSelect(next);
    button(next)?.focus();
  };

  return (
    <div className="tabswrap" data-left={edges.left || undefined} data-right={edges.right || undefined}>
      <div className="tabs" ref={row} role="tablist" aria-label="What do you want to check?" onScroll={readEdges}>
        <span className="tabthumb" ref={thumb} aria-hidden="true" />
        {TABS.map((k, i) => (
          <button key={k} type="button" role="tab" id={`tab-${k}`} aria-controls={`panel-${k}`} aria-selected={k === tab} tabIndex={k === tab ? 0 : -1}
            className="tab" onClick={() => onSelect(k)} onKeyDown={(e) => onKeyDown(e, i)}>
            <Light />
            <TabIcon tab={k} />
            <span className="wgt" data-label={TAB_NAME[k]}>{TAB_NAME[k]}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
