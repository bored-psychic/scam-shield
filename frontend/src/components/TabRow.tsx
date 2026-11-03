import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import gsap from "gsap";
import { TAB_NAME, TABS, type TabKey } from "../lib/tabs";
import TabIcon from "./TabIcon";

type Props = { tab: TabKey; onSelect: (k: TabKey) => void };

/* The four tabs, the WAI-ARIA tabs pattern (plan 6.1): a tablist of buttons with aria-selected and aria-controls, arrow keys move between the tabs
   and select them, Home / End jump, only the selected tab is in the Tab order. The selected pill is one element behind the buttons, moved with a
   transform. Phone (<= 640 px): one scrolling row with scroll-snap and edge fades as the scroll hint, the selected tab kept in view. */
export default function TabRow({ tab, onSelect }: Props) {
  const row = useRef<HTMLDivElement>(null), thumb = useRef<HTMLSpanElement>(null);
  const [edges, setEdges] = useState({ left: false, right: false });

  const button = (k: TabKey) => row.current?.querySelector<HTMLElement>(`#tab-${k}`) ?? null;
  const place = () => {
    const on = button(tab);
    if (thumb.current && on) gsap.set(thumb.current, { x: on.offsetLeft, width: on.offsetWidth, height: on.offsetHeight });
  };
  const readEdges = () => {
    const el = row.current;
    if (el) setEdges({ left: el.scrollLeft > 1, right: el.scrollLeft + el.clientWidth < el.scrollWidth - 1 });
  };
  const bringIntoView = () => {
    const el = row.current, on = button(tab);
    if (el && on && el.scrollWidth > el.clientWidth) el.scrollLeft = on.offsetLeft - (el.clientWidth - on.offsetWidth) / 2;
  };

  useLayoutEffect(() => { place(); bringIntoView(); readEdges(); }, [tab]);
  useEffect(() => {   // the fonts or the width change the tabs' sizes
    const el = row.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => { place(); readEdges(); });
    ro.observe(el);
    for (const b of el.querySelectorAll(".tab")) ro.observe(b);
    return () => ro.disconnect();
  });

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
            <TabIcon tab={k} />
            <span className="wgt" data-label={TAB_NAME[k]}>{TAB_NAME[k]}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
