import { useEffect, useLayoutEffect, useRef } from "react";
import gsap from "gsap";
import { mayAnimate, onSwitchStart } from "../lib/motion";

type Props<T extends string> = { label: string; options: readonly (readonly [T, string])[]; value: T | null; onPick: (v: T) => void };

/* A compact toggle: buttons with aria-pressed in a labelled group, and one thumb behind the pressed one. The thumb is placed by GSAP with a transform (it pins
   `translate` inline, so the lift moves it by `top`). When the choice changes it slides over .42 s with the tab pill's ease (power4.out), from wherever it is; the
   first placement, a resize, reduced motion and a theme switch (D30) put it there at once. value null: nothing pressed yet, no thumb. */
const SLIDE_S = .42;

export default function Seg<T extends string>({ label, options, value, onPick }: Props<T>) {
  const box = useRef<HTMLDivElement>(null), thumb = useRef<HTMLSpanElement>(null);
  const placed = useRef<HTMLSpanElement | null>(null);   // the thumb element that has been placed; a thumb that mounts later (value was null) starts at its button
  const slide = useRef<gsap.core.Tween | null>(null);
  const target = () => {
    const on = box.current?.querySelector<HTMLElement>('[aria-pressed="true"]');
    return on ? { x: on.offsetLeft, width: on.offsetWidth, height: on.offsetHeight } : null;
  };
  const place = () => {   // no motion
    const to = target();
    slide.current?.kill(); slide.current = null;
    if (thumb.current && to) { gsap.set(thumb.current, to); placed.current = thumb.current; }
  };
  useLayoutEffect(() => {
    const to = target();
    if (!thumb.current || !to) return;
    if (placed.current !== thumb.current || !mayAnimate()) { place(); return; }
    slide.current?.kill();
    slide.current = gsap.to(thumb.current, { ...to, duration: SLIDE_S, ease: "power4.out", onComplete: () => { slide.current = null; } });
  }, [value]);
  useEffect(() => {   // the fonts or the width change the buttons' sizes
    const el = box.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(place);
    ro.observe(el);
    for (const b of el.querySelectorAll(".segbtn")) ro.observe(b);   // on a phone the row keeps its width while the buttons inside it change
    const off = onSwitchStart(() => { if (slide.current) place(); });   // a theme switch starting: straight to the end
    return () => { ro.disconnect(); off(); slide.current?.kill(); };
  }, []);
  return (
    <div className="seg" ref={box} role="group" aria-label={label}>
      {value !== null && <span className="segthumb" ref={thumb} aria-hidden="true" />}
      {options.map(([v, text]) => (
        <button key={v} type="button" className="segbtn" aria-pressed={v === value} onClick={() => onPick(v)}>
          <span className="wgt" data-label={text}>{text}</span>
        </button>
      ))}
    </div>
  );
}
