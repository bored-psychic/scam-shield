import { useEffect, useLayoutEffect, useRef } from "react";
import gsap from "gsap";

type Props<T extends string> = { label: string; options: readonly (readonly [T, string])[]; value: T | null; onPick: (v: T) => void };

/* A compact toggle: buttons with aria-pressed in a labelled group, and one thumb behind the pressed one. The thumb is placed by GSAP with a transform
   (it pins `translate` inline, so the lift moves it by `top`); it moves at once: only the tab switch animates. value null: nothing pressed yet, no thumb. */
export default function Seg<T extends string>({ label, options, value, onPick }: Props<T>) {
  const box = useRef<HTMLDivElement>(null), thumb = useRef<HTMLSpanElement>(null);
  const place = () => {
    const on = box.current?.querySelector<HTMLElement>('[aria-pressed="true"]');
    if (thumb.current && on) gsap.set(thumb.current, { x: on.offsetLeft, width: on.offsetWidth, height: on.offsetHeight });
  };
  useLayoutEffect(place, [value]);
  useEffect(() => {   // the fonts or the width change the buttons' sizes
    const el = box.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(place);
    ro.observe(el);
    return () => ro.disconnect();
  });
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
