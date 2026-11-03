import { useLayoutEffect, useRef } from "react";
import { addLight } from "../lib/pointerLight";

// A glass widget's pointer light: its own layers, as the widget's first children (lib/pointerLight.ts moves them). Nothing here takes the pointer or is read by assistive tech.
export default function Light() {
  const layer = useRef<HTMLSpanElement>(null), rim = useRef<HTMLSpanElement>(null);
  useLayoutEffect(() => addLight(layer.current!, rim.current!), []);
  return (
    <>
      <span className="light" ref={layer} aria-hidden="true"><i className="lightspot" /></span>
      <span className="rimspot" ref={rim} aria-hidden="true"><i /></span>
    </>
  );
}
