import { Fragment, useId } from "react";
import { tipLines, type Cluster, type Segment } from "../lib/evidence";
import Light from "./Light";

export type Pulse = { id: string; n: number; on: boolean };   // n counts the taps, so a second tap restarts the animation

type Props = {
  segs: Segment[];
  truncated: boolean;
  pulse: Pulse | null;
  onShow: (c: Cluster, anchor: HTMLElement) => void;
  onHide: () => void;
};

/* The message as pasted, with each underlined part (a cluster of overlapping evidence, lib/evidence.ts) in its most severe colour.
   Every part is focusable and shows the tooltip on hover, focus or tap; its accessible description is the same list of titles.
   The text keeps its line breaks and scrolls inside the panel when long. */
export default function MessagePanel({ segs, truncated, pulse, onShow, onHide }: Props) {
  const uid = useId();
  const marked = segs.flatMap((s) => (s.cluster ? [s.cluster] : []));
  return (
    <div className="box msg g-msg">
      <Light />
      <span className="lab">Your message{marked.length > 0 && <small> · hover or tap the underlined parts</small>}</span>
      <div className="mtext" data-scroll>
        {segs.map((s, i) => {
          const c = s.cluster;
          if (!c) return <Fragment key={i}>{s.text}</Fragment>;
          const pulsing = pulse?.id === c.id;
          return (
            // a new key on each tap remounts the mark, which restarts its CSS animation
            <mark key={pulsing ? `${c.id}:${pulse.n}` : c.id} data-cid={c.id} tabIndex={0} aria-describedby={`${uid}${c.id}`}
              className={pulsing && pulse.on ? `${c.effect} pulse` : c.effect}
              onMouseEnter={(e) => onShow(c, e.currentTarget)} onMouseLeave={onHide}
              onFocus={(e) => onShow(c, e.currentTarget)} onBlur={onHide}
              onClick={(e) => onShow(c, e.currentTarget)}>
              {s.text}
            </mark>
          );
        })}
      </div>
      {marked.map((c) => <span key={c.id} id={`${uid}${c.id}`} hidden>{tipLines(c).map((l) => l.title).join(". ")}</span>)}
      {truncated && <div className="note">Only the first part of this long message was read.</div>}
    </div>
  );
}
