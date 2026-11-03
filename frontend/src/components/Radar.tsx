import { Fragment } from "react";
import { useReducedMotion } from "motion/react";
import type { Evidence, Level } from "../types/report";
import { EFFECT_COLOR, LEVELS } from "../lib/levels";

// Where the blips sit, in % of the radar (the prototype's SPOTS): one per blip, in blips() order.
const SPOTS: [x: number, y: number][] = [[30, 28], [70, 36], [28, 68], [68, 74]];

type Props = {
  level: Level;
  blips: Evidence[];                    // blips() of the Report: at most 4 warnings, one per tag
  pointable: boolean[];                 // per blip: whether it has an underlined part to pulse
  onPoint: (e: Evidence) => void;
};

/* The radar meter, option 8b "Labelled blips" (docs/design/README.md), ported from the prototype's radar(). The sweep is in the verdict
   colour; each blip is a warning sign, labelled with its Evidence.tag and coloured by its severity. Tapping a label pulses its part of the
   message. No number or percentage (D4); with no blips the caption says what the verdict says. Can't judge and reduced motion: the sweep
   stands still. The blips are there from the start: the result page has no entrance animations (2026-11-03). */
export default function Radar({ level, blips, pointable, onPoint }: Props) {
  const reduced = useReducedMotion();
  const n = blips.length, word = LEVELS[level].word, color = LEVELS[level].color;
  const signs = `${n} warning sign${n === 1 ? "" : "s"} found`;
  const caption = n ? signs + (pointable.some(Boolean) ? " · tap a tag" : "")
    : level === "no_warning_signs" ? "Scanned · no warning signs found"
    : level === "promotional" ? "Scanned · registered promotional sender"
    : level === "cant_judge" ? "Scan stopped · not enough to judge" : "Scanned";
  const label = n ? `Scan result: ${word}, ${signs}` : `Scan result: ${word}`;

  return (
    <div className="rwrap">
      <div className="radar" role="group" aria-label={label}>
        <div className={reduced || level === "cant_judge" ? "sweep still" : "sweep"} aria-hidden="true"
          style={{ background: `conic-gradient(from 0deg, color-mix(in srgb, ${color} 40%, transparent), transparent 25%)` }}></div>
        {blips.map((e, i) => {
          const [x, y] = SPOTS[i], c = EFFECT_COLOR[e.effect];
          const place = { ...(x < 50 ? { right: `calc(${100 - x}% + 9px)` } : { left: `calc(${x}% + 9px)` }), top: `calc(${y}% - 14px)`, color: c };
          return (
            <Fragment key={e.tag}>
              <div className="blip" aria-hidden="true"
                style={{ left: `${x}%`, top: `${y}%`, background: c, color: c, boxShadow: `0 0 10px ${c}` }}></div>
              {pointable[i]
                ? <button type="button" className="lbl" style={place} onClick={() => onPoint(e)}>{e.tag}</button>
                : <span className="lbl nopoint" style={place}>{e.tag}</span>}
            </Fragment>
          );
        })}
        <div className="core" aria-hidden="true"></div>
      </div>
      <div className="rcap">{caption}</div>
    </div>
  );
}
