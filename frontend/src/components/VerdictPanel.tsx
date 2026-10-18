import type { Ref } from "react";
import type { Evidence, Level } from "../types/report";
import { LEVEL_SUMMARY, LEVELS } from "../lib/levels";
import Radar from "./Radar";

type Props = {
  level: Level;
  blips: Evidence[];
  pointable: boolean[];
  onPoint: (e: Evidence) => void;
  headingRef: Ref<HTMLHeadingElement>;
};

// The verdict: icon, word and colour (D4: always all three), the fixed one-line summary for the level, and the radar.
export default function VerdictPanel({ level, blips, pointable, onPoint, headingRef }: Props) {
  const lv = LEVELS[level];
  return (
    <div className="box verdict g-verdict">
      <div className="vtop">
        <div className="vicon" style={{ background: lv.color }}>
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d={lv.icon} stroke="#04060A" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin={lv.roundJoin ? "round" : undefined} />
          </svg>
        </div>
        <div>
          <h2 ref={headingRef} tabIndex={-1} className="vword" style={{ color: lv.color }}>{lv.word}</h2>
          <div className="vline">{LEVEL_SUMMARY[level]}</div>
        </div>
      </div>
      <Radar level={level} blips={blips} pointable={pointable} onPoint={onPoint} />
    </div>
  );
}
