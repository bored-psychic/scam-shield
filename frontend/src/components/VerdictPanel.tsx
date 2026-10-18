import type { Ref } from "react";
import type { Evidence, Level } from "../types/report";
import { LEVEL_SUMMARY, LEVELS } from "../lib/levels";
import Radar from "./Radar";
import RiskMeter from "./RiskMeter";

type Props = {
  level: Level;
  blips: Evidence[];
  pointable: boolean[];
  onPoint: (e: Evidence) => void;
  headingRef: Ref<HTMLHeadingElement>;
  note?: string | null;   // D23: "Raised after the website checks." when the live link checks raised the verdict
  score?: number | null;  // D24: Report.risk_score; null = no meter (Can't judge)
  lowered?: string | null;   // D24: Report.lowered.text, when a brand-owned link (P1) really lowered the verdict
};

// The verdict: icon, word and colour (D4: always all three), the fixed one-line summary for the level, the "Lowered from..." line when a brand-owned
// link lowered it, the risk score with its meter, and the radar.
export default function VerdictPanel({ level, blips, pointable, onPoint, headingRef, note = null, score = null, lowered = null }: Props) {
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
          {note && <div className="vraised" role="status">{note}</div>}
        </div>
      </div>
      {lowered && <p className="vlowered"><i aria-hidden="true">↓</i><span>{lowered}</span></p>}
      {score !== null && <RiskMeter score={score} level={level} />}
      <Radar level={level} blips={blips} pointable={pointable} onPoint={onPoint} />
    </div>
  );
}
