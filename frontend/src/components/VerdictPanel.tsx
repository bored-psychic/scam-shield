import type { CSSProperties, Ref } from "react";
import type { Evidence, Level } from "../types/report";
import { levelSummary, LEVELS } from "../lib/levels";
import type { Noun } from "../lib/tabs";
import Light from "./Light";
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
  noun?: Noun;               // what was checked, for the one line under the verdict
};

// "Lowered from Likely scam: the link belongs to Jio (...)": the part up to the first colon is set as a serif lead-in; the text is the backend's, unchanged.
function LoweredText({ text }: { text: string }) {
  const m = /^(Lowered from [^:]+:)\s(.*)$/s.exec(text);
  return m ? <><b>{m[1]}</b> {m[2]}</> : <>{text}</>;
}

// The verdict: icon, word and colour (D4: always all three), the fixed one-line summary for the level, the "Lowered from..." line when a brand-owned
// link lowered it, the risk score with its meter, and the radar.
export default function VerdictPanel({ level, blips, pointable, onPoint, headingRef, note = null, score = null, lowered = null, noun = "message" }: Props) {
  const lv = LEVELS[level];
  return (
    <div className="box verdict g-verdict" style={{ "--lvl": lv.color } as CSSProperties}>
      <Light />
      <div className="vtop">
        <div className="vicon" style={{ background: lv.color }}>
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d={lv.icon} style={{ stroke: "var(--on-color)" }} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin={lv.roundJoin ? "round" : undefined} />
          </svg>
        </div>
        <div>
          <h2 ref={headingRef} tabIndex={-1} className="vword" style={{ color: lv.color }}>{lv.word}</h2>
          <div className="vline">{levelSummary(level, noun)}</div>
          {note && <div className="vraised" role="status">{note}</div>}
        </div>
      </div>
      {lowered && <p className="vlowered"><i aria-hidden="true">↓</i><span><LoweredText text={lowered} /></span></p>}
      {score !== null && <RiskMeter score={score} level={level} />}
      <Radar level={level} blips={blips} pointable={pointable} onPoint={onPoint} />
    </div>
  );
}
