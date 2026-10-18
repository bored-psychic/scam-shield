import { useId } from "react";
import type { Level } from "../types/report";
import { LEVELS } from "../lib/levels";
import { bandOf, EDGES, METER_NOTE } from "../lib/risk";

type Props = { score: number; level: Level };

/* The risk score (D24): "Risk score 82 / 100" and a green > amber > red bar with the two band edges (30 and 70) marked and each zone named, so
   colour is never the only signal. A warning-sign meter, not a probability (the line under it says so). The number is the backend's Report.risk_score,
   always inside the band of the verdict; nothing here computes or adjusts it. role="meter" gives assistive tech the value and its range, and
   aria-valuetext reads it as a sentence with the zone's name. */
export default function RiskMeter({ score, level }: Props) {
  const uid = useId();
  const zone = bandOf(score);
  return (
    <div className="score">
      <div className="sline2">
        <span className="sect" id={`${uid}l`}>Risk score</span>
        <span className="snum"><b style={{ color: LEVELS[level].color }}>{score}</b><span> / 100</span></span>
      </div>
      <div className="meter" role="meter" aria-labelledby={`${uid}l`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={score}
           aria-valuetext={`${score} out of 100, in the ${zone.name} range`}>
        <i className="tick" style={{ left: `${EDGES[0]}%` }} />
        <i className="tick" style={{ left: `${EDGES[1]}%` }} />
        <i className="knob" style={{ left: `${score}%` }} />
      </div>
      <div className="mscale" aria-hidden="true">
        <span style={{ left: "0%" }}>0</span><span style={{ left: `${EDGES[0]}%` }}>{EDGES[0]}</span>
        <span style={{ left: `${EDGES[1]}%` }}>{EDGES[1]}</span><span style={{ left: "100%" }}>100</span>
      </div>
      <div className="mzones" aria-hidden="true">
        <span style={{ width: `${EDGES[0]}%` }}>No warning signs</span>
        <span style={{ width: `${EDGES[1] - EDGES[0]}%` }}>Suspicious</span>
        <span style={{ width: `${100 - EDGES[1]}%` }}>Likely scam</span>
      </div>
      <p className="mnote">{METER_NOTE}</p>
    </div>
  );
}
