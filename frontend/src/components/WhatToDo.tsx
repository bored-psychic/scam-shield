import type { Level } from "../types/report";
import { canGetHelp } from "../lib/getHelp";
import GetHelp from "./GetHelp";

/** What "Get help" needs: the pasted text and the links in it. Without it the panel is not shown. */
export type HelpInfo = { message: string; quotes: string[] };
type Props = { advice: string[]; level: Level; tip: string | null; help?: HelpInfo };

/** text with every sender ID in it (JM-JIOCPN-P) kept on one line: a browser would otherwise break it at a hyphen. */
function NoBreakIds({ text }: { text: string }) {
  const parts = text.split(/(\b[A-Z]{2}-[A-Z0-9]{6}(?:-[PSTG])?\b)/);
  return <>{parts.map((p, i) => (i % 2 ? <span key={i} className="nobr">{p}</span> : p))}</>;
}

/* What to do now: Report.advice as a numbered list, as the backend wrote it, in its order (D24: the tick boxes are gone). The numbers are drawn
   by CSS counters on a real <ol>, so assistive tech still reads a list of N steps. The helpline and the reporting portal are not here: on a warning
   verdict they are in "Get help" (GetHelp), the one place for those actions. tip: the "check who sent it" line (lib/sender.ts, D22), shown as a
   note rather than a step. */
export default function WhatToDo({ advice, level, tip, help }: Props) {
  return (
    <div className="box todo g-todo">
      <span className="sect" style={{ margin: 0 }}>What to do now</span>
      <ol className="steplist" role="list">
        {advice.map((a, i) => <li key={i}>{a}</li>)}
      </ol>
      {tip && <p className="sendertip"><b>Tip</b><NoBreakIds text={tip} /></p>}
      {help && canGetHelp(level) && <GetHelp level={level} message={help.message} quotes={help.quotes} />}
    </div>
  );
}
