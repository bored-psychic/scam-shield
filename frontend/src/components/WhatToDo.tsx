import { useEffect, useRef, useState } from "react";
import type { Level } from "../types/report";
import { canAskFirst } from "../lib/askFirst";
import AskFirst from "./AskFirst";

const HELPLINE = "1930";   // the national cyber-fraud helpline
const PORTAL = "https://cybercrime.gov.in";

/** What "Ask someone first" needs: the top reason, the pasted text and the links in it. Without it the button is not shown. */
export type AskInfo = { reason: string | null; message: string; quotes: string[] };
type Props = { advice: string[]; level: Level; tip: string | null; ask?: AskInfo };

/** text with every sender ID in it (JM-JIOCPN-P) kept on one line: a browser would otherwise break it at a hyphen. */
function NoBreakIds({ text }: { text: string }) {
  const parts = text.split(/(\b[A-Z]{2}-[A-Z0-9]{6}(?:-[PSTG])?\b)/);
  return <>{parts.map((p, i) => (i % 2 ? <span key={i} className="nobr">{p}</span> : p))}</>;
}

/* What to do now: Report.advice as a numbered list, as the backend wrote it, in its order (D24: the tick boxes are gone; nothing here has state but the
   copy button). The numbers are drawn by CSS counters on a real <ol>, so assistive tech still reads a list of N steps. On a warning
   verdict also the helpline and the reporting portal. Copying uses the clipboard; where that is refused, the number is shown selected.
   tip: the "check who sent it" line (lib/sender.ts, D22), shown as a note rather than a step. */
export default function WhatToDo({ advice, level, tip, ask }: Props) {
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  const num = useRef<HTMLSpanElement>(null);
  const warn = level === "likely_scam" || level === "suspicious";

  useEffect(() => {
    if (copy === "copied") {
      const t = setTimeout(() => setCopy("idle"), 2500);
      return () => clearTimeout(t);
    }
    if (copy === "failed" && num.current) {
      const range = document.createRange();
      range.selectNodeContents(num.current);
      getSelection()?.removeAllRanges();
      getSelection()?.addRange(range);
    }
  }, [copy]);

  async function copyHelpline() {
    try {
      await navigator.clipboard.writeText(HELPLINE);
      setCopy("copied");
    } catch {
      setCopy("failed");
    }
  }

  return (
    <div className="box todo g-todo">
      <span className="sect" style={{ margin: 0 }}>What to do now</span>
      <ol className="steplist" role="list">
        {advice.map((a, i) => <li key={i}>{a}</li>)}
      </ol>
      {tip && <p className="sendertip"><b>Tip</b><NoBreakIds text={tip} /></p>}
      {ask && canAskFirst(level) && <AskFirst level={level} reason={ask.reason} message={ask.message} quotes={ask.quotes} />}
      {warn && (
        <div className="helpline">
          <button type="button" className="ghost" onClick={copyHelpline}>{copy === "copied" ? `Copied ${HELPLINE}` : `Copy helpline ${HELPLINE}`}</button>
          {copy === "failed" && <span className="hlnum" ref={num}>{HELPLINE}</span>}
          <a className="ghost" href={PORTAL} target="_blank" rel="noreferrer">cybercrime.gov.in ↗</a>
          <span className="sr-only" aria-live="polite">{copy === "copied" ? "Copied" : copy === "failed" ? "Couldn't copy. The number is selected." : ""}</span>
        </div>
      )}
    </div>
  );
}
