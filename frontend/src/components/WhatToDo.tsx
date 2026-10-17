import { useEffect, useId, useRef, useState } from "react";
import type { Level } from "../types/report";
import { NoBreakIds } from "./SenderField";

const HELPLINE = "1930";   // the national cyber-fraud helpline
const PORTAL = "https://cybercrime.gov.in";

type Props = { advice: string[]; level: Level; tip: string | null };

/* What to do now: Report.advice as steps to tick off (in memory only, gone with the result), as the backend wrote them. On a warning
   verdict also the helpline and the reporting portal. Copying uses the clipboard; where that is refused, the number is shown selected.
   tip: the "check who sent it" line (lib/sender.ts, D22), shown as a note rather than a step, when the sender was left blank. */
export default function WhatToDo({ advice, level, tip }: Props) {
  const uid = useId();
  const [done, setDone] = useState<boolean[]>(() => advice.map(() => false));
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
      {advice.map((a, i) => (
        <label key={i} htmlFor={`${uid}${i}`}>
          <input id={`${uid}${i}`} type="checkbox" checked={done[i]} onChange={(e) => setDone((d) => d.map((v, j) => (j === i ? e.target.checked : v)))} />
          <span>{a}</span>
        </label>
      ))}
      {tip && <p className="sendertip"><b>Tip</b><NoBreakIds text={tip} /></p>}
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
