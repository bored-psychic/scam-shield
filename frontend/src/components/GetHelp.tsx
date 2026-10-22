import { useEffect, useId, useRef, useState } from "react";
import { CALL_URL, CHAKSHU_URL, CYBERCRIME_URL, helpOrder, reportableMessage, type HelpLevel } from "../lib/getHelp";

type Props = {
  level: HelpLevel;
  message: string;           // exactly what was pasted: masked and defanged here before it is copied for Chakshu
  quotes: string[];          // the links in it, as written (defanged along with the rest)
};

const CALL_HINT = "Call within the first hour, the bank can freeze the money.";

/* "Get help" (shown on Suspicious and Likely scam only): a button that opens a small panel of two compact rows, no title and no paragraphs.
   Helpline: a tel:1930 link and cybercrime.gov.in (the "call within the first hour" hint is only the Call button's aria-label and title).
   Report scam: one anchor to Chakshu on Sanchar Saathi (new tab, so no popup blocker) whose click first copies the PII-masked, defanged message
   (lib/getHelp.ts); a short status line says it was copied. Nothing is submitted, sent or stored by this page. Likely scam shows Helpline then
   Report scam, Suspicious the reverse. English only, like the rest of the result page. ("Ask someone first" was dropped by the user, 2026-10-23.) */
export default function GetHelp({ level, message, quotes }: Props) {
  const [open, setOpen] = useState(false);
  const [report, setReport] = useState<"idle" | "copied" | "failed">("idle");
  const id = useId(), panelId = `${id}-panel`;
  const btn = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (report === "idle") return;
    const t = setTimeout(() => setReport("idle"), 5000);
    return () => clearTimeout(t);
  }, [report]);

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape" && open) { e.stopPropagation(); setOpen(false); btn.current?.focus(); }
  }

  /* The link itself opens Chakshu; this only copies first, in the same tap. */
  function copyReport() {
    navigator.clipboard.writeText(reportableMessage(message, quotes)).then(() => setReport("copied"), () => setReport("failed"));
  }

  const rows = {
    helpline: (
      <div className="helprow" key="helpline" role="group" aria-labelledby={`${id}-helpline`}>
        <span className="helplabel" id={`${id}-helpline`}>Helpline</span>
        <div className="helpbtns">
          <a className="callbtn" href={CALL_URL} aria-label={`Call 1930. ${CALL_HINT}`} title={CALL_HINT}>Call 1930</a>
          <a className="ghost helplink" href={CYBERCRIME_URL} target="_blank" rel="noopener noreferrer">cybercrime.gov.in <span aria-hidden="true">↗</span></a>
        </div>
      </div>
    ),
    report: (
      <div className="helprow" key="report" role="group" aria-labelledby={`${id}-report`}>
        <span className="helplabel" id={`${id}-report`}>Report scam</span>
        <div className="helpbtns">
          <a className="ghost helpchakshu" href={CHAKSHU_URL} target="_blank" rel="noopener noreferrer" onClick={copyReport}>
            Copy &amp; report on Chakshu <span aria-hidden="true">↗</span>
          </a>
        </div>
      </div>
    ),
  };

  return (
    <div className="ask" onKeyDown={onKeyDown}>
      <button type="button" ref={btn} className="ghost askbtn" aria-expanded={open} aria-controls={panelId} onClick={() => setOpen((o) => !o)}>
        Get help <span aria-hidden="true">{open ? "▴" : "▾"}</span>
      </button>
      {open && (
        <div className="askpanel" id={panelId} role="group" aria-label="Get help">
          {helpOrder(level).map((k) => rows[k])}
        </div>
      )}
      {report !== "idle" && (
        <p className={`helptoast${report === "failed" ? " bad" : ""}`} role="status">
          {report === "copied" ? "Copied – paste it on Chakshu after logging in" : "Couldn't copy – copy the message by hand from the result"}
        </p>
      )}
    </div>
  );
}
