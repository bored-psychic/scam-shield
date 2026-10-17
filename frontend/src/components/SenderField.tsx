import { useEffect, useId, useRef, useState } from "react";
import { useReducedMotion } from "motion/react";
import { SENDER_HELP_INTRO, SENDER_HELP_OUTRO, SENDER_HINT, SENDER_MAX, SENDER_PLACEHOLDER, SUFFIX_HELP } from "../lib/sender";

type Props = { value: string; onChange: (sender: string) => void };

/** text with every sender ID in it (JM-JIOCPN-P) kept on one line: a browser would otherwise break it at a hyphen. */
export function NoBreakIds({ text }: { text: string }) {
  const parts = text.split(/(\b[A-Z]{2}-[A-Z0-9]{6}(?:-[PSTG])?\b)/);
  return <>{parts.map((p, i) => (i % 2 ? <span key={i} className="nobr">{p}</span> : p))}</>;
}

/* The optional sender (D22), under the message box: what the phone showed as the sender. Typed by hand (reading it from a screenshot is not
   built: BUGS.md). The info button opens a short explainer of TRAI's type letters, in the page flow under the hint (an overlay was covered by
   the phone footer, which sits in the flow above main's stacking context); it closes on a click outside, on Escape (focus back to the button)
   or on the button. Like the message, the value only goes into the /api/analyse request body.
   autoCapitalize is off on purpose: the API tells a bare header (JIOCPN) from a word (Amazon) by its capitals, and a phone keyboard set to
   capitalise would turn a typed brand name into a header. */
export default function SenderField({ value, onChange }: Props) {
  const id = useId(), [open, setOpen] = useState(false);
  const btn = useRef<HTMLButtonElement>(null), pop = useRef<HTMLDivElement>(null);
  const reduced = useReducedMotion();

  useEffect(() => {
    if (!open) return;
    // the explainer pushes the example chips down; on a desktop the footer is fixed to the bottom of the screen, so scroll just enough that the
    // explainer and the chips under it clear it (.spop's scroll-margin-bottom); nothing moves when they already do
    pop.current?.scrollIntoView({ block: "nearest", behavior: reduced ? "auto" : "smooth" });
    const onClick = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!pop.current?.contains(t) && !btn.current?.contains(t)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); btn.current?.focus(); } };
    document.addEventListener("click", onClick);
    addEventListener("keydown", onKey);
    return () => { document.removeEventListener("click", onClick); removeEventListener("keydown", onKey); };
  }, [open, reduced]);

  return (
    <div className="sender">
      <div className="srow">
        <label htmlFor={`${id}in`}>Sender <span>(optional)</span></label>
        <input id={`${id}in`} type="text" value={value} maxLength={SENDER_MAX} placeholder={SENDER_PLACEHOLDER} aria-describedby={`${id}hint`}
          autoComplete="off" autoCorrect="off" autoCapitalize="off" spellCheck={false} enterKeyHint="done" onChange={(e) => onChange(e.target.value)} />
        <button ref={btn} type="button" className="sinfo" aria-expanded={open} aria-controls={`${id}help`} aria-label="What a sender ID tells you"
          onClick={() => setOpen((o) => !o)}>i</button>
      </div>
      <p id={`${id}hint`} className="shint"><NoBreakIds text={SENDER_HINT} /></p>
      {open && (
        <div ref={pop} id={`${id}help`} className="spop" role="note">
          <p><NoBreakIds text={SENDER_HELP_INTRO} /></p>
          <ul>{SUFFIX_HELP.map(([k, v]) => <li key={k}><b>{k}</b><span>{v}</span></li>)}</ul>
          <p>{SENDER_HELP_OUTRO}</p>
        </div>
      )}
    </div>
  );
}
