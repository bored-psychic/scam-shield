import type { Evidence } from "../types/report";
import { EFFECT_COLOR } from "../lib/levels";

type Props = {
  reasons: string[];                // Report.reasons (at most 3), shown as sent
  targets: (Evidence | null)[];     // reasonTargets(): the evidence each reason is the title of
  pointable: boolean[];             // per reason: whether that evidence has an underlined part
  onPoint: (e: Evidence) => void;
};

// Why: the reasons as buttons. Tapping one pulses its part of the message; a reason with nothing to point at (the wording model, a
// disguised link, "Too little text to judge") does nothing and says nothing about the message.
export default function WhyPanel({ reasons, targets, pointable, onPoint }: Props) {
  return (
    <div className="box g-why">
      <span className="sect">Why</span>
      {reasons.length === 0 ? <div className="note">No warning signs were found in this message.</div> : (
        <div className="reasons">
          {reasons.map((r, i) => {
            const t = targets[i];
            return (
              <button key={r} type="button" className={pointable[i] ? "reason" : "reason nospan"} onClick={() => { if (t && pointable[i]) onPoint(t); }}>
                <span className="dot" style={{ background: t ? EFFECT_COLOR[t.effect] : "var(--grey)" }}></span>
                <span>{r}{pointable[i] && <small>Tap to see it in the message</small>}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
