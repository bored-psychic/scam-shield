import type { Evidence, Sender } from "../types/report";
import { EFFECT_COLOR } from "../lib/levels";

// The sender on the result screen (D22): the API's own label ("Registered business · Promotional", "Personal mobile number", "Not recognised")
// and, for a business ID, its header. A mobile number is never in the Report, so it can never be shown here. note: the sender evidence when it
// is not one of the reasons (lib/sender.ts senderNote), as one line under the chip with a dot in its effect colour.
export default function SenderChip({ sender, note = null }: { sender: Sender; note?: Evidence | null }) {
  return (
    <div className="sblock">
      <div className={`schip ${sender.kind}`}>
        <span>Sender</span>
        <b>{sender.label}</b>
        {sender.header && <code>{sender.header}</code>}
      </div>
      {note && <p className="snote"><i aria-hidden="true" style={{ background: EFFECT_COLOR[note.effect] }}></i><span>{note.title}</span></p>}
    </div>
  );
}
