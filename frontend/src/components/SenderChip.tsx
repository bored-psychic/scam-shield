import type { Sender } from "../types/report";

// The sender on the result screen (D22): the API's own label ("Registered business · Promotional", "Personal mobile number", "Not recognised")
// and, for a business ID, its header. A mobile number is never in the Report, so it can never be shown here.
export default function SenderChip({ sender }: { sender: Sender }) {
  return (
    <div className={`schip ${sender.kind}`}>
      <span>Sender</span>
      <b>{sender.label}</b>
      {sender.header && <code>{sender.header}</code>}
    </div>
  );
}
