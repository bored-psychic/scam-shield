import type { Details } from "../types/report";
import Light from "./Light";
import FactRows from "./FactRows";

type Props = { details: Details };

// Report.details (v6): the fact sheet of an input that is not a link: payment details, app details or sender details. The same rows as a link's "Website details" (icon + colour
// per effect, a "why" line for red flags, the source, "Checking…" while pending), always open: it is the panel's content, not an extra. Every value, effect and line comes from the
// API; nothing here judges anything. What a live check sent off the device is listed under the rows, as for a link.
export default function DetailsPanel({ details }: Props) {
  const sent = [...new Set(details.facts.flatMap((f) => (f.sent ? [f.sent] : [])))];
  return (
    <div className="box link g-link g-details" role="group" aria-label={details.title}>
      <Light />
      <span className="sect" style={{ margin: 0 }}>{details.title}</span>
      <div className="facts sheet">
        <FactRows facts={details.facts} />
        {sent.length > 0 && <div className="note sent">Sent off this device: {sent.join("; ")}</div>}
      </div>
      {details.note && <div className="note">{details.note}</div>}
    </div>
  );
}
