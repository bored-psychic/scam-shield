import type { Failure } from "../api";
import { SCHEMA_VERSION } from "../types/report";

type Props = { failure: Failure; onRetry: () => void; onBack: () => void };

function describe(f: Failure): { text: string; retry: boolean } {
  switch (f.kind) {
    case "unreachable": return { text: "Couldn't reach the checker. Is the API running?", retry: true };
    case "rejected": return { text: f.detail, retry: false };   // the API's own words, e.g. "Paste a message to check."
    case "failed": return { text: f.detail, retry: true };
    case "schema": return { text: `The checker answered in a format this page can't read (schema version ${f.got}, expected ${SCHEMA_VERSION}).`, retry: false };
  }
}

// Shown instead of a result when the check did not come back. Back keeps the text in the box so it can be edited.
export default function ErrorPanel({ failure, onRetry, onBack }: Props) {
  const { text, retry } = describe(failure);
  return (
    <section className="box verdict" role="alert">
      <p className="m-0 text-base leading-normal">{text}</p>
      <div className="flex flex-wrap items-center gap-2">
        {retry && <button type="button" className="go" onClick={onRetry}>Retry</button>}
        <button type="button" className="ghost" onClick={onBack}>← Back to the message</button>
      </div>
    </section>
  );
}
