import type { Fact } from "../types/report";
import { EFFECT_COLOR, EFFECT_ICON } from "../lib/levels";
import { factText, showWhy } from "../lib/facts";

// The rows of a fact sheet: label, a shape + colour per effect, the value, for a red flag one line on why it matters, and where the fact came from. Shared by a link's
// "Website details" (WebsiteDetails) and by Report.details (DetailsPanel), so both read alike. Pending rows say "Checking…", failed ones "Couldn't verify (...)".
export default function FactRows({ facts }: { facts: Fact[] }) {
  return (
    <dl>
      {facts.map((f) => (
        <div key={f.key} className={`frow ${f.status}`}>
          <dt>{f.label}</dt>
          <dd>
            <span className="fval">
              <i aria-hidden="true" style={{ color: EFFECT_COLOR[f.effect] }}>{f.status === "pending" ? "·" : EFFECT_ICON[f.effect]}</i>
              <span>{factText(f)}</span>
            </span>
            {showWhy(f) && f.status !== "pending" && <small>{f.why}</small>}
            {f.source && f.status === "ok" && <small className="src">{f.source}</small>}
          </dd>
        </div>
      ))}
    </dl>
  );
}
