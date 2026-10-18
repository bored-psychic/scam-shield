import type { LinkInfo } from "../types/report";
import { EFFECT_COLOR, EFFECT_ICON } from "../lib/levels";
import { factText, openByDefault, showWhy } from "../lib/facts";

type Props = {
  info: LinkInfo;
  onExpand?: (url: string) => void;   // the "Where does this short link go?" button; absent = no button
  expanding: boolean;                 // the request for this link is under way
  expandFailed: boolean;              // the last request for it got no answer from the checker
};

// D23 "Website details": a fact sheet about the link's background (registry, DNS, certificate logs, lists, popularity, owner), each row with
// a shape + colour per effect and, for a red flag, one line on why it matters. Pending rows say "Checking…", failed ones "Couldn't verify
// (...)". The link itself is never opened: the button asks only the shortener where a short link points.
export default function WebsiteDetails({ info, onExpand, expanding, expandFailed }: Props) {
  const short = info.host;
  return (
    <details className="facts" open={openByDefault(info) || undefined}>
      <summary>Website details</summary>
      {info.shortener && info.expandable && onExpand && (
        <div className="expand">
          <button type="button" className="ghost" onClick={() => onExpand(info.url)} disabled={expanding} aria-busy={expanding}>
            {expanding ? `Asking ${short}…` : "Where does this short link go?"}
          </button>
          <div className="note">
            {expandFailed ? "Couldn't reveal it: the checker didn't answer." : `Asks ${short} only, and ${short} may count it as a click. The destination is not opened.`}
          </div>
        </div>
      )}
      <dl>
        {info.facts.map((f) => (
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
      {info.sent.length > 0 && (
        <div className="note sent">Sent off this device: {info.sent.join("; ")}</div>
      )}
    </details>
  );
}
