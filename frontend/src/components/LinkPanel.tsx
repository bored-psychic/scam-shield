import { Fragment } from "react";
import type { Report } from "../types/report";
import { linkBlocks, type LinkBlock } from "../lib/links";
import { EFFECT_COLOR, EFFECT_ICON } from "../lib/levels";

const TINT: Record<LinkBlock["effect"], string> = { danger: "", caution: "caution", unknown: "quiet", neutral: "quiet", reassuring: "quiet" };

function Address({ b }: { b: LinkBlock }) {
  if (b.quote === null) return <div className="url disguised">A disguised link</div>;
  if (!b.parts) return <div className="url">{b.quote}</div>;
  const { sub, owner, rest } = b.parts;
  return (
    <div className="url">
      {sub.map((l, i) => <Fragment key={i}>{l}<i>.</i></Fragment>)}
      <b className={TINT[b.effect] || undefined}>{owner.map((l, i) => <Fragment key={i}>{i > 0 && <i>.</i>}{l}</Fragment>)}</b>
      {rest}
    </div>
  );
}

// One block per link in the message (the child Reports): the host cut into its labels with the owner part set apart, and every check
// the link got, with a shape and colour per effect. Nothing here is fetched: the link is only ever a string.
export default function LinkPanel({ report }: { report: Report }) {
  const blocks = linkBlocks(report);
  return (
    <div className="box link g-link">
      <span className="sect" style={{ margin: 0 }}>{blocks.length > 1 ? "Links" : "Link"}</span>
      {blocks.map((b, i) => (
        <div key={i} className="lblock">
          <Address b={b} />
          <div className="checks">
            {b.checks.map((c, j) => (
              <div key={j}><i aria-hidden="true" style={{ color: EFFECT_COLOR[c.effect] }}>{EFFECT_ICON[c.effect]}</i><span>{c.title}</span></div>
            ))}
          </div>
        </div>
      ))}
      <div className="note">{blocks.length > 1 ? "The links were not opened." : "The link was not opened."}</div>
    </div>
  );
}
