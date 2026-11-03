import { Fragment } from "react";
import type { Report } from "../types/report";
import { linkBlocks, type LinkBlock } from "../lib/links";
import { EFFECT_COLOR, EFFECT_ICON } from "../lib/levels";
import Light from "./Light";
import WebsiteDetails from "./WebsiteDetails";

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

type Props = {
  report: Report;
  onExpand?: (url: string) => void;   // D23: ask a shortener where its link goes (the page re-checks the message with expand)
  expanding: string | null;           // the short link being revealed now
  expandFailed: string | null;        // the short link whose last request got no answer
};

// One block per link in the message (the child Reports): the host cut into its labels with the owner part set apart, every check the link
// got with a shape and colour per effect, and (D23) its "Website details". Nothing here is fetched: the link is only ever a string; the live
// checks look up its domain name, never the site.
export default function LinkPanel({ report, onExpand, expanding, expandFailed }: Props) {
  const blocks = linkBlocks(report);
  const looked = blocks.some((b) => b.info && b.info.sent.length > 0);
  return (
    <div className="box link g-link">
      <Light />
      <span className="sect" style={{ margin: 0 }}>{blocks.length > 1 ? "Links" : "Link"}</span>
      {blocks.map((b, i) => (
        <div key={i} className="lblock">
          <Address b={b} />
          <div className="checks">
            {b.checks.map((c, j) => (
              <div key={j}><i aria-hidden="true" style={{ color: EFFECT_COLOR[c.effect] }}>{EFFECT_ICON[c.effect]}</i><span>{c.title}</span></div>
            ))}
          </div>
          {b.info && <WebsiteDetails info={b.info} onExpand={onExpand} expanding={expanding === b.info.url} expandFailed={expandFailed === b.info.url} />}
        </div>
      ))}
      <div className="note">
        {blocks.length > 1 ? "The links were not opened." : "The link was not opened."}
        {looked && " Only the website's name was looked up."}
      </div>
    </div>
  );
}
