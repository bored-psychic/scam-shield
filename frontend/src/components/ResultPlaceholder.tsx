/* TEMPORARY: a plain result view so the API wiring can be checked end to end. Frontend part 2 replaces this file with the bento result
   from docs/design/README.md (verdict + radar, message with underlines, why, link, what to do now).
   Contract v2 has no summary or headline field: the one-line summaries are `reasons` (at most 3); `category` and `advice` are shown if
   set (to_report() fills neither yet). No score or percentage anywhere (D4). Link evidence lives in the child reports. */
import type { Report } from "../types/report";
import { EFFECT_COLOR, LEVELS } from "../lib/levels";

type Props = { report: Report; onAgain: () => void };

export default function ResultPlaceholder({ report, onAgain }: Props) {
  const lv = LEVELS[report.level];
  const evidence = [...report.evidence, ...report.children.flatMap((c) => c.evidence)];
  return (
    <section className="result" aria-live="polite">
      <div className="rtop">
        <button className="ghost" type="button" onClick={onAgain}>← Check another message</button>
        <span className="rmeta">Checked on this device · nothing was stored</span>
      </div>
      <div className="box verdict">
        <div className="vtop">
          <div className="vicon" style={{ background: lv.color }}>
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d={lv.icon} stroke="#04060A" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin={lv.roundJoin ? "round" : undefined} />
            </svg>
          </div>
          <div>
            <div className="vword" style={{ color: lv.color }}>{lv.word}</div>
            {report.category && <div className="vline">{report.category}</div>}
          </div>
        </div>
        {report.reasons.length > 0 && (
          <div>
            <span className="sect">Why</span>
            <ul className="m-0 grid list-none gap-1 p-0">{report.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
          </div>
        )}
        {report.advice.length > 0 && (
          <div>
            <span className="sect">What to do</span>
            <ul className="m-0 grid list-none gap-1 p-0">{report.advice.map((a, i) => <li key={i}>{a}</li>)}</ul>
          </div>
        )}
        <div>
          <span className="sect">Evidence</span>
          {evidence.length === 0 ? <p className="m-0 text-muted">None.</p> : (
            <ul className="m-0 grid list-none gap-2.5 p-0">
              {evidence.map((e, i) => (
                <li key={`${e.id}-${i}`} className="grid gap-0.5">
                  <span className="font-mono text-[11.5px]" style={{ color: EFFECT_COLOR[e.effect] }}>● {e.tag} <span className="text-faint">· {e.effect}</span></span>
                  <span>{e.title}</span>
                  {e.quote !== null && <span className="text-[13.5px] text-muted [overflow-wrap:anywhere]">“{e.quote}”</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  );
}
