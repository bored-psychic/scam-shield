import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useReducedMotion } from "motion/react";
import type { Evidence, Report } from "../types/report";
import { allEvidence, blips as blipsOf, clusterOf, reasonTargets, segments, type Cluster } from "../lib/evidence";
import VerdictPanel from "./VerdictPanel";
import MessagePanel, { type Pulse } from "./MessagePanel";
import WhyPanel from "./WhyPanel";
import LinkPanel from "./LinkPanel";
import WhatToDo from "./WhatToDo";
import Tip, { type TipAt } from "./Tip";
import { useMedia } from "../lib/useMedia";
import { SENDER_TIP, showSenderTip } from "../lib/sender";
import { linkQuotes } from "../lib/getHelp";

type Props = {
  report: Report;
  text: string;            // exactly what was sent, which the spans index
  onAgain: () => void;
  raised?: boolean;        // D23: the live link checks raised the verdict after it was first shown
  onExpand?: (url: string) => void;   // D23: reveal a short link's destination (asks the shortener only)
  expanding?: string | null;
  expandFailed?: string | null;
};

const PULSE_MS = 2400, PULSE_STILL_MS = 1500;   // two 1.2 s pulses; with reduced motion a static highlight instead

// Fully on screen, and inside the message panel's visible part: then pointing at it needs no scroll.
function inView(el: HTMLElement) {
  const r = el.getBoundingClientRect(), box = el.closest("[data-scroll]")?.getBoundingClientRect();
  return r.top >= 0 && r.bottom <= innerHeight && (!box || (r.top >= box.top && r.bottom <= box.bottom));
}

/* The result screen (docs/design/README.md, Screens 3): the verdict + radar, the message with its underlined parts, why, the links and
   what to do now. On a wide screen there are two columns, each panel as tall as its content (verdict, why | message, links, what to do);
   on phones one column in the order verdict, message, why, links, what to do. The two arrangements are two different DOM orders, not a
   CSS reordering, so the tab order always follows what is on screen. Everything shown comes from the Report; the one line under the
   verdict is fixed per level (lib/levels.ts). The 0-100 risk score (D24) is shown as a warning-sign meter, never as a percentage; the model's own
   score, its thresholds and timings are not shown (D4). */
export default function Result({ report, text, onAgain, raised = false, onExpand, expanding = null, expandFailed = null }: Props) {
  const reduced = useReducedMotion();
  const twoColumns = useMedia("(min-width: 901px)");   // the same breakpoint as the stylesheet's
  const root = useRef<HTMLElement>(null), heading = useRef<HTMLHeadingElement>(null);
  const segs = useMemo(() => segments(text, allEvidence(report), report.level), [text, report]);
  const blips = useMemo(() => blipsOf(report), [report]);
  const targets = useMemo(() => reasonTargets(report), [report]);
  const [tip, setTip] = useState<TipAt | null>(null);
  const [pulse, setPulse] = useState<Pulse | null>(null);

  const showTip = useCallback((cluster: Cluster, anchor: HTMLElement) => setTip({ cluster, anchor, show: true }), []);
  const hideTip = useCallback(() => setTip((t) => (t?.show ? { ...t, show: false } : t)), []);
  const point = (e: Evidence) => {
    const c = clusterOf(segs, e);
    if (c) setPulse((p) => ({ id: c.id, n: (p?.n ?? 0) + 1, on: true }));
  };
  const pointable = (list: (Evidence | null)[]) => list.map((e) => clusterOf(segs, e) !== null);

  useEffect(() => { heading.current?.focus({ preventScroll: true }); }, []);   // screen readers start at the verdict

  useEffect(() => {   // after a tap on a reason or a radar tag: bring the pulsing part into view, then show its tooltip
    if (!pulse?.on) return;
    const el = root.current?.querySelector<HTMLElement>(`mark[data-cid="${pulse.id}"]`);
    const c = segs.find((s) => s.cluster?.id === pulse.id)?.cluster;
    let wait = 0;
    // the page and the message panel may both scroll, and each ends on its own: show the tooltip once nothing has scrolled for 120 ms
    const settle = () => {
      clearTimeout(wait);
      wait = setTimeout(() => { removeEventListener("scroll", settle, { capture: true }); if (el && c) showTip(c, el); }, 120);
    };
    if (el && c) {
      if (inView(el)) showTip(c, el);
      else {
        addEventListener("scroll", settle, { capture: true, passive: true });
        el.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: innerWidth <= 900 ? "center" : "nearest" });
        settle();
      }
    }
    const off = setTimeout(() => setPulse((p) => (p && p.n === pulse.n ? { ...p, on: false } : p)), reduced ? PULSE_STILL_MS : PULSE_MS);
    return () => { clearTimeout(wait); clearTimeout(off); removeEventListener("scroll", settle, { capture: true }); };
  }, [pulse, segs, reduced, showTip]);

  const hasLinks = report.children.length > 0;
  const verdict = <VerdictPanel level={report.level} blips={blips} pointable={pointable(blips)} onPoint={point} headingRef={heading}
                                note={raised ? "Raised after the website checks." : null}
                                score={report.risk_score} lowered={report.lowered?.text ?? null} />;
  const message = <MessagePanel segs={segs} truncated={report.meta.truncated} pulse={pulse} onShow={showTip} onHide={hideTip} />;
  const why = <WhyPanel reasons={report.reasons} targets={targets} pointable={pointable(targets)} onPoint={point} />;
  const links = hasLinks && <LinkPanel report={report} onExpand={onExpand} expanding={expanding} expandFailed={expandFailed} />;
  const todo = <WhatToDo advice={report.advice} level={report.level} tip={showSenderTip(report) ? SENDER_TIP : null}
                       help={{ message: text, quotes: linkQuotes(report) }} />;
  return (
    <section className="result" ref={root}>
      <div className="rtop">
        <button className="ghost" type="button" onClick={onAgain}>← Check another message</button>
        <span className="rmeta">Checked on this device · nothing was stored</span>
      </div>
      <div className="bento">
        {twoColumns ? (
          <>
            <div className="bcol">{verdict}{why}</div>
            <div className="bcol">{message}{links}{todo}</div>
          </>
        ) : (
          <>{verdict}{message}{why}{links}{todo}</>
        )}
      </div>
      <Tip at={tip} onHide={hideTip} />
    </section>
  );
}
