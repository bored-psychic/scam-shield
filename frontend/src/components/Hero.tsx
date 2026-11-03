import { HERO, type TabKey } from "../lib/tabs";

/* The headline and its sub-line for a tab. Every word is its own pair of spans, so the tab switch can move the words behind a mask; the spaces between
   them stay real text, so the heading reads as one sentence. */
export default function Hero({ tab }: { tab: TabKey }) {
  const { lead, accent, sub } = HERO[tab];
  const words = lead.split(" ");
  return (
    <section className="hero" aria-live="polite">
      <h1 data-tab={tab}>
        <span className="hline">
          {words.map((w, i) => <span key={`${tab}${i}`}><span className="hw"><span className="hwi">{w}</span></span>{" "}</span>)}
          <span className="hw" key={`${tab}acc`}><span className="hwi"><em>{accent}</em>?</span></span>
        </span>
      </h1>
      <p className="sub">{sub}</p>
    </section>
  );
}
