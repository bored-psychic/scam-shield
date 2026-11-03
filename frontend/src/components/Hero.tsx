import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";
import gsap from "gsap";
import { mayAnimate, onSwitchStart } from "../lib/motion";
import { HERO, type TabKey } from "../lib/tabs";

/* The headline and its sub-line for a tab, and the headline's part of the tab switch (D30). Every word is its own pair of spans, so the words can move behind a mask (.masking, on only while they
   move: at rest the words' halo is not clipped); the spaces between them stay real text, so the heading reads as one sentence. The switch has two steps, never overlapping: the old headline leaves
   completely (words up and out, .3 s, power3.in), and only then React writes the new one, which enters word by word (.6 s, stagger .05, power4.out). There is one heading in the page at any moment. The
   sub-line fades out with the old headline and in after the new one. A click during a switch kills what is running and starts again from where the words are, towards the newest tab. Reduced motion:
   instant. A theme switch starting: everything jumps to the end state, so it snapshots the page at rest. */
export default function Hero({ tab }: { tab: TabKey }) {
  const [shown, setShown] = useState(tab);
  const h1 = useRef<HTMLHeadingElement>(null), line = useRef<HTMLParagraphElement>(null);
  const run = useRef<gsap.core.Timeline | null>(null), goal = useRef(tab);

  const words = () => h1.current!.querySelectorAll(".hwi");
  const stop = () => { run.current?.kill(); run.current = null; };
  const atRest = () => {
    gsap.set(words(), { clearProps: "all" });
    gsap.set(line.current, { clearProps: "all" });
    h1.current!.classList.remove("masking");
  };

  useLayoutEffect(() => {
    if (tab === goal.current) return;
    goal.current = tab;
    stop();
    if (!mayAnimate()) { atRest(); setShown(tab); return; }
    h1.current!.classList.add("masking");
    const enter = () => {
      flushSync(() => setShown(tab));
      run.current = gsap.timeline({ onComplete: () => { run.current = null; atRest(); } })
        .fromTo(words(), { yPercent: 110, opacity: 1 }, { yPercent: 0, duration: .6, stagger: .05, ease: "power4.out", immediateRender: true })
        .to(line.current, { opacity: 1, duration: .3, ease: "power2.out" });
    };
    run.current = gsap.timeline({ onComplete: enter })
      .to(words(), { yPercent: -110, opacity: 0, duration: .3, ease: "power3.in" }, 0)
      .to(line.current, { opacity: 0, duration: .3, ease: "power3.in" }, 0);
  }, [tab]);

  useEffect(() => {
    const off = onSwitchStart(() => {
      if (!run.current) return;
      stop();
      atRest();
      flushSync(() => setShown(goal.current));
    });
    return () => { off(); stop(); };
  }, []);

  const { lead, accent, sub } = HERO[shown];
  return (
    <section className="hero" aria-live="polite">
      <h1 ref={h1} data-tab={shown}>
        <span className="hline">
          {lead.split(" ").map((w, i) => <span key={`${shown}${i}`}><span className="hw"><span className="hwi">{w}</span></span>{" "}</span>)}
          <span className="hw" key={`${shown}acc`}><span className="hwi"><em>{accent}</em>?</span></span>
        </span>
      </h1>
      <p className="sub" ref={line}>{sub}</p>
    </section>
  );
}
