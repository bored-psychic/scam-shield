import { useEffect, useRef, useState } from "react";
import type { Hit } from "./Globe";

export type FeedItem = Hit & { id: number };

// "Simulated from real rankings · not live ⓘ" with its sources popover, and the last 4 simulated hits from the globe.
export default function Footer({ hits }: { hits: FeedItem[] }) {
  const [open, setOpen] = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);
  const popRef = useRef<HTMLDivElement>(null);

  useEffect(() => {   // close on a click outside or Escape, as the prototype did
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!popRef.current?.contains(t) && !btnRef.current?.contains(t)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); btnRef.current?.focus(); } };
    document.addEventListener("click", onClick);
    addEventListener("keydown", onKey);
    return () => { document.removeEventListener("click", onClick); removeEventListener("keydown", onKey); };
  }, [open]);

  return (
    <footer>
      <div className="srcwrap">
        <button type="button" className="srcbtn" ref={btnRef} aria-expanded={open} aria-controls="srcpop" onClick={() => setOpen((o) => !o)}>
          <i></i>Simulated from real rankings · not live <b>ⓘ</b>
        </button>
        {open && (
          // The prototype's text and links, minus its line "Verdicts on this page are mocked too": here they come from the checker.
          <div className="srcpop" id="srcpop" ref={popRef}>
            <p><b>Not live.</b> Each line is a simulated attack, drawn at random from real published rankings.</p>
            <p><span className="k wci"></span><b>Red</b> lines start in the biggest cybercrime hubs of the <a href="https://www.ox.ac.uk/news/2024-04-10-world-first-cybercrime-index-ranks-countries-cybercrime-threat-level" target="_blank" rel="noopener noreferrer">World Cybercrime Index</a> (Oxford &amp; UNSW, PLOS ONE, 2024): Russia, Ukraine, China, US, Nigeria, Romania, North Korea, UK, Brazil, India. Weighted by index score (published for the top 5; 6–10 estimated from rank).</p>
            <p><span className="k ddos"></span><b>Orange</b> lines start in the top-10 DDoS source countries of the <a href="https://blog.cloudflare.com/ddos-threat-report-2025-q4/" target="_blank" rel="noopener noreferrer">Cloudflare DDoS report, Q4 2025</a>: Bangladesh, Ecuador, Indonesia, Argentina, Hong Kong, Ukraine, Vietnam, Taiwan, Singapore, Peru.</p>
            <p>All lines land in that report's top-10 most attacked locations: China, Hong Kong, Germany, Brazil, US, UK, Vietnam, Azerbaijan, India, Singapore. Weighted by rank.</p>
          </div>
        )}
      </div>
      <div className="feed" aria-hidden="true">
        {hits.map((h) => (
          <div key={h.id} className={`ev ${h.kind}`}><i></i>{`${h.src} → ${h.tgt} `}<span>{h.kind === "wci" ? "cybercrime hub" : "DDoS"}</span></div>
        ))}
      </div>
    </footer>
  );
}
