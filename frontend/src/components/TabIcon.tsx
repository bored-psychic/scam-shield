import type { TabKey } from "../lib/tabs";

// The tab icons of docs/design/tabs-home.html, one line each, in the text's colour.
export default function TabIcon({ tab, size = 16 }: { tab: TabKey; size?: number }) {
  const line = { stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round" } as const;
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      {tab === "message" && <path d="M4 5h16v11H9l-5 4z" {...line} />}
      {tab === "link" && <path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1" {...line} />}
      {tab === "payment" && <><rect x="3" y="6" width="18" height="12" rx="2" {...line} /><path d="M3 10h18M7 15h3" {...line} /></>}
      {tab === "app" && <><rect x="7" y="3" width="10" height="18" rx="2" {...line} /><path d="M11 17h2" {...line} /></>}
    </svg>
  );
}
