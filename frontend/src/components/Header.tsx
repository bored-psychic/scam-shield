import type { Theme } from "../lib/theme";

type Props = { theme: Theme; onToggleTheme: (button: HTMLElement) => void };

// Logo, the "Checked on this device" pill (as in the prototype) and the sun / moon theme button (2026-10-18). The button shows the theme it
// switches TO (a sun in the dark theme, a moon in the light one) and says so in its label; the icon turns in when it changes, unless motion is reduced.
// The switch's animation starts from the button (lib/themeSwitch.ts: the black hole opens beside it).
export default function Header({ theme, onToggleTheme }: Props) {
  const next = theme === "dark" ? "light" : "dark";
  return (
    <header>
      <div className="mark">
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 2.5 4 5.6v6.1c0 4.7 3.3 8.6 8 9.8 4.7-1.2 8-5.1 8-9.8V5.6L12 2.5Z" style={{ stroke: "var(--ink)" }} strokeWidth="1.6" />
          <path d="m8.5 12.2 2.4 2.4 4.6-5" style={{ stroke: "var(--accent)" }} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        Scam Shield
      </div>
      <div className="hright">
        <div className="local" title="Messages are checked on this device. Nothing you paste is stored or sent."><i></i><span>Checked on this device</span></div>
        <button type="button" className="themebtn" onClick={(e) => onToggleTheme(e.currentTarget)} aria-label={`Switch to the ${next} theme`} title={`Switch to the ${next} theme`}>
          {next === "light" ? (
            <svg key="sun" viewBox="0 0 24 24" fill="none" aria-hidden="true" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round">
              <circle cx="12" cy="12" r="4.2" />
              <path d="M12 2.8v2.1M12 19.1v2.1M2.8 12h2.1M19.1 12h2.1M5.5 5.5l1.5 1.5M17 17l1.5 1.5M5.5 18.5 7 17M17 7l1.5-1.5" />
            </svg>
          ) : (
            <svg key="moon" viewBox="0 0 24 24" fill="none" aria-hidden="true" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round">
              <path d="M19.5 14.6A7.9 7.9 0 0 1 9.4 4.5a7.9 7.9 0 1 0 10.1 10.1Z" />
            </svg>
          )}
        </button>
      </div>
    </header>
  );
}
