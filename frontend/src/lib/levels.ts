import type { Effect, Level } from "../types/report";

// How a verdict looks: word (as LEVEL_LABEL in src/shield/contracts.py), colour and icon path (as the prototype's LV). D4: the verdict is
// always word + icon + colour. The prototype had no "Can't judge" verdict; it gets grey and the icon of the prototype's grey fallback panel.
// Promotional (D22) is new: a calm blue and a price tag, so it reads as neither "safe" (green tick) nor "careful" (amber).
export const LEVELS: Record<Level, { word: string; color: string; icon: string; roundJoin: boolean }> = {
  no_warning_signs: { word: "No warning signs found", color: "var(--green)", icon: "M5 12.5l4.2 4.2L19 7", roundJoin: true },
  suspicious: { word: "Suspicious", color: "var(--amber)", icon: "M12 7v6M12 16.5v.5", roundJoin: false },
  likely_scam: { word: "Likely scam", color: "var(--red)", icon: "M8 8l8 8M16 8l-8 8", roundJoin: false },
  cant_judge: { word: "Can't judge", color: "var(--grey)", icon: "M12 8v5M12 16v.5", roundJoin: false },
  promotional: { word: "Promotional", color: "var(--blue)", icon: "M13 4.5h6.5V11l-8.5 8.5L4.5 13zM16 8h.01", roundJoin: true },
};

// The one line under the verdict word. Fixed per level, never written per message: what a message triggered is said by the reasons,
// the underlines and the radar, all from the Report.
export const LEVEL_SUMMARY: Record<Level, string> = {
  likely_scam: "This message has strong signs of a scam.",
  suspicious: "Parts of this message are risky. Check before you act.",
  no_warning_signs: "Nothing strong was found. That does not prove it is safe.",
  cant_judge: "There isn't enough here to judge.",
  promotional: "Marketing from a registered business ID. Likely genuine, but not proof.",
};

// Evidence colour by effect (the prototype's COL for danger / caution / neutral; reassuring and unknown are new).
export const EFFECT_COLOR: Record<Effect, string> = {
  danger: "var(--red)", caution: "var(--amber)", neutral: "var(--grey)", reassuring: "var(--green)", unknown: "var(--grey)",
};

// A shape per effect, so colour is never the only signal (link checks, tooltip lines).
export const EFFECT_ICON: Record<Effect, string> = { danger: "✕", caution: "!", unknown: "?", neutral: "○", reassuring: "✓" };
