import type { Effect, Level } from "../types/report";

// How a verdict looks: word (as LEVEL_LABEL in src/shield/contracts.py), colour and icon path (as the prototype's LV). D4: the verdict is
// always word + icon + colour. The prototype had no "Can't judge" verdict; it gets grey and the icon of the prototype's grey fallback panel.
export const LEVELS: Record<Level, { word: string; color: string; icon: string; roundJoin: boolean }> = {
  no_warning_signs: { word: "No warning signs found", color: "var(--green)", icon: "M5 12.5l4.2 4.2L19 7", roundJoin: true },
  suspicious: { word: "Suspicious", color: "var(--amber)", icon: "M12 7v6M12 16.5v.5", roundJoin: false },
  likely_scam: { word: "Likely scam", color: "var(--red)", icon: "M8 8l8 8M16 8l-8 8", roundJoin: false },
  cant_judge: { word: "Can't judge", color: "var(--grey)", icon: "M12 8v5M12 16v.5", roundJoin: false },
};

// Evidence colour by effect (the prototype's COL for danger / caution / neutral; reassuring and unknown are new).
export const EFFECT_COLOR: Record<Effect, string> = {
  danger: "var(--red)", caution: "var(--amber)", neutral: "var(--grey)", reassuring: "var(--green)", unknown: "var(--grey)",
};
