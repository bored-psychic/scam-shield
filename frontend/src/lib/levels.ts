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

// Plan 6.4: the line under the verdict per input, fixed and frontend-owned. A message's is LEVEL_SUMMARY; a link's and an email's are the same words with "link" / "email". A payment's
// and an app's are their own sentences: for them "No warning signs" never says "safe", and Can't judge says what only the payment app, or only an install, can show. Promotional is a
// message-only level (a registered business ID), so those two inputs never reach it; the Can't judge line stands in for it if one ever did.
const PAYMENT_SUMMARY: Record<Level, string> = {
  likely_scam: "This payment has strong signs of a scam.",
  suspicious: "Something about this payment is risky. Check before you pay.",
  no_warning_signs: "Nothing in it looks wrong. Only your payment app can show who you would pay.",
  cant_judge: "Only your payment app can show who owns this ID.",
  promotional: "Only your payment app can show who owns this ID.",
};
const APP_SUMMARY: Record<Level, string> = {
  likely_scam: "This app has strong signs of a fraud app.",
  suspicious: "Parts of this app are risky. Do not install it yet.",
  no_warning_signs: "It carries the official app's signature. Install apps from the Play Store all the same.",
  cant_judge: "A file check cannot tell what this app does once installed.",
  promotional: "A file check cannot tell what this app does once installed.",
};
const worded = (noun: string) => Object.fromEntries(Object.entries(LEVEL_SUMMARY).map(([k, v]) => [k, v.replace(/message/g, noun)])) as Record<Level, string>;
/** LEVEL_SUMMARY per input: `INPUT_SUMMARY[input][level]`. */
export const INPUT_SUMMARY: Record<"message" | "email" | "link" | "payment" | "app", Record<Level, string>> = {
  message: LEVEL_SUMMARY, email: worded("email"), link: worded("link"), payment: PAYMENT_SUMMARY, app: APP_SUMMARY,
};
export const levelSummary = (level: Level, noun: keyof typeof INPUT_SUMMARY = "message") => INPUT_SUMMARY[noun][level];

// Evidence colour by effect (the prototype's COL for danger / caution / neutral; reassuring and unknown are new).
export const EFFECT_COLOR: Record<Effect, string> = {
  danger: "var(--red)", caution: "var(--amber)", neutral: "var(--grey)", reassuring: "var(--green)", unknown: "var(--grey)",
};

// A shape per effect, so colour is never the only signal (link checks, tooltip lines).
export const EFFECT_ICON: Record<Effect, string> = { danger: "✕", caution: "!", unknown: "?", neutral: "○", reassuring: "✓" };
