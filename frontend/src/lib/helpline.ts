import type { Level } from "../types/report";

// The helpline row (shown on Suspicious and Likely scam only, always visible inside What to do now): the two official actions a user may need.
// Pure data and functions; the component (components/Helpline.tsx) only shows them. Nothing here sends, stores or fetches anything.
// Dropped by the user, do not re-add: "Ask someone first" (a note to send on WhatsApp / SMS, 2026-10-23), the "Get help" toggle, and the
// "Copy & report on Chakshu" flow with its PII-mask port and link defanging (2026-10-23).

export type HelpLevel = Extract<Level, "suspicious" | "likely_scam">;

/** Only a warning verdict gets the helpline row (Suspicious, Likely scam), not No warning signs, Promotional or Can't judge. */
export const canGetHelp = (level: Level): level is HelpLevel => level === "suspicious" || level === "likely_scam";

export const CALL_URL = "tel:1930";
export const CYBERCRIME_URL = "https://cybercrime.gov.in";

export type HelpLang = "en" | "hi" | "kn";
/** `tag` is the BCP 47 tag for the lang attribute; `name` is the language's own name, shown on the switch. */
export const HELP_LANGS: { id: HelpLang; tag: string; name: string }[] = [
  { id: "en", tag: "en", name: "EN" },
  { id: "hi", tag: "hi", name: "हिंदी" },
  { id: "kn", tag: "kn", name: "ಕನ್ನಡ" },
];

/* Hindi wording is the model's and NOT yet checked by a native speaker (HELP_NEEDS_REVIEW.hi); Kannada was checked. Set hi to false only after
   a native speaker has signed it off. */
export const HELP_NEEDS_REVIEW: Record<HelpLang, boolean> = { en: false, hi: true, kn: false };

export const HELP_STRINGS: Record<HelpLang, { label: string; call: string; portal: string; hint: string }> = {
  en: {
    label: "Cyber crime helpline",
    call: "Call 1930",
    portal: "File a complaint on cybercrime.gov.in",
    hint: "If money was lost, call within one hour so the bank can hold the funds.",
  },
  hi: {
    label: "साइबर क्राइम हेल्पलाइन",
    call: "1930 पर कॉल करें",
    portal: "cybercrime.gov.in पर शिकायत दर्ज करें",
    hint: "यदि पैसे गए हैं, तो एक घंटे के भीतर कॉल करें, ताकि बैंक पैसे रोक सके।",
  },
  kn: {
    label: "ಸೈಬರ್ ಕ್ರೈಂ ಹೆಲ್ಪ್‌ಲೈನ್",
    call: "1930ಕ್ಕೆ ಕರೆ ಮಾಡಿ",
    portal: "cybercrime.gov.in ನಲ್ಲಿ ದೂರು ದಾಖಲಿಸಿ",
    hint: "ಹಣ ಕಳೆದುಕೊಂಡಿದ್ದರೆ ಒಂದು ಗಂಟೆಯೊಳಗೆ ಕರೆ ಮಾಡಿ, ಬ್ಯಾಂಕ್ ಹಣವನ್ನು ತಡೆಹಿಡಿಯಬಹುದು.",
  },
};
