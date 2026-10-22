import type { Level, Report } from "../types/report";

// "Ask someone first": the note a user can send to a person they trust before paying or sharing anything. Pure functions; the component
// (components/AskFirst.tsx) only shows the result. Nothing here sends, stores or fetches anything: the WhatsApp and SMS links are plain
// hrefs that open the user's own app when they tap them, and no phone number is needed because the user picks the contact there.

export type NoteLang = "en" | "hi" | "kn";
export type AskLevel = Extract<Level, "suspicious" | "likely_scam">;

export const NOTE_LANGS: { id: NoteLang; label: string; lang: string }[] = [
  { id: "en", label: "English", lang: "en" },
  { id: "hi", label: "हिन्दी", lang: "hi" },
  { id: "kn", label: "ಕನ್ನಡ", lang: "kn" },
];

/** Only a warning verdict gets the button (Suspicious, Likely scam), not No warning signs, Promotional or Can't judge. */
export const canAskFirst = (level: Level): level is AskLevel => level === "suspicious" || level === "likely_scam";

/* Hindi and Kannada wording was checked by a native speaker (2026-10-22), so NEEDS_REVIEW is false for both; set a language back to true to
   show the "not yet checked" line next to the picker again. The reason is the backend's English sentence in every language (the Report has no
   translations), so a Hindi or Kannada note carries one English clause. */
export const NEEDS_REVIEW: Record<NoteLang, boolean> = { en: false, hi: false, kn: false };

const WORDS: Record<NoteLang, { verdict: Record<AskLevel, string>; head: string; says: string; tail: string; message: string }> = {
  en: {
    verdict: { suspicious: "Suspicious", likely_scam: "Likely scam" },
    head: "Hi, I got a message that might be a scam.",
    says: "Scam Shield says:",
    tail: "Please call me before I pay or share anything.",
    message: "The message:",
  },
  hi: {
    verdict: { suspicious: "संदिग्ध", likely_scam: "स्कैम होने की संभावना अधिक" },
    head: "नमस्ते, मुझे एक मैसेज मिला है जो स्कैम हो सकता है।",
    says: "Scam Shield के अनुसार:",
    tail: "पैसे भेजने या कुछ भी शेयर करने से पहले कृपया मुझे फ़ोन करें।",
    message: "मैसेज:",
  },
  kn: {
    verdict: { suspicious: "ಸಂಶಯಾಸ್ಪದ", likely_scam: "ಸ್ಕ್ಯಾಮ್ ಆಗಿರುವ ಸಾಧ್ಯತೆ ಹೆಚ್ಚು" },
    head: "ನಮಸ್ಕಾರ, ನನಗೆ ಒಂದು ಸಂದೇಶ ಬಂದಿದೆ, ಅದು ಸ್ಕ್ಯಾಮ್ ಆಗಿರಬಹುದು.",
    says: "Scam Shield ಪ್ರಕಾರ:",
    tail: "ನಾನು ಹಣ ಕಳುಹಿಸುವ ಅಥವಾ ಏನನ್ನಾದರೂ ಹಂಚಿಕೊಳ್ಳುವ ಮೊದಲು ದಯವಿಟ್ಟು ನನಗೆ ಕರೆ ಮಾಡಿ.",
    message: "ಸಂದೇಶ:",
  },
};

/* "Get help" panel (2026-10-22): the panel around the note. Three sections: 1930 + cybercrime.gov.in (lost money / shared an OTP), report to Chakshu
   (Sanchar Saathi), ask someone you trust (the note above). Likely scam shows them 1 -> 2 -> 3, Suspicious 3 -> 2 -> 1. NEW HINDI AND KANNADA
   STRINGS BELOW ARE THE MODEL'S, NOT CHECKED BY A NATIVE SPEAKER: HELP_NEEDS_REVIEW is true for both and the panel says so. */
export const HELP_NEEDS_REVIEW: Record<NoteLang, boolean> = { en: false, hi: true, kn: true };
export const CALL_URL = "tel:1930";
export const CYBERCRIME_URL = "https://cybercrime.gov.in";
export const CHAKSHU_URL = "https://sancharsaathi.gov.in/sfc/";

export type HelpWords = {
  title: string; lostHead: string; call: string; portal: string; hour: string;
  reportHead: string; chakshu: string; steps: [string, string, string]; reportNote: string; copied: string; copyFailed: string;
  askHead: string;
};
export const HELP: Record<NoteLang, HelpWords> = {
  en: {
    title: "Get help",
    lostHead: "Lost money or shared an OTP/PIN?",
    call: "Call 1930 now",
    portal: "Report on cybercrime.gov.in",
    hour: "Call within the first hour, the bank can freeze the money.",
    reportHead: "Report this message",
    chakshu: "Copy message & open Chakshu",
    steps: ["Log in with your mobile number.", "Choose the medium: SMS, WhatsApp or call.", "Paste the message."],
    reportNote: "Scam Shield sends nothing. You submit the report yourself on the government site.",
    copied: "Message copied", copyFailed: "Couldn't copy the message. Copy it by hand from the result.",
    askHead: "Ask someone you trust",
  },
  hi: {
    title: "मदद लें",
    lostHead: "पैसे गँवा दिए या OTP/PIN बता दिया?",
    call: "अभी 1930 पर कॉल करें",
    portal: "cybercrime.gov.in पर रिपोर्ट करें",
    hour: "पहले एक घंटे में कॉल करें, बैंक पैसे फ़्रीज़ कर सकता है।",
    reportHead: "इस मैसेज की रिपोर्ट करें",
    chakshu: "मैसेज कॉपी करें और चक्षु खोलें",
    steps: ["अपने मोबाइल नंबर से लॉग इन करें।", "माध्यम चुनें: SMS, WhatsApp या कॉल।", "मैसेज पेस्ट करें।"],
    reportNote: "Scam Shield कुछ नहीं भेजता। रिपोर्ट आप खुद सरकारी साइट पर सबमिट करते हैं।",
    copied: "मैसेज कॉपी हो गया", copyFailed: "मैसेज कॉपी नहीं हो सका। नतीजे से हाथ से कॉपी करें।",
    askHead: "किसी भरोसेमंद व्यक्ति से पूछें",
  },
  kn: {
    title: "ಸಹಾಯ ಪಡೆಯಿರಿ",
    lostHead: "ಹಣ ಕಳೆದುಕೊಂಡಿದ್ದೀರಾ ಅಥವಾ OTP/PIN ಹಂಚಿಕೊಂಡಿದ್ದೀರಾ?",
    call: "ಈಗಲೇ 1930 ಗೆ ಕರೆ ಮಾಡಿ",
    portal: "cybercrime.gov.in ನಲ್ಲಿ ವರದಿ ಮಾಡಿ",
    hour: "ಮೊದಲ ಒಂದು ಗಂಟೆಯೊಳಗೆ ಕರೆ ಮಾಡಿ, ಬ್ಯಾಂಕ್ ಹಣವನ್ನು ಫ್ರೀಜ್ ಮಾಡಬಹುದು.",
    reportHead: "ಈ ಸಂದೇಶವನ್ನು ವರದಿ ಮಾಡಿ",
    chakshu: "ಸಂದೇಶ ನಕಲಿಸಿ ಮತ್ತು ಚಕ್ಷು ತೆರೆಯಿರಿ",
    steps: ["ನಿಮ್ಮ ಮೊಬೈಲ್ ಸಂಖ್ಯೆಯಿಂದ ಲಾಗಿನ್ ಮಾಡಿ.", "ಮಾಧ್ಯಮ ಆರಿಸಿ: SMS, WhatsApp ಅಥವಾ ಕರೆ.", "ಸಂದೇಶವನ್ನು ಪೇಸ್ಟ್ ಮಾಡಿ."],
    reportNote: "Scam Shield ಏನನ್ನೂ ಕಳುಹಿಸುವುದಿಲ್ಲ. ವರದಿಯನ್ನು ನೀವೇ ಸರ್ಕಾರಿ ಸೈಟ್‌ನಲ್ಲಿ ಸಲ್ಲಿಸುತ್ತೀರಿ.",
    copied: "ಸಂದೇಶ ನಕಲಾಗಿದೆ", copyFailed: "ಸಂದೇಶ ನಕಲಿಸಲಾಗಲಿಲ್ಲ. ಫಲಿತಾಂಶದಿಂದ ಕೈಯಾರೆ ನಕಲಿಸಿ.",
    askHead: "ನಂಬಿಕಸ್ಥರನ್ನು ಕೇಳಿ",
  },
};

/** Which sections, top to bottom: Likely scam leads with the emergency steps, Suspicious with asking someone first. */
export const helpOrder = (level: AskLevel): ("lost" | "report" | "ask")[] =>
  level === "likely_scam" ? ["lost", "report", "ask"] : ["ask", "report", "lost"];

/** The message as the Chakshu form should get it: PII-masked and defanged like the share note, but not cut at MAX_MESSAGE_CHARS (a report wants all of it). */
export const reportableMessage = (text: string, quotes: string[] = []): string => defang(maskPii(text.trim()), quotes);

/** The most of the message that goes into a note. A WhatsApp link carries the whole note in its address, and Hindi and Kannada letters take nine
 *  characters each once percent-encoded, so an unbounded paste could exceed what a browser or app accepts. */
export const MAX_MESSAGE_CHARS = 500;

/* PII masks for the shared copy of the message. The Report does not carry a masked copy of the text (the result screen shows what was pasted), so
   the same masks the data pipeline uses are applied here: a port of MASKS in src/pii.py, same order, same tokens. Python's \w, \b and \d are
   Unicode-aware and JavaScript's are ASCII, so those are spelled out with \p{..} and lookarounds. Keep in step with src/pii.py (lib tests F6 check
   the cases). Victim names are not masked there either. */
const W = "[\\p{L}\\p{N}_]", NOT_W = "(?<![\\p{L}\\p{N}_])", NOT_W_AFTER = "(?![\\p{L}\\p{N}_])";
// the NPCI app / bank handle list of src/pii.py UPI_HANDLES (longest first, as there)
const UPI_HANDLES = [
  "abfspay", "airtel", "apl", "aubank", "axis", "axisb", "axisbank", "axl", "barodampay", "boi", "cbin", "centralbank", "citi",
  "cnrb", "cub", "dbs", "dlb", "equitas", "ezeepay", "fbl", "federal", "freecharge", "hdfc", "hdfcbank", "hsbc", "ibl", "icici",
  "idbi", "idfcbank", "idfcfirst", "ikwik", "indianbank", "indus", "iob", "jio", "jkb", "jupiteraxis", "kbl", "kmbl", "kotak",
  "kvb", "mahb", "mairtel", "naviaxis", "okaxis", "okhdfcbank", "okicici", "oksbi", "paytm", "pingpay", "pnb", "postbank", "psb",
  "ptaxis", "pthdfc", "ptsbi", "ptyes", "rapl", "rbl", "sbi", "sc", "sib", "slice", "superyes", "tapicici", "timecosmos", "tjsb",
  "uboi", "uco", "unionbank", "upi", "waaxis", "wahdfcbank", "waicici", "wasbi", "yapl", "ybl", "yesbank", "yesbankltd",
].sort((a, b) => b.length - a.length);
const MASKS: [RegExp, string][] = [
  [new RegExp(`(?:${W}|[.+-])+@(?:${W}|-)+\\.(?:${W}|\\.)+`, "gu"), "<EMAIL>"],
  [new RegExp(`${NOT_W}(?:${W}|[.-]){2,}@(?:${UPI_HANDLES.join("|")})${NOT_W_AFTER}`, "giu"), "<UPI_ID>"],
  [new RegExp(`${NOT_W}(?:${W}|[.+-])+@[A-Za-z](?:${W}|-)*`, "gu"), "<EMAIL>"],
  [new RegExp(`(?:\\+91[\\s-]?|\\+92[\\s-]?|(?<![\\p{L}\\p{N}_])0)?${NOT_W}[6-9]\\d{4}[\\s-]?\\d{5}${NOT_W_AFTER}`, "gu"), "<PHONE>"],
  [new RegExp(`${NOT_W}(?:XX|xx|\\*{2,})?\\d{9,18}${NOT_W_AFTER}`, "gu"), "<ACCOUNT>"],
];

export function maskPii(text: string): string {
  let t = text.replaceAll("<UPI>", "<UPI_ID>");
  for (const [rx, tok] of MASKS) t = t.replace(rx, tok);
  return t;
}

/** Make links in the shared copy unclickable (https://x.com -> hxxps://x[.]com), so the person who receives the note cannot open a scam link by
 *  tapping it in WhatsApp or SMS. The report's own link quotes are defanged too, which catches a bare "name.top" that an app would also turn
 *  into a link. */
export function defang(text: string, quotes: string[] = []): string {
  const dots = (s: string) => s.replace(/\./g, "[.]");
  let t = text;
  for (const q of [...new Set(quotes)].filter((x) => x.length > 3).sort((a, b) => b.length - a.length)) {
    t = t.split(q).join(dots(q.replace(/^http/i, "hxxp")));
  }
  t = t.replace(/\b(?:https?:\/\/|www\.)[^\s<>"')\]]+/gi, (m) => dots(m.replace(/^http/i, "hxxp")));
  return t.replace(/\bhttp(?=s?:\/\/)/gi, "hxxp");   // a scheme the PII mask cut short ("http://<EMAIL>/verify"): still not a link
}

/** The message as it goes into a note: PII-masked, links defanged, at most MAX_MESSAGE_CHARS characters. */
export function shareableMessage(text: string, quotes: string[] = []): string {
  const clean = defang(maskPii(text.trim()), quotes);
  const chars = Array.from(clean);
  return chars.length > MAX_MESSAGE_CHARS ? `${chars.slice(0, MAX_MESSAGE_CHARS).join("").trimEnd()}…` : clean;
}

/** The link quotes of a Report, as written in the message (for defang). */
export const linkQuotes = (report: Report): string[] =>
  report.children.flatMap((c) => c.evidence.map((e) => e.quote).filter((q): q is string => q !== null));

/** The note. Default: verdict + the top reason + the request to call first. With `message`, the (already shareable) message is appended. */
export function buildNote(level: AskLevel, reason: string | null, lang: NoteLang, message: string | null = null): string {
  const w = WORDS[lang];
  const r = reason?.trim().replace(/[.\s]+$/, "");
  const says = `${w.says} ${w.verdict[level]}${r ? ` – ${r}` : ""}.`;
  const note = `${w.head} ${says} ${w.tail}`;
  return message ? `${note}\n\n${w.message}\n${message}` : note;
}

/** wa.me/?text=... opens WhatsApp's contact picker with the note typed in. encodeURIComponent writes every non-ASCII letter as UTF-8 %XX. */
export const whatsappUrl = (note: string) => `https://wa.me/?text=${encodeURIComponent(note)}`;
/** sms:?&body=... : the "?&" form is the one both iOS and Android's messaging apps read without a number. */
export const smsUrl = (note: string) => `sms:?&body=${encodeURIComponent(note)}`;
