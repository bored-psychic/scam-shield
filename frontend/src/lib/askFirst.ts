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

/* NEEDS REVIEW BY A NATIVE SPEAKER (Hindi and Kannada): written by the model, not yet checked. The panel says so next to the picker; remove
   that line only after the wording is signed off. The reason is the backend's English sentence in every language (the Report has no
   translations), so a Hindi or Kannada note carries one English clause. */
export const NEEDS_REVIEW: Record<NoteLang, boolean> = { en: false, hi: true, kn: true };

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
    tail: "पैसे भेजने या कुछ भी साझा करने से पहले कृपया मुझे फ़ोन करें।",
    message: "मैसेज:",
  },
  kn: {
    verdict: { suspicious: "ಸಂಶಯಾಸ್ಪದ", likely_scam: "ಸ್ಕ್ಯಾಮ್ ಆಗಿರುವ ಸಾಧ್ಯತೆ ಹೆಚ್ಚು" },
    head: "ನಮಸ್ಕಾರ, ನನಗೆ ಒಂದು ಸಂದೇಶ ಬಂದಿದೆ, ಅದು ಸ್ಕ್ಯಾಮ್ ಆಗಿರಬಹುದು.",
    says: "Scam Shield ಹೇಳುವುದು:",
    tail: "ನಾನು ಹಣ ಕಳುಹಿಸುವ ಅಥವಾ ಏನನ್ನಾದರೂ ಹಂಚಿಕೊಳ್ಳುವ ಮೊದಲು ದಯವಿಟ್ಟು ನನಗೆ ಕರೆ ಮಾಡಿ.",
    message: "ಸಂದೇಶ:",
  },
};

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
