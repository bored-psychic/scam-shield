import type { Level, Report } from "../types/report";

// "Get help" (shown on Suspicious and Likely scam only): the two official actions a user may need, nothing else. Pure functions and strings; the
// component (components/GetHelp.tsx) only shows them. Nothing here sends, stores or fetches anything.
// "Ask someone first" (a note to send on WhatsApp / SMS) was dropped by the user on 2026-10-23: do not re-add it.

export type HelpLevel = Extract<Level, "suspicious" | "likely_scam">;

/** Only a warning verdict gets Get help (Suspicious, Likely scam), not No warning signs, Promotional or Can't judge. */
export const canGetHelp = (level: Level): level is HelpLevel => level === "suspicious" || level === "likely_scam";

export const CALL_URL = "tel:1930";
export const CYBERCRIME_URL = "https://cybercrime.gov.in";
export const CHAKSHU_URL = "https://sancharsaathi.gov.in/sfc/";

/** The two rows, top to bottom: Likely scam leads with the helpline (money may already be gone), Suspicious with reporting. */
export const helpOrder = (level: HelpLevel): ("helpline" | "report")[] =>
  level === "likely_scam" ? ["helpline", "report"] : ["report", "helpline"];

/** The message as the Chakshu form should get it: PII-masked and defanged, all of it (a report wants the whole text). */
export const reportableMessage = (text: string, quotes: string[] = []): string => defang(maskPii(text.trim()), quotes);

/* PII masks for the copy of the message that goes to Chakshu. The Report does not carry a masked copy of the text (the result screen shows what was pasted), so
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

/** Make links in the copied message unclickable (https://x.com -> hxxps://x[.]com), so nobody can open a scam link by tapping it in a pasted
 *  report. The report's own link quotes are defanged too, which catches a bare "name.top" that an app would also turn
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

/** The link quotes of a Report, as written in the message (for defang). */
export const linkQuotes = (report: Report): string[] =>
  report.children.flatMap((c) => c.evidence.map((e) => e.quote).filter((q): q is string => q !== null));
