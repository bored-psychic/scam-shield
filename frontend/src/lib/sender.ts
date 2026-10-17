import type { Evidence, Report } from "../types/report";

// The optional sender input (decision D22). What the field says, the short TRAI explainer behind its info button, and when the result screen
// suggests checking the sender. The verdict itself comes from the API; nothing here judges a sender (the API classifies it and labels it).

export const SENDER_MAX = 40;   // MAX_LEN in src/shield/messages/sender.py: anything longer is "Not recognised" anyway
export const SENDER_PLACEHOLDER = "e.g. JM-JIOCPN-P or +91 98…";
export const SENDER_HINT = "If your phone shows the full sender ID (like JM-JIOCPN-P), enter that: the last letter tells us the message type.";

// The awareness part: TRAI's type letters in plain words (TCCCPR 2025 amendment, on phones since May 2025).
export const SUFFIX_HELP: readonly [letter: "P" | "S" | "T" | "G", meaning: string][] = [
  ["P", "Promotional: offers and ads"],
  ["S", "Service: updates from a company you use"],
  ["T", "Transactional: OTPs and bank alerts"],
  ["G", "Government"],
];
export const SENDER_HELP_INTRO = "In India, businesses must send SMS from a registered sender ID, like JM-JIOCPN-P. The last letter is the message type:";
export const SENDER_HELP_OUTRO = "Scam SMS usually come from ordinary 10-digit mobile numbers. A registered ID is a strong hint, not proof: it can be misused, so never share an OTP or PIN.";

// The one piece of "what to do" copy the frontend owns. It cannot live in Report.advice: with the sender left blank the Report must be exactly
// what it was before D22, so the tip is shown here when the sender is missing (Report.sender null), the verdict is a warning and there is a link.
export const SENDER_TIP = "Check who sent it: registered businesses use IDs like JM-JIOCPN-P; scams usually come from ordinary numbers.";

/** The sender evidence (id sender.*) when it is NOT one of the reasons. The backend gives the sender reason a place among the three only when one is
 *  free (or first, on Promotional), so it never pushes a warning out; the page then shows it under the sender chip instead, right below the verdict. */
export function senderNote(report: Report): Evidence | null {
  const e = report.evidence.find((x) => x.id.startsWith("sender."));
  return e && !report.reasons.includes(e.title) ? e : null;
}

export function showSenderTip(report: Report): boolean {
  return report.sender === null && (report.level === "suspicious" || report.level === "likely_scam") && report.children.length > 0;
}
