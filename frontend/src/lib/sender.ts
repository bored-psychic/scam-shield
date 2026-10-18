import type { Report } from "../types/report";

// What is left of the sender on the page (decision D22). The sender input, its hint, the TRAI explainer and the sender chip were removed on
// 2026-10-18 (product decision: users won't type a sender). The API still takes an optional sender, kept dormant for reading it from a
// screenshot later; the page never sends one, so Report.sender is always null here. What stays is the "check who sent it" tip, for awareness.

// The one piece of "what to do" copy the frontend owns. It cannot live in Report.advice: with no sender the Report must be exactly what it was
// before D22, so the tip is shown here when the sender is missing (Report.sender null), the verdict is a warning and there is a link.
export const SENDER_TIP = "Check who sent it: real businesses send from IDs like JM-JIOCPN-P; scams usually come from ordinary phone numbers.";

export function showSenderTip(report: Report): boolean {
  return report.sender === null && (report.level === "suspicious" || report.level === "likely_scam") && report.children.length > 0;
}
