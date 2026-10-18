import type { Fact, Level, LinkInfo, Report } from "../types/report";

// How the "Website details" sheet (D23) writes a link's facts. Display only: every value, effect and reason comes from the API (Report.link),
// and nothing here judges a link or makes a request.

export const PENDING_TEXT = "Checking…";
export const OFFLINE_TEXT = "Couldn't verify (offline)";

/** The value column: "Checking…" while pending; a hidden short-link destination before the button is pressed says so. */
export function factText(f: Fact): string {
  if (f.status === "pending") return PENDING_TEXT;
  if (f.value === null) return f.key === "destination" ? "Hidden" : "Not checked";
  return f.value;
}

/** A fact's "why it matters" line is shown for red flags, reassurances and unknowns; neutral facts stay one line. */
export const showWhy = (f: Fact) => f.why !== null && f.effect !== "neutral";

/** The sheet starts open when a fact is a red flag (danger / caution), so the reason is on screen without a tap. */
export const openByDefault = (info: LinkInfo) => info.facts.some((f) => f.effect === "danger" || f.effect === "caution");

/** The live call failed (the API stopped answering): every pending row becomes "Couldn't verify (offline)", never "safe". A copy. */
export function markLiveFailed(report: Report): Report {
  return {
    ...report,
    pending: [],
    children: report.children.map((c) => ({
      ...c,
      pending: [],
      link: c.link && {
        ...c.link,
        facts: c.link.facts.map((f) => (f.status === "pending" ? { ...f, status: "failed" as const, value: OFFLINE_TEXT, effect: "unknown" as const } : f)),
      },
    })),
  };
}

const RANK: Partial<Record<Level, number>> = { no_warning_signs: 0, suspicious: 1, likely_scam: 2 };

/** Whether the live checks raised the verdict (they can only raise it: every positive check is offline). */
export function raisedByLive(before: Report, after: Report): boolean {
  const a = RANK[before.level], b = RANK[after.level];
  return b !== undefined && (a === undefined ? false : b > a);
}
