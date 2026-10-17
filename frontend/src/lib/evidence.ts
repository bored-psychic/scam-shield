import type { Effect, Evidence, Level, Report } from "../types/report";

// What the result screen draws from a Report: which phrases to underline, which blips the radar shows, where a reason points. Display only:
// every verdict, effect and title comes from the API, and nothing here judges a message.

const ORDER = (e: Evidence) => (e.id.startsWith("rule.") ? 0 : e.id.startsWith("tactic.") ? 2 : e.id.startsWith("model.") ? 3 : 4);

/** The Report's evidence and every child's (link) evidence, in the order to_report() picks reasons: rule.* -> links -> tactic.* -> model.*
 *  (anything else last). The objects are the Report's own, so they can be compared by identity. */
export function allEvidence(report: Report): Evidence[] {
  const top = (g: number) => report.evidence.filter((e) => ORDER(e) === g);
  return [...top(0), ...report.children.flatMap((c) => c.evidence), ...top(2), ...top(3), ...top(4)];
}

export type MarkEffect = Extract<Effect, "danger" | "caution" | "unknown" | "neutral">;
const RANK: Record<MarkEffect, number> = { danger: 3, caution: 2, unknown: 1, neutral: 0 };

/** One underlined stretch of the message: the union of evidence spans that overlap, directly or through each other. */
export interface Cluster {
  id: string;            // "c<start>-<end>": stable for the same Report, used to pulse it
  start: number;         // [start, end) in code points
  end: number;
  effect: MarkEffect;    // the most severe member: danger > caution > unknown > neutral
  members: Evidence[];   // every evidence in it, in allEvidence order (the tooltip lists their titles)
}
export interface Segment { text: string; cluster: Cluster | null }

/** Whether an evidence is underlined at all: it needs a span; reassuring evidence never is; neutral evidence only on a verdict without a
 *  warning, no-warning or promotional (there it shows what was read and found normal; on a flagged verdict it would sit beside the warnings as noise). */
export function isDrawn(e: Evidence, level: Level): boolean {
  return e.span !== null && e.effect !== "reassuring" && (e.effect !== "neutral" || level === "no_warning_signs" || level === "promotional");
}

/** The clusters over a text of `length` code points. A span outside the text is skipped, never drawn half. */
export function clusters(length: number, evidence: Evidence[], level: Level): Cluster[] {
  const order = new Map(evidence.map((e, i) => [e, i]));
  const ev = evidence
    .filter((e) => isDrawn(e, level) && e.span![0] >= 0 && e.span![0] < e.span![1] && e.span![1] <= length)
    .sort((a, b) => a.span![0] - b.span![0] || b.span![1] - a.span![1]);
  const out: Omit<Cluster, "id">[] = [];
  for (const e of ev) {
    const [s, t] = e.span!, last = out[out.length - 1], effect = e.effect as MarkEffect;
    if (last && s < last.end) {   // overlaps the cluster so far (spans that only touch stay apart)
      last.end = Math.max(last.end, t);
      last.members.push(e);
      if (RANK[effect] > RANK[last.effect]) last.effect = effect;
    } else {
      out.push({ start: s, end: t, effect, members: [e] });
    }
  }
  return out.map((c) => ({ ...c, id: `c${c.start}-${c.end}`, members: c.members.sort((a, b) => order.get(a)! - order.get(b)!) }));
}

/** The message cut into plain and underlined segments. Offsets are code points (Array.from), as the contract's spans are; joining the
 *  segments' texts gives back `text` exactly. */
export function segments(text: string, evidence: Evidence[], level: Level): Segment[] {
  const chars = Array.from(text);
  const out: Segment[] = [];
  let at = 0;
  for (const c of clusters(chars.length, evidence, level)) {
    if (c.start > at) out.push({ text: chars.slice(at, c.start).join(""), cluster: null });
    out.push({ text: chars.slice(c.start, c.end).join(""), cluster: c });
    at = c.end;
  }
  if (at < chars.length) out.push({ text: chars.slice(at).join(""), cluster: null });
  return out;
}

export const MAX_BLIPS = 4;

/** The radar's blips: warning evidence (danger or caution), one per tag, at most 4, in allEvidence order. None on a no-warning verdict,
 *  so the meter can never contradict the verdict word (D4). */
export function blips(report: Report): Evidence[] {
  if (report.level === "no_warning_signs") return [];
  const seen = new Set<string>(), out: Evidence[] = [];
  for (const e of allEvidence(report)) {
    if ((e.effect === "danger" || e.effect === "caution") && !seen.has(e.tag)) {
      seen.add(e.tag);
      out.push(e);
      if (out.length === MAX_BLIPS) break;
    }
  }
  return out;
}

/** For each reason, the first evidence whose title is that reason (to_report() copies reasons from titles), or null (e.g. "Too little
 *  text to judge", which no evidence carries). */
export function reasonTargets(report: Report): (Evidence | null)[] {
  const ev = allEvidence(report);
  return report.reasons.map((r) => ev.find((e) => e.title === r) ?? null);
}

/** What the tooltip and the mark's description list for a cluster: each member's title once, with its effect, in member order. */
export function tipLines(c: Cluster): { title: string; effect: Effect }[] {
  const seen = new Set<string>();
  return c.members.filter((e) => !seen.has(e.title) && !!seen.add(e.title)).map((e) => ({ title: e.title, effect: e.effect }));
}

/** The cluster an evidence was drawn in, or null (no span, or not drawn). */
export function clusterOf(segs: Segment[], e: Evidence | null): Cluster | null {
  if (!e) return null;
  return segs.find((s) => s.cluster?.members.includes(e))?.cluster ?? null;
}
