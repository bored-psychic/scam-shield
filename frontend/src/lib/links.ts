import type { Effect, Report } from "../types/report";

// How the link panel writes a link: the host cut into its labels, with the part that names the site's owner (the registrable domain)
// set apart, so "sbi.example-kyc.top" reads as a site of example-kyc.top. Display only: the link's verdict comes from the API, and no
// list here is used to judge anything. The owner rule is a short approximation of the Public Suffix List: the last two labels, or the
// last three after these common two-level suffixes.
const TWO_LEVEL = new Set(["co.in", "org.in", "net.in", "gov.in", "ac.in", "edu.in", "nic.in", "res.in", "bank.in", "co.uk", "org.uk", "com.au"]);

export interface LinkParts {
  host: string;       // as the URL parser reads it: lower case, IDN in punycode, no userinfo or port
  sub: string[];      // labels before the owner part, e.g. ["www"]
  owner: string[];    // the owner part's labels, e.g. ["onlinesbi", "sbi"]
  rest: string;       // path, query and fragment ("" for a bare host)
}

/** The parts of a link as written in a message ("http://" is assumed when there is no scheme), or null if it doesn't parse as a URL. */
export function linkParts(url: string): LinkParts | null {
  const raw = url.trim();
  let u: URL;
  try {
    u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`);
  } catch {
    return null;
  }
  const host = u.hostname.replace(/\.$/, "");
  const labels = host.split(".");
  if (!host || labels.some((l) => !l)) return null;
  const ip = host.startsWith("[") || labels.every((l) => /^\d+$/.test(l));   // an IP address has no owner part: show it whole
  const n = ip ? labels.length : labels.length >= 3 && TWO_LEVEL.has(labels.slice(-2).join(".")) ? 3 : Math.min(2, labels.length);
  const rest = (u.pathname === "/" ? "" : u.pathname) + u.search + u.hash;
  return { host, sub: labels.slice(0, labels.length - n), owner: labels.slice(-n), rest };
}

/** The owner part as one string, e.g. "hdfc.bank.in". */
export const ownerOf = (p: LinkParts) => p.owner.join(".");

const SEVERITY: Record<Effect, number> = { danger: 4, caution: 3, unknown: 2, neutral: 1, reassuring: 0 };

/** One block of the link panel per child Report (a link in the message). */
export interface LinkBlock {
  quote: string | null;        // the link as written; null for a disguised (refanged) link, which is not in the text as such
  parts: LinkParts | null;     // null: disguised, or written in a way the URL parser rejects (then the quote is shown as is)
  effect: Effect;              // the most severe of its evidence: tints the owner part
  checks: { title: string; effect: Effect }[];   // every piece of the child's evidence, in its order
}

export function linkBlocks(report: Report): LinkBlock[] {
  return report.children.map((c) => {
    const quote = c.evidence.find((e) => e.quote !== null)?.quote ?? null;
    const effect = c.evidence.reduce<Effect>((m, e) => (SEVERITY[e.effect] > SEVERITY[m] ? e.effect : m), "reassuring");
    return { quote, parts: quote === null ? null : linkParts(quote), effect, checks: c.evidence.map((e) => ({ title: e.title, effect: e.effect })) };
  });
}
