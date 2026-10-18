// The Report contract, schema v5: a mirror of src/shield/contracts.py, which is the source of truth. Field names and unions match it
// exactly; the API sends every field (pydantic model_dump), so none are optional here. Change both files together and bump the version.
// v3 (D22): Report.sender and the level "promotional". v4 (D23): Report.link, a link's "Website details" (LinkInfo + Fact rows).
// v5 (D24): Report.risk_score (the 0-100 warning-sign meter) and Report.lowered (a P1 link signal lowered the verdict).
export const SCHEMA_VERSION = "5";

export type Level = "likely_scam" | "suspicious" | "no_warning_signs" | "cant_judge" | "promotional";
export const LEVEL_VALUES: readonly Level[] = ["likely_scam", "suspicious", "no_warning_signs", "cant_judge", "promotional"];

export type Effect = "danger" | "caution" | "neutral" | "reassuring" | "unknown";

export type Module = "messages" | "links" | "transactions" | "apps";

export interface Evidence {
  id: string;              // dotted, e.g. "rule.otp_request"
  module: Module;
  effect: Effect;
  title: string;           // one plain sentence
  detail: string;
  quote: string | null;    // an exact piece of the user's input, if the evidence points at one
  /** Where the quote sits in the ORIGINAL input: [start, end) in Unicode code points (Python str indexing). JavaScript strings count
   *  UTF-16 units, so an emoji before the quote shifts every offset: index with Array.from(text), never text.slice(). */
  span: [number, number] | null;
  tag: string;             // short radar label, e.g. "OTP request"
  source: string | null;   // where a fact came from, e.g. "OpenPhish feed, 2026-10-09"
  sent: string | null;     // what a live check sent out; null = nothing left the machine
}

export interface Meta {
  text_score: number | null;
  text_thresholds: [number, number] | null;   // (Suspicious from, Likely scam from)
  escalated: boolean;      // raised to Suspicious by the OTP / PIN / CVV rule
  truncated: boolean;      // the text head read only the first MAX_CHARS characters
  lang: string | null;
  ms: number | null;
  models: Record<string, string>;
}

/** What the sender given to the API was classified as (D22). A mobile number is never echoed: only a business header is. The page has no sender
 *  input since 2026-10-18 and never sends one, so it always gets null; the block stays in the contract for screenshot sender extraction later. */
export interface Sender {
  kind: "dlt" | "dlt_bare" | "mobile" | "other";
  suffix: "P" | "S" | "T" | "G" | null;   // dlt only
  header: string | null;                  // dlt and dlt_bare only, e.g. "JIOCPN"
  label: string;                          // e.g. "Registered business · Promotional"
}

/** One row of a link's "Website details" (D23). value is null while pending, or for a short link's hidden destination. */
export interface Fact {
  key: string;             // e.g. "age", "server", "dest_age"
  label: string;           // e.g. "Registered"
  value: string | null;    // e.g. "3 days ago (15 Oct 2026)"; a failed check says "Couldn't verify (...)"
  effect: Effect;
  why: string | null;      // why it matters, one plain line (every red flag has one)
  status: "ok" | "pending" | "failed" | "skipped";
  source: string | null;   // e.g. "Tranco list updated 3 h ago", "Advisory provided by Google"
  sent: string | null;     // what this check sent off the machine
}

/** A link's background (D23), on its child Report. Nothing in it was fetched from the link itself. */
export interface LinkInfo {
  url: string;
  host: string;
  shown_host: string;      // xn-- labels decoded
  owner: string;           // the registered domain the checks looked up
  shortener: boolean;
  expandable: boolean;     // the "Where does this short link go?" button can be offered
  destination: string | null;
  facts: Fact[];
  sent: string[];          // every live call made for this link
}

/** D24: a P1 link signal (a verified .brand ending or a .bank.in address) lowered the verdict. `text` is the whole calm sentence, written by the backend:
 *  "Lowered from Likely scam: the link belongs to Jio (only Reliance can register .jio addresses)." Set only when the level really fell. */
export interface Lowered {
  from_level: "likely_scam";
  text: string;
}

export interface Report {
  schema_version: "5";
  module: Module;
  level: Level;
  score: number | null;    // never shown as a percentage (D4)
  category: string | null;
  sender: Sender | null;   // null: no sender was given (and always on a child Report)
  evidence: Evidence[];
  reasons: string[];       // at most 3
  advice: string[];
  children: Report[];
  pending: string[];       // ids of live checks still running (message: "links"; link: "registration", "dns", "sb")
  link: LinkInfo | null;   // D23: on a link's child Report; null on the message Report
  /** D24: 0-100 warning-sign meter, always inside the band of `level` (No warning signs / Promotional 0-29, Suspicious 30-69, Likely scam 70-100).
   *  null for Can't judge and on a child Report. A meter, NOT a probability: the model is not calibrated. */
  risk_score: number | null;
  lowered: Lowered | null;   // D24
  meta: Meta;
}
