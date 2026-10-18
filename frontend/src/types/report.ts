// The Report contract, schema v3: a mirror of src/shield/contracts.py, which is the source of truth. Field names and unions match it
// exactly; the API sends every field (pydantic model_dump), so none are optional here. Change both files together and bump the version.
// v3 (D22): Report.sender and the level "promotional".
export const SCHEMA_VERSION = "3";

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

export interface Report {
  schema_version: "3";
  module: Module;
  level: Level;
  score: number | null;    // never shown as a percentage (D4)
  category: string | null;
  sender: Sender | null;   // null: no sender was given (and always on a child Report)
  evidence: Evidence[];
  reasons: string[];       // at most 3
  advice: string[];
  children: Report[];
  pending: string[];       // ids of live checks still running
  meta: Meta;
}
