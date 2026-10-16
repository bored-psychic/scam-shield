import { LEVEL_VALUES, SCHEMA_VERSION, type Report } from "./types/report";

// Client for the local checker (src/shield/api/main.py). Relative path: in development Vite forwards /api to 127.0.0.1:8000.
// The pasted text goes into the request body and nowhere else: nothing here logs it.

export type Failure =
  | { kind: "unreachable" }                  // no answer from the API: network error, timeout, or the dev proxy's error page
  | { kind: "rejected"; detail: string }     // 422: the API refused the text and said why
  | { kind: "failed"; detail: string }       // the API answered with an error of its own (e.g. 500 "The analysis failed.")
  | { kind: "schema"; got: string };         // an answer this page cannot read (schema_version is not SCHEMA_VERSION)

export class CheckError extends Error {
  readonly failure: Failure;
  constructor(failure: Failure) {
    super(`check failed: ${failure.kind}`);   // never the text
    this.name = "CheckError";
    this.failure = failure;
  }
}

const TIMEOUT_MS = 30_000;   // an analysis takes milliseconds; this only keeps the checking screen from waiting forever

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;

export async function analyse(text: string): Promise<Report> {
  const signal = AbortSignal.timeout(TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch("/api/analyse", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      signal,
    });
  } catch {
    throw new CheckError({ kind: "unreachable" });
  }
  const body: unknown = await res.json().catch(() => undefined);
  if (signal.aborted) throw new CheckError({ kind: "unreachable" });

  if (!res.ok) {
    const detail = isObject(body) && typeof body.detail === "string" ? body.detail : null;
    if (res.status === 422) throw new CheckError({ kind: "rejected", detail: detail ?? "The checker couldn't read this message." });
    // No JSON detail: not the API speaking (the Vite proxy answers 500 with an empty body when the API is down).
    throw new CheckError(detail !== null ? { kind: "failed", detail } : { kind: "unreachable" });
  }

  const version = isObject(body) ? body.schema_version : undefined;
  if (!isObject(body) || version !== SCHEMA_VERSION || !LEVEL_VALUES.includes(body.level as Report["level"])
      || !Array.isArray(body.evidence) || !Array.isArray(body.reasons) || !Array.isArray(body.children)) {
    throw new CheckError({ kind: "schema", got: version === undefined ? "none" : String(version) });
  }
  return body as unknown as Report;
}
