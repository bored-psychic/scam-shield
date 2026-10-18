import { LEVEL_VALUES, SCHEMA_VERSION, type Report } from "./types/report";
import { OCR_MESSAGES, validateImage } from "./lib/screenshot";

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

/** D23: live = also run the link background checks (the API sends only domain names to registries, DNS, certificate logs and, with a key,
 *  Safe Browsing); expand = short links of this text the user asked to reveal (the shortener is asked; the destination is never opened). */
export type LiveOptions = { live?: boolean; expand?: string[] };

/** The first call's body is only the text: the offline analysis, which makes no network call. The page then asks again with live: true. The
 *  API's optional sender field (D22) is dormant: the page has no sender input since 2026-10-18 and never sends one, so Report.sender is
 *  always null; the field stays for reading the sender from a screenshot later. */
export async function analyse(text: string, opts: LiveOptions = {}): Promise<Report> {
  const signal = AbortSignal.timeout(TIMEOUT_MS);
  const body = opts.live ? { text, live: true, ...(opts.expand?.length ? { expand: opts.expand } : {}) } : { text };
  let res: Response;
  try {
    res = await fetch("/api/analyse", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal,
    });
  } catch {
    throw new CheckError({ kind: "unreachable" });
  }
  const answer: unknown = await res.json().catch(() => undefined);
  if (signal.aborted) throw new CheckError({ kind: "unreachable" });

  if (!res.ok) {
    const detail = isObject(answer) && typeof answer.detail === "string" ? answer.detail : null;
    if (res.status === 422) throw new CheckError({ kind: "rejected", detail: detail ?? "The checker couldn't read this message." });
    // No JSON detail: not the API speaking (the Vite proxy answers 500 with an empty body when the API is down).
    throw new CheckError(detail !== null ? { kind: "failed", detail } : { kind: "unreachable" });
  }

  const version = isObject(answer) ? answer.schema_version : undefined;
  if (!isObject(answer) || version !== SCHEMA_VERSION || !LEVEL_VALUES.includes(answer.level as Report["level"])
      || !Array.isArray(answer.evidence) || !Array.isArray(answer.reasons) || !Array.isArray(answer.children)) {
    throw new CheckError({ kind: "schema", got: version === undefined ? "none" : String(version) });
  }
  return answer as unknown as Report;
}

// Screenshot input (D19). The image goes into the request body of POST /api/ocr (local Tesseract, in memory) and nowhere else; the
// answer is only the text, which the page puts in the box for the user to check before it is ever sent to /api/analyse.
export type OcrResult = { text: string; lines: string[]; dropped: number };

export class OcrError extends Error {   // .message is what the page shows, in plain words; never anything read from the image
  constructor(message: string) {
    super(message);
    this.name = "OcrError";
  }
}

const OCR_TIMEOUT_MS = 45_000;   // Tesseract takes about a second and the API stops it at 20 s; this only keeps the page from waiting forever

export async function ocr(image: Blob, signal?: AbortSignal): Promise<OcrResult> {
  const problem = validateImage(image);   // checked here too, so a file that is too big or the wrong type is never uploaded
  if (problem) throw new OcrError(problem);
  const timeout = AbortSignal.timeout(OCR_TIMEOUT_MS);
  const form = new FormData();
  form.append("image", image, "screenshot");   // a fixed part name: the file's own name is not sent
  let res: Response;
  try {
    res = await fetch("/api/ocr", { method: "POST", body: form, signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
  } catch (e) {
    if (signal?.aborted) throw e;   // the page cancelled it (screenshot removed or replaced): not a failure to show
    throw new OcrError(OCR_MESSAGES.unreachable);
  }
  const body: unknown = await res.json().catch(() => undefined);
  if (signal?.aborted) throw signal.reason;
  if (timeout.aborted) throw new OcrError(OCR_MESSAGES.unreachable);

  if (!res.ok) {
    const detail = isObject(body) && typeof body.detail === "string" ? body.detail : null;
    switch (res.status) {
      case 413: throw new OcrError(OCR_MESSAGES.size);
      case 415: throw new OcrError(OCR_MESSAGES.type);
      case 422: throw new OcrError(detail ?? OCR_MESSAGES.unreadable);
      case 503: throw new OcrError(OCR_MESSAGES.unavailable);
    }
    // No JSON detail: not the API speaking (the Vite proxy answers 500 with an empty body when the API is down), as in analyse().
    throw new OcrError(detail !== null ? OCR_MESSAGES.failed : OCR_MESSAGES.unreachable);
  }
  if (!isObject(body) || typeof body.text !== "string" || !Array.isArray(body.lines) || typeof body.dropped !== "number") {
    throw new OcrError(OCR_MESSAGES.failed);
  }
  return { text: body.text, lines: body.lines as string[], dropped: body.dropped };
}
