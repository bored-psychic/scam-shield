import { afterEach, describe, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { analyse, check, CheckError, type LiveOptions } from "../api";
import ErrorPanel from "../components/ErrorPanel";
import { NO_INPUTS, requestOf, textToCheck, type Inputs } from "./tabs";
import { markLiveFailed, needsLive, OFFLINE_TEXT } from "./facts";
import type { Report } from "../types/report";
import raw from "./__fixtures__/reports.json";

// npm test. W2: every tab sends its input to POST /api/check (X1 the request each tab builds, X2 the payment and app requests, X3 the client's bodies and errors,
// X4 a 501 is said plainly, X5 the live re-check for any input with links). The wording and routing tests are in wording.test.tsx.
const FIXTURES = raw as unknown as { label: string; text: string; report: unknown }[];
const I = (set: Partial<Inputs>): Inputs => ({ ...NO_INPUTS, ...set });
afterEach(() => vi.unstubAllGlobals());

describe("X1 what the SMS / Email and Link tabs send", () => {
  test("SMS: kind message with the text as typed; nothing to send while empty", () => {
    expect(requestOf("message", I({ sms: " hello\nthere " }))).toEqual({ kind: "message", text: " hello\nthere " });
    expect(requestOf("message", I({ sms: "  \n " }))).toBeNull();
  });
  test("Email: kind email with the trimmed subject and the body; the API joins them exactly as the page's checked text does", () => {
    const i = I({ kind: "email", subject: "  Hi ", body: "Body text", from: "a@b.c", attachments: "x.apk", headers: "H: 1" });
    expect(requestOf("message", i)).toEqual({ kind: "email", subject: "Hi", body: "Body text" });   // the optional fields are not sent
    expect(requestOf("message", i)!.subject + "\n\n" + requestOf("message", i)!.body).toBe(textToCheck("message", i));
  });
  test("Email whose subject is empty (its text came from a screenshot) goes as a message, as before W2", () => {
    expect(requestOf("message", I({ kind: "email", subject: " ", body: "only body" }))).toEqual({ kind: "message", text: "only body" });
    expect(requestOf("message", I({ kind: "email", subject: "Hi", body: " " }))).toBeNull();
  });
  test("Link: kind auto with the trimmed line, so a pasted message is checked as one (and the page says so)", () => {
    expect(requestOf("link", I({ link: "  https://x.example/a  " }))).toEqual({ kind: "auto", text: "https://x.example/a" });
    expect(requestOf("link", I({ link: " " }))).toBeNull();
  });
});

describe("X2 what the Payment and App tabs send", () => {
  test("Payment: a single token is a UPI ID, other text a payment request; only kind and text", () => {
    expect(requestOf("payment", I({ upi: " refund.desk@ybl " }))).toEqual({ kind: "upi_id", text: "refund.desk@ybl" });
    expect(requestOf("payment", I({ upi: "upi://pay?pa=a@ybl&am=1" }))).toEqual({ kind: "upi_id", text: "upi://pay?pa=a@ybl&am=1" });
    expect(requestOf("payment", I({ upi: "Rahul is requesting Rs 5000", started: "no" }))).toEqual({ kind: "payment_request", text: "Rahul is requesting Rs 5000" });
    expect(requestOf("payment", I({ upi: "" }))).toBeNull();
  });
  test("Payment screenshot mode sends {kind: payment_proof} and nothing else, whatever is typed", () => {
    expect(requestOf("payment", I({ payMode: "shot", upi: "refund.desk@ybl" }))).toEqual({ kind: "payment_proof" });
  });
  test("App: a name as app; the file mode as apk with the file name only (never the file); nothing to send while empty", () => {
    expect(requestOf("app", I({ appName: " SBI YONO " }))).toEqual({ kind: "app", text: "SBI YONO" });
    expect(requestOf("app", I({ appMode: "file", fileName: "SBI KYC Update.apk", how: "kyc" }))).toEqual({ kind: "apk", text: "SBI KYC Update.apk" });
    expect(requestOf("app", I({ appMode: "file", how: "kyc" }))).toEqual({ kind: "apk" });
    expect(requestOf("app", I({ appMode: "file" }))).toBeNull();
    expect(requestOf("app", I({ appMode: "name", appName: "" }))).toBeNull();
  });
});

describe("X3 the check() client", () => {
  const ok = () => vi.fn(async () => new Response(JSON.stringify(FIXTURES[0].report), { status: 200, headers: { "Content-Type": "application/json" } }));
  const sent = (f: ReturnType<typeof ok>) => f.mock.calls[0] as unknown as [string, RequestInit];
  test("POSTs to /api/check: the request, then live, then expand only with live", async () => {
    const cases: [LiveOptions, object][] = [[{}, {}], [{ live: true }, { live: true }], [{ live: true, expand: ["https://bit.ly/x"] }, { live: true, expand: ["https://bit.ly/x"] }], [{ expand: ["https://bit.ly/x"] }, {}]];
    for (const [opts, extra] of cases) {
      const f = ok();
      vi.stubGlobal("fetch", f);
      await check({ kind: "message", text: "hi" }, opts);
      expect(sent(f)[0]).toBe("/api/check");
      expect(JSON.parse(sent(f)[1].body as string)).toEqual({ kind: "message", text: "hi", ...extra });
    }
  });
  test("analyse() still posts {text} to /api/analyse", async () => {
    const f = ok();
    vi.stubGlobal("fetch", f);
    await analyse("hi", { live: true });
    expect(sent(f)[0]).toBe("/api/analyse");
    expect(JSON.parse(sent(f)[1].body as string)).toEqual({ text: "hi", live: true });
  });
  const fails = (status: number, body: unknown) => vi.fn(async () => new Response(body === undefined ? "" : JSON.stringify(body), { status }));
  const failure = async (p: Promise<unknown>) => { try { await p; } catch (e) { return (e as CheckError).failure; } throw new Error("did not fail"); };
  test("the same errors as analyse(): 422 rejected, 500 with detail failed, no detail unreachable, a wrong schema", async () => {
    vi.stubGlobal("fetch", fails(422, { detail: "Paste a message to check." }));
    expect(await failure(check({ kind: "message", text: " " }))).toEqual({ kind: "rejected", detail: "Paste a message to check." });
    vi.stubGlobal("fetch", fails(500, { detail: "The analysis failed." }));
    expect(await failure(check({ kind: "message", text: "x" }))).toEqual({ kind: "failed", detail: "The analysis failed." });
    vi.stubGlobal("fetch", fails(500, undefined));
    expect(await failure(check({ kind: "message", text: "x" }))).toEqual({ kind: "unreachable" });
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network"); }));
    expect(await failure(check({ kind: "message", text: "x" }))).toEqual({ kind: "unreachable" });
    vi.stubGlobal("fetch", fails(200, { schema_version: "5", level: "suspicious", evidence: [], reasons: [], children: [] }));
    expect(await failure(check({ kind: "message", text: "x" }))).toEqual({ kind: "schema", got: "5" });
  });
});

describe("X4 'This check is not available yet.' is said plainly", () => {
  test("a 501 is its own failure, with the API's line", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: "This check is not available yet." }), { status: 501 })));
    const f = await check({ kind: "upi_id", text: "a@ybl" }).then(() => null, (e: CheckError) => e.failure);
    expect(f).toEqual({ kind: "unavailable", detail: "This check is not available yet." });
  });
  test("the error panel shows that line, no Retry (asking again changes nothing), a way back", () => {
    const html = renderToStaticMarkup(<ErrorPanel failure={{ kind: "unavailable", detail: "This check is not available yet." }} onRetry={() => {}} onBack={() => {}} noun={null} />);
    expect(html.replace(/<[^>]+>/g, "")).toContain("This check is not available yet.");
    expect(html).not.toContain("Retry");
    expect(html).toContain("← Back");
    expect(html).not.toMatch(/Likely scam|Suspicious|No warning signs|Can't judge/);   // never a verdict
  });
});

describe("X5 the live re-check is for any input that has links", () => {
  const reports = FIXTURES.map((f) => f.report as Report);
  test("on the 96 message / link Reports needsLive is exactly today's rule (pending is not empty), so their flow is unchanged", () => {
    expect(reports.filter(needsLive).length).toBe(reports.filter((r) => r.pending.length > 0).length);
    for (const r of reports) expect(needsLive(r)).toBe(r.pending.length > 0);
    expect(reports.filter(needsLive).length).toBeGreaterThan(0);
  });
  const withDetails = (r: Report, pending: string[]): Report => ({ ...r, input: "upi_id", module: "transactions", pending, children: r.children,
    details: { kind: "payment", title: "Payment details", note: null, facts: [{ key: "handle", label: "Bank handle", value: null, effect: "unknown", why: null, status: "pending", source: null, sent: null }] } });
  test("a payment-style Report with a pending link check asks again; a finished one does not", () => {
    const linked = reports.find((r) => r.children.some((c) => c.pending.length > 0))!;
    expect(needsLive(withDetails(linked, []))).toBe(true);   // only the child link is pending
    expect(needsLive(withDetails(reports.find((r) => r.children.length === 0)!, []))).toBe(false);
  });
  test("when the live call fails, pending rows of a fact sheet become 'Couldn't verify', never 'safe'", () => {
    const r = markLiveFailed(withDetails(reports.find((x) => x.children.length === 0)!, ["links"]));
    expect(r.pending).toEqual([]);
    expect(r.details!.facts[0]).toMatchObject({ status: "failed", value: OFFLINE_TEXT, effect: "unknown" });
  });
});
