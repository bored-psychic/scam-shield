import { describe, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Fact, Report } from "../types/report";
import DetailsPanel from "../components/DetailsPanel";
import Result from "../components/Result";
import WebsiteDetails from "../components/WebsiteDetails";
import raw from "./__fixtures__/reports.json";

// npm test. D1-D4: Report.details (v6) in DetailsPanel, the generalised WebsiteDetails: the same rows, icons, "why" lines and "sent off this device" note.
vi.mock("../components/Tip", () => ({ default: () => null }));   // the tooltip portals into document.body, which a server render has not got
const FIXTURES = raw as unknown as { label: string; text: string; report: Report }[];
const fact = (o: Partial<Fact> & Pick<Fact, "key" | "label">): Fact => ({ value: null, effect: "neutral", why: null, status: "ok", source: null, sent: null, ...o });
const FACTS: Fact[] = [
  fact({ key: "handle", label: "Bank handle", value: "ybl (PhonePe)", effect: "neutral", source: "NPCI handle list, 2026-10-30" }),
  fact({ key: "name", label: "Name on the ID", value: "refund.desk", effect: "caution", why: "A refund desk is a name scammers pick; the registered name only shows in your payment app." }),
  fact({ key: "age", label: "Registered", value: "3 days ago", effect: "danger", why: "New names are often scams.", sent: "the registered domain example.top to the .top registry" }),
  fact({ key: "dns", label: "DNS", value: null, status: "pending" }),
];
const DETAILS = { kind: "payment" as const, title: "Payment details", facts: FACTS, note: "Only your payment app can show who owns this ID." };
const base = FIXTURES.find((f) => f.report.children.length === 0 && f.report.input === "message")!;
const asPayment = { ...base.report, input: "upi_id" as const, module: "transactions" as const, details: DETAILS };
const textOf = (html: string) => html.replace(/<[^>]+>/g, "");

describe("D1 the fact sheet", () => {
  const html = renderToStaticMarkup(<DetailsPanel details={DETAILS} />);
  test("title, every row's label and value, the 'why' line for flags and unknowns, the source for an ok row", () => {
    const t = textOf(html);
    expect(t).toContain("Payment details");
    for (const f of FACTS) expect(t).toContain(f.label);
    expect(t).toContain("ybl (PhonePe)");
    expect(t).toContain("A refund desk is a name scammers pick");
    expect(t).toContain("New names are often scams.");
    expect(t).toContain("NPCI handle list, 2026-10-30");
    expect(t).toContain("Checking…");           // the pending row
    expect(t).toContain("Only your payment app can show who owns this ID.");   // details.note
  });
  test("a shape and a colour per effect (never colour alone), the pending row has none", () => {
    expect(html).toContain("✕");   // danger
    expect(html).toContain("!");   // caution
    expect(html).toContain("○");   // neutral
    expect(html).toMatch(/class="frow pending"/);
  });
  test("what a live check sent is listed once, as for a link", () => {
    expect(textOf(html)).toContain("Sent off this device: the registered domain example.top to the .top registry");
    const none = renderToStaticMarkup(<DetailsPanel details={{ ...DETAILS, facts: FACTS.map((f) => ({ ...f, sent: null })) }} />);
    expect(none).not.toContain("Sent off this device");
  });
  test("a labelled group in the panel's grid slot (the same box as the link panel, so the approved minimum height applies)", () => {
    expect(html).toMatch(/^<div class="box link g-link g-details" role="group" aria-label="Payment details">/);
  });
  test("no note, no empty note line", () => {
    expect(renderToStaticMarkup(<DetailsPanel details={{ ...DETAILS, note: null }} />)).not.toContain("payment app can show");
  });
});

describe("D2 the link sheet reads the same rows", () => {
  test("WebsiteDetails and DetailsPanel render a fact row with identical markup", () => {
    const info = FIXTURES.find((f) => f.report.children.some((c) => c.link))!.report.children.find((c) => c.link)!.link!;
    const row = (html: string, key: string) => html.match(new RegExp(`<div class="frow [^"]*"><dt>${key}</dt>.*?</dd></div>`))?.[0];
    const facts = info.facts.filter((f) => f.status === "ok").slice(0, 3);
    const link = renderToStaticMarkup(<WebsiteDetails info={{ ...info, facts }} expanding={false} expandFailed={false} />);
    const panel = renderToStaticMarkup(<DetailsPanel details={{ kind: "app", title: "App details", facts, note: null }} />);
    expect(facts.length).toBeGreaterThan(0);
    for (const f of facts) expect(row(panel, f.label), f.key).toBe(row(link, f.label));
  });
});

describe("D3 the result page shows Report.details", () => {
  test("a payment-style Report gets the panel; a message or link Report never does", () => {
    const page = (r: Report) => renderToStaticMarkup(<Result report={r} text="" onAgain={() => {}} />);
    expect(page(asPayment)).toContain("Payment details");
    for (const f of FIXTURES) expect(page(f.report), f.label).not.toContain("g-details");
  });
});
