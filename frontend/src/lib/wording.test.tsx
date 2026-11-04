import { describe, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { InputKind, Level, Report } from "../types/report";
import Checking from "../components/Checking";
import ErrorPanel from "../components/ErrorPanel";
import Result from "../components/Result";
import { INPUT_SUMMARY, LEVEL_SUMMARY } from "./levels";
import { ROUTING_LINES, routingNotice } from "./routing";
import { nounOf, nounOfInput, NO_INPUTS, TABS, type TabKey } from "./tabs";
import raw from "./__fixtures__/reports.json";

// npm test. W2 per-input wording: Q1 the line under the verdict per input, Q2 the routing notice, Q3 the result page per input, Q4 the Checking steps, Q5 the way back.
vi.mock("../components/Tip", () => ({ default: () => null }));   // the tooltip portals into document.body, which a server render has not got
const FIXTURES = raw as unknown as { label: string; text: string; report: Report }[];
const textOf = (html: string) => html.replace(/<[^>]+>/g, "");
const LEVELS: Level[] = ["likely_scam", "suspicious", "no_warning_signs", "cant_judge", "promotional"];
const msg = FIXTURES.find((f) => f.report.input === "message" && f.report.children.length === 0)!;

describe("Q1 LEVEL_SUMMARY per input", () => {
  test("message is today's table; link and email are the same words with the noun (as before W2)", () => {
    expect(INPUT_SUMMARY.message).toEqual(LEVEL_SUMMARY);
    for (const noun of ["email", "link"] as const) for (const l of LEVELS) expect(INPUT_SUMMARY[noun][l], `${noun} ${l}`).toBe(LEVEL_SUMMARY[l].replace(/message/g, noun));
  });
  test("payment and app: the plan's sentences, word for word", () => {
    expect(INPUT_SUMMARY.payment).toMatchObject({
      likely_scam: "This payment has strong signs of a scam.",
      suspicious: "Something about this payment is risky. Check before you pay.",
      no_warning_signs: "Nothing in it looks wrong. Only your payment app can show who you would pay.",
      cant_judge: "Only your payment app can show who owns this ID.",
    });
    expect(INPUT_SUMMARY.app).toMatchObject({
      likely_scam: "This app has strong signs of a fraud app.",
      suspicious: "Parts of this app are risky. Do not install it yet.",
      no_warning_signs: "It carries the official app's signature. Install apps from the Play Store all the same.",
      cant_judge: "A file check cannot tell what this app does once installed.",
    });
  });
  test("the new copy is formal: no contractions", () => {
    for (const noun of ["payment", "app"] as const) for (const l of LEVELS) expect(INPUT_SUMMARY[noun][l], `${noun} ${l}`).not.toMatch(/n't|'re|'s (?!signature)|'ll/);
  });
  test("what was checked decides the noun: the Report's input, else the tab's", () => {
    const want: Record<InputKind, string> = { message: "message", email: "email", link: "link", upi_id: "payment", payment_request: "payment", qr: "payment", payment_proof: "payment", app: "app", apk: "app" };
    for (const [k, n] of Object.entries(want)) expect(nounOfInput(k as InputKind, "message")).toBe(n);
    expect(nounOfInput(null, "link")).toBe("link");
    expect(nounOfInput("message", "email")).toBe("email");   // an email whose subject is empty
    expect(nounOfInput("message", "link")).toBe("message");  // a message pasted in the Link tab
    expect(TABS.map((t) => nounOf(t, NO_INPUTS))).toEqual(["message", "link", "payment", "app"]);
  });
});

describe("Q2 the routing notice", () => {
  test("the four lines, exactly", () => {
    expect(ROUTING_LINES).toEqual({
      upi_id: "This looks like a UPI ID, so it was checked as a payment ID.",
      link: "This looks like a link, so it was checked as one.",
      message: "This looks like a message, so it was checked as one.",
      qr_link: "This QR code holds a link, so the link was checked.",
    });
  });
  test("shown only when the input differs from the tab", () => {
    expect(routingNotice("message", "link")).toBe(ROUTING_LINES.link);
    expect(routingNotice("message", "upi_id")).toBe(ROUTING_LINES.upi_id);
    expect(routingNotice("link", "message")).toBe(ROUTING_LINES.message);
    expect(routingNotice("payment", "link", true)).toBe(ROUTING_LINES.qr_link);
    expect(routingNotice("payment", "message")).toBe(ROUTING_LINES.message);
    for (const [tab, own] of [["message", ["message", "email"]], ["link", ["link"]], ["payment", ["upi_id", "payment_request", "qr", "payment_proof"]], ["app", ["app", "apk"]]] as [TabKey, InputKind[]][])
      for (const i of own) expect(routingNotice(tab, i), `${tab} ${i}`).toBeNull();
    expect(routingNotice("message", null)).toBeNull();
  });
});

describe("Q3 the result page per input", () => {
  const page = (r: Report, tab: TabKey, text: string) => renderToStaticMarkup(<Result report={r} text={text} onAgain={() => {}} tab={tab} noun={nounOf(tab, NO_INPUTS)} />);
  const as = (input: InputKind, level: Level): Report => ({ ...msg.report, input, level, module: input.startsWith("app") || input === "apk" ? "apps" : "transactions", children: [], evidence: [], reasons: [], risk_score: null, details: null, pending: [] });
  test("a message in the Message tab: no notice; the same message sent from the Link tab: the notice, in the message's words", () => {
    expect(page(msg.report, "message", msg.text)).not.toContain('class="routed"');
    const html = page(msg.report, "link", msg.text);
    expect(html).toContain('<p class="routed" role="status">This looks like a message, so it was checked as one.</p>');
    expect(textOf(html)).toContain("Your message");
  });
  test("a link Report from the SMS tab: the notice and the link wording; from the Link tab: no notice", () => {
    const link = FIXTURES.find((f) => f.report.input === "link")!;
    expect(page(link.report, "message", link.text)).toContain("This looks like a link, so it was checked as one.");
    expect(textOf(page(link.report, "message", link.text))).toContain("The link · not opened");
    expect(page(link.report, "link", link.text)).not.toContain('class="routed"');
  });
  test("a payment Report: its summary, 'this payment', no message panel when no text was sent", () => {
    for (const level of ["likely_scam", "suspicious", "no_warning_signs", "cant_judge"] as const) {
      const html = page(as("payment_proof", level), "payment", "");
      expect(textOf(html), level).toContain(INPUT_SUMMARY.payment[level].replace("&", "&amp;"));
      expect(html, level).not.toContain("g-msg");
    }
    expect(textOf(page(as("upi_id", "no_warning_signs"), "payment", "refund.desk@ybl"))).toContain("The payment");
    expect(textOf(page(as("upi_id", "no_warning_signs"), "payment", "x@ybl"))).toContain("No warning signs were found in this payment.");
  });
  test("an app Report: its summary, 'this app', no underline panel for a file", () => {
    const html = page(as("apk", "suspicious"), "app", "");
    expect(textOf(html)).toContain("Parts of this app are risky. Do not install it yet.");
    expect(html).not.toContain("g-msg");
    expect(textOf(page(as("app", "no_warning_signs"), "app", "SBI YONO"))).toContain("No warning signs were found in this app.");
  });
  test("the helpline row is on a Suspicious or Likely scam result of every input", () => {
    for (const input of ["upi_id", "payment_request", "qr", "payment_proof", "app", "apk"] as InputKind[])
      for (const level of ["suspicious", "likely_scam"] as const) {
        const html = page({ ...as(input, level), advice: ["If you paid or shared details, call 1930 now."] }, input.startsWith("a") ? "app" : "payment", "");
        expect(html, `${input} ${level}`).toContain("1930");
      }
  });
});

describe("Q4 the Checking steps per input", () => {
  const steps = (noun: "message" | "email" | "link" | "payment" | "app") => [...renderToStaticMarkup(<Checking outcome="pending" onFinished={() => {}} noun={noun} />).matchAll(/<\/i>([^<]+)<\/div>/g)].map((m) => m[1]);
  test("message, email and link keep the approved three lines; payment and app have their own", () => {
    for (const n of ["message", "email", "link"] as const) expect(steps(n)).toEqual([`Reading the ${n}`, "Checking links and payment IDs", "Looking for OTP requests and pressure tricks"]);
    expect(steps("payment")).toEqual(["Reading the payment details", "Checking the UPI ID and its name", "Looking for refund and prize tricks"]);
    expect(steps("app")).toEqual(["Reading the app details", "Checking the app name and package", "Looking for fake-app tricks"]);
  });
});

describe("Q5 the way back", () => {
  test("'Check something else' on the result; the error panel's way back names what was checked", () => {
    const html = renderToStaticMarkup(<Result report={msg.report} text={msg.text} onAgain={() => {}} />);
    expect(textOf(html)).toContain("← Check something else");
    expect(textOf(html)).toContain("Checked on this device · nothing was stored");
    const back = (noun: "payment" | "app") => textOf(renderToStaticMarkup(<ErrorPanel failure={{ kind: "unavailable", detail: "This check is not available yet." }} onRetry={() => {}} onBack={() => {}} noun={noun} />));
    expect(back("payment")).toContain("← Back to the payment");
    expect(back("app")).toContain("← Back to the app");
  });
});
