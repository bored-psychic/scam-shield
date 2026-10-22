import { describe, expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Report } from "../types/report";
import { CALL_URL, canGetHelp, CHAKSHU_URL, CYBERCRIME_URL, defang, helpOrder, linkQuotes, maskPii, reportableMessage } from "./getHelp";
import GetHelp from "../components/GetHelp";
import WhatToDo from "../components/WhatToDo";
import * as lib from "./getHelp";
import raw from "./__fixtures__/reports.json";

// npm test. "Get help" (2026-10-22; cut down to two compact rows on 2026-10-23, "Ask someone first" dropped by the user).
//   H1 only Suspicious and Likely scam get the button         H3 maskPii() agrees with src/pii.py mask_text()
//   H4 links in the copied message are made unclickable       H7 the two rows, their order, links and wording; the "Ask someone" parts are gone
type Fixture = { label: string; text: string; report: Report };
const FIXTURES = raw as unknown as Fixture[];

describe("H1 who gets the button", () => {
  test("canGetHelp: suspicious and likely_scam only", () => {
    expect(["likely_scam", "suspicious", "no_warning_signs", "cant_judge", "promotional"].map((l) => canGetHelp(l as never)))
      .toEqual([true, true, false, false, false]);
  });
  test("WhatToDo renders the button only on a warning level and only when given the message", () => {
    const help = { message: "m", quotes: [] };
    for (const level of ["likely_scam", "suspicious"] as const)
      expect(renderToStaticMarkup(<WhatToDo advice={["a"]} level={level} tip={null} help={help} />)).toContain("Get help");
    for (const level of ["no_warning_signs", "cant_judge", "promotional"] as const)
      expect(renderToStaticMarkup(<WhatToDo advice={["a"]} level={level} tip={null} help={help} />)).not.toContain("Get help");
    expect(renderToStaticMarkup(<WhatToDo advice={["a"]} level="likely_scam" tip={null} />)).not.toContain("Get help");
  });
  test("the panel is closed until the button is pressed, and the button says so", () => {
    const html = renderToStaticMarkup(<GetHelp level="suspicious" message="m" quotes={[]} />);
    expect(html).toContain('aria-expanded="false"');
    expect(html).not.toContain("1930");
  });
});

describe("H3 PII masks (cases and expected values from src/pii.py mask_text)", () => {
  test.each([
    ["Call 9876543210 or +91 98765 43210 now", "Call <PHONE> or <PHONE> now"],
    ["Pay to ramesh.k@oksbi and mail a.b@gmail.com", "Pay to <UPI_ID> and mail <EMAIL>"],
    ["Acct 123456789012 and XX12345678901 blocked", "Acct <ACCOUNT> and <ACCOUNT> blocked"],
    ["send to OFFERS@VISHAL today", "send to <EMAIL> today"],
    ["UPI dunzo.payu@axisbank ok", "UPI <UPI_ID> ok"],
    ["Call 09876543210", "Call <ACCOUNT>"],
    ["फोन 9876543210 पर", "फोन <PHONE> पर"],
    ["hello <UPI> x", "hello <UPI_ID> x"],
    ["no pii here 12345", "no pii here 12345"],
  ])("%s", (input, want) => expect(maskPii(input)).toBe(want));
});

describe("H4 links are made unclickable", () => {
  test("scheme and www links", () => {
    expect(defang("Verify at https://sbi-kyc.example.top/login now")).toBe("Verify at hxxps://sbi-kyc[.]example[.]top/login now");
    expect(defang("see www.bad.com/x, ok")).toBe("see www[.]bad[.]com/x, ok");
  });
  test("a bare domain is caught through the report's own link quotes", () => {
    expect(defang("Update at sbi-kyc.top today", ["sbi-kyc.top"])).toBe("Update at sbi-kyc[.]top today");
  });
  test("every fixture's reportable message has no working link left", () => {
    for (const f of FIXTURES) {
      const out = reportableMessage(f.text, linkQuotes(f.report));
      expect(out, f.label).not.toMatch(/https?:\/\//i);
      for (const q of linkQuotes(f.report)) if (q.length > 3 && /\./.test(q)) expect(out, `${f.label}: ${q}`).not.toContain(q);
    }
  });
});

describe("H7 Get help rows", () => {
  test("order: Likely scam Helpline then Report scam, Suspicious the reverse", () => {
    expect(helpOrder("likely_scam")).toEqual(["helpline", "report"]);
    expect(helpOrder("suspicious")).toEqual(["report", "helpline"]);
  });
  test("the three official links", () => {
    expect(CALL_URL).toBe("tel:1930");
    expect(CYBERCRIME_URL).toBe("https://cybercrime.gov.in");
    expect(CHAKSHU_URL).toBe("https://sancharsaathi.gov.in/sfc/");
  });
  test("the report message is masked, defanged and not cut", () => {
    const long = "Call 9876543210 now https://evil.example/x " + "word ".repeat(300);
    const m = reportableMessage(long, ["https://evil.example/x"]);
    expect(m).toContain("<PHONE>");
    expect(m).toContain("hxxps://evil[.]example/x");
    expect(m).not.toContain("9876543210");
    expect(Array.from(m).length).toBeGreaterThan(500);
  });
  test("the note feature is gone from the module (dropped by the user, do not re-add)", () => {
    for (const gone of ["buildNote", "whatsappUrl", "smsUrl", "shareableMessage", "NOTE_LANGS", "HELP", "NEEDS_REVIEW"]) expect(gone in lib, gone).toBe(false);
  });
});
