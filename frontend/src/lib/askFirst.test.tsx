import { describe, expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Report } from "../types/report";
import { buildNote, CALL_URL, canAskFirst, CHAKSHU_URL, CYBERCRIME_URL, defang, HELP, HELP_NEEDS_REVIEW, helpOrder, reportableMessage, linkQuotes, MAX_MESSAGE_CHARS, maskPii, NEEDS_REVIEW, shareableMessage, smsUrl, whatsappUrl } from "./askFirst";
import WhatToDo from "../components/WhatToDo";
import raw from "./__fixtures__/reports.json";

// npm test. "Get help" (2026-10-22).
//   H1 only Suspicious and Likely scam get the button         H2 the default note, in three languages, and the reason's full stop
//   H3 maskPii() agrees with src/pii.py mask_text()           H4 links in the shared message are made unclickable
//   H5 the message is appended only when asked, and capped    H6 WhatsApp / SMS links: every character survives a decode, no number in them
type Fixture = { label: string; text: string; report: Report };
const FIXTURES = raw as unknown as Fixture[];

describe("H1 who gets the button", () => {
  test("canAskFirst: suspicious and likely_scam only", () => {
    expect(["likely_scam", "suspicious", "no_warning_signs", "cant_judge", "promotional"].map((l) => canAskFirst(l as never)))
      .toEqual([true, true, false, false, false]);
  });
  test("WhatToDo renders the button only on a warning level and only when given the message", () => {
    const ask = { reason: "It asks for your OTP", message: "m", quotes: [] };
    for (const level of ["likely_scam", "suspicious"] as const)
      expect(renderToStaticMarkup(<WhatToDo advice={["a"]} level={level} tip={null} ask={ask} />)).toContain("Get help");
    for (const level of ["no_warning_signs", "cant_judge", "promotional"] as const)
      expect(renderToStaticMarkup(<WhatToDo advice={["a"]} level={level} tip={null} ask={ask} />)).not.toContain("Get help");
    expect(renderToStaticMarkup(<WhatToDo advice={["a"]} level="likely_scam" tip={null} />)).not.toContain("Get help");
  });
  test("the panel is closed until the button is pressed, and the button says so", () => {
    const html = renderToStaticMarkup(<WhatToDo advice={["a"]} level="suspicious" tip={null} ask={{ reason: null, message: "m", quotes: [] }} />);
    expect(html).toContain('aria-expanded="false"');
    expect(html).not.toContain("wa.me");
  });
});

describe("H2 the note", () => {
  test("English default: verdict, top reason, ask to call first", () => {
    expect(buildNote("likely_scam", "It asks you to share an OTP.", "en")).toBe(
      "Hi, I got a message that might be a scam. Scam Shield says: Likely scam – It asks you to share an OTP. Please call me before I pay or share anything.");
    expect(buildNote("suspicious", "The link is new", "en")).toContain("Scam Shield says: Suspicious – The link is new. Please call me");
  });
  test("no reason: the dash is left out", () => {
    expect(buildNote("suspicious", null, "en")).toContain("Scam Shield says: Suspicious. Please call me");
    expect(buildNote("suspicious", "  ", "en")).not.toContain("–");
  });
  test("Hindi and Kannada notes are in their script, name the verdict and are signed off (NEEDS_REVIEW false)", () => {
    for (const lang of ["hi", "kn"] as const) {
      const n = buildNote("likely_scam", "It asks for your OTP", lang);
      expect(n).toMatch(lang === "hi" ? /[ऀ-ॿ]/ : /[ಀ-೿]/);
      expect(n).toContain("Scam Shield");
      expect(n).toContain("It asks for your OTP");
      expect(NEEDS_REVIEW[lang]).toBe(false);
    }
    expect(NEEDS_REVIEW.en).toBe(false);
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
  test("every fixture's shareable message has no working link left", () => {
    for (const f of FIXTURES) {
      const out = shareableMessage(f.text, linkQuotes(f.report));
      expect(out, f.label).not.toMatch(/https?:\/\//i);
      for (const q of linkQuotes(f.report)) if (q.length > 3 && /\./.test(q)) expect(out, `${f.label}: ${q}`).not.toContain(q);
    }
  });
});

describe("H5 the message in the note", () => {
  test("appended only when given, after the note", () => {
    const n = buildNote("suspicious", "r", "en", "hello");
    expect(n.endsWith("\n\nThe message:\nhello")).toBe(true);
    expect(buildNote("suspicious", "r", "en")).not.toContain("hello");
  });
  test("masked in the note, phone and UPI id gone", () => {
    const out = shareableMessage("Send Rs 1 to ravi@ybl or call 9876543210");
    expect(out).toBe("Send Rs 1 to <UPI_ID> or call <PHONE>");
  });
  test("capped by characters, not UTF-16 units, with an ellipsis", () => {
    const long = "😀".repeat(MAX_MESSAGE_CHARS + 50);
    const out = shareableMessage(long);
    expect(Array.from(out).length).toBe(MAX_MESSAGE_CHARS + 1);
    expect(out.endsWith("…")).toBe(true);
    expect(shareableMessage("short")).toBe("short");
  });
});

describe("H6 WhatsApp and SMS links", () => {
  const notes = [
    buildNote("likely_scam", "It asks for your OTP & a PIN?", "en", "Pay ₹500 now! 100% sure=yes #1"),
    buildNote("likely_scam", "It asks for your OTP", "hi", "आपका खाता बंद हो जाएगा"),
    buildNote("suspicious", "It asks for your OTP", "kn", "ನಿಮ್ಮ ಖಾತೆ ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ"),
  ];
  test.each(notes.map((n, i) => [["en", "hi", "kn"][i], n]))("%s: the address is plain ASCII and decodes back to the note", (_, note) => {
    const wa = whatsappUrl(note), sms = smsUrl(note);
    expect(wa.startsWith("https://wa.me/?text=")).toBe(true);
    expect(sms.startsWith("sms:?&body=")).toBe(true);
    for (const u of [wa, sms]) expect(u).toMatch(/^[\x21-\x7e]+$/);      // no space, newline or non-ASCII character left
    expect(decodeURIComponent(wa.slice("https://wa.me/?text=".length))).toBe(note);
    expect(decodeURIComponent(sms.slice("sms:?&body=".length))).toBe(note);
    // the characters that would end or split the value are escaped, so the whole note is one text= / body= value
    for (const u of [wa.split("text=")[1], sms.split("body=")[1]]) expect(u).not.toMatch(/[&#?=+ \n]/);
  });
  test("a Hindi letter is its UTF-8 bytes (न = E0 A4 A8) and the newline is %0A", () => {
    expect(whatsappUrl("न\nx")).toBe("https://wa.me/?text=%E0%A4%A8%0Ax");
    expect(smsUrl("ನ")).toBe("sms:?&body=%E0%B2%A8");
  });
  test("no phone number is in either address", () => {
    expect(whatsappUrl("hi")).toBe("https://wa.me/?text=hi");
    expect(smsUrl("hi")).toBe("sms:?&body=hi");
  });
});

describe("H7 Get help panel", () => {
  test("section order: Likely scam lost -> report -> ask, Suspicious the reverse", () => {
    expect(helpOrder("likely_scam")).toEqual(["lost", "report", "ask"]);
    expect(helpOrder("suspicious")).toEqual(["ask", "report", "lost"]);
  });
  test("the three official links", () => {
    expect(CALL_URL).toBe("tel:1930");
    expect(CYBERCRIME_URL).toBe("https://cybercrime.gov.in");
    expect(CHAKSHU_URL).toBe("https://sancharsaathi.gov.in/sfc/");
  });
  test("every language has every string, three steps, and HI / KN are flagged for review", () => {
    for (const lang of ["en", "hi", "kn"] as const) {
      const w = HELP[lang];
      for (const v of [w.title, w.lostHead, w.call, w.portal, w.hour, w.reportHead, w.chakshu, w.reportNote, w.copied, w.copyFailed, w.askHead]) expect(v.length).toBeGreaterThan(3);
      expect(w.steps).toHaveLength(3);
      expect(w.call).toContain("1930");
    }
    expect(HELP.hi.call).toMatch(/[ऀ-ॿ]/);
    expect(HELP.kn.call).toMatch(/[ಀ-೿]/);
    expect(HELP_NEEDS_REVIEW).toEqual({ en: false, hi: true, kn: true });
  });
  test("the report message is masked and defanged, and not cut at the note's cap", () => {
    const long = "Call 9876543210 now https://evil.example/x " + "word ".repeat(300);
    const m = reportableMessage(long, ["https://evil.example/x"]);
    expect(m).toContain("<PHONE>");
    expect(m).toContain("hxxps://evil[.]example/x");
    expect(m).not.toContain("9876543210");
    expect(Array.from(m).length).toBeGreaterThan(MAX_MESSAGE_CHARS);
  });
});
