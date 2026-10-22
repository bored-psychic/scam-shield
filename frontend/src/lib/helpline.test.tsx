import { describe, expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { CALL_URL, canGetHelp, CYBERCRIME_URL, HELP_LANGS, HELP_NEEDS_REVIEW, HELP_STRINGS } from "./helpline";
import Helpline from "../components/Helpline";
import WhatToDo from "../components/WhatToDo";
import * as lib from "./helpline";

// npm test. The helpline row (2026-10-23): always visible inside What to do now on Suspicious and Likely scam, EN / हिंदी / ಕನ್ನಡ switch.
//   H1 only Suspicious and Likely scam get the row   H7 the row, its links, wording and switch; the dropped features are gone from the module

describe("H1 who gets the row", () => {
  test("canGetHelp: suspicious and likely_scam only", () => {
    expect(["likely_scam", "suspicious", "no_warning_signs", "cant_judge", "promotional"].map((l) => canGetHelp(l as never)))
      .toEqual([true, true, false, false, false]);
  });
  test("WhatToDo shows the row, with no toggle, on a warning level only, under the steps", () => {
    for (const level of ["likely_scam", "suspicious"] as const) {
      const html = renderToStaticMarkup(<WhatToDo advice={["a"]} level={level} tip={null} />);
      expect(html).toContain("Cyber crime helpline");
      expect(html).toContain('href="tel:1930"');
      expect(html).toContain('href="https://cybercrime.gov.in"');
      expect(html).not.toContain("Get help");
      expect(html).not.toContain("aria-expanded");
      expect(html.indexOf("steplist")).toBeLessThan(html.indexOf("helprow"));
    }
    for (const level of ["no_warning_signs", "cant_judge", "promotional"] as const) {
      const html = renderToStaticMarkup(<WhatToDo advice={["a"]} level={level} tip={null} />);
      expect(html).not.toContain("1930");
      expect(html).not.toContain("helprow");
    }
  });
});

describe("H7 the helpline row", () => {
  test("the two official links", () => {
    expect(CALL_URL).toBe("tel:1930");
    expect(CYBERCRIME_URL).toBe("https://cybercrime.gov.in");
  });
  test("English wording, the first-hour hint only as aria-label and title of the Call button", () => {
    const html = renderToStaticMarkup(<Helpline />);
    expect(html).toContain("Cyber crime helpline");
    expect(html).toContain(">Call 1930<");
    expect(html).toContain("File a complaint on cybercrime.gov.in<span class=\"arrow\"");
    expect(html).toContain('aria-label="Call 1930. If money was lost, call within one hour so the bank can hold the funds."');
    expect(html).toContain('title="If money was lost, call within one hour so the bank can hold the funds."');
    expect(html).not.toContain("Chakshu");
  });
  test("the switch: EN pressed first, three buttons in the user's order, each tagged with its language", () => {
    const html = renderToStaticMarkup(<Helpline />);
    expect(HELP_LANGS.map((l) => l.name)).toEqual(["EN", "हिंदी", "ಕನ್ನಡ"]);
    expect(html.match(/aria-pressed="true"/g)).toHaveLength(1);
    expect(html).toMatch(/lang="hi"[^>]*aria-pressed="false"[^>]*>हिंदी/);
    expect(html).toMatch(/lang="kn"[^>]*aria-pressed="false"[^>]*>ಕನ್ನಡ/);
  });
  test("Hindi and Kannada strings are exactly the supplied ones", () => {
    expect(HELP_STRINGS.hi).toEqual({
      label: "साइबर क्राइम हेल्पलाइन", call: "1930 पर कॉल करें", portal: "cybercrime.gov.in पर शिकायत दर्ज करें",
      hint: "यदि पैसे गए हैं, तो एक घंटे के भीतर कॉल करें, ताकि बैंक पैसे रोक सके।" });
    expect(HELP_STRINGS.kn).toEqual({
      label: "ಸೈಬರ್ ಕ್ರೈಂ ಹೆಲ್ಪ್‌ಲೈನ್", call: "1930ಕ್ಕೆ ಕರೆ ಮಾಡಿ", portal: "cybercrime.gov.in ನಲ್ಲಿ ದೂರು ದಾಖಲಿಸಿ",
      hint: "ಹಣ ಕಳೆದುಕೊಂಡಿದ್ದರೆ ಒಂದು ಗಂಟೆಯೊಳಗೆ ಕರೆ ಮಾಡಿ, ಬ್ಯಾಂಕ್ ಹಣವನ್ನು ತಡೆಹಿಡಿಯಬಹುದು." });
  });
  test("HELP_NEEDS_REVIEW: Hindi true, Kannada false", () => {
    expect(HELP_NEEDS_REVIEW).toEqual({ en: false, hi: true, kn: false });
  });
  test("dropped features are gone from the module (the user's decision, do not re-add)", () => {
    for (const gone of ["maskPii", "defang", "reportableMessage", "linkQuotes", "CHAKSHU_URL", "helpOrder", "buildNote", "whatsappUrl", "smsUrl", "shareableMessage"])
      expect(gone in lib, gone).toBe(false);
  });
});
