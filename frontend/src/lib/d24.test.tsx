import { describe, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Report } from "../types/report";
import { SENDER_TIP } from "./sender";
import { METER_NOTE } from "./risk";
import Result from "../components/Result";
import WhatToDo from "../components/WhatToDo";
import raw from "./__fixtures__/reports.json";

// npm test. D24 on the page: A the "Lowered from..." line, B the risk score meter, C What to do as a numbered list. (D, the fonts, is checked on the
// built site by e2e/fonts.mjs.) Components are rendered to HTML with react-dom/server; the Reports are real ones from frontend/scripts/dump_fixture.py,
// which now also holds the Jio promo with a mobile number / an OTP request and the 14 demo messages.
type Fixture = { label: string; text: string; report: Report };
const FIXTURES = raw as unknown as Fixture[];
const fx = (label: string) => {
  const f = FIXTURES.find((x) => x.label === label);
  if (!f) throw new Error(`fixture ${label} missing: rerun frontend/scripts/dump_fixture.py`);
  return f;
};
vi.mock("../components/Tip", () => ({ default: () => null }));   // the tooltip portals into document.body, which a server render has not got
const textOf = (html: string) => html.replace(/<[^>]+>/g, "");
const page = (f: Fixture) => renderToStaticMarkup(<Result report={f.report} text={f.text} onAgain={() => {}} />);
const DEMO = FIXTURES.filter((f) => f.label.startsWith("demo-"));
const JIO_NOTE = "Lowered from Likely scam: the link belongs to Jio (only Reliance can register .jio addresses).";
const BANDS = { no_warning_signs: [0, 29], promotional: [0, 29], suspicious: [30, 69], likely_scam: [70, 100] } as const;

test("the fixtures hold the 14 demo messages and the two Jio cases", () => {
  expect(DEMO).toHaveLength(14);
  fx("jio-mobile-number"); fx("jio-otp-request");
});

describe("A the 'Lowered from...' line", () => {
  test("shown for the Jio fixture, with the backend's sentence, calm (not the amber 'raised' style), directly under the verdict and above the meter", () => {
    const f = fx("jio-no-sender");
    expect(f.report.level).toBe("suspicious");
    expect(f.report.lowered).toEqual({ from_level: "likely_scam", text: JIO_NOTE });
    const html = page(f);
    expect(html).toContain('class="vlowered"');
    expect(textOf(html)).toContain(JIO_NOTE);
    expect(html).not.toContain("vraised");
    const at = (s: string) => html.indexOf(s);
    expect(at('class="vword"')).toBeGreaterThan(-1);
    expect(at('class="vword"')).toBeLessThan(at('class="vlowered"'));
    expect(at('class="vlowered"')).toBeLessThan(at('class="meter"'));
    expect(at('class="vlowered"')).toBeLessThan(at('class="radar'));
  });
  test("not shown for Jio + a mobile number (still Likely scam) or Jio + an OTP request (still Likely scam)", () => {
    for (const label of ["jio-mobile-number", "jio-otp-request"]) {
      const f = fx(label);
      expect(f.report.level, label).toBe("likely_scam");
      expect(f.report.lowered, label).toBeNull();
      expect(page(f), label).not.toContain("vlowered");
      expect(textOf(page(f)), label).not.toContain("Lowered from");
    }
  });
  test("not shown on any of the 14 demo messages", () => {
    for (const f of DEMO) {
      expect(f.report.lowered, f.label).toBeNull();
      expect(textOf(page(f)), f.label).not.toContain("Lowered from");
    }
  });
  test("shown exactly where the Report says so: it is the Jio fixture alone among the sender-free fixtures, and only on a Suspicious verdict", () => {
    const withNote = FIXTURES.filter((f) => f.report.lowered !== null);
    expect(withNote.map((f) => f.label).sort()).toEqual(["jio-bare", "jio-mobile", "jio-no-sender", "jio-other"].sort());   // the same text; the sender variants cannot change it
    for (const f of FIXTURES) {
      expect(page(f).includes('class="vlowered"'), f.label).toBe(f.report.lowered !== null);
      if (f.report.lowered) expect(f.report.level).toBe("suspicious");
    }
  });
});

describe("B the risk score", () => {
  test("every fixture: the score is inside its level's band; null for Can't judge and nothing else", () => {
    for (const f of FIXTURES) {
      const r = f.report;
      if (r.level === "cant_judge") expect(r.risk_score, f.label).toBeNull();
      else {
        const [lo, hi] = BANDS[r.level];
        expect(r.risk_score, f.label).not.toBeNull();
        expect(Number.isInteger(r.risk_score), f.label).toBe(true);
        expect(r.risk_score!, f.label).toBeGreaterThanOrEqual(lo);
        expect(r.risk_score!, f.label).toBeLessThanOrEqual(hi);
      }
      for (const c of r.children) expect(c.risk_score, f.label).toBeNull();
    }
  });
  test("within one level the score never decreases as the model's score increases", () => {
    for (const level of ["no_warning_signs", "suspicious", "likely_scam"] as const) {
      const rows = FIXTURES.filter((f) => f.report.level === level && f.report.meta.text_score !== null)
        .map((f) => [f.report.meta.text_score!, f.report.risk_score!, f.label] as const).sort((a, b) => a[0] - b[0]);
      expect(rows.length, level).toBeGreaterThan(3);
      rows.slice(1).forEach((r, i) => expect(r[1], `${level}: ${rows[i][2]} -> ${r[2]}`).toBeGreaterThanOrEqual(rows[i][1]));
    }
  });
  test("the meter: 'Risk score 82 / 100', role meter with the value, the note under it, band edges 30 and 70, and no meter for Can't judge", () => {
    for (const f of FIXTURES) {
      const html = page(f), text = textOf(html), s = f.report.risk_score;
      if (s === null) {
        expect(html, f.label).not.toContain('role="meter"');
        expect(text, f.label).not.toContain("Risk score");
        continue;
      }
      expect(html, f.label).toContain('role="meter"');
      expect(html, f.label).toContain(`aria-valuenow="${s}"`);
      expect(html, f.label).toContain('aria-valuemin="0"');
      expect(html, f.label).toContain('aria-valuemax="100"');
      expect(html, f.label).toMatch(/aria-valuetext="\d+ out of 100, in the [a-z ]+ range"/);
      expect(text, f.label).toContain(`Risk score${s} / 100`);
      expect(text, f.label).toContain(METER_NOTE);
      expect(html, f.label).toContain('class="tick" style="left:30%"');
      expect(html, f.label).toContain('class="tick" style="left:70%"');
    }
    expect(METER_NOTE).toBe("Higher = more warning signs. Not a percentage chance.");
  });
  test("it is never written as a percentage", () => {
    for (const f of FIXTURES) expect(textOf(page(f)), f.label).not.toMatch(/Risk score\s*\d+\s*%/);
  });
});

describe("C What to do now is a numbered list", () => {
  test("no checkbox or other input; a real ordered list; the steps are the Report's advice, in order, word for word", () => {
    for (const f of FIXTURES) {
      const html = renderToStaticMarkup(<WhatToDo advice={f.report.advice} level={f.report.level} tip={null} />);
      expect(html, f.label).not.toMatch(/<input|type="checkbox"|<label/);
      expect(html, f.label).toContain("<ol");
      const items = [...html.matchAll(/<li>(.*?)<\/li>/g)].map((m) => m[1].replace(/&#x27;/g, "'").replace(/&amp;/g, "&").replace(/&quot;/g, '"'));
      expect(items, f.label).toEqual(f.report.advice);
    }
  });
  test("the 'Check who sent it' tip behaves as before: printed only when given, sender IDs on one line, a note and not a step", () => {
    const r = fx("jio-no-sender").report;
    const html = renderToStaticMarkup(<WhatToDo advice={r.advice} level={r.level} tip={SENDER_TIP} />);
    expect(textOf(html)).toContain(SENDER_TIP);
    expect(html).toContain('<span class="nobr">JM-JIOCPN-P</span>');
    expect(html.match(/<li>/g)).toHaveLength(r.advice.length);
    expect(renderToStaticMarkup(<WhatToDo advice={r.advice} level={r.level} tip={null} />)).not.toContain("sendertip");
    expect(textOf(page(fx("jio-no-sender")))).toContain(SENDER_TIP);
  });
  test("What to do now has no helpline buttons: on a warning verdict they are in Get help, on a quiet one nothing is added", () => {
    const w = renderToStaticMarkup(<WhatToDo advice={["a"]} level="likely_scam" tip={null} />);
    expect(w).not.toContain("Copy helpline 1930");
    expect(w).not.toContain("cybercrime.gov.in");
    expect(w).not.toContain("helptext");
    expect(renderToStaticMarkup(<WhatToDo advice={["a"]} level="no_warning_signs" tip={null} />)).not.toContain("helpline");
  });
});
