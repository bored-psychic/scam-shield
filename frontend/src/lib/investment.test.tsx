import { describe, expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Report } from "../types/report";
import { INVEST_ADVICE, INVEST_HEADING, INVEST_NEEDS_REVIEW, INVEST_PREFIX, INVEST_REASONS, INVEST_TAGS, isInvestAdvice, reasonText } from "./investment";
import { reasonTargets } from "./evidence";
import WhatToDo from "../components/WhatToDo";
import WhyPanel from "../components/WhyPanel";
import Helpline from "../components/Helpline";
import raw from "./__fixtures__/reports.json";

// npm test. The investment-scam rules A1-A12 in the UI (2026-10-25, docs/plans/investment_scams.md Phase A), on real Reports from the Python checker
// (frontend/scripts/dump_fixture.py: the "invest-*" and "demo-d04" / "demo-d07" entries).
//   N1 every rule has a reason in English, Hindi and Kannada; the English is what the API sends; Hindi / Kannada are marked needs-review
//   N2 the investment card: shown above the steps iff the API added the SEBI line, never as a numbered step, in the language of the switch
//   N3 the Why reasons: an investment rule's reason follows the language, every other reason stays as sent
//   N4 the helpline switch can be driven by the result screen (props) and still works alone
type Fixture = { label: string; text: string; report: Report };
const FIXTURES = raw as unknown as Fixture[];
const fx = (label: string) => {
  const f = FIXTURES.find((x) => x.label === label);
  if (!f) throw new Error(`fixture ${label} missing: rerun frontend/scripts/dump_fixture.py`);
  return f.report;
};
const DEVANAGARI = /[ऀ-ॿ]/, KANNADA = /[ಀ-೿]/;
const SEBI_LINE = "SEBI-registered brokers and advisers collect UPI payments only through IDs with the @valid handle (for example name.brk@validhdfc), and never promise guaranteed returns. Check any adviser at sebi.gov.in before paying.";

describe("N1 reasons in three languages", () => {
  const ids = Object.keys(INVEST_REASONS);
  test("twelve rules, each with an English, Hindi and Kannada reason in its own script", () => {
    expect(ids).toHaveLength(12);
    expect(Object.keys(INVEST_TAGS).sort()).toEqual([...ids].sort());
    for (const id of ids) {
      const r = INVEST_REASONS[id];
      expect(id.startsWith(INVEST_PREFIX)).toBe(true);
      expect(r.en.length).toBeGreaterThan(10);
      expect(r.en.length).toBeLessThanOrEqual(120);   // the contract's title limit
      expect(DEVANAGARI.test(r.hi)).toBe(true);
      expect(KANNADA.test(r.kn)).toBe(true);
      expect(KANNADA.test(r.hi) || DEVANAGARI.test(r.kn)).toBe(false);
    }
  });
  test("the English reasons and tags are the ones the API sends (real Reports)", () => {
    const seen = new Set<string>();
    for (const f of FIXTURES) {
      for (const e of f.report.evidence.filter((e) => e.id.startsWith(INVEST_PREFIX))) {
        seen.add(e.id);
        expect(INVEST_REASONS[e.id], e.id).toBeDefined();
        expect(e.title).toBe(INVEST_REASONS[e.id].en);
        expect(e.tag).toBe(INVEST_TAGS[e.id]);
        expect(e.quote).not.toBeNull();
      }
    }
    expect(seen.size).toBeGreaterThanOrEqual(5);   // the fixtures exercise several rules
  });
  test("the three examples the user named read as asked", () => {
    expect(INVEST_REASONS["rule.invest_guaranteed"].en).toBe("Promises guaranteed returns. No real investment can guarantee returns.");
    expect(INVEST_REASONS["rule.invest_vip_group"].en).toBe("Invites you to a paid or VIP tips group.");
    expect(INVEST_REASONS["rule.invest_upi"].en).toBe("Asks for investment money to a UPI ID that is not a SEBI @valid ID.");
  });
  test("Hindi and Kannada are flagged for a native speaker, English is not", () => {
    expect(INVEST_NEEDS_REVIEW).toEqual({ en: false, hi: true, kn: true });
  });
});

describe("N2 the investment card", () => {
  test("the API's advice line is the card's English text, and only that line is the card", () => {
    expect(INVEST_ADVICE.en).toBe(SEBI_LINE);
    expect(isInvestAdvice(SEBI_LINE)).toBe(true);
    expect(isInvestAdvice("Don't reply, click the link or call back.")).toBe(false);
    expect(DEVANAGARI.test(INVEST_ADVICE.hi) && KANNADA.test(INVEST_ADVICE.kn)).toBe(true);
    expect(INVEST_ADVICE.hi).toContain("@valid");
    expect(INVEST_ADVICE.kn).toContain("sebi.gov.in");
  });
  test("a Report whose rule fired carries the line first, and it is the card, not a step", () => {
    const rep = fx("invest-vip-group-tips");
    expect(rep.advice[0]).toBe(SEBI_LINE);
    const html = renderToStaticMarkup(<WhatToDo advice={rep.advice} level={rep.level} tip={null} />);
    expect(html).toContain('class="investcard"');
    expect(html).toContain(SEBI_LINE);
    expect(html).toContain(INVEST_HEADING.en);
    expect(html.match(/<li>/g)).toHaveLength(rep.advice.length - 1);
    expect(html.indexOf("investcard")).toBeLessThan(html.indexOf("steplist"));
    expect(html).toContain("Cyber crime helpline");   // the helpline row is still under the steps
  });
  test("Hindi and Kannada: the card and the helpline row change together", () => {
    const rep = fx("invest-vip-group-tips");
    for (const lang of ["hi", "kn"] as const) {
      const html = renderToStaticMarkup(<WhatToDo advice={rep.advice} level={rep.level} tip={null} lang={lang} onLang={() => {}} />);
      expect(html).toContain(INVEST_ADVICE[lang]);
      expect(html).toContain(INVEST_HEADING[lang]);
      expect(html).not.toContain(SEBI_LINE);
      expect(html).toMatch(new RegExp(`class="investcard" lang="${lang}"`));
      expect(html).toMatch(new RegExp(`lang="${lang}"[^>]*aria-pressed="true"`));
    }
  });
  test("no card without the line: other reports, and a no-warning verdict", () => {
    for (const label of ["otp-share-kyc", "invest-sebi-valid-template", "invest-valid-id-pay", "bank-example"]) {
      const rep = fx(label);
      expect(rep.advice.some(isInvestAdvice), label).toBe(false);
      expect(renderToStaticMarkup(<WhatToDo advice={rep.advice} level={rep.level} tip={null} />)).not.toContain("investcard");
    }
  });
  test("the line is on every report whose rule fired, and on none whose rule did not", () => {
    for (const f of FIXTURES) {
      const fired = f.report.evidence.some((e) => e.id.startsWith(INVEST_PREFIX));
      expect(f.report.advice.some(isInvestAdvice), f.label).toBe(fired);
      if (fired) expect(["suspicious", "likely_scam"]).toContain(f.report.level);   // the rules raise to at least Suspicious
    }
  });
  test("the rules do not fire on SEBI's own @valid template or a genuine broker's @valid payment line", () => {
    for (const label of ["invest-sebi-valid-template", "invest-valid-id-pay"]) {
      expect(fx(label).evidence.filter((e) => e.id.startsWith(INVEST_PREFIX)), label).toEqual([]);
    }
  });
});

describe("N3 the Why reasons follow the language", () => {
  const rep = fx("demo-d07");   // A3 + A5 (two investment reasons) and the model's wording line, which has no translation
  const targets = reasonTargets(rep);
  const show = (lang: "en" | "hi" | "kn") =>
    renderToStaticMarkup(<WhyPanel reasons={rep.reasons} targets={targets} pointable={rep.reasons.map(() => false)} onPoint={() => {}} lang={lang} />);
  test("English: the reasons as sent", () => {
    const html = show("en");
    for (const r of rep.reasons) expect(html).toContain(r.replace("'", "&#x27;"));
  });
  test("Hindi / Kannada: the investment reasons are translated, the model line stays English", () => {
    for (const lang of ["hi", "kn"] as const) {
      const html = show(lang);
      expect(html).toContain(INVEST_REASONS["rule.invest_guaranteed"][lang]);
      expect(html).toContain(INVEST_REASONS["rule.invest_vip_group"][lang]);
      expect(html).not.toContain("Promises guaranteed returns");
      expect(html).toContain("The wording is very similar to known scam messages");
      expect(html).toContain(`lang="${lang}"`);
    }
  });
  test("reasonText: an unknown or missing evidence keeps the sent text", () => {
    expect(reasonText("sent", null, "hi")).toBe("sent");
    expect(reasonText("sent", { ...rep.evidence[0], id: "rule.otp_request" }, "kn")).toBe("sent");
  });
});

describe("N4 the helpline switch", () => {
  test("alone it starts in English; driven by props it shows the given language", () => {
    expect(renderToStaticMarkup(<Helpline />)).toMatch(/lang="en"[^>]*aria-pressed="true"/);
    expect(renderToStaticMarkup(<Helpline lang="kn" onLang={() => {}} />)).toMatch(/lang="kn"[^>]*aria-pressed="true"/);
  });
});
