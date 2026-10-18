import { afterEach, describe, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { analyse, CheckError } from "../api";
import type { Report } from "../types/report";
import { LEVEL_VALUES } from "../types/report";
import { LEVEL_HEX, LEVEL_SUMMARY, LEVELS } from "./levels";
import { blips } from "./evidence";
import { SENDER_TIP, showSenderTip } from "./sender";
import App from "../App";
import Result from "../components/Result";
import VerdictPanel from "../components/VerdictPanel";
import WhatToDo from "../components/WhatToDo";
import raw from "./__fixtures__/reports.json";

// npm test. The sender (D22) on the page. The sender input, its hint, the TRAI explainer and the sender chip were removed on 2026-10-18 (product
// decision); the API keeps its optional sender field, dormant. What the page still has: the Promotional level (reachable only through the API) and
// the "check who sent it" tip. Components are rendered to HTML with react-dom/server (no browser needed); the Reports are real ones from
// frontend/scripts/dump_fixture.py (the ones with a sender block were made by calling the API with a sender, which the page never does).
type Fixture = { label: string; text: string; report: Report };
const FIXTURES = raw as unknown as Fixture[];
const fx = (label: string) => {
  const f = FIXTURES.find((x) => x.label === label);
  if (!f) throw new Error(`fixture ${label} missing: rerun frontend/scripts/dump_fixture.py`);
  return f;
};

vi.mock("../components/Tip", () => ({ default: () => null }));   // the tooltip portals into document.body, which a server render has not got
afterEach(() => vi.unstubAllGlobals());
const textOf = (html: string) => html.replace(/<[^>]+>/g, "");
// every class name and text the removed sender UI used (SenderField: .sender .srow .sinfo .shint .spop; SenderChip: .sblock .schip .snote)
const SENDER_UI = /class="(?:[^"]* )?(?:sender|srow|sinfo|shint|spop|sblock|schip|snote)(?: [^"]*)?"|Sender <span>|\(optional\)|What a sender ID tells you/;

describe("S1 the Promotional level (reachable only through the API)", () => {
  test("is a level, with its own word, colour, icon and summary", () => {
    expect(LEVEL_VALUES).toContain("promotional");
    expect(LEVELS.promotional.word).toBe("Promotional");
    expect(LEVEL_SUMMARY.promotional.length).toBeGreaterThan(0);
    const others = LEVEL_VALUES.filter((l) => l !== "promotional");
    for (const l of others) {
      expect(LEVELS.promotional.color, l).not.toBe(LEVELS[l].color);   // distinct from Safe (green) and Suspicious (amber), and the rest
      expect(LEVEL_HEX.promotional, l).not.toBe(LEVEL_HEX[l]);
      expect(LEVELS.promotional.icon, l).not.toBe(LEVELS[l].icon);
    }
  });
  test("the Jio promo with a P header is Promotional: the P reason first, no blips, its own advice", () => {
    const r = fx("jio-promotional").report;
    expect(r.level).toBe("promotional");
    expect(r.schema_version).toBe("3");
    expect(r.reasons[0]).toBe("Sent from a registered business ID (promotional)");
    expect(blips(r)).toEqual([]);
    expect(r.advice.join(" ")).toMatch(/expected/);
    expect(fx("jio-no-sender").report.level).toBe("likely_scam");   // the same text without a sender
  });
  test("the verdict panel shows the word, the blue icon and the radar caption, and no sender chip", () => {
    const html = renderToStaticMarkup(<VerdictPanel level="promotional" blips={[]} pointable={[]} onPoint={() => {}} headingRef={null} />);
    expect(html).toContain(">Promotional</h2>");
    expect(html).toContain("background:var(--blue)");
    expect(html).toContain("Scanned · registered promotional sender");
    expect(html).not.toMatch(SENDER_UI);
  });
});

describe("S2 no sender UI on the result screen, even for a Report that has a sender block", () => {
  const withSender = FIXTURES.filter((f) => f.report.sender !== null);
  test("the fixtures still cover every sender kind", () => {
    expect(new Set(withSender.map((f) => f.report.sender!.kind))).toEqual(new Set(["dlt", "dlt_bare", "mobile", "other"]));
  });
  test.each(withSender.map((f) => [f.label, f] as const))("%s", (_, f) => {
    const html = renderToStaticMarkup(<Result report={f.report} text={f.text} onAgain={() => {}} />);
    expect(html).toContain(`>${LEVELS[f.report.level].word}</h2>`);   // the verdict is drawn
    expect(html).not.toMatch(SENDER_UI);
    expect(textOf(html)).not.toContain(f.report.sender!.label);       // "Registered business · Promotional", "Personal mobile number", "Not recognised"
    expect(html).not.toMatch(/<code>[A-Z0-9]{6}<\/code>/);
  });
});

describe("S3 no sender UI on the home screen", () => {
  const html = renderToStaticMarkup(<App />);
  test("the home screen has the message box and no sender field, hint or explainer", () => {
    expect(html).toContain("<textarea");
    expect(html).not.toMatch(SENDER_UI);
    expect(html).not.toMatch(/<input[^>]*type="text"/);
    expect(textOf(html)).not.toMatch(/JM-JIOCPN-P|sender/i);
  });
  test("the sender components are gone", () => {
    const files = Object.keys(import.meta.glob("../components/*.tsx"));
    expect(files.length).toBeGreaterThan(10);
    expect(files.filter((f) => /Sender/.test(f))).toEqual([]);
  });
});

describe("S4 the 'check who sent it' tip", () => {
  test("its wording: no mention of typing or entering a sender", () => {
    expect(SENDER_TIP).toBe("Check who sent it: real businesses send from IDs like JM-JIOCPN-P; scams usually come from ordinary phone numbers.");
    expect(SENDER_TIP).not.toMatch(/\b(enter|type|typed|field|box|optional)\b/i);
  });
  test.each(FIXTURES.map((f) => [f.label, f.report] as const))("%s", (_, r) => {
    const want = r.sender === null && (r.level === "suspicious" || r.level === "likely_scam") && r.children.length > 0;
    expect(showSenderTip(r)).toBe(want);
  });
  test("shown for the Jio text without a sender; not when a Report has a sender, nor on a quiet verdict or a message without a link", () => {
    expect(showSenderTip(fx("jio-no-sender").report)).toBe(true);
    expect(showSenderTip(fx("kyc-promotional").report)).toBe(false);
    expect(showSenderTip(fx("jio-promotional").report)).toBe(false);
    expect(showSenderTip(fx("bank-example").report)).toBe(false);
    expect(FIXTURES.some((f) => f.report.sender === null && f.report.level === "likely_scam" && f.report.children.length === 0 && !showSenderTip(f.report))).toBe(true);
  });
  test("WhatToDo prints the tip only when given, with the sender ID kept on one line", () => {
    const r = fx("jio-no-sender").report;
    const html = renderToStaticMarkup(<WhatToDo advice={r.advice} level={r.level} tip={SENDER_TIP} />);
    expect(textOf(html)).toContain(SENDER_TIP);
    expect(html).toContain('<span class="nobr">JM-JIOCPN-P</span>');
    expect(renderToStaticMarkup(<WhatToDo advice={r.advice} level={r.level} tip={null} />)).not.toContain("sendertip");
  });
  test("the result screen for the Jio text without a sender shows it", () => {
    const f = fx("jio-no-sender");
    expect(textOf(renderToStaticMarkup(<Result report={f.report} text={f.text} onAgain={() => {}} />))).toContain(SENDER_TIP);
  });
});

describe("S5 api.analyse() never sends a sender", () => {
  const answer = (body: unknown) => vi.fn(async () => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } }));
  const sentBody = (f: ReturnType<typeof answer>) => JSON.parse((f.mock.calls[0] as unknown as [string, RequestInit])[1].body as string);
  test("the request body is exactly { text }", async () => {
    expect(analyse.length).toBe(1);
    const f = answer(fx("jio-no-sender").report);
    vi.stubGlobal("fetch", f);
    await analyse("hi");
    expect(sentBody(f)).toEqual({ text: "hi" });
  });
  test("still reads a v3 Promotional Report (an API answer the page could get if a sender were sent); refuses a v2 answer", async () => {
    vi.stubGlobal("fetch", answer(fx("jio-promotional").report));
    expect((await analyse("hi")).level).toBe("promotional");
    vi.stubGlobal("fetch", answer({ ...fx("jio-no-sender").report, schema_version: "2" }));
    const e = await analyse("hi").then(() => null, (x: unknown) => x);
    expect(e).toBeInstanceOf(CheckError);
    expect((e as CheckError).failure).toEqual({ kind: "schema", got: "2" });
  });
});
