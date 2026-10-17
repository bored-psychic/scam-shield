import { afterEach, describe, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { analyse, CheckError } from "../api";
import type { Report } from "../types/report";
import { LEVEL_VALUES } from "../types/report";
import { LEVEL_HEX, LEVEL_SUMMARY, LEVELS } from "./levels";
import { blips } from "./evidence";
import { SENDER_HELP_OUTRO, SENDER_HINT, SENDER_MAX, SENDER_PLACEHOLDER, SENDER_TIP, SUFFIX_HELP, showSenderTip } from "./sender";
import SenderField from "../components/SenderField";
import SenderChip from "../components/SenderChip";
import VerdictPanel from "../components/VerdictPanel";
import WhatToDo from "../components/WhatToDo";
import raw from "./__fixtures__/reports.json";

// npm test. The sender input (D22): the field, the chip, the Promotional level and the "check who sent it" tip. Components are rendered to HTML
// with react-dom/server (no browser needed); the Reports are real ones from frontend/scripts/dump_fixture.py.
type Fixture = { label: string; text: string; report: Report };
const FIXTURES = raw as unknown as Fixture[];
const fx = (label: string) => {
  const f = FIXTURES.find((x) => x.label === label);
  if (!f) throw new Error(`fixture ${label} missing: rerun frontend/scripts/dump_fixture.py`);
  return f.report;
};

afterEach(() => vi.unstubAllGlobals());
const textOf = (html: string) => html.replace(/<[^>]+>/g, "");

describe("S1 the Promotional level", () => {
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
    const r = fx("jio-promotional");
    expect(r.level).toBe("promotional");
    expect(r.schema_version).toBe("3");
    expect(r.reasons[0]).toBe("Sent from a registered business ID (promotional)");
    expect(blips(r)).toEqual([]);
    expect(r.advice.join(" ")).toMatch(/expected/);
    expect(fx("jio-no-sender").level).toBe("likely_scam");   // the same text without a sender
  });
  test("the verdict panel shows the word, the blue icon and the chip", () => {
    const html = renderToStaticMarkup(<VerdictPanel level="promotional" sender={fx("jio-promotional").sender} blips={[]} pointable={[]} onPoint={() => {}} headingRef={null} />);
    expect(html).toContain(">Promotional</h2>");
    expect(html).toContain("background:var(--blue)");
    expect(html).toContain("Registered business · Promotional");
    expect(html).toContain("Scanned · registered promotional sender");
  });
});

describe("S2 the sender chip", () => {
  const chip = (label: string) => renderToStaticMarkup(<SenderChip sender={fx(label).sender!} />);
  test.each([
    ["jio-promotional", "Registered business · Promotional", "JIOCPN"],
    ["jio-bare", "Registered business · type unknown", "JIOCPN"],
    ["bank-transactional", "Registered business · Transactional", "HDFCBK"],
  ])("%s: label and header", (label, text, header) => {
    expect(chip(label)).toContain(text);
    expect(chip(label)).toContain(`<code>${header}</code>`);
  });
  test("a mobile number: kind only, no number, no header", () => {
    const s = fx("jio-mobile").sender!;
    expect(s).toEqual({ kind: "mobile", suffix: null, header: null, label: "Personal mobile number" });
    expect(chip("jio-mobile")).toContain("Personal mobile number");
    expect(chip("jio-mobile")).not.toMatch(/\d{5}|<code>/);
  });
  test("anything else: Not recognised, no change to the level", () => {
    expect(fx("jio-other").sender!.label).toBe("Not recognised");
    expect(fx("jio-other").level).toBe(fx("jio-no-sender").level);
  });
  test("no sender: no chip", () => {
    const html = renderToStaticMarkup(<VerdictPanel level="likely_scam" sender={null} blips={[]} pointable={[]} onPoint={() => {}} headingRef={null} />);
    expect(html).not.toContain("schip");
  });
});

describe("S3 the sender field", () => {
  const html = renderToStaticMarkup(<SenderField value="" onChange={() => {}} />);
  test("label, placeholder, length cap, no auto-capitals, hint wired to the input", () => {
    expect(html).toMatch(/>Sender <span>\(optional\)<\/span><\/label>/);
    expect(html).toContain(`placeholder="${SENDER_PLACEHOLDER}"`);
    expect(SENDER_PLACEHOLDER).toBe("e.g. JM-JIOCPN-P or +91 98…");
    expect(html).toContain(`maxLength="${SENDER_MAX}"`);
    expect(html).toContain('autoCapitalize="off"');
    const hintId = /aria-describedby="([^"]+)"/.exec(html)![1];
    const hint = new RegExp(`id="${hintId}" class="shint">(.*?)</p>`).exec(html)![1];
    expect(textOf(hint)).toBe(SENDER_HINT);
    expect(hint).toContain('<span class="nobr">JM-JIOCPN-P</span>');   // the ID is never broken at a hyphen
    expect(SENDER_HINT).toBe("If your phone shows the full sender ID (like JM-JIOCPN-P), enter that: the last letter tells us the message type.");
  });
  test("the info button starts closed; the explainer covers P, S, T, G and ordinary numbers", () => {
    expect(html).toContain('aria-expanded="false"');
    expect(html).not.toContain('class="spop"');
    expect(SUFFIX_HELP.map(([k]) => k)).toEqual(["P", "S", "T", "G"]);
    expect(SENDER_HELP_OUTRO).toMatch(/ordinary 10-digit mobile numbers/);
  });
});

describe("S4 the 'check who sent it' tip", () => {
  test.each(FIXTURES.map((f) => [f.label, f.report] as const))("%s", (_, r) => {
    const want = r.sender === null && (r.level === "suspicious" || r.level === "likely_scam") && r.children.length > 0;
    expect(showSenderTip(r)).toBe(want);
  });
  test("shown for the Jio text without a sender; not once a sender is given, nor on a quiet verdict or a message without a link", () => {
    expect(showSenderTip(fx("jio-no-sender"))).toBe(true);
    expect(showSenderTip(fx("kyc-promotional"))).toBe(false);
    expect(showSenderTip(fx("jio-promotional"))).toBe(false);
    expect(showSenderTip(fx("bank-example"))).toBe(false);
    expect(FIXTURES.some((f) => f.report.sender === null && f.report.level === "likely_scam" && f.report.children.length === 0 && !showSenderTip(f.report))).toBe(true);
  });
  test("WhatToDo prints the tip only when given", () => {
    const r = fx("jio-no-sender");
    expect(textOf(renderToStaticMarkup(<WhatToDo advice={r.advice} level={r.level} tip={SENDER_TIP} />))).toContain(SENDER_TIP);
    expect(renderToStaticMarkup(<WhatToDo advice={r.advice} level={r.level} tip={null} />)).not.toContain("sendertip");
  });
});

describe("S5 api.analyse() and the sender", () => {
  const answer = (body: unknown) => vi.fn(async () => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } }));
  const sentBody = (f: ReturnType<typeof answer>) => JSON.parse((f.mock.calls[0] as unknown as [string, RequestInit])[1].body as string);
  test("sends the sender when it is not blank, and leaves it out when it is", async () => {
    for (const [sender, want] of [["JM-JIOCPN-P", { text: "hi", sender: "JM-JIOCPN-P" }], ["", { text: "hi" }], ["   ", { text: "hi" }]] as const) {
      const f = answer(fx("jio-promotional"));
      vi.stubGlobal("fetch", f);
      await analyse("hi", sender);
      expect(sentBody(f)).toEqual(want);
    }
  });
  test("reads a v3 Promotional Report; refuses a v2 answer as a schema mismatch", async () => {
    vi.stubGlobal("fetch", answer(fx("jio-promotional")));
    expect((await analyse("hi", "JM-JIOCPN-P")).level).toBe("promotional");
    vi.stubGlobal("fetch", answer({ ...fx("jio-no-sender"), schema_version: "2" }));
    const e = await analyse("hi").then(() => null, (x: unknown) => x);
    expect(e).toBeInstanceOf(CheckError);
    expect((e as CheckError).failure).toEqual({ kind: "schema", got: "2" });
  });
});
