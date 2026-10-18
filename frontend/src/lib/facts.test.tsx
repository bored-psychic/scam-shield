import { afterEach, describe, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Report } from "../types/report";
import { analyse } from "../api";
import { factText, markLiveFailed, OFFLINE_TEXT, openByDefault, PENDING_TEXT, raisedByLive } from "./facts";
import { linkBlocks } from "./links";
import LinkPanel from "../components/LinkPanel";
import WebsiteDetails from "../components/WebsiteDetails";
import raw from "./__fixtures__/reports.json";

// npm test. D23 "Website details" on real offline Reports (frontend/scripts/dump_fixture.py: analyse() without live checks, so the network
// rows are "pending"), plus the live / expand request bodies.
//   F1 pending rows say "Checking…", a hidden destination "Hidden"   F2 a failed live call turns every pending row into "Couldn't verify (offline)"
//   F3 the verdict note only when the live checks raised the level   F4 the sheet: open on a red flag, the Jio owner line, the short-link button
//   F5 api.analyse(): {text} first, then {text, live: true}, and expand only with live   F6 the link panel lists a sheet per link and its note
type Fixture = { label: string; text: string; report: Report };
const FIXTURES = raw as unknown as Fixture[];
const fx = (label: string) => {
  const f = FIXTURES.find((x) => x.label === label);
  if (!f) throw new Error(`fixture ${label} missing: rerun frontend/scripts/dump_fixture.py`);
  return f;
};
const linkOf = (label: string, i = 0) => fx(label).report.children[i].link!;

afterEach(() => vi.unstubAllGlobals());

describe("F1 fact values", () => {
  test("pending -> Checking…; hidden destination -> Hidden", () => {
    const jio = linkOf("jio-no-sender");
    const age = jio.facts.find((f) => f.key === "age")!;
    expect(age.status).toBe("pending");
    expect(factText(age)).toBe(PENDING_TEXT);
    const dest = linkOf("shortener-keywords").facts.find((f) => f.key === "destination")!;
    expect(dest.value).toBeNull();
    expect(factText(dest)).toBe("Hidden");
  });
});

describe("F2 a failed live call never shows a pending row as safe", () => {
  test("every pending row becomes Couldn't verify (offline), effect unknown", () => {
    const r = fx("jio-no-sender").report;
    expect(r.pending).toEqual(["links"]);
    const after = markLiveFailed(r);
    expect(after.pending).toEqual([]);
    for (const c of after.children) {
      expect(c.pending).toEqual([]);
      for (const f of c.link!.facts) expect(f.status).not.toBe("pending");
    }
    const age = after.children[0].link!.facts.find((f) => f.key === "age")!;
    expect([age.status, age.value, age.effect]).toEqual(["failed", OFFLINE_TEXT, "unknown"]);
    expect(r.children[0].link!.facts.find((f) => f.key === "age")!.status).toBe("pending");   // a copy: the original is untouched
  });
});

describe("F3 raised after the website checks", () => {
  test("only an increase counts", () => {
    const base = fx("jio-no-sender").report;
    expect(raisedByLive(base, { ...base, level: "likely_scam" })).toBe(true);
    expect(raisedByLive(base, base)).toBe(false);
    expect(raisedByLive(base, { ...base, level: "no_warning_signs" })).toBe(false);
    expect(raisedByLive({ ...base, level: "cant_judge" }, base)).toBe(false);
  });
});

describe("F4 the Website details sheet", () => {
  test("the Jio link: Jio is the owner, the network rows are checking", () => {
    const html = renderToStaticMarkup(<WebsiteDetails info={linkOf("jio-no-sender")} expanding={false} expandFailed={false} />);
    expect(html).toContain("Website details");
    expect(html).toMatch(/Jio \(\.jio is its own domain ending\)/);
    expect(html).toContain(PENDING_TEXT);
    expect(html).not.toContain("Where does this short link go?");
  });
  test("a lookalike link opens on its red flag and says why", () => {
    const kyc = fx("kyc-promotional").report.children.find((c) => c.link?.owner === "sbi-kyc-update.top")!.link!;
    expect(openByDefault(kyc)).toBe(true);
    const html = renderToStaticMarkup(<WebsiteDetails info={kyc} expanding={false} expandFailed={false} />);
    expect(html).toMatch(/<details[^>]* open=""/);
    expect(html).toContain("Not SBI");
    expect(html).toContain("Scammers put a brand");
  });
  test("a short link offers the button, and warns that the shortener may count a click", () => {
    const info = linkOf("shortener-keywords");
    expect(info.shortener && info.expandable).toBe(true);
    const html = renderToStaticMarkup(<WebsiteDetails info={info} onExpand={() => {}} expanding={false} expandFailed={false} />);
    expect(html).toContain("Where does this short link go?");
    expect(html).toMatch(/may count it as a click\. The destination is not opened\./);
    expect(renderToStaticMarkup(<WebsiteDetails info={info} onExpand={() => {}} expanding expandFailed={false} />)).toMatch(/Asking [^<]+…/);
  });
});

describe("F5 request bodies", () => {
  const answer = () => vi.fn(async () => new Response(JSON.stringify(fx("jio-no-sender").report), { status: 200, headers: { "Content-Type": "application/json" } }));
  const bodyOf = (f: ReturnType<typeof answer>) => JSON.parse((f.mock.calls[0] as unknown as [string, RequestInit])[1].body as string);
  test("offline {text}, live {text, live}, expand only with live", async () => {
    let f = answer();
    vi.stubGlobal("fetch", f);
    await analyse("hi");
    expect(bodyOf(f)).toEqual({ text: "hi" });
    f = answer();
    vi.stubGlobal("fetch", f);
    await analyse("hi", { live: true });
    expect(bodyOf(f)).toEqual({ text: "hi", live: true });
    f = answer();
    vi.stubGlobal("fetch", f);
    await analyse("hi https://bit.ly/x", { live: true, expand: ["https://bit.ly/x"] });
    expect(bodyOf(f)).toEqual({ text: "hi https://bit.ly/x", live: true, expand: ["https://bit.ly/x"] });
    f = answer();
    vi.stubGlobal("fetch", f);
    await analyse("hi", { expand: ["https://bit.ly/x"] });
    expect(bodyOf(f)).toEqual({ text: "hi" });
  });
});

describe("F6 the link panel", () => {
  test("one sheet per link with a readable host; the not-opened note", () => {
    for (const f of FIXTURES.filter((x) => x.report.children.length)) {
      const html = renderToStaticMarkup(<LinkPanel report={f.report} expanding={null} expandFailed={null} />);
      const sheets = (html.match(/<summary>Website details<\/summary>/g) ?? []).length;
      expect(sheets, f.label).toBe(linkBlocks(f.report).filter((b) => b.info).length);
      expect(html, f.label).toMatch(/The links? (was|were) not opened\./);
      expect(html, f.label).not.toContain("Only the website's name was looked up");   // offline Reports: nothing was sent
    }
  });
});
