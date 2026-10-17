import { describe, expect, test } from "vitest";
import type { Report } from "../types/report";
import { allEvidence, blips, clusterOf, isDrawn, reasonTargets, segments, type Cluster } from "./evidence";
import { linkBlocks, linkParts, ownerOf } from "./links";
import raw from "./__fixtures__/reports.json";

// npm test. The fixtures are real Reports from the Python checker (frontend/scripts/dump_fixture.py: every tests/tricky_inputs.py entry
// plus four extras), so these tests check the display logic against what the API actually sends.
type Fixture = { label: string; text: string; report: Report };
const FIXTURES = raw as unknown as Fixture[];
const fixture = (label: string) => {
  const f = FIXTURES.find((x) => x.label === label);
  if (!f) throw new Error(`fixture ${label} missing: rerun frontend/scripts/dump_fixture.py`);
  return f;
};
const segsOf = (f: Fixture) => segments(f.text, allEvidence(f.report), f.report.level);
const clustersOf = (f: Fixture) => segsOf(f).flatMap((s) => (s.cluster ? [s.cluster] : []));
const each = test.each(FIXTURES.map((f) => [f.label, f] as const));

test("fixtures are there", () => {
  expect(FIXTURES.length).toBeGreaterThanOrEqual(31);
});

describe("U1 joining the segments gives back the text", () => {
  each("%s", (_, f) => {
    expect(segsOf(f).map((s) => s.text).join("")).toBe(f.text);
  });
});

describe("U2 every drawn span lies in exactly one cluster and slices back to its quote", () => {
  each("%s", (_, f) => {
    const chars = Array.from(f.text), cs = clustersOf(f);
    for (const e of allEvidence(f.report).filter((x) => x.span !== null)) {
      const [s, t] = e.span!;
      expect(chars.slice(s, t).join(""), e.id).toBe(e.quote);
      const holding = cs.filter((c) => c.members.includes(e));
      if (isDrawn(e, f.report.level)) {
        expect(holding, e.id).toHaveLength(1);
        expect(holding[0].start <= s && t <= holding[0].end, e.id).toBe(true);
      } else {
        expect(holding, e.id).toHaveLength(0);
      }
    }
    cs.slice(1).forEach((c, i) => expect(c.start).toBeGreaterThanOrEqual(cs[i].end));   // clusters never overlap each other
  });
});

test("U3 code-point indexing: the emoji fixture's OTP cluster is exactly 'Share your OTP'", () => {
  const f = fixture("emoji-otp"), segs = segsOf(f);
  const otp = allEvidence(f.report).find((e) => e.id === "rule.otp_request")!;
  const c = clusterOf(segs, otp)!;
  expect(segs.find((s) => s.cluster === c)!.text).toBe("Share your OTP");
  expect(f.text.slice(...otp.span!)).not.toBe("Share your OTP");   // UTF-16 slicing would be off by the two emoji
});

test("U4 the shipping fixture has ONE cluster, 'share the PIN', danger, with both members", () => {
  const f = fixture("shipping-pin"), segs = segsOf(f), cs = segs.flatMap((s) => (s.cluster ? [s.cluster] : []));
  expect(cs).toHaveLength(1);
  expect(segs.find((s) => s.cluster === cs[0])!.text).toBe("share the PIN");
  expect(cs[0].effect).toBe("danger");
  expect(cs[0].members.map((e) => e.id)).toEqual(["rule.otp_request", "tactic.payment"]);
});

describe("U5 neutral underlines only on a verdict without a warning (no-warning or promotional)", () => {
  each("%s", (_, f) => {
    if (f.report.level !== "no_warning_signs" && f.report.level !== "promotional") {
      expect(clustersOf(f).filter((c: Cluster) => c.effect === "neutral" || c.members.some((e) => e.effect === "neutral"))).toEqual([]);
    }
  });
  test("the bank example is no_warning_signs with dotted neutral clusters", () => {
    const f = fixture("bank-example");
    expect(f.report.level).toBe("no_warning_signs");
    const neutral = clustersOf(f).filter((c) => c.effect === "neutral");
    expect(neutral.length).toBeGreaterThan(0);
    expect(neutral.length).toBe(clustersOf(f).length);
  });
});

describe("U6 blips: at most 4, warnings only, one per tag, none on a no-warning verdict", () => {
  each("%s", (_, f) => {
    const b = blips(f.report);
    expect(b.length).toBeLessThanOrEqual(4);
    expect(b.every((e) => e.effect === "danger" || e.effect === "caution")).toBe(true);
    expect(new Set(b.map((e) => e.tag)).size).toBe(b.length);
    if (f.report.level === "no_warning_signs") expect(b).toEqual([]);
  });
});

test("U7 every reason in every fixture has a target evidence", () => {
  const misses = FIXTURES.flatMap((f) => reasonTargets(f.report).flatMap((t, i) => (t ? [] : [`${f.label}: ${f.report.reasons[i]}`])));
  expect(misses).toEqual([]);
  const total = FIXTURES.reduce((n, f) => n + f.report.reasons.length, 0);
  expect(total).toBeGreaterThan(0);
});

describe("U8 linkParts", () => {
  test.each([
    ["http://sbi-kyc-update.top/login", "sbi-kyc-update.top"],
    ["https://www.onlinesbi.sbi", "onlinesbi.sbi"],
    ["abc.gov.in", "abc.gov.in"],
    ["https://netbanking.hdfc.bank.in/x", "hdfc.bank.in"],
  ])("%s -> owner %s", (url, owner) => {
    expect(ownerOf(linkParts(url)!)).toBe(owner);
  });
  test("labels and rest", () => {
    expect(linkParts("https://netbanking.hdfc.bank.in/x")).toEqual({ host: "netbanking.hdfc.bank.in", sub: ["netbanking"], owner: ["hdfc", "bank", "in"], rest: "/x" });
    expect(linkParts("http://sbi.co.in@totally-different.top/verify")!.host).toBe("totally-different.top");   // userinfo is not the host
  });
  test("not a url -> null", () => {
    expect(linkParts("not a url")).toBeNull();
  });
});

test("U9 the bet365 promo: gambling category, a 'Gambling site' blip, gambling advice first, both link titles in the link panel", () => {
  const f = fixture("bet365-promo"), r = f.report;
  expect(r.category).toBe("gambling");
  expect(blips(r).map((e) => e.tag)).toContain("Gambling site");
  // the gambling line is the extra first item: the rest is the same level's advice on a non-gambling report (wording lives in the backend)
  const plain = FIXTURES.find((x) => x.report.level === r.level && x.report.category === null)!.report;
  expect(r.advice.slice(1)).toEqual(plain.advice);
  expect(plain.advice).not.toContain(r.advice[0]);
  expect(r.advice[0]).toMatch(/betting/i);
  const blocks = linkBlocks(r);
  expect(blocks).toHaveLength(1);
  expect(blocks[0].checks.map((c) => c.title)).toEqual(r.children[0].evidence.map((e) => e.title));
  expect(blocks[0].checks.map((c) => c.title)).toEqual(expect.arrayContaining(["Gambling or betting site", "The link looks somewhat like phishing links"]));
  expect(ownerOf(blocks[0].parts!)).toBe("bet365.com");
});
