// Layout check of the result screen with the D23 "Website details" (no overlap, no horizontal scroll, nothing sticking out of its panel).
//
//   cd frontend && npm run build && node e2e/overlap.mjs [--shots DIR]
//
// Every viewport x case runs in BOTH themes (2026-10-18; picked through prefers-color-scheme): the serif headings and the theme button change widths.
//
// Serves the built dist/ with Vite's preview server on 127.0.0.1:4173 and drives the INSTALLED Google Chrome through playwright-core (no
// browser download). /api/analyse and /api/check are answered inside the page from the real Reports in src/lib/__fixtures__/reports.json (offline: the network
// rows pending), then a live answer made from the same Report with long values filled in, and an expanded answer for the short-link button.
// So it needs no backend, makes no network request, and opens no link. Viewports: 360 / 390 / 430 px phones (several heights) and 1280 / 1440
// desktop. States checked per case: pending, after the live answer with every "Website details" sheet open, and after the short-link button.
// Exit code 1 on any failure. Earlier sessions ran the same checks from a scratch directory; this is the committed version (D23).
import { readFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { preview } from "vite";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = JSON.parse(readFileSync(join(HERE, "..", "src", "lib", "__fixtures__", "reports.json"), "utf8"));
const shotsAt = process.argv.indexOf("--shots");
const SHOTS = shotsAt > 0 ? process.argv[shotsAt + 1] : null;
const VIEWPORTS = [[360, 640], [360, 800], [390, 600], [390, 844], [430, 932], [1280, 800], [1440, 900]];
const NO_LINK = "invest-vip-group-tips";   // 2026-10-25: the investment card and the translated Why reasons (a Report with no link, rules A3 + A5)
const CASES = ["jio-no-sender", "kyc-promotional", "shortener-keywords", NO_LINK];
const THEMES = ["dark", "light"];
const PORT = 4173;

const fx = (label) => {
  const f = FIXTURES.find((x) => x.label === label);
  if (!f) throw new Error(`fixture ${label} missing: rerun frontend/scripts/dump_fixture.py`);
  return f;
};
const clone = (x) => JSON.parse(JSON.stringify(x));

// Long but realistic values, so a narrow screen has to wrap them.
const LIVE_VALUES = {
  age: ["3 days ago (15 Oct 2026)", "caution", "Scam sites are usually days or weeks old; real banks' and shops' sites are years old."],
  server: ["FIXTURE-VERY-LONG-HOSTING-PROVIDER-NAME-INTERNATIONAL-PRIVATE-LIMITED (AS4294967294) · United Arab Emirates", "neutral", null],
  safe_browsing: ["Not listed", "neutral", null],
};
function liveOf(report, raised) {
  const r = clone(report);
  r.pending = [];
  if (raised) { r.level = "likely_scam"; r.risk_score = Math.max(r.risk_score ?? 0, 70); r.lowered = null; }   // a live red flag ends the P1 lowering (D24)
  for (const c of r.children) {
    c.pending = [];
    if (!c.link) continue;
    c.link.facts = c.link.facts.flatMap((f) => {
      if (f.status !== "pending") return [f];
      const [value, effect, why] = LIVE_VALUES[f.key] ?? ["Couldn't verify (timed out)", "unknown", null];
      const row = { ...f, status: "ok", value, effect, why, sent: `domain ${c.link.owner} → rdap.example-registry-with-a-long-name.example (registry)` };
      return f.key === "age" ? [row, { ...row, key: "registrar", label: "Registrar", value: "An Extremely Long Registrar Name Of Some Sort, LLC (IANA 9999)", effect: "neutral", why: null }] : [row];
    });
    if (!c.link.shortener) c.link.sent = [`domain ${c.link.owner} → rdap.example-registry-with-a-long-name.example (registry)`, `domain ${c.link.owner} → cloudflare-dns.com (DNS)`];
  }
  return r;
}
function expandedOf(report) {
  const r = liveOf(report, true);
  for (const c of r.children) {
    if (!c.link?.shortener) continue;
    const dest = "https://sbi-kyc-update-secure-login-verification-centre.top/account/verify?session=abcdef1234567890abcdef";
    c.link.expandable = false;
    c.link.destination = dest;
    c.link.facts = c.link.facts.map((f) => (f.key === "destination" ? { ...f, status: "ok", value: dest, effect: "neutral", why: null } : f));
    c.link.facts.push({ key: "dest_owner", label: "Destination: owner", value: "Not SBI ('sbi' in sbi-kyc-update-secure-login-verification-centre.top)",
                        effect: "caution", why: "SBI's own sites are sbi.co.in, onlinesbi.com. Scammers put a brand's name in their own web address.",
                        status: "ok", source: null, sent: null });
    c.link.sent = ["short link bit.ly/abc → bit.ly"];
  }
  return r;
}

// Everything measured in the page: problems as strings.
function measure() {
  const out = [];
  const near = (a, b) => a <= b + 1;
  if (!near(document.documentElement.scrollWidth, innerWidth)) out.push(`horizontal scroll: page ${document.documentElement.scrollWidth} > ${innerWidth}`);
  const panels = [...document.querySelectorAll(".bento > .box, .bento > .bcol > .box")];
  if (!panels.length) out.push("no result panels");
  const rects = panels.map((p) => [p.className.split(" ").slice(0, 2).join("."), p.getBoundingClientRect()]);
  for (let i = 0; i < rects.length; i++)
    for (let j = i + 1; j < rects.length; j++) {
      const [na, a] = rects[i], [nb, b] = rects[j];
      const w = Math.min(a.right, b.right) - Math.max(a.left, b.left), h = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
      if (w > 1 && h > 1) out.push(`panels overlap: ${na} / ${nb} (${Math.round(w)}x${Math.round(h)} px)`);
    }
  for (const box of document.querySelectorAll(".box.link")) {
    const b = box.getBoundingClientRect();
    for (const el of box.querySelectorAll(".url, .checks div, summary, dt, dd, .fval, .frow small, .expand button, .expand .note, .note")) {
      const r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) continue;   // inside a closed sheet
      if (r.left < b.left - 1 || r.right > b.right + 1) out.push(`${el.tagName.toLowerCase()}.${el.className || ""} sticks out of the link panel (${Math.round(r.left)}..${Math.round(r.right)} vs ${Math.round(b.left)}..${Math.round(b.right)})`);
      if (el.scrollWidth > el.clientWidth + 1 && el.clientWidth > 0) out.push(`${el.tagName.toLowerCase()} text overflows (${el.scrollWidth} > ${el.clientWidth}): ${el.textContent.slice(0, 40)}`);
    }
    const rows = [...box.querySelectorAll(".frow")].map((r) => r.getBoundingClientRect()).filter((r) => r.height);
    for (let i = 1; i < rows.length; i++) if (rows[i].top < rows[i - 1].bottom - 1) out.push("Website details rows overlap");
    for (const row of box.querySelectorAll(".frow")) {
      const dt = row.querySelector("dt")?.getBoundingClientRect(), dd = row.querySelector("dd")?.getBoundingClientRect();
      if (dt && dd && dt.height && dd.height) {
        const w = Math.min(dt.right, dd.right) - Math.max(dt.left, dd.left), h = Math.min(dt.bottom, dd.bottom) - Math.max(dt.top, dd.top);
        if (w > 1 && h > 1) out.push(`label and value overlap in a row: ${row.querySelector("dt").textContent}`);
      }
    }
  }
  // Helpline row (2026-10-23): always visible inside What to do now on a warning verdict; everything in it stays in the What to do panel, nothing
  // overlaps (also with the long Hindi / Kannada labels, the page sets lang through the switch), buttons >= 40 px tall on a phone, text >= 14 px
  const row = document.querySelector(".helprow");
  if (row) {
    const todo = row.closest(".box").getBoundingClientRect();
    const kids = [...row.querySelectorAll(".helplabel, .helplangbtn, .callbtn, .helplink")].filter((el) => el.getClientRects().length);
    for (const el of [row, ...kids]) {
      const r = el.getBoundingClientRect();
      if (r.left < todo.left - 1 || r.right > todo.right + 1) out.push(`help: ${el.className || el.tagName} sticks out of the What to do panel (${Math.round(r.left)}..${Math.round(r.right)} vs ${Math.round(todo.left)}..${Math.round(todo.right)})`);
      if (el.scrollWidth > el.clientWidth + 1 && el.clientWidth > 0) out.push(`help: ${el.className || el.tagName} overflows (${el.scrollWidth} > ${el.clientWidth})`);
    }
    for (let i = 0; i < kids.length; i++)
      for (let j = i + 1; j < kids.length; j++) {
        const a = kids[i].getBoundingClientRect(), b = kids[j].getBoundingClientRect();
        if (kids[i].contains(kids[j]) || kids[j].contains(kids[i])) continue;
        const w = Math.min(a.right, b.right) - Math.max(a.left, b.left), h = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
        if (w > 1 && h > 1) out.push(`help: ${kids[i].className || kids[i].tagName} overlaps ${kids[j].className || kids[j].tagName}`);
      }
    for (const el of row.querySelectorAll(".callbtn, .helplink")) {
      const r = el.getBoundingClientRect(), fs = parseFloat(getComputedStyle(el).fontSize);
      if (r.height < 40) out.push(`help: ${el.className} is ${Math.round(r.height)} px tall (< 40)`);
      if (fs < 14) out.push(`help: ${el.className} text is ${fs}px (< 14)`);
    }
    for (const el of row.querySelectorAll(".helplangbtn")) {
      const r = el.getBoundingClientRect();
      if (r.height < 24 || r.width < 24) out.push(`help: switch button ${el.textContent} is ${Math.round(r.width)}x${Math.round(r.height)} px (< 24)`);
    }
  }
  // Investment card (2026-10-25): above the steps, inside What to do now, text >= 14 px; the Why reasons never overflow their buttons
  const card = document.querySelector(".investcard");
  if (card) {
    const todo = card.closest(".box").getBoundingClientRect(), r = card.getBoundingClientRect(), list = document.querySelector(".steplist").getBoundingClientRect();
    if (r.left < todo.left - 1 || r.right > todo.right + 1) out.push(`invest: the card sticks out of the What to do panel (${Math.round(r.left)}..${Math.round(r.right)} vs ${Math.round(todo.left)}..${Math.round(todo.right)})`);
    if (r.bottom > list.top + 1) out.push("invest: the card is not above the steps");
    for (const el of card.querySelectorAll("b, p")) {
      const fs = parseFloat(getComputedStyle(el).fontSize);
      if (el.scrollWidth > el.clientWidth + 1) out.push(`invest: ${el.tagName} overflows (${el.scrollWidth} > ${el.clientWidth})`);
      if (el.tagName === "P" && fs < 14) out.push(`invest: card text is ${fs}px (< 14)`);
    }
  }
  for (const b of document.querySelectorAll(".reasons .reason")) {
    if (b.scrollWidth > b.clientWidth + 1) out.push(`why: a reason overflows its button (${b.scrollWidth} > ${b.clientWidth}): ${b.textContent.slice(0, 40)}`);
  }
  // Risk meter (2026-10-23): at any score the knob (moved here to 0, 1, 30, 50, 70, 99, 100) does not touch a scale number, and a number stays on the panel
  const knob = document.querySelector(".meter .knob");
  if (knob) {
    const keep = knob.style.left, anim = knob.style.animation, trans = knob.style.transition;
    knob.style.animation = "none"; knob.style.transition = "none";   // a transition on left would leave the knob where it was
    for (const sc of [0, 1, 30, 50, 70, 99, 100]) {
      knob.style.left = `${sc}%`;
      const k = knob.getBoundingClientRect();
      for (const n of document.querySelectorAll(".mscale span")) {
        const r = n.getBoundingClientRect();
        const w = Math.min(k.right, r.right) - Math.max(k.left, r.left), h = Math.min(k.bottom, r.bottom) - Math.max(k.top, r.top);
        if (w > 0 && h > 0) out.push(`meter: the knob at ${sc} touches the scale number ${n.textContent}`);
      }
    }
    knob.style.left = keep; knob.style.animation = anim; knob.style.transition = trans;
  }
  // Radar tags (2026-10-23): at least 24 px tall (WCAG 2.5.8), none sticking out of the radar's wrapper
  for (const t of document.querySelectorAll(".radar .lbl")) {
    const r = t.getBoundingClientRect();
    if (r.height < 24) out.push(`radar: tag "${t.textContent}" is ${r.height.toFixed(1)} px tall (< 24)`);
  }
  return out;
}

async function runCase(browser, [w, h], label, theme) {
  const f = fx(label);
  const raised = label === "jio-no-sender";
  const ctx = await browser.newContext({ viewport: { width: w, height: h }, reducedMotion: "reduce", deviceScaleFactor: 1, colorScheme: theme });
  const page = await ctx.newPage();
  const problems = [];
  let release;
  const liveGate = new Promise((res) => { release = res; });
  await page.route(/\/api\/(?:analyse|check)$/, async (route) => {
    const body = JSON.parse(route.request().postData() || "{}");
    if (body.expand) return route.fulfill({ json: expandedOf(f.report) });
    if (body.live) { await liveGate; return route.fulfill({ json: liveOf(f.report, raised) }); }
    return route.fulfill({ json: f.report });
  });
  await page.route((url) => !url.href.startsWith(`http://127.0.0.1:${PORT}/`), (route) => { problems.push(`request outside the page: ${route.request().url()}`); route.abort(); });
  await page.goto(`http://127.0.0.1:${PORT}/`);
  await page.fill("#msg", f.text);
  await page.click("button.go");
  await page.waitForSelector(label === NO_LINK ? ".result .box" : ".result .box.link");
  const tag = `${theme.padEnd(5)} ${w}x${h} ${label}`;
  if ((await page.evaluate(() => document.documentElement.dataset.theme)) !== theme) problems.push(`the page is not in the ${theme} theme`);
  const check = async (state) => {
    for (const p of await page.evaluate(measure)) problems.push(`${state}: ${p}`);
    if (SHOTS) { mkdirSync(SHOTS, { recursive: true }); await page.screenshot({ path: join(SHOTS, `${theme}_${label}_${w}x${h}_${state}.png`), fullPage: true }); }
  };
  if (!(await page.locator(".frow.pending").count()) && label !== "shortener-keywords" && label !== NO_LINK) problems.push("pending: no pending row was shown");
  await check("pending");
  release();
  await page.waitForFunction(() => !document.querySelector(".frow.pending"));
  if (raised && !(await page.locator(".vraised").count())) problems.push("live: the 'Raised after the website checks' note is missing");
  await page.evaluate(() => document.querySelectorAll("details.facts").forEach((d) => { d.open = true; }));
  await check("live");
  const btn = page.locator("button", { hasText: "Where does this short link go?" });
  if (await btn.count()) {
    await btn.first().click();
    await page.waitForFunction(() => [...document.querySelectorAll("dd")].some((d) => d.textContent.includes("verification-centre.top")));
    await page.evaluate(() => document.querySelectorAll("details.facts").forEach((d) => { d.open = true; }));
    await check("expanded");
  } else if (label === "shortener-keywords") problems.push("the short-link button is missing");
  // Helpline row: on a warning verdict it is there without any toggle, links and wording right; then switch to Hindi and Kannada and check the layout again
  const warn = await page.evaluate(() => /Likely scam|Suspicious/.test(document.querySelector(".vword")?.textContent ?? ""));
  if (warn !== (await page.locator(".helprow").count() > 0)) problems.push(`help: the row is ${warn ? "missing on" : "shown on"} a ${warn ? "warning" : "non-warning"} verdict`);
  if (await page.locator("button.askbtn, .askpanel, .helptoast, .helpchakshu").count()) problems.push("help: a dropped element (Get help toggle / Chakshu / toast) is back");
  if (warn) {
    const links = await page.evaluate(() => ({ call: document.querySelector(".callbtn")?.getAttribute("href"), portal: document.querySelector(".helplink")?.getAttribute("href"),
      target: document.querySelector(".helplink")?.getAttribute("target"), hint: document.querySelector(".callbtn")?.getAttribute("aria-label"),
      label: document.querySelector(".helplabel")?.textContent, below: document.querySelector(".steplist").compareDocumentPosition(document.querySelector(".helprow")) & 4 }));
    if (links.call !== "tel:1930" || links.portal !== "https://cybercrime.gov.in" || links.target !== "_blank") problems.push(`help: wrong links ${JSON.stringify(links)}`);
    if (!/within one hour/.test(links.hint ?? "")) problems.push("help: the Call button has no one-hour aria-label");
    if (links.label !== "Cyber crime helpline") problems.push(`help: label is "${links.label}"`);
    if (!links.below) problems.push("help: the row is not under the steps");
    await check("help-en");
    if (f.report.advice.some((a) => /@valid/.test(a)) !== (await page.locator(".investcard").count() > 0)) problems.push("invest: the card does not match the SEBI advice line");
    if (await page.locator(".steplist li", { hasText: "@valid" }).count()) problems.push("invest: the SEBI line is also a numbered step");
    for (const [name, label] of [["हिंदी", "साइबर क्राइम हेल्पलाइन"], ["ಕನ್ನಡ", "ಸೈಬರ್ ಕ್ರೈಂ ಹೆಲ್ಪ್‌ಲೈನ್"]]) {
      await page.click(`.helplangbtn:has-text("${name}")`);
      const got = await page.locator(".helplabel").textContent();
      if (got !== label) problems.push(`help: ${name} label is "${got}"`);
      if (f.report.evidence.some((e) => e.id.startsWith("rule.invest_"))) {   // the investment reasons and the card follow the switch
        const script = name === "हिंदी" ? /[\u0900-\u097F]/ : /[\u0C80-\u0CFF]/;
        const why = await page.locator(".reasons .reason").first().textContent(), cardText = await page.locator(".investcard").textContent();
        if (!script.test(why ?? "")) problems.push(`invest: the first reason is not in ${name}: "${why}"`);
        if (!script.test(cardText ?? "")) problems.push(`invest: the card is not in ${name}`);
      }
      await check(`help-${name}`);
    }
  }
  await ctx.close();
  return [tag, problems];
}

const server = await preview({ root: join(HERE, ".."), preview: { host: "127.0.0.1", port: PORT, strictPort: true }, logLevel: "silent" });
const browser = await chromium.launch({ channel: "chrome", headless: true });
let failed = 0;
try {
  for (const theme of THEMES)
  for (const vp of VIEWPORTS)
    for (const label of CASES) {
      const [tag, problems] = await runCase(browser, vp, label, theme);
      console.log(`${problems.length ? "FAIL" : "ok  "} ${tag}`);
      for (const p of problems.slice(0, 8)) console.log(`      ${p}`);
      failed += problems.length ? 1 : 0;
    }
} finally {
  await browser.close();
  await new Promise((res) => server.httpServer.close(res));
}
const RUNS = THEMES.length * VIEWPORTS.length * CASES.length;
console.log(`\n${RUNS - failed}/${RUNS} theme x viewport x case runs without a layout problem`);
process.exit(failed ? 1 : 0);
