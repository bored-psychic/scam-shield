import { describe, expect, test } from "vitest";
import { createRef } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import Home from "../components/Home";
import { clearChecked, emailText, firstLink, HERO, NO_INPUTS, NOT_BUILT, PROOF_EXPLANATION, SAMPLES, TAB_NAME, TABS, textToCheck, validateApk, type Inputs, type TabKey } from "./tabs";

// npm test. The four tabs (D29.15): T1 the exact copy of docs/design/tabs-home.html, T2 what each tab sends, T3 "Check something else", T4 the first link of a screenshot's text,
// T5 the APK picker's check, T6 the tabs and panels as rendered. Browser side (keyboard, phone row, motion, lift, light): e2e/tabs.mjs.
const home = (tab: TabKey, set: Partial<Inputs> = {}) => renderToStaticMarkup(
  <Home tab={tab} onTab={() => {}} inputs={{ ...NO_INPUTS, ...set }} patch={() => {}} onCheck={() => {}} onSample={() => {}}
    messageRef={createRef<HTMLTextAreaElement>()} linkRef={createRef<HTMLInputElement>()} autoFocus={false} />);
const textOf = (html: string) => html.replace(/<[^>]+>/g, "");

describe("T1 the copy of tabs-home.html", () => {
  test("tab names, in order", () => {
    expect(TABS.map((k) => TAB_NAME[k])).toEqual(["SMS / Email", "Link", "Payment / UPI", "App / APK"]);
  });
  test("headline and sub-line per tab, the accent word in an em", () => {
    const want: Record<TabKey, [string, string, string]> = {
      message: ["Is this message a scam?", "scam", "Paste it or add a screenshot."],
      link: ["Is this link safe?", "safe", "Checked without opening it."],
      payment: ["Is this payment genuine?", "genuine", "Check a UPI ID or a screenshot."],
      app: ["Is this app real?", "real", "Check it before you install."],
    };
    for (const k of TABS) {
      const html = home(k), [h1, accent, sub] = want[k];
      expect(HERO[k].sub).toBe(sub);
      expect(textOf(html.match(/<h1[^>]*>.*?<\/h1>/s)![0]).replace(/\s+/g, " ").trim()).toBe(h1);
      expect(html).toContain(`<em>${accent}</em>?`);
      expect(html).toContain(`<p class="sub">${sub}</p>`);
    }
  });
  test("the sample chips", () => {
    expect(SAMPLES.map((s) => s.label)).toEqual(["KYC link SMS", "Fake bank email", "UPI refund ID", "APK sent on WhatsApp", "Payment screenshot"]);
    for (const s of SAMPLES) expect(textOf(home("message"))).toContain(s.label);
  });
});

describe("T2 what the Check button sends", () => {
  test("SMS: the text as typed; email: subject + blank line + body (until W7); nothing else of the email", () => {
    expect(textToCheck("message", { ...NO_INPUTS, sms: " hello\nthere " })).toBe(" hello\nthere ");
    const email = { ...NO_INPUTS, kind: "email", subject: "Hi", body: "Body text", from: "a@b.c", attachments: "x.apk", headers: "H: 1" } as Inputs;
    expect(textToCheck("message", email)).toBe("Hi\n\nBody text");
    expect(emailText("  ", "only body")).toBe("only body");
  });
  test("Link: one line, trimmed", () => expect(textToCheck("link", { ...NO_INPUTS, link: "  https://x.example/a  " })).toBe("https://x.example/a"));
  test("Payment and App: the ID / request, the app's name or the file's name; nothing for the payment screenshot mode (no text is sent)", () => {
    const all = { ...NO_INPUTS, upi: " refund.desk@ybl ", appName: " SBI ", fileName: "a.apk" };
    expect(textToCheck("payment", all)).toBe("refund.desk@ybl");
    expect(textToCheck("payment", { ...all, payMode: "shot" })).toBe("");
    expect(textToCheck("app", all)).toBe("SBI");
    expect(textToCheck("app", { ...all, appMode: "file" })).toBe("a.apk");
  });
});

describe("T3 Check something else", () => {
  test("clears what was checked, keeps the other tabs' text and the modes", () => {
    const i = { ...NO_INPUTS, sms: "s", link: "l", upi: "u", subject: "x", body: "y", attachments: "a", messageMode: "shot" } as Inputs;
    expect(clearChecked("link", i)).toEqual({ ...i, link: "" });
    expect(clearChecked("message", i)).toEqual({ ...i, sms: "" });
    expect(clearChecked("message", { ...i, kind: "email" })).toEqual({ ...i, kind: "email", subject: "", body: "", attachments: "" });
  });
});

test("T4 the first link in a screenshot's text", () => {
  expect(firstLink("Update now: sbi-kyc-update.top/login and then www.other.in")).toBe("sbi-kyc-update.top/login");
  expect(firstLink("go to https://a.example/x?y=1 today")).toBe("https://a.example/x?y=1");
  expect(firstLink("no link in this one")).toBeNull();
});

test("T5 the APK picker refuses before anything happens", () => {
  expect(validateApk({ name: "a.apk", size: 1 })).toBeNull();
  expect(validateApk({ name: "A.APK", size: 50 * 1024 * 1024 })).toBeNull();
  expect(validateApk({ name: "a.apk", size: 50 * 1024 * 1024 + 1 })).toMatch(/too large/);
  expect(validateApk({ name: "a.apk", size: 0 })).toMatch(/empty/);
  expect(validateApk({ name: "a.pdf", size: 10 })).toMatch(/\.apk/);
});

describe("T6 the tabs and panels", () => {
  test("WAI-ARIA: a tablist of four tabs, one selected and in the Tab order, each controlling its own tabpanel", () => {
    for (const k of TABS) {
      const html = home(k);
      expect(html).toContain('role="tablist"');
      const tabs = [...html.matchAll(/<button[^>]*role="tab"[^>]*>/g)].map((m) => m[0]);
      expect(tabs).toHaveLength(4);
      for (const t of TABS) {
        const b = tabs.find((x) => x.includes(`id="tab-${t}"`))!;
        expect(b).toContain(`aria-controls="panel-${t}"`);
        expect(b).toContain(`aria-selected="${t === k}"`);
        expect(b).toContain(`tabindex="${t === k ? 0 : -1}"`);
        expect(html).toMatch(new RegExp(`role="tabpanel" id="panel-${t}" aria-labelledby="tab-${t}"`));
      }
      expect([...html.matchAll(/role="tabpanel"[^>]* hidden/g)]).toHaveLength(3);
    }
  });
  test("SMS / Email: paste text and screenshot modes, an Email toggle with Subject, Body and the optional details", () => {
    const sms = home("message");
    expect(sms).toContain('id="msg"');
    expect(sms).not.toContain('id="em-subj"');
    const email = home("message", { kind: "email" });
    expect(email).toContain('id="em-subj"');
    expect(email).toContain('id="em-body"');
    expect(textOf(email)).toContain("Sender, reply-to, attachments and headers");
    expect(email).toMatch(/<details class="more">/);
    expect(email).not.toMatch(/<details[^>]* open/);
    expect(textOf(email)).toContain("Check email");
    expect(textOf(home("message", { messageMode: "shot" }))).toContain("Choose a screenshot of the message");
  });
  test("Link: one line, a visible label, not spell-checked", () => {
    const html = home("link");
    expect(html).toMatch(/<label class="lbl" for="url">The link<\/label>/);
    expect(html).toMatch(/<input id="url"[^>]*inputMode="url"[^>]*autoCapitalize="off"[^>]*spellCheck="false"/i);
    expect(textOf(html)).toContain("Check link");
  });
  test("Payment: 'UPI ID or payment request' + Screenshot; Check disabled while empty, with the not-built line; the Screenshot mode has no file input at all", () => {
    const html = home("payment");
    expect(textOf(html)).toContain("UPI ID or payment request");
    expect(textOf(html)).toContain("Did you start this payment?");
    expect(textOf(html)).toContain(NOT_BUILT.payment);
    expect(html).toMatch(/<button class="go" type="button" disabled=""[^>]*aria-describedby="pay-notbuilt"/);
    const shot = home("payment", { payMode: "shot" });
    expect(textOf(shot)).toContain(PROOF_EXPLANATION);
    expect(textOf(shot)).toContain("Show me what to do");
    expect(shot).not.toContain('type="file"');
    expect(shot).not.toMatch(/<button class="go" type="button" disabled=""/);   // W2: it sends {kind: "payment_proof"} (no image); X2 in check.test.tsx
  });
  test("App: 'Name or link' + 'App file', no Screenshot mode; Check disabled while empty, with the not-built line", () => {
    for (const appMode of ["name", "file"] as const) {
      const html = home("app", { appMode });
      expect(textOf(html)).toContain("Name or link");
      expect(textOf(html)).toContain("App file");
      expect(textOf(html.slice(html.indexOf('id="panel-app"'), html.indexOf('class="ex"')))).not.toContain("Screenshot");
      expect(textOf(html)).toContain(NOT_BUILT.app);
      expect(html).toMatch(/<button class="go" type="button" disabled=""[^>]*aria-describedby="app-notbuilt"/);
    }
    const file = home("app", { appMode: "file" });
    expect(textOf(file)).toContain("How did you get this file?");
    expect(textOf(file)).toContain("The file is read on this device. It is never installed or run.");
    expect(file).toContain('accept=".apk,application/vnd.android.package-archive"');
  });
});
