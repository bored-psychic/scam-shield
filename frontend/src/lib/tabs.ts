// The four tabs of the home screen (D29.15; docs/design/tabs-home.html, docs/plans/multi_input.md section 6): their names, headlines, what each
// sends to the checker today, and the samples. Pure: no DOM, unit-tested (src/lib/tabs.test.ts). The Report contract is not touched: until W1 / W7
// everything that can be checked goes to today's /api/analyse as one text.

export type TabKey = "message" | "link" | "payment" | "app";
export const TABS: readonly TabKey[] = ["message", "link", "payment", "app"];
export const TAB_NAME: Record<TabKey, string> = { message: "SMS / Email", link: "Link", payment: "Payment / UPI", app: "App / APK" };

// The exact copy of tabs-home.html. The accent word is the only part in italics and red; the question mark follows it.
export const HERO: Record<TabKey, { lead: string; accent: string; sub: string }> = {
  message: { lead: "Is this message a", accent: "scam", sub: "Paste it or add a screenshot." },
  link: { lead: "Is this link", accent: "safe", sub: "Checked without opening it." },
  payment: { lead: "Is this payment", accent: "genuine", sub: "Check a UPI ID or a screenshot." },
  app: { lead: "Is this app", accent: "real", sub: "Check it before you install." },
};

export type MessageKind = "sms" | "email";
export type AddMode = "type" | "shot";
export type AppMode = "name" | "file";
export type Started = "yes" | "no" | "unsure";

// Everything typed on the home screen, one set per tab, kept while the user moves between tabs and to the result and back. Only the theme is ever stored (ARCHITECTURE 5.4).
export type Inputs = {
  kind: MessageKind; messageMode: AddMode; sms: string;
  subject: string; body: string; from: string; displayName: string; replyTo: string; attachments: string; headers: string;
  linkMode: AddMode; link: string;
  payMode: AddMode; upi: string; started: Started | null;
  appMode: AppMode; appName: string; how: string; fileName: string;
};
export const NO_INPUTS: Inputs = {
  kind: "sms", messageMode: "type", sms: "",
  subject: "", body: "", from: "", displayName: "", replyTo: "", attachments: "", headers: "",
  linkMode: "type", link: "",
  payMode: "type", upi: "", started: null,
  appMode: "name", appName: "", how: "", fileName: "",
};

/** An email as today's /api/analyse reads it (until W7): subject, a blank line, body. The optional sender, attachment and header fields are not sent. */
export const emailText = (subject: string, body: string) => (subject.trim() ? `${subject.trim()}\n\n${body}` : body);

/** The text the Check button sends from a tab. Payment and App have no check yet (W3 / W4, W6): nothing is sent from them. */
export function textToCheck(tab: TabKey, i: Inputs): string {
  if (tab === "message") return i.kind === "email" ? emailText(i.subject, i.body) : i.sms;
  if (tab === "link") return i.link.trim();
  return "";
}

/** The same inputs with what was just checked cleared, for "Check something else". The modes stay as they were. */
export function clearChecked(tab: TabKey, i: Inputs): Inputs {
  if (tab === "message" && i.kind === "email") return { ...i, subject: "", body: "", from: "", displayName: "", replyTo: "", attachments: "", headers: "" };
  if (tab === "message") return { ...i, sms: "" };
  if (tab === "link") return { ...i, link: "" };
  return i;
}

// The first link in a text read from a screenshot (the paste box's own cosmetic pattern; the checker decides what a link is). The Link tab holds one link, so only the first is kept.
const LINK = /\b(?:https?:\/\/|www\.)\S+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|xyz|top|info|net|org|co|online|site|link)(?:\/\S*)?/i;
export const firstLink = (text: string): string | null => text.match(LINK)?.[0] ?? null;

export const MAX_APK_BYTES = 50 * 1024 * 1024;   // D29.5
/** null when the picked file is an APK of at most 50 MB, else the message to show. Nothing reads its bytes or uploads it: there is no APK check yet (W11). */
export function validateApk(file: { name: string; size: number }): string | null {
  if (!/\.apk$/i.test(file.name)) return "Choose an .apk file.";
  if (file.size === 0) return "This file is empty. Choose an .apk file.";
  if (file.size > MAX_APK_BYTES) return "This file is too large (max 50 MB).";
  return null;
}

// Plan section 2.4: the payment card line, shown under the Payment tab's control.
export const PAYMENT_CARD = "Before you pay, check the registered name your payment app shows. Receiving money never needs your UPI PIN, a QR scan or an approved request.";
// Plan section 6.2: the fixed explanation of the Payment tab's Screenshot mode. No file is ever asked for or uploaded.
export const PROOF_EXPLANATION = "A screenshot cannot prove a payment, so there is nothing to upload.";
// One plain line per tab whose check does not exist yet (Payment W3 / W4, App W6).
export const NOT_BUILT: Partial<Record<TabKey, string>> = { payment: "The payment check is not built yet.", app: "The app check is not built yet." };

// Plan section 4.1: "How did you get this file?"
export const HOW_CHAT: [value: string, label: string][] = [
  ["invite", "An invitation"], ["bill", "A bill or challan"], ["kyc", "A KYC or bank update"], ["parcel", "A parcel or courier"],
  ["reward", "A reward, cashback or refund"], ["job", "A job or task"], ["other", "Something else"],
];
export const HOW_OTHER: [value: string, label: string][] = [["website", "From a website I chose"], ["unknown", "I don't know"]];

// The five sample chips of tabs-home.html. A chip only fills in the tab: nothing is checked until the user presses Check, and the verdict comes from the checker like any other.
export type Sample = { id: string; label: string; tab: TabKey; set: Partial<Inputs> };
export const SAMPLES: readonly Sample[] = [
  { id: "kyc", label: "KYC link SMS", tab: "message", set: { kind: "sms", messageMode: "type",
    sms: "Dear Customer, your SBI account will be blocked today. Update your PAN and KYC immediately: hxxps://sbi-kyc-update[.]top/verify" } },
  { id: "email", label: "Fake bank email", tab: "message", set: { kind: "email", messageMode: "type",
    subject: "Action required: your account will be suspended",
    body: "Dear customer, your account has been temporarily restricted. Download the attached form to complete verification within 24 hours.",
    displayName: "SBI Alerts", from: "sbi.alerts.kyc@gmail.com", attachments: "SBI_KYC_Form.apk" } },
  { id: "upi", label: "UPI refund ID", tab: "payment", set: { payMode: "type", upi: "refund.desk@ybl", started: "no" } },
  { id: "apk", label: "APK sent on WhatsApp", tab: "app", set: { appMode: "file", fileName: "SBI KYC Update.apk", how: "kyc" } },
  { id: "proof", label: "Payment screenshot", tab: "payment", set: { payMode: "shot" } },
];
