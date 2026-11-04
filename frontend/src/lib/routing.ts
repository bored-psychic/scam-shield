import type { InputKind } from "../types/report";
import type { TabKey } from "./tabs";

// Plan 6.3: when the Report's `input` differs from the tab it was sent from, one calm line above the verdict says what the checker made of it. The page owns these four lines
// (like the level summaries); the backend only sets `input`.
export const ROUTING_LINES = {
  upi_id: "This looks like a UPI ID, so it was checked as a payment ID.",
  link: "This looks like a link, so it was checked as one.",
  message: "This looks like a message, so it was checked as one.",
  qr_link: "This QR code holds a link, so the link was checked.",
} as const;

// What each tab is for: a Report whose input is one of these needs no notice.
const OWN: Record<TabKey, readonly InputKind[]> = {
  message: ["message", "email"],
  link: ["link"],
  payment: ["upi_id", "payment_request", "qr", "payment_proof"],
  app: ["app", "apk"],
};

/** The notice for a Report checked from `tab`, or null when it was checked as the tab says (or as something that has no line). `viaQr`: the input was a decoded QR code (no tab
 *  reads one yet: W10), so a link found in it gets the fourth line. */
export function routingNotice(tab: TabKey, input: InputKind | null, viaQr = false): string | null {
  if (input === null || OWN[tab].includes(input)) return null;
  if (input === "link") return viaQr ? ROUTING_LINES.qr_link : ROUTING_LINES.link;
  if (input === "upi_id") return ROUTING_LINES.upi_id;
  if (input === "message") return ROUTING_LINES.message;
  return null;
}
