import { useLayoutEffect, useMemo, type RefObject } from "react";

// The glass paste box. The chips only count what has been typed, with the prototype's DETECT patterns (unchanged); the verdict comes from the API.
const DETECT: [name: string, rx: RegExp, warn: boolean][] = [
  ["link", /\b(?:https?:\/\/|www\.)\S+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|xyz|top|info|net|org|co|online|site|link)(?:\/\S*)?/gi, false],
  ["UPI ID", /\b[\w.\-]{2,}@(?:ybl|okaxis|oksbi|okhdfcbank|okicici|paytm|upi|ibl|axl|apl)\b/gi, false],
  ["phone number", /(?:\+?91[\s-]?)?\b[6-9]\d{9}\b/g, false],
  ["amount", /(?:₹|rs\.?|inr)\s?[\d,]+(?:\.\d+)?/gi, false],
  ["OTP / PIN mention", /\b(?:otp|pin|cvv)\b/gi, true],
];
const MAX_CHARS = 20000;    // the API's limit (MAX_TEXT_CHARS in src/shield/api/main.py)
const COUNT_FROM = 18000;   // show the length counter past this
const KEYS = /Mac|iPhone|iPad|iPod/.test(navigator.userAgent) ? "⌘↵" : "Ctrl ↵";

type Props = {
  value: string;
  onChange: (text: string) => void;
  onSubmit: () => void;
  inputRef: RefObject<HTMLTextAreaElement | null>;
  autoFocus: boolean;
};

export default function PasteBox({ value, onChange, onSubmit, inputRef, autoFocus }: Props) {
  const blank = !value.trim();
  const found = useMemo(() => DETECT.flatMap(([name, rx, warn]) => {
    const n = value.match(rx)?.length ?? 0;
    return n ? [{ name, warn, label: `${n} ${name}${n > 1 && !name.endsWith("mention") ? "s" : ""}` }] : [];
  }), [value]);

  useLayoutEffect(() => {   // grow with the text up to the CSS max-height, as the prototype's detect() did
    const ta = inputRef.current;
    if (!ta) return;
    ta.style.height = "auto";
    ta.style.height = Math.min(260, ta.scrollHeight) + "px";
  }, [value, inputRef]);

  return (
    <div className="box">
      <div className="hero" style={{ gap: 0 }}>
        <label htmlFor="msg" className="sr-only">Message to check</label>
        <textarea id="msg" ref={inputRef} rows={3} maxLength={MAX_CHARS} autoFocus={autoFocus} value={value}
          placeholder="Paste a WhatsApp, SMS or email message…"
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => {
            if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && !e.nativeEvent.isComposing && !blank) { e.preventDefault(); onSubmit(); }
          }} />
        <div className="boxfoot">
          <div className="found">
            {found.length > 0
              ? found.map((f) => <span key={f.name} className={f.warn ? "fchip warn" : "fchip"}><b></b>{f.label}</span>)
              : <span className="hint">{blank ? "links, UPI IDs and numbers show up here" : "no links, UPI IDs or numbers found"}</span>}
          </div>
          {value.length > COUNT_FROM && (
            <span className={value.length >= MAX_CHARS ? "count full" : "count"}>{value.length.toLocaleString("en-IN")} / 20,000</span>
          )}
          <button className="go" type="button" disabled={blank} onClick={onSubmit}>Check <kbd>{KEYS}</kbd></button>
        </div>
      </div>
    </div>
  );
}
