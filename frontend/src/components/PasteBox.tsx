import { useLayoutEffect, useMemo, useRef, type RefObject } from "react";
import { IMAGE_TYPES } from "../lib/screenshot";
import type { AddMode, Inputs, MessageKind } from "../lib/tabs";
import { useScreenshot } from "../lib/useScreenshot";
import Light from "./Light";
import Seg from "./Seg";
import { DropArea, ShotCard } from "./ShotParts";

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

const KINDS = [["sms", "SMS or chat"], ["email", "Email"]] as const;
const MODES = [["type", "Paste text"], ["shot", "Screenshot"]] as const;

type Props = {
  inputs: Inputs;
  patch: (change: Partial<Inputs>) => void;
  onSubmit: () => void;
  inputRef: RefObject<HTMLTextAreaElement | null>;
  autoFocus: boolean;
};

/* The SMS / Email tab: today's paste box (detection chips, screenshot by picker, drop or an image-only paste, Cmd / Ctrl + Enter) in the compact box of
   docs/design/tabs-home.html, plus an Email toggle. An email has a Subject and a Body, both needed; its text goes to today's /api/analyse as subject + blank line
   + body (lib/tabs.ts, until W7). A screenshot's text goes into the Body, so the subject may stay empty then. The optional sender, attachment and header
   fields are kept here only: nothing reads them until W7, and the page says so. */
export default function PasteBox({ inputs, patch, onSubmit, inputRef, autoFocus }: Props) {
  const { kind, messageMode: mode } = inputs, email = kind === "email";
  const value = email ? inputs.body : inputs.sms;
  const toTop = useRef(false);
  const focusBox = () => inputRef.current?.focus({ preventScroll: true });
  const s = useScreenshot({
    value, toTop, focusBox,
    onChange: (text) => patch(email ? { body: text, messageMode: "type" } : { sms: text, messageMode: "type" }),
  });
  const { busy, setBox, addImage } = s;
  const picker = useRef<HTMLInputElement>(null);
  const blank = !value.trim() || (email && !inputs.subject.trim() && s.shot?.phase !== "read");
  const room = email && inputs.subject.trim() ? MAX_CHARS - inputs.subject.trim().length - 2 : MAX_CHARS;   // the subject, the blank line and the body must fit the API's limit

  const found = useMemo(() => DETECT.flatMap(([name, rx, warn]) => {
    const n = value.match(rx)?.length ?? 0;
    return n ? [{ name, warn, label: `${n} ${name}${n > 1 && !name.endsWith("mention") ? "s" : ""}` }] : [];
  }), [value]);

  useLayoutEffect(() => {   // grow with the text up to the CSS max-height, as the prototype's detect() did
    const ta = inputRef.current;
    if (!ta) return;
    ta.style.height = "auto";
    ta.style.height = Math.min(260, ta.scrollHeight + ta.offsetHeight - ta.clientHeight) + "px";
    if (toTop.current) {   // text just read from a screenshot: start the user at its first line
      toTop.current = false;
      ta.focus({ preventScroll: true });
      ta.setSelectionRange(0, 0);
      ta.scrollTop = 0;
    }
  }, [value, mode, kind, inputRef]);

  const field = (id: string, text: string, key: keyof Inputs, mono = false) => (
    <input id={id} className={mono ? "field mono" : "field"} type="text" aria-label={text} placeholder={text} autoCapitalize="off" spellCheck={false}
      value={inputs[key] as string} onChange={(e) => patch({ [key]: e.target.value })} />
  );
  const submitKeys = (e: React.KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && !e.nativeEvent.isComposing && !blank && !busy) { e.preventDefault(); onSubmit(); }
  };

  return (
    <div className="paste">
      <ShotCard s={s} />
      <div className={s.dragging ? "box entry drop" : "box entry"} role="group" aria-label="Message box: paste a message, or drop a screenshot here" {...s.boxProps}>
        <Light />
        <div className="bar">
          <Seg<MessageKind> label="What is it?" options={KINDS} value={kind} onPick={(k) => patch({ kind: k })} />
          <Seg<AddMode> label="How do you want to add it?" options={MODES} value={mode} onPick={(m) => patch({ messageMode: m })} />
        </div>
        {mode === "shot" ? (
          <>
            <DropArea title={email ? "Choose a screenshot of the email" : "Choose a screenshot of the message"} small="or drop it here" onClick={() => picker.current?.click()} />
            {email && <p className="hintc">Show the sender's full address before you take the screenshot.</p>}
          </>
        ) : email ? (
          <>
            <input id="em-subj" className="field" type="text" aria-label="Subject" placeholder="Subject" autoFocus={autoFocus}
              value={inputs.subject} onChange={(e) => patch({ subject: e.target.value })} onKeyDown={submitKeys} />
            <textarea id="em-body" ref={inputRef} className="field" rows={3} aria-label="Email text" placeholder="Email text" maxLength={room} value={value}
              onChange={(e) => setBox(e.target.value)} onKeyDown={submitKeys} />
            <details className="more">
              <summary>Sender, reply-to, attachments and headers <span>(optional)</span></summary>
              <div className="two">
                {field("em-name", "Display name", "displayName")}
                {field("em-from", "From", "from", true)}
              </div>
              {field("em-reply", "Reply-To", "replyTo", true)}
              {field("em-att", "Attachment names (comma-separated)", "attachments", true)}
              <textarea id="em-head" className="field mono" rows={3} aria-label="Headers" placeholder="Headers. Gmail: ⋮ > Show original, then copy the part above the message"
                value={inputs.headers} onChange={(e) => patch({ headers: e.target.value })} />
              <p className="hintc">The check does not read these details yet. It reads the subject and the email text.</p>
            </details>
          </>
        ) : (
          <>
            <label htmlFor="msg" className="sr-only">Message to check</label>
            <textarea id="msg" ref={inputRef} className="field" rows={3} maxLength={MAX_CHARS} autoFocus={autoFocus} value={value}
              placeholder="Paste the SMS, WhatsApp or chat message"
              onChange={(e) => setBox(e.target.value)} onKeyDown={submitKeys} />
          </>
        )}
        <input ref={picker} type="file" accept={IMAGE_TYPES.join(",")} hidden
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = "";   // the input lets go of the file; picking the same one again still fires
            if (file) addImage(file);
          }} />
        <div className="boxfoot">
          <div className="found">
            {found.length > 0
              ? found.map((f) => <span key={f.name} className={f.warn ? "fchip warn" : "fchip"}><b></b>{f.label}</span>)
              : <p className="hintc">Read on this device. Nothing is stored.</p>}
          </div>
          <div className="acts">
            {value.length > COUNT_FROM && (
              <span className={value.length >= room ? "count full" : "count"}>{value.length.toLocaleString("en-IN")} / {room.toLocaleString("en-IN")}</span>
            )}
            <button className="go" type="button" disabled={blank || busy || mode === "shot"} onClick={onSubmit}>{email ? "Check email" : "Check message"}</button>
          </div>
        </div>
        {s.dragging && <div className="dropzone" aria-hidden="true">Drop the screenshot to read its text</div>}
      </div>
    </div>
  );
}
