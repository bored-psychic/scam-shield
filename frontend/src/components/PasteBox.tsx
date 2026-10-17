import { useEffect, useLayoutEffect, useMemo, useRef, useState, type DragEvent, type RefObject } from "react";
import { ocr, OcrError } from "../api";
import { firstFile, IMAGE_TYPES, OCR_MESSAGES, ocrNotice, pastedImage, validateImage } from "../lib/screenshot";

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

/* Screenshot input (D19, part B). Pick, drop or paste a screenshot -> checked here (type, size) -> thumbnail + "Reading" -> POST /api/ocr
   -> its text goes into the box for the user to check; the check itself only runs when they press Check. The image lives only in memory:
   the File, and an object URL for the thumbnail that is revoked when the screenshot is replaced, removed, or the box goes away. */
type Shot =
  | { phase: "reading"; url: string }
  | { phase: "ask"; url: string; text: string; dropped: number }   // read, but the box holds the user's own text: replace it only if they say so
  | { phase: "read"; url: string; dropped: number }
  | { phase: "error"; url: string | null; message: string };      // url null: refused before upload, so there is no thumbnail

type Props = {
  value: string;
  onChange: (text: string) => void;
  onSubmit: () => void;
  inputRef: RefObject<HTMLTextAreaElement | null>;
  autoFocus: boolean;
};

const hasFiles = (e: DragEvent) => e.dataTransfer.types.includes("Files");

export default function PasteBox({ value, onChange, onSubmit, inputRef, autoFocus }: Props) {
  const [shot, setShot] = useState<Shot | null>(null);
  const [dragging, setDragging] = useState(false);
  const run = useRef(0), reading = useRef<AbortController | null>(null), drags = useRef(0), toTop = useRef(false);
  const own = useRef(value);   // the last text this box put in (typed or read); any other change came from outside (an example chip)
  const box = useRef<HTMLDivElement>(null), picker = useRef<HTMLInputElement>(null);
  const busy = shot?.phase === "reading" || shot?.phase === "ask";
  const blank = !value.trim();
  const url = shot?.url ?? null;

  const found = useMemo(() => DETECT.flatMap(([name, rx, warn]) => {
    const n = value.match(rx)?.length ?? 0;
    return n ? [{ name, warn, label: `${n} ${name}${n > 1 && !name.endsWith("mention") ? "s" : ""}` }] : [];
  }), [value]);

  useLayoutEffect(() => {   // grow with the text up to the CSS max-height, as the prototype's detect() did
    const ta = inputRef.current;
    if (!ta) return;
    ta.style.height = "auto";
    ta.style.height = Math.min(260, ta.scrollHeight) + "px";
    if (toTop.current) {   // text just read from a screenshot: start the user at its first line
      toTop.current = false;
      ta.focus({ preventScroll: true });
      ta.setSelectionRange(0, 0);
      ta.scrollTop = 0;
    }
  }, [value, inputRef]);

  useEffect(() => (url ? () => URL.revokeObjectURL(url) : undefined), [url]);
  useEffect(() => () => { run.current++; reading.current?.abort(); }, []);   // leaving the home screen cancels a read in flight

  useEffect(() => {   // an example chip replaced the text: the screenshot and its notice no longer describe what is in the box
    if (value === own.current) return;
    own.current = value;
    stop();
    setShot(null);
  }, [value]);

  useEffect(() => {   // a file dropped next to the box would otherwise make the browser open it in place of this page
    const guard = (e: globalThis.DragEvent) => {
      if (!e.dataTransfer?.types.includes("Files") || box.current?.contains(e.target as Node)) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "none";
    };
    window.addEventListener("dragover", guard);
    window.addEventListener("drop", guard);
    return () => { window.removeEventListener("dragover", guard); window.removeEventListener("drop", guard); };
  }, []);

  function stop() {   // forget the screenshot being read, if any: its answer is ignored
    run.current++;
    reading.current?.abort();
    reading.current = null;
  }
  function setBox(text: string) {
    own.current = text;
    onChange(text);
  }
  function place(text: string) {
    if (text === own.current) { inputRef.current?.focus({ preventScroll: true }); return; }
    toTop.current = true;
    setBox(text);
  }
  function focusBox() {
    inputRef.current?.focus({ preventScroll: true });
  }

  function addImage(file: File) {
    stop();
    const problem = validateImage(file);
    if (problem) { setShot({ phase: "error", url: null, message: problem }); return; }
    const id = run.current, ctl = new AbortController(), src = URL.createObjectURL(file);
    reading.current = ctl;
    setShot({ phase: "reading", url: src });
    ocr(file, ctl.signal).then(
      ({ text, dropped }) => {
        if (run.current !== id) return;
        reading.current = null;
        const now = own.current;   // what is in the box now: the user may have typed while the screenshot was read
        if (now.trim() && now !== text) { setShot({ phase: "ask", url: src, text, dropped }); return; }
        place(text);
        setShot({ phase: "read", url: src, dropped });
      },
      (e: unknown) => {
        if (run.current !== id) return;
        reading.current = null;
        setShot({ phase: "error", url: src, message: e instanceof OcrError ? e.message : OCR_MESSAGES.failed });
      },
    );
  }

  const replace = () => {
    if (shot?.phase !== "ask") return;
    place(shot.text);
    setShot({ phase: "read", url: shot.url, dropped: shot.dropped });
  };
  const remove = () => { stop(); setShot(null); focusBox(); };   // keeps the text

  const status = !shot ? null
    : shot.phase === "reading" ? { icon: "on", mark: "", text: "Reading your screenshot…" }
    : shot.phase === "read" ? { icon: "done", mark: "✓", text: ocrNotice(shot.dropped) }
    : shot.phase === "ask" ? { icon: "warn", mark: "?", text: "Replace your text with the text from the screenshot?" }
    : { icon: "bad", mark: "!", text: shot.message };

  return (
    <div className="paste">
      <div className={shot ? `shot on ${shot.phase}` : "shot"}>
        {url && <span className={shot?.phase === "reading" ? "thumb scan" : "thumb"}><img src={url} alt="Your screenshot" draggable={false} /></span>}
        <div className="sline">
          {status && <i className={status.icon} aria-hidden="true">{status.mark}</i>}
          {/* always in the page, so screen readers hear every change of it */}
          <p className="shotmsg" role="status">{status?.text}</p>
        </div>
        {shot && (
          <div className="sacts">
            {shot.phase === "ask" ? (
              <>
                <button type="button" className="ghost" onClick={replace}>Replace</button>
                <button type="button" className="ghost" onClick={remove}>Keep my text</button>
              </>
            ) : url ? (
              <button type="button" className="ghost" onClick={remove}>Remove screenshot</button>
            ) : (
              <button type="button" className="ghost" onClick={remove}>Dismiss</button>
            )}
          </div>
        )}
      </div>

      <div ref={box} className={dragging ? "box drop" : "box"} role="group" aria-label="Message box: paste a message, or drop a screenshot here"
        onPaste={(e) => {
          const image = pastedImage(e.clipboardData);
          if (image) { e.preventDefault(); addImage(image); }
        }}
        onDragEnter={(e) => { if (!hasFiles(e)) return; e.preventDefault(); drags.current++; setDragging(true); }}
        onDragOver={(e) => { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = "copy"; }}
        onDragLeave={(e) => { if (!hasFiles(e)) return; if (--drags.current <= 0) { drags.current = 0; setDragging(false); } }}
        onDrop={(e) => {
          if (!hasFiles(e)) return;
          e.preventDefault();
          drags.current = 0;
          setDragging(false);
          const file = firstFile(e.dataTransfer);
          if (file) addImage(file);
        }}>
        <div className="hero" style={{ gap: 0 }}>
          <label htmlFor="msg" className="sr-only">Message to check</label>
          <textarea id="msg" ref={inputRef} rows={3} maxLength={MAX_CHARS} autoFocus={autoFocus} value={value}
            placeholder="Paste a WhatsApp, SMS or email message…"
            onChange={(e) => setBox(e.target.value)}
            onKeyDown={(e) => {
              if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && !e.nativeEvent.isComposing && !blank && !busy) { e.preventDefault(); onSubmit(); }
            }} />
          <div className="boxfoot">
            <div className="found">
              {found.length > 0
                ? found.map((f) => <span key={f.name} className={f.warn ? "fchip warn" : "fchip"}><b></b>{f.label}</span>)
                : <span className="hint">{blank ? "links, UPI IDs and numbers show up here" : "no links, UPI IDs or numbers found"}</span>}
            </div>
            <div className="acts">
              {value.length > COUNT_FROM && (
                <span className={value.length >= MAX_CHARS ? "count full" : "count"}>{value.length.toLocaleString("en-IN")} / 20,000</span>
              )}
              <button type="button" className="ghost shotbtn" title="Read the text of a screenshot (PNG, JPG or WEBP, up to 8 MB)"
                onClick={() => picker.current?.click()}>
                <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <rect x="3.5" y="4.5" width="17" height="15" rx="3" stroke="currentColor" strokeWidth="1.6" />
                  <circle cx="9" cy="9.6" r="1.7" stroke="currentColor" strokeWidth="1.4" />
                  <path d="m4.5 17 5-4.4 3.4 2.9 2.6-2.1 4 3.4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                Screenshot
              </button>
              <input ref={picker} type="file" accept={IMAGE_TYPES.join(",")} hidden
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  e.target.value = "";   // the input lets go of the file; picking the same one again still fires
                  if (file) addImage(file);
                }} />
              <button className="go" type="button" disabled={blank || busy} onClick={onSubmit}>Check <kbd>{KEYS}</kbd></button>
            </div>
          </div>
        </div>
        {dragging && <div className="dropzone" aria-hidden="true">Drop the screenshot to read its text</div>}
      </div>
    </div>
  );
}
