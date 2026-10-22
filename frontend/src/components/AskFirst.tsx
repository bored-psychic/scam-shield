import { useEffect, useId, useRef, useState } from "react";
import { buildNote, NEEDS_REVIEW, NOTE_LANGS, shareableMessage, smsUrl, whatsappUrl, type AskLevel, type NoteLang } from "../lib/askFirst";

type Props = {
  level: AskLevel;
  reason: string | null;     // the top reason, as the Report words it
  message: string;           // exactly what was pasted: masked and defanged here before it goes into a note
  quotes: string[];          // the links in it, as written (defanged along with the rest)
};

/* "Ask someone first" (shown on Suspicious and Likely scam only): a button that opens a small panel under it with a ready-made note
   (verdict, the top reason, "please call me before I pay or share anything") and three ways to hand it over: a WhatsApp link, an SMS link,
   and Copy. No phone number is needed, the user picks the contact in their own app. The links are plain hrefs: nothing is sent, stored or
   fetched by this page, and the app opens only when the user taps. "Include the message" is off by default and, when on, adds the pasted
   text with PII masked and links made unclickable (lib/askFirst.ts). Hindi and Kannada notes are marked as needing a native speaker's review. */
export default function AskFirst({ level, reason, message, quotes }: Props) {
  const [open, setOpen] = useState(false);
  const [lang, setLang] = useState<NoteLang>("en");
  const [withMessage, setWithMessage] = useState(false);
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  const id = useId(), panelId = `${id}-panel`, groupName = `${id}-lang`;
  const btn = useRef<HTMLButtonElement>(null), noteEl = useRef<HTMLParagraphElement>(null);

  const note = buildNote(level, reason, lang, withMessage ? shareableMessage(message, quotes) : null);
  const langInfo = NOTE_LANGS.find((l) => l.id === lang)!;

  useEffect(() => { setCopy("idle"); }, [note]);   // an edited choice makes the old "Copied" untrue
  useEffect(() => {
    if (copy !== "copied") return;
    const t = setTimeout(() => setCopy("idle"), 2500);
    return () => clearTimeout(t);
  }, [copy]);
  useEffect(() => {
    if (copy !== "failed" || !noteEl.current) return;   // where the clipboard is refused, select the note so the user can copy it by hand
    const range = document.createRange();
    range.selectNodeContents(noteEl.current);
    getSelection()?.removeAllRanges();
    getSelection()?.addRange(range);
  }, [copy]);

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape" && open) { e.stopPropagation(); setOpen(false); btn.current?.focus(); }
  }

  async function copyNote() {
    try { await navigator.clipboard.writeText(note); setCopy("copied"); } catch { setCopy("failed"); }
  }

  return (
    <div className="ask" onKeyDown={onKeyDown}>
      <button type="button" ref={btn} className="ghost askbtn" aria-expanded={open} aria-controls={panelId} onClick={() => setOpen((o) => !o)}>
        Ask someone first <span aria-hidden="true">{open ? "▴" : "▾"}</span>
      </button>
      {open && (
        <div className="askpanel" id={panelId} role="group" aria-label="Ask someone first">
          <p className="askhint">Send this to someone you trust, and wait for their reply before you pay or share anything. You choose who in your own app.</p>
          <fieldset className="asklang">
            <legend>Language of the note</legend>
            {NOTE_LANGS.map((l) => (
              <label key={l.id} lang={l.lang}>
                <input type="radio" name={groupName} value={l.id} checked={lang === l.id} onChange={() => setLang(l.id)} />
                <span>{l.label}</span>
              </label>
            ))}
          </fieldset>
          {NEEDS_REVIEW[lang] && (
            <p className="askreview">This wording is not yet checked by a native speaker. The reason is in English.</p>
          )}
          <p className="asknote" ref={noteEl} lang={langInfo.lang}>{note}</p>
          <label className="askcheck">
            <input type="checkbox" checked={withMessage} onChange={(e) => setWithMessage(e.target.checked)} />
            <span>Include the message <small>(phone numbers, emails, UPI IDs and account numbers hidden; links made unclickable)</small></span>
          </label>
          <div className="askactions">
            <a className="ghost" href={whatsappUrl(note)} target="_blank" rel="noopener noreferrer">Send on WhatsApp ↗</a>
            <a className="ghost" href={smsUrl(note)}>Send SMS</a>
            <button type="button" className="ghost" onClick={copyNote}>{copy === "copied" ? "Copied" : "Copy note"}</button>
          </div>
          <p className="askprivacy">Nothing is stored and Scam Shield sends nothing. WhatsApp or Messages opens only when you tap.</p>
          <span className="sr-only" role="status" aria-live="polite">{copy === "copied" ? "Note copied" : copy === "failed" ? "Couldn't copy. The note is selected." : ""}</span>
        </div>
      )}
    </div>
  );
}
