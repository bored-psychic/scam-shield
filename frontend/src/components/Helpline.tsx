import { useId, useState } from "react";
import { CALL_URL, CYBERCRIME_URL, HELP_LANGS, HELP_STRINGS, type HelpLang } from "../lib/helpline";

/* The helpline row (shown on Suspicious and Likely scam only, inside What to do now, under the steps): a label, [Call 1930] and
   [cybercrime.gov.in ↗], with a compact EN / हिंदी / ಕನ್ನಡ switch on the right of the row. The "if money was lost, call within one hour" hint is
   only the Call button's aria-label and title. English until the user picks another language (not remembered). Nothing is submitted, sent or
   stored by this page. HELP_NEEDS_REVIEW (lib/helpline.ts) marks wording not yet checked by a native speaker; the row shows nothing about it. */
export default function Helpline() {
  const [lang, setLang] = useState<HelpLang>("en");
  const id = useId();
  const s = HELP_STRINGS[lang], tag = HELP_LANGS.find((l) => l.id === lang)!.tag;
  return (
    <div className="helprow" role="group" aria-labelledby={`${id}-label`}>
      <div className="helphead">
        <span className="helplabel" id={`${id}-label`} lang={tag}>{s.label}</span>
        <div className="helplang" role="group" aria-label="Language">
          {HELP_LANGS.map((l) => (
            <button key={l.id} type="button" lang={l.tag} className="helplangbtn" aria-pressed={lang === l.id} onClick={() => setLang(l.id)}>{l.name}</button>
          ))}
        </div>
      </div>
      <div className="helpbtns" lang={tag}>
        <a className="callbtn" href={CALL_URL} aria-label={`${s.call}. ${s.hint}`} title={s.hint}>{s.call}</a>
        <a className="ghost helplink" href={CYBERCRIME_URL} target="_blank" rel="noopener noreferrer"><span>{s.portal}<span className="arrow" aria-hidden="true">↗</span></span></a>
      </div>
    </div>
  );
}
