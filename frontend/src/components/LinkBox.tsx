import { useRef, type RefObject } from "react";
import { IMAGE_TYPES } from "../lib/screenshot";
import { firstLink, type AddMode, type Inputs } from "../lib/tabs";
import { useScreenshot } from "../lib/useScreenshot";
import Light from "./Light";
import Seg from "./Seg";
import { DropArea, ShotCard } from "./ShotParts";

const MODES = [["type", "Paste link"], ["shot", "Screenshot"]] as const;
type Props = { inputs: Inputs; patch: (change: Partial<Inputs>) => void; onSubmit: () => void; inputRef: RefObject<HTMLInputElement | null>; autoFocus: boolean };

/* The Link tab: one line, sent to today's /api/analyse as it is. The link is only ever a string: it is not opened, and the live checks look up its domain name,
   never the site. In Screenshot mode the same local OCR reads the image; the first link in its text goes into the line, for the user to check before pressing Check. */
export default function LinkBox({ inputs, patch, onSubmit, inputRef, autoFocus }: Props) {
  const toTop = useRef(false);
  const s = useScreenshot({
    value: inputs.link, toTop, focusBox: () => inputRef.current?.focus({ preventScroll: true }),
    onChange: (text) => patch({ link: text, linkMode: "type" }),
    pick: firstLink, noText: "No link found in this screenshot. Type it in instead.",
  });
  const picker = useRef<HTMLInputElement>(null);
  const mode = inputs.linkMode, blank = !inputs.link.trim();
  return (
    <div className="paste">
      <ShotCard s={s} />
      <div className={s.dragging ? "box entry drop" : "box entry"} role="group" aria-label="Link box: paste a link, or drop a screenshot here" {...s.boxProps}>
        <Light />
        <div className="bar">
          {mode === "type" ? <label className="lbl" htmlFor="url">The link</label> : <span className="lbl">The link</span>}
          <Seg<AddMode> label="How do you want to add it?" options={MODES} value={mode} onPick={(m) => patch({ linkMode: m })} />
        </div>
        {mode === "type" ? (
          <input id="url" ref={inputRef} className="field mono" type="text" inputMode="url" autoCapitalize="off" spellCheck={false} placeholder="https://" autoFocus={autoFocus} value={inputs.link}
            onChange={(e) => s.setBox(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && !e.nativeEvent.isComposing && !blank && !s.busy) { e.preventDefault(); onSubmit(); } }} />
        ) : (
          <DropArea title="Choose a screenshot that shows the link" small="or drop it here" onClick={() => picker.current?.click()} />
        )}
        <input ref={picker} type="file" accept={IMAGE_TYPES.join(",")} hidden
          onChange={(e) => { const file = e.target.files?.[0]; e.target.value = ""; if (file) s.addImage(file); }} />
        <div className="boxfoot">
          <p className="hintc">Never opened. Only the website's name is looked up.</p>
          <div className="acts"><button className="go" type="button" disabled={blank || s.busy || mode === "shot"} onClick={onSubmit}>Check link</button></div>
        </div>
        {s.dragging && <div className="dropzone" aria-hidden="true">Drop the screenshot to read its text</div>}
      </div>
    </div>
  );
}
