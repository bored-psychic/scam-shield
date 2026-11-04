import { useRef, useState } from "react";
import { HOW_CHAT, HOW_OTHER, NOT_BUILT, validateApk, type AppMode, type Inputs } from "../lib/tabs";
import { firstFile } from "../lib/screenshot";
import Light from "./Light";
import Seg from "./Seg";
import { DropArea } from "./ShotParts";

const MODES = [["name", "Name or link"], ["file", "App file"]] as const;
type Props = { inputs: Inputs; patch: (change: Partial<Inputs>) => void; onSubmit: () => void };

/* The App tab (plan 6.2). No Screenshot mode. The button sends the input to /api/check; while the apps engine is not built (W6, the file W11) the API answers "This check is not
   available yet." and the page says exactly that, never a verdict. A chosen file is only looked at for its name and size, refused above 50 MB or if it is not an .apk; its bytes are
   never read and it goes nowhere. */
export default function AppBox({ inputs, patch, onSubmit }: Props) {
  const mode = inputs.appMode, blank = mode === "name" ? !inputs.appName.trim() : !inputs.fileName.trim() && !inputs.how;
  const picker = useRef<HTMLInputElement>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const take = (file: File) => {
    const bad = validateApk(file);
    setProblem(bad);
    if (!bad) patch({ fileName: file.name });
  };
  return (
    <div className="paste">
      <div className="box entry" role="group" aria-label="App box" data-drop={mode === "file" || undefined}
        onDragOver={(e) => { if (e.dataTransfer.types.includes("Files") && mode === "file") { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; } }}
        onDrop={(e) => { if (mode !== "file" || !e.dataTransfer.types.includes("Files")) return; e.preventDefault(); const f = firstFile(e.dataTransfer); if (f) take(f); }}>
        <Light />
        <div className="bar">
          <span className="lbl">The app</span>
          <Seg<AppMode> label="How do you want to check it?" options={MODES} value={mode} onPick={(m) => patch({ appMode: m })} />
        </div>
        {mode === "name" ? (
          <input id="app-name" className="field mono" type="text" aria-label="App name, package name or Play Store link" autoCapitalize="off" spellCheck={false}
            placeholder="App name, package name or Play Store link" value={inputs.appName} onChange={(e) => patch({ appName: e.target.value })} />
        ) : (
          <>
            <DropArea icon="phone" title="Choose the APK file" small="or drop it here · up to 50 MB" onClick={() => picker.current?.click()} />
            <input ref={picker} type="file" accept=".apk,application/vnd.android.package-archive" hidden
              onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; if (f) take(f); }} />
            {problem && <p className="hintc notbuilt" role="status">{problem}</p>}
            <input id="app-file" className="field mono" type="text" aria-label="File name, if you know it" placeholder="File name, if you know it" autoCapitalize="off" spellCheck={false}
              value={inputs.fileName} onChange={(e) => patch({ fileName: e.target.value })} />
            <select id="app-how" className="field" aria-label="How did you get this file?" value={inputs.how} onChange={(e) => patch({ how: e.target.value })}>
              <option value="">How did you get this file?</option>
              <optgroup label="In a chat or SMS, said to be:">
                {HOW_CHAT.map(([v, t]) => <option key={v} value={v}>{t}</option>)}
              </optgroup>
              {HOW_OTHER.map(([v, t]) => <option key={v} value={v}>{t}</option>)}
            </select>
            <p className="hintc">The file is read on this device. It is never installed or run.</p>
          </>
        )}
        <div className="boxfoot">
          <p className="hintc notbuilt" id="app-notbuilt">{NOT_BUILT.app}</p>
          <div className="acts"><button className="go" type="button" disabled={blank} onClick={onSubmit} aria-describedby="app-notbuilt">Check app</button></div>
        </div>
      </div>
    </div>
  );
}
