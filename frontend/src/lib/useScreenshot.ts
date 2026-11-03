import { useEffect, useRef, useState, type DragEvent, type RefObject } from "react";
import { ocr, OcrError } from "../api";
import { firstFile, OCR_MESSAGES, ocrNotice, pastedImage, validateImage } from "./screenshot";

/* Screenshot input (D19, part B), moved out of PasteBox so the Link tab's Screenshot mode reads the same way. Pick, drop or paste a screenshot
   -> checked here (type, size) -> thumbnail + "Reading" -> POST /api/ocr -> its text goes into the box for the user to check; the check itself only
   runs when they press Check. The image lives only in memory: the File, and an object URL for the thumbnail that is revoked when the screenshot is
   replaced, removed, or the box goes away. */
export type Shot =
  | { phase: "reading"; url: string }
  | { phase: "ask"; url: string; text: string; dropped: number }   // read, but the box holds the user's own text: replace it only if they say so
  | { phase: "read"; url: string; dropped: number }
  | { phase: "error"; url: string | null; message: string };      // url null: refused before upload, so there is no thumbnail

const hasFiles = (e: DragEvent) => e.dataTransfer.types.includes("Files");

type Options = {
  value: string;                                 // what is in the box
  onChange: (text: string) => void;
  focusBox: () => void;
  toTop: RefObject<boolean>;                     // set when text was just read: the box starts the user at its first line
  /** What to put in the box from the text read; null: nothing usable, and `noText` is shown instead. Default: all of it. */
  pick?: (text: string) => string | null;
  noText?: string;
};

export function useScreenshot({ value, onChange, focusBox, toTop, pick, noText = "" }: Options) {
  const [shot, setShot] = useState<Shot | null>(null);
  const [dragging, setDragging] = useState(false);
  const run = useRef(0), reading = useRef<AbortController | null>(null), drags = useRef(0);
  const own = useRef(value);   // the last text this box put in (typed or read); any other change came from outside (a sample chip)
  const url = shot?.url ?? null;

  useEffect(() => (url ? () => URL.revokeObjectURL(url) : undefined), [url]);
  useEffect(() => () => { run.current++; reading.current?.abort(); }, []);   // leaving the box cancels a read in flight

  useEffect(() => {   // a sample chip replaced the text: the screenshot and its notice no longer describe what is in the box
    if (value === own.current) return;
    own.current = value;
    stop();
    setShot(null);
  }, [value]);

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
    if (text === own.current) { focusBox(); return; }
    toTop.current = true;
    setBox(text);
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
        const got = pick ? pick(text) : text;
        if (got === null) { setShot({ phase: "error", url: src, message: noText }); return; }
        const now = own.current;   // what is in the box now: the user may have typed while the screenshot was read
        if (now.trim() && now !== got) { setShot({ phase: "ask", url: src, text: got, dropped }); return; }
        place(got);
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

  // spread on the box: an image-only paste and a dropped file are read, wherever in the box they land (data-drop: the page's guard leaves them alone)
  const boxProps = {
    "data-drop": true,
    onPaste: (e: React.ClipboardEvent) => {
      const image = pastedImage(e.clipboardData);
      if (image) { e.preventDefault(); addImage(image); }
    },
    onDragEnter: (e: DragEvent) => { if (!hasFiles(e)) return; e.preventDefault(); drags.current++; setDragging(true); },
    onDragOver: (e: DragEvent) => { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = "copy"; },
    onDragLeave: (e: DragEvent) => { if (!hasFiles(e)) return; if (--drags.current <= 0) { drags.current = 0; setDragging(false); } },
    onDrop: (e: DragEvent) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      drags.current = 0;
      setDragging(false);
      const file = firstFile(e.dataTransfer);
      if (file) addImage(file);
    },
  };

  return { shot, dragging, status, url, setBox, addImage, replace, remove, boxProps, busy: shot?.phase === "reading" || shot?.phase === "ask" };
}
