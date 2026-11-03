import { useEffect, type RefObject } from "react";
import { TABS, type Inputs, type Sample, type TabKey } from "../lib/tabs";
import AppBox from "./AppBox";
import Examples from "./Examples";
import Hero from "./Hero";
import LinkBox from "./LinkBox";
import PasteBox from "./PasteBox";
import PaymentBox from "./PaymentBox";
import TabRow from "./TabRow";

type Props = {
  tab: TabKey;
  onTab: (k: TabKey) => void;
  inputs: Inputs;
  patch: (change: Partial<Inputs>) => void;
  onCheck: () => void;
  onSample: (s: Sample) => void;
  messageRef: RefObject<HTMLTextAreaElement | null>;
  linkRef: RefObject<HTMLInputElement | null>;
  autoFocus: boolean;
};

/* The home screen (docs/design/tabs-home.html, plan 6, D29.15): headline, four tabs, the selected tab's box, sample chips. Every tab has its tabpanel in the page, so aria-controls
   always points at something; only the selected one has its content. What was typed stays in App, so nothing is lost on the way to another tab or to the result. */
export default function Home({ tab, onTab, inputs, patch, onCheck, onSample, messageRef, linkRef, autoFocus }: Props) {
  useEffect(() => {   // a file dropped next to a box would otherwise make the browser open it in place of this page
    const guard = (e: DragEvent) => {
      if (!e.dataTransfer?.types.includes("Files") || (e.target instanceof Element && e.target.closest("[data-drop]"))) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "none";
    };
    window.addEventListener("dragover", guard);
    window.addEventListener("drop", guard);
    return () => { window.removeEventListener("dragover", guard); window.removeEventListener("drop", guard); };
  }, []);

  const box = (k: TabKey) => {
    if (k === "message") return <PasteBox inputs={inputs} patch={patch} onSubmit={onCheck} inputRef={messageRef} autoFocus={autoFocus} />;
    if (k === "link") return <LinkBox inputs={inputs} patch={patch} onSubmit={onCheck} inputRef={linkRef} autoFocus={autoFocus} />;
    if (k === "payment") return <PaymentBox inputs={inputs} patch={patch} />;
    return <AppBox inputs={inputs} patch={patch} />;
  };

  return (
    <>
      <Hero tab={tab} />
      <TabRow tab={tab} onSelect={onTab} />
      {TABS.map((k) => (
        <div key={k} role="tabpanel" id={`panel-${k}`} aria-labelledby={`tab-${k}`} hidden={k !== tab}>{k === tab && box(k)}</div>
      ))}
      <Examples onPick={onSample} />
    </>
  );
}
