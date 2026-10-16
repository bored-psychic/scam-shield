import { useCallback, useEffect, useRef, useState } from "react";
import { useReducedMotion } from "motion/react";
import Globe, { type Hit } from "./components/Globe";
import Header from "./components/Header";
import PasteBox from "./components/PasteBox";
import Examples from "./components/Examples";
import Footer, { type FeedItem } from "./components/Footer";
import Checking, { type CheckOutcome } from "./components/Checking";
import ResultPlaceholder from "./components/ResultPlaceholder";
import ErrorPanel from "./components/ErrorPanel";
import { analyse, CheckError, type Failure } from "./api";
import type { Report } from "./types/report";

type Screen = "home" | "checking" | "result" | "error";

export default function App() {
  const [screen, setScreen] = useState<Screen>("home");
  const [text, setText] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [hits, setHits] = useState<FeedItem[]>([]);
  const [focusBox, setFocusBox] = useState(false);   // focus the box when coming back to it, not on first load (as the prototype)
  const run = useRef(0), hitId = useRef(0);
  const input = useRef<HTMLTextAreaElement>(null);
  const reduced = useReducedMotion();

  const onHit = useCallback((h: Hit) => {
    const id = ++hitId.current;
    setHits((prev) => [{ ...h, id }, ...prev].slice(0, 4));
  }, []);

  function check() {
    if (!text.trim()) return;
    const id = ++run.current;   // only the latest check may change the screen
    setReport(null); setFailure(null); setScreen("checking");
    analyse(text).then(
      (r) => { if (run.current === id) setReport(r); },
      (e) => { if (run.current === id) setFailure(e instanceof CheckError ? e.failure : { kind: "unreachable" }); },
    );
  }
  const finishChecking = () => setScreen(report ? "result" : "error");   // called by Checking once the answer is in and the steps have ticked
  const again = () => { run.current++; setText(""); setReport(null); setFailure(null); setFocusBox(true); setScreen("home"); };
  const back = () => { setFocusBox(true); setScreen("home"); };
  const pick = (t: string) => { setText(t); input.current?.focus(); };

  useEffect(() => {
    if (screen === "result") window.scrollTo({ top: 0, behavior: reduced ? "auto" : "smooth" });
  }, [screen, reduced]);

  const outcome: CheckOutcome = failure ? "failed" : report ? "answered" : "pending";

  return (
    <>
      <Globe dim={screen === "result"} onHit={onHit} />
      <Header />
      <main>
        <div className="col">
          {screen === "home" && (
            <>
              <section className="hero">
                <h1>Got a message that feels <em>off</em>?</h1>
                <p className="sub">Paste it here. We read it for the tricks scammers use and tell you why, in a few seconds.</p>
              </section>
              <PasteBox value={text} onChange={setText} onSubmit={check} inputRef={input} autoFocus={focusBox} />
              <Examples onPick={pick} />
            </>
          )}
          {screen === "checking" && <Checking outcome={outcome} onFinished={finishChecking} />}
          {screen === "result" && report && <ResultPlaceholder report={report} onAgain={again} />}
          {screen === "error" && failure && <ErrorPanel failure={failure} onRetry={check} onBack={back} />}
        </div>
      </main>
      {screen !== "result" && <Footer hits={hits} />}
    </>
  );
}
