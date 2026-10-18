import { useCallback, useEffect, useRef, useState } from "react";
import { useReducedMotion } from "motion/react";
import Globe, { type Hit } from "./components/Globe";
import Header from "./components/Header";
import PasteBox from "./components/PasteBox";
import Examples from "./components/Examples";
import Footer, { type FeedItem } from "./components/Footer";
import Checking, { type CheckOutcome } from "./components/Checking";
import Result from "./components/Result";
import ErrorPanel from "./components/ErrorPanel";
import { analyse, CheckError, type Failure } from "./api";
import { markLiveFailed, raisedByLive } from "./lib/facts";
import { useTheme } from "./lib/theme";
import type { Report } from "./types/report";

type Screen = "home" | "checking" | "result" | "error";

export default function App() {
  const [screen, setScreen] = useState<Screen>("home");
  const [text, setText] = useState("");
  const [checked, setChecked] = useState("");   // the text the current result is about: its evidence spans index this string
  const [report, setReport] = useState<Report | null>(null);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [raised, setRaised] = useState(false);                       // D23: the live link checks raised the verdict
  const [expanding, setExpanding] = useState<string | null>(null);   // the short link being revealed
  const [expandFailed, setExpandFailed] = useState<string | null>(null);
  const [hits, setHits] = useState<FeedItem[]>([]);
  const [focusBox, setFocusBox] = useState(false);   // focus the box when coming back to it, not on first load (as the prototype)
  const run = useRef(0), hitId = useRef(0);
  const input = useRef<HTMLTextAreaElement>(null);
  const reduced = useReducedMotion();
  const [theme, toggleTheme] = useTheme();

  const onHit = useCallback((h: Hit) => {
    const id = ++hitId.current;
    setHits((prev) => [{ ...h, id }, ...prev].slice(0, 4));
  }, []);

  // D23: the offline verdict comes first; if it has link checks pending, the same text is checked again with live: true (only domain names
  // leave the device) and the answer replaces it. Live checks can only raise a verdict, and then the verdict panel says so.
  function live(sent: string, id: number, offline: Report) {
    analyse(sent, { live: true }).then(
      (r) => { if (run.current === id) { setRaised(raisedByLive(offline, r)); setReport(r); } },
      () => { if (run.current === id) setReport(markLiveFailed(offline)); },   // pending rows become "Couldn't verify (offline)"
    );
  }
  function check() {
    if (!text.trim()) return;
    const id = ++run.current;   // only the latest check may change the screen
    const sent = text;
    setReport(null); setFailure(null); setRaised(false); setExpanding(null); setExpandFailed(null); setScreen("checking");
    analyse(sent).then(
      (r) => { if (run.current === id) { setChecked(sent); setReport(r); if (r.pending.length) live(sent, id, r); } },
      (e) => { if (run.current === id) setFailure(e instanceof CheckError ? e.failure : { kind: "unreachable" }); },
    );
  }
  function expand(url: string) {   // "Where does this short link go?": the shortener is asked, the destination never opened
    const id = run.current, before = report;
    setExpanding(url); setExpandFailed(null);
    analyse(checked, { live: true, expand: [url] }).then(
      (r) => { if (run.current === id) { if (before) setRaised((was) => was || raisedByLive(before, r)); setReport(r); setExpanding(null); } },
      () => { if (run.current === id) { setExpanding(null); setExpandFailed(url); } },
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
      <Globe dim={screen === "result"} onHit={onHit} theme={theme} />
      <Header theme={theme} onToggleTheme={toggleTheme} />
      <main>
        <div className={screen === "result" ? "col wide" : "col"}>
          {screen === "home" && (
            <>
              <section className="hero">
                <h1>Got a message that feels <em>off</em>?</h1>
                <p className="sub"><em>Paste it here.</em> We read it for the tricks scammers use and tell you why, in a few seconds.</p>
              </section>
              <PasteBox value={text} onChange={setText} onSubmit={check} inputRef={input} autoFocus={focusBox} />
              <Examples onPick={pick} />
            </>
          )}
          {screen === "checking" && <Checking outcome={outcome} onFinished={finishChecking} />}
          {screen === "result" && report && (
            <Result report={report} text={checked} onAgain={again} raised={raised} onExpand={expand} expanding={expanding} expandFailed={expandFailed} />
          )}
          {screen === "error" && failure && <ErrorPanel failure={failure} onRetry={check} onBack={back} />}
        </div>
      </main>
      {screen !== "result" && <Footer hits={hits} />}
    </>
  );
}
