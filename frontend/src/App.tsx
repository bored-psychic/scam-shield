import { useCallback, useEffect, useRef, useState } from "react";
import { useReducedMotion } from "motion/react";
import Globe, { type Hit } from "./components/Globe";
import Header from "./components/Header";
import Home from "./components/Home";
import Footer, { type FeedItem } from "./components/Footer";
import Checking, { type CheckOutcome } from "./components/Checking";
import Result from "./components/Result";
import ErrorPanel from "./components/ErrorPanel";
import { analyse, CheckError, type Failure } from "./api";
import { markLiveFailed, raisedByLive } from "./lib/facts";
import { clearChecked, NO_INPUTS, textToCheck, type Inputs, type Sample, type TabKey } from "./lib/tabs";
import { useTheme } from "./lib/theme";
import type { Report } from "./types/report";

type Screen = "home" | "checking" | "result" | "error";

export default function App() {
  const [screen, setScreen] = useState<Screen>("home");
  const [tab, setTab] = useState<TabKey>("message");   // not stored (ARCHITECTURE 5.4); SMS / Email is the default
  const [inputs, setInputs] = useState<Inputs>(NO_INPUTS);
  const [checked, setChecked] = useState("");   // the text the current result is about: its evidence spans index this string
  const [report, setReport] = useState<Report | null>(null);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [raised, setRaised] = useState(false);                       // D23: the live link checks raised the verdict
  const [expanding, setExpanding] = useState<string | null>(null);   // the short link being revealed
  const [expandFailed, setExpandFailed] = useState<string | null>(null);
  const [hits, setHits] = useState<FeedItem[]>([]);
  const [focusBox, setFocusBox] = useState(false);   // focus the box when coming back to it, not on first load (as the prototype)
  const run = useRef(0), hitId = useRef(0);
  const messageInput = useRef<HTMLTextAreaElement>(null), linkInput = useRef<HTMLInputElement>(null);
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
  const patch = useCallback((change: Partial<Inputs>) => setInputs((i) => ({ ...i, ...change })), []);
  function check() {
    const sent = textToCheck(tab, inputs);
    if (!sent.trim()) return;
    const id = ++run.current;   // only the latest check may change the screen
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
  const again = () => { run.current++; setInputs((i) => clearChecked(tab, i)); setReport(null); setFailure(null); setFocusBox(true); setScreen("home"); };
  const back = () => { setFocusBox(true); setScreen("home"); };
  const pick = (s: Sample) => {   // a sample chip fills in its tab; the user still presses Check
    setTab(s.tab);
    patch(s.set);
    if (s.tab === "message" && s.set.kind !== "email") messageInput.current?.focus();
  };

  useEffect(() => {
    if (screen === "result") window.scrollTo({ top: 0, behavior: reduced ? "auto" : "smooth" });
  }, [screen, reduced]);

  const outcome: CheckOutcome = failure ? "failed" : report ? "answered" : "pending";

  return (
    <>
      <Globe dim={screen === "result"} onHit={onHit} theme={theme} />
      <Header theme={theme} onToggleTheme={toggleTheme} />
      <main>
        <div className={screen === "result" ? "col wide" : screen === "home" ? "col home" : "col"}>
          {screen === "home" && (
            <Home tab={tab} onTab={setTab} inputs={inputs} patch={patch} onCheck={check} onSample={pick} messageRef={messageInput} linkRef={linkInput} autoFocus={focusBox} />
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
