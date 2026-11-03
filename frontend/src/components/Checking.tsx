import { useEffect, useEffectEvent, useState } from "react";
import { useReducedMotion } from "motion/react";
import type { Noun } from "../lib/tabs";
import Light from "./Light";

const steps = (noun: Noun) => [`Reading the ${noun}`, "Checking links and payment IDs", "Looking for OTP requests and pressure tricks"];
const TICK_MS = 350;   // one step per tick (the prototype used 380 ms)

export type CheckOutcome = "pending" | "answered" | "failed";

type Props = { outcome: CheckOutcome; onFinished: () => void; noun?: Noun };

/* The checklist on the checking screen, inside the same glass box as the paste box. No spinner: as in the prototype, step i turns on
   after i ticks and is done 0.9 ticks later. The last step is also held until the API has answered, so the result shows only when both
   the answer is in and all three steps have ticked, and the list never looks finished while the checker is still working.
   Reduced motion: no ticking, the result shows as soon as the answer is in. On a failure the list stops where it is. */
export default function Checking({ outcome, onFinished, noun = "message" }: Props) {
  const STEPS = steps(noun);
  const tick = useReducedMotion() ? 0 : TICK_MS;
  const [events, setEvents] = useState(0);   // clock events so far: step i is on after event 2i+1 and done after event 2i+2
  const [startedAt] = useState(() => performance.now());
  const failed = outcome === "failed";
  const finish = useEffectEvent(onFinished);

  useEffect(() => {
    if (failed) return;
    const timers = [0, 0.9, 1, 1.9, 2, 2.9].map((at, i) => setTimeout(() => setEvents((n) => Math.max(n, i + 1)), at * tick));
    return () => timers.forEach(clearTimeout);
  }, [tick, failed]);

  const last = STEPS.length - 1;
  const isDone = (i: number) => events >= 2 * i + 2 && (i < last || outcome === "answered");
  const allDone = isDone(last);

  useEffect(() => {
    if (!allDone && !failed) return;
    // as the prototype: the result 120 ms after the last tick's slot; a failure waits at least one tick so the panel doesn't just flash
    const wait = allDone ? tick * 0.1 + 120 : Math.max(0, startedAt + tick - performance.now()) + 120;
    const t = setTimeout(() => finish(), wait);
    return () => clearTimeout(t);
  }, [allDone, failed, tick, startedAt]);

  return (
    <div className="box">
      <Light />
      <div className="steps" aria-live="polite">
        {STEPS.map((s, i) => {
          const done = isDone(i), on = !done && events >= 2 * i + 1;
          return <div key={s} className={done ? "step done" : on ? "step on" : "step"}><i>{done ? "✓" : ""}</i>{s}</div>;
        })}
      </div>
    </div>
  );
}
