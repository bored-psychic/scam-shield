import { SAMPLES, type Sample } from "../lib/tabs";

// The sample chips of docs/design/tabs-home.html. A chip only fills in its tab (lib/tabs.ts): its verdict comes from the API like any other message's, when the user presses Check.
export default function Examples({ onPick }: { onPick: (s: Sample) => void }) {
  return (
    <section className="hero">
      <div className="ex"><span>Try a sample:</span>
        {SAMPLES.map((s) => <button key={s.id} type="button" onClick={() => onPick(s)}>{s.label}</button>)}
      </div>
    </section>
  );
}
