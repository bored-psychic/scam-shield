import { NOT_BUILT, PAYMENT_CARD, PROOF_EXPLANATION, type AddMode, type Inputs, type Started } from "../lib/tabs";
import Light from "./Light";
import Seg from "./Seg";

const MODES = [["type", "UPI ID or payment request"], ["shot", "Screenshot"]] as const;
const STARTED = [["yes", "Yes"], ["no", "No"], ["unsure", "Not sure"]] as const;
type Props = { inputs: Inputs; patch: (change: Partial<Inputs>) => void; onSubmit: () => void };

/* The Payment tab (plan 6.2, D29.15). The button sends the input to /api/check; while the payments engine is not built (W3 / W4) the API answers "This check is not available yet."
   and the page says exactly that, never a verdict. Screenshot mode asks for no file at all: a screenshot cannot prove a payment, so there is nothing to upload (the plan's fixed
   explanation); its button sends only {kind: "payment_proof"}. */
export default function PaymentBox({ inputs, patch, onSubmit }: Props) {
  const mode = inputs.payMode, blank = mode === "type" && !inputs.upi.trim();
  return (
    <div className="paste">
      <div className="box entry" role="group" aria-label="Payment box">
        <Light />
        <div className="bar">
          <span className="lbl">Payment</span>
          <Seg<AddMode> label="How do you want to check it?" options={MODES} value={mode} onPick={(m) => patch({ payMode: m })} />
        </div>
        {mode === "type" ? (
          <>
            <textarea id="upi" className="field mono" rows={2} aria-label="UPI ID or payment request" autoCapitalize="off" spellCheck={false} placeholder="A UPI ID, a upi:// string or the request text"
              value={inputs.upi} onChange={(e) => patch({ upi: e.target.value })} />
            <div className="bar">
              <span className="lbl">Did you start this payment?</span>
              <Seg<Started> label="Did you start this payment?" options={STARTED} value={inputs.started} onPick={(v) => patch({ started: v })} />
            </div>
          </>
        ) : (
          <p className="explain">{PROOF_EXPLANATION}</p>
        )}
        <div className="boxfoot">
          <div className="found">
            <p className="hintc">{PAYMENT_CARD}</p>
            <p className="hintc notbuilt" id="pay-notbuilt">{NOT_BUILT.payment}</p>
          </div>
          <div className="acts"><button className="go" type="button" disabled={blank} onClick={onSubmit} aria-describedby="pay-notbuilt">{mode === "type" ? "Check payment" : "Show me what to do"}</button></div>
        </div>
      </div>
    </div>
  );
}
