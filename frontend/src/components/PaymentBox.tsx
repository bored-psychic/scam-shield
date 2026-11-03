import { NOT_BUILT, PAYMENT_CARD, PROOF_EXPLANATION, type AddMode, type Inputs, type Started } from "../lib/tabs";
import Light from "./Light";
import Seg from "./Seg";

const MODES = [["type", "UPI ID or payment request"], ["shot", "Screenshot"]] as const;
const STARTED = [["yes", "Yes"], ["no", "No"], ["unsure", "Not sure"]] as const;
type Props = { inputs: Inputs; patch: (change: Partial<Inputs>) => void };

/* The Payment tab (plan 6.2, D29.15). The check is not built yet (W3 / W4): the button stays disabled and one plain line says so; nothing is sent. Screenshot mode asks
   for no file at all: a screenshot cannot prove a payment, so there is nothing to upload (the plan's fixed explanation). */
export default function PaymentBox({ inputs, patch }: Props) {
  const mode = inputs.payMode;
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
          <div className="acts"><button className="go" type="button" disabled aria-describedby="pay-notbuilt">{mode === "type" ? "Check payment" : "Show me what to do"}</button></div>
        </div>
      </div>
    </div>
  );
}
