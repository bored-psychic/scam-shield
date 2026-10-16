// The three example chips. A chip only fills the box with the prototype's example text: its verdict comes from the API like any other
// message (the prototype's hand-written verdicts, levels and reasons are deliberately not ported).
const EXAMPLES = [
  { id: "arrest", label: "Digital arrest call",
    text: "This is Inspector Rakesh Sharma from Mumbai Cyber Crime. A parcel in your name with illegal items was seized by customs. You are now under digital arrest. Do not disconnect this call or tell anyone. Transfer ₹49,999 to the verification account immediately to clear your name: cbi-verify-case.xyz" },
  { id: "kyc", label: "KYC update SMS",
    text: "Dear Customer, your SBI account will be blocked today due to pending KYC. Update now: sbi-kyc-update.top/login Share the OTP sent to your number to complete verification." },
  { id: "bank", label: "Genuine bank alert",
    text: "Rs.2,500.00 debited from A/c XX4821 on 14-10-26 to VPA swiggy@ybl. Not you? Call 1800-XXX-XXXX. Never share your OTP with anyone. -HDFC Bank" },
];

export default function Examples({ onPick }: { onPick: (text: string) => void }) {
  return (
    <section className="hero">
      <div className="ex"><span>try</span>
        {EXAMPLES.map((ex) => <button key={ex.id} type="button" onClick={() => onPick(ex.text)}>{ex.label}</button>)}
      </div>
    </section>
  );
}
