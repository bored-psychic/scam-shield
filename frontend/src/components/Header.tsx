// Logo and the "Checked on this device" pill, as in the prototype.
export default function Header() {
  return (
    <header>
      <div className="mark">
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 2.5 4 5.6v6.1c0 4.7 3.3 8.6 8 9.8 4.7-1.2 8-5.1 8-9.8V5.6L12 2.5Z" stroke="#EDF1F7" strokeWidth="1.6" />
          <path d="m8.5 12.2 2.4 2.4 4.6-5" stroke="#FF4D4D" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        Scam Shield
      </div>
      <div className="local" title="Messages are checked on this device. Nothing you paste is stored or sent."><i></i><span>Checked on this device</span></div>
    </header>
  );
}
