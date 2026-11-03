import type { useScreenshot } from "../lib/useScreenshot";

/* The pieces of a screenshot input shared by the SMS / Email and Link tabs. ShotCard: the card above the box (thumbnail, what is happening, its controls); its
   status line is always in the page, so screen readers hear every change of it. DropArea: the Screenshot mode's big target (the file picker; a file may also be dropped on the box). */
export function ShotCard({ s }: { s: ReturnType<typeof useScreenshot> }) {
  const { shot, url, status, replace, remove } = s;
  return (
    <div className={shot ? `shot on ${shot.phase}` : "shot"}>
      {url && <span className={shot?.phase === "reading" ? "thumb scan" : "thumb"}><img src={url} alt="Your screenshot" draggable={false} /></span>}
      <div className="sline">
        {status && <i className={status.icon} aria-hidden="true">{status.mark}</i>}
        <p className="shotmsg" role="status">{status?.text}</p>
      </div>
      {shot && (
        <div className="sacts">
          {shot.phase === "ask" ? (
            <>
              <button type="button" className="ghost" onClick={replace}>Replace</button>
              <button type="button" className="ghost" onClick={remove}>Keep my text</button>
            </>
          ) : url ? (
            <button type="button" className="ghost" onClick={remove}>Remove screenshot</button>
          ) : (
            <button type="button" className="ghost" onClick={remove}>Dismiss</button>
          )}
        </div>
      )}
    </div>
  );
}

export function DropArea({ title, small, onClick, icon = "up" }: { title: string; small: string; onClick: () => void; icon?: "up" | "phone" }) {
  return (
    <button type="button" className="dropbtn" onClick={onClick}>
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        {icon === "up" ? <path d="M12 16V4M7 9l5-5 5 5M5 20h14" /> : <><rect x="7" y="3" width="10" height="18" rx="2" /><path d="M11 17h2" /></>}
      </svg>
      <span><b>{title}</b>{small}</span>
    </button>
  );
}
