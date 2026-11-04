import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import gsap from "gsap";
import { SplitText } from "gsap/SplitText";
import Globe, { type Hit } from "./components/Globe";
import Header from "./components/Header";
import Footer, { type FeedItem } from "./components/Footer";

gsap.registerPlugin(SplitText);
const EASE = "power4.out";
type K = "msg" | "link" | "pay" | "app";
const KEYS: K[] = ["msg", "link", "pay", "app"];
const TAB_NAME: Record<K, string> = { msg: "SMS / Email", link: "Link", pay: "Payment / UPI", app: "App / APK" };
const HERO: Record<K, [string, string, string]> = {
  msg: ["Is this message a ", "scam", "Paste it or add a screenshot."],
  link: ["Is this link ", "safe", "Checked without opening it."],
  pay: ["Is this payment ", "genuine", "Check a UPI ID or a screenshot."],
  app: ["Is this app ", "real", "Check it before you install."],
};
const ICON: Record<K, string> = {
  msg: '<path d="M4 5h16v11H9l-5 4z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>',
  link: '<path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
  pay: '<rect x="3" y="6" width="18" height="12" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M3 10h18M7 15h3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
  app: '<rect x="7" y="3" width="10" height="18" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M11 17h2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
};
const svg = (k: K, s = 16) => `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" aria-hidden="true">${ICON[k]}</svg>`;
const MODES: Record<K, [string, string][]> = {
  msg: [["type", "Paste text"], ["shot", "Screenshot"]],
  link: [["type", "Paste link"], ["shot", "Screenshot"]],
  pay: [["type", "UPI ID"], ["shot", "Screenshot"]],
  app: [["type", "Name"], ["apk", "APK file"], ["shot", "Screenshot"]],
};

/* ---------- sample results (design samples, not real checks) ---------- */
const COL: Record<string, string> = { L: "#FF3B3B", S: "#F5B544", N: "#3DD68C" };
const TINT: Record<string, string> = { L: "255,59,59", S: "245,181,68", N: "61,214,140" };
const NAME: Record<string, string> = { L: "Likely scam", S: "Suspicious", N: "No warning signs found" };
const VICON: Record<string, string> = {
  L: '<path d="M7 7l10 10M17 7L7 17" stroke="#04060A" stroke-width="2.6" stroke-linecap="round"/>',
  S: '<path d="M12 6v8" stroke="#04060A" stroke-width="2.6" stroke-linecap="round"/><circle cx="12" cy="18" r="1.6" fill="#04060A"/>',
};
const MK: Record<string, [string, string]> = { x: ["✕", "#FF3B3B"], "!": ["!", "#F5B544"], "?": ["?", "#9AA5B8"], o: ["○", "#9AA5B8"], v: ["✓", "#3DD68C"] };
const R: Record<K, any> = {
  msg: { lvl: "L", score: 90, sub: "This message imitates SBI to collect your banking details.",
    chips: [["L", "Fake bank link"], ["L", "New website"], ["S", "Pressure"]],
    why: [["L", "The link imitates SBI but is not an official SBI website."], ["L", "The website was registered recently (sample: 4 days ago)."], ["S", "It says your account will be blocked today, to rush you."]],
    inH: "Your message", inBody: '<p class="d-intext">Dear Customer, your SBI account <u style="border-color:#F5B544">will be blocked today</u>. Update your PAN and KYC immediately: <u style="border-color:#FF3B3B">hxxps://sbi-kyc-update[.]top/verify</u></p>',
    detH: "Website details", det: [["Name", "x", "sbi-kyc-update.top"], ["Ending", "!", ".top", "Cheap endings are common on short-lived scam sites."], ["Registered", "x", "4 days ago (sample)"], ["Phishing lists", "?", "Not listed yet"]],
    detFoot: "The link was not opened. Only public records about the website name were looked up.",
    tipH: "Before you open a link", tipP: "Type the bank's address yourself, or use its official app.",
    todo: ["Do not open the link or reply.", "Never share an OTP, UPI PIN or card number.", "If you entered details, call your bank, then 1930."] },
  link: { lvl: "L", score: 90, sub: "This website imitates SBI. Do not enter any details on it.",
    chips: [["L", "Look-alike name"], ["L", "New website"]],
    why: [["L", 'The name contains "sbi" but it is not an official SBI website.'], ["L", "The website was registered recently (sample: 4 days ago)."]],
    inH: "The link · not opened", inBody: '<p class="d-inbig"><u>sbi-kyc-update</u>.top<span class="d-dim">/login</span></p>',
    detH: "Website details", det: [["Name", "x", "sbi-kyc-update.top"], ["Ending", "!", ".top", "Cheap endings are common on short-lived scam sites."], ["Registered", "x", "4 days ago (sample)"], ["Popularity", "o", "Not among the top 1 million sites"], ["Phishing lists", "?", "Not listed yet"]],
    detFoot: "The link was not opened. Only public records about the website name were looked up.",
    tipH: "Before you open a link", tipP: "Type the bank's address yourself, or use its official app.",
    todo: ["Do not open this link.", "Use the bank's official app or website instead.", "If you entered details, call your bank, then 1930."] },
  pay: { lvl: "S", score: 30, sub: "This UPI ID uses words scammers use to pose as a refund desk.", note: "No wording to score for a UPI ID: the meter shows the start of its band.",
    chips: [["S", "Refund word in ID"], ["S", "Not started by you"]],
    why: [["S", 'The ID contains the word "refund". Refunds never need you to pay or approve anything.'], ["S", "You did not start this payment. Requests you did not expect are the usual way these scams begin."]],
    inH: "The UPI ID", inBody: '<p class="d-inbig">refund.desk<span style="color:#F5B544">@ybl</span></p><dl class="d-kv"><dt>You said</dt><dd>You did not start this payment</dd></dl>',
    detH: "Payment details", det: [["Handle", "v", "@ybl", "On the official handle list (sample)."], ["Registered name", "?", "Shown only in your payment app", "Check it there before you pay."], ["Reports", "?", "Not checked", "Search the ID yourself: cybercrime.gov.in, Report & Check Suspect."]],
    detFoot: "Nothing about this ID was looked up online.",
    tipH: "Before you pay", tipP: "Check the registered name your payment app shows. Receiving money never needs your UPI PIN.",
    todo: ["Do not pay or approve anything to this ID.", "Never enter your UPI PIN to receive money.", "If you already paid, call your bank, then 1930."] },
  app: { lvl: "L", score: 96, sub: "This file claims to be an SBI app, arrived on WhatsApp, and can read your SMS messages.",
    chips: [["L", "Sent as a file"], ["L", "Reads your SMS"], ["S", "Screen control"]],
    why: [["L", "It arrived as a KYC update on WhatsApp. Banks never send app files."], ["L", "It claims to be SBI and can read SMS, where your OTPs arrive."], ["S", "It asks to control the screen (accessibility access)."]],
    inH: "The app file", inBody: '<p class="d-inbig">SBI KYC Update.apk</p><dl class="d-kv"><dt>Package</dt><dd class="d-mono">com.sbi.kyc.update2</dd><dt>Size</dt><dd>4.2 MB</dd></dl>',
    detH: "App details", det: [["Official SBI app", "x", "No (sample)", "The signature does not match the bank's app."], ["Permissions", "x", "Read SMS, accessibility", "Together these can read OTPs and press buttons for you."], ["How you got it", "x", "Sent on WhatsApp"], ["Installed or run", "v", "No"]],
    detFoot: "The file was read on this device. It was not installed or run, and it is gone.",
    tipH: "Before you install", tipP: "Install banking apps only from the Play Store, from the bank's own listing.",
    todo: ["Do not install the file. Delete it.", "If you installed it, turn on flight mode and call your bank.", "Report it at cybercrime.gov.in or call 1930."] },
};

function radar(r: any) {
  const C = 115, POS = [[-58, -52], [48, -34], [-52, 46], [44, 62]];
  let s = `<svg viewBox="0 0 230 230" aria-hidden="true"><defs><radialGradient id="sw" cx="115" cy="115" r="105" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="${COL[r.lvl]}" stop-opacity=".04"/><stop offset="1" stop-color="${COL[r.lvl]}" stop-opacity=".45"/></radialGradient></defs>`;
  [105, 70, 35].forEach((rr) => { s += `<circle cx="115" cy="115" r="${rr}" fill="none" stroke="rgba(255,255,255,.13)"/>`; });
  s += '<path d="M115 8v214M8 115h214" stroke="rgba(255,255,255,.08)"/><path d="M115 115 L220 115 A105 105 0 0 1 115 220 Z" fill="url(#sw)"/>';
  r.chips.forEach((c: any, i: number) => { const q = POS[i]; s += `<circle cx="${C + q[0]}" cy="${C + q[1]}" r="${c[0] === "L" ? 7 : 6}" fill="${COL[c[0]]}"/>`; });
  s += '<circle cx="115" cy="115" r="4.5" fill="#EDF1F7"/></svg>';
  r.chips.forEach((c: any, i: number) => {
    const q = POS[i], side = q[0] < 0 ? `right:${230 - (C + q[0]) + 14}px` : `left:${C + q[0] + 14}px`;
    s += `<span class="d-rtag" style="top:${C + q[1]}px;${side};color:${COL[c[0]]};border-color:${COL[c[0]]}88">${c[1]}</span>`;
  });
  return s;
}
function resultHTML(k: K) {
  const r = R[k], c = COL[r.lvl];
  const tabs = KEYS.map((t) => `<button type="button" class="d-rtab d-glass d-lift" data-k="${t}" aria-pressed="${t === k}">${svg(t, 14)}${TAB_NAME[t]}</button>`).join("");
  return `<div class="d-rbar"><button type="button" class="d-back d-glass d-lift">← Check something else</button><div class="d-rtabs">${tabs}</div><span class="d-stored">Checked on this device · nothing was stored</span></div>
  <div class="d-grid"><div class="d-col">
    <section class="d-card d-glass d-verdict" style="--tint:${TINT[r.lvl]}"><div class="d-vhead"><div class="d-vicon" style="background:${c}"><svg width="22" height="22" viewBox="0 0 24 24" fill="none">${VICON[r.lvl]}</svg></div><div><h2 style="color:${c}">${NAME[r.lvl]}</h2><p class="d-vsub">${r.sub}</p></div></div>
      <div><div class="d-score"><span class="d-lab">Risk score</span><span><span class="d-num" style="color:${c}">${r.score}</span> <span class="d-of">/ 100</span></span></div>
      <div class="d-meter"><span class="d-tick" style="left:30%"></span><span class="d-tick" style="left:70%"></span><span class="d-knob" style="left:${r.score}%;border-color:${c}"></span></div>
      <div class="d-scale"><span>0 · No warning signs</span><span>30 · Suspicious</span><span>70 · Likely</span></div></div>
      <p class="d-note">${r.note || "Higher = more warning signs. Not a percentage chance."}</p>
      <div class="d-radar">${radar(r)}</div><p class="d-rcap">${r.chips.length} warning signs found</p></section>
    <section class="d-card d-glass"><h3>Why</h3><ul class="d-why">${r.why.map((w: any) => `<li><span class="d-dot" style="background:${COL[w[0]]}"></span><span>${w[1]}</span></li>`).join("")}</ul></section>
  </div><div class="d-col">
    <section class="d-card d-glass"><h3>${r.inH}</h3>${r.inBody}</section>
    <section class="d-card d-glass"><h3>${r.detH}</h3><dl class="d-rows">${r.det.map((d: any) => `<div><dt>${d[0]}</dt><dd><span class="d-mk" style="color:${MK[d[1]][1]}">${MK[d[1]][0]}</span>${d[2]}${d[3] ? `<small>${d[3]}</small>` : ""}</dd></div>`).join("")}</dl><p class="d-dfoot">${r.detFoot}</p></section>
    <section class="d-card d-glass"><h3>What to do now</h3><div class="d-tip"><b>${r.tipH}</b><p>${r.tipP}</p></div><ol class="d-todo">${r.todo.map((t: string) => `<li>${t}</li>`).join("")}</ol>
      <div class="d-help"><a class="d-call d-lift" href="tel:1930">Call 1930</a><a class="d-glass d-ghost d-lift" href="https://cybercrime.gov.in" rel="noopener">cybercrime.gov.in ↗</a><div class="d-lang"><button type="button" class="d-lift" aria-pressed="true">EN</button><button type="button" class="d-lift" aria-pressed="false">हिंदी</button><button type="button" class="d-lift" aria-pressed="false">ಕನ್ನಡ</button></div></div></section>
  </div></div>`;
}

const DROP = (title: string, small: string) => (
  <label className="d-drop d-lift"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 16V4M7 9l5-5 5 5M5 20h14" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg><span><b>{title}</b>{small}</span></label>
);

function Seg({ name, opts, value, onPick }: { name: string; opts: [string, string][]; value: string; onPick: (v: string) => void }) {
  const ref = useRef<HTMLDivElement>(null), first = useRef(true);
  useLayoutEffect(() => {
    const el = ref.current!, on = el.querySelector<HTMLElement>('[aria-pressed="true"]')!, th = el.querySelector<HTMLElement>(".d-sthumb")!;
    gsap.to(th, { x: on.offsetLeft - 3, width: on.offsetWidth, duration: first.current ? 0 : 0.42, ease: EASE });
    first.current = false;
  }, [value]);
  return (
    <div className="d-seg" ref={ref} role="group" aria-label={name}>
      <span className="d-sthumb" aria-hidden="true" />
      {opts.map(([v, l]) => <button key={v} type="button" className="d-lift" aria-pressed={v === value} onClick={() => onPick(v)}>{l}</button>)}
    </div>
  );
}

export default function Demo() {
  const [screen, setScreen] = useState<"home" | "result">("home");
  const [tab, setTab] = useState<K>("msg");
  const [mode, setMode] = useState<Record<K, string>>({ msg: "type", link: "type", pay: "type", app: "type" });
  const [kind, setKind] = useState("sms");
  const [started, setStarted] = useState("no");
  const [hits, setHits] = useState<FeedItem[]>([]);
  const hitId = useRef(0);
  const onHit = useCallback((h: Hit) => setHits((l) => [{ ...h, id: ++hitId.current }, ...l].slice(0, 4)), []);
  const h1 = useRef<HTMLHeadingElement>(null), sub = useRef<HTMLParagraphElement>(null), panel = useRef<HTMLFormElement>(null);
  const tabsRef = useRef<HTMLDivElement>(null), thumb = useRef<HTMLSpanElement>(null), resRef = useRef<HTMLDivElement>(null);
  const prevH = useRef<number | null>(null), dir = useRef(0);

  // ---- GSAP 1: the globe rises on load ----
  useEffect(() => {
    const stage = document.querySelector<HTMLElement>(".stage");
    if (!stage || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    stage.style.transition = "none";
    gsap.fromTo(stage, { yPercent: 45, opacity: 0 }, { yPercent: 0, opacity: 1, duration: 2.2, ease: "expo.out", delay: 0.15, clearProps: "transform,opacity,transition" });
  }, []);

  // headline: written once, then rolled by GSAP on each tab switch
  const heroHTML = (k: K) => `<span class="d-hline"><span class="d-hin">${HERO[k][0]}<em class="d-acc">${HERO[k][1]}</em>?</span></span>`;
  useLayoutEffect(() => { if (h1.current && !h1.current.innerHTML) h1.current.innerHTML = heroHTML(tab); }, []);

  const placeThumb = (k: K, dur: number) => {
    const btn = tabsRef.current?.querySelector<HTMLElement>(`[data-k="${k}"]`); if (!btn || !thumb.current) return;
    gsap.to(thumb.current, { x: btn.offsetLeft, width: btn.offsetWidth, duration: dur, ease: EASE });
  };
  useLayoutEffect(() => { if (screen === "home") placeThumb(tab, 0); }, [screen]);
  useEffect(() => { document.fonts?.ready.then(() => placeThumb(tab, 0)); }, []);

  // ---- GSAP 2: the tab switch (pill slides, headline rolls word by word, box eases to its new height) ----
  const selectTab = (k: K) => {
    if (k === tab) return;
    dir.current = KEYS.indexOf(k) > KEYS.indexOf(tab) ? 1 : -1;
    prevH.current = panel.current!.offsetHeight;
    placeThumb(k, 0.55);
    const el = h1.current!, old = el.querySelector<HTMLElement>(".d-hline")!, wrap = document.createElement("span");
    wrap.innerHTML = heroHTML(k); const next = wrap.firstElementChild as HTMLElement;
    gsap.set(old, { position: "absolute", left: 0, right: 0, top: 0 }); el.appendChild(next);
    const split = SplitText.create(next.firstElementChild as HTMLElement, { type: "words", mask: "words" });
    gsap.timeline({ onComplete: () => { old.remove(); split.revert(); } })
      .to(old.firstElementChild, { yPercent: -110, opacity: 0, duration: 0.38, ease: "power3.in" }, 0)
      .from(split.words, { yPercent: 110, duration: 0.7, stagger: 0.05, ease: EASE }, 0.12);
    const s = sub.current!;
    gsap.timeline().to(s, { opacity: 0, y: -6, duration: 0.18 }).add(() => { s.textContent = HERO[k][2]; }).to(s, { opacity: 1, y: 0, duration: 0.38, ease: EASE });
    setTab(k);
  };
  const pickMode = (v: string) => { prevH.current = panel.current!.offsetHeight; dir.current = 0; setMode((m) => ({ ...m, [tab]: v })); };
  const pickKind = (v: string) => { prevH.current = panel.current!.offsetHeight; dir.current = 0; setKind(v); };
  useLayoutEffect(() => {
    const p = panel.current; if (!p || prevH.current == null) return;
    const h0 = prevH.current, h1v = p.offsetHeight; prevH.current = null;
    gsap.fromTo(p, { height: h0 }, { height: h1v, duration: 0.45, ease: EASE, clearProps: "height" });
    gsap.from(p.querySelectorAll(".d-swap"), { opacity: 0, x: dir.current * 22, y: dir.current ? 0 : 8, duration: 0.4, stagger: 0.04, ease: EASE });
  }, [tab, mode, kind]);

  // ---- the light plays across the glass as the pointer moves: CSS variables, a very short smoothing so it keeps up ----
  useEffect(() => {
    const qs = new WeakMap<Element, any>();
    const onMove = (e: PointerEvent) => {
      document.querySelectorAll<HTMLElement>(".d-glass").forEach((el) => {
        const r = el.getBoundingClientRect();
        let q = qs.get(el);
        if (!q) { q = { x: gsap.quickTo(el, "--mx", { duration: 0.12, ease: "power2" }), y: gsap.quickTo(el, "--my", { duration: 0.12, ease: "power2" }), a: gsap.quickTo(el, "--ang", { duration: 0.18, ease: "power2" }), last: null }; qs.set(el, q); }
        const x = e.clientX - r.left, y = e.clientY - r.top;
        // angle to the pointer, unwrapped so the edge highlight turns the short way round
        let ang = (Math.atan2(y - r.height / 2, x - r.width / 2) * 180) / Math.PI + 90;
        if (q.last !== null) { while (ang - q.last > 180) ang -= 360; while (ang - q.last < -180) ang += 360; }
        q.last = ang; q.x(x); q.y(y); q.a(ang);
      });
    };
    addEventListener("pointermove", onMove);
    return () => removeEventListener("pointermove", onMove);
  }, []);

  // result page: plain swap (no transition), globe dims as in the app
  useEffect(() => {
    const el = resRef.current; if (!el) return;
    const onClick = (e: MouseEvent) => {
      const t = e.target as HTMLElement, rt = t.closest<HTMLElement>(".d-rtab"), back = t.closest(".d-back"), lg = t.closest<HTMLElement>(".d-lang button");
      if (lg) { lg.parentElement!.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b === lg))); return; }
      if (rt) { setTab(rt.dataset.k as K); h1.current && (h1.current.innerHTML = ""); setScreen("home"); }
      else if (back) { h1.current && (h1.current.innerHTML = ""); setScreen("home"); }
    };
    el.addEventListener("click", onClick); return () => el.removeEventListener("click", onClick);
  }, [screen]);
  useLayoutEffect(() => { if (screen === "home" && h1.current && !h1.current.innerHTML) { h1.current.innerHTML = heroHTML(tab); if (sub.current) sub.current.textContent = HERO[tab][2]; } }, [screen]);
  const check = (e?: React.FormEvent) => { e?.preventDefault(); setScreen("result"); scrollTo(0, 0); };

  const m = mode[tab], em = kind === "email";
  const body = (() => {
    if (tab === "msg") return m === "shot" ? DROP(em ? "Choose a screenshot of the email" : "Choose a screenshot of the message", em ? "or drop it here · show the sender's full address first" : "or drop it here")
      : em ? <>
          <input id="em-subj" className="d-field d-swap" aria-label="Subject" defaultValue="Action required: your account will be suspended" />
          <textarea id="em-body" className="d-field d-swap" rows={3} aria-label="Email text" defaultValue="Dear customer, your account has been temporarily restricted. Download the attached form to complete verification within 24 hours." />
          <details className="d-more d-swap"><summary>Sender, reply-to, attachments and headers <span>(optional, makes the check stronger)</span></summary></details>
        </> : <textarea id="msg" className="d-field" rows={3} aria-label="The message" defaultValue="Dear Customer, your SBI account will be blocked today. Update your PAN and KYC immediately: hxxps://sbi-kyc-update[.]top/verify" />;
    if (tab === "link") return m === "shot" ? DROP("Choose a screenshot that shows the link", "or drop it here") : <input id="url" className="d-field d-mono" aria-label="The link" defaultValue="https://sbi-kyc-update.top/login" />;
    if (tab === "pay") return m === "shot" ? DROP("Choose a screenshot of the request, QR code or receipt", "or drop it here · we work out which it is") : <input id="upi" className="d-field d-mono" aria-label="UPI ID or payment request" defaultValue="refund.desk@ybl" />;
    return m === "apk" ? DROP("Choose the APK file", "read only, never installed · up to 50 MB") : m === "shot" ? DROP("Choose a screenshot of the app's page", "or the message that sent it") : <input id="app" className="d-field d-mono" aria-label="App name" defaultValue="SBI KYC Update" />;
  })();
  const hint = { msg: "Read on this device. Nothing is stored.", link: "Never opened. Only the website's name is looked up.", pay: "Receiving money never needs your UPI PIN.", app: "Files are read on this device and deleted after the check." }[tab];
  const go = { msg: em ? "Check email" : "Check message", link: "Check link", pay: "Check payment", app: "Check app" }[tab];

  return (
    <>
      <Globe dim={screen === "result"} onHit={onHit} theme="dark" />
      <Header theme="dark" onToggleTheme={() => {}} />
      <main>
        {screen === "home" ? (
          <div className="d-home">
            <div className="d-hero"><h1 ref={h1} className="d-h1" /><p ref={sub} className="d-sub">{HERO[tab][2]}</p></div>
            <div className="d-tabs" ref={tabsRef} role="tablist" aria-label="What do you want to check?">
              <span className="d-thumb" ref={thumb} aria-hidden="true" />
              {KEYS.map((k) => <button key={k} type="button" role="tab" data-k={k} aria-selected={k === tab} className="d-tab d-glass d-lift" onClick={() => selectTab(k)} dangerouslySetInnerHTML={{ __html: svg(k) + TAB_NAME[k] }} />)}
            </div>
            <form className="d-panel d-glass" ref={panel} onSubmit={check}>
              <div className="d-bar d-swap">
                {tab === "msg" ? <Seg name="What is it?" opts={[["sms", "SMS or chat"], ["email", "Email"]]} value={kind} onPick={pickKind} /> : <span className="d-lbl">{{ link: "The link", pay: "Payment", app: "The app" }[tab]}</span>}
                <Seg key={tab} name="How do you want to add it?" opts={MODES[tab]} value={m} onPick={pickMode} />
              </div>
              <div className="d-swap d-body">{body}</div>
              {tab === "pay" && <div className="d-bar d-swap"><span className="d-lbl">Did you start this payment?</span><Seg name="Did you start this payment?" opts={[["no", "No"], ["yes", "Yes"], ["ns", "Not sure"]]} value={started} onPick={setStarted} /></div>}
              {tab === "app" && <select id="how" className="d-field d-swap" aria-label="How did you get this app?"><option>How did you get it? Sent on WhatsApp or SMS</option><option>From the Google Play Store</option><option>From a website</option><option>Someone on a call asked me to install it</option></select>}
              <div className="d-actions d-swap"><span className="d-hint">{hint}</span><button type="submit" className="d-go d-lift">{go}</button></div>
            </form>
            <div className="d-try"><span>Try a sample:</span>
              {KEYS.map((k) => <button key={k} type="button" className="d-glass d-lift" onClick={() => { setTab(k); h1.current && (h1.current.innerHTML = heroHTML(k)); if (sub.current) sub.current.textContent = HERO[k][2]; setScreen("result"); }}>{{ msg: "KYC link SMS", link: "Fake bank website", pay: "UPI refund ID", app: "APK sent on WhatsApp" }[k]}</button>)}
            </div>
          </div>
        ) : (
          <div className="d-result" ref={resRef} dangerouslySetInnerHTML={{ __html: resultHTML(tab) }} />
        )}
      </main>
      {screen === "home" && <Footer hits={hits} />}
      <p className="d-banner">Design demo: your app's own globe. Results are samples, not real checks.</p>
    </>
  );
}
