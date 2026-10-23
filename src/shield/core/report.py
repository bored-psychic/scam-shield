import re
from shield.config import model_versions
from shield.contracts import Evidence, Effect, Fact, Level, LinkInfo, Lowered, Meta, Report, Sender
from shield.core.advice import advice_for
from shield.core.risk import risk_score
from shield.core.sender_rule import RISKY_THING
from shield.core.verdict import PROMOTIONAL
from shield.messages.sender import SUFFIX_NAME

# Adapter: the loose dict that router.analyse() returns -> the typed Report (shield.contracts). No per-call I/O (model_versions() reads the
# model files once per process and is cached); analyse() is untouched.
_LEVEL = {0: Level.NO_WARNING_SIGNS, 1: Level.SUSPICIOUS, 2: Level.LIKELY_SCAM, PROMOTIONAL: Level.PROMOTIONAL}
_BY_LEVEL = {2: Effect.DANGER, 1: Effect.CAUTION, 0: Effect.NEUTRAL}
_TAG_TITLES = {"authority": "Claims to be from a bank, government body or company", "urgency": "Pushes you to act quickly",
               "payment": "Asks for money or payment details", "isolation": "Tells you to keep this secret or delete it"}
# Titles for a tactic cue on a message that got no warning: these cues also appear in genuine alerts, so they must not read as accusations.
_NEUTRAL_TAG_TITLES = {"authority": "Mentions a bank, government body or company", "urgency": "Uses time words (common in genuine alerts too)",
                       "payment": "Mentions money or payments (normal in genuine bank alerts)", "isolation": "Mentions keeping something private"}
# Short radar labels (Evidence.tag), by evidence id.
_TAGS = {"rule.otp_request": "OTP request", "rule.pin_to_receive": "PIN to receive", "tactic.authority": "Authority claim", "tactic.urgency": "Urgency", "tactic.payment": "Payment ask",
         "tactic.isolation": "Secrecy", "model.text": "Scam wording", "model.url": "Risky link", "link.shortener": "Hidden link",
         "link.free_hosting": "Free hosting", "link.free_hosting_keyword": "Lookalike site", "link.unscored": "Unreadable link",
         "link.gambling": "Gambling site", "rule.safety_advice": "Safety advice", "sender.registered": "Registered sender",
         "sender.registered_misused": "Registered, but risky", "sender.mobile": "Personal number"}
# D23 link checks bring their own tags (shield.links.reputation); this one replaces the model's link rating when a positive check overrides it
_URL_TITLE_OVERRIDDEN = "The address pattern looked unusual to the model, but who owns the site is known"
_TEXT_TITLES = {2: "The wording is very similar to known scam messages", 1: "The wording is somewhat similar to known scam messages",
                0: "The wording does not resemble known scam messages"}
# The text head said Suspicious but the safety-advice cap (router.safety_advice_cap) lowered the verdict: the score stays visible, as neutral, with a title
# that says why it was set aside (a no-warning verdict must carry no caution evidence, A7).
_TEXT_TITLE_CAPPED = "Wording partly resembles scam messages, but it contains standard safety advice"
_URL_TITLES = {2: "The link looks like known phishing links", 1: "The link looks somewhat like phishing links",
               0: "The link does not look like known phishing links"}
# C2 (b): the URL model rated the link higher, but nothing else (no list, registry or certificate check) agreed, so it stops at Suspicious
_URL_CAPPED = "The website-name check rates this link higher, but no other check agreed, so it is shown as Suspicious."
# Promotional (D22): the wording score stays visible, as neutral, with a title that says why it did not decide the verdict (like the capped title above)
_TEXT_TITLE_PROMO = "The wording resembles scam messages, as many genuine offers do"

# The sender (D22). Chip labels (Report.sender.label), the reassuring reason for a registered ID with no hard-risk signal, and the plain names of the
# hard-risk signals for the misuse evidence's detail. The ID itself is only ever a business header; a mobile number is never written anywhere.
_SENDER_LABEL = {"P": "Registered business · Promotional", "S": "Registered business · Service", "T": "Registered business · Transactional",
                 "G": "Registered sender · Government", None: "Registered business · type unknown"}
_REGISTERED_TITLE = {"P": "Sent from a registered business ID (promotional)", "S": "Sent from a registered business ID (service)",
                     "T": "Sent from a registered business ID (transactional)", "G": "Sent from a registered government sender ID",
                     None: "Sent from a registered business ID (type unknown)"}
_MOBILE_TITLE = "Sent from a personal mobile number; businesses use registered IDs like JM-JIOCPN-P"
_RISK_NAMES = {"otp_request": "an OTP / PIN / CVV / password request", "pin_to_receive": "a UPI PIN asked for to receive money", "phishing_link": "a link the URL model rates as phishing",
               "link_red_flag": "a link red flag (a scam list, look-alike letters or name, a raw IP, a shared scam server, or a brand-new website)",
               "lookalike_link": "a lookalike link on free hosting", "gambling": "a gambling or betting link", "legal_threat": "an arrest or legal threat",
               "secrecy": "a demand for secrecy", "cutoff_threat": "a threat to block or cut off a service", "earning_promise": "a promise of guaranteed or easy earnings",
               "payment_demand": "a payment or fee demand"}
# The OTP rule also catches password requests (2026-10-18): a hit that names a password gets its own title and tag; every other hit keeps the old ones.
_PASSWORD = re.compile(r"pass(?:word|code|wd)")
_OTP_TITLE, _PASSWORD_TITLE = "Asks you to share an OTP, PIN or CVV", "Asks you to share a password"


def _level(n):
    return Level.CANT_JUDGE if n is None else _LEVEL[n]

def _in_text(text, phrase):
    """(quote, span) of phrase in text, or (None, None). cred_requests() and tactic_tags() return their matches lower-cased (and tactic_tags runs on
    PII-masked text), so look for the phrase ignoring case and quote the user's own spelling; a cue that is not in the text (a mask token)
    gives (None, None). span is [start, end) in code points (str indexing), the same measure as text[start:end] == quote.
    Whole words first, so the cue "pin" points at "PIN" and not at the inside of "shipping"; only if no whole-word match exists, any match."""
    if not phrase:
        return None, None
    m = re.search(rf"(?<!\w){re.escape(phrase)}(?!\w)", text, re.I) or re.search(re.escape(phrase), text, re.I)
    return (m.group(0), (m.start(), m.end())) if m else (None, None)

def _link_report(l, text, flagged, hard_free):
    """The child Report of one link. The first piece of evidence follows the link's normal assessment (base_level); a gambling hit floors the
    link at Suspicious (router.analyse). D23: each red flag of its background checks is its own evidence, ahead of the model's rating; a
    positive check that was applied (router.apply_positives) is reassuring evidence and turns the model's rating into a neutral note; a
    display-only note (abuse TLD) is caution beside a warning verdict and neutral otherwise; the fact sheet is Report.link."""
    kind, level, c = l["kind"], l["base_level"], l.get("checks")
    at = text.find(l["url"])   # a refanged link (hxxp, [.]) is not in the text as such: no quote, no span
    quote, span = (l["url"], (at, at + len(l["url"]))) if at >= 0 else (None, None)
    def ev(id_, effect, title, detail=None, tag=None):
        return Evidence(id=id_, module="links", effect=effect, title=title, tag=tag or _TAGS[id_], detail=(l["note"] or "") if detail is None else detail,
                        quote=quote, span=span)
    if kind == "shortener":
        e = ev("link.shortener", Effect.UNKNOWN, "Shortened link: its real destination is hidden")
    elif kind == "free" and level is None:
        e = ev("link.free_hosting", Effect.UNKNOWN, "Free hosting: the domain says nothing about this site")
    elif kind == "free" and level == 1:
        e = ev("link.free_hosting_keyword", Effect.CAUTION, "Free-hosted site with a brand or scam word in its name")
    elif kind == "model" and level is not None and l.get("positive_applied"):
        e = ev("model.url", Effect.NEUTRAL, _URL_TITLE_OVERRIDDEN if level else _URL_TITLES[0])
    elif kind == "model" and level is not None:
        e = ev("model.url", _BY_LEVEL[level], _URL_TITLES[level], _URL_CAPPED if l.get("url_capped") else None)
    elif kind == "model":   # a link with no parseable host: the URL model dropped it
        e = ev("link.unscored", Effect.UNKNOWN, "The link could not be read, so it was not checked")
    else:
        raise ValueError(f"unexpected link in analyse() output: kind={kind!r}, level={level!r}")
    flags = [ev(f["id"], Effect(f["effect"]), f["title"], f["why"], f["tag"]) for f in (c["flags"] if c else [])]
    evidence = flags + [e] + ([ev("link.gambling", Effect.CAUTION, "Gambling or betting site", l["gambling"]["detail"])] if l["gambling"] else [])
    if c:
        evidence += [ev(n["id"], Effect.CAUTION if flagged else Effect.NEUTRAL, n["title"], n["why"], n["tag"]) for n in c["notes"]]
        p = c["positive"]
        if p and (l.get("positive_applied") or (p["kind"] == "display" and hard_free and not c["flags"])):
            evidence.append(ev(p["id"], Effect.REASSURING, p["title"], p["why"], p["tag"]))
    info = None if not c else LinkInfo(url=l["url"], host=c["host"], shown_host=c["shown_host"], owner=c["reg"], shortener=c["shortener"],
                                       expandable=c["expandable"], destination=c["destination"], facts=[Fact(**f) for f in c["facts"]], sent=c["sent"])
    return Report(module="links", level=_level(l["level"]), score=l["score"], evidence=evidence, pending=list(c["pending"]) if c else [], link=info)

def _sender_block(sid):
    """Report.sender for a parsed sender (kind "none" -> None). Only a business header is echoed."""
    if sid.kind == "none":
        return None
    if sid.kind in ("dlt", "dlt_bare"):
        return Sender(kind=sid.kind, suffix=sid.suffix, header=sid.header, label=_SENDER_LABEL[sid.suffix])
    return Sender(kind=sid.kind, label="Personal mobile number" if sid.kind == "mobile" else "Not recognised")

def _sender_evidence(s, flagged):
    """The one piece of sender evidence for analyse()'s r["sender"] (None when the rule added no reason). It has no quote: the sender is not in the text."""
    sid, rule = s["id"], s["rule"]
    shown = "-".join(p for p in (sid.prefix, sid.header, sid.suffix) if p)   # the business ID as typed, normalised; never a mobile number
    kind = f"type {sid.suffix} ({SUFFIX_NAME[sid.suffix]})" if sid.suffix else "no type letter shown"
    if rule in ("promotional", "registered"):
        return Evidence(id="sender.registered", module="messages", effect=Effect.REASSURING, title=_REGISTERED_TITLE[sid.suffix], tag=_TAGS["sender.registered"],
                        detail=f"{shown}: {kind}. A registered ID is a strong hint, not proof.")
    if rule == "misuse":   # caution beside a warning; on a verdict with no warning (a payment demand alone sets no level) it is a neutral note
        risks = s["hard_risks"]
        return Evidence(id="sender.registered_misused", module="messages", effect=Effect.CAUTION if flagged else Effect.NEUTRAL,
                        title=f"Registered sender, but {RISKY_THING[risks[0]]}. Registered IDs can still be misused.", tag=_TAGS["sender.registered_misused"],
                        detail=f"{shown}: {kind}. Not softened because of " + ", ".join(_RISK_NAMES[k] for k in risks) + ".")
    if rule == "mobile":
        return Evidence(id="sender.mobile", module="messages", effect=Effect.CAUTION, title=_MOBILE_TITLE, tag=_TAGS["sender.mobile"],
                        detail="A hint, not proof: on its own it does not change the verdict.")
    return None

def to_report(text: str, r: dict) -> Report:
    level = _level(r["level"])
    flagged = level in (Level.SUSPICIOUS, Level.LIKELY_SCAM)
    promo = level == Level.PROMOTIONAL
    ev = []
    if r["pin_to_receive"]:   # one piece of evidence, quoting the first phrase; ahead of the OTP rule's: it is the more specific reading of the same words
        quote, span = _in_text(text, r["pin_to_receive"][0])
        ev.append(Evidence(id="rule.pin_to_receive", module="messages", effect=Effect.DANGER, tag=_TAGS["rule.pin_to_receive"], quote=quote, span=span,
                           title="Asks for your UPI PIN to receive money (receiving money never needs a PIN)"))
    for hit in r["cred_request"]:
        quote, span = _in_text(text, hit)
        pw = bool(_PASSWORD.search(hit)) and not re.search(r"one[- ]?time", hit)   # a one-time password is an OTP
        ev.append(Evidence(id="rule.otp_request", module="messages", effect=Effect.DANGER, title=_PASSWORD_TITLE if pw else _OTP_TITLE,
                           tag="Password request" if pw else _TAGS["rule.otp_request"], quote=quote, span=span))
    capped = bool(r.get("safety_advice"))   # the cap lowered Suspicious to No warning signs: say so, as reassurance
    if capped:
        quote, span = _in_text(text, r["safety_advice"][0])
        ev.append(Evidence(id="rule.safety_advice", module="messages", effect=Effect.REASSURING, title="Contains standard 'never share your OTP' safety advice",
                           tag=_TAGS["rule.safety_advice"], quote=quote, span=span))
    for tag, cues in r["tags"].items():
        if cues:
            quote, span = next((f for f in (_in_text(text, c) for c in cues) if f[0]), (None, None))   # the first cue that is in the text
            title = _TAG_TITLES.get(tag, f"Uses a {tag} tactic") if flagged else _NEUTRAL_TAG_TITLES.get(tag, f"Uses a {tag} tactic")
            ev.append(Evidence(id=f"tactic.{tag}", module="messages", effect=Effect.CAUTION if flagged else Effect.NEUTRAL, title=title,
                               tag=_TAGS.get(f"tactic.{tag}", tag[:24]), detail="Matched: " + ", ".join(cues), quote=quote, span=span))
    if r["text_score"] is not None:
        lo, hi = r["text_thresholds"]
        title = (_TEXT_TITLE_PROMO if promo and r["text_level"] else _TEXT_TITLE_CAPPED if capped and not promo else _TEXT_TITLES[r["text_level"]])
        ev.append(Evidence(id="model.text", module="messages", effect=Effect.NEUTRAL if capped or promo else _BY_LEVEL[r["text_level"]],
                           title=title, tag=_TAGS["model.text"], detail=f"score {r['text_score']:.3f} (Suspicious from {lo:.3f}, Likely scam from {hi:.3f})"))
    s = r.get("sender")   # D22: None unless a sender was given
    sender_ev = _sender_evidence(s, flagged) if s else None
    if sender_ev:
        ev.append(sender_ev)
    children = [_link_report(l, text, flagged, not r.get("hard_risks")) for l in r["links"]]

    # reasons: only warnings, rule hits first, then the links, then the tactic tags, then the text model
    child_ev = [e for c in children for e in c.evidence]
    ordered = ([e for e in ev if e.id.startswith("rule.")] + child_ev + [e for e in ev if e.id.startswith("tactic.")]
               + [e for e in ev if e.id == "model.text"])
    reasons = list(dict.fromkeys(e.title for e in ordered if e.effect in (Effect.DANGER, Effect.CAUTION)))[:3]
    if level == Level.CANT_JUDGE and not reasons:
        reasons = list(dict.fromkeys(e.title for e in child_ev if e.effect == Effect.UNKNOWN))[:3] if children else ["Too little text to judge"]
    # The sender reason (D22) never pushes a warning out: it is first when it IS the verdict (Promotional, where the message itself carries no warning),
    # otherwise it takes a free place after the warnings. With three warnings already there it is not a reason; the frontend shows it under the sender
    # chip, right below the verdict word, so it is always on screen. This keeps the wording model's "very similar to known scam messages" (always the
    # last warning) where it was.
    # D23 P1 cap (router.apply_positives): the brand line takes a free place like the sender reason, never pushing a warning out; with three
    # warnings already there it is still on the link panel, as the link's reassuring evidence.
    if r.get("positive_cap") and len(reasons) < 3 and not promo:
        reasons = reasons + [r["positive_cap"]]
    if sender_ev and promo:
        reasons = [sender_ev.title] + [x for x in reasons if x != sender_ev.title][:2]
    elif sender_ev and len(reasons) < 3:
        reasons = reasons + [sender_ev.title]
    meta = Meta(text_score=r["text_score"], text_thresholds=r.get("text_thresholds"), escalated=r["escalated"], truncated=r.get("truncated", False),
                models=dict(model_versions()))
    category = "gambling" if any(l["gambling"] for l in r["links"]) else None
    low = r.get("lowered")   # D24: only if the level shown is still the one the P1 lowering produced (a later step, e.g. the sender rule, may have moved it)
    lowered = Lowered(from_level=_LEVEL[low["from"]], text=low["text"]) if low and r["level"] == 1 else None
    return Report(module="messages", level=level, score=r["text_score"], category=category, sender=_sender_block(s["id"]) if s else None,
                  evidence=ev, reasons=reasons, advice=advice_for(level, category), children=children,
                  pending=["links"] if any(c.pending for c in children) else [], risk_score=risk_score(level, r["text_score"], r.get("text_thresholds"), r.get("text_meter_ends")),
                  lowered=lowered, meta=meta)
