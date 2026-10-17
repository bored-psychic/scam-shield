import re
from shield.config import model_versions
from shield.contracts import Evidence, Effect, Level, Meta, Report, Sender
from shield.core.advice import advice_for
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
_TEXT_TITLES = {2: "The wording is very similar to known scam messages", 1: "The wording is somewhat similar to known scam messages",
                0: "The wording does not resemble known scam messages"}
# The text head said Suspicious but the safety-advice cap (router.safety_advice_cap) lowered the verdict: the score stays visible, as neutral, with a title
# that says why it was set aside (a no-warning verdict must carry no caution evidence, A7).
_TEXT_TITLE_CAPPED = "Wording partly resembles scam messages, but it contains standard safety advice"
_URL_TITLES = {2: "The link looks like known phishing links", 1: "The link looks somewhat like phishing links",
               0: "The link does not look like known phishing links"}
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
_RISK_NAMES = {"otp_request": "an OTP / PIN / CVV request", "pin_to_receive": "a UPI PIN asked for to receive money", "phishing_link": "a link the URL model rates as phishing",
               "lookalike_link": "a lookalike link on free hosting", "gambling": "a gambling or betting link", "payment_demand": "a payment or fee demand"}


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

def _link_report(l, text):
    # the evidence about the link itself follows its normal assessment (base_level); a gambling hit only floors the link's level at Suspicious (router.analyse)
    kind, level = l["kind"], l["base_level"]
    def ev(id_, effect, title, detail=None):
        at = text.find(l["url"])   # a refanged link (hxxp, [.]) is not in the text as such: no quote, no span
        return Evidence(id=id_, module="links", effect=effect, title=title, tag=_TAGS[id_], detail=(l["note"] or "") if detail is None else detail,
                        quote=l["url"] if at >= 0 else None, span=(at, at + len(l["url"])) if at >= 0 else None)
    if kind == "shortener":
        e = ev("link.shortener", Effect.UNKNOWN, "Shortened link: its real destination is hidden")
    elif kind == "free" and level is None:
        e = ev("link.free_hosting", Effect.UNKNOWN, "Free hosting: the domain says nothing about this site")
    elif kind == "free" and level == 1:
        e = ev("link.free_hosting_keyword", Effect.CAUTION, "Free-hosted site with a brand or scam word in its name")
    elif kind == "model" and level is not None:
        e = ev("model.url", _BY_LEVEL[level], _URL_TITLES[level])
    elif kind == "model":   # a link with no parseable host: the URL model dropped it
        e = ev("link.unscored", Effect.UNKNOWN, "The link could not be read, so it was not checked")
    else:
        raise ValueError(f"unexpected link in analyse() output: kind={kind!r}, level={level!r}")
    evidence = [e] + ([ev("link.gambling", Effect.CAUTION, "Gambling or betting site", l["gambling"]["detail"])] if l["gambling"] else [])
    return Report(module="links", level=_level(l["level"]), score=l["score"], evidence=evidence)

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
        ev.append(Evidence(id="rule.otp_request", module="messages", effect=Effect.DANGER, title="Asks you to share an OTP, PIN or CVV",
                           tag=_TAGS["rule.otp_request"], quote=quote, span=span))
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
    children = [_link_report(l, text) for l in r["links"]]

    # reasons: only warnings, rule hits first, then the links, then the tactic tags, then the text model
    child_ev = [e for c in children for e in c.evidence]
    ordered = ([e for e in ev if e.id.startswith("rule.")] + child_ev + [e for e in ev if e.id.startswith("tactic.")]
               + [e for e in ev if e.id == "model.text"])
    reasons = list(dict.fromkeys(e.title for e in ordered if e.effect in (Effect.DANGER, Effect.CAUTION)))[:3]
    if level == Level.CANT_JUDGE and not reasons:
        reasons = list(dict.fromkeys(e.title for e in child_ev if e.effect == Effect.UNKNOWN))[:3] if children else ["Too little text to judge"]
    if sender_ev:   # the sender reason always gets one of the three places: first when it IS the verdict (Promotional), else after the two strongest
        rest = [x for x in reasons if x != sender_ev.title]
        reasons = [sender_ev.title] + rest[:2] if promo else rest[:2] + [sender_ev.title]
    meta = Meta(text_score=r["text_score"], text_thresholds=r.get("text_thresholds"), escalated=r["escalated"], truncated=r.get("truncated", False),
                models=dict(model_versions()))
    category = "gambling" if any(l["gambling"] for l in r["links"]) else None
    return Report(module="messages", level=level, score=r["text_score"], category=category, sender=_sender_block(s["id"]) if s else None,
                  evidence=ev, reasons=reasons, advice=advice_for(level, category), children=children, meta=meta)
