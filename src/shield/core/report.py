import re
from shield.config import model_versions
from shield.contracts import Evidence, Effect, Level, Meta, Report
from shield.core.advice import advice_for

# Adapter: the loose dict that router.analyse() returns -> the typed Report (shield.contracts). No per-call I/O (model_versions() reads the
# model files once per process and is cached); analyse() is untouched.
_LEVEL = {0: Level.NO_WARNING_SIGNS, 1: Level.SUSPICIOUS, 2: Level.LIKELY_SCAM}
_BY_LEVEL = {2: Effect.DANGER, 1: Effect.CAUTION, 0: Effect.NEUTRAL}
_TAG_TITLES = {"authority": "Claims to be from a bank, government body or company", "urgency": "Pushes you to act quickly",
               "payment": "Asks for money or payment details", "isolation": "Tells you to keep this secret or delete it"}
# Titles for a tactic cue on a message that got no warning: these cues also appear in genuine alerts, so they must not read as accusations.
_NEUTRAL_TAG_TITLES = {"authority": "Mentions a bank, government body or company", "urgency": "Uses time words (common in genuine alerts too)",
                       "payment": "Mentions money or payments (normal in genuine bank alerts)", "isolation": "Mentions keeping something private"}
# Short radar labels (Evidence.tag), by evidence id.
_TAGS = {"rule.otp_request": "OTP request", "tactic.authority": "Authority claim", "tactic.urgency": "Urgency", "tactic.payment": "Payment ask",
         "tactic.isolation": "Secrecy", "model.text": "Scam wording", "model.url": "Risky link", "link.shortener": "Hidden link",
         "link.free_hosting": "Free hosting", "link.free_hosting_keyword": "Lookalike site", "link.unscored": "Unreadable link",
         "link.gambling": "Gambling site"}
_TEXT_TITLES = {2: "The wording is very similar to known scam messages", 1: "The wording is somewhat similar to known scam messages",
                0: "The wording does not resemble known scam messages"}
_URL_TITLES = {2: "The link looks like known phishing links", 1: "The link looks somewhat like phishing links",
               0: "The link does not look like known phishing links"}


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

def to_report(text: str, r: dict) -> Report:
    level = _level(r["level"])
    flagged = level in (Level.SUSPICIOUS, Level.LIKELY_SCAM)
    ev = []
    for hit in r["cred_request"]:
        quote, span = _in_text(text, hit)
        ev.append(Evidence(id="rule.otp_request", module="messages", effect=Effect.DANGER, title="Asks you to share an OTP, PIN or CVV",
                           tag=_TAGS["rule.otp_request"], quote=quote, span=span))
    for tag, cues in r["tags"].items():
        if cues:
            quote, span = next((f for f in (_in_text(text, c) for c in cues) if f[0]), (None, None))   # the first cue that is in the text
            title = _TAG_TITLES.get(tag, f"Uses a {tag} tactic") if flagged else _NEUTRAL_TAG_TITLES.get(tag, f"Uses a {tag} tactic")
            ev.append(Evidence(id=f"tactic.{tag}", module="messages", effect=Effect.CAUTION if flagged else Effect.NEUTRAL, title=title,
                               tag=_TAGS.get(f"tactic.{tag}", tag[:24]), detail="Matched: " + ", ".join(cues), quote=quote, span=span))
    if r["text_score"] is not None:
        lo, hi = r["text_thresholds"]
        ev.append(Evidence(id="model.text", module="messages", effect=_BY_LEVEL[r["text_level"]], title=_TEXT_TITLES[r["text_level"]], tag=_TAGS["model.text"],
                           detail=f"score {r['text_score']:.3f} (Suspicious from {lo:.3f}, Likely scam from {hi:.3f})"))
    children = [_link_report(l, text) for l in r["links"]]

    # reasons: only warnings, rule hits first, then the links, then the tactic tags, then the text model
    child_ev = [e for c in children for e in c.evidence]
    ordered = ([e for e in ev if e.id.startswith("rule.")] + child_ev + [e for e in ev if e.id.startswith("tactic.")]
               + [e for e in ev if e.id == "model.text"])
    reasons = list(dict.fromkeys(e.title for e in ordered if e.effect in (Effect.DANGER, Effect.CAUTION)))[:3]
    if level == Level.CANT_JUDGE and not reasons:
        reasons = list(dict.fromkeys(e.title for e in child_ev if e.effect == Effect.UNKNOWN))[:3] if children else ["Too little text to judge"]
    meta = Meta(text_score=r["text_score"], text_thresholds=r.get("text_thresholds"), escalated=r["escalated"], truncated=r.get("truncated", False),
                models=dict(model_versions()))
    category = "gambling" if any(l["gambling"] for l in r["links"]) else None
    return Report(module="messages", level=level, score=r["text_score"], category=category, evidence=ev, reasons=reasons,
                  advice=advice_for(level, category), children=children, meta=meta)
