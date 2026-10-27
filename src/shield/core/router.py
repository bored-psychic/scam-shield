import re
from pii import mask_text
from shield import config
from url_features import parse_url
from textprep import URL_TOKEN, MAX_CHARS, extract_urls, model_text, replace_urls
from shield.core.verdict import LEVELS, r3, level_of, fuse
from shield.messages.invest_rules import invest_rule_hits
from shield.messages.rules import advisory_phrases, cred_requests, has_indian_mobile, pin_to_receive
from shield.messages.tactics import tactic_tags
from shield.links.lexical import url_notes
from shield.links.gambling import GAMBLING_VERDICT, load_gambling
from shield.links.platforms import assess_link
from shield.links import live as live_checks
from shield.links.lists import load_lists
from shield.links.reputation import assess as assess_background
from shield.core.lang import detect_lang
from shield.core.sender_rule import apply_sender, hard_risks
from shield.messages.sender import parse_sender

MAX_TEXT_CHARS, MAX_URLS = 20000, 10
MIN_PROSE_WORDS = 3   # fewer words than this once links are removed -> a bare link, the text head has nothing to read

def safety_advice_cap(text, r):
    """(phrases, blockers): the 'never share your OTP' phrases found in the text, and the names of the conditions that stop the cap from applying
    (empty = the cap applies). r is analyse()'s result before the cap. The cap only ever lowers Suspicious to No warning signs, and only when the
    text head is the sole reason for Suspicious and nothing around the advice looks like a scam, because a scammer can paste the same sentence
    onto any scam: never at Likely scam, never with a link, a phone number to call, a request for a credential, secrecy or time pressure."""
    phrases = advisory_phrases(text)
    blockers = [name for name, hit in (
        ("no advisory phrase", not phrases),
        ("credential request", bool(r["cred_request"])),
        ("PIN-to-receive request", bool(r["pin_to_receive"])),
        ("investment-scam rule", bool(r.get("invest_rules"))),
        ("text level is not Suspicious", r["text_level"] != 1 or r["level"] != 1),
        ("has a link", bool(r["links"])),
        ("has a mobile number", has_indian_mobile(text)),
        ("isolation cue", bool(r["tags"]["isolation"])),
        ("urgency cue", bool(r["tags"]["urgency"])),
        ("gambling hit", any(l["gambling"] for l in r["links"]))) if hit]
    return phrases, blockers

def apply_positives(text, r):
    """D23 positive signals (P1 a verified .brand TLD or .bank.in address, P2 a Tranco top-10k site that is no platform): only when the
    message has no hard-risk signal (sender_rule.hard_risks: D22's list + any link red flag, with a positive link's own URL-model rating left
    out) and never on a link with a red flag. Such a link is set to No warning signs (its URL-model rating is overridden) and the message
    is fused again. If then every link is positive, at least one is P1, the text has no Indian mobile number and the level is still Likely
    scam, it is capped at Suspicious (never lower: like D22's cap for registered senders). Sets r["hard_risks"] and r["positive_cap"], and r["lowered"]:
    None, or {"from": the level before, "text": "Lowered from Likely scam: the link belongs to Jio (...)."} when a P1 link is what lowered the level
    (D24). Judged by what would have happened without it: the level fell below `before` and either the P1 cap did it, or overriding only the P2 links
    would have left it higher. P2 alone lowering a verdict, or P1 firing without a change, sets nothing."""
    r["hard_risks"], r["positive_cap"], r["lowered"] = hard_risks(text, r), None, None
    pos = [l for l in r["links"] if l["positive"] in ("p1", "p2") and not l["flags"]]
    if not pos or r["hard_risks"]:
        return
    before, was = r["level"], {id(l): l["risk_level"] for l in r["links"]}
    for l in pos:
        l["risk_level"], l["level"], l["positive_applied"] = 0, 0, True
        l["verdict"] = LEVELS[0]
    levels = [l["risk_level"] for l in r["links"] if l["risk_level"] is not None]
    r["url_level"] = max(levels) if levels else None
    r["level"] = fuse(r["text_level"], r["url_level"])
    capped = False
    if (r["level"] == 2 and all(l.get("positive_applied") for l in r["links"]) and any(l["positive"] == "p1" for l in r["links"])
            and not has_indian_mobile(text)):
        r["level"], capped = 1, True
        r["positive_cap"] = next(l["checks"]["positive"]["title"] for l in r["links"] if l["positive"] == "p1")
    p1 = next((l["checks"]["positive"] for l in pos if l["positive"] == "p1" and l["checks"]["positive"].get("lowered")), None)
    if before is not None and r["level"] is not None and r["level"] < before and p1:
        p2_only = [0 if l.get("positive_applied") and l["positive"] == "p2" else was[id(l)] for l in r["links"]]
        p2_only = [x for x in p2_only if x is not None]
        if capped or (fuse(r["text_level"], max(p2_only) if p2_only else None) or 0) > r["level"]:
            r["lowered"] = {"from": before, "text": f"Lowered from {LEVELS[before]}: " + p1["lowered"].replace("{}", "the link", 1) + "."}


def apply_language_cap(r):
    """D5 language cap (docs/decisions/D5_operating_point.md section 6: "Where no real dev data exists (Hindi, Kannada, Hinglish), the text model alone can
    reach at most Suspicious ... Link evidence and checked rules are unaffected"). Lowers Likely scam to Suspicious when the message is in a capped language
    (config.LANG_CAP_LANGS) and the text head is the only thing that made it Likely: its own level is Likely scam, no link is rated Suspicious or higher on
    the phishing side (r["url_level"], after the D23 positives; a URL-model Suspicious beside a text Suspicious is the fusion's second head, so a text
    Likely beside it is not "alone"), and no investment rule with a Likely-scam floor fired. The OTP / PIN / CVV, PIN-to-receive and gambling rules only
    floor at Suspicious, so they never made a Likely scam and need no exemption. Sets r["lang_cap"] when it lowers the level."""
    if (r["level"] == 2 and r["text_level"] == 2 and (r["url_level"] or 0) < 1 and r["lang"] in config.LANG_CAP_LANGS
            and not any(h["floor"] >= 2 for h in r["invest_rules"])):
        r["level"], r["lang_cap"] = 1, True


def analyse(text, text_model, url_model, safety_cap=None, sender=None, live=False, expand=(), explain=False, invest_rules=None, lang_cap=None):
    """safety_cap: apply the safety-advice cap (None = config.SAFETY_ADVICE_CAP). When it fires, level is 0 and r["safety_advice"] holds the phrases.
    sender: what the user's phone showed as the sender (D22), or None. It is read by the sender rule layer, last; None, "" and spaces change nothing
    (r["sender"] is None). The string is never logged or stored, and r keeps only its kind / header / suffix (sender_rule.apply_sender).
    live: run the network link checks (D23: shield.links.live, only registered domains leave the machine, <= 4 s); False = the offline
    analysis, which makes no network call and marks those checks pending. expand: short links (as extracted) the user asked to reveal.
    invest_rules: apply the investment-scam rules A1-A12 (None = config.INVEST_RULES). r["invest_rules"] holds the hits (shield.messages.invest_rules).
    lang_cap: apply the D5 language cap (None = config.LANG_CAP); r["lang"] always holds the detected language (shield.core.lang).
    explain: fill r["grams"] with the text head's strongest pieces of text (nothing shows them since the Gradio app was retired on 2026-10-28; the Report does not
    carry them, and for MuRIL they cost one extra batch of forward passes, so the API leaves this off)."""
    text = (text or "")[:MAX_TEXT_CHARS]
    urls = extract_urls(text, MAX_URLS)
    prose_words = len(re.findall(r"\w+", replace_urls(text).replace(URL_TOKEN, " ")))
    cred, pin_recv = cred_requests(text), pin_to_receive(text)
    r = {"urls": urls, "cred_request": cred, "pin_to_receive": pin_recv, "invest_rules": [], "escalated": False, "tags": tactic_tags(mask_text(text), cred),   # masked, so a phone / UPI id / account number shows up as a payment cue
         "text_score": None, "text_level": None, "grams": [], "links": [], "top_score": None, "breakdown": None, "notes": [],
         "lang": detect_lang(text), "lang_cap": False}
    if prose_words >= MIN_PROSE_WORDS:
        prepared = model_text(text, mask_pii=True)   # PII masks, URLs -> <URL>, first 2000 chars: what baseline.py trained on (textprep.py)
        r["text_thresholds"] = tuple(r3(t) for t in text_model.thresholds)
        r["text_meter_ends"] = getattr(text_model, "meter_ends", None)   # risk.curve: None = the D24 linear curve (baseline)
        r["text_score"] = r3(text_model.score(prepared))
        r["text_level"] = level_of(r["text_score"], *r["text_thresholds"])
        r["grams"] = text_model.explain(prepared, k=14) if explain else []
        r["truncated"] = len(prepared) >= MAX_CHARS
    # one entry per link, in input order: shorteners and free hosting are assessed by rule, the rest go to the URL model
    r["links"] = [{"url": u, "host": parse_url(u)[0], "score": None, "level": None, "verdict": "", "note": "", "kind": "model",
                   **(assess_link(u) or {})} for u in urls]
    by_url = {l["url"]: l for l in r["links"] if l["kind"] == "model"}
    if by_url:
        scored, X = url_model.score_many(list(by_url))
        for row in scored.itertuples():
            l = by_url[row.url]
            l["score"], l["level"] = float(row.score), int(row.level)
            l["verdict"] = LEVELS[l["level"]] if l["level"] else "not flagged"
        if len(scored):
            top = int(scored["score"].idxmax())
            r["top_score"], r["top_url"] = float(scored.loc[top, "score"]), scored.loc[top, "url"]
            r["breakdown"] = url_model.breakdown(X.iloc[top])
            r["notes"] = url_notes(r["top_url"])
    # gambling / betting (G1): every link but a shortener (its destination is hidden) is looked up locally. A hit keeps the link's normal
    # assessment (URL model or free-hosting rule, saved as base_level) and floors its level at Suspicious.
    lookup = load_gambling()
    for l in r["links"]:
        l["base_level"] = l["model_level"] = l["level"]   # model_level: the URL model's own level; the C2 cap below lowers base_level, the sender rule still reads this
        l["gambling"] = None if l["kind"] == "shortener" else lookup.match(l["url"])
        if l["gambling"] and (l["level"] or 0) < 1:
            l["level"], l["verdict"] = 1, GAMBLING_VERDICT
    # background checks (D23): lists, names, and (live=True) registry / DNS / certificate / Safe Browsing / the expand button. A red flag floors
    # the link's phishing-side level (risk_level), which, unlike a gambling hit, counts as the URL side of the fusion.
    lists = load_lists()
    state = "off" if not config.LIVE_CHECKS else "done" if live else "pending"
    results = live_checks.run([l["url"] for l in r["links"]], lists, expand_urls=set(expand)) if state == "done" and r["links"] else {}
    for l in r["links"]:
        c = l["checks"] = assess_background(l, lists, results.get(l["url"]), state)
        l["flags"] = [f["code"] for f in c["flags"]] if c else []
        l["positive"] = c["positive"]["kind"] if c and c["positive"] else None
        if l["kind"] == "model" and not l["flags"] and (l["base_level"] or 0) > config.URL_ALONE_MAX_LEVEL:   # C2 (b): the URL model alone stops at Suspicious
            l["base_level"] = l["level"] = config.URL_ALONE_MAX_LEVEL
            l["verdict"], l["url_capped"] = LEVELS[l["level"]], True
        floor = c["floor"] if c else None
        l["risk_level"] = l["base_level"] if floor is None else max(l["base_level"] or 0, floor)
        if floor is not None and (l["level"] or 0) < floor:
            l["level"], l["verdict"] = floor, f"{LEVELS[floor]} - {c['flags'][0]['tag'].lower()}"
    levels = [l["risk_level"] for l in r["links"] if l["risk_level"] is not None]   # the phishing side only: a gambling hit is not a second head agreeing
    r["url_level"] = max(levels) if levels else None
    r["level"] = fuse(r["text_level"], r["url_level"])
    if (cred or pin_recv) and (r["level"] is None or r["level"] < 1):   # hard rules (OTP / PIN / CVV request, UPI PIN to receive money): at least Suspicious, whatever the scores say
        r["level"], r["escalated"] = 1, True
    if any(l["gambling"] for l in r["links"]) and (r["level"] is None or r["level"] < 1):   # gambling floor: Suspicious, never Likely scam on its own
        r["level"] = 1
    # investment-scam rules (Phase A, raise-only): on the raw text, before the positives so that a hit counts as a hard-risk signal (hard_risks) and no
    # brand-owned link or registered sender softens it. Hook rules floor the level at Suspicious, money rules at Likely scam; neither ever lowers.
    if config.INVEST_RULES if invest_rules is None else invest_rules:
        r["invest_rules"] = invest_rule_hits(text)
        if r["invest_rules"]:
            floor = max(h["floor"] for h in r["invest_rules"])
            if r["level"] is None or r["level"] < floor:
                r["level"] = floor
    apply_positives(text, r)   # D23 P1 / P2: only without a hard-risk signal, so after every floor above
    if config.LANG_CAP if lang_cap is None else lang_cap:   # D5 language cap: after the floors and positives, so it sees the level they left
        apply_language_cap(r)
    # safety-advice cap: last, so every hard rule and floor above has already had its say (the conditions refuse a message any of them fired on)
    if config.SAFETY_ADVICE_CAP if safety_cap is None else safety_cap:
        phrases, blockers = safety_advice_cap(text, r)
        if not blockers:   # 'no advisory phrase' is one of the blockers
            r["level"], r["safety_advice"] = 0, phrases
    # the sender (D22): after everything else, so a hard rule, the gambling floor or a phishing link it finds has already set the level it refuses to soften
    return apply_sender(r, parse_sender(sender), text)
