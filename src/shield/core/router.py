import re
from pii import mask_text
from shield import config
from url_features import parse_url
from textprep import URL_TOKEN, MAX_CHARS, extract_urls, model_text, replace_urls
from shield.core.verdict import LEVELS, r3, level_of, fuse
from shield.messages.rules import advisory_phrases, cred_requests, has_indian_mobile, pin_to_receive
from shield.messages.tactics import tactic_tags
from shield.links.lexical import url_notes
from shield.links.gambling import GAMBLING_VERDICT, load_gambling
from shield.links.platforms import assess_link

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
        ("text level is not Suspicious", r["text_level"] != 1 or r["level"] != 1),
        ("has a link", bool(r["links"])),
        ("has a mobile number", has_indian_mobile(text)),
        ("isolation cue", bool(r["tags"]["isolation"])),
        ("urgency cue", bool(r["tags"]["urgency"])),
        ("gambling hit", any(l["gambling"] for l in r["links"]))) if hit]
    return phrases, blockers

def analyse(text, text_model, url_model, safety_cap=None):
    """safety_cap: apply the safety-advice cap (None = config.SAFETY_ADVICE_CAP). When it fires, level is 0 and r["safety_advice"] holds the phrases."""
    text = (text or "")[:MAX_TEXT_CHARS]
    urls = extract_urls(text, MAX_URLS)
    prose_words = len(re.findall(r"\w+", replace_urls(text).replace(URL_TOKEN, " ")))
    cred, pin_recv = cred_requests(text), pin_to_receive(text)
    r = {"urls": urls, "cred_request": cred, "pin_to_receive": pin_recv, "escalated": False, "tags": tactic_tags(mask_text(text), cred),   # masked, so a phone / UPI id / account number shows up as a payment cue
         "text_score": None, "text_level": None, "grams": [], "links": [], "top_score": None, "breakdown": None, "notes": []}
    if prose_words >= MIN_PROSE_WORDS:
        prepared = model_text(text, mask_pii=True)   # PII masks, URLs -> <URL>, first 2000 chars: what baseline.py trained on (textprep.py)
        r["text_thresholds"] = tuple(r3(t) for t in text_model.thresholds)
        r["text_score"] = r3(text_model.score(prepared))
        r["text_level"] = level_of(r["text_score"], *r["text_thresholds"])
        r["grams"] = text_model.explain(prepared, k=14)
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
        l["base_level"] = l["level"]
        l["gambling"] = None if l["kind"] == "shortener" else lookup.match(l["url"])
        if l["gambling"] and (l["level"] or 0) < 1:
            l["level"], l["verdict"] = 1, GAMBLING_VERDICT
    levels = [l["base_level"] for l in r["links"] if l["base_level"] is not None]   # the phishing side only: a gambling hit is not a second head agreeing
    r["url_level"] = max(levels) if levels else None
    r["level"] = fuse(r["text_level"], r["url_level"])
    if (cred or pin_recv) and (r["level"] is None or r["level"] < 1):   # hard rules (OTP / PIN / CVV request, UPI PIN to receive money): at least Suspicious, whatever the scores say
        r["level"], r["escalated"] = 1, True
    if any(l["gambling"] for l in r["links"]) and (r["level"] is None or r["level"] < 1):   # gambling floor: Suspicious, never Likely scam on its own
        r["level"] = 1
    # safety-advice cap: last, so every hard rule and floor above has already had its say (the conditions refuse a message any of them fired on)
    if config.SAFETY_ADVICE_CAP if safety_cap is None else safety_cap:
        phrases, blockers = safety_advice_cap(text, r)
        if not blockers:   # 'no advisory phrase' is one of the blockers
            r["level"], r["safety_advice"] = 0, phrases
    return r
