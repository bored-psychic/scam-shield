import datetime as dt, os

from shield.links.lists import BLOCKLISTS, TOP_POPULAR
from shield.links.lookalike import abuse_tld, brand_tld, homograph, link_domain, lookalike, raw_ip, restricted_zone, unicode_host
from shield.links.platforms import SHORTENERS, platform_of, suffix_match

# One link's background checks -> the decision D23 table (docs/decisions/D23_link_checks.md §2). Pure: the lists and the live results are
# passed in. The router applies the level rules (floors, P1 / P2 under the hard-risk condition); report.py turns the output into Evidence
# and the "Website details" fact sheet (Report.link).
#
# Red flags, raise only (the link's phishing-side level = max(URL model level, floor), which enters the existing fusion as the URL side):
#   R1 on OpenPhish / URLhaus -> Likely scam        R2 Google Safe Browsing match -> Likely scam     R3 IDN homograph -> Likely scam
#   R4 brand lookalike -> Suspicious                R5 raw IP host -> Suspicious                     R6 shares a server with listed IPs -> Suspicious
#   R7 registered < 30 days ago -> Suspicious       R8 first certificate < 7 days (only when R7 cannot be checked) -> Suspicious
#   R9 two or more of R4-R8 on the same link -> Likely scam
# Positive, only without any hard-risk signal in the message and never against a red flag on the same link (router.apply_positives):
#   P1 a verified .brand TLD or a .bank.in address -> link No warning signs; the message Likely scam -> Suspicious when every link is P1 / P2
#      and the text has no Indian mobile number           P2 Tranco top 10k, not a platform / shortener / gambling site -> link No warning signs
# Display only (never a level): .gov.in / .nic.in, abuse TLD, age 30-179 days, registration length, registrar, RDAP status, provider,
# country, popularity outside the top 10k, a plain international (IDN) address.
NEW_DOMAIN_DAYS, YOUNG_DOMAIN_DAYS, NEW_CERT_DAYS = 30, 180, 7
FLOOR = {"R1": 2, "R2": 2, "R3": 2, "R4": 1, "R5": 1, "R6": 1, "R7": 1, "R8": 1}
CAUTION_FLAGS = ("R4", "R5", "R6", "R7", "R8")
# Networks where one IP serves thousands of unrelated sites (CDNs, big clouds' front ends, shared web hosting): sharing one of their IPs with a
# listed host means nothing, so R6 is not raised. VPS providers (OVH, Hetzner, DigitalOcean ...) are NOT here: there one IP is usually one customer.
CDN_ASNS = {13335: "Cloudflare", 209242: "Cloudflare", 20940: "Akamai", 16625: "Akamai", 32787: "Akamai", 54113: "Fastly", 15169: "Google",
            396982: "Google Cloud", 19527: "Google", 16509: "Amazon", 14618: "Amazon", 8075: "Microsoft", 8068: "Microsoft", 32934: "Meta",
            13414: "X (Twitter)", 60068: "CDN77", 22612: "Namecheap", 46606: "Unified Layer", 26496: "GoDaddy"}
COUNTRY = {"IN": "India", "US": "United States", "GB": "United Kingdom", "DE": "Germany", "NL": "Netherlands", "FR": "France", "SG": "Singapore",
           "HK": "Hong Kong", "CN": "China", "RU": "Russia", "JP": "Japan", "CA": "Canada", "AU": "Australia", "IE": "Ireland", "SE": "Sweden",
           "FI": "Finland", "VN": "Vietnam", "ID": "Indonesia", "TR": "Turkey", "UA": "Ukraine", "BR": "Brazil", "KR": "South Korea",
           "AE": "United Arab Emirates", "MY": "Malaysia", "TH": "Thailand", "PH": "Philippines", "BD": "Bangladesh", "PK": "Pakistan",
           "LT": "Lithuania", "BG": "Bulgaria", "RO": "Romania", "PL": "Poland", "IT": "Italy", "ES": "Spain", "CH": "Switzerland",
           "SC": "Seychelles", "PA": "Panama", "BZ": "Belize", "KH": "Cambodia", "MM": "Myanmar"}
FAIL_WORDS = {"offline": "offline", "timeout": "timed out", "refused": "not allowed", "too_large": "answer too large"}
SB_SOURCE = "Advisory provided by Google"


def _fail(why):
    return f"Couldn't verify ({FAIL_WORDS.get(why, 'the service did not answer properly')})"

def _ago(days):
    if days <= 0:
        return "today"
    if days == 1:
        return "1 day ago"
    if days < 60:
        return f"{days} days ago"
    if days < 730:
        return f"{days // 30} months ago"
    return f"{days // 365} years ago"

def _fact(key, label, value, effect="neutral", why=None, status="ok", source=None, sent=None):
    return {"key": key, "label": label, "value": value, "effect": effect, "why": why, "status": status, "source": source, "sent": sent}

def _flag(code, id_, title, why, tag):
    return {"code": code, "id": id_, "effect": "danger" if FLOOR[code] == 2 else "caution", "title": title, "why": why, "tag": tag}

def _updated(lists, name, today):
    t = lists.updated(name)
    if t is None:
        return ""
    hours = int((today - t).total_seconds() // 3600)
    return f"updated {hours} h ago" if hours < 48 else f"updated {hours // 24} days ago"


# The registry operator as a short name for the "Lowered from..." sentence (D24): the legal name of the 15 verified .brand TLDs, kept short.
# brand_tlds.json is rewritten by update_link_lists.py, so these names cannot live there; a TLD missing here falls back to its legal name.
_OPERATOR_SHORT = {"jio": "Reliance", "reliance": "Reliance", "ril": "Reliance", "sbi": "State Bank of India", "hdfcbank": "HDFC Bank", "hdfc": "HDFC Bank",
                   "airtel": "Airtel", "bharti": "Bharti", "tatamotors": "Tata Motors", "amazon": "Amazon", "google": "Google", "youtube": "Google",
                   "microsoft": "Microsoft", "apple": "Apple", "netflix": "Netflix"}

def _operator(bt):
    return _OPERATOR_SHORT.get(bt["tld"], bt["registry_operator"])


def _names(url, host, reg, lists, gambling, now):
    """The offline checks of one address: flags, positive, display notes and facts."""
    flags, notes, facts, positive = [], [], [], None
    root = platform_of(host)
    shortener = bool(suffix_match(host, SHORTENERS))
    rank = lists.tranco_rank(reg)
    ip = raw_ip(host)
    # ownership: a .brand TLD, a restricted zone, or an Indian brand's name on someone else's domain
    bt, zone = brand_tld(host), restricted_zone(host)
    look = None if (bt or zone) else lookalike(host, reg, rank)
    if bt:
        why = f".{bt['tld']} is a brand domain ending: under ICANN's rules only {bt['registry_operator']} (and its affiliates) can register these."
        positive = {"kind": "p1", "id": "link.brand_owned", "title": f"Belongs to {bt['brand']}: only {bt['registry_operator']} can register .{bt['tld']} addresses",
                    "why": why, "tag": "Brand's own site",
                    "lowered": f"{{}} belongs to {bt['brand'].split(' (')[0]} (only {_operator(bt)} can register .{bt['tld']} addresses)"}
        facts.append(_fact("owner", "Owner", f"{bt['brand']} (.{bt['tld']} is its own domain ending)", "reassuring", why,
                           source=f"ICANN gTLD list (Specification 13) + IANA root zone, verified {bt['verified']}"))
    elif zone:
        kind = "p1" if zone["effect"] == "p1" else "display"
        positive = {"kind": kind, "id": "link.bank_in" if kind == "p1" else "link.gov_zone", "title": zone["title"], "why": zone["why"],
                    "tag": "Bank-only domain" if kind == "p1" else "Government domain",
                    "lowered": f"{{}} ends in .{zone['zone']} (only {'banks' if zone['zone'] == 'bank.in' else zone['owner']} can register these addresses)"}
        facts.append(_fact("owner", "Owner", f"Registered to {zone['owner']} (.{zone['zone']})", "reassuring", zone["why"], source=zone["sources"][0].split(" ")[0]))
    elif look:
        own = ", ".join(look["owned"])
        how = "a near copy of the name" if look["how"] == "near" else "the name"
        why = f"{look['brand']}'s own sites are {own}. Scammers put a brand's name in their own web address."
        flags.append(_flag("R4", "link.lookalike", f"Uses {how} {look['brand']}, but the site isn't {look['brand']}'s", why, "Brand lookalike"))
        facts.append(_fact("owner", "Owner", f"Not {look['brand']} ('{look['token']}' in {reg})", "caution", why))
    # lists (R1)
    hits, problems = lists.listed(url, host), lists.blocklist_problems()
    checked = [shown for n, shown in BLOCKLISTS.items() if shown not in problems]
    upd = "; ".join(f"{shown} {_updated(lists, n, now)}" for n, shown in BLOCKLISTS.items() if shown not in problems)
    gaps = "; ".join(f"couldn't check {shown} ({why})" for shown, why in problems.items())
    if hits:
        names = " and ".join(dict.fromkeys(n for n, _ in hits))
        why = "Security researchers have already reported this address."
        flags.append(_flag("R1", "link.listed", f"Reported as a phishing or malware link ({names})", why, "Reported scam link"))
        facts.append(_fact("lists", "Scam lists", f"On {names}" + (f"; {gaps}" if gaps else ""), "danger", why, source=upd or None))
    elif checked:
        facts.append(_fact("lists", "Scam lists", f"Not on {' or '.join(checked)}" + (f"; {gaps}" if gaps else ""), "neutral",
                           "Not listed is not proof: new scam sites take hours or days to be reported.", source=upd or None))
    else:
        facts.append(_fact("lists", "Scam lists", f"Couldn't verify ({', '.join(sorted(set(problems.values())))})", "unknown", status="failed"))
    # look-alike letters (R3) and raw IPs (R5)
    homo = homograph(host, lists.top_labels)
    shown_host = unicode_host(host)
    if homo:
        target = homo["looks_like"] or "another name"
        why = "Letters from another alphabet make a fake address read like a real one."
        flags.append(_flag("R3", "link.homograph", f"The address uses look-alike letters from another alphabet to imitate '{target}'", why, "Look-alike letters"))
        facts.append(_fact("idn", "Letters", f"Written as {homo['label']}, imitating {target}", "danger", why))
    elif shown_host != host:
        facts.append(_fact("idn", "Letters", f"International address, shown as {shown_host}"))
    if ip:
        why = "Real businesses use a name. A bare server number hides who runs it."
        flags.append(_flag("R5", "link.raw_ip", "The link is a bare server number (IP address), not a website name", why, "Raw IP link"))
        facts.append(_fact("address", "Address", f"IP address {ip}", "caution", why))
    # hosting platforms, popularity (P2), abuse TLD (display)
    if root and not shortener:
        facts.append(_fact("hosting", "Hosting", f"On {root}, where anyone can publish", "neutral",
                           f"Facts about {root} say nothing about this page, so its registration was not looked up."))
    if not lists.has_tranco:
        facts.append(_fact("popularity", "Popularity", _fail_list(lists, "tranco"), "unknown", status="failed"))
    elif ip:
        pass
    elif rank is None:
        facts.append(_fact("popularity", "Popularity", "Not in the top 1 million websites", "neutral",
                           "Most scam sites aren't, and neither are many small genuine businesses.", source="Tranco list " + _updated(lists, "tranco", now)))
    else:
        about = f"{root} is #{rank:,} of the top 1 million, but anyone can post there" if root else f"#{rank:,} of the top 1 million websites"
        p2 = rank <= TOP_POPULAR and not root and not ip and not gambling and positive is None and not look
        facts.append(_fact("popularity", "Popularity", about, "reassuring" if p2 else "neutral", source="Tranco list " + _updated(lists, "tranco", now)))
        if p2:
            positive = {"kind": "p2", "id": "link.popular", "title": f"A well-known website (#{rank:,} of the most visited)",
                        "why": "Popular, long-established sites are rarely scam sites, though one can be hacked.", "tag": "Well-known site"}
    a = abuse_tld(reg) if not ip else None
    if a:
        why = f"Interisle counted {a[1]:g} phishing names per 10,000 .{a[0]} names (May-July 2026). Genuine sites use it too."
        notes.append({"id": "link.abuse_tld", "effect": "caution", "title": f"The ending .{a[0]} is among the most abused for phishing",
                      "why": why, "tag": "Risky ending"})
        facts.append(_fact("ending", "Ending", f".{a[0]} (high phishing rate)", "caution", why, source="Interisle Cybercrime Information Center"))
    return {"flags": flags, "notes": notes, "facts": facts, "positive": positive, "rank": rank, "ip": ip, "shown_host": shown_host}

def _fail_list(lists, name):
    return f"Couldn't verify ({lists.status.get(name) or 'list not downloaded'})"


def _registration(res, reg, positive, today):
    """Facts + flags (R7 / R8) from the registration result {"rdap": ..., "crtsh": ...}."""
    flags, facts = [], []
    rd = res.get("rdap") or {}
    brand_safe = positive is not None and positive["kind"] == "p1"   # a .brand / .bank.in name is registered by the owner: its age means nothing
    created = rd.get("created") if rd.get("status") == "ok" else None
    tld = reg.rsplit(".", 1)[-1]
    if created:
        days = (today - created).days
        if days < NEW_DOMAIN_DAYS and not brand_safe:
            why = "Scam sites are usually days or weeks old; real banks' and shops' sites are years old."
            flags.append(_flag("R7", "link.new_domain", f"The website was registered {_ago(days)}", why, "New website"))
            facts.append(_fact("age", "Registered", f"{_ago(days)} ({created:%d %b %Y})", "caution", why, sent=rd["sent"]))
        elif days < YOUNG_DOMAIN_DAYS and not brand_safe:
            facts.append(_fact("age", "Registered", f"{_ago(days)} ({created:%d %b %Y})", "caution",
                               "Fairly new. Not proof of anything, but worth a second look.", sent=rd["sent"]))
        else:
            facts.append(_fact("age", "Registered", f"{_ago(days)} ({created:%d %b %Y})", "neutral", sent=rd["sent"]))
        if rd.get("expires"):
            years = round((rd["expires"] - created).days / 365.25)
            facts.append(_fact("registration_length", "Paid until", f"{rd['expires']:%d %b %Y}" + (f" ({years} year{'s' if years != 1 else ''} in all)" if years else "")))
    elif rd.get("status") == "not_found":
        facts.append(_fact("age", "Registered", "The registry has no record of this name (it may have been taken down)", "unknown", sent=rd["sent"]))
    elif rd.get("status") == "ok":   # the registry answered but gave no registration event: not a failure
        facts.append(_fact("age", "Registered", "The registry didn't share a registration date", "unknown", sent=rd["sent"]))
    elif rd.get("status") == "unsupported":
        facts.append(_fact("age", "Registered", f"Couldn't verify (no public registry lookup for .{tld})", "unknown", status="failed"))
    else:
        facts.append(_fact("age", "Registered", _fail(rd.get("why")), "unknown", status="failed", sent=rd.get("sent")))
    if rd.get("registrar"):
        facts.append(_fact("registrar", "Registrar", rd["registrar"]))
    held = [s for s in rd.get("statuses", []) if "hold" in s.lower()]
    if held:
        facts.append(_fact("status", "Registry status", "On hold: the registry has switched this name off", "neutral",
                           "Registries put a name on hold after abuse reports or unpaid bills."))
    ct = res.get("crtsh")
    if ct is not None:
        if ct.get("status") == "ok":
            days = (today - ct["first"]).days
            if days < NEW_CERT_DAYS and not brand_safe:
                why = "A site that got its very first security certificate this week is brand new."
                flags.append(_flag("R8", "link.new_cert", f"The website's first security certificate is from {_ago(days)}", why, "New website"))
                facts.append(_fact("certificate", "First certificate", f"{_ago(days)} ({ct['first']:%d %b %Y})", "caution", why, sent=ct["sent"]))
            else:
                facts.append(_fact("certificate", "First certificate", f"{_ago(days)} ({ct['first']:%d %b %Y})", sent=ct["sent"]))
        elif ct.get("status") == "none":
            facts.append(_fact("certificate", "First certificate", "None logged (the site has never had a certificate)", "neutral", sent=ct["sent"]))
        else:
            facts.append(_fact("certificate", "First certificate", _fail(ct.get("why")), "unknown", status="failed", sent=ct.get("sent")))
    return flags, facts

def _server(res, lists):
    flags, facts = [], []
    st = res.get("status")
    if st == "ok" and res["ips"]:
        ip = res["ips"][0]
        a = lists.asn(ip)
        where = f"{a[2]} (AS{a[0]}) · {COUNTRY.get(a[1], a[1])}" if a else "provider unknown"
        facts.append(_fact("server", "Server", where, "neutral", source="iptoasn.com" if a else None, sent=res["sent"]))
        shared = [i for i in res["ips"] if i in lists.bad_ips and not ((b := lists.asn(i)) and b[0] in CDN_ASNS)]
        if shared:
            why = "Scammers often run many fake sites from one server."
            flags.append(_flag("R6", "link.shared_server", "Its server also hosts addresses reported for phishing or malware", why, "Shared scam server"))
            facts.append(_fact("shared", "Shared server", "Same IP as a reported scam address (URLhaus / OpenPhish)", "caution", why))
    elif st == "ok" or st == "nxdomain":
        facts.append(_fact("server", "Server", "The name has no address in DNS (no website there now)", "unknown", sent=res["sent"]))
    else:
        facts.append(_fact("server", "Server", _fail(res.get("why")), "unknown", status="failed", sent=res.get("sent")))
    return flags, facts

def _safe_browsing(res):
    if res.get("status") == "skipped":
        return [], []
    if res.get("status") == "ok" and res["threats"]:
        why = "Google has flagged this site for phishing or malware."
        kinds = ", ".join(t.replace("_", " ").lower() for t in res["threats"])
        return ([_flag("R2", "link.safe_browsing", "Google Safe Browsing lists this site as dangerous", why, "Safe Browsing hit")],
                [_fact("safe_browsing", "Google Safe Browsing", f"Listed ({kinds})", "danger", why, source=SB_SOURCE, sent=res["sent"])])
    if res.get("status") == "ok":
        return [], [_fact("safe_browsing", "Google Safe Browsing", "Not listed", "neutral", source=SB_SOURCE, sent=res["sent"])]
    return [], [_fact("safe_browsing", "Google Safe Browsing", _fail(res.get("why")), "unknown", status="failed", sent=res.get("sent"))]


PENDING_FACTS = {"registration": ("age", "Registered"), "dns": ("server", "Server"), "sb": ("safe_browsing", "Google Safe Browsing")}

def _domain(url, host, reg, lists, live, checks, state, gambling, now):
    """Offline names + live results (or pending / off rows) for one address."""
    out = _names(url, host, reg, lists, gambling, now)
    flags, facts, today = out["flags"], out["facts"], now.date()
    for check in checks:
        if check == "sb" and not _sb_on():
            continue
        if state == "done":
            res = live.get(check)
            if res is None:
                continue
            if check == "registration":
                f, x = _registration(res, reg, out["positive"], today)
            elif check == "dns":
                f, x = _server(res, lists)
            else:
                f, x = _safe_browsing(res)
            flags += f
            facts += x
        else:
            key, label = PENDING_FACTS[check]
            facts.append(_fact(key, label, None, "unknown", status="pending") if state == "pending"
                         else _fact(key, label, "Not checked (live checks are off)", "unknown", status="skipped"))
    return out

def _sb_on():
    return bool(os.environ.get("SAFE_BROWSING_KEY", "").strip())


def assess(l, lists, live=None, state="pending", now=None):
    """The D23 checks of one link of router.analyse() (l: url, kind, gambling). state: "pending" (offline call, live checks to come), "done"
    (live = this link's results from live.run), "off" (live checks switched off). Returns the dict the router and report.py read."""
    from shield.links.live import plan   # plan() is pure string work (which checks a link gets)
    now = now or dt.datetime.now(dt.timezone.utc)
    url = l["url"]
    host, reg, checks = plan(url)
    if not host:
        return None
    shortener = bool(suffix_match(host, SHORTENERS))
    out = _domain(url, host, reg, lists, live or {}, checks, state, bool(l.get("gambling")), now)
    pending = [c for c in checks if state == "pending" and (c != "sb" or _sb_on())]
    destination, expandable = None, False
    if shortener:
        ex = (live or {}).get("expand")
        if ex is None:
            expandable = state != "off"
            out["facts"].insert(0, _fact("destination", "Goes to", None if state != "off" else "Not checked (live checks are off)", "unknown",
                                         f"Hidden. The button asks {platform_of(host)} where it leads; the destination itself is not opened.",
                                         status="skipped"))
        elif ex["status"] == "ok":
            destination = ex["destination"]
            dhost, dreg = link_domain(destination)
            dlive = (live or {}).get("dest", {})
            d = _domain(destination, dhost, dreg, lists, dlive, plan(destination)[2], "done", False, now)
            out["facts"].insert(0, _fact("destination", "Goes to", destination, "neutral", sent=ex["sent"]))
            for f in d["flags"]:
                out["flags"].append(dict(f, title=_dest_title(f["title"])))
            out["notes"] += [dict(n, title=_dest_title(n["title"])) for n in d["notes"]]
            out["facts"] += [dict(f, key="dest_" + f["key"], label="Destination: " + f["label"].lower()) for f in d["facts"]]
            if d["positive"] and d["positive"]["kind"] in ("p1", "p2"):
                out["positive"] = dict(d["positive"], title=_dest_title(d["positive"]["title"]), lowered=d["positive"].get("lowered") and d["positive"]["lowered"].replace("{}", "the link's destination", 1))
        else:
            why = {"no_redirect": "the shortener didn't say", "too_many_hops": "too many short links in a row"}.get(ex["status"], FAIL_WORDS.get(ex.get("why"), "no answer"))
            out["facts"].insert(0, _fact("destination", "Goes to", f"Couldn't reveal ({why})", "unknown", status="failed", sent=ex.get("sent")))
    codes = [f["code"] for f in out["flags"]]
    floor = max((FLOOR[c] for c in codes), default=None)
    if len({c for c in codes if c in CAUTION_FLAGS}) >= 2:   # R9
        tags = ", ".join(dict.fromkeys(f["tag"].lower() for f in out["flags"] if f["code"] in CAUTION_FLAGS))
        out["flags"].append({"code": "R9", "id": "link.red_flags", "effect": "danger", "title": "Several warning signs on this one link",
                             "why": f"Together ({tags}) they are typical of a phishing site.", "tag": "Several red flags"})
        floor = 2
    sent = [f["sent"] for f in out["facts"] if f.get("sent")]
    return {"host": host, "reg": reg, "shown_host": out["shown_host"], "flags": out["flags"], "notes": out["notes"], "facts": out["facts"],
            "positive": out["positive"], "floor": floor, "pending": pending, "shortener": shortener, "expandable": expandable,
            "destination": destination, "sent": list(dict.fromkeys(sent))}

def _dest_title(t):
    t = t[0].lower() + t[1:]
    return ("Its destination: " + t)[:120]
