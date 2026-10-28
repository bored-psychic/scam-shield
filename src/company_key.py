import re

# splits-v3 D-v3.4 (docs/plans/splits_v3.md): a company-name key for fake_job_postings posts that have no company_profile.
# fake_job_postings has no company-name column; build_text.py keys a post by the first 150 characters of its profile (company_key), and 3,082
# posts have no profile, so they were grouped by text similarity only (BUGS.md "Company grouping only covers job posts with a profile").
#   1. name_of_profile(): from a post WITH a profile, the leading proper-noun phrase before " is a / is an / is the" or ", a / an" (1-4 capitalised
#      tokens, >= MIN_NAME_CHARS characters, not on the stop list).
#   2. fill_company_keys(): for a post WITHOUT a profile, search title + description for those names (case-insensitive, word-bounded). A name that is
#      contained in a longer matched name does not count (the longest match wins). Exactly one distinct name -> the company_key of that name's
#      profile posts; zero or several names -> no key (as before). A name whose profile posts carry more than one company_key (the same company
#      with two profile texts) is ambiguous: its profile-less posts get no key and the name is counted.
# Pure functions on strings and frames: no file is read, nothing is written. build_text.py calls them behind --company-name-key (off by default,
# so a default build is byte-identical to the splits-v2 messages.csv).

MIN_NAME_CHARS = 5
MAX_NAME_TOKENS = 4
# A "name" that is also an ordinary word ("There is a ...", "Money is a ...") would key every post that uses the word. A name whose all-lowercase form
# appears as plain lowercase text in at least this many posts is treated as a common word and dropped (counted in the ledger).
COMMON_WORD_POSTS = 3
# a name that is just a pronoun / generic noun phrase is not a company ("We are a ...", "Our company is a ...", "The company is a ...")
STOP_NAMES = {"we", "our", "our company", "the company", "company", "this company", "the firm", "our firm", "our client", "our clients", "the client",
              "client", "my client", "it", "this", "that", "they", "the organization", "our organization", "organization", "the group", "our group",
              "the team", "our team", "a company", "the business", "our business", "business", "the agency", "our agency", "the world"}
# the phrase before the verb: up to MAX_NAME_TOKENS capitalised tokens (a capital letter or digit first), at the start of the profile
_TOKEN = r"[A-Z0-9][\w&'.\-]*"
_NAME_RX = re.compile(rf"^\s*(?P<name>{_TOKEN}(?:[ \t]+{_TOKEN}){{0,{MAX_NAME_TOKENS - 1}}})\s*(?:,\s*an?\b|\s+(?:is|are)\s+(?:an?|the)\b)")
_WORD = re.compile(r"\w+")


def name_of_profile(profile):
    """The company name a profile text starts with, or "" (see the module comment)."""
    m = _NAME_RX.match(str(profile))
    if not m:
        return ""
    name = re.sub(r"\s+", " ", m.group("name")).strip(" .,'-")
    if name.lower().startswith("the ") and len(name) > 4:
        name = name[4:]
    if len(name) < MIN_NAME_CHARS or name.lower() in STOP_NAMES:
        return ""
    return name


def name_tokens(name):
    return tuple(w.lower() for w in _WORD.findall(name))


def lowercase_posts(texts, by_first):
    """{name tokens: number of texts where the name appears with every token already lowercase in the text} (the common-word test)."""
    hits = {}
    for text in texts:
        orig = _WORD.findall(str(text))
        toks = [w.lower() for w in orig]
        seen = set()
        for i, t in enumerate(toks):
            for nt in by_first.get(t, ()):
                if nt not in seen and tuple(toks[i:i + len(nt)]) == nt and all(o == o.lower() for o in orig[i:i + len(nt)]):
                    seen.add(nt)
        for nt in seen:
            hits[nt] = hits.get(nt, 0) + 1
    return hits


def names_in(text, by_first):
    """The distinct maximal names (token tuples) found in `text`, word-bounded and case-insensitive. by_first = {first token: [token tuples]}."""
    toks = [w.lower() for w in _WORD.findall(str(text))]
    spans = []
    for i, t in enumerate(toks):
        for nt in by_first.get(t, ()):
            if tuple(toks[i:i + len(nt)]) == nt:
                spans.append((i, i + len(nt), nt))
    # drop a match that sits inside a longer one ("acme" inside "acme corporation")
    maximal = {nt for a, b, nt in spans if not any((c <= a and b <= d and (c, d) != (a, b)) for c, d, _ in spans)}
    return maximal


def fill_company_keys(posts):
    """posts: DataFrame with title, description, company_profile (raw strings) and company_key ("" where no profile). Returns (keys, ledger):
    keys = a Series of company_key with the profile-less posts' keys filled in where the rule above gives exactly one; ledger = counts and
    {"new_groups_by_size": [(name, posts newly keyed), ...]} for the by-eye check."""
    prof_name = posts["company_profile"].fillna("").map(name_of_profile)
    has_key = posts["company_key"] != ""
    named = has_key & (prof_name != "")
    keys_of = {}   # name tokens -> {company_key}
    display = {}
    for name, key in zip(prof_name[named], posts["company_key"][named]):
        nt = name_tokens(name)
        keys_of.setdefault(nt, set()).add(key)
        display.setdefault(nt, name)
    by_first = {}
    for nt in keys_of:
        by_first.setdefault(nt[0], []).append(nt)
    lower = lowercase_posts((f"{t} {d}" for t, d in zip(posts["title"], posts["description"])), by_first)
    common = {nt for nt in keys_of if lower.get(nt, 0) >= COMMON_WORD_POSTS}
    keys_of = {nt: k for nt, k in keys_of.items() if nt not in common}
    by_first = {}
    for nt in keys_of:
        by_first.setdefault(nt[0], []).append(nt)
    out = posts["company_key"].copy()
    todo = posts.index[~has_key]
    zero = several = ambiguous = filled = 0
    gained = {}
    for i in todo:
        found = names_in(f"{posts.at[i, 'title']} {posts.at[i, 'description']}", by_first)
        if not found:
            zero += 1
        elif len(found) > 1:
            several += 1
        else:
            (nt,) = found
            if len(keys_of[nt]) != 1:
                ambiguous += 1
                continue
            (key,) = keys_of[nt]
            out.at[i] = key
            filled += 1
            gained[display[nt]] = gained.get(display[nt], 0) + 1
    names = {k: display[nt] for nt, ks in keys_of.items() for k in ks}   # company_key -> display name, for the ledger of straddling groups
    ledger = {"key_names": names, "posts": len(posts), "with_profile_key": int(has_key.sum()), "profile_names": len(keys_of) + len(common), "common_word_names_dropped": len(common), "profile_posts_with_a_name": int(named.sum()),
              "profile_less": len(todo), "keyed": filled, "no_name_found": zero, "several_names_found": several, "ambiguous_name": ambiguous,
              "new_groups_by_size": sorted(gained.items(), key=lambda kv: (-kv[1], kv[0]))}
    return out, ledger


def keep_by_priority(frozen_split, key):
    """Straddling company groups among frozen rows: returns a boolean Series (index of `frozen_split`) that is True for the rows to DROP.
    frozen_split = each row's frozen split (NaN where not frozen), key = its company_key. In a group that holds frozen rows of more than one
    split, the rows of the highest-priority split stay (test > val > train) and the frozen rows of the others are dropped (D-v3.4: the
    splits-v2 precedent of dropping the train side, extended so a test row never moves). Rows that are not frozen are never dropped here."""
    rank = {"test": 3, "val": 2, "train": 1}
    r = frozen_split.map(rank)
    top = r.groupby(key[key != ""]).transform("max").reindex(frozen_split.index)
    nsplit = frozen_split.groupby(key[key != ""]).transform("nunique").reindex(frozen_split.index)
    return (key != "") & frozen_split.notna() & (nsplit > 1) & (r < top)
