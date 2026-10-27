import re, unicodedata
from pii import UPI_HANDLES

# D11 (docs/decisions/README.md): the folded view of a message, for the RULES and the lexicons only (OTP / PIN / CVV, PIN-to-receive, investment A1-A12,
# tactic tags, fear cues). The models keep reading textprep.model_text (rule 11), the folded view never reaches one and is never stored. lang.detect_lang
# stays on the raw text.
#
# fold(text) -> (folded, FoldMap). What it does, in order, per character:
#   1. drops invisible characters: zero-width space / joiners, word joiner, BOM, soft hyphen, bidi marks, variation selectors, tag characters ...
#      ZWJ / ZWNJ are kept next to Devanagari or Kannada, where they are part of the spelling;
#   2. leaves Devanagari and Kannada (and their extension blocks) exactly as they are: no NFKC, no folding;
#   3. NFKC (fullwidth, mathematical bold / italic, circled and compatibility forms become plain letters), then the CONFUSABLE table (Cyrillic, Greek,
#      Latin small capitals and a few Latin look-alikes -> ASCII), then accents on a Latin letter are dropped (e + U+0301, "e" with an acute -> e);
#   4. leet, inside a token (a run of ASCII letters, digits, @ and $) that holds at least two letters: 0 -> o, 3 -> e, 4 -> a, 5 -> s, 1 -> i or l (whichever makes a
#      word the rules know, i otherwise: "p1n", "c1ick", "cla1m"), @ -> a between letters ("sh@re", "p@$$word"), $ -> s inside or after a letter or in front of a lower-case letter
#      ("$hare"); and "R5 5000" / "R$ 3,000" -> "Rs". A single digit between letters is leet. A run of digits is leet only if it is at most 3 long, every digit
#      of it is 0 1 3 4 or 5 and the token has at least as many letters as the run has digits ("p455w0rd", "53nd"; a run of three only between letters); anything else is a number and stays. Never
#      in a pure number, so amounts (Rs 5,000, Rs5000, 10am), OTP codes, phone numbers, account numbers and times are untouched. Not inside a UPI id (a known
#      NPCI handle after the @, or @valid...), an e-mail address or a link; not in a number with its unit ("4hrs", "5th", "3pm", "2x"). A word-initial
#      "@name" is a mention and stays, unless "a" + name is a word the rules look for ("@ccount", "@pk": see _leet_initial_at).
# The folded text is NOT lower-cased and keeps its length per character (a removed character is simply gone, a compatibility character such as the
# ligature "fi" may become two), so FoldMap maps every folded character back to the character(s) of the original that made it: any match on the folded
# text can be shown on the user's own text.

_INVISIBLE = ({0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x2028, 0x2029, 0x3164, 0xFEFF, 0xFFA0}
              | set(range(0x180B, 0x180E)) | set(range(0x200B, 0x2010)) | set(range(0x202A, 0x202F)) | set(range(0x2060, 0x2070))
              | set(range(0xFE00, 0xFE10)) | set(range(0xE0000, 0xE0080)))
_JOINERS = {0x200C, 0x200D}   # kept next to an Indic letter

# Devanagari, Kannada, Devanagari Extended, Vedic Extensions: never folded.
def _indic(ch):
    o = ord(ch)
    return 0x0900 <= o <= 0x097F or 0x0C80 <= o <= 0x0CFF or 0xA8E0 <= o <= 0xA8FF or 0x1CD0 <= o <= 0x1CFF

# Look-alike letters (after NFKC) -> Latin. Explicit and small on purpose; Cyrillic and Greek capitals / small letters that are drawn like a Latin
# letter, Latin small capitals ("ꜱʜᴀʀᴇ"), and a few Latin letters (dotless i, script g, stroked l / o).
_PAIRS = (
    "АA ВB ЕE КK МM НH ОO РP СC ТT УY ХX ІI ЈJ ЅS ԜW ԚQ ҮY ԌG "                      # Cyrillic capitals
    "аa еe оo рp сc уy хx іi јj ѕs һh ԁd ԛq ԝw кk мm тt ԍg ӏl "                      # Cyrillic small letters
    "ΑA ΒB ΕE ΖZ ΗH ΙI ΚK ΜM ΝN ΟO ΡP ΤT ΥY ΧX "                                    # Greek capitals
    "οo νv αa ιi κk ρp τt υu χx εe ηn μu γy "                                        # Greek small letters
    "ᴀa ʙb ᴄc ᴅd ᴇe ꜰf ɢg ʜh ɪi ᴊj ᴋk ʟl ᴍm ɴn ᴏo ᴘp ʀr ꜱs ᴛt ᴜu ᴠv ᴡw ʏy ᴢz "      # Latin small capitals
    "ıi ɑa ɡg ɩi ſs ɭl ȷj øo łl đd ħh ɔc ɛe")                                       # other Latin look-alikes
CONFUSABLE = {p[0]: p[1] for p in _PAIRS.split()}

_LEET = {"0": "o", "3": "e", "4": "a", "5": "s"}
_LEET_CHARS = set("01345@$")
_TOKEN = re.compile(r"[A-Za-z0-9@$]+")
_UNITS = r"(?:am|pm|hrs?|hours?|mins?|secs?|k|l|cr|lakhs?|x|gb|mb|kb|kg|km|cm|mm|g|d|days?|weeks?|months?|yrs?|years?|yo|th|s|%)"
# A number with its unit or ordinal ("4hrs", "10am", "5th", "1st", "22nd", "2x", "500gb"): not leet.
_QUANTITY = re.compile(rf"^\d+{_UNITS}$|^(?:\d*1st|\d*2nd|\d*3rd)$", re.I)
_CURRENCY = re.compile(r"^(?:rs|inr|usd|usdt|eur)\d+$|^\d+(?:rs|inr|usdt|usd)$", re.I)
# A link (or a bare domain with a path or port): its characters are not touched.
_URLISH = re.compile(r"://|^www\.|[\w-]\.[a-z]{2,}(?:[/?#]|:\d|$)")
_UPI_HANDLE = re.compile(r"(?i)^(?:%s|valid[a-z]*)$" % "|".join(UPI_HANDLES))


class FoldMap:
    """Maps folded character positions back to the original text. starts[i] / ends[i] = the original [start, end) the folded character i came from."""
    __slots__ = ("starts", "ends", "n")

    def __init__(self, starts, ends, n):
        self.starts, self.ends, self.n = starts, ends, n   # n = len(original)

    def span(self, s, e):
        """The original (start, end) of the folded span [s, e): from the first character's origin to the last one's."""
        if e <= s:
            at = self.starts[s] if s < len(self.starts) else self.n
            return at, at
        return self.starts[s], self.ends[e - 1]


def _fold_chars(text):
    """Steps 1-3: (chars, starts, ends), one entry per folded character."""
    out, st, en = [], [], []
    n = len(text)
    for i, ch in enumerate(text):
        o = ord(ch)
        if o in _INVISIBLE:
            if o in _JOINERS and ((i and _indic(text[i - 1])) or (i + 1 < n and _indic(text[i + 1]))):
                out.append(ch); st.append(i); en.append(i + 1)
            continue
        if _indic(ch) or o < 128:
            out.append(ch); st.append(i); en.append(i + 1)
            continue
        for c in unicodedata.normalize("NFKC", ch):
            c = CONFUSABLE.get(c, c)
            if ord(c) >= 128:
                if unicodedata.category(c) == "Mn":
                    if out and out[-1].isascii() and out[-1].isalpha():
                        continue   # a combining accent on a Latin letter
                else:
                    d = unicodedata.normalize("NFKD", c)
                    base = CONFUSABLE.get(d[0], d[0])
                    if base.isascii() and base.isalpha() and all(unicodedata.category(x) == "Mn" for x in d[1:]):
                        c = base   # a Latin letter with an accent (also a Cyrillic yo, Greek alpha with tonos ...)
            out.append(c); st.append(i); en.append(i + 1)
    return out, st, en


_ONE = "\x01"   # marks a leet 1 until its word is known

def _letterish(c):
    return bool(c) and (c.isalpha() or c in "@$" or c == _ONE)

# Words the rules look for: the lower-case words in the rules' own patterns (the lexicons this fold serves), read once, plus common words. Two uses, both
# only to choose between readings of an ambiguous character, never to rewrite a word into another: a word-initial "@" is leet ("@ccount", "@nd") only if
# "a" + the rest is such a word (a mention like "@telegram" or "@amazon" is not), and a "1" is read as "i" or "l" by whichever makes a known word ("p1n" and
# "c1ick", but "cla1m" and "a1l" too), "i" when neither does.
_COMMON = {"and", "any", "are", "all", "also", "after", "again", "about", "above", "ask", "asked", "at", "as", "an", "app", "apps", "apk", "account", "accounts", "access",
           "act", "action", "activate", "add", "added", "address", "advance", "agent", "alert", "allotment", "allocation", "amount", "apply", "approve", "approved",
           "arrest", "assured", "authority", "available", "avoid", "aadhaar", "aadhar", "amazon", "apple", "airtel", "axis", "will", "call", "bill", "block", "blocked",
           "click", "link", "login", "legal", "limited", "claim", "failed", "help", "fill", "still", "final", "official", "notice", "offer", "online", "update",
           "verify", "invest", "pin", "otp", "kyc", "lakh", "refund", "win", "won", "prize", "winner", "bank", "pay", "paid", "payment", "within", "immediately"}
_TWO = {"be", "to", "do", "go", "no", "so", "he", "we", "me", "of", "on", "or", "as", "at", "an", "is", "it", "in", "if", "up", "my", "by", "oh", "ok"}
_WORDS = []

def _words():
    if not _WORDS:
        from shield.messages import invest_rules, rules, tactics, threats   # lazy: these modules do not import this one, but the router imports both
        pats = []
        for mod in (rules, tactics, invest_rules, threats):
            for v in vars(mod).values():
                for x in (v.values() if isinstance(v, dict) else v if isinstance(v, (list, tuple)) else [v]):
                    pats.append(x.pattern if isinstance(x, re.Pattern) else x if isinstance(x, str) and len(x) > 8 else "")
        stems = {w for p in pats for w in re.findall(r"[a-z]{3,}", re.sub(r"\\[a-zA-Z]", " ", p.lower()))}
        _WORDS.extend(sorted(stems | _COMMON))
    return _WORDS

def _known(w):
    w = w.lower()
    return any(w == st or (len(st) >= 4 and w.startswith(st)) for st in _words())

def _leet_initial_at(rest):
    """Whether "@" + rest (the letters after a word-initial "@") reads as an 'a' word the rules know."""
    return rest.isalpha() and _known("a" + rest)

def _read_ones(word, one="1"):
    """word: letters and `one` characters (already otherwise folded). Each `one` becomes 'i' or 'l': the reading that is a known word, 'i' if none is."""
    k = word.count(one)
    if k == 0 or k > 3:
        return word.replace(one, "i")
    for pick in range(1 << k):
        cand, n = [], 0
        for c in word:
            if c == one:
                cand.append("l" if (pick >> n) & 1 else "i")
                n += 1
            else:
                cand.append(c)
        if _known("".join(cand)):
            return "".join(cand)
    return word.replace(one, "i")


# "Rs" with its s swapped for a leet character, in front of an amount: "R5 5000", "R$ 3,000", "R$5000".
_RS = re.compile(r"^[Rr][5$]\d*$")

def _leet_token(chars, a, b, after):
    """Fold the leet characters of the token chars[a:b] in place (see the module comment). after: the characters right after the token."""
    tok = "".join(chars[a:b])
    if _RS.match(tok) and (len(tok) > 2 or (after[:1] == " " and after[1:2].isdigit()) or after[:1].isdigit()):
        chars[a + 1] = "s"
        return
    letters = sum(c.isalpha() for c in tok)
    if len(tok) == 2 and letters == 1:   # "t0", "b3", "0n", "1s": a two-letter word with one leet character
        word = _read_ones("".join(_LEET.get(c, c) for c in tok))
        if word.lower() in _TWO and word != tok:
            chars[a:b] = list(word)
        return
    if letters < 2 or _QUANTITY.match(tok) or _CURRENCY.match(tok) or re.search(r"\d{4}", tok):
        return   # needs two letters; not a number with its unit; not an id with a long number in it (a message id, an order number)
    if "@" in tok:
        handle = tok[tok.rindex("@") + 1:]
        if _UPI_HANDLE.match(handle) or (after[:1] == "." and after[1:2].isalpha()):
            return   # a UPI id or an e-mail address
    orig = chars[a:b]
    for k in range(a, b):   # digits first
        c, prev, nxt = orig[k - a], orig[k - a - 1] if k > a else "", orig[k - a + 1] if k + 1 < b else ""
        if c not in _LEET and c != "1":
            continue
        if not nxt and not prev.isdigit() and letters <= 3 and sum(x in _LEET_CHARS for x in orig) == 1:
            continue   # "CB1", "EH1", "SB1": a short id with one digit at the end, not a word with a leet last letter
        if prev.isdigit() or nxt.isdigit():
            # a run of digits: leet only if it is short, every digit of it is leet, and the token has at least as many letters as the run has digits
            lo = k - a
            while lo and orig[lo - 1].isdigit():
                lo -= 1
            hi = k - a
            while hi + 1 < len(orig) and orig[hi + 1].isdigit():
                hi += 1
            run = orig[lo:hi + 1]
            if len(run) > 3 or any(d not in _LEET_CHARS for d in run) or letters < len(run) or (len(run) == 3 and (lo == 0 or hi == len(orig) - 1)):
                continue   # part of a number (OTP482913, XX1234, ab12, 151OFF); a run of three is leet only inside a word ("p455w0rd")
        chars[k] = _ONE if c == "1" else _LEET[c]   # a '1' is decided below, once the rest of its word is folded
    for k in range(a, b):   # then the symbols, next to what the digits became
        c, prev, nxt = orig[k - a], chars[k - 1] if k > a else "", chars[k + 1] if k + 1 < b else ""
        if c == "@" and not prev and nxt and _leet_initial_at("".join(orig[k - a + 1:])):
            chars[k] = "a"   # "@ccount", "@nd"
        elif c == "@" and _letterish(prev) and (_letterish(nxt) or (not nxt and after[:1] not in (".", "") and not after[:1].isalnum() and letters >= 2)):
            chars[k] = "a"   # "sh@re", "p@$$word", a word-final "dat@"; a word-initial "@name" is a mention and stays
        elif c == "$" and ((_letterish(prev) and not nxt.isdigit()) or (not prev.isalnum() and nxt.islower())):
            chars[k] = "s"   # "pa$$word", "$hare"; "$5" is money and "$BTC" a ticker, and stay
    if _ONE in chars[a:b]:   # now the ones: each reads as i or l, whichever makes a known word of the letters around it
        k = a
        while k < b:
            if chars[k] == _ONE or chars[k].isalpha():
                e = k
                while e < b and (chars[e] == _ONE or chars[e].isalpha()):
                    e += 1
                if _ONE in chars[k:e]:
                    chars[k:e] = list(_read_ones("".join(chars[k:e]), _ONE))
                k = e
            else:
                k += 1


def fold(text):
    """(folded, FoldMap) for the text: see the module comment. fold("") == ("", ...)."""
    text = text or ""
    chars, st, en = _fold_chars(text)
    s = "".join(chars)
    if any(c in _LEET_CHARS for c in s):
        for chunk in re.finditer(r"\S+", s):
            word = chunk.group(0)
            if not any(c in _LEET_CHARS for c in word) or _URLISH.search(word.rstrip(".,;:!?)")):
                continue
            for m in _TOKEN.finditer(word):
                if any(c in _LEET_CHARS for c in m.group(0)):
                    e = chunk.start() + m.end()
                    _leet_token(chars, chunk.start() + m.start(), e, s[e:e + 2])
        s = "".join(chars)
    return s, FoldMap(st, en, len(text))


# ---------------------------------------------------------------- the reason line (EN / HI / KN)
# One reason, shown when a rule or tactic fires on the folded text but did not fire on the raw text. Hindi and Kannada are drafts for the native-speaker
# review (D15), marked needs-review like shield.core.lang.LANG_CAP_LINE; the Report carries the English line only (the contract is unchanged).
FOLD_LINE = {"en": "Hidden or look-alike characters were used to disguise the wording.",
             "hi": "शब्दों को छिपाने के लिए छिपे हुए या मिलते-जुलते अक्षरों का इस्तेमाल किया गया है।",
             "kn": "ಪದಗಳನ್ನು ಮರೆಮಾಡಲು ಗುಪ್ತ ಅಥವಾ ಹೋಲುವ ಅಕ್ಷರಗಳನ್ನು ಬಳಸಲಾಗಿದೆ."}
FOLD_NEEDS_REVIEW = {"en": False, "hi": True, "kn": True}
FOLD_TAG = "Disguised text"   # radar label (<= 24 characters)
