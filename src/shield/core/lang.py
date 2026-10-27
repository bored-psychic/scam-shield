import re, unicodedata
from textprep import URL_TOKEN, replace_urls

# Which language a message is written in, by script and a small word list. No dependency, no model, nothing stored: it exists for one purpose, the
# D5 language cap (shield.core.router.apply_language_cap).
#
# D5 (docs/decisions/D5_operating_point.md, section 6), quoted: "Language cap. One global pair of cut-offs. Where no real dev data exists (Hindi,
# Kannada, Hinglish), the text model alone can reach at most Suspicious. The cap lifts once real-dev has >= 150 independent hard-legit messages in
# that language. Link evidence and checked rules are unaffected." D6 (docs/decisions/README.md) labels the same languages experimental.
#
# detect_lang(text) -> "en" | "hi" | "kn" | "hinglish" | "unknown"
#   hi        Devanagari is at least NATIVE_SHARE of the letters (a Hindi message with English brand names still counts: the text head is as untested on it)
#   kn        Kannada script, same rule; if both scripts are present the larger wins
#   hinglish  Latin script with Hindi function words: at least 2 distinct list hits and the hits are at least HINGLISH_SHARE of the words
#   en        any other text with Latin letters (also other Latin-script languages: the label means "not one of the capped languages")
#   unknown   no letters at all (emoji only, numbers only, a bare link), or the letters are mostly another script (Tamil, Arabic, ...)
# The share is counted over letters and vowel signs, so digits, punctuation, emoji, links and mask tokens (<URL>, <PHONE> ...) do not move it.
# It is a heuristic with known errors (a Hinglish message that avoids the list reads "en"; Marathi in Devanagari reads "hi"); an error towards
# "en" leaves today's behaviour, an error towards a capped language only turns a Likely scam from the text model alone into Suspicious.
NATIVE_SHARE = 0.20
HINGLISH_SHARE = 0.15
HINGLISH_MIN_HITS = 2

_DEVANAGARI = (0x0900, 0x097F)
_KANNADA = (0x0C80, 0x0CFF)
_NOT_LETTERS = set(range(0x0966, 0x0970)) | {0x0964, 0x0965, 0x0970} | set(range(0x0CE6, 0x0CF0))   # Devanagari / Kannada digits, danda signs, abbreviation sign
_MASK_TOKEN = re.compile(r"<[A-Z_]+>")
_WORD = re.compile(r"[a-z]+")

# Hindi written in Latin letters. Only words that are not also common English words: "me", "to", "do", "hi", "ho", "na", "band", "ji", "main", "par",
# "kar" are left out (an English "to" or "do" must not count). A short list is enough because the rule needs two distinct hits and a share of the words.
HINGLISH_WORDS = frozenset("""
hai hain tha thi hoga hogi honge gaya gayi gaye kiya kiye kare karen karein karo kijiye kijiyega kripya
aap aapka aapki aapke aapko apna apni apne hum humara hamara tum tumhara mera meri mere unka unki iska iski
ka ki ke ko se mein pe tak bhi nahi nahin nhi aur ya lekin magar kyunki kyonki agar warna toh
kya kyun kab kaise kahan kaun kitna kitne kitni
abhi turant jaldi sirf bas bahut thoda zyada
khata khate paisa paise rupaye rupay rashi
jayega jayegi jaega jaegi jaenge chalu wapas vapas bhej bhejo bhejein bheje bhejna
dhanyavaad dhanyavad shukriya namaste sahi galat suraksha
sakte sakta sakti milega milegi milenge milna lijiye dijiye batayein batao bataye
""".split())


def _counts(text):
    """(devanagari, kannada, latin, other) letter counts of text with links and mask tokens removed."""
    text = _MASK_TOKEN.sub(" ", replace_urls(text).replace(URL_TOKEN, " "))
    dev = kan = lat = other = 0
    for ch in text:
        cp = ord(ch)
        if cp in _NOT_LETTERS:
            continue
        if _DEVANAGARI[0] <= cp <= _DEVANAGARI[1]:
            dev += 1
        elif _KANNADA[0] <= cp <= _KANNADA[1]:
            kan += 1
        elif ch.isascii():
            lat += ch.isalpha()
        elif ch.isalpha() or unicodedata.category(ch).startswith("M"):
            other += 1   # a letter of another script (or a combining mark of one); emoji and symbols are neither
    return dev, kan, lat, other, text


def detect_lang(text):
    dev, kan, lat, other, cleaned = _counts(text or "")
    total = dev + kan + lat + other
    if total == 0:
        return "unknown"
    if max(dev, kan) / total >= NATIVE_SHARE:
        return "hi" if dev >= kan else "kn"
    if other / total > 0.5:
        return "unknown"
    words = _WORD.findall(cleaned.lower())
    hits = {w for w in words if w in HINGLISH_WORDS}
    n_hits = sum(1 for w in words if w in HINGLISH_WORDS)
    if len(hits) >= HINGLISH_MIN_HITS and n_hits / len(words) >= HINGLISH_SHARE:
        return "hinglish"
    return "en" if lat else "unknown"


# The reason line the cap adds (D5 + D6), in the three UI languages. The English line is the one in Report.reasons / the evidence title. The Hindi and
# Kannada lines are the model's wording, NOT checked by a native speaker (LANG_CAP_NEEDS_REVIEW, D15, D17): the Report carries only the English
# (the contract is unchanged), so showing hi / kn is frontend work (D17), which reads these three strings and must show the review mark.
LANG_CAP_LINE = {
    "en": "This language is less tested; treat this as a warning, not a verdict.",
    "hi": "इस भाषा में जाँच कम हुई है; इसे चेतावनी मानें, अंतिम निर्णय नहीं।",
    "kn": "ಈ ಭಾಷೆಯಲ್ಲಿ ಪರೀಕ್ಷೆ ಕಡಿಮೆ ನಡೆದಿದೆ; ಇದನ್ನು ಎಚ್ಚರಿಕೆ ಎಂದು ಪರಿಗಣಿಸಿ, ಅಂತಿಮ ತೀರ್ಪು ಅಲ್ಲ.",
}
LANG_CAP_NEEDS_REVIEW = {"en": False, "hi": True, "kn": True}
