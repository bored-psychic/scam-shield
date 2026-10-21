import math
from shield.contracts import Level

# The 0-100 risk score (decision D24, docs/decisions/README.md). A warning-sign meter, NOT a probability: 82 does not mean "82% likely to be a
# scam" (the MuRIL head's score is temperature-scaled on val, D27, but the meter is a piecewise map of it, and the TF-IDF baseline is not calibrated).
# It is a deterministic function of things already in the Report: the FINAL level, the text model's score, its two cut-offs and, for a head that
# declares them, its meter ends. Computed here and nowhere else; the frontend only draws it.
#
#   1. base: the text score p mapped piecewise through (Suspicious cut-off -> 30, Likely-scam cut-off -> 70) and the two ends:
#        no meter ends (TF-IDF baseline, D24 as built): linear in p, ends 0 -> 0 and 1 -> 100
#        meter ends (p0, p100) (MuRIL, D27): linear in log-odds, ends p0 -> 0 and p100 -> 100 (the 1st / 99th percentile of the head's val
#        scores), flat beyond them. In p the curve would squeeze 0.44-1 into 70-100; in log-odds the number follows how far past a cut-off it is
#   2. rounded, then CLAMPED into the band of the final level (so the score can never contradict the level)
#
#   level                  band    why
#   No warning signs       0-29    below the first cut-off
#   Suspicious             30-69
#   Likely scam            70-100
#   Promotional (dormant)  0-29    only the sender rule sets it, and only when nothing hard-risk was found, so it is a no-warning verdict whose
#                                  sender says "registered marketing". It is not 0 (the wording may still look like a scam, as many genuine
#                                  offers do: the model score still moves it inside the band) and not above 29 (it must never look like a warning)
#   Can't judge            none    no score is shown (null)
#
# A rule or link signal that raised the level above what the text score alone says (OTP rule, a phishing list, a red flag) lifts the number to the
# band floor through the clamp; a P1 lowering (a brand-owned link) holds it at the band ceiling the same way. No text score (a bare link): the band floor.
BANDS = {Level.NO_WARNING_SIGNS: (0, 29), Level.SUSPICIOUS: (30, 69), Level.LIKELY_SCAM: (70, 100), Level.PROMOTIONAL: (0, 29)}
SUSPICIOUS_AT, LIKELY_AT = 30, 70   # the score at the model's two cut-offs: the first point of the Suspicious and of the Likely scam band


def _logit(p: float) -> float:
    p = min(max(p, 1e-9), 1 - 1e-9)   # a 3-decimal score can be 0.000 or 1.000
    return math.log(p / (1 - p))


def curve(p: float, lo: float, hi: float, ends: tuple[float, float] | None = None) -> float:
    """The model score p (0-1) on the 0-100 scale, where lo / hi are the text model's two cut-offs. ends None: linear between (0,0), (lo,30),
    (hi,70), (1,100). ends (p0, p100): linear in log-odds between (p0,0), (lo,30), (hi,70), (p100,100), clamped to 0 / 100 outside."""
    assert 0 < lo < hi < 1, f"cut-offs must satisfy 0 < {lo} < {hi} < 1"
    if ends is not None:
        p0, p100 = ends
        assert 0 < p0 < lo and hi < p100 < 1, f"meter ends must satisfy 0 < {p0} < {lo} and {hi} < {p100} < 1"
        x, a, b = _logit(p), _logit(lo), _logit(hi)
        if x <= a:
            return SUSPICIOUS_AT * min(max((x - _logit(p0)) / (a - _logit(p0)), 0.0), 1.0)
        if x <= b:
            return SUSPICIOUS_AT + (LIKELY_AT - SUSPICIOUS_AT) * (x - a) / (b - a)
        return LIKELY_AT + (100 - LIKELY_AT) * min(max((x - b) / (_logit(p100) - b), 0.0), 1.0)
    p = min(max(p, 0.0), 1.0)
    if p <= lo:
        return SUSPICIOUS_AT * p / lo
    if p <= hi:
        return SUSPICIOUS_AT + (LIKELY_AT - SUSPICIOUS_AT) * (p - lo) / (hi - lo)
    return LIKELY_AT + (100 - LIKELY_AT) * (p - hi) / (1 - hi)


def risk_score(level: Level, text_score: float | None, thresholds: tuple[float, float] | None,
               ends: tuple[float, float] | None = None) -> int | None:
    """The 0-100 score for a message Report with this final level, or None for Can't judge. ends: the text head's meter ends (curve())."""
    if level not in BANDS:
        return None
    floor, ceiling = BANDS[level]
    if text_score is None or thresholds is None:
        return floor
    base = math.floor(curve(text_score, *thresholds, ends) + 0.5)   # half up, not Python's banker's rounding: the same input always gives the same number
    return min(max(base, floor), ceiling)
