LEVELS = ["No warning signs found", "Suspicious", "Likely scam"]   # level 0 is never called "Safe": it only means nothing strong was found

r3 = lambda x: round(float(x), 3)
def level_of(score, lo, hi):
    """Scores and cut-offs are shown to 3 decimals, so they are compared at 3 decimals: the level can then never contradict the numbers
    on screen (a score shown as 0.428 against 'Suspicious from 0.428' is Suspicious). Moves a cut-off by at most 0.0005."""
    return 0 if score < lo else (1 if score < hi else 2)


def fuse(text_level, url_level):
    """Placeholder until the fusion model exists: the higher of the two heads' levels, and if both heads are at least Suspicious
    the evidence agrees, so Likely scam. Either head alone can raise a flag; neither can clear the other."""
    levels = [l for l in (text_level, url_level) if l is not None]
    if not levels:
        return None
    return 2 if len(levels) == 2 and min(levels) >= 1 else max(levels)
