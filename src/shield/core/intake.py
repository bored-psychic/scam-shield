"""Which engine does a pasted text belong to? (docs/plans/multi_input.md section 2.1, decision D29, W1.)

classify(text) -> "message" | "link" | "upi_id" | "qr"

It routes only the inputs the message engine cannot read anyway: a text with fewer than router.MIN_PROSE_WORDS prose words (the router calls such a
text Can't judge: the text head has nothing to read). Anything with more words around it is "message", and so is any request-shaped text
("x@ybl is requesting Rs 500 ..."): eval_real.py scores router.analyse on messages, so a message that the real test set could contain must never be
routed away from the engine that was measured (CLAUDE.md rule 12, plan 2.1). Nothing here reads the network or the models; it is string work only.

  link    exactly one link (textprep.extract_urls) and fewer than MIN_PROSE_WORDS prose words once links are removed (router.prose_word_count), i.e.
          what today's router calls a bare link
  upi_id  the whole text, trimmed, is one UPI ID: pii.mask_text (the v2 masks every shipped head was trained on) turns it into the single token
          <UPI_ID>. The ID's own letters ("rajesh.kumar@oksbi" has three) are not prose, so the word count does not apply
  qr      the whole text is one upi:// payment string, with no whitespace in it (a real upi:// URI percent-encodes spaces)

W1 only labels: /api/analyse and /api/check still send upi_id and qr texts through the message engine and report input "message" (there is no payments
engine until W3). pii.UPI_HANDLES has no recorded source (plan 2.6), which is fine for routing: a wrong guess costs a label, never a verdict.
"""
from typing import Literal

from pii import mask_text
from textprep import extract_urls
from shield.core.router import MAX_TEXT_CHARS, MIN_PROSE_WORDS, prose_word_count

Classified = Literal["message", "link", "upi_id", "qr"]
UPI_SCHEME = "upi://"
_UPI_TOKEN = "<UPI_ID>"


def classify(text: str | None) -> Classified:
    s = (text or "")[:MAX_TEXT_CHARS].strip()   # the same cut analyse() makes first
    if not s:
        return "message"
    if s[:len(UPI_SCHEME)].lower() == UPI_SCHEME and not any(c.isspace() for c in s):
        return "qr"
    if "@" in s and mask_text(s) == _UPI_TOKEN:   # "@" first: the literal text "<UPI>" or "<UPI_ID>" is not an ID
        return "upi_id"
    if prose_word_count(s) < MIN_PROSE_WORDS and len(extract_urls(s)) == 1:
        return "link"
    return "message"
