"""JSON API for the web frontend (D9): POST /api/analyse {text, sender?, live?, expand?} -> Report v6 (message text; a bare link is labelled input "link"),
POST /api/check {kind, text?, subject?, body?, sender?, live?, expand?} -> Report v6 for the tabs (W1: auto / message / link / email; every other kind is 501
until its engine exists), POST /api/ocr -> the text of a screenshot, GET /api/health.

Run (from anywhere; models are found relative to the project root):
    uvicorn shield.api.main:app --host 127.0.0.1 --port 8000

Local-first (docs/ARCHITECTURE.md §1, §5.4): the pasted text and the optional sender (D22) are analysed in memory and never logged, printed or written to disk.
The first, offline analysis makes no outbound network call; the live link checks (live: true, D23) send only a registered domain to the allowlisted
services in shield/core/net.py (CLAUDE.md rule 8), the expand button only the short link to its shortener, and no link is ever fetched. The page
makes the offline call first and then the live one, so the verdict appears at once. There is no request-body logging, no docs/openapi
page, and CORS admits only the Vite dev server. uvicorn's own access log shows the method, path and status, never the body.
A screenshot (D19) is read the same way: in memory, by a local Tesseract process over a pipe, never stored (shield/ocr/reader.py,
shield/api/upload.py); the text goes back to the page, which lets the user check it before it is sent to /api/analyse.
"""
import time
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from starlette.concurrency import run_in_threadpool

from shield.api.upload import BadUpload, UploadTooLarge, read_part
from shield.config import model_versions
from shield.contracts import SCHEMA_VERSION
from shield.core import net
from shield.core.intake import classify
from shield.core.report import to_report
from shield.core.router import analyse
from shield.links.gambling import load_gambling
from shield.links.lexical import load_url_model
from shield.links.lists import warm as warm_lists
from shield.links.platforms import SHORTENERS, suffix_match
from textprep import extract_urls
from url_features import parse_url
from shield.messages.text_head import load_text_model
from shield.ocr.reader import MAX_BYTES as MAX_IMAGE_BYTES, ImageRejected, ImageTooLarge, OcrUnavailable, UnsupportedImage, read_image

MAX_TEXT_CHARS = 20000   # same cap as router.MAX_TEXT_CHARS, but here an over-long message is refused, not silently cut
MAX_URLS = 10            # router.MAX_URLS: the links analyse() extracts
ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]   # the Vite dev server


class AnalyseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str
    # D22: what the user's phone showed as the sender, optional. Treated exactly like the text: in memory only, never logged or stored, nothing
    # looked up. Absent, null, "" and spaces all mean "no sender" and give the same Report as before D22 (plus "sender": null).
    sender: str | None = None
    # D23: live = run the network link checks (domains only, <= 4 s); expand = short links from this text the user pressed "Where does this
    # short link go?" for (each must be a link of the text and on the shortener list; at most 3). expand needs live.
    live: bool = False
    expand: list[str] = []


CheckKind = Literal["auto", "message", "link", "email", "upi_id", "payment_request", "qr", "payment_proof", "app", "apk"]
BUILT_KINDS = ("auto", "message", "link", "email")   # W1; the payments (W3) and apps (W6) engines fill the rest
NOT_AVAILABLE = "This check is not available yet."
NOT_A_LINK = "Paste a single link to check."
EMAIL_INCOMPLETE = "Add the subject and the body of the email to check."
EMAIL_TOO_LONG = "Paste the part with the request and the links (at most 20,000 characters)."


class CheckRequest(BaseModel):
    """POST /api/check (plan 6.2 / 8.1). Every field except kind is optional because the tabs send different ones; the rules per kind are in check()."""
    model_config = ConfigDict(extra="forbid")
    kind: CheckKind
    text: str | None = None        # auto, message, link
    subject: str | None = None     # email
    body: str | None = None        # email
    sender: str | None = None      # D22, exactly as on /api/analyse (ignored for email: a mail's From belongs to the email engine, W7)
    live: bool = False
    expand: list[str] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.text_model = load_text_model()   # once per process, not per request
    app.state.url_model = load_url_model()
    load_gambling()   # the gambling lookup (362k domains) is read once here, so the first request does not pay for it
    warm_lists()      # D23 link lists (Tranco 1M, blocklists, RDAP bootstrap, the IP -> ASN table), likewise
    net.forbid_updates()   # list downloads belong to src/update_link_lists.py, never to the API process
    model_versions()  # the model-file hashes for Report.meta.models, likewise computed once
    yield


app = FastAPI(title="Scam Shield API", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["GET", "POST"],
                   allow_headers=["Content-Type"])   # a JSON POST is preflighted, and the preflight asks for content-type


@app.get("/api/health")
def health():
    return {"status": "ok", "schema_version": SCHEMA_VERSION}


def _validate_text(text, live, expand):
    """The checks /api/analyse has always made on a message text (fixed messages, nothing from the text in them)."""
    if not text.strip():
        raise HTTPException(status_code=422, detail="Paste a message to check.")
    if len(text) > MAX_TEXT_CHARS:
        raise HTTPException(status_code=422, detail="Message is too long (max 20,000 characters).")
    _validate_expand(text, live, expand)


def _validate_expand(text, live, expand):
    if expand:
        links = extract_urls(text, MAX_URLS)
        if not live or len(expand) > 3 or any(u not in links or not suffix_match(parse_url(u)[0], SHORTENERS) for u in expand):
            raise HTTPException(status_code=422, detail="Only a short link from this message can be revealed.")


def _run(request, text, input_of, sender, live, expand):
    """Analyse `text` and build the Report. input_of(text) names the Report's input (called inside the try, so a failure there is as silent as one in the
    analysis). Nothing the user sent may reach a log: the exception is dropped with `from None`."""
    t0 = time.perf_counter()
    try:
        rep = to_report(text, analyse(text, request.app.state.text_model, request.app.state.url_model, sender=sender, live=live, expand=tuple(expand)),
                        input=input_of(text))
    except Exception:
        # `from None`: an exception raised while reading the text can carry that text in its message (a pydantic error prints its input),
        # and uvicorn would write the chained traceback to the log. Nothing the user pasted may reach a log.
        raise HTTPException(status_code=500, detail="The analysis failed.") from None
    rep.meta.ms = round((time.perf_counter() - t0) * 1000, 1)
    return rep.model_dump(mode="json")


def _message_or_link(text):
    """A bare link is a link; everything else, including a UPI ID or a upi:// string (no payments engine until W3), is checked as a message."""
    return "link" if classify(text) == "link" else "message"


@app.post("/api/analyse")
def analyse_message(body: AnalyseRequest, request: Request):
    _validate_text(body.text, body.live, body.expand)
    return _run(request, body.text, _message_or_link, body.sender, body.live, body.expand)


@app.post("/api/check")
def check(body: CheckRequest, request: Request):
    """One endpoint for the tabs. auto / message: as /api/analyse. link: the same engine, but the text must be one link (422 otherwise). email: subject and
    body through the message engine as "email". Every other kind answers 501 with a fixed message until its engine exists. Same logging rules as
    /api/analyse: no text, subject, body, sender or link is ever logged or put into an error message."""
    if body.kind not in BUILT_KINDS:
        raise HTTPException(status_code=501, detail=NOT_AVAILABLE)
    if body.kind == "email":
        if not (body.subject or "").strip() or not (body.body or "").strip():
            raise HTTPException(status_code=422, detail=EMAIL_INCOMPLETE)
        text = body.subject + "\n\n" + body.body
        if len(text) > MAX_TEXT_CHARS:
            raise HTTPException(status_code=422, detail=EMAIL_TOO_LONG)
        _validate_expand(text, body.live, body.expand)
        return _run(request, text, lambda _: "email", None, body.live, body.expand)
    text = body.text or ""
    _validate_text(text, body.live, body.expand)
    if body.kind == "link":
        try:
            is_link = classify(text) == "link"
        except Exception:
            raise HTTPException(status_code=500, detail="The analysis failed.") from None
        if not is_link:
            raise HTTPException(status_code=422, detail=NOT_A_LINK)
        return _run(request, text, lambda _: "link", body.sender, body.live, body.expand)
    return _run(request, text, _message_or_link, body.sender, body.live, body.expand)


@app.post("/api/ocr")
async def ocr_screenshot(request: Request):
    """multipart field "image" (PNG / JPEG / WEBP, <= 8 MB) -> {"text", "lines", "dropped", "ms"}. The Report contract is not involved:
    the page shows this text for the user to check and then posts it to /api/analyse."""
    too_large = HTTPException(status_code=413, detail="The screenshot is too large (max 8 MB).")
    try:
        data = await read_part(request, "image", MAX_IMAGE_BYTES)
    except UploadTooLarge:
        raise too_large from None
    except BadUpload:
        raise HTTPException(status_code=422, detail="Choose a screenshot to check.") from None
    try:
        res = await run_in_threadpool(read_image, data)   # Tesseract takes about a second and must not block the event loop
    except ImageTooLarge:
        raise too_large from None
    except UnsupportedImage as e:
        raise HTTPException(status_code=415, detail=str(e)) from None
    except ImageRejected as e:
        raise HTTPException(status_code=422, detail=str(e)) from None   # fixed plain-text messages, never anything from the image
    except OcrUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e)) from None
    except Exception:
        # `from None` as in /api/analyse: nothing read from the screenshot may reach a log through a chained traceback.
        raise HTTPException(status_code=500, detail="Reading the screenshot failed.") from None
    if not res["text"]:
        raise HTTPException(status_code=422, detail="No text found in the screenshot.")
    return {"text": res["text"], "lines": res["lines"], "dropped": res["dropped"], "ms": res["ms"]}
