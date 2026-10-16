"""JSON API for the web frontend (D9): POST /api/analyse -> Report v2, GET /api/health.

Run (from anywhere; models are found relative to the project root):
    uvicorn shield.api.main:app --host 127.0.0.1 --port 8000

Local-first (docs/ARCHITECTURE.md §1, §5.4): the pasted text is analysed in memory and never logged, printed or written to disk, and an
analysis makes no outbound network call (links are parsed as strings, never fetched). There is no request-body logging, no docs/openapi
page, and CORS admits only the Vite dev server. uvicorn's own access log shows the method, path and status, never the body.
"""
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict

from shield.contracts import SCHEMA_VERSION
from shield.core.report import to_report
from shield.core.router import analyse
from shield.links.lexical import load_url_model
from shield.messages.text_head import load_text_model

MAX_TEXT_CHARS = 20000   # same cap as router.MAX_TEXT_CHARS, but here an over-long message is refused, not silently cut
ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]   # the Vite dev server


class AnalyseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.text_model = load_text_model()   # once per process, not per request
    app.state.url_model = load_url_model()
    yield


app = FastAPI(title="Scam Shield API", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["GET", "POST"],
                   allow_headers=["Content-Type"])   # a JSON POST is preflighted, and the preflight asks for content-type


@app.get("/api/health")
def health():
    return {"status": "ok", "schema_version": SCHEMA_VERSION}


@app.post("/api/analyse")
def analyse_message(body: AnalyseRequest, request: Request):
    text = body.text
    if not text.strip():
        raise HTTPException(status_code=422, detail="Paste a message to check.")
    if len(text) > MAX_TEXT_CHARS:
        raise HTTPException(status_code=422, detail="Message is too long (max 20,000 characters).")
    t0 = time.perf_counter()
    try:
        rep = to_report(text, analyse(text, request.app.state.text_model, request.app.state.url_model))
    except Exception:
        # `from None`: an exception raised while reading the text can carry that text in its message (a pydantic error prints its input),
        # and uvicorn would write the chained traceback to the log. Nothing the user pasted may reach a log.
        raise HTTPException(status_code=500, detail="The analysis failed.") from None
    rep.meta.ms = round((time.perf_counter() - t0) * 1000, 1)
    return rep.model_dump(mode="json")
