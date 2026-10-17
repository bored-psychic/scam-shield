from enum import Enum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# The one answer shape every module returns (docs/ARCHITECTURE.md §2 "Contracts", docs/decisions/README.md D4). The web app, the JSON API,
# tests and future scorers read a Report and nothing else. Bump SCHEMA_VERSION on any change a consumer would notice.
# v2 (2026-10-17): Evidence.span and Evidence.tag, for the in-message underlines and the radar labels
# v3 (2026-10-18, D22): Report.sender (the sender the user typed, classified) and the level PROMOTIONAL. A v2 reader would reject both (an unknown
# level value; an unknown field under extra="forbid"), hence the bump. With no sender, a v3 Report is the v2 Report plus "sender": null.
SCHEMA_VERSION = "3"


class Level(str, Enum):
    LIKELY_SCAM = "likely_scam"
    SUSPICIOUS = "suspicious"
    NO_WARNING_SIGNS = "no_warning_signs"   # never called "Safe": it only means nothing strong was found
    CANT_JUDGE = "cant_judge"
    PROMOTIONAL = "promotional"             # D22: a registered promotional sender (suffix P) and no hard-risk signal; only ever set by the sender rule

LEVEL_LABEL = {Level.LIKELY_SCAM: "Likely scam", Level.SUSPICIOUS: "Suspicious",
               Level.NO_WARNING_SIGNS: "No warning signs found", Level.CANT_JUDGE: "Can't judge", Level.PROMOTIONAL: "Promotional"}
# CANT_JUDGE and PROMOTIONAL have no rank: they are not points on the scale (Promotional says who sent it, not how risky the words are)
LEVEL_RANK = {Level.NO_WARNING_SIGNS: 0, Level.SUSPICIOUS: 1, Level.LIKELY_SCAM: 2}


class Effect(str, Enum):
    DANGER = "danger"
    CAUTION = "caution"
    NEUTRAL = "neutral"
    REASSURING = "reassuring"
    UNKNOWN = "unknown"

Module = Literal["messages", "links", "transactions", "apps"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Evidence(_Strict):
    id: str = Field(pattern=r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")   # dotted, e.g. "rule.otp_request"
    module: Module
    effect: Effect
    title: str = Field(min_length=1, max_length=120)   # one plain sentence
    detail: str = ""
    quote: str | None = None     # an exact piece of the user's input, if the evidence points at one
    # Where the quote sits in the ORIGINAL input text: [start, end), counted in Unicode code points (Python str indexing, so text[start:end] == quote).
    # JavaScript strings count UTF-16 units, so an emoji before the quote shifts every offset: the frontend must index with Array.from(text), never text.slice().
    span: tuple[int, int] | None = None
    tag: str = Field(min_length=1, max_length=24)   # short radar label, e.g. "OTP request"
    source: str | None = None    # where a fact came from, e.g. "OpenPhish feed, 2026-10-09"
    sent: str | None = None      # what a live check sent out, e.g. "domain xyz.in -> rdap.nixiregistry.in"; None = nothing left the machine

    @model_validator(mode="after")
    def _span_goes_with_quote(self):
        if (self.span is None) != (self.quote is None):
            raise ValueError("span and quote are either both set or both None")
        if self.span is not None and not self.span[0] < self.span[1]:
            raise ValueError("span must have start < end")
        return self


class Meta(_Strict):
    text_score: float | None = None
    text_thresholds: tuple[float, float] | None = None   # (Suspicious from, Likely scam from)
    escalated: bool = False      # raised to Suspicious by the OTP / PIN / CVV rule
    truncated: bool = False      # the text head read only the first MAX_CHARS characters
    lang: str | None = None
    ms: float | None = None
    models: dict[str, str] = {}


class Sender(_Strict):
    """What the sender the user typed was classified as (shield.messages.sender, D22). The raw string is never echoed: a DLT header is a business ID
    and is given back; a mobile number is personal data and only its kind is; anything else ("other") may be a name or an email, so kind only too."""
    kind: Literal["dlt", "dlt_bare", "mobile", "other"]
    suffix: Literal["P", "S", "T", "G"] | None = None   # dlt only; None for dlt without a type letter, dlt_bare, mobile and other
    header: str | None = Field(default=None, pattern=r"^[A-Z0-9]{6}$")   # dlt and dlt_bare only, e.g. "JIOCPN"
    label: str = Field(min_length=1, max_length=60)      # e.g. "Registered business · Promotional", "Personal mobile number", "Not recognised"

    @model_validator(mode="after")
    def _only_business_ids_echoed(self):
        if (self.header is not None) != (self.kind in ("dlt", "dlt_bare")):
            raise ValueError("header is set exactly for dlt and dlt_bare")
        if self.suffix is not None and self.kind != "dlt":
            raise ValueError("only a dlt sender has a suffix")
        return self


class Report(_Strict):
    schema_version: Literal["3"] = "3"
    module: Module
    level: Level
    score: float | None = None
    category: str | None = None
    sender: Sender | None = None   # None: no sender given (and always on a child Report)
    evidence: list[Evidence] = []
    reasons: list[str] = []      # at most 3
    advice: list[str] = []
    children: list["Report"] = []
    pending: list[str] = []      # ids of live checks still running
    meta: Meta = Meta()

    @field_validator("reasons")
    @classmethod
    def _at_most_three(cls, v):
        if len(v) > 3:
            raise ValueError("a Report shows at most 3 reasons")
        return v
