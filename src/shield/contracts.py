from enum import Enum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# The one answer shape every module returns (docs/ARCHITECTURE.md §2 "Contracts", docs/decisions/README.md D4). The web app, the JSON API,
# tests and future scorers read a Report and nothing else. Bump SCHEMA_VERSION on any change a consumer would notice.
SCHEMA_VERSION = "2"   # v2 (2026-10-17): Evidence.span and Evidence.tag, for the in-message underlines and the radar labels


class Level(str, Enum):
    LIKELY_SCAM = "likely_scam"
    SUSPICIOUS = "suspicious"
    NO_WARNING_SIGNS = "no_warning_signs"   # never called "Safe": it only means nothing strong was found
    CANT_JUDGE = "cant_judge"

LEVEL_LABEL = {Level.LIKELY_SCAM: "Likely scam", Level.SUSPICIOUS: "Suspicious",
               Level.NO_WARNING_SIGNS: "No warning signs found", Level.CANT_JUDGE: "Can't judge"}
LEVEL_RANK = {Level.NO_WARNING_SIGNS: 0, Level.SUSPICIOUS: 1, Level.LIKELY_SCAM: 2}   # CANT_JUDGE has no rank: it is not a point on the scale


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


class Report(_Strict):
    schema_version: Literal["2"] = "2"
    module: Module
    level: Level
    score: float | None = None
    category: str | None = None
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
