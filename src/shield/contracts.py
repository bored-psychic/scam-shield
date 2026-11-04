from enum import Enum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# The one answer shape every module returns (docs/ARCHITECTURE.md §2 "Contracts", docs/decisions/README.md D4). The web app, the JSON API,
# tests and future scorers read a Report and nothing else. Bump SCHEMA_VERSION on any change a consumer would notice.
# v2 (2026-10-17): Evidence.span and Evidence.tag, for the in-message underlines and the radar labels
# v3 (2026-10-18, D22): Report.sender (the sender the user typed, classified) and the level PROMOTIONAL. A v2 reader would reject both (an unknown
# level value; an unknown field under extra="forbid"), hence the bump. With no sender, a v3 Report is the v2 Report plus "sender": null.
# v4 (2026-10-18, D23): Report.link (a link's "Website details" fact sheet: LinkInfo + Fact rows) on the child Report of each link; null on the
# message Report. A v3 reader would reject the unknown field, hence the bump.
# v5 (2026-10-18, D24): Report.risk_score (the 0-100 warning-sign meter, inside the band of the final level) and Report.lowered (a P1 brand-owned
# link lowered the verdict: from which level, and the sentence that says why). Both null on a child Report.
# v6 (2026-11-04, D29 / W1, docs/plans/multi_input.md 2.2): Report.input (what kind of input was checked) and Report.details (a fact sheet for inputs that are not
# links: payment / app / email); both null on a child Report, details null for message and link. A v5 reader would reject the unknown fields, hence the bump.
SCHEMA_VERSION = "6"


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
# What was checked (Report.input). Each kind belongs to one module; a child (link) Report has no input.
InputKind = Literal["message", "link", "email", "upi_id", "payment_request", "qr", "payment_proof", "app", "apk"]
MODULE_OF_INPUT: dict[str, str] = {"message": "messages", "link": "messages", "email": "messages", "upi_id": "transactions", "payment_request": "transactions",
                                   "qr": "transactions", "payment_proof": "transactions", "app": "apps", "apk": "apps"}
DETAILS_OF_MODULE: dict[str, str] = {"messages": "email", "transactions": "payment", "apps": "app"}   # Details.kind by Report.module


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


class Fact(_Strict):
    """One row of a link's "Website details" (D23). value is None while the check is pending, or for a hidden destination not revealed yet."""
    key: str = Field(pattern=r"^[a-z_]+$")             # e.g. "age", "server", "dest_age"
    label: str = Field(min_length=1, max_length=40)     # e.g. "Registered"
    value: str | None = None                            # e.g. "3 days ago (15 Oct 2026)"
    effect: Effect
    why: str | None = None                              # why it matters, one plain line (every red flag has one)
    status: Literal["ok", "pending", "failed", "skipped"]   # failed = "Couldn't verify (...)", never shown as safe
    source: str | None = None                           # e.g. "Tranco list updated 3 h ago"
    sent: str | None = None                             # what this check sent off the machine, e.g. "domain x.top -> rdap.zdnsgtld.com (registry)"


class LinkInfo(_Strict):
    """A link's background (D23), on its child Report. Nothing here was fetched from the link itself."""
    url: str                       # the link as extracted (refanged)
    host: str                      # lower case, IDN in punycode
    shown_host: str                # the host with xn-- labels decoded (what a phone would show)
    owner: str                     # the registered domain the checks looked up (one label + .bank.in / .gov.in for those zones)
    shortener: bool
    expandable: bool               # a short link whose destination the button can ask for (live checks on, not revealed yet)
    destination: str | None = None  # the revealed destination of a short link (never requested)
    facts: list[Fact] = []
    sent: list[str] = []           # every live call made for this link: what was sent, to which service


class Details(_Strict):
    """A fact sheet for an input that is not a link (payment, app, email), rendered like a link's LinkInfo.facts. Nothing builds one in W1."""
    kind: Literal["payment", "app", "email"]
    title: str = Field(min_length=1, max_length=40)     # "Payment details", "App details", "Sender details"
    facts: list[Fact] = []
    note: str | None = None                              # e.g. "The file was read on this device. It was not installed or run, and it is gone."


class Lowered(_Strict):
    """D24: the verdict was lowered by a P1 positive link signal (a verified .brand ending or a .bank.in address; shield.core.router.apply_positives)."""
    from_level: Literal[Level.LIKELY_SCAM]   # P1 only ever lowers Likely scam (to Suspicious); a wider rule must widen this on purpose
    text: str = Field(min_length=1, max_length=240)   # one calm sentence, e.g. "Lowered from Likely scam: the link belongs to Jio (only Reliance can register .jio addresses)."


# The score's bands by level (shield.core.risk.BANDS, repeated here so the contract rejects a score that contradicts its level without importing the core)
RISK_BANDS = {Level.NO_WARNING_SIGNS: (0, 29), Level.SUSPICIOUS: (30, 69), Level.LIKELY_SCAM: (70, 100), Level.PROMOTIONAL: (0, 29)}


class Report(_Strict):
    schema_version: Literal["6"] = "6"
    module: Module
    input: InputKind | None = None   # v6: what was checked; None on a child (link) Report and when to_report() was not told
    level: Level
    score: float | None = None
    category: str | None = None
    sender: Sender | None = None   # None: no sender given (and always on a child Report)
    evidence: list[Evidence] = []
    reasons: list[str] = []      # at most 3
    advice: list[str] = []
    children: list["Report"] = []
    pending: list[str] = []      # ids of live checks still running (child: "registration", "dns", "sb"; message: "links")
    link: LinkInfo | None = None   # D23: on a link's child Report; None on the message Report
    risk_score: int | None = None  # D24: 0-100 warning-sign meter inside the band of `level`; None for Can't judge and on a child Report. NOT a probability
    lowered: Lowered | None = None   # D24: set only when a P1 link signal actually lowered the level shown (never when it fired and the level stayed)
    details: Details | None = None   # v6: a fact sheet for payment / app / email inputs; None for message and link
    meta: Meta = Meta()

    @model_validator(mode="after")
    def _score_matches_level(self):
        if self.risk_score is None:
            return self
        if self.level not in RISK_BANDS:
            raise ValueError(f"a {self.level.value} Report has no risk_score")
        lo, hi = RISK_BANDS[self.level]
        if not lo <= self.risk_score <= hi:
            raise ValueError(f"risk_score {self.risk_score} is outside the {lo}-{hi} band of {self.level.value}")
        return self

    @model_validator(mode="after")
    def _input_module_details(self):
        """module follows input, details.kind follows module, and a child Report (always a link) has no input."""
        if self.input is not None and self.module != MODULE_OF_INPUT[self.input]:
            raise ValueError(f"input {self.input!r} belongs to the {MODULE_OF_INPUT[self.input]} module, not {self.module}")
        if self.details is not None and self.details.kind != DETAILS_OF_MODULE.get(self.module):
            raise ValueError(f"details of kind {self.details.kind!r} do not go with the {self.module} module")
        if any(c.input is not None for c in self.children):
            raise ValueError("a child Report has no input")
        return self

    @field_validator("risk_score")
    @classmethod
    def _score_range(cls, v):
        if v is not None and not 0 <= v <= 100:
            raise ValueError("risk_score is 0-100")
        return v

    @field_validator("reasons")
    @classmethod
    def _at_most_three(cls, v):
        if len(v) > 3:
            raise ValueError("a Report shows at most 3 reasons")
        return v
