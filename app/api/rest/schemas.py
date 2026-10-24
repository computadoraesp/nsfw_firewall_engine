"""Pydantic schemas for the REST management, audit and versioned ``/v1`` API.

``/v1`` is the *stable* contract promised by ``pront.md`` §20. The un-versioned
routes kept for backwards compatibility live in :mod:`app.api.rest.router` and
are aliases of the same engine calls - they are frozen, while everything under
``/v1`` may only gain fields, never change or remove them (§50: models evolve,
the API does not break).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

#: §22 lifecycle states. Mirrors ``adapters.base.ModelStatus`` without importing
#: the adapter package into the schema module, so the wire contract stays
#: independent of which models happen to be registered.
_MODEL_STATUSES = frozenset(
    {"candidate", "validated", "production", "deprecated", "blocked"}
)

#: Wire-level input bounds (§17, §38).
#:
#: These fields are caller-controlled and had **no** upper bound, so a single
#: authenticated request could submit tens of megabytes and have the engine
#: scan them. They are separate from ``preprocessing.max_image_bytes``, which
#: bounds *decoded* media and is enforced much later - after the bytes are
#: already resident in memory. Refusing at the schema edge is the cheap
#: defence; the deeper limit stays as a second line.
#:
#: 8 MB of base64 decodes to ~6 MB of media, comfortably above the 20 MiB
#: media limit's useful range for a single inline payload, while keeping a
#: request body bounded. 1 MB of text is far beyond any real page body and
#: still scans in milliseconds.
MAX_BASE64_CHARS = 8 * 1024 * 1024
MAX_TEXT_CHARS = 1024 * 1024
#: Caller-supplied identifiers are echoed into audit records and dead letters.
MAX_REQUEST_ID_CHARS = 256
MAX_URL_CHARS = 2048


class MediaItem(BaseModel):
    """One payload inside a batch/inspect request (§20 ``/v1/batch``)."""

    content_base64: str = Field(
        ...,
        max_length=MAX_BASE64_CHARS,
        description="Base64 or data-URI encoded media",
    )
    media_type: str = Field(default="IMAGE", description="IMAGE | VIDEO | TEXT | HTML")
    text: Optional[str] = Field(default=None, max_length=MAX_TEXT_CHARS)
    request_id: str = Field(default="", max_length=MAX_REQUEST_ID_CHARS)

    @field_validator("media_type")
    @classmethod
    def _upper(cls, value: str) -> str:
        return (value or "IMAGE").upper()


class InspectRequest(BaseModel):
    """``POST /v1/inspect`` - inspect one payload and return a full decision."""

    content_base64: str = Field(
        ...,
        max_length=MAX_BASE64_CHARS,
        description="Base64 or data-URI encoded media",
    )
    media_type: str = Field(default="IMAGE", description="IMAGE | VIDEO | TEXT | HTML")
    request_id: str = Field(default="", max_length=MAX_REQUEST_ID_CHARS)
    text: Optional[str] = Field(default=None, max_length=MAX_TEXT_CHARS)
    explain: bool = False
    #: Optional URL/domain context (§12). Context is *advisory*: it contributes
    #: to the text signal but can never on its own produce a BLOCK.
    url: Optional[str] = Field(default=None, max_length=MAX_URL_CHARS)
    domain: Optional[str] = Field(default=None, max_length=253)
    title: Optional[str] = Field(default=None, max_length=512)
    overrides: Optional["ThresholdOverrides"] = None

    @field_validator("media_type")
    @classmethod
    def _upper(cls, value: str) -> str:
        return (value or "IMAGE").upper()


class BatchRequest(BaseModel):
    """``POST /v1/batch`` - inspect many payloads in one round trip.

    The bounds are enforced in the route (not by pydantic) because the cap is a
    *resource-exhaustion* control (§17) that must answer ``413`` rather than a
    schema-validation ``422`` - a firewall wants to distinguish "too big" from
    "malformed".
    """

    items: List[MediaItem] = Field(..., description="1..64 payloads")

    @field_validator("items")
    @classmethod
    def _not_empty(cls, value: List[MediaItem]) -> List[MediaItem]:
        if not value:
            raise ValueError("items must not be empty")
        return value


class ThresholdOverrides(BaseModel):
    """Optional per-request threshold overrides."""

    fast_hard_nsfw: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    deep_hard_nsfw: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    multimodal_hard_nsfw: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    def as_engine_overrides(self) -> Optional[dict]:
        data = self.model_dump(exclude_none=True)
        return data or None


class ClassifyBase64Request(BaseModel):
    """Classify a base64-encoded image / video frame."""

    image_base64: str = Field(
        ..., max_length=MAX_BASE64_CHARS, description="Base64 (or data-URI) encoded media"
    )
    media_type: str = Field(default="IMAGE", description="IMAGE | VIDEO | TEXT | HTML")
    request_id: str = Field(default="", max_length=MAX_REQUEST_ID_CHARS)
    text: Optional[str] = Field(
        default=None,
        max_length=MAX_TEXT_CHARS,
        description="Optional accompanying text for multimodal fusion",
    )
    explain: bool = Field(default=False, description="Include per-stage scores")
    overrides: Optional[ThresholdOverrides] = None

    @field_validator("media_type")
    @classmethod
    def _upper(cls, value: str) -> str:
        return (value or "IMAGE").upper()

    @field_validator("image_base64")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("image_base64 must not be empty")
        return value


class ClassifyTextRequest(BaseModel):
    """Classify a text / HTML payload directly."""

    text: str = Field(..., max_length=MAX_TEXT_CHARS)
    media_type: str = Field(default="TEXT", description="TEXT | HTML")
    request_id: str = Field(default="", max_length=MAX_REQUEST_ID_CHARS)
    explain: bool = False
    overrides: Optional[ThresholdOverrides] = None

    @field_validator("media_type")
    @classmethod
    def _upper(cls, value: str) -> str:
        value = (value or "TEXT").upper()
        if value not in ("TEXT", "HTML"):
            raise ValueError("media_type must be TEXT or HTML")
        return value


class StageResultSchema(BaseModel):
    """A single stage's contribution to the decision."""

    path: str
    score: float
    latency_ms: float
    executed: bool = True
    model: str = ""
    fallback: bool = False


class ClassifyResponse(BaseModel):
    """Classification outcome returned by the REST API."""

    verdict: str
    decided_by: str
    score: float
    total_latency_ms: float
    media_type: str = "UNKNOWN"
    request_id: str = ""
    should_block: bool = False
    stages: List[StageResultSchema] = Field(default_factory=list)
    text: Optional[Dict] = None


# ---------------------------------------------------------------------------
# §21 - the normalised model/decision schemas, as a stable wire contract.
# ---------------------------------------------------------------------------


class ModelIdentity(BaseModel):
    """The §21 normalised output of a single model."""

    model_id: str
    model_version: str
    categories: Dict[str, float] = Field(default_factory=dict)
    confidence: float = 0.0
    latency_ms: float = 0.0


class DecisionEnvelope(BaseModel):
    """The §21 decision envelope returned by ``/v1/inspect``."""

    decision: str = Field(..., description="ALLOW | REVIEW | BLOCK | QUARANTINE")
    policy_id: str = ""
    category: str = ""
    confidence: float = 0.0
    scores: Dict[str, float] = Field(default_factory=dict)
    models_used: List[str] = Field(default_factory=list)


class InspectResponse(BaseModel):
    """``POST /v1/inspect`` - the full inspection result plus the §21 decision."""

    request_id: str = ""
    verdict: str = "UNKNOWN"
    decision: str = "ALLOW"
    policy_id: str = ""
    category: str = ""
    confidence: float = 0.0
    score: float = 0.0
    scores: Dict[str, float] = Field(default_factory=dict)
    models_used: List[str] = Field(default_factory=list)
    is_blocking: bool = False
    would_be_action: str = ""
    mode: str = "enforcement"
    #: §19 caller dimensions this decision was evaluated against (zone, groups,
    #: device, ...). Present so an auditor can see *why* a rule fired.
    matched_dimensions: Optional[Dict] = None
    media_type: str = "UNKNOWN"
    reason: str = ""
    from_cache: bool = False
    #: True when this response replays an earlier decision for the same
    #: ``request_id`` (§33 idempotency). A caller can always tell a repeat from
    #: a fresh classification, which is what makes retry bugs diagnosable.
    idempotent_replay: bool = False
    content_sha256: str = ""
    detected_mime: str = ""
    total_latency_ms: float = 0.0
    timed_out: bool = False
    stages: List[StageResultSchema] = Field(default_factory=list)
    text: Optional[Dict] = None
    error: str = ""
    #: §12 HTML/URL context signals. Metadata only (title, domain, flags) -
    #: never the page body, so this is safe to log under
    #: ``privacy.retain_raw_payloads: false`` (§18).
    context: Optional[Dict] = None


class BatchItemResult(BaseModel):
    """Per-item outcome inside a batch response.

    A failing item never fails the batch: firewalls need to see *every*
    verdict, and one malformed payload must not blind the operator to the rest
    of the traffic.
    """

    request_id: str = ""
    index: int = 0
    verdict: str = "UNKNOWN"
    decision: str = "ALLOW"
    score: float = 0.0
    is_blocking: bool = False
    from_cache: bool = False
    total_latency_ms: float = 0.0
    error: str = ""
    content_sha256: str = ""


class BatchResponse(BaseModel):
    """``POST /v1/batch`` - aggregate of a batch inspection."""

    results: List[BatchItemResult] = Field(default_factory=list)
    total: int = 0
    blocked: int = 0
    errored: int = 0
    total_latency_ms: float = 0.0


class ModelDescriptor(BaseModel):
    """One entry of ``GET /v1/models`` (§22 model registry)."""

    model_id: str
    stage: str
    version: str = ""
    runtime: str = ""
    source: str = ""
    license: str = "unknown"
    #: One of §22's five lifecycle states: candidate | validated | production |
    #: deprecated | blocked.
    status: str = "candidate"
    loaded: bool = False
    is_stub: bool = True
    #: False for deprecated/blocked models: present in the registry, but not
    #: permitted to decide anything.
    may_serve: bool = True
    #: ``cascade`` for the built-in stages, ``adapter`` for §41 third-party
    #: wrappers, so an operator can tell which rows are replaceable.
    kind: str = "cascade"
    weights_hash: str = ""


class InspectTextRequest(BaseModel):
    """Body of ``POST /v1/classify/text``.

    Mirrors :class:`InspectRequest` minus the binary payload. The distinction
    matters for policy: an HTML page carries its own ``<title>``/meta/alt text,
    so the context a rule sees (url, domain, title) comes from the document
    itself rather than from what the caller asserts.
    """

    text: str = Field(..., max_length=MAX_TEXT_CHARS, description="Text or HTML document to classify")
    media_type: str = Field(default="TEXT", description="TEXT | HTML")
    request_id: str = Field(default="", max_length=MAX_REQUEST_ID_CHARS)
    url: str = Field(default="", max_length=MAX_URL_CHARS, description="Page URL; contributes to the §19 context")
    domain: str = Field(default="", max_length=253, description="Page domain; derived from url if empty")
    explain: bool = False
    overrides: Optional[ThresholdOverrides] = None

    @field_validator("media_type")
    @classmethod
    def _upper(cls, value: str) -> str:
        normalised = (value or "TEXT").strip().upper()
        if normalised not in {"TEXT", "HTML"}:
            raise ValueError(f"media_type must be TEXT or HTML, got {value!r}")
        return normalised


class DeadLetterSchema(BaseModel):
    """One dead-lettered request (§33). Never carries the payload."""

    request_id: str = ""
    tenant_id: str = ""
    endpoint: str = ""
    #: ``classify_error`` | ``circuit_open`` | ``retries_exhausted`` | ...
    reason: str = "unknown"
    error: str = ""
    #: SHA256 of the failed payload - a correlation handle, never the bytes.
    content_sha256: str = ""
    attempts: int = 1
    media_type: str = ""
    queued_at: float = 0.0


class DeadLetterListResponse(BaseModel):
    """``GET /v1/dead-letters``."""

    letters: List[DeadLetterSchema] = Field(default_factory=list)
    #: False when ``resilience.dead_letter_enabled`` is off.
    enabled: bool = True
    stats: Dict[str, Any] = Field(default_factory=dict)
    total: int = 0


class ModelStatusUpdate(BaseModel):
    """Body of ``POST /v1/models/{stage}/status`` (§22 lifecycle)."""

    status: str = Field(..., description="candidate | validated | production | deprecated | blocked")
    #: Why the transition is being made. Recorded in the audit log: a model
    #: promotion without a stated reason is exactly the kind of change nobody can
    #: explain six months later.
    reason: str = ""

    @field_validator("status")
    @classmethod
    def _known(cls, value: str) -> str:
        normalised = (value or "").strip().lower()
        if normalised not in _MODEL_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(_MODEL_STATUSES)}, got {value!r}"
            )
        return normalised


class ModelStatusResponse(BaseModel):
    """Outcome of a lifecycle transition."""

    stage: str
    model_id: str
    previous_status: str
    status: str
    may_serve: bool
    servable_stages: List[str] = Field(default_factory=list)


class ModelListResponse(BaseModel):
    """``GET /v1/models`` - the model registry as served to operators."""

    models: List[ModelDescriptor] = Field(default_factory=list)
    runtime_available: bool = False
    active_providers: List[str] = Field(default_factory=list)
    total: int = 0


class PolicyRuleSchema(BaseModel):
    """A declarative rule (``pront.md`` §19)."""

    field: str
    operator: str = "=="
    value: Any = None
    action: str = "allow"
    description: str = ""


class PolicyDocument(BaseModel):
    """The wire representation of a policy - never executable code."""

    policy_id: str
    description: str = ""
    rules: List[PolicyRuleSchema] = Field(default_factory=list)
    default_action: str = "review"
    tenant_id: str = ""


class PolicyListResponse(BaseModel):
    """``GET /v1/policies``."""

    policies: List[PolicyDocument] = Field(default_factory=list)
    total: int = 0


class PolicyMutationResponse(BaseModel):
    """``POST /v1/policies`` - the applied policy plus audit metadata."""

    policy_id: str
    tenant_id: str = ""
    rules_applied: int = 0
    created: bool = False
    replaced: bool = False


class ReadyResponse(BaseModel):
    """``GET /v1/ready`` - Kubernetes-style readiness probe (§33)."""

    ready: bool
    reason: str = ""
    version: str = ""
    models_loaded: int = 0
    checks: Dict[str, bool] = Field(default_factory=dict)


    error: str = ""
    # Enforcement / audit additions
    action: str = "ALLOW"
    policy_id: str = ""
    from_cache: bool = False
    content_sha256: str = ""
    detected_mime: str = ""


class EnforceResponse(BaseModel):
    """Enforcement decision for firewall / SWG consumers (Sec. 19 / 30)."""

    action: str
    policy_id: str
    reason: str
    status_code: int
    headers: Dict[str, str] = Field(default_factory=dict)
    body: str = ""
    is_blocking: bool = False
    risk_score: float = 0.0
    #: Audit mode (§30): the action that would have been enforced.
    would_be_action: str = ""
    mode: str = "enforcement"


class HealthResponse(BaseModel):
    """Engine readiness report."""

    healthy: bool
    version: str
    mode: str = "triage"
    active_providers: List[str] = Field(default_factory=list)
    runtime_available: bool = False
    models_loaded: Dict[str, bool] = Field(default_factory=dict)
    uptime_seconds: int = 0
    loaded_models_count: int = 0
    text_model_loaded: bool = False
    cache: Dict = Field(default_factory=dict)
    policy: Dict = Field(default_factory=dict)
    security: Dict = Field(default_factory=dict)
    firewall_mode: str = "enforcement"


class ConfigResponse(BaseModel):
    """Exposed configuration summary (safe subset)."""

    version: str
    mode: str
    thresholds: Dict
    timeouts: Dict


class ErrorResponse(BaseModel):
    """Standard error envelope."""

    detail: str
