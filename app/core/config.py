"""Configuration loading and validation for the NSFW Firewall Engine.

The engine configuration is defined in ``config/engine_config.yaml``. This
module parses that file into strongly typed :class:`pydantic.BaseModel`
instances so that the rest of the codebase can rely on validated values.

The location of the YAML file can be overridden with the
``NSFW_ENGINE_CONFIG`` environment variable; otherwise the default
``config/engine_config.yaml`` relative to the project root is used.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger("nsfw_engine.core.config")

# Source checkout root, or the installation prefix for a built wheel.
_SOURCE_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = (
    _SOURCE_ROOT
    if (_SOURCE_ROOT / "config" / "engine_config.yaml").is_file()
    else Path(sys.prefix)
)
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "engine_config.yaml"
DEFAULT_LOGGING_CONFIG_PATH = PROJECT_ROOT / "config" / "logging_config.yaml"


class EngineMeta(BaseModel):
    name: str = "nsfw-firewall-engine"
    version: str = "1.0.0"
    environment: str = "production"
    mode: str = "triage"
    request_timeout_ms: int = 250
    workers: int = 4
    #: Refuse to boot when ``environment == "production"`` and
    #: ``security.enabled`` is false.
    #:
    #: This was declared in ``engine_config.yaml`` but had no field here, so
    #: pydantic silently dropped it and the "SECURITY:" comment it carried was
    #: inert - the only thing enforcing it was a ``getattr`` default in
    #: ``app/main.py``. It is now a real, validated setting.
    require_auth_in_production: bool = True
    # DEPRECATED alias for ``policy.fail_action``. Both keys exist in
    # ``engine_config.yaml`` but only ``policy.fail_action`` is authoritative;
    # this is reconciled (and any disagreement logged) by ``EngineConfig`` so the
    # two can never silently diverge.
    fail_mode: str = "ALLOW"

    @field_validator("mode")
    @classmethod
    def _validate_mode(cls, value: str) -> str:
        allowed = {"triage", "fast_only"}
        if value not in allowed:
            raise ValueError(f"engine.mode must be one of {allowed}, got {value!r}")
        return value

    @field_validator("fail_mode")
    @classmethod
    def _validate_fail_mode(cls, value: str) -> str:
        normalised = (value or "ALLOW").upper()
        allowed = {"ALLOW", "BLOCK"}
        if normalised not in allowed:
            raise ValueError(f"engine.fail_mode must be one of {allowed}, got {value!r}")
        return normalised


class StageThresholds(BaseModel):
    hard_nsfw: float = 0.85
    hard_sfw: float = 0.15
    escalate: bool = True


class MultimodalThresholds(BaseModel):
    hard_nsfw: float = 0.75
    review: float = 0.40


class TextThresholds(BaseModel):
    weight: float = 0.30
    keyword_score_cap: float = 1.0
    # Fusion strategy used when blending visual and text signals:
    #   weighted  -> (1-w)*image + w*text
    #   max       -> max(image, text)
    #   noisy_or  -> 1 - (1-image)*(1 - w*text)
    fusion_strategy: str = "weighted"

    @field_validator("fusion_strategy")
    @classmethod
    def _validate_strategy(cls, value: str) -> str:
        normalised = (value or "weighted").lower()
        allowed = {"weighted", "max", "noisy_or"}
        if normalised not in allowed:
            raise ValueError(f"text.fusion_strategy must be one of {allowed}, got {value!r}")
        return normalised


class PremiumThresholds(BaseModel):
    """Thresholds for the §10 Premium Path (licence-cleared ViT).

    ``enabled`` is the important field: the stage is opt-in. It is the most
    expensive model in the cascade and it ships unbenchmarked, so enabling it
    by default would put an unmeasured model on the blocking path (§49).
    """

    enabled: bool = False
    #: The premium stage is an arbiter, so it mirrors the multimodal shape
    #: rather than the fast/deep one: a REVIEW band, not an escalate chain.
    hard_nsfw: float = 0.75
    review: float = 0.40


class Thresholds(BaseModel):
    fast_path: StageThresholds = Field(
        default_factory=lambda: StageThresholds(hard_nsfw=0.85, hard_sfw=0.15)
    )
    deep_path: StageThresholds = Field(
        default_factory=lambda: StageThresholds(hard_nsfw=0.80, hard_sfw=0.20)
    )
    multimodal: MultimodalThresholds = Field(default_factory=MultimodalThresholds)
    #: §10 Premium Path. Off unless an operator opts in, because the ViT is the
    #: most expensive stage in the cascade and its thresholds are only
    #: meaningful once it has been benchmarked on a labelled set (§49).
    premium: PremiumThresholds = Field(default_factory=PremiumThresholds)
    text: TextThresholds = Field(default_factory=TextThresholds)


class Timeouts(BaseModel):
    fast_path_ms: int = 10
    #: §45 measured: the deployed Deep-Path checkpoint (EfficientNet 17.7M at
    #: 380px) measures ~84 ms on this CPU, so the original 20-40 ms budget from
    #: the EfficientNet-B0 design note does not hold for it. The budget is set
    #: from measurement rather than left aspirational, because a budget the
    #: stage always breaches is worse than no budget at all: every request that
    #: escalates would be reported as a deadline breach.
    deep_path_ms: int = 120
    multimodal_ms: int = 90
    #: §10 Premium Path budget. Generous because a ViT at 384px is the most
    #: expensive stage; it only runs after everything cheaper was inconclusive.
    premium_ms: int = 120
    text_ms: int = 15
    video_frame_ms: int = 120


class OnnxProvider(BaseModel):
    """A requested ONNX Runtime execution provider plus its tuning options.

    Providers may be declared in ``engine_config.yaml`` either as a bare string
    (``- CPUExecutionProvider``) or as a mapping carrying provider options
    (``- name: CUDAExecutionProvider`` / ``options: {...}``).
    """

    name: str
    options: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _coerce(cls, value: Any) -> Any:
        if isinstance(value, str):
            return {"name": value}
        return value


class OnnxConfig(BaseModel):
    providers: List[OnnxProvider] = Field(
        default_factory=lambda: [OnnxProvider(name="CPUExecutionProvider")]
    )
    intra_op_num_threads: int = 4
    inter_op_num_threads: int = 1
    graph_optimization_level: str = "ORT_ENABLE_ALL"
    enable_fp16: bool = True

    @property
    def provider_names(self) -> List[str]:
        """Ordered provider names, e.g. ``["CUDAExecutionProvider", ...]``."""
        return [provider.name for provider in self.providers]

    @property
    def provider_options(self) -> Dict[str, Dict[str, Any]]:
        """Per-provider option maps, keyed by provider name."""
        return {
            provider.name: dict(provider.options)
            for provider in self.providers
            if provider.options
        }


class Paths(BaseModel):
    models_dir: str = "models_onnx"
    fast_path_model: str = "models_onnx/fast_path_mobilenetv3.onnx"
    deep_path_model: str = "models_onnx/vit_nsfw.onnx"
    multimodal_model: str = "models_onnx/multimodal_clip.onnx"
    text_model: str = "models_onnx/text_distilbert.onnx"
    #: §10 Premium Path. Must match ``HuggingFaceViTAdapter.default_model_path``
    #: so the adapter and the config cannot disagree about which graph is the
    #: premium one.
    premium_model: str = "models_onnx/vit_nsfw.onnx"
    log_dir: str = "logs"


class Preprocessing(BaseModel):
    fast_path_resize: Tuple[int, int] = (224, 224)
    #: Keep the configured Deep-Path resolution aligned with its model sidecar.
    deep_path_resize: Tuple[int, int] = (224, 224)
    multimodal_resize: Tuple[int, int] = (224, 224)
    mean: Tuple[float, float, float] = (0.485, 0.456, 0.406)
    std: Tuple[float, float, float] = (0.229, 0.224, 0.225)
    max_image_bytes: int = 20 * 1024 * 1024
    max_image_dim: int = 8192
    max_pixels: int = 64 * 1024 * 1024
    allowed_mime_types: List[str] = Field(
        default_factory=lambda: [
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/gif",
            # P6 is the only format the dependency-free fallback decoder reads.
            "image/x-portable-pixmap",
            "text/html",
            "text/plain",
        ]
    )


class FirewallConfig(BaseModel):
    """Firewall operating mode (§30).

    ``enforcement`` - decisions are acted on (ALLOW/BLOCK/REVIEW/QUARANTINE).
    ``audit`` - classification and policy run unchanged, but every decision is
    *simulated* and always ALLOWs. This is the safe way to tune thresholds on
    live traffic without blocking anyone.
    """

    mode: str = "enforcement"
    #: Record what the decision *would* have been in audit mode.
    report_would_be: bool = True

    @field_validator("mode")
    @classmethod
    def _validate_mode(cls, value: str) -> str:
        normalised = (value or "enforcement").lower()
        allowed = {"enforcement", "audit"}
        if normalised not in allowed:
            raise ValueError(f"firewall.mode must be one of {allowed}, got {value!r}")
        return normalised


class SecurityConfig(BaseModel):
    """Authentication, RBAC and audit controls (§16, §18, §35).

    Defaults are **development-safe but not production-safe**: ``enabled`` is
    ``False`` so the service boots without secrets. Production deployments must
    set ``enabled: true`` and provision hashed API keys - see
    ``docs/THREAT_MODEL.md`` (residual risk #1).
    """

    enabled: bool = False
    # When auth is disabled, requests still get a principal with these roles so
    # authorisation code is exercised identically in dev and prod.
    anonymous_roles: List[str] = Field(default_factory=lambda: ["read_only", "service_account"])
    # key_id -> API key. Store the SHA256 hex of the secret (hash_api_keys=True)
    # so the config file never contains a usable credential.
    api_keys: Dict[str, str] = Field(default_factory=dict)
    hash_api_keys: bool = True
    # Optional space/comma separated key_id per role: "k1:read_only,k2:super_admin"
    key_roles: Dict[str, str] = Field(default_factory=dict)
    #: key_id -> the tenant that key is *entitled* to.
    #:
    #: This is what makes multi-tenancy real. Previously nothing bound a key to
    #: a tenant, so the ``X-Tenant-Id`` request header - fully client-controlled
    #: - was copied straight onto the principal. Any valid key could therefore
    #: claim any tenant, read its policy and decide against its rules (§34).
    key_tenants: Dict[str, str] = Field(default_factory=dict)
    #: Accept an ``X-Tenant-Id`` header from a key that has no binding above.
    #:
    #: Defaults to ``False``: an unbound key asserting a tenant is precisely the
    #: spoof this mapping exists to stop, so it is rejected rather than
    #: believed. Single-tenant deployments are unaffected - they simply send no
    #: header, and the principal keeps an empty tenant.
    allow_unbound_tenant_header: bool = False
    audit_enabled: bool = True
    max_audit_entries: int = 1000
    #: Refuse to start a credential-carrying transport that is not encrypted.
    #: Turning this off is only defensible for a loopback-only deployment.
    require_transport_tls: bool = True
    #: Durable audit sink (§18, and ``config/privacy.yaml``'s ``secure_s3`` /
    #: ``retention_days: 365``).
    #:
    #: The trail used to be a bounded ``deque`` in RAM, so every restart - and
    #: a crash is exactly when the evidence is wanted - erased it. Append-only
    #: JSONL keeps the metadata-only guarantee (§18: principal, verdict, hash -
    #: never payload bytes) while making the record outlive the process.
    audit_file: str = ""
    # When true, a request must carry X-Tenant-Id (multi-tenant deployments).
    require_tenant_header: bool = False

    # -- rate limiting (§17) --------------------------------------------------
    #: Off by default so a fresh checkout is not throttled mid-debugging.
    #: Production deployments behind an NGFW should enable it: the firewall
    #: limits *who* may connect, the engine must still limit *how fast*.
    rate_limit_enabled: bool = False
    #: Sustained requests per second per (tenant, principal).
    rate_limit_per_second: float = 50.0
    #: Largest instantaneous burst. A proxy replaying cached decisions after a
    #: restart is a legitimate burst; a sustained flood is not.
    rate_limit_burst: float = 100.0
    #: Upper bound on tracked buckets, so a flood of distinct keys cannot grow
    #: the limiter's memory without limit (§38 resource exhaustion).
    rate_limit_max_keys: int = 10_000


class ResilienceConfig(BaseModel):
    """Circuit breaker settings (§33).

    Disabled by default for the same reason as rate limiting: a breaker with a
    mis-tuned threshold stops a working engine from serving traffic, which is a
    worse outcome than the slow calls it prevents.
    """

    breaker_enabled: bool = False
    #: Consecutive failures before the breaker opens.
    breaker_failure_threshold: int = 5
    #: Seconds the breaker stays open before probing again.
    breaker_recovery_timeout: float = 30.0
    #: Bounded retries around a stage call (§33).
    retry_attempts: int = 3
    retry_backoff_seconds: float = 0.05
    #: Dead-letter queue (§33). Enabled by default: unlike the breaker and the
    #: rate limiter, *not* capturing a failure is never the right behaviour - the
    #: request would simply vanish with nothing to replay. Costs one dict.
    dead_letter_enabled: bool = True
    dead_letter_max_entries: int = 1_000
    dead_letter_ttl_seconds: float = 86_400.0
    #: Probes admitted while half-open.
    breaker_half_open_calls: int = 1
    #: When the breaker is open, resolve through ``policy.fail_action``
    #: (BLOCK) rather than allowing the request through.
    #:
    #: Declared in ``engine_config.yaml`` with a SECURITY comment but never
    #: declared as a field, so it was dropped by pydantic and controlled
    #: nothing. Now a real setting.
    breaker_fail_closed: bool = True
    #: Bounded retries for a *failed* stage (§33 ``bounded retries``). Zero
    #: disables retrying entirely, which is the right default for inference:
    #: a retry costs the full inference budget and rarely succeeds on a
    #: deterministic failure.
    max_retries: int = 0
    #: Replay a stored decision when the caller repeats a ``request_id``
    #: (§33 ``idempotency``). Off by default because it only helps callers that
    #: actually supply a stable request id, and it costs one lookup per request.
    idempotency_enabled: bool = False
    #: How long a completed decision is replayable. Must exceed the retry
    #: window of whatever sits in front of the engine (LB, proxy, NGFW).
    idempotency_ttl_seconds: float = 300.0
    #: Upper bound on remembered decisions, so client-supplied ids cannot grow
    #: the map without limit (§38 resource exhaustion).
    idempotency_max_entries: int = 10_000


class PrivacyConfig(BaseModel):
    retain_raw_payloads: bool = False
    log_content_hashes: bool = True
    #: Salt for content digests in the audit trail and cache keys.
    #:
    #: SECURITY: this used to default to the literal ``"enterprise-nsfw-salt"``,
    #: committed to the repository. A salt that ships with the data it protects
    #: is not a salt - it is a constant, and it makes every digest in the
    #: deployment precomputable by anyone who can read the repo. The shipped
    #: value is now the literal placeholder ``${NSFW_HASH_SALT}``, resolved from
    #: the environment; leaving it unresolved degrades to an empty salt, which
    #: is honest about offering no protection rather than pretending otherwise.
    hash_salt: str = "${NSFW_HASH_SALT}"
    #: Pepper for API-key digests. Must come from the environment (a Kubernetes
    #: Secret, a mounted file). Empty means "no pepper", which still leaves
    #: scrypt's per-key salt doing the work - a pepper adds nothing an attacker
    #: with the whole config does not already have.
    hash_pepper: str = "${NSFW_HASH_PEPPER}"


class CacheConfig(BaseModel):
    enabled: bool = True
    type: str = "memory"
    # Accepts fractional values so short-lived (sub-second) TTLs are testable.
    ttl_seconds: float = 86400.0
    max_entries: int = 100000
    # Redis backend: connection URL (falls back to the NSFW_REDIS_URL env var)
    # and key prefix. Ignored when type == "memory".
    url: str = ""
    prefix: str = "nsfw:decision"

    @field_validator("type")
    @classmethod
    def _validate_type(cls, value: str) -> str:
        normalised = (value or "memory").lower()
        if normalised not in {"memory", "redis"}:
            raise ValueError(f"cache.type must be memory or redis, got {value!r}")
        return normalised


class ObservabilityConfig(BaseModel):
    prometheus_port: int = 9090
    enable_tracing: bool = False
    log_level: str = "INFO"
    log_format: str = "json"
    #: Optional bearer token for ``GET /metrics``.
    #:
    #: The scrape endpoint has to stay reachable without credentials for
    #: Prometheus and for Kubernetes probes, but it is also the one endpoint
    #: that reports the tenant roster, the policy ids and the request rates to
    #: whoever can reach the port. A token keeps both properties: open for the
    #: scraper, closed for everyone else. Resolved from ``NSFW_METRICS_TOKEN``.
    metrics_token: str = "${NSFW_METRICS_TOKEN}"
    #: Hash the ``tenant`` metric label to a stable pseudonym.
    #:
    #: ``/metrics`` is anonymous so scrapers and probes keep working, which
    #: otherwise means it publishes the customer roster. Pseudonyms keep every
    #: grouping and alert intact while removing the names; set false only on a
    #: management network where readable labels are worth the disclosure.
    pseudonymize_tenants: bool = True


class PolicyConfig(BaseModel):
    """Enterprise policy mapping verdicts onto enforcement actions (Sec. 19)."""

    default_policy_id: str = "default"
    # Action taken when a payload is classified NSFW: BLOCK | QUARANTINE | REVIEW
    nsfw_action: str = "BLOCK"
    # Action taken when the payload is ambiguous.
    review_action: str = "REVIEW"
    # Action taken when the payload is classified safe.
    sfw_action: str = "ALLOW"
    # Action used when classification fails / times out (engine.fail_mode).
    fail_action: str = "ALLOW"
    block_status_code: int = 403
    quarantine_status_code: int = 451
    block_message: str = "Blocked by NSFW firewall policy"
    # Optional per-tenant overrides: tenant_id -> {verdict_key: action}
    tenant_overrides: Dict[str, Dict[str, str]] = Field(default_factory=dict)

    @field_validator("nsfw_action", "review_action", "sfw_action", "fail_action")
    @classmethod
    def _validate_action(cls, value: str) -> str:
        normalised = (value or "ALLOW").upper()
        allowed = {"ALLOW", "BLOCK", "REVIEW", "QUARANTINE"}
        if normalised not in allowed:
            raise ValueError(f"policy action must be one of {allowed}, got {value!r}")
        return normalised


class GrpcTransport(BaseModel):
    #: SECURITY: loopback until TLS is configured. This transport carries the
    #: API key itself, and it used to be served by ``add_insecure_port`` - so
    #: the credential crossed the network in cleartext to every hop between the
    #: client and the engine. A key sniffed once is valid on REST *and* gRPC,
    #: so a single passive observer defeats the entire authentication model:
    #: scrypt protects the key at rest, and nothing protected it on the wire.
    host: str = "127.0.0.1"
    port: int = 50051
    max_workers: int = 8
    max_message_bytes: int = 16 * 1024 * 1024
    #: Serve over TLS. Required unless ``security.require_transport_tls`` is
    #: explicitly turned off for a loopback-only deployment.
    tls_enabled: bool = True
    tls_cert_file: str = ""
    tls_key_file: str = ""
    #: CA bundle for verifying the client certificate, when mTLS is used.
    tls_ca_file: str = ""
    #: When true, clients must present a certificate signed by ``tls_ca_file``.
    tls_require_client_auth: bool = False


class IcapTransport(BaseModel):
    #: SECURITY: loopback by default. This socket exposes the full
    #: classification *and* enforcement surface, and until this iteration it had
    #: no access control of any kind, so binding every interface handed that
    #: surface to the whole network. The common deployment is a proxy on the
    #: same host; anything wider is now an explicit opt-in.
    host: str = "127.0.0.1"
    port: int = 1344
    max_body_bytes: int = 32 * 1024 * 1024
    service_tag: str = "nsfw-firewall"
    #: CIDR ranges permitted to open a session. Empty means "loopback only",
    #: which is the secure default and keeps a freshly started server usable.
    #: Widening this is how an operator deliberately exposes the engine to a
    #: proxy on another host.
    trusted_proxies: List[str] = Field(
        default_factory=lambda: ["127.0.0.1/32", "::1/128"]
    )
    #: Tenant whose policy governs ICAP traffic.
    #:
    #: SECURITY: the handler used to read ``X-ICAP-Tenant-Id`` from the request
    #: and hand it straight to ``policy.decide(tenant_id=...)``. That is the
    #: iteration-1 tenant-spoof finding reproduced on a socket with no
    #: authentication whatsoever: any peer chose which tenant's rules decided
    #: its traffic. The tenant is now server-side configuration.
    default_tenant: str = ""


class RestTransport(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080


class Transport(BaseModel):
    grpc: GrpcTransport = Field(default_factory=GrpcTransport)
    icap: IcapTransport = Field(default_factory=IcapTransport)
    rest: RestTransport = Field(default_factory=RestTransport)


class VideoConfig(BaseModel):
    sample_fps: float = 2.0
    max_frames: int = 120
    early_exit_score: float = 0.90
    #: Aggregation of per-frame scores into one video score (§14).
    #: ``max`` | ``mean`` | ``percentile`` | ``weighted``. See
    #: :data:`app.services.video_pipeline.AGGREGATORS`.
    aggregation: str = "max"
    #: Percentile used when ``aggregation == "percentile"`` (§14).
    percentile: float = 95.0
    #: ``uniform`` | ``scene_change`` (§14). ``scene_change`` picks frames where
    #: the decoded content changes most, which catches short explicit inserts
    #: that uniform sampling can step over.
    sampling: str = "uniform"
    #: Frame-difference threshold above which a cut is treated as a scene change.
    scene_threshold: float = 0.35


class CalibrationConfig(BaseModel):
    """Score calibration (§26).

    Calibration is **off by default**. Enabling it without a fitted
    ``config/calibration.json`` would be a no-op anyway, and an uncalibrated
    system that *claims* to be calibrated is worse than one that admits it.
    """

    enabled: bool = False
    #: JSON document produced by ``scripts/calibrate``.
    path: str = "config/calibration.json"


class EngineConfig(BaseModel):
    """Fully validated engine configuration."""

    engine: EngineMeta = Field(default_factory=EngineMeta)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    timeouts: Timeouts = Field(default_factory=Timeouts)
    onnx: OnnxConfig = Field(default_factory=OnnxConfig)
    paths: Paths = Field(default_factory=Paths)
    preprocessing: Preprocessing = Field(default_factory=Preprocessing)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    resilience: ResilienceConfig = Field(default_factory=ResilienceConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    firewall: FirewallConfig = Field(default_factory=FirewallConfig)
    transport: Transport = Field(default_factory=Transport)
    video: VideoConfig = Field(default_factory=VideoConfig)
    calibration: CalibrationConfig = Field(default_factory=CalibrationConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)

    def model_path(self, relative: str) -> Path:
        """Resolve a path from the config against the project root."""
        candidate = Path(relative)
        return candidate if candidate.is_absolute() else (PROJECT_ROOT / candidate)

    @model_validator(mode="after")
    def _reconcile_fail_mode(self) -> "EngineConfig":
        """Keep the deprecated ``engine.fail_mode`` in step with the real switch.

        ``engine_config.yaml`` carries both ``engine.fail_mode`` and
        ``policy.fail_action``. Only the latter is read by the policy engine, so
        an operator who set only ``fail_mode: BLOCK`` would silently get
        fail-*open* behaviour. ``policy.fail_action`` wins, the deprecated field
        is rewritten to match, and a disagreement is logged loudly.
        """
        if self.engine.fail_mode != self.policy.fail_action:
            logger.warning(
                "engine.fail_mode=%r is deprecated and disagrees with "
                "policy.fail_action=%r; using policy.fail_action. "
                "Remove engine.fail_mode from the config.",
                self.engine.fail_mode,
                self.policy.fail_action,
            )
            self.engine.fail_mode = self.policy.fail_action
        return self


def _read_yaml(path: Path) -> dict[str, Any]:
    # SECURITY: a missing configuration must stop the process.
    #
    # This used to return ``{}`` silently, which is the worst possible failure
    # for a firewall: every default that follows is permissive
    # (``security.enabled=False``, ``rate_limit_enabled=False``,
    # ``policy.fail_action="ALLOW"``). The engine started, answered /health in
    # green, and served every payload with no authentication and no rate limit.
    #
    # A firewall that cannot start is an outage; a firewall that starts
    # believing it is protected is a breach.
    if not path.exists():
        raise FileNotFoundError(
            f"SECURITY: engine configuration not found at {path}. Refusing to "
            "start with defaults - a missing config would silently disable "
            "authentication, rate limiting and fail-closed behaviour. Set "
            "NSFW_ENGINE_CONFIG or pass an explicit path."
        )
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Configuration root must be a mapping, got {type(data)!r}")
    if not data:
        raise ValueError(
            f"SECURITY: configuration at {path} is empty. Refusing to start "
            "with defaults - see the note in _read_yaml."
        )
    return data


def _resolve_placeholders(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Expand ``${VAR}`` / ``${VAR:-default}`` against the environment.

    The config file is version-controlled and readable by anyone with repo
    access, so it must not carry secret material. Placeholders keep the *shape*
    of the configuration reviewable while the value comes from the
    environment. An unresolved placeholder becomes an empty string rather than
    the literal ``${...}``, so a missing secret degrades to "no protection"
    instead of becoming a constant that looks configured.
    """
    pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

    def _walk(node: Any) -> Any:
        if isinstance(node, str):
            def substitute(match: re.Match) -> str:
                name, fallback = match.group(1), match.group(2)
                value = os.environ.get(name)
                if value is None:
                    value = fallback if fallback is not None else ""
                return value
            return pattern.sub(substitute, node)
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(v) for v in node]
        return node

    return _walk(raw)


def _apply_env_secrets(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Overlay credentials supplied through the environment onto *raw*.

    API keys must not live in a version-controlled YAML: the repository that
    shipped one hashed from the literal word ``"test"``, which is a public,
    working credential for every deployment that copied it (§38). They are now
    injected from the environment - a Kubernetes Secret, a mounted file, the
    process supervisor - so the repository can be read by anyone without
    granting them access.

    ``NSFW_API_KEYS`` accepts either JSON::

        NSFW_API_KEYS='{"svc": "<sha256-hex>"}'

    or the ``key=digest`` semicolon form::

        NSFW_API_KEYS='svc=<sha256-hex>;probe=<sha256-hex>'

    ``NSFW_KEY_TENANTS`` maps a key to the tenant it is entitled to::

        NSFW_KEY_TENANTS='{"svc": "acme"}'
    """
    security = raw.setdefault("security", {})
    if not isinstance(security, dict):
        return raw

    keys_env = os.environ.get("NSFW_API_KEYS", "").strip()
    if keys_env:
        try:
            parsed = json.loads(keys_env)
            if not isinstance(parsed, dict):
                raise ValueError("expected a JSON object")
        except ValueError:
            parsed = {}
            for chunk in keys_env.replace("\n", ";").split(";"):
                if "=" in chunk:
                    key_id, _, digest = chunk.partition("=")
                    if key_id.strip():
                        parsed[key_id.strip()] = digest.strip()
        merged = dict(security.get("api_keys") or {})
        merged.update({str(k): str(v).strip() for k, v in parsed.items()})
        security["api_keys"] = merged
        logger.info(
            "loaded %d API key(s) from NSFW_API_KEYS", len(parsed)
        )

    tenants_env = os.environ.get("NSFW_KEY_TENANTS", "").strip()
    if tenants_env:
        try:
            parsed_tenants = json.loads(tenants_env)
            if isinstance(parsed_tenants, dict):
                merged_t = dict(security.get("key_tenants") or {})
                merged_t.update({str(k): str(v).strip() for k, v in parsed_tenants.items()})
                security["key_tenants"] = merged_t
                logger.info("loaded %d tenant binding(s) from NSFW_KEY_TENANTS", len(parsed_tenants))
        except ValueError as exc:
            logger.error("NSFW_KEY_TENANTS is not valid JSON (%s) - ignoring", exc)

    return raw


def load_config(path: str | os.PathLike[str] | None = None) -> EngineConfig:
    """Load and validate the engine configuration.

    When *path* is omitted the ``NSFW_ENGINE_CONFIG`` environment variable is
    consulted, falling back to the packaged default.
    """
    if path is None:
        path = os.environ.get("NSFW_ENGINE_CONFIG", DEFAULT_CONFIG_PATH)
    config_path = Path(path)
    raw = _read_yaml(config_path)
    raw = _resolve_placeholders(raw)
    raw = _apply_env_secrets(raw)
    return EngineConfig.model_validate(raw)


@lru_cache(maxsize=1)
def get_config() -> EngineConfig:
    """Cached accessor for the process-wide engine configuration."""
    return load_config()


@lru_cache(maxsize=1)
def get_logging_config_path() -> Path:
    """Location of the structured logging config."""
    override = os.environ.get("NSFW_LOGGING_CONFIG")
    return Path(override) if override else DEFAULT_LOGGING_CONFIG_PATH
