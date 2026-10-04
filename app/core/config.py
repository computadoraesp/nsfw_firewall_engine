"""Configuration loading and validation for the NSFW Firewall Engine.

The engine configuration is defined in ``config/engine_config.yaml``. This
module parses that file into strongly typed :class:`pydantic.BaseModel`
instances so that the rest of the codebase can rely on validated values.

The location of the YAML file can be overridden with the
``NSFW_ENGINE_CONFIG`` environment variable; otherwise the default
``config/engine_config.yaml`` relative to the project root is used.
"""

from __future__ import annotations

import os
from functools import lru_cache
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger("nsfw_engine.core.config")

# Project root: <repo>/nsfw_firewall_engine
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "engine_config.yaml"
DEFAULT_LOGGING_CONFIG_PATH = PROJECT_ROOT / "config" / "logging_config.yaml"


class EngineMeta(BaseModel):
    name: str = "nsfw-firewall-engine"
    version: str = "1.0.0"
    environment: str = "production"
    mode: str = "triage"
    request_timeout_ms: int = 250
    workers: int = 4
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


class Thresholds(BaseModel):
    fast_path: StageThresholds = Field(
        default_factory=lambda: StageThresholds(hard_nsfw=0.85, hard_sfw=0.15)
    )
    deep_path: StageThresholds = Field(
        default_factory=lambda: StageThresholds(hard_nsfw=0.80, hard_sfw=0.20)
    )
    multimodal: MultimodalThresholds = Field(default_factory=MultimodalThresholds)
    text: TextThresholds = Field(default_factory=TextThresholds)


class Timeouts(BaseModel):
    fast_path_ms: int = 10
    deep_path_ms: int = 40
    multimodal_ms: int = 90
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
    deep_path_model: str = "models_onnx/deep_path_efficientnet.onnx"
    multimodal_model: str = "models_onnx/multimodal_clip.onnx"
    text_model: str = "models_onnx/text_distilbert.onnx"
    log_dir: str = "logs"


class Preprocessing(BaseModel):
    fast_path_resize: Tuple[int, int] = (224, 224)
    deep_path_resize: Tuple[int, int] = (384, 384)
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
    audit_enabled: bool = True
    max_audit_entries: int = 1000
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
    hash_salt: str = "enterprise-nsfw-salt"


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
    host: str = "0.0.0.0"
    port: int = 50051
    max_workers: int = 8
    max_message_bytes: int = 16 * 1024 * 1024


class IcapTransport(BaseModel):
    host: str = "0.0.0.0"
    port: int = 1344
    max_body_bytes: int = 32 * 1024 * 1024
    service_tag: str = "nsfw-firewall"


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
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Configuration root must be a mapping, got {type(data)!r}")
    return data


def load_config(path: str | os.PathLike[str] | None = None) -> EngineConfig:
    """Load and validate the engine configuration.

    When *path* is omitted the ``NSFW_ENGINE_CONFIG`` environment variable is
    consulted, falling back to the packaged default.
    """
    if path is None:
        path = os.environ.get("NSFW_ENGINE_CONFIG", DEFAULT_CONFIG_PATH)
    config_path = Path(path)
    raw = _read_yaml(config_path)
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

