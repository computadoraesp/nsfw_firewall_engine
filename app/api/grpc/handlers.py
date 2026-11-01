"""gRPC request handlers / adapters for the NSFW Firewall Engine.

This module translates between the generated protobuf messages and the
engine's native Python API. The generated code (``nsfw_engine_pb2`` /
``nsfw_engine_pb2_grpc``) is produced from ``proto/nsfw_engine.proto``:

    Python -m grpc_tools.protoc -I proto --Python_out=proto --grpc_Python_out=proto proto/nsfw_engine.proto

When ``grpcio`` is not installed the module still imports cleanly: the mapping
helpers remain usable and :class:`NsfwEngineServicer` raises a descriptive error
only if instantiated.
"""

from __future__ import annotations

import logging
from typing import Iterable, Iterator, Optional

from app.core.engine import ClassificationResult, NsfwEngine
from app.core.metrics import record_rate_limited
from app.core.resilience import RateLimiter
from app.core.security import Permission
from app.models.base import DecisionPath, MediaType, Verdict

logger = logging.getLogger("nsfw_engine.api.grpc.handlers")


class _Unauthenticated(Exception):
    """Raised when a gRPC call carries no valid API key."""


class _RateLimited(Exception):
    """Raised when a gRPC call exceeds the per-principal budget (§17)."""

    def __init__(self, retry_after: float) -> None:
        super().__init__(f"rate limit exceeded; retry in {retry_after:.2f}s")
        self.retry_after = retry_after


def authenticate(context, engine) -> Optional[str]:
    """Authorise a gRPC call by API key from request metadata (§16, §35).

    Mirrors the REST dependency: the key travels in ``x-api-key`` (or
    ``authorization: Bearer``) metadata, probes/health stay unauthenticated.
    Returns the principal key id, or ``None`` when auth is disabled.
    """
    security = getattr(engine, "security", None)
    if security is None or not security.enabled:
        return None
    metadata = {}
    try:
        metadata = {key.lower(): value for key, value in (context.invocation_metadata() or [])}
    except Exception:  # noqa: BLE001 - unit tests may pass a stub context
        metadata = {}
    presented = metadata.get("x-api-key")
    if not presented:
        authorization = metadata.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            presented = authorization[7:].strip()
    tenant = metadata.get("x-tenant-id", "")
    try:
        # SECURITY: require_tenant is forwarded from configuration, exactly as
        # REST does. It used to be omitted here, so `security.require_tenant_header`
        # protected the REST surface while the gRPC surface silently ignored it -
        # two transports, one engine, two different authentication contracts.
        principal = security.authenticate(
            presented,
            tenant_id=tenant,
            require_tenant=bool(
                getattr(security.config, "require_tenant_header", False)
            ),
        )
        principal.require(Permission.CLASSIFY)
        throttle(context, engine, principal)
    except Exception as exc:  # noqa: BLE001 - surfaced to the client as UNAUTHENTICATED
        security.audit("grpc_auth_failed")
        raise _Unauthenticated(str(exc)) from exc
    return principal.key_id


def throttle(context, engine, principal) -> None:
    """Per-principal rate limit for gRPC (§17).

    SECURITY: classification is CPU-bound inference, and this transport had no
    limiter at all - one client could saturate every worker in the thread pool
    for free. The bucket is keyed on the *principal*, not the socket peer: a
    deployment behind an NGFW has every call arriving from one address, and
    keying on that address would collapse the entire tenant estate into a
    single bucket, so one noisy caller could throttle everyone.
    """
    limiter = getattr(engine, "rate_limiter", None)
    if limiter is None:
        return
    allowed, retry_after = limiter.check(
        RateLimiter.key_for(principal.tenant_id, principal.key_id)
    )
    if not allowed:
        try:
            context.set_trailing_metadata(
                (("retry-after", str(max(1, int(retry_after + 0.999)))),)
            )
        except Exception:  # noqa: BLE001 - metadata is best-effort
            pass
        record_rate_limited(principal.tenant_id)
        raise _RateLimited(retry_after)

# -- optional generated protobuf imports -------------------------------------
try:  # pragma: no cover - depends on generated artifacts
    from proto import nsfw_engine_pb2 as pb  # type: ignore
    from proto import nsfw_engine_pb2_grpc as pb_grpc  # type: ignore

    GRPC_AVAILABLE = True
except Exception:  # noqa: BLE001
    try:  # pragma: no cover - alternate import layout
        import nsfw_engine_pb2 as pb  # type: ignore
        import nsfw_engine_pb2_grpc as pb_grpc  # type: ignore

        GRPC_AVAILABLE = True
    except Exception:  # noqa: BLE001
        pb = None
        pb_grpc = None
        GRPC_AVAILABLE = False


# Human-readable <-> enum mappings that work without the generated code.
_MEDIA_NAME_TO_ENUM = {
    "IMAGE": MediaType.IMAGE,
    "VIDEO": MediaType.VIDEO,
    "TEXT": MediaType.TEXT,
    "HTML": MediaType.HTML,
    "UNKNOWN": MediaType.UNKNOWN,
}


def media_type_from_pb(value: int) -> MediaType:
    """Map a protobuf ``MediaType`` enum int to the internal enum."""
    if pb is None:
        return MediaType.UNKNOWN
    mapping = {
        pb.MEDIA_IMAGE: MediaType.IMAGE,
        pb.MEDIA_VIDEO_FRAME: MediaType.VIDEO,
        pb.MEDIA_TEXT: MediaType.TEXT,
        pb.MEDIA_HTML: MediaType.HTML,
        pb.MEDIA_UNSPECIFIED: MediaType.UNKNOWN,
    }
    return mapping.get(value, MediaType.UNKNOWN)


def media_type_from_name(name: str) -> MediaType:
    """Map a string media type (used by the REST/ICAP adapters) to the enum."""
    return _MEDIA_NAME_TO_ENUM.get((name or "").upper(), MediaType.UNKNOWN)


def overrides_from_pb(overrides) -> Optional[dict]:
    """Convert a ``ThresholdOverrides`` message into a plain dict."""
    if overrides is None:
        return None
    result: dict = {}
    for field in ("fast_hard_nsfw", "deep_hard_nsfw", "multimodal_hard_nsfw"):
        value = getattr(overrides, field, 0.0)
        if value:
            result[field] = float(value)
    return result or None


def result_to_pb(result: ClassificationResult, explain: bool = False):
    """Build a ``ClassifyResponse`` message from a :class:`ClassificationResult`."""
    if pb is None:  # pragma: no cover - guarded by caller
        raise RuntimeError("protobuf bindings are not available")
    response = pb.ClassifyResponse(
        verdict=_VERDICT_TO_PB.get(result.verdict, pb.VERDICT_UNSPECIFIED),
        decided_by=_PATH_TO_PB.get(result.decided_by, pb.PATH_UNSPECIFIED),
        risk_score=float(result.score),
        total_latency_ms=int(round(result.total_latency_ms)),
        request_id=result.request_id or "",
        error=result.error or "",
    )
    if explain:
        for stage in result.stages:
            response.stages.add(
                path=_PATH_TO_PB.get(stage.path, pb.PATH_UNSPECIFIED),
                score=float(stage.score),
                latency_ms=int(round(stage.latency_ms)),
                executed=bool(stage.executed),
            )
    return response


def build_media_type_pb(media_type: MediaType) -> int:
    if pb is None:
        return 0
    return _MEDIA_TO_PB.get(media_type, 0)


# These maps are populated lazily once the generated bindings exist.
_MEDIA_TO_PB: dict = {}
_VERDICT_TO_PB: dict = {}
_PATH_TO_PB: dict = {}


def _populate_enums() -> None:
    if pb is None:
        return
    _MEDIA_TO_PB.update(
        {
            MediaType.IMAGE: pb.MEDIA_IMAGE,
            MediaType.VIDEO: pb.MEDIA_VIDEO_FRAME,
            MediaType.TEXT: pb.MEDIA_TEXT,
            MediaType.HTML: pb.MEDIA_HTML,
            MediaType.UNKNOWN: pb.MEDIA_UNSPECIFIED,
        }
    )
    _VERDICT_TO_PB.update(
        {
            Verdict.SFW: pb.VERDICT_ALLOW,
            Verdict.NSFW: pb.VERDICT_BLOCK,
            Verdict.REVIEW: pb.VERDICT_REVIEW,
            Verdict.UNKNOWN: pb.VERDICT_UNSPECIFIED,
        }
    )
    _PATH_TO_PB.update(
        {
            DecisionPath.FAST: pb.PATH_FAST,
            DecisionPath.DEEP: pb.PATH_DEEP,
            DecisionPath.MULTIMODAL: pb.PATH_MULTIMODAL,
            DecisionPath.PREMIUM: getattr(pb, "PATH_PREMIUM", pb.PATH_UNSPECIFIED),
            DecisionPath.TEXT: pb.PATH_TEXT_ONLY,
            DecisionPath.UNKNOWN: pb.PATH_UNSPECIFIED,
        }
    )


_populate_enums()


def _authenticate(context, engine) -> None:
    """Authenticate and throttle, aborting the call on failure."""
    try:
        authenticate(context, engine)
    except _Unauthenticated as exc:
        context.abort(16, f"unauthenticated: {exc}")  # UNAUTHENTICATED
    except _RateLimited as exc:
        context.abort(8, str(exc))  # RESOURCE_EXHAUSTED


# -- servicer ----------------------------------------------------------------
if GRPC_AVAILABLE:  # pragma: no cover - depends on generated artifacts

    class NsfwEngineServicer(pb_grpc.NsfwEngineServicer):
        """gRPC service implementation backed by :class:`NsfwEngine`."""

        def __init__(self, engine: NsfwEngine) -> None:
            self.engine = engine

        def Classify(self, request, context):  # noqa: N802 - gRPC naming
            _authenticate(context, self.engine)
            media_type = media_type_from_pb(request.media_type)
            result = self.engine.classify(
                request.payload,
                media_type=media_type,
                request_id=request.request_id,
                text=getattr(request, "html_context", "") or None,
                overrides=overrides_from_pb(request.overrides),
            )
            return result_to_pb(result, explain=request.explain)

        def ClassifyStream(self, request_iterator: Iterable, context):  # noqa: N802
            """Classify a stream of frames, returning the aggregate verdict."""
            _authenticate(context, self.engine)
            frames = []
            last_request = None
            for request in request_iterator:
                last_request = request
                frames.append(request.payload)
            if not frames:
                context.abort(3, "empty stream")  # INVALID_ARGUMENT
            media_type = (
                media_type_from_pb(last_request.media_type)
                if last_request
                else MediaType.IMAGE
            )
            if media_type is MediaType.VIDEO:
                video = self.engine.video_pipeline.analyze_encoded_frames(
                    frames, request_id=getattr(last_request, "request_id", "")
                )
                result = ClassificationResult(
                    verdict=video.verdict,
                    decided_by=video.decided_by,
                    score=video.score,
                    media_type=MediaType.VIDEO,
                    request_id=video.request_id,
                    error=video.error,
                )
            else:
                result = self.engine.classify(
                    frames[-1],
                    media_type=media_type,
                    request_id=getattr(last_request, "request_id", ""),
                )
            return result_to_pb(result, explain=getattr(last_request, "explain", False))

        def Health(self, request, context):  # noqa: N802
            info = self.engine.health()
            return pb.HealthResponse(
                healthy=bool(info["healthy"]),
                version=str(info["version"]),
                active_providers=list(info.get("active_providers") or []),
                uptime_seconds=int(info.get("uptime_seconds", 0)),
                loaded_models_count=int(info.get("loaded_models_count", 0)),
            )

else:

    class NsfwEngineServicer:  # type: ignore[no-redef]
        """Placeholder servicer used when ``grpcio`` is unavailable."""

        def __init__(self, engine: NsfwEngine) -> None:
            self.engine = engine
            raise RuntimeError(
                "grpcio / generated protobuf bindings are not installed. "
                "Run: pip install grpcio grpcio-tools protobuf, then generate the "
                "stubs from proto/nsfw_engine.proto."
            )

