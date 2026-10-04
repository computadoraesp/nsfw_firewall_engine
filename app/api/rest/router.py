"""FastAPI router exposing the management and audit REST surface.

Endpoints
---------
``GET  /health``          engine readiness
``GET  /config``          safe configuration summary
``POST /classify``        classify a base64-encoded payload
``POST /classify/text``   classify a text / HTML document
``POST /classify/raw``    classify a raw request body

The router never raises on classification errors; failures are reported in the
response body so the firewall can fail open with full visibility.
"""

from __future__ import annotations

import base64
import binascii
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.concurrency import run_in_threadpool

from app.api.grpc.handlers import media_type_from_name
from app.api.rest.schemas import (
    ClassifyBase64Request,
    ClassifyResponse,
    ClassifyTextRequest,
    ConfigResponse,
    EnforceResponse,
    HealthResponse,
    StageResultSchema,
)
from app.core.engine import ClassificationResult, NsfwEngine
from app.core.metrics import (
    record_enforcement,
    record_process_resources,
    record_queue_latency,
    record_rate_limited,
    record_request,
    record_request_error,
    render_latest,
    set_queue_depth,
    set_startup_time,
)
from app.core.security import (
    AuthenticationError,
    AuthorizationError,
    Permission,
    Principal,
    SecurityContext,
)
from app.core.resilience import RateLimiter
from app.services.content_inspector import inspect_payload
from app.services.enforcement import HttpEnforcementAdapter

logger = logging.getLogger("nsfw_engine.api.rest.router")

router = APIRouter()

#: In-flight request counter backing the ``nsfw_queue_depth`` gauge (§31).
#: A dict rather than a plain int so the middleware closure can mutate it without
#: a ``nonlocal`` declaration; the whole thing is process-local by design, since
#: per-pod depth is what an autoscaler needs (HPA reads it per replica).
_IN_FLIGHT = {"depth": 0}

#: Wall-clock origin for the startup-time metric. Captured at *import* time so it
#: covers interpreter start, config loading and model loading - all of which
#: happen before ``create_app`` is reached. Reading it inside ``create_app``
#: instead would report only the app-construction cost and systematically
#: under-report a slow boot by however long model loading took.
_PROCESS_START = time.perf_counter()


def get_engine(request: Request) -> NsfwEngine:
    """Dependency that yields the engine stored on ``app.state``."""
    engine = getattr(request.app.state, "engine", None)
    if engine is None:  # pragma: no cover - misconfiguration guard
        raise HTTPException(status_code=503, detail="engine not initialised")
    return engine


def get_security(request: Request) -> SecurityContext:
    """Dependency that yields the security context stored on ``app.state``."""
    context = getattr(request.app.state, "security", None)
    if context is None:  # pragma: no cover - misconfiguration guard
        raise HTTPException(status_code=503, detail="security context not initialised")
    return context


def get_rate_limiter(request: Request) -> Optional[RateLimiter]:
    """Dependency that yields the rate limiter, or ``None`` when disabled."""
    return getattr(request.app.state, "rate_limiter", None)


def enforce_rate_limit(
    request: Request,
    security: SecurityContext = Depends(get_security),
    limiter: Optional[RateLimiter] = Depends(get_rate_limiter),
) -> Principal:
    """Authenticate **and** throttle the caller (§17).

    Rate limiting runs after authentication so the budget is charged per
    principal rather than per source IP: behind an NGFW every request may share
    one address, and keying on IP would let a single tenant exhaust the whole
    engine's capacity (§34).

    The rejection is an explicit ``429`` with ``Retry-After`` - never a silent
    allow. Failing open under load would be indistinguishable from a working
    filter to the client, which is the policy bypass §38 warns about.
    """
    principal = _authenticate(request, security, Permission.CLASSIFY)
    if limiter is None:
        return principal
    key = RateLimiter.key_for(principal.tenant_id, principal.key_id)
    allowed, retry_after = limiter.check(key)
    if not allowed:
        security.audit("rate_limited", principal, retry_after=retry_after)
        record_rate_limited(principal.tenant_id)
        logger.warning(
            "rate limit hit for tenant=%r key=%r (retry in %.2fs)",
            principal.tenant_id, principal.key_id, retry_after,
        )
        raise HTTPException(
            status_code=429,
            detail="rate limit exceeded",
            headers={
                "Retry-After": str(max(1, int(retry_after + 0.999))),
                "X-RateLimit-Limit": str(int(limiter.rate)),
            },
        )
    return principal


# Same marker as require(): ops tooling and tests identify protected routes by
# this attribute rather than guessing from the dependency list.
enforce_rate_limit.__nsfw_permission__ = Permission.CLASSIFY.value  # type: ignore[attr-defined]


def _authenticate(
    request: Request, security: SecurityContext, permission: Permission
) -> Principal:
    """Authenticate the caller and check *permission*, mapping errors to HTTP."""
    try:
        principal = security.authenticate(
            _extract_api_key(request),
            tenant_id=request.headers.get("x-tenant-id", ""),
            require_tenant=security.config.require_tenant_header,
        )
    except AuthenticationError as exc:
        security.audit("auth_failed")
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except AuthorizationError as exc:
        security.audit("authz_denied", permission=permission.value)
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    try:
        security.authorize(principal, permission)
    except AuthorizationError as exc:
        security.audit("authz_denied", principal, permission=permission.value)
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return principal


def _extract_api_key(request: Request) -> Optional[str]:
    """Read the credential from ``X-API-Key`` or ``Authorization: Bearer``."""
    header = request.headers.get("x-api-key")
    if header:
        return header.strip()
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def require(permission: Permission):
    """Build a FastAPI dependency enforcing *permission* for the caller.

    Probes stay public: ``/health``, ``/metrics`` and ``/`` never use this.
    """

    def dependency(
        request: Request,
        security: SecurityContext = Depends(get_security),
    ) -> Principal:
        return _authenticate(request, security, permission)

    # Marker used by tests/ops tooling to identify protected routes without
    # guessing from the dependency list.
    dependency.__nsfw_permission__ = permission.value  # type: ignore[attr-defined]
    return dependency


def _decode_base64(value: str) -> bytes:
    """Decode a base64 string, tolerating a ``data:`` URI prefix."""
    payload = value.split(",", 1)[1] if value.startswith("data:") else value
    try:
        return base64.b64decode(payload, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid base64 payload: {exc}") from exc


def to_response(
    result: ClassificationResult, inspection: Optional[dict] = None
) -> ClassifyResponse:
    """Convert an engine result into the REST response model.

    ``record_enforcement`` is called here because this is the single funnel every
    legacy classify endpoint passes through (``/classify``, ``/classify/text``,
    ``/classify/raw``). Emitting the counter anywhere else would mean three call
    sites to keep in sync, and a metric that only some paths update is worse
    than none - it under-reports blocks, which is the one number an operator
    most needs to trust.
    """
    record_enforcement(result.action or "ALLOW")
    inspection = inspection or {}
    return ClassifyResponse(
        verdict=result.verdict.value,
        decided_by=result.decided_by.value,
        score=float(result.score),
        total_latency_ms=float(result.total_latency_ms),
        media_type=result.media_type.value,
        request_id=result.request_id,
        should_block=result.should_block,
        stages=[StageResultSchema(**s.as_dict()) for s in result.stages],
        text=result.text,
        error=result.error,
        action=result.action or "ALLOW",
        policy_id=result.policy_id,
        from_cache=bool(result.from_cache),
        content_sha256=str(inspection.get("sha256", "")),
        detected_mime=str(inspection.get("mime", "")),
    )


def _secure_inspect(payload: bytes, config) -> dict:
    """Run the content inspector and reject payloads that fail security checks.

    A MIME mismatch is *advisory* here (the sniffed type is recorded and
    returned), while size, dimension and decompression-bomb violations are
    rejected with ``400`` so hostile payloads never reach a decoder.
    """
    inspection = inspect_payload(
        payload, max_bytes=config.preprocessing.max_image_bytes, enforce_mime=False
    ) or {}
    if inspection and not inspection.get("valid", True):
        raise HTTPException(
            status_code=400, detail=str(inspection.get("error") or "payload rejected")
        )
    return inspection


@router.get("/health", response_model=HealthResponse, tags=["ops"])
def health(engine: NsfwEngine = Depends(get_engine)) -> HealthResponse:
    """Liveness / readiness probe."""
    info = engine.health()
    return HealthResponse(
        healthy=bool(info.get("healthy", False)),
        version=str(info.get("version", "")),
        mode=str(info.get("mode", "triage")),
        active_providers=list(info.get("active_providers") or []),
        runtime_available=bool(info.get("runtime_available", False)),
        models_loaded=dict(info.get("models_loaded") or {}),
        uptime_seconds=int(info.get("uptime_seconds", 0)),
        loaded_models_count=int(info.get("loaded_models_count", 0)),
        text_model_loaded=bool(info.get("text_model_loaded", False)),
        cache=dict(info.get("cache") or {}),
        policy=dict(info.get("policy") or {}),
        security=dict(info.get("security") or {}),
        firewall_mode=str(info.get("firewall_mode", "enforcement")),
    )


@router.get("/metrics", response_class=PlainTextResponse, tags=["ops"])
def metrics() -> PlainTextResponse:
    """Prometheus scrape endpoint (Sec. 31).

    Works with or without ``prometheus_client`` installed - the engine ships a
    built-in exposition fallback so scraping never fails.

    ``record_process_resources`` is invoked here rather than from a background
    timer so the CPU/RSS gauges are sampled at scrape time. That keeps them
    meaningful (they cover the interval since the previous scrape) without
    spawning a thread that runs even when nobody is watching.
    """
    record_process_resources()
    return PlainTextResponse(render_latest(), media_type="text/plain; version=0.0.4")


@router.get("/config", response_model=ConfigResponse, tags=["ops"])
def get_config_summary(
    engine: NsfwEngine = Depends(get_engine),
    principal: Principal = Depends(require(Permission.READ_CONFIG)),
) -> ConfigResponse:
    """Return the decision thresholds and timeouts in effect."""
    config = engine.config
    return ConfigResponse(
        version=config.engine.version,
        mode=config.engine.mode,
        thresholds=config.thresholds.model_dump(),
        timeouts=config.timeouts.model_dump(),
    )


@router.post("/classify", response_model=ClassifyResponse, tags=["classify"])
async def classify_base64(
    payload: ClassifyBase64Request,
    engine: NsfwEngine = Depends(get_engine),
    security: SecurityContext = Depends(get_security),
    principal: Principal = Depends(enforce_rate_limit),
) -> ClassifyResponse:
    """Classify a base64-encoded image / video frame."""
    raw = _decode_base64(payload.image_base64)
    inspection = _secure_inspect(raw, engine.config)
    overrides = payload.overrides.as_engine_overrides() if payload.overrides else None
    media_type = media_type_from_name(payload.media_type)
    result = await run_in_threadpool(
        engine.classify,
        raw,
        media_type,
        payload.request_id,
        payload.text,
        overrides,
    )
    security.audit(
        "classify",
        principal,
        verdict=result.verdict.value,
        action=result.action,
        media_type=result.media_type.value,
        content_sha256=inspection.get("sha256"),
        from_cache=result.from_cache,
    )
    return to_response(result, inspection)


@router.post("/classify/text", response_model=ClassifyResponse, tags=["classify"])
async def classify_text(
    payload: ClassifyTextRequest,
    engine: NsfwEngine = Depends(get_engine),
) -> ClassifyResponse:
    """Classify a text / HTML document."""
    overrides = payload.overrides.as_engine_overrides() if payload.overrides else None
    result = await run_in_threadpool(
        engine.classify_text,
        payload.text,
        payload.request_id,
        media_type_from_name(payload.media_type),
        overrides,
    )
    return to_response(result)


@router.post("/classify/raw", response_model=ClassifyResponse, tags=["classify"])
async def classify_raw(
    request: Request,
    media_type: str = Query("IMAGE"),
    text: Optional[str] = Query(None),
    request_id: str = Query(""),
    engine: NsfwEngine = Depends(get_engine),
) -> ClassifyResponse:
    """Classify a raw request body (e.g. ``curl --data-binary @file``)."""
    raw = await request.body()
    if not raw:
        raise HTTPException(status_code=400, detail="empty request body")
    inspection = _secure_inspect(raw, engine.config)
    result = await run_in_threadpool(
        engine.classify,
        raw,
        media_type_from_name(media_type),
        request_id,
        text,
        None,
    )
    return to_response(result, inspection)


@router.post("/enforce", response_model=EnforceResponse, tags=["enforce"])
async def enforce(
    payload: ClassifyBase64Request,
    tenant_id: str = Query(""),
    engine: NsfwEngine = Depends(get_engine),
    security: SecurityContext = Depends(get_security),
    principal: Principal = Depends(require(Permission.ENFORCE)),
) -> EnforceResponse:
    """Classify then translate the decision into a firewall/SWG response.

    This is what an inline proxy or NGFW calls when it needs the actual status
    code, headers and block page rather than the raw classification.
    """
    raw = _decode_base64(payload.image_base64)
    _secure_inspect(raw, engine.config)
    overrides = payload.overrides.as_engine_overrides() if payload.overrides else None
    result = await run_in_threadpool(
        engine.classify,
        raw,
        media_type_from_name(payload.media_type),
        payload.request_id,
        payload.text,
        overrides,
    )
    decision = engine.policy.decide(
        result, tenant_id=tenant_id or principal.tenant_id
    )
    enforcement = HttpEnforcementAdapter(engine.config.policy).response_for(decision)
    security.audit(
        "enforce",
        principal,
        verdict=decision.verdict,
        action=decision.action.value,
        policy_id=decision.policy_id,
        status_code=enforcement.status_code,
    )
    return EnforceResponse(
        action=decision.action.value,
        policy_id=decision.policy_id,
        reason=decision.reason,
        status_code=enforcement.status_code,
        headers=enforcement.headers,
        body=enforcement.body.decode("utf-8", errors="replace"),
        is_blocking=enforcement.is_blocking,
        risk_score=decision.risk_score,
        would_be_action=decision.would_be_action,
        mode=decision.mode,
    )


@router.get("/audit", tags=["ops"])
def audit_entries(
    limit: int = Query(100, ge=1, le=1000),
    security: SecurityContext = Depends(get_security),
    principal: Principal = Depends(require(Permission.READ_AUDIT)),
) -> dict:
    """Recent audit records (metadata only - never payload bytes, §18)."""
    return {
        "entries": security.audit_log.entries(limit),
        "total": len(security.audit_log),
    }


@router.get("/me", tags=["ops"])
def whoami(principal: Principal = Depends(require(Permission.READ_CONFIG))) -> dict:
    """Identity and permissions of the calling principal."""
    return principal.as_dict()


@router.get("/", include_in_schema=False)
def index() -> JSONResponse:
    return JSONResponse(
        {"service": "nsfw-firewall-engine", "docs": "/docs", "health": "/health"}
    )


def create_app(
    engine: Optional[NsfwEngine] = None, config: Optional["EngineConfig"] = None
) -> "FastAPI":
    """Build a FastAPI application wired to a :class:`NsfwEngine` instance."""
    from fastapi import FastAPI  # imported lazily to keep module import light

    if config is None and engine is not None:
        config = engine.config
    if config is None:
        from app.core.config import get_config

        config = get_config()
    if engine is None:
        engine = NsfwEngine(config)

    app = FastAPI(
        title="NSFW Firewall Engine",
        version=config.engine.version,
        description="Triage-based NSFW classification (Fast -> Deep -> Multimodal).",
    )
    app.state.engine = engine
    app.state.security = SecurityContext(config.security)

    @app.middleware("http")
    async def _metrics_middleware(request: Request, call_next):
        """Count requests, track in-flight depth and measure queueing (§31).

        ``queue_depth`` is a real gauge here rather than a simulation: it is
        incremented before the handler runs and decremented in a ``finally``, so
        it reports requests actually in flight. That is the signal an operator
        needs to tell saturation from a burst.

        ``queue_latency`` is measured from the moment Starlette hands the request
        to this middleware until the endpoint actually starts running - i.e. the
        delay attributable to everything ahead of the handler (dependency
        resolution, thread-pool dispatch), not inference time. Together with the
        in-flight gauge it separates "too much work in the process" from "the
        model is slow".

        Errors are counted from the *response status* rather than from a
        try/except around ``call_next``. An exception raised inside the endpoint
        is converted to a 500 by the surrounding error middleware, which may sit
        outside this one; inspecting the status we return is the only way to see
        faults this layer would otherwise never learn about.
        """
        tenant = request.headers.get("x-tenant-id", "")
        endpoint = request.url.path
        record_request(tenant, endpoint)
        set_queue_depth(_IN_FLIGHT["depth"] + 1)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            _IN_FLIGHT["depth"] = max(0, _IN_FLIGHT["depth"] - 1)
            set_queue_depth(_IN_FLIGHT["depth"])
        record_queue_latency(time.perf_counter() - started)
        if response.status_code >= 500:
            record_request_error(endpoint)
        return response

    # Rate limiting (§17). Absent from app.state when disabled, which the
    # dependency reads as "do not throttle" - so the limiter costs nothing at
    # all on deployments that have not opted in.
    if config.security.rate_limit_enabled:
        app.state.rate_limiter = RateLimiter(
            rate=config.security.rate_limit_per_second,
            capacity=config.security.rate_limit_burst,
            max_keys=config.security.rate_limit_max_keys,
        )
        logger.info(
            "rate limiting enabled: %.0f req/s, burst %.0f, per (tenant, principal)",
            config.security.rate_limit_per_second,
            config.security.rate_limit_burst,
        )
    app.include_router(router)
    # The stable, versioned contract (pront.md §20). Registered after the
    # legacy router so /v1 paths always resolve - there is no overlap between
    # the two, but ordering keeps the OpenAPI document grouped legacy-first.
    from app.api.rest.v1 import router as v1_router

    app.include_router(v1_router)

    # §31. Measured from interpreter start so model loading is included - a slow
    # boot otherwise looks exactly like a deployment receiving no traffic.
    set_startup_time(time.perf_counter() - _PROCESS_START)
    return app


if __name__ == "__main__":  # pragma: no cover - runtime entrypoint
    import uvicorn

    from app.core.config import get_config
    from app.core.logging_setup import setup_logging

    setup_logging(level=get_config().observability.log_level)
    settings = get_config()
    uvicorn.run(
        create_app(engine=NsfwEngine(settings)),
        host=settings.transport.rest.host,
        port=settings.transport.rest.port,
    )


