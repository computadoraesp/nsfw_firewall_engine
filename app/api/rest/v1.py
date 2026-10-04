"""The versioned ``/v1`` REST contract (``pront.md`` §20).

Endpoints
---------
``POST /v1/inspect``    classify a payload *and* apply policy (the main entry point)
``POST /v1/classify``   classify only, without the enforcement translation
``POST /v1/batch``      inspect many payloads in one bounded round trip
``GET  /v1/models``     the model registry (§22)
``GET  /v1/policies``   the active rule set (§19)
``POST /v1/policies``   register/replace a tenant or global policy (§19)
``GET  /v1/health``     liveness (§33)
``GET  /v1/ready``      readiness - what Kubernetes and the load balancer use

Design rules that matter here:

* ``/health`` and ``/ready`` stay **unauthenticated** so an orchestrator can
  probe them, but they never disclose configuration beyond a safe summary.
* Every other route requires a permission through the same
  :func:`app.api.rest.router.require` dependency used by the legacy routes, so
  RBAC (§35) is identical on both surfaces.
* Payload limits, MIME checks and decompression-bomb protection are delegated
  to :func:`app.api.rest.router._secure_inspect` - a batch can never be used as
  a way around the per-payload security checks.
"""

from __future__ import annotations

import logging
import time
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from app.api.grpc.handlers import media_type_from_name
from app.api.rest.router import (
    _decode_base64,
    _secure_inspect,
    enforce_rate_limit,
    get_engine,
    get_security,
    require,
    to_response,
)
from app.api.rest.schemas import (
    BatchItemResult,
    BatchRequest,
    BatchResponse,
    DeadLetterListResponse,
    DeadLetterSchema,
    InspectRequest,
    InspectResponse,
    InspectTextRequest,
    ModelDescriptor,
    ModelListResponse,
    ModelStatusResponse,
    ModelStatusUpdate,
    PolicyDocument,
    PolicyListResponse,
    PolicyMutationResponse,
    PolicyRuleSchema,
    ReadyResponse,
)
from app.core.engine import NsfwEngine
from app.core.metrics import record_dead_letter, record_enforcement
from app.models.base import MediaType
from app.core.request_context import context_from_headers
from app.core.security import Permission, Principal, SecurityContext
from app.services.content_inspector import inspect_payload

logger = logging.getLogger("nsfw_engine.api.rest.v1")

#: Prefix is part of the published contract (§20) - never change it in place.
router = APIRouter(prefix="/v1", tags=["v1"])

#: Hard cap on a single batch (§17 resource-exhaustion protection).
MAX_BATCH_ITEMS = 64

#: Verdict -> policy category exposed in the §21 envelope.
_VERDICT_CATEGORY = {
    "NSFW": "explicit",
    "REVIEW": "ambiguous",
    "SFW": "safe",
    "UNKNOWN": "unknown",
}

#: Provenance/licence metadata (§4), mirroring docs/MODEL_PROVENANCE.md. Keeping
#: it here means the API can never claim a licence the registry has not cleared.
_LICENSES = {
    "fast_path": "MIT (nsfwjs code)",
    "deep_path": "LEGAL_REVIEW_REQUIRED",
    "multimodal": "LEGAL_REVIEW_REQUIRED",
    "text": "Apache-2.0 (candidate)",
}


def _models_loaded(result) -> List[str]:
    """Names of the models that actually contributed to *result*."""
    names: List[str] = []
    for stage in result.stages:
        if stage.executed:
            names.append(stage.model or stage.path.value)
    return names


def _stage_scores(result) -> dict:
    """Per-stage score breakdown, the ``scores`` field of the §21 envelope."""
    return {stage.path.value: round(float(stage.score), 6) for stage in result.stages}




def _dead_letter(
    engine: NsfwEngine,
    *,
    tenant_id: str = "",
    endpoint: str = "",
    reason: str = "unknown",
    error: str = "",
    request_id: str = "",
    content_sha256: str = "",
    attempts: int = 1,
    media_type: str = "",
) -> None:
    """Publish an undecidable request to the dead-letter queue (§33).

    Wrapped in a bare ``except`` on purpose. This runs on the *failure* path, so
    raising from here would convert a handled classification error into an
    unhandled 500 - turning a degraded request into a dropped connection. A
    letter that cannot be recorded is a problem worth logging, never worth
    propagating.
    """
    queue = getattr(engine, "dead_letters", None)
    if queue is None:
        return
    try:
        letter = queue.publish(
            tenant_id=tenant_id,
            endpoint=endpoint,
            reason=reason,
            error=error,
            request_id=request_id,
            content_sha256=content_sha256,
            attempts=attempts,
            media_type=media_type,
        )
        logger.warning(
            "dead-letter queued: reason=%s tenant=%s request_id=%s",
            reason,
            tenant_id or "-",
            request_id or "-",
        )
        record_dead_letter(reason)
        if letter is not None:
            logger.debug("dead-letter digest=%s", letter.content_sha256 or "-")
    except Exception as exc:  # noqa: BLE001
        logger.error("failed to publish dead letter (%s): %s", reason, exc)


async def _inspect(
    payload: InspectRequest,
    engine: NsfwEngine,
    security: SecurityContext,
    principal: Principal,
    headers: Optional[dict] = None,
) -> InspectResponse:
    """Shared implementation behind ``/v1/inspect``."""
    # §33 idempotency. Checked before any work so a retry costs a dict lookup
    # rather than a full inference pass. The replay is marked so the caller can
    # tell a fresh decision from a repeated one - silently returning the same
    # body with no marker makes retry bugs very hard to diagnose.
    store = getattr(engine, "idempotency", None)
    replay_key = payload.request_id
    if store is not None and replay_key:
        cached = store.get(principal.tenant_id, replay_key)
        if cached is not None:
            security.audit("inspect_replayed", principal, request_id=replay_key)
            return cached.model_copy(update={"idempotent_replay": True})

    raw = _decode_base64(payload.content_base64)
    inspection = _secure_inspect(raw, engine.config)
    overrides = payload.overrides.as_engine_overrides() if payload.overrides else None
    tenant_id = principal.tenant_id
    context = _context_for(payload)

    # §19: caller dimensions, from the authenticated principal first and the
    # request headers second. A client cannot assert its own identity -
    # `context_from_headers` lets explicit arguments win over headers, and the
    # principal is what is authenticated (§35).
    request_context = context_from_headers(
        headers or {},
        tenant_id=tenant_id,
        user_id=principal.key_id,
        groups=[getattr(role, "value", str(role)) for role in principal.roles],
        url=payload.url or "",
        domain=payload.domain or context.domain,
    )

    result = await run_in_threadpool(
        engine.classify_with_context,
        raw,
        media_type_from_name(payload.media_type),
        payload.request_id,
        payload.text,
        overrides,
        url=payload.url or "",
        domain=payload.domain or "",
        title=payload.title or "",
    )
    decision = engine.policy.decide(
        result, tenant_id=tenant_id, request_context=request_context
    )

    security.audit(
        "inspect",
        principal,
        verdict=result.verdict.value,
        action=decision.action.value,
        policy_id=decision.policy_id,
        media_type=result.media_type.value,
        content_sha256=inspection.get("sha256"),
        from_cache=result.from_cache,
        mode=decision.mode,
    )
    response = InspectResponse(
        request_id=result.request_id,
        verdict=result.verdict.value,
        decision=decision.action.value,
        policy_id=decision.policy_id,
        category=_VERDICT_CATEGORY.get(result.verdict.value, "unknown"),
        confidence=round(float(result.score), 6),
        score=round(float(result.score), 6),
        scores=_stage_scores(result),
        models_used=_models_loaded(result),
        is_blocking=decision.is_blocking,
        would_be_action=decision.would_be_action,
        mode=decision.mode,
        media_type=result.media_type.value,
        reason=decision.reason,
        from_cache=bool(result.from_cache),
        content_sha256=str(inspection.get("sha256", "")),
        detected_mime=str(inspection.get("mime", "")),
        total_latency_ms=round(float(result.total_latency_ms), 3),
        timed_out=bool(result.timed_out),
        stages=to_response(result).stages,
        text=result.text,
        error=result.error,
        context=context.as_dict(),
        matched_dimensions=decision.matched_dimensions or None,
    )
    if store is not None and replay_key:
        # Only a *successful* decision is remembered. Caching an error would
        # pin a transient failure for the whole TTL and turn a blip into an
        # outage for that caller (§33 bounded retries, not cached errors).
        if not result.error:
            store.remember(principal.tenant_id, replay_key, response)
    # §33 dead-letter. A result carrying an `error` is a request the engine could
    # not decide; policy resolves that to fail_action, which defaults to ALLOW.
    # That is precisely the silent bypass §38 warns about, so the request is
    # captured here while an operator still has a chance to act on it. Only the
    # SHA256 is kept - never the bytes.
    if result.error:
        _dead_letter(
            engine,
            tenant_id=principal.tenant_id,
            endpoint="/v1/inspect",
            reason="classify_error",
            error=result.error,
            request_id=payload.request_id,
            content_sha256=str(inspection.get("sha256") or ""),
            media_type=result.media_type.value,
        )
    return response


@router.post("/inspect", response_model=InspectResponse)
async def inspect(
    payload: InspectRequest,
    request: Request,
    engine: NsfwEngine = Depends(get_engine),
    security: SecurityContext = Depends(get_security),
    principal: Principal = Depends(enforce_rate_limit),
) -> InspectResponse:
    """Classify a payload and return the complete enforcement decision (§20/§21)."""
    return await _inspect(payload, engine, security, principal, headers=request.headers)


@router.post("/classify", response_model=InspectResponse)
async def classify(
    payload: InspectRequest,
    request: Request,
    engine: NsfwEngine = Depends(get_engine),
    security: SecurityContext = Depends(get_security),
    principal: Principal = Depends(enforce_rate_limit),
) -> InspectResponse:
    """Alias of ``/v1/inspect`` kept for clients written against §20's wording.

    Identical behaviour on purpose: a firewall must not be able to bypass policy
    by calling ``classify`` instead of ``inspect``.
    """
    return await _inspect(payload, engine, security, principal, headers=request.headers)

def _context_for(payload: InspectRequest):
    """Extract the §12 context for a request, for audit and explain output.

    Only metadata is retained (title, domain, flags) - never the page body - so
    this is safe to log under ``privacy.retain_raw_payloads: false`` (§18).
    """
    from app.services.html_context import extract_context

    return extract_context(
        payload.text if payload.media_type.upper() == "HTML" else None,
        url=payload.url or "",
        domain=payload.domain or "",
    )


@router.post("/classify/text", response_model=InspectResponse)
async def classify_text_v1(
    payload: InspectTextRequest,
    request: Request,
    engine: NsfwEngine = Depends(get_engine),
    security: SecurityContext = Depends(get_security),
    principal: Principal = Depends(enforce_rate_limit),
) -> InspectResponse:
    """Classify a text or HTML document, with §19 policy context (§12 + §20).

    The versioned counterpart of the legacy ``POST /classify/text``. It exists
    because HTML pages are where the context dimensions matter most: the
    document supplies its own title, meta description and alt text, so a rule on
    ``domain`` or ``url`` sees facts from the page rather than assertions from
    the caller. Routing HTML through only the legacy endpoint meant those
    dimensions never reached policy for that traffic.

    Context handling matches the image path exactly - §12 metadata only, never
    the body - so the two endpoints cannot leak different amounts of content.
    """
    from app.services.html_context import extract_context

    context = extract_context(
        payload.text if payload.media_type.upper() == "HTML" else None,
        url=payload.url or "",
        domain=payload.domain or "",
    )
    request_context = context_from_headers(
        request.headers,
        tenant_id=principal.tenant_id,
        user_id=principal.key_id,
        groups=[getattr(role, "value", str(role)) for role in principal.roles],
        url=payload.url or "",
        domain=payload.domain or context.domain,
    )
    overrides = payload.overrides.as_engine_overrides() if payload.overrides else None
    result = await run_in_threadpool(
        engine.classify_text,
        payload.text,
        payload.request_id,
        MediaType[payload.media_type.upper()],
        overrides,
    )
    decision = engine.policy.decide(
        result, tenant_id=principal.tenant_id, request_context=request_context
    )
    record_enforcement(decision.action.value)
    security.audit(
        "classify_text",
        principal,
        verdict=result.verdict.value,
        action=decision.action.value,
        media_type=result.media_type.value,
        domain=context.domain,
    )
    if result.error:
        # §33: an undecidable document is a document that passed uninspected.
        _dead_letter(
            engine,
            tenant_id=principal.tenant_id,
            endpoint="/v1/classify/text",
            reason="classify_error",
            error=result.error,
            request_id=payload.request_id,
            media_type=result.media_type.value,
        )
    return InspectResponse(
        request_id=result.request_id,
        verdict=result.verdict.value,
        decision=decision.action.value,
        policy_id=decision.policy_id,
        category=_VERDICT_CATEGORY.get(result.verdict.value, "unknown"),
        confidence=round(float(result.score), 6),
        score=round(float(result.score), 6),
        scores=_stage_scores(result),
        models_used=_models_loaded(result),
        is_blocking=decision.is_blocking,
        would_be_action=decision.would_be_action,
        mode=decision.mode,
        media_type=result.media_type.value,
        reason=decision.reason,
        from_cache=bool(result.from_cache),
        total_latency_ms=round(float(result.total_latency_ms), 3),
        timed_out=bool(result.timed_out),
        stages=to_response(result).stages,
        text=result.text,
        error=result.error,
        context=context.as_dict(),
        matched_dimensions=decision.matched_dimensions or None,
    )


@router.post("/batch", response_model=BatchResponse)
async def batch(
    payload: BatchRequest,
    engine: NsfwEngine = Depends(get_engine),
    security: SecurityContext = Depends(get_security),
    principal: Principal = Depends(enforce_rate_limit),
) -> BatchResponse:
    """Inspect up to :data:`MAX_BATCH_ITEMS` payloads in one call (§20).

    Items are processed sequentially on purpose: the cascade is CPU-bound and
    a burst of parallel inference would blow the per-stage latency budget for
    every item instead of failing predictably. Per-item failures are reported
    inline rather than aborting the batch.
    """
    if len(payload.items) > MAX_BATCH_ITEMS:
        raise HTTPException(
            status_code=413,
            detail=f"batch exceeds the maximum of {MAX_BATCH_ITEMS} items",
        )

    started = time.perf_counter()
    results: List[BatchItemResult] = []

    for index, item in enumerate(payload.items):
        try:
            raw = _decode_base64(item.content_base64)
            inspection = inspect_payload(
                raw,
                max_bytes=engine.config.preprocessing.max_image_bytes,
                enforce_mime=False,
            ) or {}
            if inspection and not inspection.get("valid", True):
                raise ValueError(str(inspection.get("error") or "payload rejected"))

            result = await run_in_threadpool(
                engine.classify,
                raw,
                media_type_from_name(item.media_type),
                item.request_id,
                item.text,
                None,
            )
            decision = engine.policy.decide(result, tenant_id=principal.tenant_id)
            security.audit(
                "inspect_batch_item",
                principal,
                verdict=result.verdict.value,
                action=decision.action.value,
                batch_index=index,
            )
            results.append(
                BatchItemResult(
                    request_id=result.request_id,
                    index=index,
                    verdict=result.verdict.value,
                    decision=decision.action.value,
                    score=round(float(result.score), 6),
                    is_blocking=decision.is_blocking,
                    from_cache=bool(result.from_cache),
                    total_latency_ms=round(float(result.total_latency_ms), 3),
                    content_sha256=str(inspection.get("sha256", "")),
                )
            )
        except Exception as exc:  # noqa: BLE001 - one bad item must not fail all
            item_error = f"{type(exc).__name__}: {exc}"
            logger.warning("batch item %d failed: %s", index, item_error)
            security.audit("inspect_batch_failed", principal, batch_index=index)
            results.append(
                BatchItemResult(index=index, request_id=item.request_id, error=item_error)
            )

    return BatchResponse(
        results=results,
        total=len(results),
        blocked=sum(1 for r in results if r.is_blocking),
        errored=sum(1 for r in results if r.error),
        total_latency_ms=round((time.perf_counter() - started) * 1000.0, 3),
    )


@router.get("/models", response_model=ModelListResponse)
def models(
    engine: NsfwEngine = Depends(get_engine),
    principal: Principal = Depends(require(Permission.READ_CONFIG)),
) -> ModelListResponse:
    """The model registry as a machine-readable document (§22).

    Exposes status, license and load state so an operator can answer "is this
    deployment actually running a model, and may I legally run it?" without
    reading the Markdown docs.
    """
    evaluators = {
        "fast_path": (engine.fast, "models_onnx/fast_path_mobilenetv3.onnx"),
        "deep_path": (engine.deep, "models_onnx/deep_path_efficientnet.onnx"),
        "multimodal": (engine.multimodal, "models_onnx/multimodal_clip.onnx"),
        "text": (engine.text_path, "models_onnx/text_distilbert.onnx"),
    }

    described = []
    for stage, (evaluator, source) in evaluators.items():
        stub = bool(getattr(evaluator, "is_stub", True))
        described.append(
            ModelDescriptor(
                model_id=str(getattr(evaluator, "model_name", stage)),
                stage=stage,
                version=engine.model_version,
                runtime=(
                    "onnxruntime" if engine.manager.runtime_available else "heuristic-fallback"
                ),
                source=source,
                license=_LICENSES.get(stage, "unknown"),
                status="candidate" if stub else "production",
                loaded=not stub,
                is_stub=stub,
                kind="cascade",
            )
        )

    # §41 adapters are listed alongside the cascade stages so a deprecated or
    # blocked upstream is *visible* here rather than silently absent - an
    # operator needs to see why OpenNSFW2 is not scoring anything.
    from adapters.registry import describe_all as describe_adapters

    for stage, info in describe_adapters(engine.manager).items():
        described.append(
            ModelDescriptor(
                model_id=str(info.get("name") or stage),
                stage=stage,
                version=engine.model_version,
                runtime=(
                    "onnxruntime" if engine.manager.runtime_available else "heuristic-fallback"
                ),
                source=str(info.get("model_path") or ""),
                license=str(info.get("license") or "unknown"),
                status=str(info.get("status") or "candidate"),
                loaded=bool(info.get("loaded")),
                is_stub=not bool(info.get("available")),
                may_serve=bool(info.get("may_serve", True)),
                kind="adapter",
            )
        )

    return ModelListResponse(
        models=described,
        runtime_available=bool(engine.manager.runtime_available),
        active_providers=list(engine.manager.active_providers()),
        total=len(described),
    )


@router.get("/dead-letters", response_model=DeadLetterListResponse)
def dead_letters(
    drain: bool = Query(False, description="Remove the letters; use for replay drains"),
    limit: int = Query(50, ge=1, le=1000),
    engine: NsfwEngine = Depends(get_engine),
    principal: Principal = Depends(require(Permission.READ_AUDIT)),
) -> DeadLetterListResponse:
    """Requests the engine could not decide (§33 dead-letter queue).

    Read with ``drain=false`` to inspect; ``drain=true`` removes the letters and
    is intended for a replay worker. Removal is irreversible, so inspection is
    the default.

    Requires ``READ_AUDIT`` rather than ``CLASSIFY``: the queue records requests
    the engine *failed* to handle, and their digests, endpoints and tenant ids
    are exactly what an auditor needs and a classification client should not see.

    Payloads are never returned. Each entry carries only a SHA256 digest, so this
    endpoint cannot become a back door to the content that failed (§38).
    """
    queue = getattr(engine, "dead_letters", None)
    if queue is None:
        return DeadLetterListResponse(letters=[], enabled=False, stats={}, total=0)
    letters = queue.drain(limit) if drain else queue.peek(limit)
    return DeadLetterListResponse(
        letters=[DeadLetterSchema(**letter.as_dict()) for letter in letters],
        enabled=True,
        stats=queue.stats(),
        total=len(letters),
    )


@router.post(
    "/models/{stage}/status",
    response_model=ModelStatusResponse,
    status_code=200,
)
def update_model_status(
    stage: str,
    update: ModelStatusUpdate,
    engine: NsfwEngine = Depends(get_engine),
    security: SecurityContext = Depends(get_security),
    principal: Principal = Depends(require(Permission.MANAGE_POLICY)),
) -> ModelStatusResponse:
    """Move a model through its §22 lifecycle.

    Requires ``MANAGE_POLICY`` because promoting a model is the highest-impact
    change an operator can make: it changes what decides whether traffic is
    blocked, without touching the firewall, the API or the policy engine (§50).

    Illegal transitions are refused with ``409``. ``candidate -> production`` is
    one of them, which is deliberate: promotion is supposed to mean "this was
    benchmarked", and §49 forbids the claim without the measurement. To promote
    you go ``candidate -> validated -> production``, and the reason field on each
    hop is what records the evidence.

    .. note::
       Even with ``security.enabled=false`` this endpoint returns ``403`` for an
       anonymous caller, because the unauthenticated principal is read-only. A
       model promotion changes what decides whether traffic is blocked; it is
       not something an unauthenticated caller should be able to do even in a
       development deployment. Configure an API key with ``policy_admin`` or
       ``security_operator`` to exercise it.
    """
    from adapters.base import ModelStatus, StatusTransitionError
    from adapters.registry import servable_adapters, set_status, status_of

    try:
        previous = status_of(stage)
    except KeyError:
        previous = None
    if previous is None:
        raise HTTPException(status_code=404, detail=f"unknown model stage: {stage!r}")

    try:
        new_status = set_status(stage, ModelStatus(update.status))
    except StatusTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:  # pragma: no cover - validator rejects first
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    servable = servable_adapters()
    security.audit(
        "model_status_changed",
        principal,
        stage=stage,
        previous_status=previous.value,
        status=new_status.value,
        reason=update.reason or "",
    )
    logger.warning(
        "model lifecycle change: stage=%s %s -> %s by %s (%s)",
        stage, previous.value, new_status.value, principal.key_id, update.reason or "no reason",
    )

    from adapters.registry import build_adapter

    adapter = build_adapter(stage)
    return ModelStatusResponse(
        stage=stage,
        model_id=getattr(adapter, "name", stage),
        previous_status=previous.value,
        status=new_status.value,
        may_serve=bool(getattr(adapter, "may_serve", True)),
        servable_stages=servable,
    )


@router.get("/policies", response_model=PolicyListResponse)
def policies(
    tenant_id: str = Query("", description="Filter by tenant; empty returns the global policy"),
    engine: NsfwEngine = Depends(get_engine),
    principal: Principal = Depends(require(Permission.READ_CONFIG)),
) -> PolicyListResponse:
    """Return the active rule set as declarative JSON (§19).

    A tenant may only ever read its own policy: the requested tenant must match
    the authenticated principal, otherwise the global policy is returned (§34).
    """
    requested = tenant_id or ""
    if requested and principal.tenant_id and requested != principal.tenant_id:
        raise HTTPException(status_code=403, detail="cross-tenant policy access denied")

    policy = engine.policy.registry.policy_for(requested)
    rules = [
        PolicyRuleSchema(
            field=rule.field,
            operator=rule.operator,
            value=rule.value,
            action=rule.action,
            description=rule.description,
        )
        for rule in policy.rules
    ]
    document = PolicyDocument(
        policy_id=policy.policy_id,
        description=policy.description,
        rules=rules,
        default_action=policy.default_action,
        tenant_id=policy.tenant_id,
    )
    return PolicyListResponse(policies=[document], total=1)


@router.post("/policies", response_model=PolicyMutationResponse, status_code=201)
def create_policy(
    document: PolicyDocument,
    engine: NsfwEngine = Depends(get_engine),
    security: SecurityContext = Depends(get_security),
    principal: Principal = Depends(require(Permission.MANAGE_POLICY)),
) -> PolicyMutationResponse:
    """Register or replace a policy at runtime (§19).

    The body is a *declarative document*, never code: rules go through the same
    operator set as file-based policies, so a policy file can never execute
    anything (§19 "rules must be declarative").

    A non-empty ``tenant_id`` must match the caller, which stops a
    ``policy_admin`` of tenant A from installing rules for tenant B (§34).
    """
    from policy.engine import policy_from_dict

    target_tenant = (document.tenant_id or "").strip()
    if target_tenant and target_tenant != principal.tenant_id:
        raise HTTPException(status_code=403, detail="cross-tenant policy write denied")

    if not document.rules:
        raise HTTPException(status_code=422, detail="a policy must declare at least one rule")

    # PolicyRegistry.add_tenant ignores an empty tenant id, so a global policy is
    # installed by replacing the registry's global_policy directly.
    policy = policy_from_dict(document.model_dump())
    if target_tenant:
        existed = target_tenant in getattr(engine.policy.registry, "_tenant_policies", {})
        engine.policy.registry.add_tenant(target_tenant, policy)
    else:
        existed = False
        engine.policy.registry.global_policy = policy

    security.audit(
        "policy_upsert",
        principal,
        policy_id=document.policy_id,
        tenant_id=target_tenant,
        rules=len(document.rules),
        replaced=existed,
    )
    logger.info(
        "policy %r upserted by %r for tenant %r (%d rules)",
        document.policy_id,
        principal.key_id,
        target_tenant or "(global)",
        len(document.rules),
    )
    return PolicyMutationResponse(
        policy_id=document.policy_id,
        tenant_id=target_tenant,
        rules_applied=len(document.rules),
        created=not existed,
        replaced=existed,
    )


@router.get("/health")
def health(engine: NsfwEngine = Depends(get_engine)) -> dict:
    """Liveness probe: the process is up and answering (§33)."""
    info = engine.health()
    return {
        "healthy": True,
        "version": info.get("version", ""),
        "mode": info.get("mode", "triage"),
        "uptime_seconds": info.get("uptime_seconds", 0),
    }


@router.get("/ready", response_model=ReadyResponse)
def ready(engine: NsfwEngine = Depends(get_engine)) -> ReadyResponse:
    """Readiness probe: is this replica fit to receive traffic (§33)?

    Readiness is intentionally stricter than liveness. A replica running purely
    on the heuristic fallback answers ``ready: false`` - routing production
    traffic to a detector-less instance would silently destroy the accuracy the
    thresholds were tuned for (§49: no claims without evidence).

    Deployments that intentionally run without ONNX weights can point their own
    probe at ``/v1/health`` instead.
    """
    info = engine.health()
    models_loaded = int(info.get("loaded_models_count", 0))
    checks = {
        "runtime_available": bool(info.get("runtime_available", False)),
        "models_loaded": models_loaded > 0,
        "policy_configured": bool(info.get("policy", {}).get("policy_id")),
    }
    is_ready = all(checks.values())
    reason = "" if is_ready else (
        "not ready: " + ", ".join(sorted(k for k, ok in checks.items() if not ok))
    )
    return ReadyResponse(
        ready=is_ready,
        reason=reason,
        version=str(info.get("version", "")),
        models_loaded=models_loaded,
        checks=checks,
    )


__all__ = ["router", "MAX_BATCH_ITEMS"]
