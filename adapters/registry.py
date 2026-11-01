"""Adapter registry (§41).

Keeps the mapping ``stage -> upstream project`` in one declarative table so
adding, removing or replacing a detector is a configuration change rather than a
code change - the §50 requirement.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Type

from adapters.base import (
    ALLOWED_TRANSITIONS,
    AdapterResult,
    BaseAdapter,
    ModelStatus,
    StatusTransitionError,
)
from adapters.vision import (
    CLIPZeroShotAdapter,
    HuggingFaceViTAdapter,
    NSFWJSAdapter,
    NuditaAdapter,
    OpenNSFW2Adapter,
)

logger = logging.getLogger("nsfw_engine.adapters.registry")

# stage -> adapter class. Mirrors the cascade stages in `app/core/engine.py`.
ADAPTER_REGISTRY: Dict[str, Type[BaseAdapter]] = {
    "fast_path": NSFWJSAdapter,
    "deep_path": OpenNSFW2Adapter,
    "multimodal": CLIPZeroShotAdapter,
    # §10 Premium Path. Apache-2.0 for BOTH code and weights, which is why it
    # sits ahead of the ambiguous-license candidates: this one can actually be
    # deployed commercially today. Mount the exported graph at
    # models_onnx/vit_nsfw.onnx (Helm: models.mountPath).
    "premium_vit": HuggingFaceViTAdapter,
    # Rejected upstream (§2 licensing) - registered so operators can *see* why
    # it is inert instead of wondering where it went.
    "rejected": NuditaAdapter,
}


def available_adapters() -> List[str]:
    """Names of every registered adapter, available or not."""
    return sorted(ADAPTER_REGISTRY)


def servable_adapters() -> List[str]:
    """Stages whose adapter is allowed to produce a decision (§22).

    This is what the cascade should iterate over. Excluding deprecated and
    blocked models here - rather than only inside each adapter - means a
    promotion or deprecation takes effect for every consumer at once, with no
    adapter needing to remember to check its own status.
    """
    return sorted(
        stage
        for stage, factory in ADAPTER_REGISTRY.items()
        if factory.status not in (ModelStatus.DEPRECATED, ModelStatus.BLOCKED)
    )


def status_of(stage: str) -> Optional[ModelStatus]:
    """Current lifecycle status for *stage*, or ``None`` when unregistered."""
    factory = ADAPTER_REGISTRY.get(stage)
    return factory.status if factory else None


def set_status(stage: str, new_status: ModelStatus) -> ModelStatus:
    """Move *stage* to *new_status*, rejecting illegal transitions (§22).

    Enforcement is the point. Without the transition table, ``status`` is just a
    label: anyone could flip a model to ``production`` without ever having
    benchmarked it, and the field would carry no information at all. Blocking
    ``candidate -> production`` directly encodes §49's "no claims without
    benchmarks" into the data model.

    Raises:
        KeyError: *stage* is not registered.
        StatusTransitionError: the transition is not permitted.
    """
    factory = ADAPTER_REGISTRY.get(stage)
    if factory is None:
        raise KeyError(f"unknown adapter stage: {stage!r}")
    target = ModelStatus(new_status)
    current = factory.status
    if target is current:
        return current
    if target not in ALLOWED_TRANSITIONS[current]:
        raise StatusTransitionError(
            f"{stage}: cannot move from {current.value} to {target.value}; "
            f"allowed: {sorted(s.value for s in ALLOWED_TRANSITIONS[current])}"
        )
    previous = current
    factory.status = target
    logger.info(
        "model lifecycle: %s %s -> %s", stage, previous.value, target.value
    )
    return target


def build_adapter(stage: str, session_manager: Any = None, **kwargs: Any) -> Optional[BaseAdapter]:
    """Instantiate the adapter registered for *stage*, or ``None`` if unknown.

    A deprecated or blocked stage still returns an adapter instance - callers
    that need to introspect it (the registry endpoint) must be able to do so -
    but the instance refuses to produce a score.
    """
    factory = ADAPTER_REGISTRY.get(stage)
    if factory is None:
        logger.debug("no adapter registered for stage %r", stage)
        return None
    return factory(session_manager=session_manager, **kwargs)


def describe_all(session_manager: Any = None) -> Dict[str, dict]:
    """Introspection payload for ``/health`` and the model registry doc."""
    described = {}
    for stage, factory in ADAPTER_REGISTRY.items():
        try:
            described[stage] = factory(session_manager=session_manager).describe()
        except Exception as exc:  # noqa: BLE001
            described[stage] = {
                "name": factory.name,
                "status": factory.status.value,
                "error": str(exc),
            }
    return described


def ensemble_score(results: List[Optional[AdapterResult]], weights: Optional[List[float]] = None) -> Optional[float]:
    """Fuse several adapter scores into one probability (§40).

    Uses a weighted mean; adapters reporting ``None`` are skipped. Returns
    ``None`` when nothing produced a score.
    """
    scored = [(r.score, w) for r, w in zip(results, weights or [1.0] * len(results)) if r is not None]
    if not scored:
        return None
    total_weight = sum(w for _, w in scored) or 1.0
    return float(sum(score * w for score, w in scored) / total_weight)


__all__ = [
    "ADAPTER_REGISTRY",
    "available_adapters",
    "build_adapter",
    "describe_all",
    "ensemble_score",
    "servable_adapters",
    "set_status",
    "status_of",
]