"""External model adapters (§41).

Spec rule: *external code must be wrapped, never called directly from the
engine.* Every third-party detector is reached through a
:class:`~adapters.base.BaseAdapter` that exposes one contract:

    bytes | text  ->  AdapterResult(score in [0,1], category, latency)

That contract is what lets §50 hold - swapping NSFWJS for OpenNSFW2 changes a
registry entry, not the engine, the API or the policy.

Every adapter degrades gracefully: if the model artifact or its runtime library
is missing, ``available`` is ``False`` and ``predict`` returns ``None`` rather
than raising, so an absent adapter never breaks the cascade (it simply falls
through to the built-in evaluators).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

logger = logging.getLogger("nsfw_engine.adapters")


class AdapterCategory(str, Enum):
    """Coarse category reported by an adapter (normalized, §40)."""

    PORN = "porn"
    SEXY = "sexy"
    NEUTRAL = "neutral"
    DRAWINGS = "drawings"
    HENTAI = "hentai"
    UNKNOWN = "unknown"


class ModelStatus(str, Enum):
    """Lifecycle state of a registered model (§22).

    The statuses are not documentation - they are *enforced*. §50 requires that
    models evolve without changing the firewall, the API or the policy, and that
    is only true if retiring a model is an operation the system understands.
    Without a status, "we stopped using OpenNSFW2" and "OpenNSFW2 is still
    quietly scoring traffic" look identical from the outside.

    ``CANDIDATE``
        Registered and runnable, but never benchmarked. Must not serve
        production traffic - §49 forbids quality claims without measurement.
    ``VALIDATED``
        Benchmarked and within tolerance, awaiting promotion.
    ``PRODUCTION``
        Promoted; safe to serve.
    ``DEPRECATED``
        Superseded. Still loadable so a rollback is possible, but it is pulled
        out of the cascade and must not receive new traffic.
    ``BLOCKED``
        Must never run: a license, security or integrity problem. Distinct from
        ``DEPRECATED`` because a deprecated model can be restored, while a blocked
        one must not be - the distinction is what stops someone "just enabling"
        Nudita to get around the AGPL boundary.
    """

    CANDIDATE = "candidate"
    VALIDATED = "validated"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"
    BLOCKED = "blocked"


#: Statuses whose adapters must never participate in inference (§22).
NON_SERVING_STATUSES = frozenset({ModelStatus.DEPRECATED, ModelStatus.BLOCKED})

# Legal lifecycle transitions. Enforced so a model cannot silently jump from
#: `candidate` straight to `production` - promotion is supposed to mean "this was
#: benchmarked", and allowing the jump makes the status meaningless.
ALLOWED_TRANSITIONS: Dict[ModelStatus, frozenset] = {
    ModelStatus.CANDIDATE: frozenset(
        {ModelStatus.VALIDATED, ModelStatus.BLOCKED, ModelStatus.DEPRECATED}
    ),
    ModelStatus.VALIDATED: frozenset(
        {ModelStatus.PRODUCTION, ModelStatus.CANDIDATE, ModelStatus.BLOCKED,
         ModelStatus.DEPRECATED}
    ),
    ModelStatus.PRODUCTION: frozenset(
        {ModelStatus.DEPRECATED, ModelStatus.BLOCKED}
    ),
    ModelStatus.DEPRECATED: frozenset(
        # Restoration is allowed (a rollback), so a deprecated model is not a
        # dead end - but it must be re-validated before serving again.
        {ModelStatus.CANDIDATE, ModelStatus.VALIDATED, ModelStatus.BLOCKED}
    ),
    ModelStatus.BLOCKED: frozenset(),
}


class StatusTransitionError(RuntimeError):
    """Raised on an illegal lifecycle transition (§22)."""



@dataclass
class AdapterResult:
    """normalized output of one adapter."""

    score: float
    adapter: str
    category: AdapterCategory = AdapterCategory.UNKNOWN
    latency_ms: float = 0.0
    model_version: str = ""

    def __post_init__(self) -> None:
        self.score = float(np.clip(float(self.score), 0.0, 1.0))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "adapter": self.adapter,
            "score": round(self.score, 6),
            "category": self.category.value,
            "latency_ms": round(self.latency_ms, 3),
            "model_version": self.model_version,
        }


class BaseAdapter:
    """Common contract for every external-model adapter."""

    #: Stable identifier used in the registry and in telemetry labels.
    name: str = "base"
    #: Upstream project + license, mirrored in docs/MODEL_PROVENANCE.md.
    license: str = "unknown"
    #: What kind of input the adapter consumes.
    accepts: str = "image"
    # Lifecycle state (§22). Subclasses override this as a class attribute.
    status: ModelStatus = ModelStatus.CANDIDATE

    def __init__(self, model_path: Optional[str] = None, session_manager: Any = None) -> None:
        self.model_path = model_path
        self.session_manager = session_manager
        self._loaded = False

    # -- capability ----------------------------------------------------------
    @property
    def may_serve(self) -> bool:
        """False when the model is deprecated or blocked (§22).

        Separate from :attr:`available` on purpose: ``available`` answers "can
        this model physically run", ``may_serve`` answers "is it allowed to
        decide anything". A deprecated model is still loadable so a rollback
        works; a blocked one must not be reachable at all.
        """
        return self.status not in NON_SERVING_STATUSES

    @property
    def available(self) -> bool:
        """True when the adapter can actually produce a score."""
        return False

    @property
    def loaded(self) -> bool:
        return self._loaded

    def describe(self) -> Dict[str, Any]:
        """Introspection for ``/health`` and the model registry."""
        return {
            "name": self.name,
            "license": self.license,
            "accepts": self.accepts,
            "status": self.status.value,
            "may_serve": self.may_serve,
            "available": self.available,
            "loaded": self.loaded,
            "model_path": self.model_path or "",
        }

    # -- inference -----------------------------------------------------------
    def predict(self, payload: Any) -> Optional[AdapterResult]:  # pragma: no cover
        """Return an :class:`AdapterResult`, or ``None`` when unavailable.

        Subclasses call :meth:`_guard` first; it is factored out so the lifecycle
        check cannot be forgotten in one adapter and not the other.
        """
        raise NotImplementedError

    def _guard(self) -> bool:
        """Return False when this model must not be used (§22).

        Every ``predict`` implementation starts with this. A deprecated model
        still loads (so a rollback is possible) but returns ``None`` rather than
        a score, and a blocked model is refused before any file is opened.
        """
        if not self.may_serve:
            logger.warning(
                "adapter %s refusing inference: status=%s", self.name, self.status.value
            )
            return False
        return True

    # -- helpers for subclasses ---------------------------------------------
    @staticmethod
    def normalize(logits: Sequence[float]) -> float:
        """Map raw model output to an NSFW probability in ``[0, 1]`` (§40).

        Mirrors ``app.core.onnx_runtime.to_probability`` so every adapter -
        built-in or external - produces comparable scores.
        """
        from app.core.onnx_runtime import to_probability

        return to_probability(np.asarray(logits, dtype=np.float32))

    @staticmethod
    def categorise(score: float) -> AdapterCategory:
        """Bucket a score into a coarse category."""
        if score >= 0.85:
            return AdapterCategory.PORN
        if score >= 0.55:
            return AdapterCategory.SEXY
        if score > 0.15:
            return AdapterCategory.NEUTRAL
        return AdapterCategory.NEUTRAL


__all__ = [
    "ALLOWED_TRANSITIONS",
    "NON_SERVING_STATUSES",
    "AdapterCategory",
    "AdapterResult",
    "BaseAdapter",
    "ModelStatus",
    "StatusTransitionError",
]