"""Premium Path evaluator (§10) - wraps the license-cleared ViT adapter.

The cascade's three built-in evaluators each own an ONNX graph directly. The
premium stage is different: it is an *external* detector reached through the
:class:`~adapters.base.BaseAdapter` contract, so this module is a thin shim that
gives it the same :class:`StageResult` shape as the others.

Two properties matter and are both inherited from the adapter rather than
reimplemented:

* it refuses to score when the label sidecar is missing or does not describe
  the graph, so an unknown class order can never reach a decision (§49);
* it returns ``executed=False`` when the artifact is not mounted, which is how
  the cascade knows the stage was skipped rather than silently passing.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

import numpy as np

from app.core.config import EngineConfig
from app.models.base import BaseEvaluator, DecisionPath, StageResult

logger = logging.getLogger("nsfw_engine.models.premium_path")


class PremiumPathEvaluator(BaseEvaluator):
    """Optional fourth stage backed by ``HuggingFaceViTAdapter``."""

    path = DecisionPath.PREMIUM
    #: The §22 registry key, which is also the §26 calibration id. It must be
    #: the registry key and not the adapter's own ``name`` (``hf_vit_nsfw``):
    #: calibration, lifecycle transitions and health all key on the registry
    #: key, so using the adapter name would silently never match.
    model_name = "premium_vit"

    def __init__(self, adapter: Any, timeout_ms: float) -> None:
        # There is no ONNX session here: the adapter owns it. ``session`` is
        # None, so ``is_stub`` is True and the stage reports itself as skipped.
        super().__init__(
            session=None, preprocessor=None, resize=(0, 0), timeout_ms=timeout_ms
        )
        self.adapter = adapter

    @classmethod
    def from_config(
        cls,
        manager,
        preprocessor,
        config: EngineConfig,
    ) -> "PremiumPathEvaluator":
        # Imported lazily: the adapters package pulls in numpy/PIL plumbing the
        # core cascade does not otherwise need, and an engine configured with
        # the stage disabled must not pay for it.
        from adapters.registry import build_adapter

        adapter = build_adapter(
            "premium_vit",
            session_manager=manager,
            model_path=config.model_path(config.paths.premium_model),
        )
        return cls(adapter=adapter, timeout_ms=config.timeouts.premium_ms)

    def evaluate(self, image: np.ndarray) -> StageResult:
        """Run the premium adapter, if it is mounted and may serve (§22)."""
        started = time.perf_counter()
        if self.adapter is None or not self.adapter.available:
            return self._skipped(started)
        result = self.adapter.predict(image)
        latency_ms = (time.perf_counter() - started) * 1000.0
        if result is None:
            # The adapter declined (no sidecar, blocked, or inference error).
            # That is a "did not contribute", never a zero score.
            logger.debug("premium adapter declined to score this payload")
            return self._skipped(started, latency_ms)
        return StageResult(
            path=self.path,
            score=float(result.score),
            latency_ms=latency_ms,
            executed=True,
            model=self.model_name,
            fallback=False,
        )

    def _skipped(
        self, started: float, latency_ms: Optional[float] = None
    ) -> StageResult:
        return StageResult(
            path=self.path,
            score=0.0,
            latency_ms=(
                latency_ms
                if latency_ms is not None
                else (time.perf_counter() - started) * 1000.0
            ),
            executed=False,
            model=self.model_name,
            fallback=True,
        )