"""Model A - Fast-Path evaluator (MobileNetV3, target < 10 ms).

The fast path runs on every request. It is a tiny INT8/FP16 model whose only
job is to confidently clear the majority of safe traffic and flag obvious NSFW
content, deferring ambiguous cases to the deep path.
"""

from __future__ import annotations

from app.core.config import EngineConfig
from app.core.onnx_runtime import OnnxSessionManager
from app.models.base import BaseEvaluator, DecisionPath


class FastPathEvaluator(BaseEvaluator):
    """Phase 1 evaluator backed by ``fast_path_mobilenetv3.onnx``."""

    path = DecisionPath.FAST
    model_name = "fast_path_mobilenetv3"

    @classmethod
    def from_config(
        cls,
        manager: OnnxSessionManager,
        preprocessor,
        config: EngineConfig,
    ) -> "FastPathEvaluator":
        session = manager.load(
            cls.model_name, config.model_path(config.paths.fast_path_model)
        )
        return cls(
            session=session,
            preprocessor=preprocessor,
            resize=tuple(config.preprocessing.fast_path_resize),
            timeout_ms=config.timeouts.fast_path_ms,
        )
