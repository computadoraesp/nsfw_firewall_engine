"""Model B - Deep-Path evaluator (configured high-capacity ONNX classifier).

The deep path is invoked only when the fast path is inconclusive. It provides a
higher-capacity decision for borderline content.
"""

from __future__ import annotations

from app.core.config import EngineConfig
from app.core.onnx_runtime import OnnxSessionManager
from app.models.base import BaseEvaluator, DecisionPath


class DeepPathEvaluator(BaseEvaluator):
    """Phase 2 evaluator backed by the configured deep-path ONNX model."""

    path = DecisionPath.DEEP
    model_name = "marqo_nsfw_vit"

    @classmethod
    def from_config(
        cls,
        manager: OnnxSessionManager,
        preprocessor,
        config: EngineConfig,
    ) -> "DeepPathEvaluator":
        model_path = config.model_path(config.paths.deep_path_model)
        session = manager.load(cls.model_name, model_path)
        return cls(
            session=session,
            preprocessor=preprocessor,
            resize=tuple(config.preprocessing.deep_path_resize),
            timeout_ms=config.timeouts.deep_path_ms,
            model_path=model_path,
        )
