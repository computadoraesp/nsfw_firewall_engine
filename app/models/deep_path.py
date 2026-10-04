"""Model B - Deep-Path evaluator (EfficientNet, target 20-40 ms).

The deep path is invoked only when the fast path is inconclusive. It provides a
higher-capacity decision for borderline content.
"""

from __future__ import annotations

from app.core.config import EngineConfig
from app.core.onnx_runtime import OnnxSessionManager
from app.models.base import BaseEvaluator, DecisionPath


class DeepPathEvaluator(BaseEvaluator):
    """Phase 2 evaluator backed by ``deep_path_efficientnet.onnx``."""

    path = DecisionPath.DEEP
    model_name = "deep_path_efficientnet"

    @classmethod
    def from_config(
        cls,
        manager: OnnxSessionManager,
        preprocessor,
        config: EngineConfig,
    ) -> "DeepPathEvaluator":
        session = manager.load(
            cls.model_name, config.model_path(config.paths.deep_path_model)
        )
        return cls(
            session=session,
            preprocessor=preprocessor,
            resize=tuple(config.preprocessing.deep_path_resize),
            timeout_ms=config.timeouts.deep_path_ms,
        )
