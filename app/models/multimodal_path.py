"""Model C - Premium Multimodal evaluator (CLIP, target 50-90 ms).

The multimodal path is the final arbiter. In addition to the visual signal it
fuses a text signal (page copy, alt text, URLs) using the CLIP embedding space
to resolve genuinely ambiguous cases. When a text signal is supplied its score
is blended with the visual score according to ``thresholds.text.weight``.
"""

from __future__ import annotations

from typing import Optional

import numpy as np

from app.core.config import EngineConfig
from app.core.fusion import fuse_scores
from app.core.onnx_runtime import OnnxSessionManager, to_probability
from app.models.base import BaseEvaluator, DecisionPath, StageResult


class MultimodalPathEvaluator(BaseEvaluator):
    """Phase 3 evaluator backed by ``multimodal_clip.onnx``."""

    path = DecisionPath.MULTIMODAL
    model_name = "multimodal_clip"

    def __init__(
        self,
        *args,
        text_weight: float = 0.30,
        fusion_strategy: str = "weighted",
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.text_weight = float(text_weight)
        self.fusion_strategy = fusion_strategy or "weighted"

    @classmethod
    def from_config(
        cls,
        manager: OnnxSessionManager,
        preprocessor,
        config: EngineConfig,
    ) -> "MultimodalPathEvaluator":
        session = manager.load(
            cls.model_name, config.model_path(config.paths.multimodal_model)
        )
        return cls(
            session=session,
            preprocessor=preprocessor,
            resize=tuple(config.preprocessing.multimodal_resize),
            timeout_ms=config.timeouts.multimodal_ms,
            text_weight=config.thresholds.text.weight,
            fusion_strategy=config.thresholds.text.fusion_strategy,
        )

    def evaluate_multimodal(
        self, image: np.ndarray, text_score: Optional[float] = None
    ) -> StageResult:
        """Evaluate the image and fuse it with an optional text signal.

        The fusion itself lives in :func:`app.core.fusion.fuse_scores` so the
        strategy is configurable and unit-tested independently of the models.
        """
        result = self.evaluate(image)
        if text_score is not None and self.text_weight > 0.0:
            result.score = fuse_scores(
                result.score,
                float(text_score),
                weight=self.text_weight,
                strategy=self.fusion_strategy,
            )
        return result


__all__ = ["MultimodalPathEvaluator", "to_probability"]
