"""Shared types and base evaluator for the model stages.

This small module defines the enums and dataclasses shared across the
evaluators (:mod:`app.models.fast_path`, :mod:`app.models.deep_path`,
:mod:`app.models.multimodal_path`) and the orchestrator
(:mod:`app.core.engine`). It also provides the deterministic skin-tone
heuristic used as a fallback when ONNX model artifacts are unavailable.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import numpy as np

from app.core.onnx_runtime import LoadedSession, to_probability

logger = logging.getLogger("nsfw_engine.models.base")


class Verdict(str, Enum):
    """Final classification verdict."""

    SFW = "SFW"
    NSFW = "NSFW"
    REVIEW = "REVIEW"
    UNKNOWN = "UNKNOWN"


class DecisionPath(str, Enum):
    """Which stage produced the winning decision."""

    FAST = "FAST"
    DEEP = "DEEP"
    MULTIMODAL = "MULTIMODAL"
    TEXT = "TEXT"
    UNKNOWN = "UNKNOWN"


class MediaType(str, Enum):
    """Media type of an analysed payload."""

    IMAGE = "IMAGE"
    VIDEO = "VIDEO"
    TEXT = "TEXT"
    HTML = "HTML"
    UNKNOWN = "UNKNOWN"


@dataclass
class StageResult:
    """Result of a single stage in the triage cascade."""

    path: DecisionPath
    score: float
    latency_ms: float
    executed: bool = True
    model: str = ""
    fallback: bool = False

    def as_dict(self) -> dict:
        return {
            "path": self.path.value,
            "score": round(float(self.score), 6),
            "latency_ms": round(float(self.latency_ms), 3),
            "executed": self.executed,
            "model": self.model,
            "fallback": self.fallback,
        }


def heuristic_nsfw_score(image: np.ndarray) -> float:
    """Deterministic skin-tone heuristic used when no ONNX model is present.

    The score is the fraction of pixels that satisfy a classic RGB skin-tone
    rule, blended with a mild saturation term. It is *not* a trained detector;
    it exists so that the cascade, thresholds and transports remain exercisable
    without model artifacts. Calibrate/disable it in production by shipping real
    ONNX models.
    """
    if image.ndim != 3 or image.shape[2] < 3:
        return 0.0
    rgb = image[..., :3].astype(np.int16)
    r, g, b = rgb[..., 0], rgb[..., 1], rgb[..., 2]
    mx = np.max(rgb, axis=-1)
    mn = np.min(rgb, axis=-1)

    skin = (
        (r > 95)
        & (g > 40)
        & (b > 20)
        & ((mx - mn) > 15)
        & (np.abs(r - g) > 15)
        & (r > g)
        & (r > b)
    )
    ratio = float(np.mean(skin))

    # Mild contribution from overall warm tone (redness) to break ties.
    warm = float(np.clip((r.mean() - b.mean()) / 255.0, 0.0, 1.0))
    score = 0.85 * ratio + 0.15 * warm
    return float(np.clip(score, 0.0, 1.0))


class BaseEvaluator:
    """Common behaviour for the three model-path evaluators."""

    path: DecisionPath = DecisionPath.UNKNOWN
    model_name: str = "base"

    def __init__(
        self,
        session: LoadedSession,
        preprocessor,
        resize: tuple[int, int],
        timeout_ms: float,
    ) -> None:
        self.session = session
        self.preprocessor = preprocessor
        self.resize = resize
        self.timeout_ms = timeout_ms

    @property
    def is_stub(self) -> bool:
        return self.session is None or self.session.is_stub

    def _infer(self, tensor: np.ndarray, image: np.ndarray) -> tuple[float, bool]:
        """Run the model, returning ``(score, used_fallback)``."""
        if self.is_stub:
            return heuristic_nsfw_score(image), True
        try:
            outputs = self.session.run(tensor)
            return to_probability(outputs), False
        except Exception as exc:  # noqa: BLE001
            logger.error("model '%s' inference failed: %s", self.model_name, exc)
            return heuristic_nsfw_score(image), True

    def evaluate(self, image: np.ndarray) -> StageResult:
        """Evaluate an already-decoded ``HWC`` uint8 RGB image."""
        started = time.perf_counter()
        tensor = self.preprocessor.array_to_tensor(image, self.resize)
        score, fallback = self._infer(tensor, image)
        latency_ms = (time.perf_counter() - started) * 1000.0
        return StageResult(
            path=self.path,
            score=score,
            latency_ms=latency_ms,
            executed=True,
            model=self.model_name,
            fallback=fallback,
        )
