"""Shared types and base evaluator for the model stages.

This small module defines the enums and dataclasses shared across the
evaluators (:mod:`app.models.fast_path`, :mod:`app.models.deep_path`,
:mod:`app.models.multimodal_path`) and the orchestrator
(:mod:`app.core.engine`). It retains a legacy skin-tone heuristic for
compatibility, but the engine does not use it to make decisions.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import numpy as np

from app.core.onnx_runtime import LoadedSession, softmax, to_probability
from adapters.labels import LabelSidecarError
from adapters.labels import load as load_labels

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
    #: §10 Premium Path: the licence-cleared ViT, consulted only after the
    #: cheaper stages are inconclusive and only when it is mounted.
    PREMIUM = "PREMIUM"
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
    """Legacy deterministic skin-tone heuristic; not used by the engine.

    The score is the fraction of pixels that satisfy a classic RGB skin-tone
    rule, blended with a mild saturation term. It is *not* a trained detector
    and must not be used for enforcement.
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
        model_path: str = "",
    ) -> None:
        self.session = session
        self.preprocessor = preprocessor
        self.resize = resize
        self.timeout_ms = timeout_ms
        #: Class metadata for this stage's artifact, if it ships a sidecar.
        #: Multi-class detectors (safe/hentai/porn/sexy/drawing) must NOT be
        #: collapsed with ``to_probability``: that averages every channel above
        #: index 0, so a confident "porn" would be diluted by "drawing" and the
        #: score would stop meaning "how NSFW is this".
        self.sidecar = None
        self._sidecar_error = None
        if model_path:
            try:
                self.sidecar = load_labels(model_path)
            except LabelSidecarError as exc:
                # A present-but-unusable sidecar means the class order is
                # unknown; refuse rather than guess (§49).
                logger.error("stage '%s': unusable label sidecar: %s", self.model_name, exc)
                self.sidecar = None
                self._sidecar_error = str(exc)

    @property
    def is_stub(self) -> bool:
        return self.session is None or self.session.is_stub

    def _infer(self, tensor: np.ndarray, image: np.ndarray) -> tuple[float, bool]:
        """Run the model, returning ``(score, used_fallback)``."""
        if self.is_stub:
            return 0.5, True
        try:
            outputs = self.session.run(tensor)
            return self._score_from_outputs(outputs), False
        except Exception as exc:  # noqa: BLE001
            logger.error("model '%s' inference failed: %s", self.model_name, exc)
            return 0.5, True

    def _score_from_outputs(self, outputs: np.ndarray) -> float:
        """Map raw logits to an NSFW probability, using the sidecar when present.

        With a sidecar the explicit classes are *summed* rather than averaged.
        That distinction is the whole point of a multi-class detector: a model
        that is 90% confident on "porn" must score high, but averaging in
        "hentai", "sexy" and "drawing" would report roughly 23% for the same
        image, which is not a confidence at all.
        """
        flat = np.asarray(outputs, dtype=np.float32).reshape(-1)
        sidecar = self.sidecar
        if self._sidecar_error:
            raise ValueError("label sidecar is invalid")
        if sidecar is not None and sidecar.labels:
            if len(sidecar.labels) != flat.size:
                # The graph and its sidecar disagree, so no index can be trusted.
                logger.error(
                    "stage '%s': sidecar declares %d classes but the graph emitted "
                    "%d; refusing to score",
                    self.model_name, len(sidecar.labels), flat.size,
                )
                raise ValueError("label sidecar does not describe this artifact")
            indices = [i for i in sidecar.positive_indices if i < flat.size]
            if not indices:
                logger.error(
                    "stage '%s': sidecar lists no explicit class among %s",
                    self.model_name, list(sidecar.labels),
                )
                raise ValueError("no explicit class in the label sidecar")
            # A multi-class head is mutually exclusive, so its outputs must be
            # normalised with softmax, not per-class sigmoid. Sigmoid would map
            # the near-zero logits of a softmaxed classifier to ~0.5 each, and
            # summing four "explicit" channels would report 1.0 for a blank
            # image. Softmax makes the channels sum to 1, so the explicit ones
            # sum to at most 1 by construction.
            probs = softmax(flat)
            return float(np.clip(sum(float(probs[i]) for i in indices), 0.0, 1.0))
        if flat.size > 2:
            raise ValueError("multi-class model requires a valid label sidecar")
        return to_probability(outputs)

    def evaluate(self, image: np.ndarray) -> StageResult:
        """Evaluate an already-decoded ``HWC`` uint8 RGB image."""
        started = time.perf_counter()
        tensor = self.preprocessor.array_to_tensor(
            image,
            self.resize,
            mean=self.sidecar.mean if self.sidecar is not None else None,
            std=self.sidecar.std if self.sidecar is not None else None,
        )
        score, fallback = self._infer(tensor, image)
        latency_ms = (time.perf_counter() - started) * 1000.0
        return StageResult(
            path=self.path,
            score=score,
            latency_ms=latency_ms,
            executed=not self.is_stub,
            model=self.model_name,
            fallback=fallback,
        )
