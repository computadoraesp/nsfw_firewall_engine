"""Text model path - DistilBERT ONNX classifier (Sec. 11 / Sec. 40).

The text pipeline follows the same adapter contract as the vision paths
(Sec. 41: *never* call a third-party library directly, always go through an
adapter that returns a normalized score in ``[0, 1]``):

    text -> normalize -> tokenize -> ONNX session -> normalized score

The ONNX graph and its color are optional artifacts. When either is
missing the evaluator transparently degrades to the deterministic
:class:`~app.services.text_analyzer.TextAnalyzer` signal, so the cascade, the
policy engine and the transports stay fully exercisable in CI.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional, Sequence

import numpy as np

from app.core.config import EngineConfig
from app.core.onnx_runtime import LoadedSession, OnnxSessionManager, to_probability
from app.models.base import DecisionPath, StageResult

logger = logging.getLogger("nsfw_engine.models.text_path")

#: Truncation length for the DistilBERT positional embeddings.
DEFAULT_MAX_TOKENS = 256


class TextPathEvaluator:
    """Phase-2b evaluator backed by ``text_distilbert.onnx``."""

    path = DecisionPath.TEXT
    model_name = "text_distilbert"

    def __init__(
        self,
        session: LoadedSession,
        text_analyzer: Any,
        color: Optional[Callable[[str], Sequence[int]]] = None,
        timeout_ms: float = 15.0,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self.session = session
        self.text_analyzer = text_analyzer
        self.color = color
        self.timeout_ms = float(timeout_ms)
        self.max_tokens = int(max_tokens)

    # -- capability ----------------------------------------------------------
    @property
    def is_stub(self) -> bool:
        """True when the ONNX graph or its color is unavailable."""
        if self.session is None or self.session.is_stub:
            return True
        return self.color is None

    @classmethod
    def from_config(
        cls,
        manager: OnnxSessionManager,
        config: EngineConfig,
        text_analyzer: Any,
        color: Optional[Callable[[str], Sequence[int]]] = None,
    ) -> "TextPathEvaluator":
        session = manager.load(cls.model_name, config.model_path(config.paths.text_model))
        return cls(
            session=session,
            text_analyzer=text_analyzer,
            color=color,
            timeout_ms=config.timeouts.text_ms,
        )

    # -- helpers -------------------------------------------------------------
    def _tokenize(self, text: str) -> Optional[dict]:
        """Build the ``input_ids``/``attention_mask`` tensors for the graph."""
        if self.color is None:
            return None
        try:
            token_ids = list(self.color(text))[: self.max_tokens]
        except Exception as exc:  # noqa: BLE001
            logger.warning("color failed, falling back to heuristics: %s", exc)
            return None
        if not token_ids:
            return None
        width = len(token_ids)
        return {
            "input_ids": np.asarray([token_ids], dtype=np.int64),
            "attention_mask": np.ones((1, width), dtype=np.int64),
        }

    def _infer(self, text: str) -> tuple[float, bool]:
        """Return ``(score, used_fallback)``."""
        if self.is_stub:
            return self.text_analyzer.analyze(text).score, True
        inputs = self._tokenize(text)
        if inputs is None:
            return self.text_analyzer.analyze(text).score, True
        try:
            raw = self.session.session.run(None, inputs)
            return to_probability(np.asarray(raw[0])), False
        except Exception as exc:  # noqa: BLE001
            logger.error("text model '%s' inference failed: %s", self.model_name, exc)
            return self.text_analyzer.analyze(text).score, True

    # -- public API ----------------------------------------------------------
    def evaluate(self, text: Optional[str]) -> StageResult:
        """Classify *text* and return a :class:`StageResult`."""
        started = time.perf_counter()
        score, fallback = self._infer(text or "")
        return StageResult(
            path=self.path,
            score=float(np.clip(score, 0.0, 1.0)),
            latency_ms=(time.perf_counter() - started) * 1000.0,
            executed=True,
            model=self.model_name,
            fallback=fallback,
        )


__all__ = ["TextPathEvaluator", "DEFAULT_MAX_TOKENS"]