"""Score fusion strategies for multimodal classification (Sec. 40).

The cascade produces an independent *visual* score and *text* score. This
module centralises how the two are combined so the strategy is configurable and
independently testable, and so future adapters (CLIP, DistilBERT, ...) always
fuse through the same well-defined contract:

    visual score + text score + weight + strategy -> fused score in [0, 1]

All functions are pure, numerically clamped and never raise.
"""

from __future__ import annotations

import logging

import numpy as np

logger = logging.getLogger("nsfw_engine.core.fusion")

#: Supported fusion strategies (mirrors ``thresholds.text.fusion_strategy``).
SUPPORTED_STRATEGIES = ("weighted", "max", "noisy_or")


def _clip(value: float) -> float:
    return float(np.clip(float(value), 0.0, 1.0))


def fuse_scores(
    visual_score: float,
    text_score: float | None,
    weight: float = 0.30,
    strategy: str = "weighted",
) -> float:
    """Fuse a visual and an optional text score into a single probability.

    Parameters
    ----------
    visual_score:
        Image signal in ``[0, 1]``.
    text_score:
        Text signal in ``[0, 1]``; ``None``/``NaN`` means "no text signal".
    weight:
        Relative trust in the text signal, clamped to ``[0, 1]``.
    strategy:
        One of :data:`SUPPORTED_STRATEGIES`. Unknown values fall back to
        ``"weighted"`` (and are logged) rather than raising, so a typo in a
        remote config can never break request handling.
    """
    visual = _clip(visual_score)
    if text_score is None:
        return visual

    try:
        text = _clip(text_score)
    except (TypeError, ValueError):
        logger.warning("non-numeric text_score %r ignored", text_score)
        return visual
    if np.isnan(text):
        return visual

    weight = _clip(weight)
    normalised = (strategy or "weighted").lower()
    if normalised not in SUPPORTED_STRATEGIES:
        logger.warning("unknown fusion strategy %r, using 'weighted'", strategy)
        normalised = "weighted"

    if normalised == "weighted":
        fused = (1.0 - weight) * visual + weight * text
    elif normalised == "max":
        fused = max(visual, text)
    else:  # noisy_or - independent evidence, evidence combination
        fused = 1.0 - (1.0 - visual) * (1.0 - weight * text)

    return _clip(fused)


__all__ = ["SUPPORTED_STRATEGIES", "fuse_scores"]