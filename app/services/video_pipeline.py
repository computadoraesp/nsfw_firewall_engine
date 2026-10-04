"""Intelligent video sampling pipeline for the NSFW Firewall Engine.

Videos are reduced to a sparse, representative set of frames (``sample_fps``)
and classified through the standard triage cascade. Classification short
circuits as soon as a frame crosses the ``early_exit_score`` threshold, keeping
video inspection within a predictable latency budget.

The pipeline is decoder-agnostic: callers supply either decoded ``HWC`` uint8
frames or encoded frame bytes. Decoding a container (mp4/webm) is left to an
optional dependency (e.g. PyAV/OpenCV) so the engine stays dependency-light.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Optional, Sequence

import numpy as np

from app.core.config import VideoConfig
from app.models.base import DecisionPath, MediaType, Verdict

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids import cycle
    from app.core.engine import NsfwEngine

logger = logging.getLogger("nsfw_engine.services.video_pipeline")

#: Severity ordering used to pick the "worst" frame verdict.
_VERDICT_RANK = {
    Verdict.SFW: 0,
    Verdict.REVIEW: 1,
    Verdict.NSFW: 2,
    Verdict.UNKNOWN: -1,
}


# ---------------------------------------------------------------------------
# Temporal aggregation (§14).
# ---------------------------------------------------------------------------
#: How the per-frame scores collapse into one video score (§14).
#:
#: ``max`` is the default and the right choice for a firewall: explicit content
#: in one frame of a two-minute clip is still explicit content, and averaging
#: would dilute a five-second insert across 120 safe frames into a clean bill of
#: health. The trade-off is a higher false-positive rate on videos that contain a
#: single ambiguous shot, which is why ``percentile`` exists as a middle ground.
AGGREGATORS = ("max", "mean", "percentile", "weighted")


def aggregate_scores(
    scores: Sequence[float],
    strategy: str = "max",
    percentile: float = 95.0,
) -> float:
    """Reduce per-frame scores to one video score (§14).

    ``weighted`` weights each frame by its position, giving later frames more
    influence. That models a viewer who reaches the end of a clip, and is the
    only non-monotonic option here - it is deliberately not the default.
    """
    values = [float(s) for s in scores]
    if not values:
        return 0.0
    name = (strategy or "max").strip().lower()
    if name == "max":
        return max(values)
    if name == "mean":
        return sum(values) / len(values)
    if name == "percentile":
        if not 0.0 < percentile <= 100.0:
            raise ValueError("percentile must be in (0, 100]")
        # Nearest-rank percentile: no interpolation, so the result is always an
        # observed frame score. An interpolated value would report a confidence
        # the engine never actually observed on any frame.
        rank = max(1, int(round(percentile / 100.0 * len(values))))
        return sorted(values)[min(rank, len(values)) - 1]
    if name == "weighted":
        total_weight = sum(range(1, len(values) + 1))
        return sum(value * (i + 1) for i, value in enumerate(values)) / total_weight
    raise ValueError(f"unknown aggregation {strategy!r}; expected one of {AGGREGATORS}")



@dataclass
class VideoAnalysisResult:
    """Aggregated result over the sampled frames of a video."""

    verdict: Verdict = Verdict.UNKNOWN
    score: float = 0.0
    decided_by: DecisionPath = DecisionPath.UNKNOWN
    frames_available: int = 0
    frames_sampled: int = 0
    frames_analyzed: int = 0
    early_exit: bool = False
    worst_frame_index: int = -1
    #: Temporal aggregation strategy that produced ``score`` (§14).
    aggregation: str = "max"
    #: Frame sampling strategy used (§14).
    sampling: str = "uniform"
    request_id: str = ""
    per_frame: List[dict] = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "score": round(float(self.score), 6),
            "decided_by": self.decided_by.value,
            "frames_available": self.frames_available,
            "frames_sampled": self.frames_sampled,
            "frames_analyzed": self.frames_analyzed,
            "early_exit": self.early_exit,
            "worst_frame_index": self.worst_frame_index,
            "aggregation": self.aggregation,
            "sampling": self.sampling,
            "request_id": self.request_id,
            "per_frame": self.per_frame,
            "error": self.error,
        }


class VideoPipeline:
    """Samples and classifies video frames via the engine cascade."""

    def __init__(self, engine: "NsfwEngine", config: VideoConfig) -> None:
        self.engine = engine
        self.config = config

    # -- sampling ------------------------------------------------------------
    #: Sampling strategies (§14).
    SAMPLERS = ("uniform", "scene_change")

    def sample_indices(
        self, total_frames: int, fps: float, frames: Optional[Sequence[np.ndarray]] = None
    ) -> List[int]:
        """Return the frame indices to analyse for a video of *total_frames*.

        With ``sampling == "scene_change"`` and the decoded *frames* supplied, the
        indices are chosen by content change instead of by timestamp. Uniform
        sampling is blind to duration: a five-second explicit insert inside a
        two-minute clip is very likely to fall between two sampled frames, while
        a scene change is almost always where the interesting content was cut in.
        """
        if total_frames <= 0:
            return []
        strategy = (self.config.sampling or "uniform").strip().lower()
        if strategy == "scene_change" and frames is not None:
            indices = self._scene_change_indices(frames)
        else:
            indices = self._uniform_indices(total_frames, fps)
        if len(indices) > self.config.max_frames:
            stride = len(indices) / float(self.config.max_frames)
            indices = [indices[int(i * stride)] for i in range(self.config.max_frames)]
        return indices

    def _uniform_indices(self, total_frames: int, fps: float) -> List[int]:
        fps = fps if fps and fps > 0 else 25.0
        step = max(1, int(round(fps / max(self.config.sample_fps, 1e-6))))
        return list(range(0, total_frames, step))

    def _scene_change_indices(self, frames: Sequence[np.ndarray]) -> List[int]:
        """Pick frames where the picture changes most, plus a regular baseline.

        The mean absolute difference against the previous frame is used because it
        is cheap, has no parameters to tune beyond a threshold, and is dominated
        by cuts. A regular baseline sample is always merged in so that a static
        shot - where the change metric is near zero everywhere - is still
        inspected; pure change detection would return nothing for a slideshow or
        a fixed-camera clip.
        """
        indices: List[int] = []
        baseline = self._uniform_indices(len(frames), 25.0)
        baseline_set = set(baseline)

        previous: Optional[np.ndarray] = None
        for index, frame in enumerate(frames):
            current = self._thumbnail(frame)
            if previous is not None:
                difference = float(np.mean(np.abs(current.astype(np.int16) - previous)))
                if difference >= self.config.scene_threshold:
                    indices.append(index)
            previous = current

        # Always keep the first frame (it has no predecessor to differ from) and
        # the regular baseline, then deduplicate in order.
        merged = sorted(set(indices) | baseline_set | {0})
        return [i for i in merged if 0 <= i < len(frames)]

    @staticmethod
    def _thumbnail(frame: np.ndarray) -> np.ndarray:
        """Downscale a frame to a small greyscale grid for change detection.

        Comparing full-resolution frames would make sampling O(n * pixels) and
        memory-hungry; a 32x32 greyscale signature is more than enough to detect
        a cut, and it makes the per-frame cost negligible next to inference.
        """
        if frame is None or getattr(frame, "size", 0) == 0:
            return np.zeros((32, 32), dtype=np.uint8)
        array = np.asarray(frame)
        if array.ndim == 3 and array.shape[2] >= 3:
            array = array[..., :3].mean(axis=-1)
        elif array.ndim == 3:
            array = array[..., 0]
        rows = max(1, array.shape[0] // 32)
        cols = max(1, array.shape[1] // 32)
        # Block-mean reduction rather than striding: striding can alias a thin
        # high-contrast feature and miss the cut entirely.
        return np.asarray(
            [
                [np.mean(array[r * rows:(r + 1) * rows, c * cols:(c + 1) * cols])
                 for c in range(min(32, array.shape[1] // cols or 1))]
                for r in range(min(32, array.shape[0] // rows or 1))
            ],
            dtype=np.uint8,
        )


    # -- analysis ------------------------------------------------------------
    def analyze_frames(
        self,
        frames: Sequence[np.ndarray],
        fps: float = 25.0,
        text: Optional[str] = None,
        request_id: str = "",
        overrides: Optional[dict] = None,
    ) -> VideoAnalysisResult:
        """Classify a decoded frame sequence, aggregating to a video verdict."""
        result = VideoAnalysisResult(request_id=request_id)
        try:
            total = len(frames)
            result.frames_available = total
            indices = self.sample_indices(total, fps, frames)
            result.frames_sampled = len(indices)

            worst = None
            worst_rank = -1
            analyzed_scores: List[float] = []
            for idx in indices:
                frame = frames[idx]
                frame_result = self.engine.classify_image(
                    frame,
                    text=text,
                    request_id=request_id,
                    media_type=MediaType.VIDEO,
                    overrides=overrides,
                )
                result.frames_analyzed += 1
                analyzed_scores.append(float(frame_result.score))
                if len(result.per_frame) < 64:
                    result.per_frame.append(
                        {
                            "index": idx,
                            "verdict": frame_result.verdict.value,
                            "score": round(float(frame_result.score), 6),
                        }
                    )

                rank = _VERDICT_RANK.get(frame_result.verdict, -1)
                if worst is None or rank > worst_rank or (
                    rank == worst_rank and frame_result.score > worst.score
                ):
                    worst_rank = rank
                    worst = frame_result
                    result.worst_frame_index = idx
                    result.decided_by = frame_result.decided_by

                if frame_result.score >= self.config.early_exit_score and rank >= 1:
                    result.early_exit = True
                    logger.debug(
                        "video early-exit at frame %d (score=%.3f)", idx, frame_result.score
                    )
                    break

            if worst is not None:
                result.verdict = worst.verdict
                # The verdict comes from the worst frame (severity ordering), but
                # the *score* comes from the configured temporal aggregation
                # (§14). With the default `max` these coincide; `mean` and
                # `percentile` let an operator report a lower overall confidence
                # for a clip that was only briefly explicit.
                result.score = aggregate_scores(
                    analyzed_scores,
                    self.config.aggregation,
                    self.config.percentile,
                )
                result.aggregation = self.config.aggregation
        except Exception as exc:  # noqa: BLE001
            logger.exception("video analysis failed")
            result.error = f"{type(exc).__name__}: {exc}"
        return result

    def analyze_encoded_frames(
        self,
        encoded_frames: Sequence[bytes],
        fps: float = 25.0,
        text: Optional[str] = None,
        request_id: str = "",
        overrides: Optional[dict] = None,
    ) -> VideoAnalysisResult:
        """Convenience wrapper that decodes each supplied frame first."""
        decoded: List[np.ndarray] = [self.engine.preprocessor.decode(blob) for blob in encoded_frames]
        return self.analyze_frames(
            decoded, fps=fps, text=text, request_id=request_id, overrides=overrides
        )

