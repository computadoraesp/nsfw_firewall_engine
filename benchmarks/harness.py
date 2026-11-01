"""Benchmark harness (§25, §45, §49).

Spec rule: **"No claims without benchmarks."** This module measures what the
engine actually does on *this* machine and refuses to invent numbers. It reports
mean/p50/p95/p99 latency per stage, end-to-end throughput and the escalation mix.

Two honesty rules are enforced in code:

1. Every report is stamped with ``models_loaded``. When the engine runs on the
   heuristic fallback the report says so - those numbers measure the *pipeline*,
   not a detector.
2. The cache is bypassable, so timings can reflect real inference rather than a
   cache hit.
"""

from __future__ import annotations

import logging
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

import numpy as np

logger = logging.getLogger("nsfw_engine.benchmarks")

#: Colors used to synthesize benchmark images when no dataset is supplied.
_DEFAULT_PALETTE = ((205, 133, 110), (0, 0, 0), (240, 240, 240), (120, 90, 70))


@dataclass
class LatencyStats:
    """Latency distribution in milliseconds."""

    samples: List[float] = field(default_factory=list)

    def add(self, value_ms: float) -> None:
        self.samples.append(float(value_ms))

    @property
    def count(self) -> int:
        return len(self.samples)

    def _percentile(self, fraction: float) -> Optional[float]:
        if not self.samples:
            return None
        ordered = sorted(self.samples)
        index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
        return round(ordered[index], 4)

    def as_dict(self) -> dict:
        if not self.samples:
            return {
                "count": 0, "mean_ms": None, "min_ms": None,
                "p50_ms": None, "p95_ms": None, "p99_ms": None, "max_ms": None,
            }
        ordered = sorted(self.samples)
        return {
            "count": len(ordered),
            "mean_ms": round(statistics.fmean(ordered), 4),
            "min_ms": round(ordered[0], 4),
            "p50_ms": self._percentile(0.50),
            "p95_ms": self._percentile(0.95),
            "p99_ms": self._percentile(0.99),
            "max_ms": round(ordered[-1], 4),
        }
@dataclass
class BenchmarkReport:
    """Aggregated benchmark output."""

    iterations: int = 0
    warmup_iterations: int = 0
    end_to_end: LatencyStats = field(default_factory=LatencyStats)
    stages: Dict[str, LatencyStats] = field(default_factory=dict)
    escalations: Dict[str, int] = field(default_factory=dict)
    verdicts: Dict[str, int] = field(default_factory=dict)
    cache_hits: int = 0
    models_loaded: bool = False
    heuristic_fallback: bool = False

    def stage(self, name: str) -> LatencyStats:
        if name not in self.stages:
            self.stages[name] = LatencyStats()
        return self.stages[name]

    @property
    def throughput_qps(self) -> Optional[float]:
        """Serial single-worker throughput derived from the mean latency."""
        if self.end_to_end.count < 2:
            return None
        mean_ms = statistics.fmean(self.end_to_end.samples)
        return round(1000.0 / mean_ms, 2) if mean_ms > 0 else None

    def as_dict(self) -> dict:
        return {
            "iterations": self.iterations,
            "warmup_iterations": self.warmup_iterations,
            "models_loaded": self.models_loaded,
            "heuristic_fallback": self.heuristic_fallback,
            "end_to_end": self.end_to_end.as_dict(),
            "throughput_qps": self.throughput_qps,
            "per_stage": {n: s.as_dict() for n, s in sorted(self.stages.items())},
            "escalations": dict(sorted(self.escalations.items())),
            "verdicts": dict(sorted(self.verdicts.items())),
            "cache_hits": self.cache_hits,
        }

    def to_Markdown(self) -> str:
        """Render the §25 benchmark matrix as a Markdown table."""
        lines = [
            "## Benchmark matrix (§25)",
            "",
            f"Iterations: **{self.iterations}** (warmup {self.warmup_iterations})",
            "",
            f"- Models loaded: **{self.models_loaded}**",
            f"- Heuristic fallback: **{self.heuristic_fallback}**",
        ]
        if self.heuristic_fallback:
            lines += [
                "",
                "> ⚠️ Measured on the **heuristic fallback** - these numbers describe "
                "the pipeline, not a detector. Re-run with real weights before "
                "publishing performance claims (§49).",
            ]
        lines += [
            "",
            "| Metric | p50 (ms) | p95 (ms) | p99 (ms) | mean (ms) |",
            "|---|---|---|---|---|",
        ]
        end = self.end_to_end.as_dict()
        lines.append(
            f"| end-to-end | {end['p50_ms']} | {end['p95_ms']} | {end['p99_ms']} | {end['mean_ms']} |"
        )
        for name, stats in sorted(self.stages.items()):
            row = stats.as_dict()
            lines.append(
                f"| stage:{name} | {row['p50_ms']} | {row['p95_ms']} | "
                f"{row['p99_ms']} | {row['mean_ms']} |"
            )
        lines += [
            "",
            f"- Throughput (serial, 1 worker): **{self.throughput_qps} req/s**",
            f"- Verdict mix: {dict(sorted(self.verdicts.items()))}",
            f"- Escalations: {dict(sorted(self.escalations.items()))}",
            f"- Cache hits: {self.cache_hits}",
        ]
        return "\n".join(lines)
def synth_images(count: int = 4, size: int = 224) -> List[np.ndarray]:
    """Deterministic solid-color images, so runs stay comparable."""
    return [
        np.full((size, size, 3), _DEFAULT_PALETTE[i % len(_DEFAULT_PALETTE)], dtype=np.uint8)
        for i in range(max(1, count))
    ]


def synth_labeled_set(
    positives: int = 12, negatives: int = 12, size: int = 224
) -> "tuple[List[np.ndarray], List[bool]]":
    """Build a labeled set of *synthetic* images for a smoke evaluation.

    This exists to exercise the §35 metrics path end to end, and it is NOT a
    quality measurement. The two groups are synthetic patterns rather than
    representative content, so a detector's score here says nothing about
    real-world accuracy, and reporting it as FPR/recall would be the §49
    "claim without evidence" failure mode.

    What it *does* prove is that accuracy, precision, recall, F1, ROC-AUC, PR-AUC
    and ECE are computed and reported against known labels. A real quality
    measurement requires a real labeled corpus via
    ``Python -m benchmarks --dataset ...``.
    """
    rng = np.random.default_rng(0)
    images: List[np.ndarray] = []
    labels: List[bool] = []

    def _noise() -> np.ndarray:
        return rng.integers(0, 24, size=(size, size, 3), dtype=np.uint8)

    for index in range(max(1, positives)):
        # A flesh-toned blob on a dark field: "explicit" by construction.
        image = np.zeros((size, size, 3), dtype=np.uint8) + _noise() // 3
        y0, x0 = size // 4, size // 4
        image[y0:y0 + size // 2, x0:x0 + size // 2] = (206, 168, 142)
        images.append(image)
        labels.append(True)

    for index in range(max(1, negatives)):
        # Cool, low-saturation noise: "safe" by construction.
        image = np.zeros((size, size, 3), dtype=np.uint8)
        image[:, :] = (40, 60, 90) + _noise() // 2
        image[size // 3:2 * size // 3, size // 3:2 * size // 3] = (30, 45, 70)
        images.append(image.astype(np.uint8))
        labels.append(False)

    return images, labels


def run_benchmark(
    engine,
    images: Optional[Sequence[np.ndarray]] = None,
    iterations: int = 50,
    warmup: int = 5,
    use_cache: bool = False,
) -> BenchmarkReport:
    """Measure per-stage latency, throughput and the escalation mix.

    Args:
        engine: A constructed :class:`~app.core.engine.NsfwEngine`.
        images: Optional image list; synthetic images are used when omitted.
        iterations: Timed requests (minimum 2 for meaningful percentiles).
        warmup: Untimed requests excluded from the statistics.
        use_cache: When ``False`` (default) the decision cache is bypassed so
            inference time is measured rather than a cache hit.
    """
    images = list(images) if images else synth_images()
    iterations = max(2, int(iterations))
    report = BenchmarkReport(iterations=iterations, warmup_iterations=warmup)

    health = engine.health()
    report.models_loaded = bool(health.get("loaded_models_count", 0))
    report.heuristic_fallback = not report.models_loaded

    previous_cache = engine.cache.enabled
    engine.cache.enabled = bool(use_cache) and previous_cache
    try:
        for index in range(iterations + max(0, int(warmup))):
            image = images[index % len(images)]
            started = time.perf_counter()
            result = engine.classify_image(image)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            if index < warmup:
                continue
            report.end_to_end.add(elapsed_ms)
            for stage in result.stages:
                report.stage(stage.path.value).add(stage.latency_ms)
            report.escalations[result.decided_by.value] = (
                report.escalations.get(result.decided_by.value, 0) + 1
            )
            report.verdicts[result.verdict.value] = (
                report.verdicts.get(result.verdict.value, 0) + 1
            )
            if result.from_cache:
                report.cache_hits += 1
    finally:
        engine.cache.enabled = previous_cache

    return report


__all__ = [
    "BenchmarkReport",
    "LatencyStats",
    "run_benchmark",
    "synth_images",
]