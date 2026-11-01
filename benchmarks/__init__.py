"""Benchmark and evaluation harnesses (§25, §35, §45, §49).

Run with::

    Python -m benchmarks --iterations 200
    Python -m benchmarks --dataset datasets/eval.example.json

These modules exist so that **every** performance or quality number in the
project is reproducible on demand rather than asserted. When the engine has no
model weights loaded they say so explicitly, because the deterministic
heuristic measures the pipeline, not a detector.
"""

from benchmarks.evaluate import (
    EvaluationReport,
    evaluate_manifest,
    load_manifest,
    roc_auc,
)
from benchmarks.harness import (
    BenchmarkReport,
    LatencyStats,
    run_benchmark,
    synth_images,
)

__all__ = [
    "BenchmarkReport",
    "EvaluationReport",
    "LatencyStats",
    "evaluate_manifest",
    "load_manifest",
    "roc_auc",
    "run_benchmark",
    "synth_images",
]