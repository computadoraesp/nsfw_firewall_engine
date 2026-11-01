"""Tests for the adapter package (§41) and the benchmark/evaluation harnesses.

The harnesses must never fabricate numbers, so several of these tests assert
that a missing dataset or missing weights produces an explicit *skipped* /
*fallback* result rather than a plausible-looking score.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from adapters import (  # noqa: E402
    ADAPTER_REGISTRY,
    AdapterCategory,
    AdapterResult,
    BaseAdapter,
    available_adapters,
    build_adapter,
    describe_all,
    ensemble_score,
)
from adapters.vision import NuditaAdapter  # noqa: E402
from app.core.config import load_config  # noqa: E402
from app.core.engine import NsfwEngine  # noqa: E402
from benchmarks.evaluate import evaluate_manifest, roc_auc  # noqa: E402
from benchmarks.harness import LatencyStats, run_benchmark, synth_images  # noqa: E402
from tests.test_engine import SKIN, make_ppm  # noqa: E402


class AdapterContractTests(unittest.TestCase):
    def test_registry_exposes_every_stage(self):
        for stage in ("fast_path", "deep_path", "multimodal"):
            self.assertIn(stage, ADAPTER_REGISTRY)
            self.assertIn(stage, available_adapters())

    def test_each_stage_maps_to_its_upstream_project(self):
        self.assertEqual(ADAPTER_REGISTRY["fast_path"].name, "nsfwjs")
        self.assertEqual(ADAPTER_REGISTRY["deep_path"].name, "opennsfw2")
        self.assertEqual(ADAPTER_REGISTRY["multimodal"].name, "clip_zeroshot")

    def test_unknown_stage_returns_none(self):
        self.assertIsNone(build_adapter("nope", None))

    def test_describe_shape_is_stable(self):
        described = describe_all(None)
        for stage in ADAPTER_REGISTRY:
            self.assertIn("license", described[stage])
            self.assertIn("available", described[stage])

    def test_score_is_clamped(self):
        self.assertEqual(AdapterResult(score=5.0, adapter="x").score, 1.0)
        self.assertEqual(AdapterResult(score=-2.0, adapter="x").score, 0.0)

    def test_normalize_matches_engine_collapse(self):
        # A single logit is squashed by sigmoid.
        self.assertAlmostEqual(BaseAdapter.normalize([0.0]), 0.5, places=5)

    def test_categorise_buckets(self):
        self.assertIs(BaseAdapter.categorise(0.95), AdapterCategory.PORN)
        self.assertIs(BaseAdapter.categorise(0.60), AdapterCategory.SEXY)

    def test_result_serialises(self):
        payload = AdapterResult(score=0.5, adapter="a").as_dict()
        self.assertEqual(payload["adapter"], "a")
        self.assertIn("category", payload)


class AdapterGracefulDegradationTests(unittest.TestCase):
    def test_missing_weights_yield_none_not_exception(self):
        adapter = build_adapter("fast_path", None)
        self.assertFalse(adapter.available)
        self.assertIsNone(adapter.predict(make_ppm(8, 8, SKIN)))

    def test_nudita_is_inert_due_to_agpl(self):
        # AGPL-3.0 code must never be loaded in-process (§2/§4).
        adapter = NuditaAdapter()
        self.assertFalse(adapter.available)
        self.assertIsNone(adapter.predict(np.zeros((4, 4, 3), dtype=np.uint8)))
        self.assertIn("AGPL", adapter.license)

    def test_non_image_payload_returns_none(self):
        adapter = build_adapter("fast_path", None)
        self.assertIsNone(adapter.predict("not an image"))

    def test_ensemble_score_skips_missing(self):
        results = [AdapterResult(score=0.8, adapter="a"), None]
        self.assertAlmostEqual(ensemble_score(results), 0.8, places=6)

    def test_ensemble_score_of_nothing_is_none(self):
        self.assertIsNone(ensemble_score([None, None]))

    def test_weighted_ensemble(self):
        results = [AdapterResult(score=1.0, adapter="a"), AdapterResult(score=0.0, adapter="b")]
        self.assertAlmostEqual(ensemble_score(results, [3.0, 1.0]), 0.75, places=6)

    def test_engine_health_surfaces_adapters(self):
        info = NsfwEngine(load_config()).health()
        self.assertIn("adapters", info)
        self.assertIn("fast_path", info["adapters"])


class LatencyStatsTests(unittest.TestCase):
    def test_percentiles(self):
        stats = LatencyStats()
        for value in (1.0, 2.0, 3.0, 4.0, 100.0):
            stats.add(value)
        payload = stats.as_dict()
        self.assertEqual(payload["count"], 5)
        self.assertEqual(payload["p50_ms"], 3.0)
        self.assertEqual(payload["min_ms"], 1.0)
        self.assertEqual(payload["max_ms"], 100.0)

    def test_empty_stats_are_null_not_zero(self):
        payload = LatencyStats().as_dict()
        self.assertEqual(payload["count"], 0)
        self.assertIsNone(payload["p50_ms"])


class BenchmarkHarnessTests(unittest.TestCase):
    def setUp(self):
        self.engine = NsfwEngine(load_config())

    def test_benchmark_reports_stages(self):
        report = run_benchmark(self.engine, iterations=6, warmup=1)
        self.assertEqual(report.end_to_end.count, 6)
        self.assertIn("FAST", report.stages)
        self.assertGreater(report.throughput_qps, 0)

    def test_flags_heuristic_fallback(self):
        # Without weights the harness must not imply detector performance.
        report = run_benchmark(self.engine, iterations=4, warmup=0)
        if not report.models_loaded:
            self.assertTrue(report.heuristic_fallback)
            self.assertIn("heuristic fallback", report.to_Markdown())

    def test_cache_is_bypassed_by_default(self):
        report = run_benchmark(self.engine, iterations=4, warmup=0)
        self.assertEqual(report.cache_hits, 0)

    def test_Markdown_has_matrix_header(self):
        report = run_benchmark(self.engine, iterations=4, warmup=0)
        self.assertIn("Benchmark matrix", report.to_Markdown())

    def test_synth_images_are_deterministic(self):
        self.assertTrue(np.array_equal(synth_images(2)[0], synth_images(2)[0]))
class RocAucTests(unittest.TestCase):
    def test_perfect_separation(self):
        self.assertEqual(roc_auc([0.1, 0.2, 0.8, 0.9], [False, False, True, True]), 1.0)

    def test_inverted_separation(self):
        self.assertEqual(roc_auc([0.9, 0.8, 0.2, 0.1], [False, False, True, True]), 0.0)

    def test_single_class_is_undefined(self):
        self.assertIsNone(roc_auc([0.1, 0.2], [True, True]))


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        config = load_config()
        config.paths.fast_path_model = "models_onnx/__missing_fast__.onnx"
        config.paths.deep_path_model = "models_onnx/__missing_deep__.onnx"
        config.paths.multimodal_model = "models_onnx/__missing_multimodal__.onnx"
        self.engine = NsfwEngine(config)

    def _dataset(self, tmp: str) -> str:
        base = Path(tmp)
        items = []
        for index in range(3):
            (base / f"safe_{index}.ppm").write_bytes(make_ppm(8, 8, (0, 0, 0)))
            items.append({"path": f"safe_{index}.ppm", "label": "sfw"})
            (base / f"nsfw_{index}.ppm").write_bytes(make_ppm(8, 8, SKIN))
            items.append({"path": f"nsfw_{index}.ppm", "label": "nsfw"})
        manifest = base / "manifest.json"
        manifest.write_text(
            json.dumps({"positive_label": "nsfw", "items": items}), encoding="utf-8"
        )
        return str(manifest)

    def test_evaluates_a_labeled_dataset(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = evaluate_manifest(self.engine, self._dataset(tmp))
        self.assertFalse(report.skipped)
        self.assertEqual(report.samples, 6)
        self.assertEqual(report.positives, 3)
        self.assertEqual(report.accuracy, 0.5)
        self.assertIsNone(report.precision)
        self.assertEqual(report.recall, 0.0)
        self.assertFalse(report.models_loaded)

    def test_missing_manifest_is_skipped_not_faked(self):
        report = evaluate_manifest(self.engine, "does-not-exist.json")
        self.assertTrue(report.skipped)
        self.assertIsNone(report.accuracy)
        self.assertIn("Skipped", report.to_Markdown())

    def test_manifest_without_samples_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "empty.json"
            manifest.write_text(json.dumps({"items": []}), encoding="utf-8")
            report = evaluate_manifest(self.engine, str(manifest))
        self.assertTrue(report.skipped)

    def test_unreadable_items_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "broken.json"
            manifest.write_text(
                json.dumps({"items": [{"path": "missing.ppm", "label": "nsfw"}]}),
                encoding="utf-8",
            )
            report = evaluate_manifest(self.engine, str(manifest))
        self.assertTrue(report.skipped)
        self.assertTrue(report.errors)

    def test_malformed_item_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "bad.json"
            manifest.write_text(json.dumps({"items": [{"label": "nsfw"}]}), encoding="utf-8")
            report = evaluate_manifest(self.engine, str(manifest))
        self.assertTrue(report.skipped)


if __name__ == "__main__":
    unittest.main(verbosity=2)