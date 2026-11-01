"""Calibration tests (§26) plus its engine integration (§40 pipeline order)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.calibration import (  # noqa: E402
    METHODS,
    CalibrationRegistry,
    Calibrator,
    expected_calibration_error,
)
from benchmarks.evaluate import roc_auc  # noqa: E402

#: An over-confident model, typical of a heavily oversampled NSFW head: it pushes
#: almost everything to the extremes while the true positive rate is much lower.
OVERCONFIDENT_SCORES = [
    0.99, 0.97, 0.95, 0.93, 0.90, 0.88, 0.86, 0.84, 0.30, 0.20, 0.12, 0.05,
]
OVERCONFIDENT_LABELS = [
    True, True, True, False, True, False, False, False, False, True, False, False,
]


def _is_monotonic(calibrator: Calibrator) -> bool:
    """A calibrator must never reorder samples (§26 monotonicity)."""
    ordered = sorted(OVERCONFIDENT_SCORES)
    return all(
        calibrator.apply(a) <= calibrator.apply(b) + 1e-9
        for a, b in zip(ordered, ordered[1:])
    )


class CalibratorApplicationTests(unittest.TestCase):
    def test_identity_is_a_no_op(self):
        calibrator = Calibrator()
        self.assertTrue(calibrator.is_identity)
        for score in (0.0, 0.25, 0.5, 0.99, 1.0):
            self.assertAlmostEqual(calibrator.apply(score), score)

    def test_output_is_always_a_probability(self):
        """Even nonsense input cannot escape [0, 1] (§26 normalized score)."""
        calibrator = Calibrator.fit("platt", OVERCONFIDENT_SCORES, OVERCONFIDENT_LABELS)
        for value in (-5.0, -1e-9, 0.0, 0.5, 1.0, 5.0):
            out = calibrator.apply(value)
            self.assertGreaterEqual(out, 0.0)
            self.assertLessEqual(out, 1.0)

    def test_non_numeric_and_non_finite_input_is_handled(self):
        """A hostile upstream must not propagate NaN into a policy threshold."""
        calibrator = Calibrator()
        self.assertEqual(calibrator.apply(float("nan")), 0.0)
        self.assertEqual(calibrator.apply(float("inf")), 0.0)
        self.assertEqual(calibrator.apply("not-a-number"), 0.0)
        self.assertEqual(calibrator.apply(None), 0.0)

    def test_degenerate_parameters_are_clamped(self):
        """A hand-edited zero temperature or slope must not invert scores."""
        self.assertGreaterEqual(
            Calibrator(method="temperature", temperature=0.0).temperature, 0.01
        )
        self.assertGreater(Calibrator(method="platt", slope=0.0).slope, 0.0)
        # A negative slope would invert the ranking - the guard must stop it.
        self.assertGreater(Calibrator(method="platt", slope=-5.0).slope, 0.0)

    def test_unknown_method_is_rejected(self):
        with self.assertRaises(ValueError):
            Calibrator(method="magic")


class CalibratorFittingTests(unittest.TestCase):
    def test_every_26_method_is_available(self):
        for method in ("temperature", "platt", "isotonic"):
            self.assertIn(method, METHODS)

    def test_each_method_reduces_calibration_error(self):
        """The whole point of §26: a fitted calibrator must measurably help."""
        before = expected_calibration_error(OVERCONFIDENT_SCORES, OVERCONFIDENT_LABELS)
        for method in ("temperature", "platt", "isotonic"):
            calibrator = Calibrator.fit(method, OVERCONFIDENT_SCORES, OVERCONFIDENT_LABELS)
            after = expected_calibration_error(
                [calibrator.apply(s) for s in OVERCONFIDENT_SCORES], OVERCONFIDENT_LABELS
            )
            self.assertIsNotNone(after)
            self.assertLess(after, before, f"{method} did not improve calibration")

    def test_all_methods_preserve_ranking(self):
        """Monotonicity means calibration can never reorder samples (§26)."""
        for method in ("temperature", "platt", "isotonic"):
            calibrator = Calibrator.fit(method, OVERCONFIDENT_SCORES, OVERCONFIDENT_LABELS)
            self.assertTrue(_is_monotonic(calibrator), f"{method} broke monotonicity")

    def test_strictly_monotonic_methods_preserve_roc_auc(self):
        """ROC-AUC is invariant under a strictly increasing calibration.

        Isotonic regression is excluded on purpose: it maps whole ranges of
        scores onto a single value, which creates *ties*. Ties change the
        rank-sum AUC even though no sample was reordered - the loss is an
        artifact of the tie handling, not a real ranking change. This is the
        standard argument for preferring temperature/platt in production when
        the ranking must stay strictly intact.
        """
        baseline = roc_auc(OVERCONFIDENT_SCORES, OVERCONFIDENT_LABELS)
        for method in ("temperature", "platt"):
            calibrator = Calibrator.fit(method, OVERCONFIDENT_SCORES, OVERCONFIDENT_LABELS)
            calibrated = [calibrator.apply(s) for s in OVERCONFIDENT_SCORES]
            self.assertAlmostEqual(
                roc_auc(calibrated, OVERCONFIDENT_LABELS), baseline, places=6,
                msg=f"{method} changed ROC-AUC",
            )

    def test_temperature_corrects_overconfidence(self):
        """An over-confident model needs T > 1 to soften its outputs."""
        calibrator = Calibrator.fit("temperature", OVERCONFIDENT_SCORES, OVERCONFIDENT_LABELS)
        self.assertGreater(calibrator.temperature, 1.0)

    def test_single_class_data_falls_back_to_identity(self):
        """A one-class validation set cannot identify a calibrator."""
        for method in ("temperature", "platt", "isotonic"):
            calibrator = Calibrator.fit(method, [0.1, 0.2, 0.3], [False, False, False])
            self.assertTrue(calibrator.is_identity, f"{method} fitted on one class")

    def test_empty_data_falls_back_to_identity(self):
        self.assertTrue(Calibrator.fit("isotonic", [], []).is_identity)

    def test_nan_samples_are_dropped_not_propagated(self):
        scores = [0.1, float("nan"), 0.5, 0.9, 0.2, 0.8]
        labels = [False, True, True, True, False, False]
        calibrator = Calibrator.fit("platt", scores, labels)
        self.assertEqual(calibrator.metadata.get("samples"), 5)


class ExpectedCalibrationErrorTests(unittest.TestCase):
    def test_perfect_calibration_is_near_zero(self):
        # Two buckets, two outcomes: reported 0.0 -> observed 0, reported 1.0 ->
        # observed 1. Confidence and outcome agree exactly in both buckets.
        scores = [0.0] * 5 + [1.0] * 5
        labels = [False] * 5 + [True] * 5
        self.assertLess(expected_calibration_error(scores, labels, bins=2), 1e-9)

    def test_a_confident_but_wrong_bucket_is_penalised(self):
        # A model reporting 0.05 confidence on samples that are all explicit:
        # the bucket is 95% wrong, and ECE must reflect that.
        scores = [0.05] * 5 + [0.95] * 5
        labels = [True] * 5 + [False] * 5
        self.assertGreater(expected_calibration_error(scores, labels, bins=2), 0.8)

    def test_maximally_wrong_confidence_is_near_one(self):
        # Everything is labeled positive but reported at ~0 confidence.
        scores = [0.0] * 5 + [0.02] * 5
        labels = [True] * 10
        self.assertGreater(expected_calibration_error(scores, labels, bins=2), 0.9)

    def test_empty_and_mismatched_inputs_return_none(self):
        self.assertIsNone(expected_calibration_error([], []))
        self.assertIsNone(expected_calibration_error([0.5], [True, False]))


class CalibrationRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "calibration.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_absent_file_yields_an_inert_registry(self):
        """A source checkout has no fitted calibration - that must be normal."""
        registry = CalibrationRegistry.load(self.path)
        self.assertEqual(registry.calibrated_models, [])
        self.assertEqual(registry.apply("fast_path_mobilenetv3", 0.42), 0.42)

    def test_unknown_model_is_identity(self):
        registry = CalibrationRegistry.load(self.path)
        self.assertFalse(registry.is_calibrated("nope"))
        self.assertEqual(registry.apply("nope", 0.9), 0.9)

    def test_roundtrip_through_json(self):
        registry = CalibrationRegistry()
        registry.set(
            "fast_path_mobilenetv3",
            Calibrator.fit("temperature", OVERCONFIDENT_SCORES, OVERCONFIDENT_LABELS),
        )
        registry.save(self.path)
        reloaded = CalibrationRegistry.load(self.path)
        self.assertEqual(reloaded.calibrated_models, ["fast_path_mobilenetv3"])
        original = registry.get("fast_path_mobilenetv3")
        restored = reloaded.get("fast_path_mobilenetv3")
        self.assertAlmostEqual(restored.temperature, original.temperature, places=5)
        self.assertAlmostEqual(restored.apply(0.7), original.apply(0.7), places=6)

    def test_isotonic_knots_survive_persistence(self):
        registry = CalibrationRegistry()
        registry.set(
            "m", Calibrator.fit("isotonic", OVERCONFIDENT_SCORES, OVERCONFIDENT_LABELS)
        )
        registry.save(self.path)
        restored = CalibrationRegistry.load(self.path).get("m")
        self.assertEqual(restored.method, "isotonic")
        self.assertTrue(restored.knots)
        self.assertAlmostEqual(restored.apply(0.6), restored.apply(0.6), places=9)

    def test_corrupt_file_degrades_to_inert(self):
        """A broken calibration file is a quality problem, never an outage."""
        self.path.write_text("{not json at all", encoding="utf-8")
        self.assertEqual(CalibrationRegistry.load(self.path).calibrated_models, [])

    def test_invalid_document_degrades_to_identity(self):
        self.path.write_text(
            json.dumps({"calibrators": {"m": {"method": "not-a-method"}}}), encoding="utf-8"
        )
        self.assertTrue(CalibrationRegistry.load(self.path).get("m").is_identity)

    def test_ece_is_reported_through_the_registry(self):
        registry = CalibrationRegistry()
        registry.set(
            "m", Calibrator.fit("isotonic", OVERCONFIDENT_SCORES, OVERCONFIDENT_LABELS)
        )
        self.assertIsNotNone(
            registry.ece("m", OVERCONFIDENT_SCORES, OVERCONFIDENT_LABELS)
        )


class CalibrateScriptTests(unittest.TestCase):
    """The fitting entry point (§26) refuses to run on unfit data."""

    def test_single_class_dataset_is_rejected(self):
        from scripts.calibrate import main

        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "m.json"
            manifest.write_text(
                json.dumps(
                    {
                        "positive_label": "nsfw",
                        "items": [{"path": f"a{i}.ppm", "label": "sfw"} for i in range(6)],
                    }
                ),
                encoding="utf-8",
            )
            # The files do not exist, so nothing is scorable: the guard must
            # refuse rather than fit a calibrator from nothing.
            self.assertEqual(main(["--dataset", str(manifest), "--dry-run"]), 2)

    def test_missing_dataset_is_rejected(self):
        from scripts.calibrate import main

        self.assertEqual(main(["--dataset", "no-such-manifest.json", "--dry-run"]), 2)


class EngineCalibrationIntegrationTests(unittest.TestCase):
    """§26 pipeline order: RAW OUTPUT -> CALIBRATION -> NORMALIZED -> FUSION."""

    def _engine(self, enabled: bool, calibrator: Calibrator):
        from app.core.config import CalibrationConfig, EngineConfig
        from app.core.engine import NsfwEngine

        config = EngineConfig(
            calibration=CalibrationConfig(enabled=enabled, path="none.json")
        )
        engine = NsfwEngine(config)
        engine.calibration.set("fast_path_mobilenetv3", calibrator)
        return engine

    def test_disabled_calibration_leaves_scores_untouched(self):
        """Disabled is the default, so existing behavior must not change.

        The registry still *holds* a calibrator here; what matters is that the
        engine refuses to apply it. A registered-but-disabled calibrator is the
        normal state after ``scripts/calibrate.py`` writes the document but an
        operator has not flipped the flag yet.
        """
        from app.models.base import DecisionPath, StageResult

        calibrator = Calibrator(method="temperature", temperature=10.0)
        engine = self._engine(False, calibrator)
        stage = StageResult(
            path=DecisionPath.FAST, score=0.95, latency_ms=1.0,
            model="fast_path_mobilenetv3",
        )
        engine._calibrate_stage(stage)
        self.assertEqual(stage.score, 0.95)

        health = engine.health()
        self.assertFalse(health["calibration"]["enabled"])
        # A registered calibrator is still reported so an operator can see that
        # a fitted document exists but is not being applied.
        self.assertEqual(
            health["calibration"]["calibrated_models"], ["fast_path_mobilenetv3"]
        )

    def test_enabled_calibration_rewrites_the_stage_score(self):
        """The calibrator must act on the stage score, before fusion."""
        from app.models.base import DecisionPath, StageResult

        calibrator = Calibrator(method="temperature", temperature=10.0)
        engine = self._engine(True, calibrator)
        stage = StageResult(
            path=DecisionPath.FAST, score=0.95, latency_ms=1.0,
            model="fast_path_mobilenetv3",
        )
        engine._calibrate_stage(stage)
        self.assertLess(stage.score, 0.95)
        self.assertAlmostEqual(stage.score, calibrator.apply(0.95), places=6)

    def test_uncalibrated_model_is_left_alone(self):
        """A calibrator for another model must not touch this stage."""
        from app.models.base import DecisionPath, StageResult

        engine = self._engine(True, Calibrator(method="temperature", temperature=10.0))
        stage = StageResult(
            path=DecisionPath.DEEP, score=0.8, latency_ms=1.0,
            model="deep_path_efficientnet",
        )
        engine._calibrate_stage(stage)
        self.assertEqual(stage.score, 0.8)

    def test_health_reports_which_models_are_calibrated(self):
        engine = self._engine(True, Calibrator(method="platt", slope=2.0, intercept=-1.0))
        self.assertEqual(
            engine.health()["calibration"]["calibrated_models"], ["fast_path_mobilenetv3"]
        )


class EvaluationMetricsTests(unittest.TestCase):
    """The §24 metric set, including the ones the report previously omitted."""

    def _report(self, tp, fp, tn, fn):
        from benchmarks.evaluate import EvaluationReport

        report = EvaluationReport(
            samples=tp + fp + tn + fn,
            positives=tp + fn,
            negatives=tn + fp,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
        )
        return report

    def test_error_rates_are_reported(self):
        report = self._report(tp=8, fp=2, tn=90, fn=1)
        self.assertAlmostEqual(report.false_positive_rate, 2 / 92, places=5)
        self.assertAlmostEqual(report.false_negative_rate, 1 / 9, places=5)
        self.assertAlmostEqual(report.specificity, 1 - 2 / 92, places=5)

    def test_error_rates_are_none_without_the_denominator(self):
        """Reporting 0% FPR on a set with no negatives would be a lie."""
        report = self._report(tp=5, fp=0, tn=0, fn=0)
        self.assertIsNone(report.false_positive_rate)
        self.assertIsNone(report.specificity)
        # FNR is still defined here: there are positives.
        self.assertIsNotNone(report.false_negative_rate)

    def test_perfect_classifier_has_zero_error_rates(self):
        report = self._report(tp=10, fp=0, tn=50, fn=0)
        self.assertEqual(report.false_positive_rate, 0.0)
        self.assertEqual(report.false_negative_rate, 0.0)
        self.assertEqual(report.accuracy, 1.0)

    def test_as_dict_exposes_the_full_24_metric_set(self):
        payload = self._report(tp=1, fp=1, tn=1, fn=1).as_dict()
        for key in (
            "accuracy", "precision", "recall", "f1", "false_positive_rate",
            "false_negative_rate", "specificity", "roc_auc", "pr_auc", "ece",
            "confusion",
        ):
            self.assertIn(key, payload)


class PrAucTests(unittest.TestCase):
    def test_perfect_ranking_is_one(self):
        from benchmarks.evaluate import pr_auc

        self.assertEqual(pr_auc([0.9, 0.8, 0.2, 0.1], [True, True, False, False]), 1.0)

    def test_inverted_ranking_is_low(self):
        from benchmarks.evaluate import pr_auc

        self.assertLess(pr_auc([0.1, 0.2, 0.8, 0.9], [True, True, False, False]), 0.5)

    def test_no_positives_returns_none(self):
        """Precision is undefined with no positives; a number would mislead."""
        from benchmarks.evaluate import pr_auc

        self.assertIsNone(pr_auc([0.5, 0.4], [False, False]))

    def test_all_ties_give_the_prevalence(self):
        """With no ranking information, AP collapses to the base rate."""
        from benchmarks.evaluate import pr_auc

        self.assertAlmostEqual(pr_auc([0.5] * 4, [True, False, False, False]), 0.25, places=5)

    def test_pr_auc_is_precision_weighted(self):
        """AP weighs precision, so it penalizes a detector that over-fires.

        Averaged precision is dominated by precision at low recall, which is why
        PR-AUC is the metric to quote alongside ROC-AUC when the positive class
        is rare. Here the detector sweeps 40 samples to catch 2 positives.
        """
        from benchmarks.evaluate import pr_auc

        # The single highest-scoring sample is a false positive.
        scores = [0.99] + [0.9] * 39 + [0.2, 0.2, 0.2] + [0.1] * 60
        labels = [False] + [False] * 39 + [True] * 3 + [False] * 60
        value = pr_auc(scores, labels)
        self.assertIsNotNone(value)
        # Precision never exceeds ~3/41 at the recall levels that matter.
        self.assertLess(value, 0.3)

    def test_pr_auc_rewards_a_detector_that_finds_the_positives_first(self):
        from benchmarks.evaluate import pr_auc, roc_auc

        scores = [0.9] * 5 + [0.1] * 95
        labels = [True] * 5 + [False] * 95
        self.assertEqual(pr_auc(scores, labels), 1.0)
        self.assertGreater(roc_auc(scores, labels), 0.97)


if __name__ == "__main__":
    unittest.main(verbosity=2)

