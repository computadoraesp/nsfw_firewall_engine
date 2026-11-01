"""Tests for the §10 Premium Path stage.

The premium ViT is opt-in and unbenchmarked, so most of these tests are about
what happens when it is *not* in play: the cascade must be unchanged, and a
stage that did not run must not be recorded as a zero score.
"""

import sys
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np  # noqa: E402

from app.core.config import EngineConfig  # noqa: E402
from app.core.engine import NsfwEngine  # noqa: E402
from app.models.base import DecisionPath, StageResult, Verdict  # noqa: E402
from app.models.premium_path import PremiumPathEvaluator  # noqa: E402


def solid(size=64, color=(0, 0, 0)):
    return np.full((size, size, 3), color, dtype=np.uint8)


class _StubAdapter:
    """Minimal BaseAdapter stand-in: available or not, scores or declines."""

    name = "hf_vit_nsfw"

    def __init__(self, available=True, score=0.9, decline=False):
        self._available = available
        self._score = score
        self._decline = decline
        self.calls = 0

    @property
    def available(self):
        return self._available

    def predict(self, payload):
        from adapters.base import AdapterResult

        self.calls += 1
        if self._decline:
            return None
        return AdapterResult(score=self._score, adapter=self.name)


def loaded_count(health):
    """Number of stages health() reports as loaded, per stage map."""
    return sum(1 for value in health["models_loaded"].values() if value)


def _engine(premium_enabled, **overrides):
    config = EngineConfig(**overrides)
    config.paths.fast_path_model = "models_onnx/__missing_fast__.onnx"
    config.paths.deep_path_model = "models_onnx/__missing_deep__.onnx"
    config.paths.multimodal_model = "models_onnx/__missing_multimodal__.onnx"
    config.thresholds.premium.enabled = premium_enabled
    # Force the cheap stages to be inconclusive so the cascade reaches the
    # premium arbiter instead of deciding on the fast path.
    config.thresholds.fast_path.hard_sfw = -0.001
    config.thresholds.fast_path.hard_nsfw = 1.001
    config.thresholds.deep_path.hard_sfw = -0.001
    config.thresholds.deep_path.hard_nsfw = 1.001
    return NsfwEngine(config)


class PremiumDisabledTests(unittest.TestCase):
    """With the stage off, unavailable models must not invent a decision."""

    def test_disabled_by_default(self):
        self.assertFalse(EngineConfig().thresholds.premium.enabled)

    def test_stage_absent_from_the_result_when_disabled(self):
        engine = _engine(False)
        result = engine.classify_image(solid())
        self.assertEqual(result.verdict, Verdict.REVIEW)
        self.assertEqual(result.decided_by, DecisionPath.UNKNOWN)
        self.assertNotIn(DecisionPath.PREMIUM, [s.path for s in result.stages])

    def test_adapter_is_never_consulted_when_disabled(self):
        engine = _engine(False)
        adapter = _StubAdapter()
        engine.premium.adapter = adapter
        engine.classify_image(solid())
        self.assertEqual(adapter.calls, 0)

    def test_disabled_model_does_not_make_engine_ready(self):
        engine = _engine(False)
        engine.premium.adapter = _StubAdapter()
        health = engine.health()
        self.assertFalse(health["models_loaded"]["premium_vit"])
        # The count depends on which artifacts happen to be mounted locally, so
        # assert on this stage's contribution rather than on an absolute total.
        loaded = health["models_loaded"]
        self.assertEqual(sum(1 for v in loaded.values() if v), loaded_count(health))
class PremiumEnabledTests(unittest.TestCase):
    def test_enabled_available_model_counts_as_loaded(self):
        engine = _engine(True)
        engine.premium.adapter = _StubAdapter()
        health = engine.health()
        self.assertTrue(health["models_loaded"]["premium_vit"])
        others = {k: v for k, v in health["models_loaded"].items() if k != "premium_vit"}
        self.assertEqual(health["loaded_models_count"], 1 + loaded_count({"models_loaded": others}))

    def test_high_score_blocks(self):
        engine = _engine(True)
        engine.premium.adapter = _StubAdapter(score=0.95)
        result = engine.classify_image(solid())
        self.assertEqual(result.verdict, Verdict.NSFW)
        self.assertEqual(result.decided_by, DecisionPath.PREMIUM)
        self.assertAlmostEqual(result.score, 0.95, places=6)

    def test_mid_score_reviews(self):
        engine = _engine(True)
        engine.premium.adapter = _StubAdapter(score=0.5)
        result = engine.classify_image(solid())
        self.assertEqual(result.verdict, Verdict.REVIEW)
        self.assertEqual(result.decided_by, DecisionPath.PREMIUM)

    def test_low_score_allows(self):
        engine = _engine(True)
        engine.premium.adapter = _StubAdapter(score=0.01)
        result = engine.classify_image(solid())
        self.assertEqual(result.verdict, Verdict.SFW)
        self.assertEqual(result.decided_by, DecisionPath.PREMIUM)

    def test_stage_is_recorded_in_stages(self):
        engine = _engine(True)
        engine.premium.adapter = _StubAdapter(score=0.95)
        result = engine.classify_image(solid())
        premium = [s for s in result.stages if s.path == DecisionPath.PREMIUM]
        self.assertEqual(len(premium), 1)
        self.assertTrue(premium[0].executed)
        self.assertEqual(premium[0].model, PremiumPathEvaluator.model_name)

    def test_fast_path_still_short_circuits(self):
        # The premium stage is an arbiter, not a mandatory gate: a decisive
        # fast-path verdict must still return before it is consulted.
        engine = _engine(True)
        config = engine.config
        config.thresholds.fast_path.hard_sfw = 0.999
        adapter = _StubAdapter(score=0.99)
        engine.premium.adapter = adapter
        with patch.object(
            engine.fast,
            "evaluate",
            return_value=StageResult(
                path=DecisionPath.FAST,
                score=0.99,
                latency_ms=0.0,
                executed=True,
                model="test_fast",
            ),
        ):
            result = engine.classify_image(solid(color=(0, 0, 0)))
        self.assertEqual(result.decided_by, DecisionPath.FAST)
        self.assertEqual(adapter.calls, 0)


class PremiumUnavailableTests(unittest.TestCase):
    """An unavailable premium stage cannot turn missing models into a verdict."""

    def test_unmounted_artifact_does_not_make_a_decision(self):
        engine = _engine(True)
        engine.premium.adapter = _StubAdapter(available=False)
        result = engine.classify_image(solid())
        self.assertEqual(result.verdict, Verdict.REVIEW)
        self.assertEqual(result.decided_by, DecisionPath.UNKNOWN)
        premium = [s for s in result.stages if s.path == DecisionPath.PREMIUM]
        self.assertTrue(premium)
        self.assertFalse(premium[0].executed)

    def test_adapter_declining_does_not_make_a_decision(self):
        # The ViT refuses to score when its label sidecar is unusable; that
        # must not become a zero score that reads as "safe".
        engine = _engine(True)
        engine.premium.adapter = _StubAdapter(decline=True)
        result = engine.classify_image(solid())
        self.assertEqual(result.verdict, Verdict.REVIEW)
        self.assertEqual(result.decided_by, DecisionPath.UNKNOWN)
        premium = [s for s in result.stages if s.path == DecisionPath.PREMIUM]
        self.assertFalse(premium[0].executed)

    def test_skipped_stage_reports_no_score(self):
        engine = _engine(True)
        engine.premium.adapter = _StubAdapter(available=False)
        result = engine.classify_image(solid())
        premium = [s for s in result.stages if s.path == DecisionPath.PREMIUM][0]
        self.assertEqual(premium.score, 0.0)
        self.assertTrue(premium.fallback)


class EvaluatorContractTests(unittest.TestCase):
    def test_loaded_premium_model_enables_latency_budgets(self):
        config = EngineConfig()
        config.thresholds.premium.enabled = True
        premium = PremiumPathEvaluator(adapter=_StubAdapter(), timeout_ms=120)
        with patch.object(PremiumPathEvaluator, "from_config", return_value=premium):
            engine = NsfwEngine(config)
        self.assertTrue(engine._models_loaded)

    def test_model_id_matches_the_adapter_registry_key(self):
        # §26 calibration and the §22 registry key on this string; if the two
        # drift apart, a fitted calibrator would never apply.
        from adapters.registry import ADAPTER_REGISTRY

        self.assertIn(PremiumPathEvaluator.model_name, ADAPTER_REGISTRY)

    def test_path_is_premium(self):
        self.assertEqual(PremiumPathEvaluator.path, DecisionPath.PREMIUM)

    def test_no_session_means_is_stub(self):
        # The stage owns no ONNX session; is_stub must be True so nothing tries
        # to calibrate or enforce a budget against a session that is absent.
        evaluator = PremiumPathEvaluator(adapter=_StubAdapter(), timeout_ms=120)
        self.assertTrue(evaluator.is_stub)

    def test_skipped_result_shape(self):
        evaluator = PremiumPathEvaluator(
            adapter=_StubAdapter(available=False), timeout_ms=120
        )
        stage = evaluator.evaluate(solid(8, 8))
        self.assertIsInstance(stage, StageResult)
        self.assertFalse(stage.executed)
        self.assertEqual(stage.path, DecisionPath.PREMIUM)


if __name__ == "__main__":
    unittest.main()