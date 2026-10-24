"""Automated tests for the NSFW Firewall Engine orchestration core.

Run with either::

    python -m unittest discover -s tests -v
    python -m pytest tests -v            # if pytest is installed

The suite is written against the standard library so it runs in minimal
environments. Tests that do not specifically exercise an ONNX model use
missing-model paths and assert that the cascade asks for review rather than
mistaking a heuristic for a trained detector.
"""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import load_config  # noqa: E402
from app.core.engine import NsfwEngine  # noqa: E402
from app.core.preprocessor import Preprocessor, PreprocessingError  # noqa: E402
from app.models.base import DecisionPath, MediaType, Verdict  # noqa: E402
from app.services.text_analyzer import TextAnalyzer  # noqa: E402
from app.services.video_pipeline import VideoPipeline  # noqa: E402


def make_ppm(width: int, height: int, rgb: tuple[int, int, int]) -> bytes:
    """Build a binary PPM (P6) image with a solid colour."""
    header = f"P6\n{width} {height}\n255\n".encode("ascii")
    return header + bytes(rgb) * (width * height)


def solid(width: int, height: int, rgb: tuple[int, int, int]) -> np.ndarray:
    img = np.zeros((height, width, 3), dtype=np.uint8)
    img[..., 0], img[..., 1], img[..., 2] = rgb
    return img


# A saturated skin-tone colour the heuristic treats as likely-NSFW.
SKIN = (205, 133, 110)
BLACK = (0, 0, 0)


class ConfigTests(unittest.TestCase):
    def test_load_config_defaults(self):
        config = load_config()
        self.assertEqual(config.engine.mode, "triage")
        self.assertGreater(config.thresholds.fast_path.hard_nsfw, 0.0)
        self.assertEqual(config.timeouts.fast_path_ms, 10)
        self.assertEqual(config.paths.deep_path_model, "models_onnx/vit_nsfw.onnx")
        self.assertEqual(config.preprocessing.deep_path_resize, (224, 224))

    def test_model_path_is_absolute(self):
        config = load_config()
        path = config.model_path(config.paths.fast_path_model)
        self.assertTrue(path.is_absolute())


class PreprocessorTests(unittest.TestCase):
    def setUp(self):
        self.pp = Preprocessor()

    def test_ppm_decode(self):
        data = make_ppm(4, 3, SKIN)
        img = self.pp.decode(data)
        self.assertEqual(img.shape, (3, 4, 3))
        np.testing.assert_array_equal(img[0, 0], np.array(SKIN, dtype=np.uint8))

    def test_resize_and_tensor_shape(self):
        img = self.pp.decode(make_ppm(8, 6, BLACK))
        tensor = self.pp.array_to_tensor(img, (4, 4))
        self.assertEqual(tensor.shape, (1, 3, 4, 4))
        self.assertEqual(tensor.dtype, np.float32)
        expected_c0 = (0.0 - 0.485) / 0.229
        self.assertAlmostEqual(float(tensor[0, 0, 0, 0]), expected_c0, places=5)

    def test_array_to_tensor_accepts_model_specific_normalization(self):
        img = np.full((2, 2, 3), 128, dtype=np.uint8)
        tensor = self.pp.array_to_tensor(
            img,
            (2, 2),
            mean=(0.5, 0.5, 0.5),
            std=(0.5, 0.5, 0.5),
        )
        expected = (128 / 255.0 - 0.5) / 0.5
        self.assertAlmostEqual(float(tensor[0, 0, 0, 0]), expected, places=5)

    def test_empty_payload_raises(self):
        with self.assertRaises(PreprocessingError):
            self.pp.decode(b"")

    def test_oversized_dimension_raises(self):
        pp = Preprocessor(max_image_dim=2)
        with self.assertRaises(PreprocessingError):
            pp.decode(make_ppm(4, 4, BLACK))


class TextAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = TextAnalyzer()

    def test_clean_text_scores_zero(self):
        result = self.analyzer.analyze("A friendly tutorial about gardening.")
        self.assertEqual(result.score, 0.0)
        self.assertEqual(result.matches, [])

    def test_html_is_stripped_and_matched(self):
        html = "<html><head><style>.x{}</style></head><body>free porn here</body></html>"
        result = self.analyzer.analyze(html)
        self.assertTrue(result.is_html)
        self.assertIn("porn", result.matches)
        self.assertGreater(result.score, 0.0)

    def test_suspicious_urls_are_flagged(self):
        result = self.analyzer.analyze("visit https://example.com/xxx-videos now")
        self.assertEqual(result.url_count, 1)
        self.assertEqual(result.suspicious_urls, 1)

    def test_score_is_capped(self):
        result = self.analyzer.analyze("porn xxx nude naked erotic hentai bdsm nude")
        self.assertLessEqual(result.score, 1.0)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.config = load_config()
        self.config.paths.fast_path_model = "models_onnx/__missing_fast__.onnx"
        self.config.paths.deep_path_model = "models_onnx/__missing_deep__.onnx"
        self.config.paths.multimodal_model = "models_onnx/__missing_multimodal__.onnx"
        self.engine = NsfwEngine(self.config)

    def test_missing_models_do_not_claim_a_safe_verdict(self):
        result = self.engine.classify_image(solid(64, 64, BLACK))
        self.assertEqual(result.verdict, Verdict.REVIEW)
        self.assertEqual(result.decided_by, DecisionPath.UNKNOWN)
        self.assertTrue(all(stage.fallback for stage in result.stages))

    def test_missing_models_do_not_block_from_skin_tone_heuristic(self):
        result = self.engine.classify_image(solid(64, 64, SKIN))
        self.assertEqual(result.verdict, Verdict.REVIEW)
        self.assertEqual(result.decided_by, DecisionPath.UNKNOWN)
        self.assertFalse(result.should_block)

    def test_cascade_escalates_to_multimodal(self):
        # Force both cheaper stages to be inconclusive.
        for stage in (self.config.thresholds.fast_path, self.config.thresholds.deep_path):
            stage.hard_nsfw = 0.999
            stage.hard_sfw = -0.001
        engine = NsfwEngine(self.config)
        result = engine.classify_image(solid(64, 64, SKIN))
        self.assertEqual(result.decided_by, DecisionPath.UNKNOWN)
        self.assertEqual(len(result.stages), 3)
        self.assertEqual(
            [s.path for s in result.stages],
            [DecisionPath.FAST, DecisionPath.DEEP, DecisionPath.MULTIMODAL],
        )

    def test_threshold_override_forces_block(self):
        result = self.engine.classify_image(
            solid(64, 64, BLACK), overrides={"fast_hard_nsfw": 0.0}
        )
        self.assertEqual(result.verdict, Verdict.REVIEW)

    def test_fast_only_without_a_model_requests_review(self):
        self.config.engine.mode = "fast_only"
        engine = NsfwEngine(self.config)
        result = engine.classify_image(solid(64, 64, SKIN))
        self.assertEqual(result.verdict, Verdict.REVIEW)
        self.assertEqual(result.decided_by, DecisionPath.FAST)

    def test_dispatch_from_bytes(self):
        result = self.engine.classify(make_ppm(32, 32, BLACK))
        self.assertEqual(result.media_type, MediaType.IMAGE)
        self.assertEqual(result.verdict, Verdict.REVIEW)

    def test_dispatch_text_only(self):
        result = self.engine.classify(b"<html><body>free porn</body></html>", MediaType.HTML)
        self.assertEqual(result.decided_by, DecisionPath.TEXT)
        self.assertGreater(result.score, 0.0)

    def test_cache_separates_media_types_for_same_payload(self):
        payload = b"free porn"
        text_result = self.engine.classify(payload, MediaType.TEXT)
        image_result = self.engine.classify(payload, MediaType.UNKNOWN)

        self.assertEqual(text_result.decided_by, DecisionPath.TEXT)
        self.assertEqual(image_result.verdict, Verdict.UNKNOWN)
        self.assertFalse(image_result.from_cache)

    def test_cache_separates_contextual_signals(self):
        payload = make_ppm(32, 32, BLACK)
        self.engine.classify(payload, MediaType.IMAGE)

        contextual = self.engine.classify(
            payload, MediaType.IMAGE, text="porn", url="https://example.test/adult"
        )

        self.assertFalse(contextual.from_cache)
        self.assertIsNotNone(contextual.text)

    def test_invalid_image_reports_error(self):
        result = self.engine.classify(b"not an image")
        self.assertEqual(result.verdict, Verdict.UNKNOWN)
        self.assertTrue(result.error)

    def test_failed_classifications_are_not_cached(self):
        first = self.engine.classify(b"not an image")
        second = self.engine.classify(b"not an image")

        self.assertTrue(first.error)
        self.assertTrue(second.error)
        self.assertFalse(second.from_cache)
        self.assertEqual(self.engine.cache.snapshot()["size"], 0)

    def test_result_as_dict_is_serialisable(self):
        import json

        result = self.engine.classify_image(solid(16, 16, BLACK))
        payload = json.dumps(result.as_dict())
        self.assertIn("verdict", payload)

    def test_health_reports_stub_models(self):
        info = self.engine.health()
        self.assertIn("models_loaded", info)
        self.assertIn("version", info)
        self.assertFalse(info["healthy"])

    def test_configured_local_marqo_model_runs_when_present(self):
        config = load_config()
        model_path = config.model_path(config.paths.deep_path_model)
        if not model_path.is_file():
            self.skipTest("local ONNX artifacts are not installed")
        config.thresholds.fast_path.hard_sfw = -0.1
        config.thresholds.fast_path.hard_nsfw = 1.1
        config.thresholds.deep_path.hard_sfw = -0.1
        config.thresholds.deep_path.hard_nsfw = 1.1
        engine = NsfwEngine(config)
        self.assertFalse(engine.deep.is_stub)
        result = engine.classify_image(solid(32, 32, BLACK))
        deep = next(stage for stage in result.stages if stage.path == DecisionPath.DEEP)
        self.assertTrue(deep.executed)
        self.assertFalse(deep.fallback)
        self.assertEqual(deep.model, "marqo_nsfw_vit")
        self.assertTrue(np.isfinite(deep.score))
        self.assertEqual(result.verdict, Verdict.REVIEW)
        self.assertEqual(result.decided_by, DecisionPath.DEEP)
        multimodal = next(
            stage for stage in result.stages if stage.path == DecisionPath.MULTIMODAL
        )
        self.assertFalse(multimodal.executed)
        self.assertTrue(engine.health()["healthy"])
        from app.api.rest.v1 import ready

        readiness = ready(engine=engine)
        self.assertTrue(readiness.ready)
        self.assertTrue(readiness.checks["models_loaded"])


class VideoPipelineTests(unittest.TestCase):
    def setUp(self):
        self.engine = NsfwEngine(load_config())
        self.pipeline = self.engine.video_pipeline

    def test_sample_indices_respects_fps(self):
        indices = self.pipeline.sample_indices(100, fps=25.0)  # sample_fps=2 -> step 12
        self.assertGreater(len(indices), 0)
        self.assertEqual(indices[0], 0)
        self.assertLessEqual(len(indices), self.engine.config.video.max_frames)

    def test_sample_indices_handles_empty(self):
        self.assertEqual(self.pipeline.sample_indices(0, 25.0), [])

    def test_analyze_frames_picks_worst(self):
        frames = [solid(32, 32, BLACK), solid(32, 32, SKIN), solid(32, 32, BLACK)]
        def classify(frame, **kwargs):
            is_nsfw = tuple(frame[0, 0]) == SKIN
            return SimpleNamespace(
                verdict=Verdict.NSFW if is_nsfw else Verdict.SFW,
                score=1.0 if is_nsfw else 0.05,
                decided_by=DecisionPath.DEEP,
            )

        with patch.object(self.engine, "classify_image", side_effect=classify):
            result = self.pipeline.analyze_frames(frames, fps=2.0)
        self.assertEqual(result.verdict, Verdict.NSFW)
        self.assertEqual(result.worst_frame_index, 1)
        self.assertTrue(result.early_exit)

    def test_analyze_all_safe_frames(self):
        frames = [solid(32, 32, BLACK) for _ in range(5)]
        safe_frame = SimpleNamespace(
            verdict=Verdict.SFW, score=0.05, decided_by=DecisionPath.DEEP
        )
        with patch.object(self.engine, "classify_image", return_value=safe_frame):
            result = self.pipeline.analyze_frames(frames, fps=2.0)
        self.assertEqual(result.verdict, Verdict.SFW)
        self.assertFalse(result.early_exit)


if __name__ == "__main__":
    unittest.main(verbosity=2)
