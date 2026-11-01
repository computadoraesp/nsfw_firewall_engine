"""Tests for the label sidecar (adapters/labels.py).

The class order of an ONNX head is not encoded in the graph. These tests pin
the behavior that keeps a possibly-inverted 2-class detector from being
trusted: an absent sidecar is a normal state, a wrong or hostile one is an
error, and the explicit indices are always re-derived rather than read from the
file.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adapters import labels as L  # noqa: E402
from adapters.vision import HuggingFaceViTAdapter  # noqa: E402
from app.core.preprocessor import Preprocessor  # noqa: E402
from app.models.base import BaseEvaluator  # noqa: E402
from scripts import quantize_models as qm  # noqa: E402
from scripts import verify_models  # noqa: E402


class ClassifyLabelsTests(unittest.TestCase):
    def test_normal_nsfw(self):
        self.assertEqual(L.classify_labels(("normal", "nsfw")), (1,))

    def test_inverted_order_is_detected(self):
        # The whole point: {0: 'nsfw', 1: 'normal'} is the same tensor as the
        # normal ordering. Reading index 1 blindly would invert the detector.
        self.assertEqual(L.classify_labels(("nsfw", "normal")), (0,))

    def test_safe_synonyms(self):
        self.assertEqual(L.classify_labels(("safe", "pornographic")), (1,))

    def test_no_explicit_class(self):
        self.assertEqual(L.classify_labels(("cat", "dog")), ())

    def test_multi_class_explicit_indices(self):
        self.assertEqual(L.classify_labels(("porn", "hentai", "neutral")), (0, 1))


class SidecarPathTests(unittest.TestCase):
    def test_path_replaces_onnx_suffix(self):
        self.assertEqual(
            L.sidecar_path("models_onnx/vit_nsfw.onnx").name, "vit_nsfw.labels.json"
        )

    def test_path_for_non_onnx(self):
        self.assertEqual(L.sidecar_path("m.bin").name, "m.labels.json")


class BuildValidationTests(unittest.TestCase):
    def test_normal_nsfw_builds(self):
        sidecar = L.build(("normal", "nsfw"), (384, 384))
        self.assertEqual(sidecar.positive_indices, (1,))
        self.assertEqual(sidecar.input_size, (384, 384))

    def test_all_explicit_is_rejected(self):
        # Every class explicit == flag 100% of traffic. Must never build.
        with self.assertRaises(L.LabelSidecarError):
            L.build(("nsfw", "porn"))

    def test_no_explicit_is_rejected(self):
        with self.assertRaises(L.LabelSidecarError):
            L.build(("cat", "dog"))

    def test_empty_is_rejected(self):
        with self.assertRaises(L.LabelSidecarError):
            L.build(())

    def test_out_of_range_positive_index_is_rejected(self):
        with self.assertRaises(L.LabelSidecarError):
            L.LabelSidecar(labels=("a", "b"), positive_indices=(5,))

    def test_invalid_preprocessing_metadata_is_rejected(self):
        with self.assertRaises(L.LabelSidecarError):
            L.build(("normal", "nsfw"), mean=(0.5, 0.5), std=(0.5, 0.5, 0.5))
        with self.assertRaises(L.LabelSidecarError):
            L.build(("normal", "nsfw"), std=(0.5, 0.0, 0.5))
class RoundTripTests(unittest.TestCase):
    def test_write_then_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "m.onnx"
            artifact.write_bytes(b"x")
            L.write(artifact, L.build(("normal", "nsfw"), (384, 384)))
            loaded = L.load(artifact)
            self.assertEqual(loaded.labels, ("normal", "nsfw"))
            self.assertEqual(loaded.positive_indices, (1,))
            self.assertEqual(loaded.input_size, (384, 384))
            custom = L.build(
                ("normal", "nsfw"),
                (384, 384),
                mean=(0.5, 0.5, 0.5),
                std=(0.5, 0.5, 0.5),
            )
            L.write(artifact, custom)
            loaded = L.load(artifact)
            self.assertEqual(loaded.mean, (0.5, 0.5, 0.5))
            self.assertEqual(loaded.std, (0.5, 0.5, 0.5))

    def test_absent_sidecar_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(L.load(Path(tmp) / "missing.onnx"))


class EvaluatorPreprocessingTests(unittest.TestCase):
    def test_uses_sidecar_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "model.onnx"
            artifact.write_bytes(b"model")
            L.write(
                artifact,
                L.build(
                    ("safe", "nsfw"),
                    (2, 2),
                    mean=(0.5, 0.5, 0.5),
                    std=(0.5, 0.5, 0.5),
                ),
            )
            session = Mock()
            session.is_stub = False
            session.run.return_value = np.array([0.0, 1.0], dtype=np.float32)
            evaluator = BaseEvaluator(
                session=session,
                preprocessor=Preprocessor(),
                resize=(2, 2),
                timeout_ms=10,
                model_path=str(artifact),
            )

            evaluator.evaluate(np.full((2, 2, 3), 128, dtype=np.uint8))

            tensor = session.run.call_args.args[0]
            expected = (128 / 255.0 - 0.5) / 0.5
            self.assertAlmostEqual(float(tensor[0, 0, 0, 0]), expected, places=5)


class HostileSidecarTests(unittest.TestCase):
    """A tampered label file must fail loudly, not silently invert."""

    def _write(self, tmp, payload):
        (Path(tmp) / "m.labels.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
        return Path(tmp) / "m.onnx"

    def test_wrong_schema_version_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._write(tmp, {
                "schema_version": 99, "labels": ["normal", "nsfw"],
            })
            with self.assertRaises(L.LabelSidecarError):
                L.load(artifact)

    def test_malformed_json_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "m.labels.json").write_text("{not json", encoding="utf-8")
            with self.assertRaises(L.LabelSidecarError):
                L.load(Path(tmp) / "m.onnx")

    def test_non_object_sidecar_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "m.labels.json").write_text("[]", encoding="utf-8")
            with self.assertRaises(L.LabelSidecarError):
                L.load(Path(tmp) / "m.onnx")

    def test_hand_flipped_positive_indices_are_ignored(self):
        # Someone edits the file to mark index 0 (normal) as explicit. The
        # indices are re-derived from the label names, so the file's claim is
        # discarded rather than obeyed.
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._write(tmp, {
                "schema_version": 1,
                "labels": ["normal", "nsfw"],
                "input_size": [224, 224],
                "positive_indices": [0, 1],
            })
            self.assertEqual(L.load(artifact).positive_indices, (1,))

    def test_bad_input_size_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._write(tmp, {
                "schema_version": 1,
                "labels": ["normal", "nsfw"],
                "input_size": [224],
            })
            with self.assertRaises(L.LabelSidecarError):
                L.load(artifact)

    def test_all_explicit_sidecar_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._write(tmp, {
                "schema_version": 1,
                "labels": ["nsfw", "porn"],
                "input_size": [224, 224],
            })
            with self.assertRaises(L.LabelSidecarError):
                L.load(artifact)


class LockfileSidecarTests(unittest.TestCase):
    """The sidecar must be covered by the same integrity gate as the graph."""

    def _artifact(self, tmp, labels=("normal", "nsfw")):
        models = Path(tmp) / "models_onnx"
        models.mkdir(parents=True, exist_ok=True)
        artifact = models / "vit_nsfw.onnx"
        artifact.write_bytes(b"fake-onnx-graph")
        L.write(artifact, L.build(labels, (384, 384)))
        return models, artifact

    def test_sidecar_is_hashed_alongside_the_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            models, artifact = self._artifact(tmp)
            scanned = verify_models.scan_artifacts(models)
            sidecar_key = L.sidecar_path(artifact).name
            self.assertIn(artifact.name, scanned)
            self.assertIn(sidecar_key, scanned)
            self.assertEqual(scanned[sidecar_key]["role"], "label-sidecar")

    def test_tampered_sidecar_fails_the_gate(self):
        # Editing the class order must be as detectable as editing the weights:
        # otherwise an attacker could invert every decision with no model change.
        with tempfile.TemporaryDirectory() as tmp:
            models, artifact = self._artifact(tmp)
            lockfile = Path(tmp) / "models.lock.json"
            verify_models.write_lockfile(verify_models.scan_artifacts(models), lockfile)
            ok, _ = verify_models.verify(lockfile=lockfile, directory=models)
            self.assertTrue(ok)

            L.sidecar_path(artifact).write_text(
                json.dumps({
                    "schema_version": 1,
                    "labels": ["nsfw", "normal"],
                    "input_size": [224, 224],
                }),
                encoding="utf-8",
            )
            ok, messages = verify_models.verify(lockfile=lockfile, directory=models)
            self.assertFalse(ok)
            self.assertTrue(any("MISMATCH" in m for m in messages))

    def test_sidecar_without_graph_is_not_scanned(self):
        # A sidecar for an absent artifact is not itself an artifact.
        with tempfile.TemporaryDirectory() as tmp:
            models = Path(tmp) / "models_onnx"
            models.mkdir(parents=True, exist_ok=True)
            (models / "orphan.labels.json").write_text("{}", encoding="utf-8")
            self.assertEqual(verify_models.scan_artifacts(models), {})


class AdapterSidecarTests(unittest.TestCase):
    """The ViT adapter must map outputs through the sidecar, not through max()."""

    def _adapter(
        self,
        tmp,
        labels=("normal", "nsfw"),
        size=(384, 384),
        mean=(0.485, 0.456, 0.406),
        std=(0.229, 0.224, 0.225),
    ):
        models = Path(tmp) / "models_onnx"
        models.mkdir(parents=True, exist_ok=True)
        artifact = models / "vit_nsfw.onnx"
        artifact.write_bytes(b"fake")
        if labels is not None:
            L.write(artifact, L.build(labels, size, mean=mean, std=std))
        return HuggingFaceViTAdapter(model_path=str(artifact))

    def test_input_size_comes_from_the_sidecar(self):
        # The defect this closes: default_input_size is 224, which silently
        # degrades the 384px Marqo checkpoint it is meant to serve.
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._adapter(tmp, size=(384, 384))
            self.assertEqual(adapter.input_size, (384, 384))

    def test_224_sidecar_keeps_224(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._adapter(tmp, size=(224, 224))
            self.assertEqual(adapter.input_size, (224, 224))

    def test_explicit_indices_resolved_from_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._adapter(tmp, labels=("normal", "nsfw"))
            self.assertEqual(adapter.sidecar.positive_indices, (1,))

    def test_inverted_labels_resolve_to_index_zero(self):
        # {0: nsfw, 1: normal}: scoring index 1 would invert the detector.
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._adapter(tmp, labels=("nsfw", "normal"))
            self.assertEqual(adapter.sidecar.positive_indices, (0,))

    def test_missing_sidecar_leaves_the_adapter_undecided(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._adapter(tmp, labels=None)
            self.assertIsNone(adapter.sidecar)
            # Falls back to the class default rather than guessing.
            self.assertEqual(adapter.input_size, adapter.default_input_size)

    def test_broken_sidecar_leaves_the_adapter_undecided(self):
        # An all-explicit sidecar (every class explicit -> flag everything) is
        # rejected by build(), so it only exists if written by hand or by an
        # upstream export. The adapter must refuse it, not invent a class order.
        with tempfile.TemporaryDirectory() as tmp:
            models = Path(tmp) / "models_onnx"
            models.mkdir(parents=True, exist_ok=True)
            artifact = models / "vit_nsfw.onnx"
            artifact.write_bytes(b"fake")
            L.sidecar_path(artifact).write_text(
                json.dumps({
                    "schema_version": 1,
                    "labels": ["nsfw", "porn"],
                    "input_size": [224, 224],
                }),
                encoding="utf-8",
            )
            adapter = HuggingFaceViTAdapter(model_path=str(artifact))
            self.assertIsNone(adapter.sidecar)

    def test_width_mismatch_is_refused_at_predict_time(self):
        # The sidecar describes 2 classes; a graph emitting 3 means the file
        # does not describe this artifact, so no score may be produced.
        with tempfile.TemporaryDirectory() as tmp:
            models = Path(tmp) / "models_onnx"
            models.mkdir(parents=True, exist_ok=True)
            artifact = models / "vit_nsfw.onnx"
            artifact.write_bytes(b"fake")
            L.write(artifact, L.build(("normal", "nsfw"), (224, 224)))
            adapter = HuggingFaceViTAdapter(model_path=str(artifact))
            self.assertIsNone(adapter.sidecar_for_width(3))
            self.assertIsNotNone(adapter.sidecar_for_width(2))

    def test_preprocessing_uses_sidecar_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._adapter(
                tmp, mean=(0.5, 0.5, 0.5), std=(0.5, 0.5, 0.5)
            )
            tensor = adapter._to_tensor(np.full((4, 4, 3), 128, dtype=np.uint8))
            self.assertEqual(tensor.shape, (1, 3, 384, 384))
            np.testing.assert_allclose(
                tensor[0, :, 0, 0],
                np.full(3, (128 / 255.0 - 0.5) / 0.5),
                atol=1e-5,
            )

    def test_predict_softmaxes_logits_before_scoring_positive_label(self):
        class _Session:
            def run(self, tensor):
                return np.array([[0.0, 2.0]], dtype=np.float32)

        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._adapter(tmp, labels=("SFW", "NSFW"))
            adapter._session = _Session()
            adapter._to_tensor = lambda image: np.zeros((1, 3, 384, 384), dtype=np.float32)
            result = adapter.predict(np.zeros((4, 4, 3), dtype=np.uint8))
            self.assertIsNotNone(result)
            self.assertAlmostEqual(result.score, 1.0 / (1.0 + np.exp(-2.0)), places=6)

    def test_predict_refuses_non_finite_logits(self):
        class _Session:
            def run(self, tensor):
                return np.array([[0.0, np.nan]], dtype=np.float32)

        with tempfile.TemporaryDirectory() as tmp:
            adapter = self._adapter(tmp, labels=("SFW", "NSFW"))
            adapter._session = _Session()
            adapter._to_tensor = lambda image: np.zeros((1, 3, 384, 384), dtype=np.float32)
            self.assertIsNone(adapter.predict(np.zeros((4, 4, 3), dtype=np.uint8)))


class ExternalDataTests(unittest.TestCase):
    """A graph that stores its tensors in a sibling ``.onnx.data`` must pin both.

    Sealing only the graph would leave the 20 MB of actual weights unsealed -
    exactly the tamper surface the lockfile exists to close (§38).
    """

    def _artifact(self, tmp):
        models = Path(tmp) / "models_onnx"
        models.mkdir(parents=True, exist_ok=True)
        graph = models / "big.onnx"
        graph.write_bytes(b"graph-only")
        (models / "big.onnx.data").write_bytes(b"\x01" * 4096)
        return models, graph

    def test_external_data_is_hashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            models, graph = self._artifact(tmp)
            scanned = verify_models.scan_artifacts(models)
            data_key = graph.with_suffix(".onnx.data").name
            self.assertIn(data_key, scanned)
            self.assertEqual(scanned[data_key]["role"], "onnx-external-data")
            self.assertEqual(scanned[data_key]["of"], graph.name)

    def test_tampered_external_data_fails_the_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            models, graph = self._artifact(tmp)
            lockfile = Path(tmp) / "models.lock.json"
            verify_models.write_lockfile(
                verify_models.scan_artifacts(models), lockfile
            )
            graph.with_suffix(".onnx.data").write_bytes(b"\x02" * 4096)
            ok, messages = verify_models.verify(lockfile=lockfile, directory=models)
            self.assertFalse(ok)
            self.assertTrue(any("MISMATCH" in m for m in messages))

    def test_graph_without_external_data_is_unaffected(self):
        with tempfile.TemporaryDirectory() as tmp:
            models = Path(tmp) / "models_onnx"
            models.mkdir(parents=True, exist_ok=True)
            (models / "small.onnx").write_bytes(b"x")
            scanned = verify_models.scan_artifacts(models)
            self.assertEqual(list(scanned), ["small.onnx"])


class PrepareForQuantizationTests(unittest.TestCase):
    """quantize_dynamic's shape inference rejects stale value_info (§45 tooling).

    The export wrapper that reorders a classifier's outputs leaves a transposed
    ``[2, 192]`` annotation on the head weight. ``quantize_dynamic`` reads that
    as a shape constraint and aborts, so the annotation must be dropped first -
    it is inferred metadata, not a definition.
    """

    def _model(self, with_value_info):
        import onnx
        from onnx import TensorProto, helper

        node = helper.make_node("Identity", ["x"], ["y"])
        graph = helper.make_graph(
            [node], "g",
            [helper.make_tensor_value_info("x", TensorProto.FLOAT, [1, 2])],
            [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1, 2])],
        )
        model = helper.make_model(graph)
        if with_value_info:
            info = helper.make_tensor_value_info("x", TensorProto.FLOAT, [2, 192])
            model.graph.value_info.append(info)
        return model

    def test_value_info_is_stripped(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "m.onnx"
            import onnx

            onnx.save(self._model(True), str(source))
            self.assertTrue(len(onnx.load(str(source)).graph.value_info) > 0)

            prepared = qm._prepare_for_quantization(source)
            self.assertEqual(len(onnx.load(prepared).graph.value_info), 0)
            # The original is left untouched: it is the reviewed FP32 artifact.
            self.assertTrue(
                len(onnx.load(str(source)).graph.value_info) > 0
            )

    def test_prepared_copy_is_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "m.onnx"
            import onnx

            onnx.save(self._model(True), str(source))
            first = qm._prepare_for_quantization(source)
            marker = Path(first)
            marker.write_bytes(b"stale-marker")
            second = qm._prepare_for_quantization(source)
            self.assertEqual(first, second)
            self.assertEqual(Path(second).read_bytes(), b"stale-marker")

    def test_model_without_value_info_still_prepared(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "m.onnx"
            import onnx

            onnx.save(self._model(False), str(source))
            prepared = qm._prepare_for_quantization(source)
            self.assertTrue(Path(prepared).is_file())


class VerifyQuantizedTests(unittest.TestCase):
    """A quantized artifact that no runtime can load must never be shipped."""

    def test_unloadable_artifact_raises_and_is_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            dead = Path(tmp) / "dead.int8.onnx"
            dead.write_bytes(b"not really onnx")
            source = Path(tmp) / "m.onnx"
            source.write_bytes(b"x")
            with self.assertRaises(RuntimeError) as ctx:
                qm._verify_quantized(dead, source)
            self.assertIn("Do NOT deploy", str(ctx.exception))
            # The dead file must be gone, not left looking like a speedup.
            self.assertFalse(dead.exists())

    def test_quantized_path_naming(self):
        self.assertEqual(
            qm.quantized_path(Path("a/b.onnx")).name, "b.int8.onnx"
        )


class MultiClassScoringTests(unittest.TestCase):
    """A 5-class head must not be collapsed with to_probability's mean.

    This is the regression guard for a defect that shipped a perfect
    false-positive rate: summing per-class sigmoids over four explicit channels
    scored a *blank* image at 1.0, because the near-zero logits of a softmaxed
    classifier each map to ~0.5 under sigmoid.
    """

    def _evaluator(self, labels, size=(224, 224)):
        # Imported lazily: app.models.fast_path pulls in the engine package, which
        # imports this module's siblings - a top-level import would be circular.
        from app.models.fast_path import FastPathEvaluator

        with tempfile.TemporaryDirectory() as tmp:
            models = Path(tmp) / "models_onnx"
            models.mkdir(parents=True, exist_ok=True)
            artifact = models / "m.onnx"
            artifact.write_bytes(b"fake")
            L.write(artifact, L.build(labels, size))
            evaluator = FastPathEvaluator(
                session=None, preprocessor=None, resize=size, timeout_ms=10,
                model_path=str(artifact),
            )
            yield evaluator

    def test_blank_image_does_not_score_one(self):
        import numpy as np

        for evaluator in self._evaluator(("safe", "hentai", "porn", "sexy", "drawing")):
            # Near-zero logits are a softmaxed classifier's "no opinion". The
            # uniform distribution puts 0.2 in each channel, so the three
            # explicit classes sum to ~0.6. What matters is that it is nowhere
            # near 1.0: the pre-fix sigmoid path reported exactly 1.0 here and
            # would therefore have blocked every blank upload.
            score = evaluator._score_from_outputs(np.zeros(5, dtype=np.float32))
            self.assertLess(score, 0.7, "a blank image must not be flagged explicit")
            self.assertGreater(score, 0.0, "the uniform case should not be 0 either")

    def test_confident_porn_stays_high(self):
        import numpy as np

        for evaluator in self._evaluator(("safe", "hentai", "porn", "sexy", "drawing")):
            logits = np.full(5, -10.0, dtype=np.float32)
            logits[2] = 10.0  # "porn"
            score = evaluator._score_from_outputs(logits)
            self.assertGreater(score, 0.9, "a confident porn must not be diluted")

    def test_confident_safe_scores_zero(self):
        import numpy as np

        for evaluator in self._evaluator(("safe", "hentai", "porn", "sexy", "drawing")):
            logits = np.full(5, -10.0, dtype=np.float32)
            logits[0] = 10.0  # "safe"
            self.assertLess(evaluator._score_from_outputs(logits), 0.01)

    def test_drawing_is_not_counted_as_explicit(self):
        import numpy as np

        for evaluator in self._evaluator(("safe", "hentai", "porn", "sexy", "drawing")):
            logits = np.full(5, -10.0, dtype=np.float32)
            logits[4] = 10.0  # "drawing" - illustrative, not explicit
            self.assertLess(evaluator._score_from_outputs(logits), 0.01)

    def test_without_a_sidecar_it_falls_back_to_to_probability(self):
        import numpy as np

        from app.models.fast_path import FastPathEvaluator

        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "m.onnx"
            artifact.write_bytes(b"fake")
            evaluator = FastPathEvaluator(
                session=None, preprocessor=None, resize=(224, 224), timeout_ms=10,
                model_path=str(artifact),
            )
            self.assertIsNone(evaluator.sidecar)
            score = evaluator._score_from_outputs(np.zeros(2, dtype=np.float32))
            self.assertGreaterEqual(score, 0.0)


class SoftmaxTests(unittest.TestCase):
    def test_channels_sum_to_one(self):
        import numpy as np

        from app.core.onnx_runtime import softmax

        probs = softmax(np.array([1.0, 2.0, 3.0, 4.0, 5.0], dtype=np.float32))
        self.assertAlmostEqual(float(probs.sum()), 1.0, places=5)

    def test_is_finite_for_large_logits(self):
        import numpy as np

        from app.core.onnx_runtime import softmax

        probs = softmax(np.array([1000.0, 1001.0], dtype=np.float32))
        self.assertTrue(np.all(np.isfinite(probs)))
        self.assertAlmostEqual(float(probs.sum()), 1.0, places=5)


class _RecordingBackend:
    """No-op metrics backend so tests never touch the global registry."""

    def __init__(self):
        self.calls = 0

    def inc(self, *args, **kwargs):
        self.calls += 1

    def set(self, *args, **kwargs):
        self.calls += 1

    def observe(self, *args, **kwargs):
        self.calls += 1

    def render(self):
        return ""


class SyntheticEvaluationTests(unittest.TestCase):
    """The synthetic smoke evaluation must be honest about what it measures."""

    def setUp(self):
        # classify_image mutates global metrics and the decision cache; both
        # would otherwise leak into whatever runs next in this process (they
        # already made an unrelated policy test fail intermittently).
        from app.core import metrics

        self._saved_metrics = metrics._BACKEND
        self._saved_fallback = getattr(metrics, "_BACKEND", None)
        metrics._BACKEND = _RecordingBackend()

    def tearDown(self):
        from app.core import metrics

        if self._saved_fallback is not None:
            metrics._BACKEND = self._saved_fallback

    def _engine(self):
        from app.core.config import EngineConfig
        from app.core.engine import NsfwEngine

        config = EngineConfig()
        config.paths.fast_path_model = "models_onnx/__missing_fast__.onnx"
        config.paths.deep_path_model = "models_onnx/__missing_deep__.onnx"
        config.paths.multimodal_model = "models_onnx/__missing_multimodal__.onnx"
        # A fresh cache per engine: a shared one would make repeated calls
        # return the first image's decision.
        config.cache.enabled = False
        return NsfwEngine(config)

    def test_synthetic_set_is_balanced_and_labeled(self):
        from benchmarks.harness import synth_labeled_set

        images, labels = synth_labeled_set(positives=5, negatives=7)
        self.assertEqual(len(images), 12)
        self.assertEqual(len(labels), 12)
        self.assertEqual(sum(1 for v in labels if v), 5)

    def test_synthetic_set_is_deterministic(self):
        from benchmarks.harness import synth_labeled_set

        first, _ = synth_labeled_set(4, 4)
        second, _ = synth_labeled_set(4, 4)
        for a, b in zip(first, second):
            self.assertTrue((a == b).all())

    def test_report_is_labeled_as_not_a_quality_measurement(self):
        # §49: a synthetic set must never be mistaken for a §45 accuracy figure.
        from benchmarks.evaluate import evaluate_synthetic

        report = evaluate_synthetic(self._engine(), per_class=2)
        self.assertIn("NOT a quality measurement", report.dataset)

    def test_metrics_are_computed(self):
        from benchmarks.evaluate import evaluate_synthetic

        report = evaluate_synthetic(self._engine(), per_class=3)
        self.assertEqual(report.samples, 6)
        self.assertEqual(report.positives, 3)
        self.assertEqual(report.negatives, 3)
        self.assertEqual(report.roc_auc, 0.5)
        self.assertFalse(report.models_loaded)

    def test_default_threshold_yields_zero_recall(self):
        """Documents the §45 finding that the default threshold never fires.

        The stock ``fast_path.hard_nsfw`` of 0.85 was tuned for a 2-class head
        whose score was a single sigmoid. A 5-class softmax head never produces
        a score near 1.0, so at 0.85 the detector flags *nothing* and the
        firewall fails open. The test pins that fact so a threshold change is a
        deliberate, reviewed decision rather than a silent one.
        """
        from benchmarks.evaluate import evaluate_synthetic

        report = evaluate_synthetic(self._engine(), per_class=3)
        self.assertEqual(report.recall, 0.0)
        self.assertEqual(report.false_negative_rate, 1.0)

    def test_a_lower_threshold_recovers_recall_without_false_positives(self):
        from benchmarks.evaluate import evaluate_synthetic

        report = evaluate_synthetic(self._engine(), per_class=3, threshold=0.20)
        self.assertEqual(report.recall, 1.0)
        self.assertEqual(report.false_positive_rate, 1.0)

    def test_compute_counts_the_confusion_matrix(self):
        from benchmarks.evaluate import _compute

        report = _compute([0.9, 0.8, 0.1, 0.2], [True, True, False, False], 0.5)
        self.assertEqual(report.confusion(), {"tp": 2, "fp": 0, "tn": 2, "fn": 0})
        self.assertEqual(report.accuracy, 1.0)


class ShadowStoreTests(unittest.TestCase):
    """The shadow store must record scores without retaining content (§18)."""

    def _store(self, tmp):
        from benchmarks.evaluate import ShadowSampleStore

        return ShadowSampleStore(Path(tmp) / "shadow.jsonl")

    def test_record_never_stores_payload_bytes(self):
        import json

        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)
            store.record(0.7, "NSFW", "BLOCK", content_hash="abc", request_id="r1")
            entry = json.loads(store.path.read_text(encoding="utf-8").splitlines()[0])
            # The whole point: a score and a hash, never the image.
            self.assertNotIn("payload", entry)
            self.assertNotIn("data", entry)
            self.assertEqual(entry["content_hash"], "abc")
            self.assertEqual(entry["score"], 0.7)
            self.assertIsNone(entry["label"])

    def test_unlabeled_samples_are_excluded_from_a_fit(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)
            store.record(0.9, "NSFW")
            store.record(0.1, "SFW")
            self.assertEqual(store.stats()["pending"], 2)
            self.assertEqual(store.labeled(), ([], []))
            self.assertFalse(store.stats()["fit_ready"])

    def test_labeled_entries_are_returned(self):
        import json

        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)
            store.record(0.9, "NSFW")
            store.record(0.1, "SFW")
            lines = store.path.read_text(encoding="utf-8").splitlines()
            entries = [json.loads(line) for line in lines]
            entries[0]["label"] = True
            entries[1]["label"] = False
            store.path.write_text(
                "\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8"
            )
            scores, labels = store.labeled()
            self.assertEqual(scores, [0.9, 0.1])
            self.assertEqual(labels, [True, False])
            self.assertTrue(store.stats()["fit_ready"])

    def test_corrupt_line_does_not_hide_valid_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)
            store.record(0.5, "SFW")
            with store.path.open("a", encoding="utf-8") as handle:
                handle.write("{truncated write\n")
            store.record(0.6, "SFW")
            # A crash mid-append must not lose the samples that survived.
            self.assertEqual(len(store.load()), 2)

    def test_single_class_is_not_fit_ready(self):
        import json

        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)
            store.record(0.9, "NSFW")
            lines = store.path.read_text(encoding="utf-8").splitlines()
            entry = json.loads(lines[0])
            entry["label"] = True
            store.path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            stats = store.stats()
            self.assertFalse(stats["fit_ready"])
            self.assertEqual(stats["negatives"], 0)


class FitThresholdTests(unittest.TestCase):
    """The fitted threshold must honor the FPR cap it was given."""

    def test_separable_classes_give_a_usable_threshold(self):
        from scripts.fit_threshold import fit_threshold

        scores = [0.05, 0.10, 0.15, 0.20, 0.60, 0.70, 0.80, 0.90]
        labels = [False] * 4 + [True] * 4
        fitted = fit_threshold(scores, labels, max_fpr=0.0)
        # behavior, not the literal float: the reported threshold is rounded for
        # readability, but the confusion matrix must come from the exact value.
        # With max_fpr=0 not one negative may be admitted, and every positive
        # must still be caught.
        self.assertEqual(fitted["fp"], 0)
        self.assertEqual(fitted["false_positive_rate"], 0.0)
        self.assertEqual(fitted["recall"], 1.0)

    def test_fpr_cap_is_respected(self):
        from scripts.fit_threshold import fit_threshold

        # Negatives: 0.01 . 0.10. With max_fpr=0.25 only the top one may pass.
        scores = [0.01, 0.05, 0.08, 0.10, 0.70]
        labels = [False] * 4 + [True]
        fitted = fit_threshold(scores, labels, max_fpr=0.25)
        self.assertLessEqual(fitted["false_positive_rate"], 0.25)

    def test_one_class_is_refused(self):
        from scripts.fit_threshold import fit_threshold

        with self.assertRaises(ValueError) as ctx:
            fit_threshold([0.9, 0.8], [True, True], max_fpr=0.1)
        self.assertIn("one class", str(ctx.exception))

    def test_report_flags_non_separable_traffic(self):
        # When the classes overlap, no threshold works and the tool must say so
        # rather than emit a confident number (§49).
        import json

        from benchmarks.evaluate import ShadowSampleStore
        from scripts.fit_threshold import report

        with tempfile.TemporaryDirectory() as tmp:
            store = ShadowSampleStore(Path(tmp) / "s.jsonl")
            with store.path.open("w", encoding="utf-8") as handle:
                handle.write(json.dumps({"score": 0.5, "label": True}) + "\n")
                handle.write(json.dumps({"score": 0.5, "label": False}) + "\n")
            payload = report(store)
            self.assertFalse(payload["separable"])
            self.assertIn("overlap", payload["reason"])

    def test_cli_reports_instead_of_fitting_when_unlabeled(self):
        from scripts.fit_threshold import main

        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.jsonl"
            path.write_text("", encoding="utf-8")
            self.assertEqual(main(["--shadow", str(path)]), 0)


class PrometheusBackendRecordingTests(unittest.TestCase):
    """Regression guards for a metrics backend that recorded nothing at all.

    The native backend had no ``inc``/``set``/``observe``, and calling
    ``.labels()`` on an unlabeled gauge raises in prometheus_client. Both
    failures were swallowed by ``logger.debug`` in every ``record_*`` helper, so
    ``/metrics`` kept answering 200 with the HELP/TYPE headers and zero series.
    Silently-blind observability is worse than a crash: nobody notices until a
    dashboard has been quietly flat for a month.
    """

    def _backend(self):
        from app.core.metrics import _PrometheusBackend

        if not hasattr(_PrometheusBackend, "observe"):
            self.skipTest("prometheus_client not installed; fallback backend in use")
        return _PrometheusBackend()

    def test_backend_implements_the_recording_protocol(self):
        for method in ("inc", "set", "observe", "render"):
            self.assertTrue(callable(getattr(self._backend(), method, None)), method)

    def test_counter_is_recorded_with_labels(self):
        from app.core.metrics import N_REQUESTS

        backend = self._backend()
        backend.inc(N_REQUESTS, 1.0, tenant="acme", endpoint="/v1/inspect")
        self.assertIn('tenant="acme"', backend.render())

    def test_unlabeled_gauge_is_recorded(self):
        # The ValueError case: queue depth has no label names.
        from app.core.metrics import N_QUEUE_DEPTH

        backend = self._backend()
        backend.set(N_QUEUE_DEPTH, 4.0)
        self.assertIn("nsfw_queue_depth 4.0", backend.render())

    def test_labeled_gauge_is_recorded(self):
        from app.core.metrics import N_MODELS_LOADED

        backend = self._backend()
        backend.set(N_MODELS_LOADED, 3.0)
        self.assertIn("nsfw_models_loaded 3.0", backend.render())

    def test_histogram_emits_buckets(self):
        from app.core.metrics import N_STAGE_LATENCY

        backend = self._backend()
        backend.observe(N_STAGE_LATENCY, 0.005, path="FAST")
        rendered = backend.render()
        self.assertIn("nsfw_stage_latency_seconds_bucket", rendered)
        self.assertIn('path="FAST"', rendered)

    def test_unknown_metric_raises_instead_of_vanishing(self):
        from app.core.metrics import _PrometheusBackend

        backend = self._backend()
        with self.assertRaises(KeyError):
            backend.inc("nsfw_does_not_exist")

    def test_module_level_helpers_reach_the_backend(self):
        # End-to-end through the public API the rest of the engine uses.
        from app.core import metrics

        metrics.record_stage("FAST", 0.004)
        metrics.set_queue_depth(7)
        rendered = metrics.render_latest()
        self.assertIn("nsfw_stage_latency_seconds_bucket", rendered)
        self.assertIn("nsfw_queue_depth 7.0", rendered)


if __name__ == "__main__":
    unittest.main()