"""Tests for the ONNX export tooling (scripts/convert_to_onnx.py).

torch/torchvision are optional build-time dependencies, so these tests never
import them: they assert the registry is wired, that the guards refuse the
mistakes that would otherwise ship a silently-wrong artifact (§49), and that
importing the script does not drag in torch.
"""

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import convert_to_onnx  # noqa: E402


class _FakeParameter(dict):
    pass


class _FakeModule:
    def __init__(self, name):
        self.name = name
        self.eval_called = False

    def eval(self):
        self.eval_called = True
        return self

    def load_state_dict(self, state, strict=True):
        if strict and set(state) != {"weight", "num_classes"}:
            raise RuntimeError("missing keys in state_dict")
        self.loaded = state
        return None


class _FakeModels:
    def __init__(self):
        self.calls = []

    def mobilenet_v3_small(self, num_classes=2):
        self.calls.append(("mobilenet_v3_small", num_classes))
        return _FakeModule("mobilenet_v3_small")

    def efficientnet_b0(self, num_classes=2):
        self.calls.append(("efficientnet_b0", num_classes))
        return _FakeModule("efficientnet_b0")

    def resnet50(self, num_classes=2):
        self.calls.append(("resnet50", num_classes))
        return _FakeModule("resnet50")


class _FakeTorch:
    def __init__(self):
        self.loaded = []

    def load(self, path, map_location=None, weights_only=False):
        self.loaded.append(path)
        return {"state_dict": {"weight": _FakeParameter(), "num_classes": 2}}


def _install_fakes():
    fake_tv = types.SimpleNamespace(models=_FakeModels())
    fake_torch = _FakeTorch()
    sys.modules["torchvision"] = fake_tv
    sys.modules["torch"] = fake_torch
    return fake_tv, fake_torch


def _remove_fakes():
    for name in ("torch", "torchvision"):
        sys.modules.pop(name, None)


class TestModelRegistry(unittest.TestCase):
    """Every configured stage must have a builder (§41)."""

    def test_every_default_input_shape_has_a_builder(self):
        # DEFAULT_INPUT_SHAPES is what --model accepts; a stage without a
        # builder would be selectable but would fail at export time.
        self.assertEqual(
            sorted(convert_to_onnx.DEFAULT_INPUT_SHAPES),
            sorted(convert_to_onnx.MODEL_REGISTRY),
        )

    def test_registry_is_not_empty(self):
        # This assertion is the regression guard for the original defect: the
        # registry shipped empty, so no model could ever be exported.
        self.assertTrue(convert_to_onnx.MODEL_REGISTRY)
        self.assertIn("fast_path", convert_to_onnx.MODEL_REGISTRY)

    def test_builders_build_two_class_heads(self):
        fake_tv, _ = _install_fakes()
        try:
            model = convert_to_onnx.MODEL_REGISTRY["fast_path"]()
        finally:
            _remove_fakes()
        self.assertEqual(fake_tv.models.calls, [("mobilenet_v3_small", 2)])
        self.assertEqual(convert_to_onnx.EXPECTED_NUM_CLASSES, 2)
        self.assertIsNotNone(model)

    def test_unknown_model_raises(self):
        with self.assertRaises(KeyError):
            convert_to_onnx.MODEL_REGISTRY["does_not_exist"]()
class TestCheckpointGuards(unittest.TestCase):
    """The guards that stop a random-weight artifact looking trained."""

    def setUp(self):
        self.fake_tv, self.fake_torch = _install_fakes()

    def tearDown(self):
        _remove_fakes()

    def test_export_without_checkpoint_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            convert_to_onnx.load_model("fast_path")
        self.assertIn("--allow-untrained", str(ctx.exception))

    def test_allow_untrained_permits_the_smoke_test(self):
        model = convert_to_onnx.load_model("fast_path", allow_untrained=True)
        self.assertTrue(model.eval_called)
        self.assertEqual(self.fake_torch.loaded, [])

    def test_missing_checkpoint_file_is_an_error(self):
        with self.assertRaises(FileNotFoundError):
            convert_to_onnx.load_model("fast_path", checkpoint="nope.pt")

    def test_checkpoint_is_loaded_strictly(self):
        # A real file must exist: the loader checks existence before reading it,
        # so a bogus path would fail on the wrong assertion.
        with tempfile.TemporaryDirectory() as tmp:
            checkpoint = Path(tmp) / "ckpt.pt"
            checkpoint.write_bytes(b"fake")
            model = convert_to_onnx.load_model("fast_path", checkpoint=str(checkpoint))
        # strict=True means a partially-matching state_dict raises inside
        # load_state_dict; assert the call is wired to read state["state_dict"].
        self.assertEqual(len(self.fake_torch.loaded), 1)
        self.assertEqual(set(model.loaded), {"weight", "num_classes"})

    def test_data_parallel_prefix_is_stripped_before_load(self):
        class _PrefixTorch(_FakeTorch):
            def load(self, path, map_location=None, weights_only=False):
                self.loaded.append(path)
                return {"module.weight": _FakeParameter(), "module.num_classes": 2}

        self.fake_torch.load = _PrefixTorch().load
        with tempfile.TemporaryDirectory() as tmp:
            checkpoint = Path(tmp) / "ckpt.pt"
            checkpoint.write_bytes(b"fake")
            model = convert_to_onnx.load_model("fast_path", checkpoint=str(checkpoint))
        self.assertEqual(set(model.loaded), {"weight", "num_classes"})


class TestPrefixStripping(unittest.TestCase):
    def test_strips_data_parallel_prefix(self):
        state = {"module.weight": 1, "module.bias": 2}
        self.assertEqual(
            set(convert_to_onnx._strip_prefixes(state)), {"weight", "bias"}
        )

    def test_strips_finetune_prefix(self):
        self.assertEqual(
            set(convert_to_onnx._strip_prefixes({"model.weight": 1})), {"weight"}
        )

    def test_leaves_clean_state_untouched(self):
        self.assertEqual(
            set(convert_to_onnx._strip_prefixes({"weight": 1})), {"weight"}
        )


class TestExport(unittest.TestCase):
    def test_export_embeds_weights_in_the_onnx_file(self):
        class FakeTorch:
            class export:
                @staticmethod
                def Dim(name):
                    return name

            @staticmethod
            def randn(*shape):
                return shape

            class onnx:
                calls = []

                @classmethod
                def export(cls, model, dummy, path, **kwargs):
                    cls.calls.append(kwargs)
                    Path(path).write_bytes(b"onnx")

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "model.onnx"
            with patch.object(convert_to_onnx, "_require_torch", return_value=FakeTorch):
                with patch.object(convert_to_onnx, "verify_export"):
                    convert_to_onnx.export(object(), output)

        self.assertEqual(FakeTorch.onnx.calls[0]["external_data"], False)
        self.assertEqual(
            FakeTorch.onnx.calls[0]["dynamic_shapes"],
            {"pixel_values": {0: "batch"}},
        )


class TestImportIsLazy(unittest.TestCase):
    def test_importing_the_script_does_not_import_torch(self):
        # CI byte-compiles and unit-tests the tooling without torch installed;
        # a top-level import would make that impossible.
        source = Path(convert_to_onnx.__file__).read_text(encoding="utf-8")
        top_level_imports = [
            line for line in source.splitlines()
            if line.startswith("import torch") or line.startswith("from torch")
        ]
        self.assertEqual(top_level_imports, [])


class TestCliArguments(unittest.TestCase):
    def test_allow_untrained_flag_defaults_off(self):
        args = convert_to_onnx.parse_args(
            ["--model", "fast_path", "--output", "out.onnx"]
        )
        self.assertFalse(args.allow_untrained)

    def test_cli_exits_non_zero_without_checkpoint(self):
        exit_code = convert_to_onnx.main(
            ["--model", "fast_path", "--output", "out.onnx"]
        )
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()