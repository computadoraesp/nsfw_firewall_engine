"""Tests for scripts/fetch_pretrained.py (the §4 license gate).

huggingface_hub is optional, so the license gate is exercised against a fake
API. The point of these tests is that a source whose upstream license is not
the expected one must never be downloaded - that is the rule which keeps Nudita
(AGPL-3.0) and OpenNSFW2 (unclear weight terms) out of a commercial engine.
"""

import sys
import json
import tempfile
import types
import unittest
from unittest.mock import patch
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import fetch_pretrained as fp  # noqa: E402


class _FakeTorchModule:
    def __init__(self):
        pass

    def __call__(self, *args):
        return self.forward(*args)

    def eval(self):
        return self


class _FakeModel:
    def load_state_dict(self, state, strict):
        self.loaded_strictly = strict

    def __call__(self, pixel_values):
        return np.array([[8.0, 1.0]], dtype=np.float32)


class _FakeCardData:
    def __init__(self, license_value):
        self.license = license_value


class _FakeInfo:
    def __init__(self, license_value, sha="a" * 40):
        self.cardData = _FakeCardData(license_value)
        self.sha = sha


class _FakeApi:
    #: Set by the test before installing; the fake hub reads it at call time.
    license_value = "apache-2.0"

    def model_info(self, repo_id):
        return _FakeInfo(self.license_value)


class LicenseGateTests(unittest.TestCase):
    def setUp(self):
        self.original = fp._require_hub
        self.downloaded = []
        self.snapshot = tempfile.TemporaryDirectory()
        self.addCleanup(self._restore)
        self.addCleanup(self.snapshot.cleanup)

    def _restore(self):
        fp._require_hub = self.original

    def _install_api(self, license_value):
        def fake_download(repo_id, revision, cache_dir=None, allow_patterns=None):
            self.downloaded.append(
                {
                    "repo_id": repo_id,
                    "revision": revision,
                    "cache_dir": cache_dir,
                    "allow_patterns": allow_patterns,
                }
            )
            root = Path(self.snapshot.name)
            for name in allow_patterns or ():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("{}", encoding="utf-8")
            return root

        def fake_require_hub():
            # The production helper does `HfApi().model_info(...)`, so the fake
            # must return the *class*, not an instance. A per-test subclass
            # carries the license, so no state leaks between test methods.
            class _LicensedApi(_FakeApi):
                pass

            _LicensedApi.license_value = license_value
            return _LicensedApi, fake_download

        fp._require_hub = fake_require_hub
        return _FakeApi()

    def test_expected_license_passes(self):
        self._install_api("apache-2.0")
        source = fp.resolve("premium_vit")
        self.assertEqual(fp.check_license(source), "apache-2.0")
        self.assertEqual(self.downloaded, [])  # check only, no download

    def test_changed_upstream_license_is_refused(self):
        # If upstream relicenses to AGPL, the fetch must stop. This is the
        # failure mode that would otherwise poison a shipped artifact.
        self._install_api("agpl-3.0")
        with self.assertRaises(RuntimeError) as ctx:
            fp.download(fp.resolve("premium_vit"))
        self.assertIn("legal review", str(ctx.exception))
        self.assertEqual(self.downloaded, [])

    def test_missing_license_field_is_refused(self):
        self._install_api("")
        with self.assertRaises(RuntimeError):
            fp.check_license(fp.resolve("premium_vit"))

    def test_download_pins_revision_and_limits_files(self):
        self._install_api("apache-2.0")
        source = fp.resolve("premium_vit")
        result = fp.download(source)
        self.assertEqual(result, Path(self.snapshot.name))
        self.assertEqual(len(self.downloaded), 1)
        call = self.downloaded[0]
        self.assertEqual(call["revision"], "a" * 40)
        self.assertEqual(set(call["allow_patterns"]), set(source.files))
        self.assertNotIn("optimizer.pt", call["allow_patterns"])

    def test_license_change_prevents_snapshot_download(self):
        self._install_api("agpl-3.0")
        with self.assertRaises(RuntimeError):
            fp.download(fp.resolve("premium_vit"))
        self.assertEqual(self.downloaded, [])


class SourceTableTests(unittest.TestCase):
    def test_all_sources_are_license_cleared(self):
        # Only permissive licenses may be listed. Nudita (AGPL-3.0) must never
        # appear here: adding it would be the "route around §4" path that the
        # blocked lifecycle state exists to prevent.
        for key, source in fp.SOURCES.items():
            self.assertIn(
                source.expected_license,
                ("apache-2.0", "mit"),
                msg=f"{key} is not license-cleared",
            )

    def test_blocked_upstreams_are_absent(self):
        blob = " ".join(
            f"{s.repo_id} {s.artifact}".lower() for s in fp.SOURCES.values()
        )
        self.assertNotIn("nudita", blob)
        self.assertNotIn("opennsfw2", blob)

    def test_every_source_declares_at_least_two_classes(self):
        # Multi-class detectors are legitimate (safe/hentai/porn/sexy/drawing):
        # the engine sums the explicit indices the sidecar names. What must hold
        # is that no head is narrower than 2, because the runtime contract
        # reads index 1 as NSFW.
        for key, source in fp.SOURCES.items():
            self.assertGreaterEqual(
                len(source.labels), 2, msg=f"{key} has a head narrower than 2"
            )

    def test_every_source_has_a_safe_class(self):
        # Without a non-explicit class the detector would score ~1.0 on
        # everything: a broken artifact, not a strict one.
        from adapters.labels import classify_labels

        for key, source in fp.SOURCES.items():
            self.assertLess(
                len(classify_labels(source.labels)),
                len(source.labels),
                msg=f"{key} has no safe class",
            )

    def test_multiclass_fast_path_is_present(self):
        # The §45 fast path: a CNN whose class order the sidecar pins.
        source = fp.resolve("fast_efficientnet")
        self.assertEqual(source.loader, "transformers")
        self.assertEqual(source.input_size, 224)
        self.assertEqual(len(source.labels), 5)
        # Index 0 must be the safe class: the runtime's 2-class contract reads
        # index 1, and the sidecar's explicit set must exclude the safe class.
        self.assertEqual(source.labels[0].lower(), "safe")

    def test_marqo_labels_are_reordered_for_engine_contract(self):
        source = fp.resolve("premium_vit")
        self.assertEqual(source.checkpoint_labels, ("NSFW", "SFW"))
        self.assertEqual(source.labels, ("SFW", "NSFW"))
        self.assertEqual(fp._output_indices(source, source.checkpoint_labels), (1, 0))

    def test_config_label_order_must_match_reviewed_checkpoint(self):
        source = fp.resolve("premium_vit")
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text(
                json.dumps({"label_names": ["SFW", "NSFW"]}), encoding="utf-8"
            )
            with self.assertRaisesRegex(RuntimeError, "reviewed order"):
                fp._checkpoint_labels(source, Path(tmp))

    def test_timm_builder_loads_local_weights_and_reorders_logits(self):
        source = fp.resolve("premium_vit")
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = Path(tmp)
            (snapshot / "config.json").write_text(
                json.dumps({"label_names": ["NSFW", "SFW"]}), encoding="utf-8"
            )
            (snapshot / "model.safetensors").write_bytes(b"weights")
            model = _FakeModel()
            fake_timm = types.SimpleNamespace(
                create_model=lambda *args, **kwargs: model
            )
            fake_torch = types.SimpleNamespace(
                nn=types.SimpleNamespace(Module=_FakeTorchModule)
            )
            safe_package = types.ModuleType("safetensors")
            safe_package.__path__ = []
            safe_torch = types.ModuleType("safetensors.torch")
            safe_torch.load_file = lambda path, device: {"weight": path}
            with patch.dict(
                sys.modules,
                {
                    "torch": fake_torch,
                    "timm": fake_timm,
                    "safetensors": safe_package,
                    "safetensors.torch": safe_torch,
                },
            ):
                exported = fp.build_pytorch_module(source, snapshot)
                logits = exported(np.zeros((1, 3, 384, 384), dtype=np.float32))
            np.testing.assert_array_equal(logits, [[1.0, 8.0]])
            self.assertTrue(model.loaded_strictly)

    def test_export_writes_a_complete_sidecar_and_returns_provenance(self):
        from adapters.labels import load as load_sidecar
        from scripts import convert_to_onnx
        source = fp.resolve("premium_vit")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "snapshot"
            snapshot.mkdir()

            def fake_export(model, destination, **kwargs):
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"validated-onnx")
                self.assertEqual(kwargs["input_shape"], (1, 3, 384, 384))

            with (
                patch.object(fp, "_verified_repo_info", return_value=("apache-2.0", "b" * 40)),
                patch.object(fp, "_download_snapshot", return_value=snapshot),
                patch.object(fp, "build_pytorch_module", return_value=object()),
                patch.object(convert_to_onnx, "export", side_effect=fake_export),
            ):
                artifact, license_value, revision = fp.export_source(
                    source, output_dir=root / "out"
                )

            sidecar = load_sidecar(artifact)
            self.assertEqual(sidecar.labels, ("SFW", "NSFW"))
            self.assertEqual(sidecar.input_size, (384, 384))
            self.assertEqual(sidecar.positive_indices, (1,))
            self.assertEqual(sidecar.mean, (0.5, 0.5, 0.5))
            self.assertEqual(license_value, "apache-2.0")
            self.assertEqual(revision, "b" * 40)

    def test_resolve_rejects_unknown_key(self):
        with self.assertRaises(KeyError):
            fp.resolve("nudita")


class ProvenanceTests(unittest.TestCase):
    def test_record_carries_source_and_license(self):
        source = fp.resolve("premium_vit")
        record = fp.provenance_record(
            source,
            Path("models_onnx/vit_nsfw.onnx"),
            "apache-2.0",
            "a" * 40,
        )
        self.assertIn("Marqo/nsfw-image-detection-384", record)
        self.assertIn("apache-2.0", record)
        self.assertIn("a" * 40, record)
        self.assertIn("vit_nsfw.onnx", record)


class CliTests(unittest.TestCase):
    def test_model_choices_match_the_table(self):
        args = fp.parse_args(["--model", "premium_vit"])
        self.assertEqual(args.model, "premium_vit")
        self.assertFalse(args.dry_run)

    def test_dry_run_flag(self):
        self.assertTrue(fp.parse_args(["--model", "premium_vit", "--dry-run"]).dry_run)

    def test_unknown_model_is_rejected_by_argparse(self):
        with self.assertRaises(SystemExit):
            fp.parse_args(["--model", "nudita"])


if __name__ == "__main__":
    unittest.main()