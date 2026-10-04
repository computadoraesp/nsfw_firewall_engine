"""Tests for latency budgets (§ timeouts), firewall modes (§30), model artifact
integrity (§4) and gRPC authentication parity (§16/§35).
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import (  # noqa: E402
    FirewallConfig,
    PolicyConfig,
    SecurityConfig,
    load_config,
)
from app.core.deadline import BudgetExceeded, Deadline, build_deadline  # noqa: E402
from app.core.engine import ClassificationResult, NsfwEngine  # noqa: E402
from app.core.policy import PolicyAction, PolicyEngine  # noqa: E402
from app.models.base import Verdict  # noqa: E402
from scripts import verify_models  # noqa: E402
from tests.test_engine import SKIN, solid  # noqa: E402


class DeadlineTests(unittest.TestCase):
    def test_fresh_deadline_has_remaining_budget(self):
        deadline = Deadline(budget_ms=100)
        self.assertFalse(deadline.expired)
        self.assertGreater(deadline.remaining_ms(), 0)

    def test_zero_budget_never_expires(self):
        deadline = Deadline(budget_ms=0)
        self.assertFalse(deadline.expired)
        self.assertEqual(deadline.remaining_ms(), float("inf"))

    def test_check_raises_once_spent(self):
        deadline = Deadline(budget_ms=100, started_at=time.perf_counter() - 1.0)
        self.assertTrue(deadline.expired)
        with self.assertRaises(BudgetExceeded):
            deadline.check("FAST")

    def test_stage_overrun_is_recorded(self):
        deadline = Deadline(budget_ms=1000, stage_budgets={"FAST": 10})
        self.assertTrue(deadline.check_stage("FAST", 25.0))
        self.assertTrue(deadline.timed_out)
        self.assertEqual(deadline.breached_at, "FAST")

    def test_stage_within_budget_is_not_a_breach(self):
        deadline = Deadline(budget_ms=1000, stage_budgets={"FAST": 10})
        self.assertFalse(deadline.check_stage("FAST", 5.0))
        self.assertFalse(deadline.timed_out)

    def test_request_expiry_is_recorded_even_without_stage_overrun(self):
        # Regression: the overall budget expiring must be *recorded*, not merely
        # detected, or timed_out stays False and policy never sees the failure.
        # The budget is pre-consumed deterministically instead of racing a timer.
        deadline = Deadline(
            budget_ms=1,
            stage_budgets={"FAST": 10_000},
            started_at=time.perf_counter() - 1.0,
        )
        deadline.check_stage("FAST", 5.0)  # comfortably inside its stage budget
        self.assertTrue(deadline.timed_out)
        self.assertTrue(deadline.expired)

    def test_stage_budgets_can_be_not_enforced_for_the_heuristic_fallback(self):
        # The per-stage budgets describe model SLOs; measuring the Python stub
        # against them must not raise a spurious breach.
        deadline = Deadline(
            budget_ms=100_000,
            stage_budgets={"FAST": 1},
            enforce_stage_budgets=False,
        )
        self.assertFalse(deadline.check_stage("FAST", 50.0))
        self.assertFalse(deadline.timed_out)

    def test_global_budget_still_applies_when_stage_budgets_are_off(self):
        deadline = Deadline(
            budget_ms=1,
            stage_budgets={"FAST": 10_000},
            enforce_stage_budgets=False,
            started_at=time.perf_counter() - 1.0,
        )
        self.assertTrue(deadline.check_stage("FAST", 5.0))
        self.assertTrue(deadline.timed_out)

    def test_as_dict_shape(self):
        payload = Deadline(budget_ms=50).as_dict()
        self.assertEqual(payload["budget_ms"], 50)
        self.assertFalse(payload["timed_out"])


class EngineDeadlineTests(unittest.TestCase):
    def _engine(self, budget_ms: int, fail_action: str = "ALLOW"):
        config = load_config()
        config.engine.request_timeout_ms = budget_ms
        config.policy.fail_action = fail_action
        return NsfwEngine(config)

    def test_generous_budget_does_not_trip(self):
        result = self._engine(250).classify_image(solid(32, 32, SKIN))
        self.assertFalse(result.timed_out)
        self.assertIsNone(result.deadline)

    def test_tiny_budget_marks_timeout(self):
        result = self._engine(1).classify_image(solid(32, 32, SKIN))
        self.assertTrue(result.timed_out)
        self.assertIsNotNone(result.deadline)
        self.assertIn("budget", result.error)

    def test_timeout_routes_through_fail_action(self):
        result = self._engine(1, fail_action="BLOCK").classify_image(solid(32, 32, SKIN))
        self.assertEqual(result.action, "BLOCK")

    def test_timeout_fail_open_by_default(self):
        result = self._engine(1).classify_image(solid(32, 32, SKIN))
        self.assertEqual(result.action, "ALLOW")

    def test_result_dict_exposes_timed_out(self):
        payload = self._engine(1).classify_image(solid(32, 32, SKIN)).as_dict()
        self.assertIn("timed_out", payload)
        self.assertTrue(payload["timed_out"])

    def test_build_deadline_reads_config(self):
        deadline = build_deadline(load_config())
        self.assertEqual(deadline.budget_ms, 250)
        self.assertIn("FAST", deadline.stage_budgets)
class FirewallModeTests(unittest.TestCase):
    def setUp(self):
        self.result = ClassificationResult(verdict=Verdict.NSFW, score=0.95)

    def test_enforcement_is_the_default(self):
        engine = PolicyEngine(PolicyConfig())
        self.assertEqual(engine.mode, "enforcement")
        decision = engine.decide(self.result)
        self.assertIs(decision.action, PolicyAction.BLOCK)
        self.assertEqual(decision.would_be_action, "")
        self.assertEqual(decision.mode, "enforcement")

    def test_audit_mode_never_blocks(self):
        engine = PolicyEngine(PolicyConfig(), FirewallConfig(mode="audit"))
        decision = engine.decide(self.result)
        self.assertIs(decision.action, PolicyAction.ALLOW)
        self.assertFalse(decision.is_blocking)

    def test_audit_mode_reports_would_be(self):
        engine = PolicyEngine(PolicyConfig(), FirewallConfig(mode="audit"))
        decision = engine.decide(self.result)
        self.assertEqual(decision.would_be_action, "BLOCK")
        self.assertIn("audit mode", decision.reason)

    def test_audit_mode_can_hide_would_be(self):
        engine = PolicyEngine(
            PolicyConfig(), FirewallConfig(mode="audit", report_would_be=False)
        )
        self.assertEqual(engine.decide(self.result).would_be_action, "")

    def test_audit_mode_still_classifies_and_scores(self):
        # Audit mode simulates *enforcement*; classification is untouched.
        config = load_config()
        config.firewall.mode = "audit"
        result = NsfwEngine(config).classify_image(solid(32, 32, SKIN))
        self.assertIs(result.verdict, Verdict.NSFW)
        self.assertEqual(result.action, "ALLOW")
        self.assertFalse(result.should_block)

    def test_audit_mode_reaches_the_enforce_adapter_as_allow(self):
        from app.services.enforcement import HttpEnforcementAdapter

        engine = PolicyEngine(PolicyConfig(), FirewallConfig(mode="audit"))
        response = HttpEnforcementAdapter(PolicyConfig()).response_for(
            engine.decide(self.result)
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.is_blocking)

    def test_invalid_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            FirewallConfig(mode="yolo")

    def test_health_reports_mode(self):
        self.assertEqual(NsfwEngine(load_config()).health()["firewall_mode"], "enforcement")


class ModelIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.lock = self.dir / "models.lock.json"
        self.artifact = self.dir / "model.onnx"

    def tearDown(self):
        self.tmp.cleanup()

    def _lock(self):
        verify_models.write_lockfile(verify_models.scan_artifacts(self.dir), self.lock)

    def test_sha256_matches_hashlib(self):
        self.artifact.write_bytes(b"abc")
        self.assertEqual(
            verify_models.sha256_file(self.artifact), hashlib.sha256(b"abc").hexdigest()
        )

    def test_verify_fails_closed_with_unvetted_artifact(self):
        """An artifact on disk with no lockfile is a failure: it is unvetted.

        Weights could be anything, including a model-poisoned substitute (§38),
        so the integrity gate must refuse to bless them implicitly.
        """
        self.artifact.write_bytes(b"unvetted")
        ok, messages = verify_models.verify(
            lockfile=self.dir / "absent.json", directory=self.dir
        )
        self.assertFalse(ok)
        self.assertIn("no lockfile", messages[0])

    def test_empty_models_dir_verifies_cleanly(self):
        """No artifacts and no lockfile is a legitimate state, not a failure.

        This repository ships no weights by design (§40 plus LEGAL_REVIEW_REQUIRED
        licences in §4). A permanently-red integrity gate trains operators to
        ignore it, which is worse than an honest green "nothing to verify".
        """
        ok, messages = verify_models.verify(
            lockfile=self.dir / "absent.json", directory=self.dir
        )
        self.assertTrue(ok)
        self.assertIn("heuristic fallback", messages[0])

    def test_require_all_rejects_an_empty_models_dir(self):
        """Production images must actually carry the weights they claim to run."""
        ok, messages = verify_models.verify(
            require_all=True, lockfile=self.dir / "absent.json", directory=self.dir
        )
        self.assertFalse(ok)
        self.assertIn("require-all", messages[0])

    def test_write_then_verify_passes(self):
        self.artifact.write_bytes(b"good")
        self._lock()
        ok, _ = verify_models.verify(lockfile=self.lock, directory=self.dir)
        self.assertTrue(ok)

    def test_tampering_is_detected(self):
        self.artifact.write_bytes(b"good")
        self._lock()
        self.artifact.write_bytes(b"tampered!!")
        ok, messages = verify_models.verify(lockfile=self.lock, directory=self.dir)
        self.assertFalse(ok)
        self.assertTrue(any("MISMATCH" in m for m in messages))

    def test_missing_artifact_is_detected(self):
        self.artifact.write_bytes(b"good")
        self._lock()
        self.artifact.unlink()
        ok, messages = verify_models.verify(lockfile=self.lock, directory=self.dir)
        self.assertFalse(ok)
        self.assertTrue(any("MISSING" in m for m in messages))

    def test_unvetted_artifact_is_flagged(self):
        # A side-loaded model absent from the lockfile must fail, not be ignored.
        self.artifact.write_bytes(b"good")
        self._lock()
        (self.dir / "sneaky.onnx").write_bytes(b"x")
        ok, messages = verify_models.verify(lockfile=self.lock, directory=self.dir)
        self.assertFalse(ok)
        self.assertTrue(any("UNVETTED" in m for m in messages))

    def test_lockfile_output_is_stable(self):
        self.artifact.write_bytes(b"good")
        self._lock()
        first = self.lock.read_text(encoding="utf-8")
        self._lock()
        self.assertEqual(first, self.lock.read_text(encoding="utf-8"))
class StubContext:
    """Minimal stand-in for a gRPC ServicerContext."""

    def __init__(self, metadata=None):
        self._metadata = metadata or []
        self.aborted = None

    def invocation_metadata(self):
        return self._metadata

    def abort(self, code, details):
        self.aborted = (code, details)
        raise RuntimeError(f"aborted {code}: {details}")


class GrpcAuthTests(unittest.TestCase):
    """gRPC authenticates with the same API keys as REST (§35 parity)."""

    def _engine(self, enabled: bool, role: str = "service_account"):
        config = load_config()
        config.security = SecurityConfig(
            enabled=enabled,
            hash_api_keys=True,
            api_keys={"svc": hashlib.sha256(b"topsecret").hexdigest()},
            key_roles={"svc": role},
        )
        return NsfwEngine(config)

    def test_disabled_auth_allows_everything(self):
        from app.api.grpc.handlers import authenticate

        self.assertIsNone(authenticate(StubContext(), self._engine(enabled=False)))

    def test_valid_key_passes(self):
        from app.api.grpc.handlers import authenticate

        context = StubContext([("x-api-key", "topsecret")])
        self.assertEqual(authenticate(context, self._engine(enabled=True)), "svc")

    def test_bearer_token_passes(self):
        from app.api.grpc.handlers import authenticate

        context = StubContext([("authorization", "Bearer topsecret")])
        self.assertEqual(authenticate(context, self._engine(enabled=True)), "svc")

    def test_missing_key_is_rejected(self):
        from app.api.grpc.handlers import _Unauthenticated, authenticate

        with self.assertRaises(_Unauthenticated):
            authenticate(StubContext(), self._engine(enabled=True))

    def test_wrong_key_is_rejected(self):
        from app.api.grpc.handlers import _Unauthenticated, authenticate

        context = StubContext([("x-api-key", "nope")])
        with self.assertRaises(_Unauthenticated):
            authenticate(context, self._engine(enabled=True))

    def test_role_without_classify_is_rejected(self):
        from app.api.grpc.handlers import _Unauthenticated, authenticate

        context = StubContext([("x-api-key", "topsecret")])
        engine = self._engine(enabled=True, role="read_only")
        with self.assertRaises(_Unauthenticated):
            authenticate(context, engine)


if __name__ == "__main__":
    unittest.main(verbosity=2)