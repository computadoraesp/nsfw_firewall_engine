"""Tests for configuration integrity: the deprecated ``fail_mode`` alias, the
Redis decision-cache backend, tracing and log-level wiring.

These exist because a config audit found values that were declared but never
read - i.e. documentation that lied.
"""

from __future__ import annotations

import logging
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.cache import DecisionCache, _RedisStore  # noqa: E402
from app.core.config import CacheConfig, EngineConfig, load_config  # noqa: E402
from app.core.engine import ClassificationResult, NsfwEngine  # noqa: E402
from app.core.metrics import init_tracing, traced, tracing_status  # noqa: E402
from app.models.base import MediaType, Verdict  # noqa: E402
from tests.test_engine import SKIN, make_ppm, solid  # noqa: E402


class FailModeReconciliationTests(unittest.TestCase):
    """``engine.fail_mode`` and ``policy.fail_action`` must never diverge."""

    def test_conflict_is_reconciled_towards_policy(self):
        config = EngineConfig.model_validate(
            {"engine": {"fail_mode": "BLOCK"}, "policy": {"fail_action": "ALLOW"}}
        )
        # policy.fail_action is authoritative; the deprecated alias follows it.
        self.assertEqual(config.policy.fail_action, "ALLOW")
        self.assertEqual(config.engine.fail_mode, "ALLOW")

    def test_agreement_is_left_alone(self):
        config = EngineConfig.model_validate(
            {"engine": {"fail_mode": "BLOCK"}, "policy": {"fail_action": "BLOCK"}}
        )
        self.assertEqual(config.engine.fail_mode, "BLOCK")

    def test_shipped_config_is_consistent(self):
        config = load_config()
        self.assertEqual(config.engine.fail_mode, config.policy.fail_action)

    def test_only_fail_action_is_read_by_policy(self):
        # Regression: an operator setting only fail_mode must not silently
        # remain fail-open, because the rule engine reads fail_action.
        config = load_config()
        config.policy.fail_action = "BLOCK"
        decision = NsfwEngine(config).policy.decide(
            ClassificationResult(
                verdict=Verdict.SFW, score=0.0, error="boom",
                media_type=MediaType.IMAGE, decided_by="FAST",
            )
        )
        self.assertEqual(decision.action.value, "BLOCK")

    def test_error_rule_precedes_verdict_rules(self):
        # A failed classification must take fail_action, not the verdict action.
        config = load_config()
        config.policy.fail_action = "ALLOW"
        config.policy.nsfw_action = "BLOCK"
        decision = NsfwEngine(config).policy.decide(
            ClassificationResult(verdict=Verdict.NSFW, score=0.99, error="timeout")
        )
        self.assertEqual(decision.action.value, "ALLOW")

    def test_no_error_uses_verdict_action(self):
        decision = NsfwEngine(load_config()).policy.decide(
            ClassificationResult(verdict=Verdict.NSFW, score=0.99)
        )
        self.assertEqual(decision.action.value, "BLOCK")


class FakeRedis:
    """Minimal in-memory stand-in for the redis client."""

    def __init__(self):
        self.strings = {}
        self.lists = {}

    def get(self, key):
        return self.strings.get(key)

    def setex(self, key, ttl, value):
        self.strings[key] = value

    def delete(self, key):
        # Real Redis DEL also removes a list stored under the key.
        self.strings.pop(key, None)
        self.lists.pop(key, None)

    def llen(self, key):
        return len(self.lists.get(key, []))

    def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)

    def lrange(self, key, start, end):
        items = list(self.lists.get(key, []))
        return items[start:] if end == -1 else items[start : end + 1]

    def ltrim(self, key, start, end):
        self.lists[key] = self.lists.get(key, [])[start : end + 1]

    def lrem(self, key, count, value):
        self.lists[key] = [i for i in self.lists.get(key, []) if i != value]


class RedisStoreTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeRedis()
        self.store = _RedisStore(self.client, 60, 3, "nsfw:test")

    def test_roundtrip(self):
        self.store.put("k", {"verdict": "NSFW"})
        self.assertEqual(self.store.get("k"), {"verdict": "NSFW"})

    def test_missing_key(self):
        self.assertIsNone(self.store.get("absent"))

    def test_undecodable_entry_is_discarded(self):
        self.client.strings["k"] = "{not json"
        self.assertIsNone(self.store.get("k"))
        self.assertNotIn("k", self.client.strings)

    def test_delete_single_key(self):
        self.store.put("k", {"a": 1})
        self.store.delete("k")
        self.assertIsNone(self.store.get("k"))

    def test_clear_everything(self):
        self.store.put("k", {"a": 1})
        self.store.clear()
        self.assertEqual(self.store.size(), 0)

    def test_eviction_is_bounded(self):
        for index in range(6):
            self.store.put(f"k{index}", {"i": index})
        self.assertLessEqual(self.store.size(), 3)
class DecisionCacheBackendTests(unittest.TestCase):
    def _engine_without_models(self):
        config = load_config()
        config.paths.fast_path_model = "models_onnx/__missing_fast__.onnx"
        config.paths.deep_path_model = "models_onnx/__missing_deep__.onnx"
        config.paths.multimodal_model = "models_onnx/__missing_multimodal__.onnx"
        return NsfwEngine(config)

    def test_memory_is_the_default(self):
        cache = DecisionCache(CacheConfig(enabled=True))
        self.assertEqual(cache.backend, "memory")
        self.assertFalse(cache.distributed)

    def test_redis_without_client_falls_back_to_memory(self):
        # No NSFW_REDIS_URL set -> no client -> must degrade, not crash.
        cache = DecisionCache(CacheConfig(enabled=True, type="redis"))
        self.assertEqual(cache.backend, "memory")
        self.assertFalse(cache.distributed)

    def test_snapshot_reports_backend(self):
        snapshot = DecisionCache(CacheConfig(enabled=True)).snapshot()
        self.assertEqual(snapshot["backend"], "memory")
        self.assertFalse(snapshot["distributed"])

    def test_invalid_backend_is_rejected(self):
        with self.assertRaises(ValueError):
            CacheConfig(type="memcached")

    def test_cached_result_survives_a_dict_roundtrip(self):
        # The cache boundary is JSON-safe, so a serialized payload must rebuild
        # into an equivalent result (this is the Redis path). ``as_dict`` rounds
        # the score for transport, so compare with tolerance.
        engine = self._engine_without_models()
        original = engine.classify_image(solid(32, 32, SKIN))
        restored = engine._result_from_cache(original.as_dict())
        self.assertEqual(restored.verdict, original.verdict)
        self.assertEqual(restored.action, original.action)
        self.assertEqual(restored.decided_by, original.decided_by)
        self.assertAlmostEqual(restored.score, original.score, places=6)

    def test_corrupt_enum_degrades_to_unknown(self):
        engine = self._engine_without_models()
        restored = engine._result_from_cache(
            {"verdict": "NOT_A_VERDICT", "decided_by": "NOPE", "media_type": "???"}
        )
        self.assertEqual(restored.verdict.value, "UNKNOWN")
        self.assertEqual(restored.decided_by.value, "UNKNOWN")

    def test_second_identical_request_is_served_from_cache(self):
        engine = self._engine_without_models()
        payload = make_ppm(16, 16, SKIN)
        first = engine.classify(payload)
        second = engine.classify(payload)
        self.assertFalse(first.from_cache)
        self.assertTrue(second.from_cache)
        self.assertEqual(first.verdict, second.verdict)


class TracingTests(unittest.TestCase):
    def test_disabled_by_default(self):
        self.assertFalse(init_tracing(enabled=False))
        self.assertEqual(tracing_status()["backend"], "none")

    def test_status_shape(self):
        status = tracing_status()
        self.assertIn("enabled", status)
        self.assertIn("backend", status)

    def test_decorator_is_transparent_when_inactive(self):
        @traced("unit.test")
        def add(a, b):
            """docstring"""
            return a + b

        self.assertEqual(add(2, 3), 5)
        self.assertEqual(add.__doc__, "docstring")

    def test_requested_but_unavailable_degrades(self):
        # opentelemetry is absent here; requesting tracing must not raise.
        self.assertIsInstance(init_tracing(enabled=True), bool)

        @traced("unit.degraded")
        def double(value):
            return value * 2

        self.assertEqual(double(4), 8)

    def test_engine_health_reports_tracing(self):
        self.assertIn("tracing", NsfwEngine(load_config()).health())


class LoggingLevelTests(unittest.TestCase):
    def test_level_override_is_applied(self):
        from app.core.logging_setup import setup_logging

        previous = logging.getLogger("nsfw_engine").level
        try:
            setup_logging(level="ERROR")
            self.assertEqual(logging.getLogger("nsfw_engine").level, logging.ERROR)
        finally:
            logging.getLogger("nsfw_engine").setLevel(previous)

    def test_invalid_level_keeps_configured(self):
        from app.core.logging_setup import _apply_level

        before = logging.getLogger("nsfw_engine").level
        _apply_level("NOT_A_LEVEL")
        self.assertEqual(logging.getLogger("nsfw_engine").level, before)

    def test_configured_level_is_readable(self):
        self.assertIn(
            load_config().observability.log_level.upper(),
            {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)