"""Tests for the policy engine, cache, fusion, text path, enforcement adapters,
content inspector wiring and Prometheus metrics.

These cover the non-model parts of the platform (pront.md Sec. 16, 19, 29, 31)
and are written against the standard library so they run in minimal CI.
"""

from __future__ import annotations

import os
import sys
import time
import unittest

import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.cache import (  # noqa: E402
    PREPROCESS_VERSION,
    DecisionCache,
    cache_key,
    payload_hash,
)
from app.core.config import CacheConfig, PolicyConfig, load_config  # noqa: E402
from app.core.engine import ClassificationResult, NsfwEngine  # noqa: E402
from app.core.fusion import fuse_scores  # noqa: E402
from app.core.metrics import render_latest  # noqa: E402
from app.core.policy import PolicyAction, PolicyEngine  # noqa: E402
from app.models.base import MediaType, Verdict  # noqa: E402
from app.models.text_path import TextPathEvaluator  # noqa: E402
from app.services.content_inspector import inspect_payload  # noqa: E402
from policy.engine import (  # noqa: E402
    PolicyRegistry,
    default_policy,
    load_policy_file,
    policy_from_config,
    policy_from_dict,
)
from policy.models import Policy, Rule  # noqa: E402
from app.services.enforcement import (  # noqa: E402
    HttpEnforcementAdapter,
    IcapEnforcementAdapter,
    NginxEnforcementAdapter,
    get_adapter,
)
from app.services.text_analyzer import TextAnalyzer  # noqa: E402
from tests.test_engine import BLACK, SKIN, make_ppm, solid  # noqa: E402


def result(verdict=Verdict.SFW, score=0.1, error="", media_type=MediaType.IMAGE):
    return ClassificationResult(
        verdict=verdict, score=score, error=error, media_type=media_type
    )


class FusionTests(unittest.TestCase):
    def test_weighted_is_convex_combination(self):
        self.assertAlmostEqual(fuse_scores(0.8, 0.2, weight=0.25), 0.65, places=6)
        self.assertAlmostEqual(fuse_scores(0.8, 0.2, weight=0.5), 0.5, places=6)

    def test_none_text_returns_visual(self):
        self.assertEqual(fuse_scores(0.42, None), 0.42)

    def test_max_strategy(self):
        self.assertAlmostEqual(fuse_scores(0.2, 0.9, weight=0.3, strategy="max"), 0.9)

    def test_noisy_or_combines_evidence(self):
        fused = fuse_scores(0.5, 1.0, weight=1.0, strategy="noisy_or")
        self.assertAlmostEqual(fused, 1.0, places=6)
        self.assertGreater(fused, 0.5)

    def test_output_is_clamped(self):
        self.assertLessEqual(fuse_scores(2.0, 2.0, weight=1.0), 1.0)
        self.assertGreaterEqual(fuse_scores(-1.0, -1.0, weight=1.0), 0.0)

    def test_unknown_strategy_falls_back(self):
        self.assertAlmostEqual(
            fuse_scores(0.8, 0.2, weight=0.5, strategy="nope"), 0.5, places=6
        )

    def test_non_numeric_text_is_ignored(self):
        self.assertEqual(fuse_scores(0.3, "abc"), 0.3)


class PolicyEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = PolicyEngine(PolicyConfig())

    def test_nsfw_blocks(self):
        decision = self.engine.decide(result(Verdict.NSFW, 0.97))
        self.assertIs(decision.action, PolicyAction.BLOCK)
        self.assertTrue(decision.is_blocking)

    def test_sfw_allows(self):
        decision = self.engine.decide(result(Verdict.SFW, 0.01))
        self.assertIs(decision.action, PolicyAction.ALLOW)
        self.assertFalse(decision.is_blocking)

    def test_review_maps_to_review(self):
        decision = self.engine.decide(result(Verdict.REVIEW, 0.5))
        self.assertIs(decision.action, PolicyAction.REVIEW)
        self.assertFalse(decision.is_blocking)

    def test_error_falls_back_to_fail_action(self):
        decision = self.engine.decide(result(Verdict.UNKNOWN, 0.0, error="boom"))
        self.assertIs(decision.action, PolicyAction.ALLOW)
        self.assertIn("UNKNOWN", decision.reason)
        self.assertIn("ALLOW", decision.reason)

    def test_fail_closed(self):
        engine = PolicyEngine(PolicyConfig(fail_action="BLOCK"))
        decision = engine.decide(result(Verdict.UNKNOWN, 0.0, error="boom"))
        self.assertIs(decision.action, PolicyAction.BLOCK)

    def test_quarantine_action(self):
        engine = PolicyEngine(PolicyConfig(nsfw_action="QUARANTINE"))
        decision = engine.decide(result(Verdict.NSFW, 0.99))
        self.assertIs(decision.action, PolicyAction.QUARANTINE)
        self.assertTrue(decision.is_blocking)

    def test_tenant_override_changes_action(self):
        engine = PolicyEngine(
            PolicyConfig(tenant_overrides={"acme": {"nsfw": "QUARANTINE"}})
        )
        decision = engine.decide(result(Verdict.NSFW, 0.99), tenant_id="acme")
        self.assertIs(decision.action, PolicyAction.QUARANTINE)
        self.assertEqual(decision.tenant_id, "acme")
        self.assertIn("acme", decision.policy_id)

    def test_other_tenant_keeps_default(self):
        engine = PolicyEngine(
            PolicyConfig(tenant_overrides={"acme": {"nsfw": "QUARANTINE"}})
        )
        decision = engine.decide(result(Verdict.NSFW, 0.99), tenant_id="globex")
        self.assertIs(decision.action, PolicyAction.BLOCK)

    def test_decision_serialises(self):
        payload = self.engine.decide(result(Verdict.NSFW, 0.9)).as_dict()
        self.assertEqual(payload["action"], "BLOCK")
        self.assertTrue(payload["is_blocking"])
class CacheTests(unittest.TestCase):
    def test_put_and_get(self):
        cache = DecisionCache(CacheConfig(enabled=True, ttl_seconds=60))
        cache.put("k", {"v": 1})
        self.assertEqual(cache.get("k"), {"v": 1})

    def test_disabled_cache_never_stores(self):
        cache = DecisionCache(CacheConfig(enabled=False))
        cache.put("k", 1)
        self.assertIsNone(cache.get("k"))

    def test_expiry(self):
        cache = DecisionCache(CacheConfig(enabled=True, ttl_seconds=0.05))
        cache.put("k", 1)
        time.sleep(0.08)
        self.assertIsNone(cache.get("k"))

    def test_lru_eviction(self):
        cache = DecisionCache(CacheConfig(enabled=True, ttl_seconds=60, max_entries=2))
        for key in ("a", "b", "c"):
            cache.put(key, key)
        self.assertIsNone(cache.get("a"))
        self.assertEqual(cache.get("c"), "c")

    def test_stats(self):
        cache = DecisionCache(CacheConfig(enabled=True))
        cache.put("k", 1)
        cache.get("k")
        cache.get("missing")
        snapshot = cache.snapshot()
        self.assertEqual(snapshot["hits"], 1)
        self.assertEqual(snapshot["misses"], 1)

    def test_key_changes_with_model_version(self):
        digest = payload_hash(b"abc")
        self.assertNotEqual(cache_key(digest, "1.0.0"), cache_key(digest, "2.0.0"))
        self.assertIn(PREPROCESS_VERSION, cache_key(digest, "1.0.0"))

    def test_salt_changes_hash(self):
        self.assertNotEqual(payload_hash(b"abc", "s1"), payload_hash(b"abc", "s2"))

    def test_get_or_compute_runs_producer_once(self):
        cache = DecisionCache(CacheConfig(enabled=True))
        calls = []

        def producer():
            calls.append(1)
            return "v"

        value, cached = cache.get_or_compute("k", producer)
        self.assertFalse(cached)
        value2, cached2 = cache.get_or_compute("k", producer)
        self.assertTrue(cached2)
        self.assertEqual(value2, "v")
        self.assertEqual(len(calls), 1)

    def test_invalidate(self):
        cache = DecisionCache(CacheConfig(enabled=True))
        cache.put("k", 1)
        cache.invalidate("k")
        self.assertIsNone(cache.get("k"))


class TextPathTests(unittest.TestCase):
    """The DistilBERT adapter and its keyword-signal fallback (Sec. 41)."""

    class _FakeSession:
        """Minimal stand-in for an onnxruntime InferenceSession."""

        def __init__(self, logit=3.0):
            self.logit = logit
            self.calls = []

        def run(self, _outputs, inputs):
            self.calls.append({k: v.shape for k, v in inputs.items()})
            return [np.array([[self.logit]], dtype=np.float32)]

    def test_is_stub_without_model(self):
        from app.core.onnx_runtime import LoadedSession

        evaluator = TextPathEvaluator(
            LoadedSession(name="text", session=None, is_stub=True), TextAnalyzer()
        )
        self.assertTrue(evaluator.is_stub)

    def test_is_stub_without_tokenizer(self):
        from app.core.onnx_runtime import LoadedSession

        fake = self._FakeSession()
        loaded = LoadedSession(name="text", session=fake, is_stub=False)
        evaluator = TextPathEvaluator(loaded, TextAnalyzer(), tokenizer=None)
        self.assertTrue(evaluator.is_stub)

    def test_falls_back_to_keyword_signal(self):
        from app.core.onnx_runtime import LoadedSession

        loaded = LoadedSession(name="text", session=None, is_stub=True)
        evaluator = TextPathEvaluator(loaded, TextAnalyzer())
        stage = evaluator.evaluate("free porn videos")
        self.assertTrue(stage.fallback)
        self.assertGreater(stage.score, 0.0)
        self.assertEqual(stage.path.value, "TEXT")

    def test_uses_onnx_session_when_available(self):
        from app.core.onnx_runtime import LoadedSession

        fake = self._FakeSession(logit=4.0)
        loaded = LoadedSession(name="text", session=fake, is_stub=False)
        evaluator = TextPathEvaluator(
            loaded, TextAnalyzer(), tokenizer=lambda text: [101, 2050, 102]
        )
        stage = evaluator.evaluate("porn")
        self.assertFalse(stage.fallback)
        self.assertGreater(stage.score, 0.9)
        # Both inputs are supplied and shaped (1, seq_len).
        self.assertEqual(sorted(fake.calls[0]), ["attention_mask", "input_ids"])
        self.assertEqual(fake.calls[0]["input_ids"], (1, 3))

    def test_broken_tokenizer_falls_back(self):
        from app.core.onnx_runtime import LoadedSession

        fake = self._FakeSession()

        def bad_tokenizer(_text):
            raise RuntimeError("no vocab")

        loaded = LoadedSession(name="text", session=fake, is_stub=False)
        evaluator = TextPathEvaluator(loaded, TextAnalyzer(), tokenizer=bad_tokenizer)
        stage = evaluator.evaluate("porn")
        self.assertTrue(stage.fallback)
        self.assertGreater(stage.score, 0.0)

    def test_score_is_clamped(self):
        from app.core.onnx_runtime import LoadedSession

        fake = self._FakeSession(logit=500.0)
        loaded = LoadedSession(name="text", session=fake, is_stub=False)
        evaluator = TextPathEvaluator(
            loaded, TextAnalyzer(), tokenizer=lambda text: [1, 2]
        )
        self.assertLessEqual(evaluator.evaluate("x").score, 1.0)
class EnforcementAdapterTests(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyEngine(PolicyConfig())
        self.config = PolicyConfig()

    def test_http_allow_passthrough(self):
        decision = self.policy.decide(result(Verdict.SFW, 0.01))
        response = HttpEnforcementAdapter(self.config).response_for(decision)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, b"")

    def test_http_block_response(self):
        decision = self.policy.decide(result(Verdict.NSFW, 0.97))
        response = HttpEnforcementAdapter(self.config).response_for(decision)
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"403 Forbidden", response.body)
        self.assertEqual(response.headers["X-NSFW-Verdict"], "blocked")
        self.assertTrue(response.is_blocking)

    def test_http_quarantine_status(self):
        engine = PolicyEngine(PolicyConfig(nsfw_action="QUARANTINE"))
        decision = engine.decide(result(Verdict.NSFW, 0.99))
        response = HttpEnforcementAdapter(self.config).response_for(decision)
        self.assertEqual(response.status_code, 451)

    def test_block_page_escapes_values(self):
        engine = PolicyEngine(PolicyConfig(default_policy_id="<script>"))
        decision = engine.decide(result(Verdict.NSFW, 0.9))
        response = HttpEnforcementAdapter(self.config).response_for(decision)
        self.assertNotIn(b"<script>", response.body)
        self.assertIn(b"&lt;script&gt;", response.body)

    def test_icap_block_and_allow(self):
        adapter = IcapEnforcementAdapter(self.config, "nsfw-firewall")
        blocked = adapter.response_bytes(self.policy.decide(result(Verdict.NSFW, 0.9)))
        allowed = adapter.response_bytes(self.policy.decide(result(Verdict.SFW, 0.0)))
        self.assertIn(b"ICAP/1.0 200 OK", blocked)
        self.assertIn(b"403 Forbidden", blocked)
        self.assertIn(b"ICAP/1.0 204 No Content", allowed)

    def test_nginx_snippet(self):
        adapter = NginxEnforcementAdapter(self.config)
        snippet = adapter.render(self.policy.decide(result(Verdict.NSFW, 0.9)))
        self.assertIn("return 403", snippet)
        allow = adapter.render(self.policy.decide(result(Verdict.SFW, 0.0)))
        self.assertIn("pass through", allow)

    def test_get_adapter_unknown(self):
        with self.assertRaises(ValueError):
            get_adapter("nope", self.config)


class ContentInspectorTests(unittest.TestCase):
    """The REST-layer security gate (Sec. 16 / 17)."""

    def test_inspection_provides_audit_hash(self):
        report = inspect_payload(b"hello world")
        self.assertEqual(len(report["sha256"]), 64)
        self.assertEqual(report["size_bytes"], 11)

    def test_empty_payload_returns_none(self):
        self.assertIsNone(inspect_payload(b""))

    def test_oversize_payload_is_invalid(self):
        report = inspect_payload(b"x" * 100, max_bytes=10)
        self.assertFalse(report["valid"])

    def test_mime_is_advisory_when_not_enforced(self):
        # A PPM is not in the allow-list; with enforce_mime=False it stays valid
        # so the classification endpoints keep working.
        report = inspect_payload(make_ppm(4, 4, SKIN), enforce_mime=False)
        self.assertFalse(report["allowed"])
        self.assertTrue(report["valid"])

    def test_router_rejects_oversize(self):
        from fastapi import HTTPException
        from app.api.rest.router import _secure_inspect

        config = load_config()
        with self.assertRaises(HTTPException) as ctx:
            _secure_inspect(b"x" * (config.preprocessing.max_image_bytes + 1), config)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_router_accepts_normal_payload(self):
        from app.api.rest.router import _secure_inspect

        config = load_config()
        report = _secure_inspect(make_ppm(8, 8, SKIN), config)
        self.assertTrue(report["valid"])
        self.assertEqual(len(report["sha256"]), 64)


class RuleEngineTests(unittest.TestCase):
    """The rule engine in the top-level ``policy`` package (Sec. 19)."""

    def test_numeric_operator(self):
        rule = Rule("score", ">=", 0.8, "block")
        self.assertTrue(rule.evaluate({"score": 0.9}))
        self.assertFalse(rule.evaluate({"score": 0.5}))

    def test_string_equality_is_case_insensitive(self):
        self.assertTrue(Rule("verdict", "==", "nsfw", "block").evaluate({"verdict": "NSFW"}))

    def test_membership_operator(self):
        rule = Rule("media_type", "in", ["TEXT", "HTML"], "review")
        self.assertTrue(rule.evaluate({"media_type": "html"}))
        self.assertFalse(rule.evaluate({"media_type": "IMAGE"}))

    def test_dotted_path_lookup(self):
        self.assertTrue(Rule("text.score", ">=", 0.5, "review").evaluate({"text": {"score": 0.6}}))

    def test_regex_operator(self):
        rule = Rule("url", "matches", r"^https://", "block")
        self.assertTrue(rule.evaluate({"url": "https://example.test/a.png"}))
        self.assertFalse(rule.evaluate({"url": "ftp://example.test/a.png"}))

    def test_missing_field_does_not_match(self):
        self.assertFalse(Rule("score", ">=", 0.5, "block").evaluate({}))

    def test_first_match_wins(self):
        policy = Policy(
            policy_id="p",
            rules=[
                Rule("score", ">=", 0.9, "block", "high"),
                Rule("score", ">=", 0.1, "review", "any"),
            ],
            default_action="allow",
        )
        decision = policy.evaluate({"score": 0.95})
        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.matched_rule.description, "high")

    def test_default_action_when_nothing_matches(self):
        policy = Policy(policy_id="p", rules=[Rule("score", ">=", 0.9, "block")])
        decision = policy.evaluate({"score": 0.1})
        self.assertEqual(decision.action, "review")
        self.assertIsNone(decision.matched_rule)

    def test_decision_records_audit_metadata(self):
        policy = Policy(policy_id="p", rules=[Rule("score", ">=", 0.1, "block", "note")])
        payload = policy.evaluate({"score": 0.5}).as_dict()
        self.assertEqual(payload["metadata"]["rule_description"], "note")
        self.assertTrue(payload["is_blocking"])

    def test_malformed_rules_are_skipped(self):
        policy = policy_from_dict(
            {
                "policy_id": "p",
                "rules": [{"operator": "==", "value": 1, "action": "block"}, {"field": "score", "value": 1}],
                "default_action": "allow",
            }
        )
        # The rule missing "field" is dropped, the other is kept.
        self.assertEqual(len(policy.rules), 1)

    def test_load_policy_file_json(self):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "policy_id": "file-policy",
                        "default_action": "allow",
                        "rules": [{"field": "score", "operator": ">=", "value": 0.7, "action": "block"}],
                    }
                ),
                encoding="utf-8",
            )
            loaded = load_policy_file(path)
        self.assertEqual(loaded.policy_id, "file-policy")
        self.assertEqual(loaded.evaluate({"score": 0.8}).action, "block")

    def test_tenant_registry_prefers_tenant_policy(self):
        registry = PolicyRegistry(default_policy())
        registry.add_tenant_rules("acme", [{"field": "verdict", "operator": "==", "value": "NSFW", "action": "quarantine"}])
        self.assertEqual(registry.evaluate({"verdict": "NSFW"}, tenant_id="acme").action, "quarantine")
        self.assertEqual(registry.evaluate({"verdict": "NSFW"}, tenant_id="globex").action, "block")

    def test_tenant_default_keeps_global_action(self):
        registry = PolicyRegistry(default_policy())
        registry.add_tenant_rules("acme", [{"field": "score", "operator": ">=", "value": 0.99, "action": "block"}])
        # An unmatched tenant context must not silently become "allow".
        self.assertEqual(registry.evaluate({"score": 0.1}, tenant_id="acme").action, "review")

    def test_bridge_delegates_to_rule_engine(self):
        # The adapter's verdict mapping must agree with the rule engine.
        engine = PolicyEngine(PolicyConfig())
        decision = engine.decide(result(Verdict.NSFW, 0.95))
        expected = PolicyRegistry(policy_from_config(PolicyConfig())).evaluate(
            {"verdict": "NSFW", "score": 0.95}
        )
        self.assertEqual(decision.action.value, expected.action.upper())


class MetricsTests(unittest.TestCase):
    def test_exposition_is_valid_text(self):
        from app.core import metrics

        metrics.record_classification("NSFW", "BLOCK", 0.01, 0.9)
        metrics.record_stage("FAST", 0.005)
        metrics.set_models_loaded(2)
        metrics.record_cache(hits=1, misses=1, size=3)
        rendered = render_latest()
        self.assertIn("nsfw_classifications_total", rendered)
        self.assertIn("nsfw_stage_latency_seconds_bucket", rendered)
        self.assertIn("nsfw_models_loaded", rendered)

    def test_backend_flag_is_bool(self):
        from app.core import metrics

        self.assertIsInstance(metrics.PROMETHEUS_NATIVE, bool)


class EngineIntegrationTests(unittest.TestCase):
    """Engine now emits an action, policy id, cache behaviour and metrics."""

    def setUp(self):
        self.config = load_config()
        self.engine = NsfwEngine(self.config)

    def test_result_carries_policy_fields(self):
        outcome = self.engine.classify_image(solid(32, 32, SKIN))
        self.assertEqual(outcome.action, "BLOCK")
        self.assertTrue(outcome.policy_id)
        self.assertTrue(outcome.should_block)

    def test_safe_result_allows(self):
        outcome = self.engine.classify_image(solid(32, 32, BLACK))
        self.assertEqual(outcome.action, "ALLOW")
        self.assertFalse(outcome.should_block)

    def test_fail_closed_blocks_errors(self):
        self.config.policy.fail_action = "BLOCK"
        engine = NsfwEngine(self.config)
        outcome = engine.classify(b"not an image at all")
        self.assertTrue(outcome.error)
        self.assertEqual(outcome.action, "BLOCK")

    def test_cache_serves_second_identical_request(self):
        payload = make_ppm(16, 16, BLACK)
        first = self.engine.classify(payload)
        second = self.engine.classify(payload)
        self.assertFalse(first.from_cache)
        self.assertTrue(second.from_cache)
        self.assertEqual(first.verdict, second.verdict)

    def test_overrides_bypass_cache(self):
        payload = make_ppm(16, 16, BLACK)
        self.engine.classify(payload)
        forced = self.engine.classify(payload, overrides={"fast_hard_nsfw": 0.0})
        self.assertFalse(forced.from_cache)
        self.assertEqual(forced.verdict, Verdict.NSFW)

    def test_health_reports_cache_and_policy(self):
        info = self.engine.health()
        self.assertIn("cache", info)
        self.assertIn("policy", info)
        self.assertIn("text_model_loaded", info)
        self.assertIn("uptime_seconds", info)

    def test_text_fuses_into_multimodal(self):
        outcome = self.engine.classify_image(solid(32, 32, BLACK), text="free porn")
        self.assertTrue(any(stage.path.value == "TEXT" for stage in outcome.stages))

    def test_result_dict_includes_new_fields(self):
        payload = self.engine.classify_image(solid(16, 16, BLACK)).as_dict()
        for key in ("action", "policy_id", "from_cache"):
            self.assertIn(key, payload)


class RestSurfaceTests(unittest.TestCase):
    def test_routes_are_registered(self):
        from app.api.rest.router import create_app

        paths = {route.path for route in create_app().routes if hasattr(route, "path")}
        for expected in ("/health", "/metrics", "/enforce", "/classify"):
            self.assertIn(expected, paths)


if __name__ == "__main__":
    unittest.main(verbosity=2)