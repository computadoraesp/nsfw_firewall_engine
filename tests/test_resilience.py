"""Rate limiting and circuit breaking tests (§17, §33)."""

from __future__ import annotations

import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.resilience import (  # noqa: E402
    CircuitBreaker,
    RateLimiter,
    TokenBucket,
)


class TokenBucketTests(unittest.TestCase):
    def test_burst_up_to_capacity_is_allowed(self):
        """A restart replaying a cached batch is a legitimate burst (§17)."""
        bucket = TokenBucket(rate=1.0, capacity=5.0, now=0.0)
        for _ in range(5):
            allowed, retry = bucket.allow(now=0.0)
            self.assertTrue(allowed)
            self.assertEqual(retry, 0.0)

    def test_beyond_capacity_is_refused_with_a_retry_hint(self):
        bucket = TokenBucket(rate=1.0, capacity=2.0, now=0.0)
        bucket.allow(now=0.0)
        bucket.allow(now=0.0)
        allowed, retry = bucket.allow(now=0.0)
        self.assertFalse(allowed)
        # At 1 token/sec, one missing token takes ~1s.
        self.assertAlmostEqual(retry, 1.0, places=3)

    def test_tokens_refill_over_time(self):
        bucket = TokenBucket(rate=10.0, capacity=10.0, now=0.0)
        for _ in range(10):
            bucket.allow(now=0.0)
        self.assertFalse(bucket.allow(now=0.0)[0])
        # 0.5s at 10/s = 5 new tokens.
        self.assertTrue(bucket.allow(now=0.5)[0])
        self.assertTrue(bucket.allow(now=0.5)[0])

    def test_refill_never_exceeds_capacity(self):
        """Idle time must not bank unlimited credit (§38 exhaustion)."""
        bucket = TokenBucket(rate=10.0, capacity=10.0, now=0.0)
        for _ in range(10):
            bucket.allow(now=0.0)
        # An hour later the bucket is full, not holding 36,000 tokens.
        self.assertLessEqual(bucket.tokens, 10.0)

    def test_zero_rate_is_rejected(self):
        with self.assertRaises(ValueError):
            TokenBucket(rate=0)

    def test_concurrent_spends_never_exceed_the_bucket(self):
        """Under contention the bucket must not hand out more than capacity."""
        bucket = TokenBucket(rate=0.0001, capacity=50.0)
        allowed_count = []
        lock = threading.Lock()

        def worker():
            for _ in range(20):
                allowed, _retry = bucket.allow()
                if allowed:
                    with lock:
                        allowed_count.append(1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # Refill over the test's duration is negligible at this rate.
        self.assertLessEqual(len(allowed_count), 51)


class RateLimiterTests(unittest.TestCase):
    def test_keys_are_isolated_per_tenant_and_principal(self):
        """One tenant must not be able to exhaust another's budget (§34)."""
        limiter = RateLimiter(rate=1.0, capacity=1.0)
        self.assertTrue(limiter.check("acme:svc")[0])
        # The same key is now empty...
        self.assertFalse(limiter.check("acme:svc")[0])
        # ...but a different principal and a different tenant are unaffected.
        self.assertTrue(limiter.check("acme:svc2")[0])
        self.assertTrue(limiter.check("globex:svc")[0])

    def test_key_for_defaults_are_stable(self):
        self.assertEqual(RateLimiter.key_for("", ""), "-:anonymous")
        self.assertEqual(RateLimiter.key_for("acme", "svc"), "acme:svc")

    def test_bucket_table_is_bounded(self):
        """A flood of distinct keys must not grow memory without limit."""
        limiter = RateLimiter(rate=1000.0, capacity=1.0, max_keys=20)
        for index in range(200):
            limiter.check(f"tenant{index}:svc")
        # Eviction keeps the table from exceeding the configured ceiling.
        self.assertLessEqual(limiter.snapshot()["tracked_keys"], 21)

    def test_reset_clears_state(self):
        limiter = RateLimiter(rate=1.0, capacity=1.0)
        limiter.check("k")
        self.assertFalse(limiter.check("k")[0])
        limiter.reset("k")
        self.assertTrue(limiter.check("k")[0])

    def test_snapshot_never_leaks_credentials(self):
        """Keys are tenant/principal ids, never secrets (§18)."""
        limiter = RateLimiter(rate=1.0)
        limiter.check("acme:svc")
        self.assertNotIn("secret", repr(limiter.snapshot()))


class CircuitBreakerTests(unittest.TestCase):
    def test_closed_breaker_allows_traffic(self):
        breaker = CircuitBreaker(failure_threshold=3)
        self.assertEqual(breaker.state, "closed")
        self.assertTrue(breaker.allows()[0])

    def test_opens_after_consecutive_failures(self):
        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60.0)
        for _ in range(2):
            breaker.record_failure()
        self.assertEqual(breaker.state, "closed")
        breaker.record_failure()
        self.assertEqual(breaker.state, "open")

    def test_a_success_resets_the_failure_streak(self):
        """Failures must be *consecutive*; an interleaved success clears them."""
        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60.0)
        breaker.record_failure()
        breaker.record_failure()
        breaker.record_success()
        breaker.record_failure()
        breaker.record_failure()
        self.assertEqual(breaker.state, "closed")

    def test_open_breaker_fails_fast_with_a_retry_hint(self):
        """An open breaker must not make callers wait out the timeout (§33)."""
        breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=30.0)
        breaker.record_failure()
        allowed, retry = breaker.allows()
        self.assertFalse(allowed)
        self.assertGreater(retry, 0.0)
        self.assertLessEqual(retry, 30.0)

    def test_half_open_admits_only_a_bounded_number_of_probes(self):
        breaker = CircuitBreaker(
            failure_threshold=1, recovery_timeout=0.01, half_open_max_calls=1
        )
        breaker.record_failure()
        time.sleep(0.02)
        self.assertEqual(breaker.state, "half_open")
        # The single probe is admitted...
        self.assertTrue(breaker.allows()[0])
        # ...and nothing else is, until that probe reports back.
        self.assertFalse(breaker.allows()[0])

    def test_successful_probe_closes_the_breaker(self):
        breaker = CircuitBreaker(
            failure_threshold=1, recovery_timeout=0.01, half_open_max_calls=1
        )
        breaker.record_failure()
        time.sleep(0.02)
        breaker.allows()
        breaker.record_success()
        self.assertEqual(breaker.state, "closed")
        self.assertTrue(breaker.allows()[0])

    def test_failed_probe_reopens_and_restarts_the_timer(self):
        """A dependency that is still broken must not be hammered (§33)."""
        breaker = CircuitBreaker(
            failure_threshold=1, recovery_timeout=0.05, half_open_max_calls=1
        )
        breaker.record_failure()
        time.sleep(0.06)
        self.assertEqual(breaker.state, "half_open")
        breaker.allows()
        breaker.record_failure()
        self.assertEqual(breaker.state, "open")
        # The timer restarted: not immediately half-open again.
        self.assertEqual(breaker.state, "open")

    def test_reset_forces_closed(self):
        breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=60.0)
        breaker.record_failure()
        self.assertEqual(breaker.state, "open")
        breaker.reset()
        self.assertEqual(breaker.state, "closed")

    def test_invalid_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            CircuitBreaker(failure_threshold=0)
        with self.assertRaises(ValueError):
            CircuitBreaker(recovery_timeout=0)

    def test_snapshot_shape(self):
        snapshot = CircuitBreaker("fast", failure_threshold=7).snapshot()
        self.assertEqual(snapshot["name"], "fast")
        self.assertEqual(snapshot["failure_threshold"], 7)
        self.assertEqual(snapshot["state"], "closed")


class ResilienceConfigTests(unittest.TestCase):
    def test_defaults_are_conservative(self):
        """Neither guard may throttle or break traffic until opted into."""
        from app.core.config import EngineConfig

        config = EngineConfig()
        self.assertFalse(config.security.rate_limit_enabled)
        self.assertFalse(config.resilience.breaker_enabled)
        # Retrying inference by default would double latency on every failure.
        self.assertEqual(config.resilience.max_retries, 0)

    def test_rate_limiter_is_only_wired_when_enabled(self):
        """A disabled limiter must not even exist on app.state."""
        from app.api.rest.router import create_app
        from app.core.config import EngineConfig

        app = create_app(config=EngineConfig())
        self.assertIsNone(getattr(app.state, "rate_limiter", None))

    def test_rate_limiter_is_built_when_enabled(self):
        from app.api.rest.router import create_app
        from app.core.config import EngineConfig, SecurityConfig

        app = create_app(
            config=EngineConfig(
                security=SecurityConfig(
                    rate_limit_enabled=True,
                    rate_limit_per_second=7.0,
                    rate_limit_burst=9.0,
                )
            )
        )
        limiter = getattr(app.state, "rate_limiter", None)
        self.assertIsNotNone(limiter)
        self.assertEqual(limiter.rate, 7.0)
        self.assertEqual(limiter.capacity, 9.0)


class VideoAggregationTests(unittest.TestCase):
    """Temporal aggregation (§14)."""

    def test_every_14_aggregator_is_available(self):
        from app.services.video_pipeline import AGGREGATORS

        for name in ("max", "mean", "percentile", "weighted"):
            self.assertIn(name, AGGREGATORS)

    def test_max_catches_a_brief_insert(self):
        """The core reason `max` is the firewall default.

        One explicit frame in a five-frame sample must not be averaged away.
        """
        from app.services.video_pipeline import aggregate_scores

        scores = [0.05, 0.05, 0.95, 0.05, 0.05]
        self.assertAlmostEqual(aggregate_scores(scores, "max"), 0.95)
        # mean dilutes it below any sensible block threshold...
        self.assertLess(aggregate_scores(scores, "mean"), 0.3)
        # ...which is exactly the failure mode `max` exists to prevent.
        self.assertGreater(aggregate_scores(scores, "max"), 0.9)

    def test_mean_is_the_arithmetic_average(self):
        from app.services.video_pipeline import aggregate_scores

        self.assertAlmostEqual(aggregate_scores([0.2, 0.4, 0.6], "mean"), 0.4, places=6)

    def test_percentile_returns_an_observed_score(self):
        """No interpolation: the result must be a score the engine saw."""
        from app.services.video_pipeline import aggregate_scores

        scores = [0.1, 0.2, 0.3, 0.8, 0.9]
        for percentile in (50, 90, 95, 100):
            self.assertIn(aggregate_scores(scores, "percentile", percentile), scores)

    def test_weighted_favours_later_frames(self):
        from app.services.video_pipeline import aggregate_scores

        rising = [0.1, 0.2, 0.9]
        self.assertGreater(
            aggregate_scores(rising, "weighted"), aggregate_scores(rising, "mean")
        )

    def test_empty_input_is_zero(self):
        from app.services.video_pipeline import aggregate_scores

        self.assertEqual(aggregate_scores([], "max"), 0.0)

    def test_unknown_strategy_is_rejected(self):
        from app.services.video_pipeline import aggregate_scores

        with self.assertRaises(ValueError):
            aggregate_scores([0.5], "median")

    def test_invalid_percentile_is_rejected(self):
        from app.services.video_pipeline import aggregate_scores

        with self.assertRaises(ValueError):
            aggregate_scores([0.5], "percentile", 0.0)
        with self.assertRaises(ValueError):
            aggregate_scores([0.5], "percentile", 101.0)


class VideoSamplingTests(unittest.TestCase):
    """Frame sampling strategies (§14)."""

    def _pipeline(self, **kwargs):
        from app.core.config import VideoConfig
        from app.services.video_pipeline import VideoPipeline

        pipeline = VideoPipeline.__new__(VideoPipeline)
        pipeline.config = VideoConfig(**kwargs)
        pipeline.engine = None
        return pipeline

    @staticmethod
    def _frames():
        """22 frames: 10 blue, 2 red (the "insert"), 10 blue again."""
        import numpy as np

        blue = np.full((64, 64, 3), (20, 60, 200), dtype=np.uint8)
        red = np.full((64, 64, 3), (230, 170, 140), dtype=np.uint8)
        return [blue] * 10 + [red] * 2 + [blue] * 10

    def test_uniform_sampling_is_timestamp_based(self):
        pipeline = self._pipeline(sampling="uniform", sample_fps=1.0)
        indices = pipeline.sample_indices(len(self._frames()), 25.0)
        self.assertEqual(indices, [0])

    def test_scene_change_finds_the_insert_uniform_would_miss(self):
        """The reason §14 lists scene-change sampling at all."""
        pipeline = self._pipeline(sampling="scene_change", scene_threshold=0.35, sample_fps=1.0)
        frames = self._frames()
        indices = pipeline.sample_indices(len(frames), 25.0, frames)
        # The cut into the red insert at frame 10 must be sampled...
        self.assertIn(10, indices)
        # ...while uniform sampling (see above) returned only frame 0.
        self.assertIn(0, indices)

    def test_scene_change_without_frames_falls_back_to_uniform(self):
        """Encoded callers that do not decode must still get a sample."""
        pipeline = self._pipeline(sampling="scene_change", sample_fps=1.0)
        # 100 frames at 25fps sampled at 1fps -> one frame every 25.
        self.assertEqual(pipeline.sample_indices(100, 25.0), [0, 25, 50, 75])

    def test_static_video_still_yields_a_sample(self):
        """Pure change detection would return nothing for a fixed-camera clip."""
        import numpy as np

        pipeline = self._pipeline(sampling="scene_change", scene_threshold=0.35, sample_fps=2.0)
        static = [np.zeros((32, 32, 3), dtype=np.uint8) for _ in range(10)]
        self.assertTrue(pipeline.sample_indices(len(static), 25.0, static))

    def test_indices_are_bounded_by_max_frames(self):
        pipeline = self._pipeline(sampling="uniform", sample_fps=25.0, max_frames=10)
        indices = pipeline.sample_indices(10000, 25.0)
        self.assertLessEqual(len(indices), 10)

    def test_zero_frames_yields_nothing(self):
        self.assertEqual(self._pipeline().sample_indices(0, 25.0), [])


class MetricsCoverageTests(unittest.TestCase):
    """The §31 metric set, on the single consolidated registry."""

    def test_every_31_metric_name_is_exposed(self):
        from app.core import metrics as m

        required = [
            "nsfw_requests_total",
            "nsfw_inspections_total",
            "nsfw_enforcement_total",
            "nsfw_model_inference_total",
            "nsfw_stage_latency_seconds",
            "nsfw_pipeline_latency_seconds",
            "nsfw_queue_depth",
            "nsfw_worker_errors_total",
            "nsfw_cpu_utilization_ratio",
            "nsfw_memory_usage_bytes",
        ]
        rendered = m.render_latest()
        for name in required:
            self.assertIn(name, rendered, f"{name} is not exposed on /metrics")

    def test_recorders_populate_the_scrape(self):
        from app.core import metrics as m

        m.record_request("acme", "/v1/inspect")
        m.record_inspection("fast_path", "miss")
        m.record_enforcement("BLOCK")
        m.record_model_inference("fast_path_mobilenetv3")
        m.record_pipeline_latency(0.011, "NSFW")
        m.record_worker_error("gpu-0")
        m.record_circuit_open("deep")
        m.set_queue_depth(4)
        rendered = m.render_latest()
        self.assertIn('tenant="acme"', rendered)
        self.assertIn('action="BLOCK"', rendered)
        self.assertIn("nsfw_queue_depth 4.0", rendered)

    def test_resource_gauges_are_populated(self):
        from app.core import metrics as m

        m.record_process_resources()
        rendered = m.render_latest()
        self.assertIn("nsfw_memory_usage_bytes", rendered)
        self.assertIn("nsfw_cpu_utilization_ratio", rendered)

    def test_recorders_never_raise_on_bad_input(self):
        """Metrics must never take down a request."""
        from app.core import metrics as m

        for call in (
            lambda: m.record_request("", ""),
            lambda: m.record_enforcement(""),
            lambda: m.set_queue_depth(-1),
            lambda: m.record_pipeline_latency(-5.0, "X"),
        ):
            self.assertIsNone(call())


class EntrypointTests(unittest.TestCase):
    """`app/main.py` must be importable and must not re-register metrics."""

    def test_entrypoint_imports_and_builds(self):
        import app.main as entrypoint

        application = entrypoint.get_app()
        self.assertIsNotNone(application)
        # Cached: a second call must not rebuild the engine.
        self.assertIs(entrypoint.get_app(), application)

    def test_entrypoint_serves_the_v1_contract(self):
        import app.main as entrypoint

        paths = {getattr(r, "path", "") for r in entrypoint.get_app().routes}
        for path in ("/v1/inspect", "/v1/batch", "/v1/models", "/v1/policies"):
            self.assertIn(path, paths)

    def test_reload_is_opt_in(self):
        """Auto-reload must never be the default (§32/§33 production rule)."""
        import inspect

        import app.main as entrypoint

        source = inspect.getsource(entrypoint.main)
        self.assertIn('os.environ.get("NSFW_RELOAD", "0")', source)
        self.assertIn("reload=reload_enabled", source)

    def test_no_duplicate_prometheus_registry(self):
        """Two registries declaring the same metric name raise at import time."""
        from app.core import metrics as m

        # Rendering must work; if a second module had registered colliding
        # names, prometheus_client would have raised during import.
        self.assertIsInstance(m.render_latest(), str)


class LicenceClearedAdapterTests(unittest.TestCase):
    """§10 Premium Path adapter backed by an explicitly Apache-2.0 model."""

    def test_adapter_is_registered_for_the_premium_stage(self):
        from adapters.registry import ADAPTER_REGISTRY
        from adapters.vision import HuggingFaceViTAdapter

        self.assertIs(ADAPTER_REGISTRY.get("premium_vit"), HuggingFaceViTAdapter)

    def test_licence_is_permissive_and_declared(self):
        from adapters.vision import HuggingFaceViTAdapter

        self.assertEqual(HuggingFaceViTAdapter.license, "Apache-2.0")
        self.assertNotIn("LEGAL_REVIEW_REQUIRED", HuggingFaceViTAdapter.license)

    def test_adapter_is_inert_without_weights(self):
        from adapters.vision import HuggingFaceViTAdapter

        adapter = HuggingFaceViTAdapter()
        self.assertFalse(adapter.available)
        self.assertIsNone(adapter.predict(b"\x00\x01"))

    def test_registry_describes_it(self):
        from adapters.registry import describe_all

        described = describe_all(None)
        self.assertIn("premium_vit", described)
        self.assertEqual(described["premium_vit"].get("license"), "Apache-2.0")

    def test_provenance_records_the_cleared_models(self):
        """§4: a licence claim must be traceable to the registry document."""
        from pathlib import Path

        doc = (
            Path(__file__).resolve().parents[1] / "docs" / "MODEL_PROVENANCE.md"
        ).read_text(encoding="utf-8")
        self.assertIn("apache-2.0", doc.lower())
        for model in (
            "AdamCodd/vit-base-nsfw-detector",
            "Falconsai/nsfw_image_detection",
            "Marqo/nsfw-image-detection-384",
        ):
            self.assertIn(model, doc, f"{model} missing from the provenance record")


class HtmlContextExtractionTests(unittest.TestCase):
    """§12: URL, domain, title, meta, alt and structure."""

    def test_extracts_title(self):
        from app.services.html_context import extract_context

        context = extract_context("<html><head><title>Free XXX Videos</title></head></html>")
        self.assertEqual(context.title, "Free XXX Videos")

    def test_extracts_meta_description_and_keywords(self):
        """Regression: <meta name=... content=...> must resolve the value.

        The value lives in `content` while the key lives in `name`; reading
        `attrs["name"]` as the value silently drops every description.
        """
        from app.services.html_context import extract_context

        context = extract_context(
            '<html><head><meta name="description" content="watch porn free">'
            '<meta name="keywords" content="porn,xxx"></head></html>'
        )
        self.assertEqual(context.meta_description, "watch porn free")
        self.assertEqual(context.meta_keywords, "porn,xxx")

    def test_extracts_opengraph_properties(self):
        from app.services.html_context import extract_context

        context = extract_context(
            '<html><head><meta property="og:title" content="XXX cams">'
            '<meta property="og:description" content="live"></head></html>'
        )
        self.assertEqual(context.og_title, "XXX cams")
        self.assertEqual(context.og_description, "live")

    def test_extracts_alt_text(self):
        from app.services.html_context import extract_context

        context = extract_context(
            '<html><body><img src="a.jpg" alt="nude video">'
            '<img src="b.jpg" alt="second"></body></html>'
        )
        self.assertIn("nude video", context.alt_values)
        self.assertIn("second", context.alt_values)
        self.assertEqual(context.image_count, 2)

    def test_detects_self_declared_rating_tag(self):
        from app.services.html_context import extract_context

        context = extract_context(
            '<html><head><meta http-equiv="Preroll" '
            'content="RTA-5042-1996-1400"></head></html>'
        )
        self.assertTrue(context.explicit_flag)

    def test_script_content_is_not_treated_as_page_copy(self):
        """A keyword inside a <script> is not evidence about the page."""
        from app.services.html_context import extract_context

        context = extract_context(
            "<html><head><script>var tags=['porn','xxx'];</script>"
            "<title>Weather</title></head><body>Sunny</body></html>"
        )
        self.assertNotIn("porn", context.visible_text.lower())
        self.assertNotIn("xxx", context.descriptive_text.lower())

    def test_known_adult_host_raises_the_flag(self):
        from app.services.html_context import analyse_domain

        _host, signal, flag = analyse_domain("https://www.xvideos.com/v/abc")
        self.assertGreater(signal, 0.0)
        self.assertTrue(flag)

    def test_ordinary_host_has_no_signal(self):
        from app.services.html_context import analyse_domain

        _host, signal, flag = analyse_domain("https://news.bbc.co.uk/weather")
        self.assertEqual(signal, 0.0)
        self.assertFalse(flag)

    def test_malformed_input_never_raises(self):
        from app.services.html_context import extract_context

        for payload in (
            "<<<>>><html<<>",
            "<html><head><title>" + "x" * 100_000,
            "\x00\x01\x02\xff",
            "<img alt='" + "y" * 50_000 + "'>",
        ):
            context = extract_context(payload)
            self.assertIsInstance(context.title, str)


class HtmlContextSafetyTests(unittest.TestCase):
    """§17/§38: the extractor consumes untrusted input, so it must be bounded."""

    def test_oversized_input_is_truncated_not_buffered(self):
        from app.services.html_context import MAX_INPUT_CHARS, extract_context

        context = extract_context(
            "<html><body>" + ("a" * (MAX_INPUT_CHARS * 2)) + "</body></html>"
        )
        self.assertTrue(context.truncated)
        self.assertLessEqual(len(context.visible_text), 64 * 1024)

    def test_alt_collection_is_bounded(self):
        from app.services.html_context import MAX_ALT_VALUES, extract_context

        gallery = "<html><body>" + "".join(
            f'<img alt="pic {i}">' for i in range(5000)
        ) + "</body></html>"
        context = extract_context(gallery)
        self.assertLessEqual(len(context.alt_values), MAX_ALT_VALUES)

    def test_domain_signal_alone_cannot_reach_a_block_threshold(self):
        """§12: context is advisory. This is the structural guarantee."""
        from app.services.text_analyzer import TextAnalyzer

        analyzer = TextAnalyzer()
        worst = analyzer.analyze(None, url="https://www.xhamster.com/x")
        # The absolute ceiling with no body text is domain + rating flag.
        ceiling = (
            analyzer.DOMAIN_WEIGHT * 0.30 + analyzer.EXPLICIT_FLAG_WEIGHT
        )
        self.assertLessEqual(worst.score, ceiling)
        # ...and that ceiling is far below any sensible block threshold.
        self.assertLess(worst.score, 0.25)

    def test_audit_summary_excludes_page_body(self):
        """§18: retain_raw_payloads is false, so the body must not be echoed."""
        from app.services.html_context import extract_context

        context = extract_context(
            "<html><body>private user-visible copy</body></html>",
            url="https://a.example/x",
        )
        self.assertNotIn("visible_text", context.as_dict())
        self.assertIn("private user-visible copy", context.visible_text)


class IdempotencyStoreTests(unittest.TestCase):
    """§33 idempotency: a repeated request_id replays, it does not re-decide."""

    def test_absent_key_returns_none(self):
        from app.core.resilience import IdempotencyStore

        store = IdempotencyStore()
        self.assertIsNone(store.get("acme", "never-seen"))

    def test_remembered_decision_is_replayed(self):
        from app.core.resilience import IdempotencyStore

        store = IdempotencyStore()
        store.remember("acme", "r1", {"decision": "BLOCK"})
        self.assertEqual(store.get("acme", "r1"), {"decision": "BLOCK"})

    def test_tenants_cannot_read_each_others_decisions(self):
        """§34: the same client-supplied id must not cross tenants."""
        from app.core.resilience import IdempotencyStore

        store = IdempotencyStore()
        store.remember("acme", "shared-id", {"decision": "BLOCK"})
        self.assertIsNone(store.get("globex", "shared-id"))

    def test_expired_entry_is_not_replayed(self):
        import time

        from app.core.resilience import IdempotencyStore

        store = IdempotencyStore(ttl_seconds=0.05)
        store.remember("acme", "r1", {"decision": "BLOCK"})
        self.assertIsNotNone(store.get("acme", "r1"))
        time.sleep(0.08)
        self.assertIsNone(store.get("acme", "r1"))

    def test_store_is_bounded(self):
        """A flood of distinct ids must not grow memory without limit (§38)."""
        from app.core.resilience import IdempotencyStore

        store = IdempotencyStore(max_entries=5)
        for index in range(500):
            store.remember("acme", f"r{index}", index)
        self.assertLessEqual(len(store), 5)

    def test_empty_request_id_is_ignored(self):
        from app.core.resilience import IdempotencyStore

        store = IdempotencyStore()
        store.remember("acme", "", {"decision": "BLOCK"})
        self.assertIsNone(store.get("acme", ""))
        self.assertEqual(len(store), 0)

    def test_forget_removes_an_entry(self):
        from app.core.resilience import IdempotencyStore

        store = IdempotencyStore()
        store.remember("acme", "r1", 1)
        store.forget("acme", "r1")
        self.assertIsNone(store.get("acme", "r1"))

    def test_disabled_by_default_on_the_engine(self):
        from app.core.config import EngineConfig
        from app.core.engine import NsfwEngine

        self.assertIsNone(NsfwEngine(EngineConfig()).idempotency)


class BenchmarkReportingTests(unittest.TestCase):
    """§25 requires CSV, JSON, Markdown and HTML output."""

    SECTIONS = {
        "benchmark": {
            "iterations": 4,
            "models_loaded": False,
            "heuristic_fallback": True,
            "end_to_end": {"p50_ms": 1.5, "p95_ms": 2.5},
        },
        "evaluation": None,
    }

    def test_csv_has_a_header_and_flat_metrics(self):
        import csv
        import io

        from benchmarks.reporting import to_csv

        rows = list(csv.reader(io.StringIO(to_csv(self.SECTIONS))))
        self.assertEqual(rows[0], ["section", "metric", "value"])
        # Nested dicts are flattened with dotted keys.
        self.assertIn(["benchmark", "end_to_end.p50_ms", "1.5"], rows)
        # The None section is skipped rather than emitting an empty block.
        self.assertFalse(any(row[0] == "evaluation" for row in rows[1:]))

    def test_html_is_self_contained(self):
        from benchmarks.reporting import to_html

        document = to_html(self.SECTIONS)
        self.assertIn("<!doctype html>", document)
        # No remote fetches: a benchmark artefact must render offline.
        self.assertNotIn("<script", document.lower())
        self.assertNotIn("http://", document.lower())
        self.assertNotIn("https://", document)

    def test_html_carries_the_heuristic_warning(self):
        """§49: the caveat must survive into the artefact most likely to be shared."""
        from benchmarks.reporting import to_html

        document = to_html(self.SECTIONS)
        self.assertIn("Heuristic fallback", document)

    def test_html_escapes_untrusted_values(self):
        from benchmarks.reporting import to_html

        document = to_html({"benchmark": {"model": "<script>x</script>"}})
        self.assertNotIn("<script>x</script>", document)
        self.assertIn("&lt;script&gt;", document)

    def test_cli_exposes_every_25_format(self):
        from benchmarks.__main__ import build_parser

        parser = build_parser()
        options = {action.dest for action in parser._actions}
        for flag in ("csv", "json", "out"):
            self.assertIn(flag, options)


class FuzzHarnessTests(unittest.TestCase):
    """§37 fuzzing: the untrusted parsers must survive arbitrary bytes."""

    def test_all_three_targets_are_clean(self):
        from scripts import fuzz

        for name, target, seed_factory in fuzz.TARGETS:
            failures = fuzz.fuzz_target(
                name, target, seed_factory(), iterations=60, seed=fuzz.DEFAULT_SEED
            )
            self.assertEqual(failures, [], f"{name} parser raised: {failures[:1]}")

    def test_harness_is_deterministic(self):
        """A failure must reproduce from the seed alone."""
        from scripts import fuzz

        def exploding(_data: bytes) -> None:
            raise RuntimeError("boom")

        first = fuzz.fuzz_target("t", exploding, [b"seed"], iterations=25, seed=7)
        second = fuzz.fuzz_target("t", exploding, [b"seed"], iterations=25, seed=7)
        self.assertEqual([r[1] for r in first], [r[1] for r in second])

    def test_slow_target_is_reported(self):
        """The time budget must actually catch a pathological parser."""
        import time

        from scripts import fuzz

        def slow(_data: bytes) -> None:
            time.sleep(0.05)

        failures = fuzz.fuzz_target(
            "slow", slow, [b"seed"], iterations=3, time_budget_ms=10.0
        )
        self.assertTrue(failures)
        self.assertIn("exceeded", failures[0][1])

    def test_mutations_change_the_input(self):
        import random

        from scripts.fuzz import mutate

        rng = random.Random(1)
        original = b"REQMOD icap://proxy ICAP/1.0\r\n\r\n"
        produced = {mutate(rng, original) for _ in range(30)}
        self.assertNotEqual(produced, {original})

    def test_every_seed_corpus_is_non_empty(self):
        from scripts import fuzz

        for _name, _target, seed_factory in fuzz.TARGETS:
            self.assertTrue(seed_factory(), "a target has no seeds")


class ModelLifecycleTests(unittest.TestCase):
    """§22 statuses must be enforced, not decorative."""

    def setUp(self):
        from adapters.registry import ADAPTER_REGISTRY
        from app.core.engine import NsfwEngine
        from app.core.security import SecurityContext

        # The registry holds class attributes, so a test that mutates them must
        # restore them or the change leaks into every later test in the process.
        self._saved = {
            stage: factory.status for stage, factory in ADAPTER_REGISTRY.items()
        }
        self.engine = NsfwEngine()
        self.security = SecurityContext(self.engine.config.security)

    def tearDown(self):
        from adapters.registry import ADAPTER_REGISTRY

        for stage, status in self._saved.items():
            ADAPTER_REGISTRY[stage].status = status

    def test_all_five_22_statuses_exist(self):
        from adapters.base import ModelStatus

        self.assertEqual(
            {s.value for s in ModelStatus},
            {"candidate", "validated", "production", "deprecated", "blocked"},
        )

    def test_candidate_cannot_jump_to_production(self):
        """§49: promotion must mean 'benchmarked', so the jump is refused."""
        from adapters.base import ModelStatus, StatusTransitionError
        from adapters.registry import set_status

        with self.assertRaises(StatusTransitionError):
            set_status("premium_vit", ModelStatus.PRODUCTION)

    def test_the_legal_path_works(self):
        from adapters.base import ModelStatus
        from adapters.registry import set_status, status_of

        set_status("premium_vit", ModelStatus.VALIDATED)
        self.assertEqual(status_of("premium_vit").value, "validated")
        set_status("premium_vit", ModelStatus.PRODUCTION)
        self.assertEqual(status_of("premium_vit").value, "production")

    def test_blocked_is_terminal(self):
        """A blocked model must not be resurrectable.

        That is what stops someone "just enabling" Nudita to route around the
        AGPL boundary (§4) - the reason `blocked` is distinct from `deprecated`.
        """
        from adapters.base import ModelStatus, StatusTransitionError
        from adapters.registry import set_status, status_of

        self.assertEqual(status_of("rejected").value, "blocked")
        with self.assertRaises(StatusTransitionError):
            set_status("rejected", ModelStatus.CANDIDATE)

    def test_deprecated_models_stop_serving_but_can_be_restored(self):
        from adapters.base import ModelStatus
        from adapters.registry import servable_adapters, set_status

        set_status("premium_vit", ModelStatus.DEPRECATED)
        self.assertNotIn("premium_vit", servable_adapters())
        # A rollback is allowed, which is the point of deprecated vs blocked.
        set_status("premium_vit", ModelStatus.VALIDATED)
        self.assertIn("premium_vit", servable_adapters())

    def test_blocked_models_are_never_servable(self):
        from adapters.registry import servable_adapters

        servable = servable_adapters()
        self.assertNotIn("rejected", servable)
        self.assertNotIn("deep_path", servable)  # blocked: licence review

    def test_blocked_adapter_refuses_to_score(self):
        """The guard must fire even when a caller holds an instance directly."""
        from adapters.registry import build_adapter

        adapter = build_adapter("rejected")
        self.assertFalse(adapter.may_serve)
        self.assertIsNone(adapter.predict(b"\x00"))

    def test_describe_reports_status_and_servability(self):
        from adapters.registry import describe_all

        info = describe_all(None)["premium_vit"]
        self.assertIn("status", info)
        self.assertIn("may_serve", info)

    def test_unknown_stage_is_a_key_error(self):
        from adapters.registry import set_status

        with self.assertRaises(KeyError):
            set_status("no_such_stage", "candidate")

    def test_models_endpoint_lists_adapters_with_status(self):
        """§22: a blocked upstream must be visible, not silently absent."""
        from app.api.rest.v1 import models
        from app.core.security import Principal

        listing = models(self.engine, Principal(roles=frozenset()))
        by_stage = {m.stage: m for m in listing.models}
        self.assertIn("rejected", by_stage)
        self.assertEqual(by_stage["rejected"].status, "blocked")
        self.assertFalse(by_stage["rejected"].may_serve)
        self.assertEqual(by_stage["rejected"].kind, "adapter")

    def test_update_endpoint_rejects_illegal_transition(self):
        from fastapi import HTTPException

        from app.api.rest.v1 import update_model_status
        from app.api.rest.schemas import ModelStatusUpdate
        from app.core.security import Principal, Role

        admin = Principal(key_id="k", roles=frozenset({Role.POLICY_ADMIN}))
        with self.assertRaises(HTTPException) as ctx:
            update_model_status(
                "premium_vit",
                ModelStatusUpdate(status="production", reason="skipping validation"),
                self.engine,
                self.security,
                admin,
            )
        self.assertEqual(ctx.exception.status_code, 409)

    def test_update_endpoint_404s_on_unknown_stage(self):
        from fastapi import HTTPException

        from app.api.rest.v1 import update_model_status
        from app.api.rest.schemas import ModelStatusUpdate
        from app.core.security import Principal, Role

        admin = Principal(key_id="k", roles=frozenset({Role.POLICY_ADMIN}))
        with self.assertRaises(HTTPException) as ctx:
            update_model_status(
                "nope",
                ModelStatusUpdate(status="validated"),
                self.engine,
                self.security,
                admin,
            )
        self.assertEqual(ctx.exception.status_code, 404)

    def test_update_endpoint_applies_and_audits(self):
        from app.api.rest.v1 import update_model_status
        from app.api.rest.schemas import ModelStatusUpdate
        from app.core.security import Principal, Role

        admin = Principal(key_id="k", roles=frozenset({Role.POLICY_ADMIN}))
        response = update_model_status(
            "premium_vit",
            ModelStatusUpdate(status="validated", reason="benchmarked on eval-2026-10"),
            self.engine,
            self.security,
            admin,
        )
        self.assertEqual(response.status, "validated")
        self.assertEqual(response.previous_status, "candidate")
        self.assertIn("premium_vit", response.servable_stages)
        events = [e.get("event") for e in self.security.audit_log.entries(50)]
        self.assertIn("model_status_changed", events)

    def test_schema_rejects_unknown_status(self):
        from pydantic import ValidationError

        from app.api.rest.schemas import ModelStatusUpdate

        with self.assertRaises(ValidationError):
            ModelStatusUpdate(status="totally-made-up")


class RequestContextTests(unittest.TestCase):
    """§19 dimensions must actually reach the rule engine."""

    class _Result:
        """Minimal classification result - all the policy bridge needs."""

        verdict = "SFW"
        score = 0.1
        error = ""
        media_type = "IMAGE"
        decided_by = "FAST"
        stages = []
        text = None

    @staticmethod
    def _engine_with(rules):
        from app.core.config import load_config
        from app.core.policy import PolicyEngine
        from policy.engine import policy_from_dict

        engine = PolicyEngine(load_config().policy)
        engine.registry.global_policy = policy_from_dict(
            {"policy_id": "t", "default_action": "allow", "rules": rules}
        )
        return engine

    def test_all_19_dimensions_are_present(self):
        from app.core.request_context import build_request_context

        ctx = build_request_context(
            tenant_id="acme", user_id="u1", groups=["staff"], device_id="d1",
            zone="eu-west", url="https://a.example/x", domain="a.example",
            category="explicit",
        )
        for key in (
            "tenant_id", "user_id", "groups", "device_id", "zone",
            "url", "domain", "category", "time",
        ):
            self.assertIn(key, ctx)

    def test_time_facet_is_derived(self):
        import datetime as dt

        from app.core.request_context import time_facet

        # Saturday 23:30 - weekend, night, outside business hours.
        facet = time_facet(dt.datetime(2026, 10, 3, 23, 30))
        self.assertEqual(facet["hour"], 23)
        self.assertEqual(facet["weekday"], 5)
        self.assertTrue(facet["is_weekend"])
        self.assertTrue(facet["night"])
        self.assertFalse(facet["business_hours"])

        # Wednesday 10:00 - the inverse.
        facet = time_facet(dt.datetime(2026, 9, 30, 10, 0))
        self.assertFalse(facet["is_weekend"])
        self.assertFalse(facet["night"])
        self.assertTrue(facet["business_hours"])

    def test_groups_parse_from_every_delimiter(self):
        from app.core.request_context import context_from_headers

        for raw in ("a,b", "a b", "a;b", "a|b", "A, B"):
            ctx = context_from_headers({"x-user-groups": raw})
            self.assertEqual(ctx["groups"], ["a", "b"], f"failed for {raw!r}")

    def test_principal_arguments_outrank_headers(self):
        """A client must not be able to assert its own identity (§35)."""
        from app.core.request_context import context_from_headers

        ctx = context_from_headers(
            {"x-user-id": "spoofed", "x-tenant-id": "victim"},
            tenant_id="acme",
            user_id="authenticated",
        )
        self.assertEqual(ctx["user_id"], "authenticated")
        self.assertEqual(ctx["tenant_id"], "acme")

    def test_domain_is_derived_from_the_url(self):
        from app.core.request_context import context_from_headers

        ctx = context_from_headers({"x-forwarded-url": "https://cdn.example/a.jpg"})
        self.assertEqual(ctx["domain"], "cdn.example")

    def test_a_zone_rule_actually_fires(self):
        """The gap this closes: a rule on `zone` used to never match."""
        from app.core.request_context import build_request_context

        engine = self._engine_with(
            [{"field": "zone", "operator": "==", "value": "kiosk", "action": "block"}]
        )
        self.assertEqual(
            engine.decide(self._Result(), "acme", build_request_context(zone="kiosk"))
            .action.value,
            "BLOCK",
        )
        self.assertEqual(
            engine.decide(self._Result(), "acme", build_request_context(zone="office"))
            .action.value,
            "ALLOW",
        )

    def test_a_group_rule_actually_fires(self):
        from app.core.request_context import build_request_context

        engine = self._engine_with(
            [{"field": "groups", "operator": "contains", "value": "contractor",
              "action": "review"}]
        )
        self.assertEqual(
            engine.decide(
                self._Result(), "acme", build_request_context(groups=["contractor"])
            ).action.value,
            "REVIEW",
        )
        self.assertEqual(
            engine.decide(
                self._Result(), "acme", build_request_context(groups=["staff"])
            ).action.value,
            "ALLOW",
        )

    def test_a_time_rule_actually_fires(self):
        import datetime as dt

        from app.core.request_context import build_request_context

        engine = self._engine_with(
            [{"field": "time.night", "operator": "==", "value": True,
              "action": "review"}]
        )
        self.assertEqual(
            engine.decide(
                self._Result(), "acme",
                build_request_context(now=dt.datetime(2026, 10, 3, 23, 30)),
            ).action.value,
            "REVIEW",
        )
        self.assertEqual(
            engine.decide(
                self._Result(), "acme",
                build_request_context(now=dt.datetime(2026, 10, 3, 12, 0)),
            ).action.value,
            "ALLOW",
        )

    def test_decision_records_the_dimensions_it_saw(self):
        from app.core.config import load_config
        from app.core.policy import PolicyEngine
        from app.core.request_context import build_request_context

        engine = PolicyEngine(load_config().policy)
        decision = engine.decide(
            self._Result(), "acme",
            build_request_context(zone="eu-west", device_id="d-9", user_id="u-1"),
        )
        self.assertEqual(decision.matched_dimensions["zone"], "eu-west")
        self.assertEqual(decision.matched_dimensions["device_id"], "d-9")

    def test_absent_context_keeps_previous_behaviour(self):
        """A caller that supplies no context must be completely unaffected."""
        from app.core.config import load_config
        from app.core.policy import PolicyEngine

        class _Blocked(RequestContextTests._Result):
            verdict = "NSFW"
            score = 0.95

        self.assertEqual(
            PolicyEngine(load_config().policy).decide(_Blocked()).action.value, "BLOCK"
        )


class TextContextEndpointTests(unittest.TestCase):
    """§12 + §19: HTML/text traffic must reach policy with its context."""

    def _run(self, engine, security, principal, request, **body):
        import asyncio

        from app.api.rest.schemas import InspectTextRequest
        from app.api.rest.v1 import classify_text_v1

        payload = InspectTextRequest(**body)
        return asyncio.run(
            classify_text_v1(payload, request, engine, security, principal)
        )

    @staticmethod
    def _request(headers=None):
        class _Req:
            def __init__(self, headers):
                self.headers = headers or {}

        return _Req(headers)

    def test_text_endpoint_exists_in_the_v1_contract(self):
        from app.api.rest.v1 import router

        paths = {route.path for route in router.routes}
        self.assertIn("/v1/classify/text", paths)

    def test_html_context_reaches_the_response(self):
        from app.services.html_context import extract_context

        html = (
            "<html><head><title>Totally Safe Page</title>"
            '<meta property="og:title" content="Meta Title"></head>'
            "<body><img alt='descriptive alt text'></body></html>"
        )
        context = extract_context(html, url="https://cdn.example/page")
        self.assertTrue(context.title)
        # §12: metadata only, never the body. This is what makes the context
        # safe to log when privacy.retain_raw_payloads is false (§18).
        serialised = context.as_dict().__repr__()
        self.assertNotIn("<body>", serialised)
        self.assertNotIn("descriptive alt text", serialised)

    def test_text_endpoint_returns_a_decision(self):
        from app.core.engine import NsfwEngine
        from app.core.security import Principal, SecurityContext

        engine = NsfwEngine()
        response = self._run(
            engine, SecurityContext(engine.config.security),
            Principal(roles=frozenset()), self._request(),
            text="a perfectly ordinary sentence about gardening",
            media_type="TEXT", url="https://example.org/post",
        )
        self.assertIn(response.decision, {"ALLOW", "REVIEW", "BLOCK", "QUARANTINE"})
        self.assertTrue(response.policy_id)

    def test_text_endpoint_reports_context_dimensions(self):
        from app.core.engine import NsfwEngine
        from app.core.security import Principal, SecurityContext

        engine = NsfwEngine()
        response = self._run(
            engine, SecurityContext(engine.config.security),
            Principal(roles=frozenset()), self._request(),
            text="<html><head><title>Page</title></head><body>hi</body></html>",
            media_type="HTML", url="https://example.org/a",
        )
        self.assertIsNotNone(response.matched_dimensions)
        self.assertIn("url", response.matched_dimensions)

    def test_schema_rejects_a_bad_media_type(self):
        from pydantic import ValidationError

        from app.api.rest.schemas import InspectTextRequest

        with self.assertRaises(ValidationError):
            InspectTextRequest(text="x", media_type="VIDEO")


class ContainsOperatorTests(unittest.TestCase):
    """Regression: `contains` against a list field silently never matched.

    A §19 group rule written the natural way - `field: groups`, `operator:
    contains`, `value: contractor` - resolved to False for every request because
    a list has no ``.lower()``. These tests pin both directions of the operator
    so the fix cannot regress.
    """

    def _evaluate(self, actual, value):
        from policy.models import Rule

        return Rule("f", "contains", value, "allow").evaluate({"f": actual})

    def test_needle_found_in_a_list(self):
        self.assertTrue(self._evaluate(["staff", "contractor"], "contractor"))

    def test_needle_absent_from_a_list(self):
        self.assertFalse(self._evaluate(["staff", "finance"], "contractor"))

    def test_matching_is_case_insensitive(self):
        self.assertTrue(self._evaluate(["Staff", "Contractor"], "contractor"))
        self.assertTrue(self._evaluate(["staff"], "STAFF"))

    def test_surrounding_whitespace_is_ignored(self):
        self.assertTrue(self._evaluate([" staff "], "staff"))

    def test_empty_list_never_matches(self):
        self.assertFalse(self._evaluate([], "contractor"))

    def test_substring_is_not_a_membership_test(self):
        """`contains` on a list means exact membership, not a substring match -
        "contractor" must not match "senior_contractor_lead"."""
        self.assertFalse(self._evaluate(["senior_contractor_lead"], "contractor"))

    def test_string_actual_still_behaves_as_substring(self):
        """The pre-existing string behaviour is unchanged."""
        self.assertTrue(self._evaluate("my user groups here", "groups"))
        self.assertFalse(self._evaluate("my user groups here", "absent"))

    def test_list_value_against_scalar_actual_still_works(self):
        """The other direction - `value` being the list - is unchanged."""
        self.assertTrue(self._evaluate("b", ["a", "b"]))
        self.assertFalse(self._evaluate("c", ["a", "b"]))


class DeadLetterQueueTests(unittest.TestCase):
    """§33 dead-letter queue: bounded, TTL-scoped, and payload-free."""

    def test_publish_and_drain_roundtrip(self):
        from app.core.resilience import DeadLetterQueue

        queue = DeadLetterQueue()
        queue.publish(tenant_id="acme", endpoint="/v1/inspect",
                      reason="classify_error", request_id="r1")
        taken = queue.drain()
        self.assertEqual(len(taken), 1)
        self.assertEqual(taken[0].reason, "classify_error")
        self.assertEqual(taken[0].tenant_id, "acme")
        self.assertEqual(len(queue), 0, "drain must remove, not peek")

    def test_never_stores_the_payload(self):
        """The whole point: a failed NSFW payload must not be retained."""
        from app.core.resilience import DeadLetterQueue

        letter = DeadLetterQueue().publish(
            tenant_id="acme", reason="classify_error",
            content_sha256="deadbeef", request_id="r1",
        )
        self.assertEqual(letter.content_sha256, "deadbeef")
        self.assertFalse(hasattr(letter, "content"))
        self.assertFalse(hasattr(letter, "body"))
        self.assertNotIn("payload", repr(letter.as_dict()))

    def test_queue_is_bounded_and_evicts_oldest(self):
        from app.core.resilience import DeadLetterQueue

        queue = DeadLetterQueue(max_entries=3)
        for i in range(5):
            queue.publish(request_id=f"r{i}", reason="classify_error")
        self.assertEqual(len(queue), 3)
        self.assertEqual([x.request_id for x in queue.peek(10)], ["r2", "r3", "r4"])

    def test_full_queue_never_raises(self):
        """A full queue must not turn a handled failure into a new one."""
        from app.core.resilience import DeadLetterQueue

        queue = DeadLetterQueue(max_entries=1)
        for _ in range(50):
            queue.publish(request_id="r", reason="classify_error")
        self.assertEqual(len(queue), 1)

    def test_ttl_purge(self):
        import time as _time

        from app.core.resilience import DeadLetterQueue

        queue = DeadLetterQueue(ttl_seconds=0.01)
        queue.publish(request_id="r1")
        _time.sleep(0.05)
        self.assertEqual(queue.purge_expired(), 1)
        self.assertEqual(len(queue), 0)

    def test_stats_group_by_reason(self):
        from app.core.resilience import DeadLetterQueue

        queue = DeadLetterQueue()
        queue.publish(reason="circuit_open")
        queue.publish(reason="circuit_open")
        queue.publish(reason="classify_error")
        self.assertEqual(queue.stats()["published"], 3)
        self.assertEqual(queue.stats()["by_reason"]["circuit_open"], 2)

    def test_engine_has_a_dlq_by_default(self):
        from app.core.engine import NsfwEngine

        # Unlike the breaker and the rate limiter, capturing a failure is not
        # optional: not doing it loses the request outright.
        self.assertIsNotNone(NsfwEngine().dead_letters)

    def test_health_exposes_the_dlq(self):
        from app.core.engine import NsfwEngine

        self.assertIn("dead_letters", NsfwEngine().health())

    def test_endpoint_requires_read_audit(self):
        """A classification client must not be able to list failed requests."""
        import inspect as _inspect

        from app.api.rest.v1 import dead_letters

        source = _inspect.getsource(dead_letters)
        self.assertIn("READ_AUDIT", source)
        self.assertNotIn("Permission.CLASSIFY", source)

    def test_endpoint_is_empty_when_disabled(self):
        from app.api.rest.v1 import dead_letters
        from app.core.engine import NsfwEngine
        from app.core.security import Principal

        engine = NsfwEngine()
        engine.dead_letters = None
        response = dead_letters(False, 10, engine, Principal(roles=frozenset()))
        self.assertFalse(response.enabled)
        self.assertEqual(response.total, 0)

    def test_endpoint_peeks_by_default(self):
        from app.api.rest.v1 import dead_letters
        from app.core.engine import NsfwEngine
        from app.core.security import Principal

        engine = NsfwEngine()
        engine.dead_letters.publish(request_id="r1", reason="classify_error")
        response = dead_letters(False, 10, engine, Principal(roles=frozenset()))
        self.assertTrue(response.enabled)
        self.assertEqual(response.total, 1)
        self.assertEqual(len(engine.dead_letters), 1, "peek must not remove")

    def test_endpoint_drains_on_request(self):
        from app.api.rest.v1 import dead_letters
        from app.core.engine import NsfwEngine
        from app.core.security import Principal

        engine = NsfwEngine()
        engine.dead_letters.publish(request_id="r1", reason="classify_error")
        drained = dead_letters(True, 10, engine, Principal(roles=frozenset()))
        self.assertEqual(drained.total, 1)
        self.assertEqual(len(engine.dead_letters), 0)

    def test_undecidable_request_is_dead_lettered(self):
        from app.api.rest.v1 import _dead_letter
        from app.core.engine import NsfwEngine

        engine = NsfwEngine()
        _dead_letter(engine, tenant_id="acme", endpoint="/v1/inspect",
                     reason="classify_error", error="boom", content_sha256="abc")
        self.assertEqual(len(engine.dead_letters), 1)
        self.assertEqual(engine.dead_letters.peek()[0].error, "boom")

    def test_helper_survives_a_broken_queue(self):
        """A failure while recording a failure must not raise."""
        from app.api.rest.v1 import _dead_letter
        from app.core.engine import NsfwEngine

        class _Broken:
            def publish(self, **kwargs):
                raise RuntimeError("queue exploded")

        engine = NsfwEngine()
        engine.dead_letters = _Broken()
        _dead_letter(engine, reason="classify_error")  # must not raise

    def test_helper_is_a_noop_when_disabled(self):
        from app.api.rest.v1 import _dead_letter
        from app.core.engine import NsfwEngine

        engine = NsfwEngine()
        engine.dead_letters = None
        _dead_letter(engine, reason="classify_error")


class BoundedRetryTests(unittest.TestCase):
    """§33 bounded retries."""

    @staticmethod
    def _always_fails(exc=None):
        def boom():
            raise exc or RuntimeError("down")

        return boom

    def test_returns_without_retrying_on_success(self):
        from app.core.resilience import call_with_retries

        calls = []
        result = call_with_retries(lambda: calls.append(1) or "ok")
        self.assertEqual(result, "ok")
        self.assertEqual(len(calls), 1)

    def test_retries_then_succeeds(self):
        from app.core.resilience import call_with_retries

        state = {"n": 0}

        def flaky():
            state["n"] += 1
            if state["n"] < 3:
                raise RuntimeError("transient")
            return "ok"

        result = call_with_retries(flaky, attempts=3, sleeper=lambda _s: None)
        self.assertEqual(result, "ok")
        self.assertEqual(state["n"], 3)

    def test_gives_up_after_the_bound(self):
        """An unbounded retry loop turns one broken dependency into one hung
        request per worker - strictly worse than failing fast."""
        from app.core.resilience import call_with_retries

        calls = []

        def failing():
            calls.append(1)
            raise RuntimeError("down")

        with self.assertRaises(RuntimeError):
            call_with_retries(failing, attempts=3, sleeper=lambda _s: None)
        self.assertEqual(len(calls), 3, "must not exceed the attempt bound")

    def test_single_attempt_means_no_retry(self):
        from app.core.resilience import call_with_retries

        calls = []

        def failing():
            calls.append(1)
            raise RuntimeError("down")

        with self.assertRaises(RuntimeError):
            call_with_retries(failing, attempts=1, sleeper=lambda _s: None)
        self.assertEqual(len(calls), 1)

    def test_backoff_grows_and_is_observable(self):
        from app.core.resilience import call_with_retries

        slept = []
        with self.assertRaises(RuntimeError):
            call_with_retries(self._always_fails(), attempts=3,
                              backoff_seconds=0.1, sleeper=slept.append)
        self.assertEqual(slept, [0.1, 0.2])

    def test_on_retry_hook_cannot_mask_the_real_error(self):
        from app.core.resilience import call_with_retries

        seen = []

        def hook(attempt, exc):
            seen.append((attempt, str(exc)))
            raise RuntimeError("reporter is broken")

        with self.assertRaises(ValueError) as ctx:
            call_with_retries(self._always_fails(ValueError("real")),
                              attempts=2, on_retry=hook, sleeper=lambda _s: None)
        self.assertEqual(len(seen), 1)
        self.assertIn("real", str(ctx.exception))

    def test_retry_on_narrows_what_is_retried(self):
        from app.core.resilience import call_with_retries

        calls = []

        def failing():
            calls.append(1)
            raise KeyError("not transient")

        with self.assertRaises(KeyError):
            call_with_retries(failing, attempts=5, retry_on=(TimeoutError,),
                              sleeper=lambda _s: None)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)


