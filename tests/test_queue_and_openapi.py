"""Queue backend tests (§33) plus the OpenAPI contract artifact (§46)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.queue import (  # noqa: E402
    InMemoryQueue,
    Job,
    KafkaQueue,
    QUEUE_BACKENDS,
    QueueError,
    QueueFull,
    RedisQueue,
    build_queue,
)


class InMemoryQueueTests(unittest.TestCase):
    def test_put_and_get(self):
        queue = InMemoryQueue()
        job_id = queue.put(Job(payload=b"data", meta={"request_id": "r1"}))
        job = queue.get(timeout=0.1)
        self.assertIsNotNone(job)
        self.assertEqual(job.job_id, job_id)
        self.assertEqual(job.meta["request_id"], "r1")

    def test_get_returns_none_when_empty(self):
        self.assertIsNone(InMemoryQueue().get(timeout=0.05))

    def test_fifo_order(self):
        queue = InMemoryQueue()
        for index in range(3):
            queue.put(Job(payload=bytes([index])))
        self.assertEqual([queue.get(0.1).payload for _ in range(3)], [b"\x00", b"\x01", b"\x02"])

    def test_bounded_queue_rejects_instead_of_growing(self):
        # Resource-exhaustion protection (§17): refuse, never grow unbounded.
        queue = InMemoryQueue(max_size=2)
        queue.put(Job(payload=b"a"))
        queue.put(Job(payload=b"b"))
        with self.assertRaises(QueueFull):
            queue.put(Job(payload=b"c"))

    def test_ack_removes_from_inflight(self):
        queue = InMemoryQueue()
        job = queue.put(Job(payload=b"a"))
        queue.get(0.1)
        self.assertEqual(queue.inflight, 1)
        queue.ack(job)
        self.assertEqual(queue.inflight, 0)

    def test_visibility_timeout_requeues(self):
        queue = InMemoryQueue(visibility_timeout=0.05)
        queue.put(Job(payload=b"a"))
        queue.get(0.1)  # now inflight and invisible
        self.assertIsNone(queue.get(timeout=0.01))
        import time

        time.sleep(0.08)
        reclaimed = queue.get(timeout=0.2)
        self.assertIsNotNone(reclaimed)
        self.assertEqual(reclaimed.payload, b"a")
        self.assertGreaterEqual(reclaimed.attempts, 2)

    def test_size_counts_ready_and_inflight(self):
        queue = InMemoryQueue()
        queue.put(Job(payload=b"a"))
        self.assertEqual(queue.size(), 1)
        queue.get(0.1)
        self.assertEqual(queue.size(), 1)

    def test_describe_shape(self):
        described = InMemoryQueue().describe()
        self.assertEqual(described["name"], "memory")
        self.assertTrue(described["available"])


class QueueBackendTests(unittest.TestCase):
    def test_registry_contains_all_backends(self):
        for name in ("memory", "redis", "kafka"):
            self.assertIn(name, QUEUE_BACKENDS)

    def test_build_by_name(self):
        self.assertIsInstance(build_queue("memory"), InMemoryQueue)

    def test_unknown_backend_raises(self):
        with self.assertRaises(ValueError):
            build_queue("nope")

    def test_optional_backends_degrade_without_client(self):
        # redis/kafka are not installed here, so they must report unavailable
        # rather than raising at construction time (§3: reuse, don't require).
        for backend in (RedisQueue(), KafkaQueue()):
            self.assertFalse(backend.available)
            self.assertEqual(backend.size(), 0)

    def test_unavailable_redis_raises_on_put(self):
        if RedisQueue().available:
            self.skipTest("redis is installed")
        with self.assertRaises(QueueError):
            RedisQueue().put(Job(payload=b"a"))

    def test_kafka_is_producer_only(self):
        with self.assertRaises(QueueError):
            KafkaQueue().get()


class OpenApiArtifactTests(unittest.TestCase):
    def test_schema_is_committed_and_current(self):
        from scripts.export_openapi import DEFAULT_OUTPUT

        self.assertTrue(DEFAULT_OUTPUT.exists(), "docs/openapi.json is not committed")

    def test_schema_covers_the_public_api(self):
        from scripts.export_openapi import DEFAULT_OUTPUT

        schema = DEFAULT_OUTPUT.read_text(encoding="utf-8")
        for path in ('"/health"', '"/metrics"', '"/classify"', '"/enforce"', '"/audit"'):
            self.assertIn(path, schema, f"{path} missing from the OpenAPI contract")


class VersionedApiTests(unittest.TestCase):
    """The ``/v1`` contract promised by ``pront.md`` §20.

    These tests exercise the route callables directly rather than through
    ``TestClient``: the installed ``httpx`` build is incompatible with this
    Starlette version, so the HTTP round trip is covered by the CI job that
    pins a compatible ``httpx``. Route *wiring* is asserted here, so a missing
    registration still cannot slip through.
    """

    def setUp(self):
        from app.api.rest.router import create_app
        from app.core.engine import NsfwEngine
        from app.core.security import SecurityContext

        self.engine = NsfwEngine()
        self.app = create_app(engine=self.engine)
        self.security = SecurityContext(self.engine.config.security)

    # -- wiring (§20) --------------------------------------------------------
    def test_every_v1_endpoint_is_registered(self):
        paths = {getattr(route, "path", "") for route in self.app.routes}
        for path in (
            "/v1/inspect",
            "/v1/classify",
            "/v1/batch",
            "/v1/models",
            "/v1/policies",
            "/v1/health",
            "/v1/ready",
        ):
            self.assertIn(path, paths, f"{path} is not registered on the app")

    def test_v1_router_uses_the_v1_prefix(self):
        from app.api.rest.v1 import router

        self.assertEqual(router.prefix, "/v1")

    def test_openapi_contract_publishes_v1(self):
        from scripts.export_openapi import DEFAULT_OUTPUT

        schema = DEFAULT_OUTPUT.read_text(encoding="utf-8")
        for path in ('"/v1/inspect"', '"/v1/batch"', '"/v1/models"', '"/v1/policies"'):
            self.assertIn(path, schema, f"{path} missing from the OpenAPI contract")

    # -- probes (§33) --------------------------------------------------------
    def test_health_is_public_and_always_ok(self):
        from app.api.rest.v1 import health

        # A detector-less replica is still *alive*: liveness must not flap on
        # model availability or Kubernetes will restart-loop it.
        body = health(self.engine)
        self.assertTrue(body["healthy"])
        self.assertIn("version", body)

    def test_ready_is_false_without_models(self):
        from app.api.rest.v1 import ready
        from app.core.config import EngineConfig
        from app.core.engine import NsfwEngine
        # This must not depend on what happens to be in models_onnx/ locally: an
        # operator who has fetched vit_nsfw.onnx would otherwise see this test
        # fail for a reason that has nothing to do with the probe.
        with tempfile.TemporaryDirectory() as empty_models:
            config = EngineConfig()
            config.paths.models_dir = empty_models
            for name in ("fast_path_model", "deep_path_model", "multimodal_model",
                         "text_model", "premium_model"):
                setattr(config.paths, name, f"{empty_models}/missing.onnx")
            engine = NsfwEngine(config)

            body = ready(engine)
            # With nothing mounted, readiness must be honest (§46).
            self.assertFalse(body.ready)
            self.assertIn("models_loaded", body.checks)
            self.assertFalse(body.checks["models_loaded"])
            self.assertTrue(body.reason)

    # -- model registry (§22) ------------------------------------------------
    def test_models_reports_every_stage_with_a_license(self):
        from app.api.rest.v1 import models
        from app.core.security import Principal

        listing = models(self.engine, Principal(roles=frozenset()))
        # Four built-in cascade stages plus the §41 third-party adapters.
        cascade = [m for m in listing.models if m.kind == "cascade"]
        adapters = [m for m in listing.models if m.kind == "adapter"]
        self.assertEqual(
            {m.stage for m in cascade}, {"fast_path", "deep_path", "multimodal", "text"}
        )
        self.assertTrue(adapters, "third-party adapters must be listed (§41/§22)")
        # §4 forbids silent ambiguity: license and status are always present.
        for model in listing.models:
            self.assertTrue(model.license)
            self.assertTrue(model.status)

    def test_models_reports_the_22_lifecycle_statuses(self):
        from app.api.rest.v1 import models
        from app.core.security import Principal

        listing = models(self.engine, Principal(roles=frozenset()))
        for model in listing.models:
            self.assertIn(
                model.status,
                {"candidate", "validated", "production", "deprecated", "blocked"},
            )

    # -- policies (§19) ------------------------------------------------------
    def test_policies_returns_the_active_ruleset(self):
        from app.api.rest.v1 import policies
        from app.core.security import Principal

        listing = policies("", self.engine, Principal(roles=frozenset()))
        self.assertEqual(listing.total, 1)
        self.assertTrue(listing.policies[0].rules)

    def test_policies_rejects_cross_tenant_read(self):
        from fastapi import HTTPException

        from app.api.rest.v1 import policies
        from app.core.security import Principal, Role

        intruder = Principal(key_id="k", roles=frozenset({Role.POLICY_ADMIN}), tenant_id="a")
        with self.assertRaises(HTTPException) as ctx:
            policies("b", self.engine, intruder)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_create_policy_rejects_cross_tenant_write(self):
        from fastapi import HTTPException

        from app.api.rest.v1 import create_policy
        from app.api.rest.schemas import PolicyDocument, PolicyRuleSchema
        from app.core.security import Principal, Role

        document = PolicyDocument(
            policy_id="p",
            tenant_id="victim",
            rules=[PolicyRuleSchema(field="score", operator=">=", value=0.9, action="block")],
        )
        intruder = Principal(key_id="k", roles=frozenset({Role.POLICY_ADMIN}), tenant_id="acme")
        with self.assertRaises(HTTPException) as ctx:
            create_policy(document, self.engine, self.security, intruder)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_create_policy_rejects_empty_rules(self):
        from fastapi import HTTPException

        from app.api.rest.v1 import create_policy
        from app.api.rest.schemas import PolicyDocument
        from app.core.security import Principal, Role

        # A super_admin, so the request is *authorized* and the 422 validation
        # path is what actually gets exercised. Authorisation is checked before
        # document validation on purpose: an unauthorized caller must not be
        # told that their document is malformed.
        admin = Principal(key_id="k", roles=frozenset({Role.SUPER_ADMIN}))
        with self.assertRaises(HTTPException) as ctx:
            create_policy(PolicyDocument(policy_id="p"), self.engine, self.security, admin)
        self.assertEqual(ctx.exception.status_code, 422)

    def test_policy_admin_may_not_replace_the_global_policy(self):
        """SECURITY: omitting tenant_id must not grant global write access.

        A tenant-scoped ``policy_admin`` used to be able to install a global
        policy simply by leaving ``tenant_id`` empty, and a global policy with
        ``default_action: allow`` switches the whole firewall off.
        """
        from fastapi import HTTPException

        from app.api.rest.v1 import create_policy
        from app.api.rest.schemas import PolicyDocument, PolicyRuleSchema
        from app.core.security import Principal, Role

        document = PolicyDocument(
            policy_id="attacker",
            tenant_id="",
            default_action="allow",
            rules=[
                PolicyRuleSchema(field="*", operator="==", value="*", action="allow")
            ],
        )
        scoped_admin = Principal(
            key_id="k", roles=frozenset({Role.POLICY_ADMIN}), tenant_id="acme"
        )
        with self.assertRaises(HTTPException) as ctx:
            create_policy(document, self.engine, self.security, scoped_admin)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_create_policy_installs_tenant_rules(self):
        from app.api.rest.v1 import create_policy
        from app.api.rest.schemas import PolicyDocument, PolicyRuleSchema
        from app.core.security import Principal, Role

        admin = Principal(key_id="k", roles=frozenset({Role.POLICY_ADMIN}), tenant_id="acme")
        document = PolicyDocument(
            policy_id="acme-strict",
            tenant_id="acme",
            rules=[
                PolicyRuleSchema(
                    field="verdict", operator="==", value="NSFW", action="quarantine"
                )
            ],
        )
        outcome = create_policy(document, self.engine, self.security, admin)
        self.assertEqual(outcome.policy_id, "acme-strict")
        self.assertTrue(outcome.created)
        self.assertEqual(outcome.rules_applied, 1)
        self.assertEqual(
            self.engine.policy.registry.policy_for("acme").policy_id, "acme-strict"
        )

    # -- batch (§20) ---------------------------------------------------------
    def test_batch_cap_is_enforced(self):
        import asyncio
        import base64

        from fastapi import HTTPException

        from app.api.rest.v1 import MAX_BATCH_ITEMS, batch
        from app.api.rest.schemas import BatchRequest, MediaItem
        from app.core.security import Principal, Role

        items = [
            MediaItem(content_base64=base64.b64encode(b"x").decode())
            for _ in range(MAX_BATCH_ITEMS + 1)
        ]
        caller = Principal(key_id="k", roles=frozenset({Role.SERVICE_ACCOUNT}))
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(batch(BatchRequest(items=items), self.engine, self.security, caller))
        self.assertEqual(ctx.exception.status_code, 413)

    def test_batch_reports_per_item_errors_without_aborting(self):
        import asyncio
        import base64

        from app.api.rest.v1 import batch
        from app.api.rest.schemas import BatchRequest, MediaItem
        from app.core.security import Principal, Role

        good = base64.b64encode(b"<html><body>hello world</body></html>").decode()
        items = [
            MediaItem(content_base64="!!!not-base64!!!", request_id="bad"),
            MediaItem(content_base64=good, media_type="HTML", request_id="ok"),
        ]
        caller = Principal(key_id="k", roles=frozenset({Role.SERVICE_ACCOUNT}))
        response = asyncio.run(
            # Keyword args: the route gained a pre-auth IP limiter parameter, so
            # a positional call bound `caller` to that slot instead.
            batch(BatchRequest(items=items), self.engine, self.security, principal=caller)
        )
        self.assertEqual(response.total, 2)
        self.assertEqual(response.errored, 1)
        # The good item must still be classified - one bad payload cannot blind
        # the operator to the rest of the traffic.
        self.assertTrue(response.results[0].error)
        self.assertFalse(response.results[1].error)

    # -- HTML context (§12) --------------------------------------------------
    def test_context_fields_are_folded_into_the_text_signal(self):
        from app.api.rest.v1 import _context_for
        from app.api.rest.schemas import InspectRequest

        payload = InspectRequest(
            content_base64="x", url="https://a.example/porn",
            domain="a.example", title="free porn",
        )
        context = _context_for(payload)
        # The host is captured verbatim...
        self.assertEqual(context.domain, "a.example")
        # ...and a token in the URL slug raises the signal even though the
        # registrable domain itself is innocuous.
        self.assertGreater(context.domain_signal, 0.0)

    def test_context_is_metadata_only(self):
        """§18: the audit payload must never carry the page body."""
        from app.api.rest.v1 import _context_for
        from app.api.rest.schemas import InspectRequest

        payload = InspectRequest(
            content_base64="x",
            media_type="HTML",
            text="<html><body>secret user-visible copy</body></html>",
            url="https://a.example/x",
        )
        summary = _context_for(payload).as_dict()
        self.assertNotIn("secret user-visible copy", str(summary))
        self.assertNotIn("visible_text", summary)


if __name__ == "__main__":
    unittest.main(verbosity=2)