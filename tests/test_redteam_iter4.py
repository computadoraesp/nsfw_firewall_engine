"""Red-team iteration 4: the wire, the throttle and the record of it all.

Iteration 3 closed the transports' *identity*. This round attacks what
survives once you are who you say you are:

* ``TransportSecurity`` - gRPC serves credentials in cleartext, and neither
  gRPC nor ICAP is throttled at all.
* ``AuditDurability``   - the audit trail is a deque in RAM: a firewall restart
  erases it, while ``config/privacy.yaml`` promises 365 days in S3.
* ``MetricsExposure``   - ``/metrics`` is anonymous and exposes the shape of
  the deployment.

Run with::

    Python -m pytest tests/test_redteam_iter4.py -v
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.test_redteam import REPO_ROOT, _client  # noqa: E402


# ---------------------------------------------------------------------------
# Transport security
# ---------------------------------------------------------------------------


class TransportSecurity(unittest.TestCase):
    """gRPC authenticates with API keys, then serves them in the clear.

    ``add_insecure_port`` means the ``x-api-key`` metadata travels as plaintext
    over whatever network reaches port 50051. A passive observer harvests a
    credential that is valid on **REST and gRPC alike** - one sniff defeats the
    whole authentication model, and the key store's scrypt hashing protects the
    file at rest, not the wire.
    """

    def test_attack_grpc_serves_credentials_in_cleartext(self):
        from app.core.config import GrpcTransport

        transport = GrpcTransport()
        self.assertTrue(
            getattr(transport, "tls_enabled", False),
            msg=(
                "gRPC has no TLS option at all: add_insecure_port() sends the "
                "API key in cleartext to anyone on the path"
            ),
        )

    def test_attack_grpc_server_uses_add_secure_port_when_configured(self):
        import inspect

        from app.api.grpc import server as grpc_server

        source = inspect.getsource(grpc_server.create_server)
        self.assertIn(
            "add_secure_port",
            source,
            msg="create_server() has no TLS path to fall back to",
        )

    def test_attack_grpc_is_not_bound_to_all_interfaces_by_default(self):
        from app.core.config import GrpcTransport

        self.assertNotEqual(
            GrpcTransport().host,
            "0.0.0.0",
            msg=(
                "gRPC binds every interface by default and carries API keys; "
                "loopback until TLS is configured"
            ),
        )

    def test_attack_grpc_refuses_to_start_without_tls(self):
        """A transport carrying credentials must not fall back to plaintext."""
        from app.core.config import SecurityConfig

        self.assertTrue(
            hasattr(SecurityConfig(), "require_transport_tls"),
            msg="no switch to refuse an unauthenticated-on-the-wire transport",
        )


class ThrottleExploits(unittest.TestCase):
    """Neither gRPC nor ICAP consults the rate limiter.

    ``RateLimiter`` is constructed in the REST app factory and referenced by no
    other transport. Classification is CPU-bound inference, so both of these are
    unthrottled denial-of-service surfaces: a single client can saturate every
    worker for free.
    """

    def test_attack_grpc_is_throttled(self):
        import inspect

        from app.api.grpc import handlers

        source = inspect.getsource(handlers)
        self.assertIn(
            "rate_limit",
            source.lower(),
            msg="the gRPC servicer performs no rate limiting whatsoever",
        )

    def test_attack_icap_is_throttled(self):
        import inspect

        from app.api.icap import icap_server

        source = inspect.getsource(icap_server)
        self.assertIn(
            "rate_limit",
            source.lower(),
            msg="the ICAP handler performs no rate limiting whatsoever",
        )

    def test_attack_throttle_key_is_not_just_the_remote_host(self):
        """Behind an NGFW every client shares one address.

        Keying a bucket on the socket peer alone collapses the whole tenant
        estate into a single limiter, so one noisy caller throttles everyone
        (and, worse, a caller can exhaust the engine by being loud).
        """
        from app.core.resilience import RateLimiter

        same_host_different_tenants = {
            RateLimiter.key_for("acme", "svc-a", "10.0.0.1"),
            RateLimiter.key_for("globex", "svc-b", "10.0.0.1"),
        }
        self.assertEqual(
            len(same_host_different_tenants),
            2,
            msg="tenants sharing a proxy address must not share a bucket",
        )


# ---------------------------------------------------------------------------
# Audit durability
# ---------------------------------------------------------------------------


class AuditDurability(unittest.TestCase):
    """The audit trail lives in a ``deque`` and dies with the process.

    ``config/privacy.yaml`` declares ``storage: secure_s3`` and
    ``retention_days: 365``. What actually runs is a bounded in-memory ring
    buffer. For a firewall the audit trail is the evidence that it was working;
    erasing it on every restart is what makes an incident unreconstructable -
    and a crash is exactly when you need it.
    """

    def test_attack_audit_records_survive_a_restart(self):
        """Two SecurityContexts over the same file must not disagree.

        The trail used to be a bounded ``deque``: a brand-new process started
        with an empty one, so ``GET /audit`` reported a clean slate right after
        a restart - precisely when an operator is trying to find out what
        happened.
        """
        import copy
        import tempfile

        from app.core.config import load_config
        from app.core.security import SecurityContext

        with tempfile.TemporaryDirectory() as tmp:
            audit_file = str(Path(tmp) / "audit.jsonl")

            config = copy.deepcopy(load_config(REPO_ROOT / "config" / "engine_config.yaml"))
            config.security.audit_enabled = True
            config.security.audit_file = audit_file

            first = SecurityContext(copy.deepcopy(config.security))
            first.audit("probe_event", verdict="BLOCK")

            # A restart: brand-new process, brand-new context, same file.
            second = SecurityContext(copy.deepcopy(config.security))
            events = [e.get("event") for e in second.audit_log.entries(1000)]
            self.assertIn(
                "probe_event",
                events,
                msg=(
                    "audit records are lost on restart: a crash erases the "
                    "evidence that the firewall was making decisions"
                ),
            )

    def test_attack_audit_file_is_append_only(self):
        import copy
        import tempfile

        from app.core.config import load_config
        from app.core.security import SecurityContext

        with tempfile.TemporaryDirectory() as tmp:
            audit_file = str(Path(tmp) / "audit.jsonl")
            config = copy.deepcopy(load_config(REPO_ROOT / "config" / "engine_config.yaml"))
            config.security.audit_enabled = True
            config.security.audit_file = audit_file

            context = SecurityContext(copy.deepcopy(config.security))
            for index in range(5):
                context.audit(f"event_{index}")

            lines = [
                ln
                for ln in Path(audit_file).read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            self.assertEqual(
                len(lines), 5, msg="each event must be appended exactly once"
            )

    def test_attack_audit_sink_never_stores_payload_bytes(self):
        """§18: the durable trail is metadata only."""
        import copy
        import json
        import tempfile

        from app.core.config import load_config
        from app.core.security import Principal, Role, SecurityContext

        with tempfile.TemporaryDirectory() as tmp:
            audit_file = str(Path(tmp) / "audit.jsonl")
            config = copy.deepcopy(load_config(REPO_ROOT / "config" / "engine_config.yaml"))
            config.security.audit_enabled = True
            config.security.audit_file = audit_file

            context = SecurityContext(copy.deepcopy(config.security))
            principal = Principal(
                key_id="svc", roles=frozenset({Role.SERVICE_ACCOUNT}), tenant_id="acme"
            )
            context.audit(
                "inspect", principal, verdict="NSFW", content_sha256="deadbeef"
            )
            raw = Path(audit_file).read_text(encoding="utf-8")
            self.assertNotIn("payload", raw)
            entry = json.loads(raw.strip().splitlines()[-1])
            self.assertEqual(entry["tenant_id"], "acme")
            self.assertEqual(entry["content_sha256"], "deadbeef")

    def test_attack_audit_log_has_a_persistent_sink(self):
        from app.core.security import AuditLog

        self.assertTrue(
            hasattr(AuditLog, "flush") or hasattr(AuditLog, "drain_all"),
            msg="AuditLog offers no way to persist or export what it holds",
        )

    def test_attack_audit_config_advertises_persistence(self):
        """The shipped config must not claim a retention it cannot honor."""
        import yaml

        raw = yaml.safe_load(
            (REPO_ROOT / "config" / "engine_config.yaml").read_text(encoding="utf-8")
        )
        audit = (raw.get("security") or {}).get("audit") or {}
        self.assertFalse(
            audit.get("durable", False) is True and not audit.get("backend"),
            msg="audit claims durability with no backend configured",
        )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


class MetricsExposure(unittest.TestCase):
    """``/metrics`` is anonymous, by design, for the Prometheus scrape.

    The residual question is whether it hands out more than a scraper needs.
    Series labeled by tenant reveal the customer roster to anyone who can
    reach the port.
    """

    def test_attack_metrics_do_not_enumerate_tenants(self):
        response = _client().get("/metrics")
        self.assertEqual(response.status_code, 200)
        body = response.text
        self.assertNotIn(
            'tenant="acme"',
            body,
            msg="/metrics exposes individual tenant names to an anonymous caller",
        )

    def test_attack_metrics_scrape_is_configurable_behind_a_token(self):
        from app.core.config import ObservabilityConfig

        config = ObservabilityConfig()
        self.assertTrue(
            hasattr(config, "metrics_token") or hasattr(config, "metrics_auth"),
            msg="no way to put the scrape endpoint behind a credential",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()