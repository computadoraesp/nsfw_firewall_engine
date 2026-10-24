"""Red-team exploit harness (iterative hardening).

Each test performs the **actual attack** and then asserts the security property
the system must hold. A failure means the vulnerability is *live*, not that the
test is wrong - these are written as exploits, not as unit tests of intent.

Grouped by the iteration in which they were found:

* ``AuthBypassExploits``   - C1: unauthenticated classification.
* ``TenantEscapeExploits`` - C5: ``X-Tenant-Id`` is client-asserted and unverified.
* ``ResourceExhaustion``   - H1/H2: unbounded metric labels, no pre-auth throttle.
* ``ConfigFailOpen``       - C3/C4: committed credential, silent downgrade.
* ``StaticGuards``         - C2/M8: controls that exist only in a comment.

Run with::

    python -m pytest tests/test_redteam.py -v
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

REPO_ROOT = Path(__file__).resolve().parents[1]

#: SHA256("test") - the value committed at config/engine_config.yaml.
SHA256_OF_TEST = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

#: The credential the harness provisions, standing in for one stolen from a
#: real deployment. It is bound to tenant ``acme``; the victim tenant is
#: ``victim-corp``.
VALID_KEY = "red-team-owned-service-key"
OWN_TENANT = "acme"
VICTIM_TENANT = "victim-corp"


#: A real, minimal 1x1 PNG. The MIME allow-list is enforced on the
#: classification path, so a "legitimate caller" test must actually send
#: something legitimate - the earlier version sent ``VALID_PNG_B64`` (the bytes
#: ``hi``), which is not an image and is now correctly refused with 415.
VALID_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmM"
    "IQAAAABJRU5ErkJggg=="
)


def _auth(tenant: str = OWN_TENANT) -> dict:
    """Headers carrying a legitimate service-account credential."""
    return {"X-API-Key": VALID_KEY, "X-Tenant-Id": tenant}


class AsgiClient:
    """Minimal ASGI caller.

    ``fastapi.testclient.TestClient`` is unusable in this environment: the
    installed ``httpx`` (0.13.3) predates ``BaseTransport``, which starlette
    1.0.1 requires. Rather than pin a dependency, the harness speaks ASGI
    directly - which is also a more honest attack surface, since it exercises
    exactly the app an HTTP client would reach.
    """

    def __init__(self, app):
        self.app = app

    def request(self, method, path, *, headers=None, json=None, content=None,
                query=b""):
        import json as jsonlib
        import urllib.parse

        import anyio

        headers = dict(headers or {})
        if json is not None:
            body = jsonlib.dumps(json).encode()
            headers.setdefault("content-type", "application/json")
        elif content is not None:
            body = content if isinstance(content, bytes) else str(content).encode()
        else:
            body = b""

        raw_headers = [
            (k.lower().encode(), str(v).encode()) for k, v in headers.items()
        ]
        raw_headers.append((b"content-length", str(len(body)).encode()))

        parsed = urllib.parse.urlsplit(path)
        # Preserve the query string: several endpoints take tenant_id / media_type
        # as Query() params, and silently dropping it made those exploits report
        # a false negative.
        merged_query = parsed.query
        if query:
            extra = query.decode() if isinstance(query, bytes) else query
            merged_query = f"{merged_query}&{extra}" if merged_query else extra
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": "http",
            "path": parsed.path,
            "raw_path": parsed.path.encode(),
            "query_string": merged_query.encode(),
            "root_path": "",
            "headers": raw_headers,
            "client": ("10.0.0.99", 54321),
            "server": ("testserver", 80),
        }

        sent = {"done": False}

        async def receive():
            if sent["done"]:
                return {"type": "http.disconnect"}
            sent["done"] = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            if message["type"] == "http.response.start":
                scope["_status"] = message["status"]
                scope["_headers"] = message.get("headers", [])
            elif message["type"] == "http.response.body":
                scope.setdefault("_body", b"")
                scope["_body"] += message.get("body", b"")

        anyio.run(self.app, scope, receive, send)

        class _Response:
            status_code = scope.get("_status", 0)
            content = scope.get("_body", b"")

            @property
            def text(self):
                return self.content.decode("utf-8", errors="replace")

            def json(self):
                return jsonlib.loads(self.text or "{}")

        return _Response()

    # Convenience verbs mirroring TestClient's surface.
    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)


def _client():
    """Build an ASGI client over a real engine with auth *enabled*.

    The shipped configuration intentionally provisions no credentials any more
    (see ``config/engine_config.yaml``), so the harness injects one the way a
    deployment would - through the environment overlay - and binds it to a
    tenant, exactly as a real service account would be.
    """
    from app.api.rest.router import create_app
    from app.core.config import load_config
    from app.core.engine import NsfwEngine
    from app.core.security import hash_secret

    config = load_config(REPO_ROOT / "config" / "engine_config.yaml")
    config.security.enabled = True
    config.security.api_keys = {"svc": hash_secret(VALID_KEY)}
    config.security.key_roles = {"svc": "service_account"}
    config.security.key_tenants = {"svc": OWN_TENANT}
    config.security.allow_unbound_tenant_header = False
    engine = NsfwEngine(config)
    return AsgiClient(create_app(engine=engine, config=config))


# ---------------------------------------------------------------------------
# C1 - unauthenticated classification
# ---------------------------------------------------------------------------


class AuthBypassExploits(unittest.TestCase):
    """C1: two legacy endpoints carry no authentication dependency at all."""

    @classmethod
    def setUpClass(cls):
        cls.client = _client()

    def test_attack_anonymous_classify_text_is_refused(self):
        """ATTACK: POST /classify/text with no X-API-Key."""
        response = self.client.post(
            "/classify/text", json={"text": "an ordinary sentence", "media_type": "TEXT"}
        )
        self.assertIn(
            response.status_code,
            (401, 403),
            msg=f"UNAUTHENTICATED CLASSIFICATION ACCEPTED (got {response.status_code})",
        )

    def test_attack_anonymous_classify_text_html_is_refused(self):
        """ATTACK: the HTML path, which is the one that feeds policy context."""
        response = self.client.post(
            "/classify/text",
            json={
                "text": "<html><head><title>x</title></head><body>y</body></html>",
                "media_type": "HTML",
            },
        )
        self.assertIn(response.status_code, (401, 403), msg="HTML path is anonymous")

    def test_attack_anonymous_classify_raw_is_refused(self):
        """ATTACK: POST /classify/raw with an arbitrary binary body."""
        response = self.client.post(
            "/classify/raw?media_type=IMAGE", content=b"\x89PNG\r\n\x1a\n" + b"A" * 256
        )
        self.assertIn(
            response.status_code,
            (401, 403),
            msg=f"UNAUTHENTICATED RAW CLASSIFICATION ACCEPTED (got {response.status_code})",
        )

    def test_attack_bogus_key_is_refused_everywhere(self):
        """ATTACK: a forged key must be rejected on every classify surface."""
        headers = {"X-API-Key": "forged-key-that-does-not-exist"}
        for path, kwargs in (
            ("/classify", {"json": {"image_base64": VALID_PNG_B64}}),
            ("/classify/text", {"json": {"text": "hi", "media_type": "TEXT"}}),
            ("/classify/raw", {"content": b"data"}),
            ("/v1/inspect", {"json": {"content_base64": VALID_PNG_B64}}),
            ("/v1/classify/text", {"json": {"text": "hi", "media_type": "TEXT"}}),
            ("/v1/batch", {"json": {"items": [{"content_base64": VALID_PNG_B64}]}}),
        ):
            with self.subTest(path=path):
                response = self.client.post(path, headers=headers, **kwargs)
                self.assertIn(
                    response.status_code,
                    (401, 403),
                    msg=f"{path} accepted a forged key ({response.status_code})",
                )


# ---------------------------------------------------------------------------
# C5 - tenant escape via a client-asserted header
# ---------------------------------------------------------------------------


class TenantEscapeExploits(unittest.TestCase):
    """C5: nothing binds an API key to a tenant, so the header is believed."""

    @classmethod
    def setUpClass(cls):
        cls.client = _client()

    def test_attack_spoofed_tenant_header_is_refused(self):
        """ATTACK: a valid key for ``acme`` claims to be ``victim-corp``."""
        response = self.client.post(
            "/v1/inspect",
            headers=_auth(VICTIM_TENANT),
            json={"content_base64": VALID_PNG_B64, "media_type": "TEXT"},
        )
        self.assertIn(
            response.status_code,
            (401, 403),
            msg=f"TENANT SPOOF ACCEPTED (got {response.status_code})",
        )

    def test_attack_spoofed_tenant_on_legacy_enforce_is_refused(self):
        """ATTACK: the legacy enforcement path resolves policy by tenant."""
        response = self.client.post(
            "/enforce", headers=_auth(VICTIM_TENANT), json={"image_base64": VALID_PNG_B64}
        )
        self.assertIn(
            response.status_code,
            (401, 403),
            msg=f"TENANT SPOOF ACCEPTED ON /enforce (got {response.status_code})",
        )

    def test_attack_spoofed_tenant_on_classify_text_is_refused(self):
        """ATTACK: the newly-locked legacy text endpoint, same header."""
        response = self.client.post(
            "/classify/text",
            headers=_auth(VICTIM_TENANT),
            json={"text": "hi", "media_type": "TEXT"},
        )
        self.assertIn(
            response.status_code,
            (401, 403),
            msg=f"TENANT SPOOF ACCEPTED ON /classify/text (got {response.status_code})",
        )

    def test_attack_spoofed_tenant_query_param_is_refused(self):
        """ATTACK: /enforce also takes tenant_id as a query parameter."""
        response = self.client.post(
            f"/enforce?tenant_id={VICTIM_TENANT}",
            headers=_auth(OWN_TENANT),
            json={"image_base64": VALID_PNG_B64},
        )
        self.assertIn(
            response.status_code,
            (401, 403),
            msg=f"TENANT SPOOF VIA QUERY PARAM ACCEPTED (got {response.status_code})",
        )

    def test_binding_is_authoritative_for_a_legitimate_caller(self):
        """The fix must not break the caller the key actually belongs to."""
        response = self.client.post(
            "/v1/inspect",
            headers=_auth(OWN_TENANT),
            json={"content_base64": VALID_PNG_B64, "media_type": "TEXT"},
        )
        self.assertEqual(
            response.status_code, 200, msg=f"legitimate caller rejected: {response.text[:200]}"
        )

    def test_key_store_can_bind_a_tenant(self):
        """The store must expose a key->tenant binding at all.

        Without one there is nothing for the authenticator to check the
        ``X-Tenant-Id`` header against, which is the root cause of C5.
        """
        from app.core.config import SecurityConfig
        from app.core.security import ApiKeyStore, SecurityContext, hash_secret

        context = SecurityContext(
            SecurityConfig(
                enabled=True,
                hash_api_keys=True,
                api_keys={"k1": hash_secret("s")},
                key_roles={"k1": "service_account"},
                key_tenants={"k1": "acme"},
            )
        )
        self.assertEqual(context.keys.tenant_for("k1"), "acme")
        self.assertIsInstance(context.keys, ApiKeyStore)

    def test_unbound_key_cannot_assert_a_tenant(self):
        """An unbound key claiming a tenant must fail closed."""
        from app.core.config import SecurityConfig
        from app.core.security import AuthorizationError, SecurityContext, hash_secret

        context = SecurityContext(
            SecurityConfig(
                enabled=True,
                hash_api_keys=True,
                api_keys={"k1": hash_secret("s")},
                key_roles={"k1": "service_account"},
                key_tenants={},
                allow_unbound_tenant_header=False,
            )
        )
        with self.assertRaises(AuthorizationError):
            context.authenticate("s", tenant_id="victim-corp")

    def test_resolve_does_not_leak_key_position_by_timing(self):
        """H7: the match must not short-circuit the comparison loop."""
        import inspect as pyinspect

        from app.core.security import ApiKeyStore

        source = pyinspect.getsource(ApiKeyStore.resolve)
        body = source.split('"""')[-1]
        self.assertNotIn(
            "return Principal(",
            body.split("if matched_id is None")[0],
            msg=(
                "resolve() returns from inside the comparison loop, so total "
                "runtime is proportional to the matching key's index"
            ),
        )


# ---------------------------------------------------------------------------
# H1 / H2 - resource exhaustion
# ---------------------------------------------------------------------------


class PolicyEscapeExploits(unittest.TestCase):
    """H4/H5: reading and writing policies across tenant boundaries."""

    #: A policy document that, if installed globally, switches the firewall off.
    DISABLE_ALL = {
        "policy_id": "attacker-global",
        "description": "allow everything",
        "default_action": "allow",
        "tenant_id": "",
        "rules": [{"field": "*", "operator": "==", "value": "*", "action": "allow"}],
    }

    def _harness(self, *, roles):
        from app.api.rest.router import create_app
        from app.core.config import load_config
        from app.core.engine import NsfwEngine
        from app.core.security import _parse_roles, hash_secret

        config = load_config(REPO_ROOT / "config" / "engine_config.yaml")
        config.security.enabled = True
        config.security.api_keys = {"ops": hash_secret(VALID_KEY)}
        config.security.key_roles = {"ops": ",".join(roles)}
        config.security.key_tenants = {"ops": OWN_TENANT}
        engine = NsfwEngine(config)
        return AsgiClient(create_app(engine=engine, config=config)), _parse_roles(roles)

    def test_attack_read_another_tenants_policy(self):
        """H4: ask for a tenant you are not bound to."""
        client, _ = self._harness(roles=["auditor"])
        response = client.get(
            f"/v1/policies?tenant_id={VICTIM_TENANT}", headers=_auth()
        )
        self.assertIn(
            response.status_code,
            (401, 403),
            msg=f"CROSS-TENANT POLICY READ ACCEPTED (got {response.status_code})",
        )

    def test_attack_policy_admin_cannot_rewrite_the_global_policy(self):
        """H5: omit tenant_id and the guard used to let anyone go global."""
        client, _ = self._harness(roles=["policy_admin"])
        response = client.post("/v1/policies", headers=_auth(), json=self.DISABLE_ALL)
        self.assertIn(
            response.status_code,
            (401, 403),
            msg=(
                "POLICY_ADMIN REWROTE THE GLOBAL POLICY "
                f"(got {response.status_code}) - the whole firewall can be "
                "switched to allow"
            ),
        )

    def test_attack_policy_admin_cannot_write_another_tenant(self):
        """H5: name a tenant you do not own."""
        client, _ = self._harness(roles=["policy_admin"])
        document = dict(self.DISABLE_ALL, tenant_id=VICTIM_TENANT)
        response = client.post("/v1/policies", headers=_auth(), json=document)
        self.assertIn(
            response.status_code,
            (401, 403),
            msg=f"CROSS-TENANT POLICY WRITE ACCEPTED (got {response.status_code})",
        )

    def test_super_admin_may_still_write_the_global_policy(self):
        """The fix must not lock out the legitimate operator."""
        client, _ = self._harness(roles=["super_admin"])
        response = client.post("/v1/policies", headers=_auth(), json=self.DISABLE_ALL)
        self.assertEqual(
            response.status_code, 201, msg=f"super_admin refused: {response.text[:200]}"
        )


class ResourceExhaustionExploits(unittest.TestCase):
    """H1: unbounded Prometheus label cardinality. H2: no pre-auth throttle."""

    def test_attack_metric_label_cardinality_is_bounded(self):
        """ATTACK: rotate X-Tenant-Id to create one permanent series per value.

        This runs through the public ``/health`` probe - no credential needed,
        because the metrics middleware fires before authentication.
        """
        import app.core.metrics as metrics

        before = metrics.render_latest()
        client = _client()

        def request_series():
            return [
                line
                for line in metrics.render_latest().splitlines()
                if line.startswith("nsfw_requests_total")
            ]

        # Batch 1: 2000 distinct header values from an unauthenticated client.
        for i in range(2000):
            client.get("/health", headers={"X-Tenant-Id": f"tenant-{i}"})
        after_first = len(request_series())

        # Batch 2: a completely different 2000 values.
        for i in range(2000, 4000):
            client.get("/health", headers={"X-Tenant-Id": f"tenant-{i}"})
        after_second = len(request_series())

        # The property that matters is that the second batch of 2000 *new*
        # header values allocates no new series: cardinality is bounded by the
        # budget, not by how hard the client pushes.
        self.assertLess(
            after_second - after_first,
            5,
            msg=(
                f"UNBOUNDED METRIC CARDINALITY: 2000 further distinct "
                f"X-Tenant-Id values created {after_second - after_first} new "
                f"series ({after_first} -> {after_second}). A remote "
                "unauthenticated client can OOM the process and Prometheus."
            ),
        )
        # And the overflow bucket must actually be in use, so the traffic stays
        # observable instead of being silently discarded.
        self.assertTrue(
            any(metrics.LABEL_OVERFLOW in line for line in request_series()),
            msg="overflow bucket never emitted - cardinality bound is inert",
        )
        # Per endpoint, the tenant label must stay inside its budget.
        health_series = [ln for ln in request_series() if 'endpoint="/health"' in ln]
        self.assertLessEqual(
            len(health_series),
            metrics.MAX_LABEL_VALUES + 1,
            msg=(
                f"{len(health_series)} tenant series for a single endpoint, "
                f"budget {metrics.MAX_LABEL_VALUES}"
            ),
        )

    def test_attack_legacy_endpoints_have_a_pre_auth_throttle(self):
        """H2: every data endpoint must carry the pre-auth IP limiter."""
        from app.api.rest.router import enforce_ip_rate_limit, router

        guarded = set()
        for route in router.routes:
            dependant = getattr(route, "dependant", None)
            if dependant is None:
                continue
            stack = [dependant]
            while stack:
                current = stack.pop()
                for sub in getattr(current, "dependencies", []) or []:
                    if getattr(sub, "call", None) is enforce_ip_rate_limit:
                        guarded.add(route.path)
                    stack.append(sub)

        for path in ("/classify", "/classify/text", "/classify/raw", "/enforce"):
            with self.subTest(path=path):
                self.assertIn(
                    path,
                    guarded,
                    msg=f"{path} has no pre-auth IP rate limiter (brute-forceable)",
                )


# ---------------------------------------------------------------------------
# C3 / C4 - configuration fail-open
# ---------------------------------------------------------------------------


class ConfigFailOpenExploits(unittest.TestCase):
    """C3: a real credential committed to the repo. C4: silent downgrade."""

    def test_attack_no_known_credential_is_committed(self):
        """ATTACK: read the config out of the repository and log in."""
        text = (REPO_ROOT / "config" / "engine_config.yaml").read_text(encoding="utf-8")
        self.assertNotIn(
            SHA256_OF_TEST,
            text,
            msg="SHA256('test') is committed: the key is literally the word 'test'",
        )

    def test_attack_configured_keys_are_not_guessable(self):
        """No shipped key may be the digest of a trivially guessable secret."""
        import hashlib

        from app.core.config import load_config

        config = load_config(REPO_ROOT / "config" / "engine_config.yaml")
        trivially_guessable = {
            "test",
            "password",
            "secret",
            "admin",
            "changeme",
            "key",
            "1234",
            "nsfw",
            "firewall",
        }
        for key_id, stored in (config.security.api_keys or {}).items():
            digest = stored.strip().lower()
            for guess in trivially_guessable:
                if hashlib.sha256(guess.encode()).hexdigest() == digest:
                    self.fail(
                        f"api_keys[{key_id!r}] is the digest of the guessable "
                        f"secret {guess!r}"
                    )

    def test_attack_missing_config_aborts_instead_of_defaulting(self):
        """C4: a missing YAML must stop the process, not disable the firewall.

        Returning ``{}`` silently yields security.enabled=False,
        rate_limit_enabled=False and fail_action=ALLOW - the engine starts
        green with no authentication at all.
        """
        from app.core.config import load_config

        with self.assertRaises(Exception):
            load_config(REPO_ROOT / "config" / "__does_not_exist__.yaml")


# ---------------------------------------------------------------------------
# C2 / M8 - controls that are only comments
# ---------------------------------------------------------------------------


class StaticGuards(unittest.TestCase):
    """Deployment-level guards that no unit test can reach."""

    def test_container_entrypoint_runs_the_production_gate(self):
        """C2: the CMD must go through app.main, which enforces the gates."""
        import json as jsonlib
        import re

        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        exec_form = re.findall(r"^CMD\s+(\[.*?\])\s*$", dockerfile, re.MULTILINE)
        self.assertTrue(exec_form, msg="no exec-form CMD found in the Dockerfile")
        cmd = jsonlib.loads(exec_form[-1])
        self.assertIn(
            "app.main",
            " ".join(cmd),
            msg=(
                f"Dockerfile CMD is {cmd!r}. app.api.rest.router builds the app "
                "directly and therefore SKIPS validate_security_dependencies() "
                "and the security.enabled=false abort in app/main.py."
            ),
        )

    def test_security_yaml_keys_are_real_pydantic_fields(self):
        """M8: a control declared in YAML but absent from the model is dead."""
        import yaml

        from app.core.config import EngineConfig

        raw = yaml.safe_load(
            (REPO_ROOT / "config" / "engine_config.yaml").read_text(encoding="utf-8")
        )
        for section, key in (
            ("engine", "require_auth_in_production"),
            ("resilience", "breaker_fail_closed"),
        ):
            if key in (raw.get(section) or {}):
                with self.subTest(section=section, key=key):
                    self.assertIn(
                        key,
                        EngineConfig.model_fields[section].annotation.model_fields,
                        msg=(
                            f"{section}.{key} is set in YAML but is not a model "
                            "field: pydantic drops it, so the control is a comment."
                        ),
                    )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
