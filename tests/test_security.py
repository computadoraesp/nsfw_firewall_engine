"""Security tests: authentication, RBAC, tenant scoping and the audit trail.

Covers `pront.md` §16, §18 and §35, and retires residual risk #1 from
`docs/THREAT_MODEL.md` (no auth on the API surface).
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import SecurityConfig, load_config  # noqa: E402
from app.core.security import (  # noqa: E402
    ROLE_PERMISSIONS,
    ApiKeyStore,
    AuditLog,
    AuthenticationError,
    AuthorizationError,
    Permission,
    Principal,
    Role,
    SecurityContext,
    hash_secret,
)


def config(**kwargs) -> SecurityConfig:
    base = dict(
        enabled=True,
        hash_api_keys=True,
        api_keys={},
        key_roles={},
        audit_enabled=True,
    )
    base.update(kwargs)
    return SecurityConfig(**base)


class RoleTests(unittest.TestCase):
    def test_every_role_is_mapped(self):
        for role in Role:
            self.assertIn(role, ROLE_PERMISSIONS)

    def test_service_account_cannot_manage_policy(self):
        roles = ROLE_PERMISSIONS[Role.SERVICE_ACCOUNT]
        self.assertIn(Permission.CLASSIFY, roles)
        self.assertNotIn(Permission.MANAGE_POLICY, roles)

    def test_read_only_cannot_classify(self):
        roles = ROLE_PERMISSIONS[Role.READ_ONLY]
        self.assertIn(Permission.READ_CONFIG, roles)
        self.assertNotIn(Permission.CLASSIFY, roles)

    def test_super_admin_has_every_permission(self):
        self.assertEqual(ROLE_PERMISSIONS[Role.SUPER_ADMIN], frozenset(Permission))

    def test_principal_unions_permissions_across_roles(self):
        principal = Principal(key_id="k", roles=frozenset({Role.READ_ONLY, Role.AUDITOR}))
        self.assertTrue(principal.has(Permission.READ_AUDIT))
        self.assertFalse(principal.has(Permission.ENFORCE))

    def test_require_raises_authorization_error(self):
        principal = Principal(key_id="k", roles=frozenset({Role.READ_ONLY}))
        with self.assertRaises(AuthorizationError):
            principal.require(Permission.CLASSIFY)

    def test_principal_serialises(self):
        payload = Principal(key_id="k", roles=frozenset({Role.READ_ONLY})).as_dict()
        self.assertEqual(payload["key_id"], "k")
        self.assertIn("read_only", payload["roles"])


class ApiKeyStoreTests(unittest.TestCase):
    def test_resolves_hashed_key(self):
        store = ApiKeyStore(config(api_keys={"k1": hash_secret("s3cret")}))
        store.add("k1", "s3cret", ["service_account"])
        principal = store.resolve("s3cret")
        self.assertEqual(principal.key_id, "k1")
        self.assertTrue(principal.has(Permission.CLASSIFY))

    def test_rejects_wrong_key(self):
        store = ApiKeyStore(config(api_keys={"k1": hash_secret("s3cret")}))
        store.add("k1", "s3cret", ["service_account"])
        with self.assertRaises(AuthenticationError):
            store.resolve("wrong")

    def test_rejects_missing_key(self):
        store = ApiKeyStore(config(api_keys={"k1": hash_secret("s")}))
        with self.assertRaises(AuthenticationError):
            store.resolve(None)

    def test_plaintext_mode(self):
        store = ApiKeyStore(config(hash_api_keys=False, api_keys={"k1": "plain"}))
        store.add("k1", "plain", ["read_only"])
        self.assertEqual(store.resolve("plain").key_id, "k1")

    def test_unknown_role_is_ignored(self):
        store = ApiKeyStore(config(api_keys={"k1": hash_secret("s")}))
        store.add("k1", "s", ["not_a_role"])
        self.assertEqual(store.resolve("s").roles, frozenset())
class SecurityContextTests(unittest.TestCase):
    def test_disabled_returns_anonymous_principal(self):
        context = SecurityContext(config(enabled=False, anonymous_roles=["service_account"]))
        principal = context.authenticate(None)
        self.assertTrue(principal.is_anonymous)
        self.assertTrue(principal.has(Permission.CLASSIFY))

    def test_enabled_requires_key(self):
        context = SecurityContext(config(enabled=True, api_keys={"k": hash_secret("s")}))
        with self.assertRaises(AuthenticationError):
            context.authenticate(None)

    def test_tenant_is_bound_to_principal(self):
        context = SecurityContext(
            config(enabled=True, api_keys={"k": hash_secret("s")}, key_roles={"k": "service_account"})
        )
        principal = context.authenticate("s", tenant_id="acme")
        self.assertEqual(principal.tenant_id, "acme")

    def test_require_tenant_header(self):
        context = SecurityContext(config(enabled=True, require_tenant_header=True))
        with self.assertRaises(AuthenticationError):
            context.authenticate(None, tenant_id="")

    def test_status_never_leaks_secrets(self):
        context = SecurityContext(config(enabled=True, api_keys={"k": hash_secret("secret")}))
        status = context.status()
        self.assertTrue(status["enabled"])
        self.assertEqual(status["api_keys_configured"], 1)
        self.assertNotIn("secret", repr(status))


class AuditLogTests(unittest.TestCase):
    def test_records_metadata_only(self):
        audit = AuditLog(config())
        principal = Principal(key_id="k1", roles=frozenset({Role.SERVICE_ACCOUNT}), tenant_id="acme")
        audit.record("classify", principal, verdict="NSFW", action="BLOCK")
        entry = audit.entries()[-1]
        self.assertEqual(entry["verdict"], "NSFW")
        self.assertEqual(entry["key_id"], "k1")
        self.assertEqual(entry["tenant_id"], "acme")

    def test_is_bounded(self):
        audit = AuditLog(config(max_audit_entries=5))
        for index in range(20):
            audit.record("classify", None, index=index)
        self.assertEqual(len(audit), 5)

    def test_limit_returns_tail(self):
        audit = AuditLog(config())
        for index in range(10):
            audit.record("e", None, index=index)
        self.assertEqual(audit.entries(limit=3)[-1]["index"], 9)

    def test_disabled_audit_records_nothing(self):
        audit = AuditLog(config(audit_enabled=False))
        audit.record("classify")
        self.assertEqual(len(audit), 0)


class ConfigWiringTests(unittest.TestCase):
    def test_security_section_is_loaded(self):
        cfg = load_config()
        self.assertFalse(cfg.security.enabled)
        self.assertTrue(cfg.security.audit_enabled)
        self.assertIn("classifier", cfg.security.key_roles)

    def test_bad_role_spec_is_survivable(self):
        cfg = SecurityConfig(anonymous_roles=["read_only", "bogus"])
        principal = SecurityContext(cfg).authenticate(None)
        self.assertIn(Role.READ_ONLY, principal.roles)


class RestAuthWiringTests(unittest.TestCase):
    """Route wiring, without needing the (env-broken) TestClient transport."""

    def _paths(self):
        from app.api.rest.router import create_app

        secured, public = [], []
        for route in create_app().routes:
            dependant = getattr(route, "dependant", None)
            if dependant is None:
                continue
            permissions = [
                getattr(dep.call, "__nsfw_permission__", None)
                for dep in dependant.dependencies
            ]
            (secured if any(permissions) else public).append(route.path)
        return secured, public

    def test_probes_stay_public(self):
        # Kubernetes probes and Prometheus scrapes must not need credentials.
        _, public = self._paths()
        for path in ("/health", "/metrics", "/"):
            self.assertIn(path, public, f"{path} must stay public")

    def test_data_endpoints_are_protected(self):
        secured, _ = self._paths()
        for path in ("/classify", "/enforce", "/config"):
            self.assertIn(path, secured, f"{path} must be protected")

    def test_app_exposes_security_context(self):
        from app.api.rest.router import create_app

        self.assertIsNotNone(getattr(create_app().state, "security", None))

    def test_engine_health_reports_security(self):
        from app.core.engine import NsfwEngine

        info = NsfwEngine(load_config()).health()
        self.assertIn("security", info)
        self.assertIn("enabled", info["security"])


if __name__ == "__main__":
    unittest.main(verbosity=2)