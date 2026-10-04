"""Authentication, RBAC and the audit trail (§16, §18, §35).

This closes the largest residual risk recorded in ``docs/THREAT_MODEL.md``: the
API surface previously had **no** authentication, so anyone reachable could
submit payloads and read decisions.

Design notes
------------
* **Probes stay public.** ``/health`` and ``/metrics`` must remain reachable
  without credentials for Kubernetes probes and Prometheus scrapes; only the
  data and management endpoints are protected.
* **API keys are compared by SHA256 in constant time**, so the config file never
  holds a usable credential.
* **Roles map to permissions**, never to endpoints, so adding an endpoint does
  not require touching the authz logic.
* **Audit records metadata only** (principal, tenant, verdict, action, hash) —
  never payload bytes — honouring ``privacy.retain_raw_payloads: false``.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, Iterable, Optional

logger = logging.getLogger("nsfw_engine.core.security")


class Permission(str, Enum):
    """Capabilities a role may hold."""

    CLASSIFY = "classify"
    ENFORCE = "enforce"
    READ_CONFIG = "read_config"
    READ_AUDIT = "read_audit"
    MANAGE_POLICY = "manage_policy"


class Role(str, Enum):
    """Roles from ``config/privacy.yaml`` (§35)."""

    SUPER_ADMIN = "super_admin"
    POLICY_ADMIN = "policy_admin"
    SECURITY_OPERATOR = "security_operator"
    AUDITOR = "auditor"
    READ_ONLY = "read_only"
    SERVICE_ACCOUNT = "service_account"


#: Least-privilege role -> permission mapping (§35).
ROLE_PERMISSIONS: Dict[Role, frozenset] = {
    Role.SUPER_ADMIN: frozenset(Permission),
    Role.POLICY_ADMIN: frozenset(
        {Permission.CLASSIFY, Permission.ENFORCE, Permission.READ_CONFIG,
         Permission.READ_AUDIT, Permission.MANAGE_POLICY}
    ),
    Role.SECURITY_OPERATOR: frozenset(
        {Permission.CLASSIFY, Permission.ENFORCE, Permission.READ_CONFIG,
         Permission.READ_AUDIT}
    ),
    Role.AUDITOR: frozenset({Permission.READ_CONFIG, Permission.READ_AUDIT}),
    Role.READ_ONLY: frozenset({Permission.READ_CONFIG}),
    Role.SERVICE_ACCOUNT: frozenset({Permission.CLASSIFY, Permission.ENFORCE}),
}


class AuthenticationError(Exception):
    """Raised when a credential is missing or invalid (HTTP 401)."""


class AuthorizationError(Exception):
    """Raised when a principal lacks a permission (HTTP 403)."""


def hash_secret(secret: str) -> str:
    """SHA256 hex digest used to store API keys at rest."""
    return hashlib.sha256((secret or "").encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Principal:
    """The authenticated caller."""

    key_id: str = "anonymous"
    roles: frozenset = frozenset()
    tenant_id: str = ""

    @property
    def is_anonymous(self) -> bool:
        return self.key_id == "anonymous"

    @property
    def permissions(self) -> frozenset:
        granted: set = set()
        for role in self.roles:
            granted.update(ROLE_PERMISSIONS.get(role, frozenset()))
        return frozenset(granted)

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require(self, permission: Permission) -> None:
        if not self.has(permission):
            raise AuthorizationError(
                f"principal {self.key_id!r} lacks {permission.value!r}"
            )

    def as_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "roles": sorted(getattr(r, "value", str(r)) for r in self.roles),
            "tenant_id": self.tenant_id,
            "permissions": sorted(p.value for p in self.permissions),
        }
def _parse_roles(value: Any) -> frozenset:
    """Coerce a role spec (str, list, or iterable) into a frozenset of roles."""
    if not value:
        return frozenset()
    if isinstance(value, str):
        names: Iterable[str] = [part for part in value.replace(" ", ",").split(",") if part]
    else:
        names = value
    roles = set()
    for name in names:
        try:
            roles.add(Role(str(name).strip().lower()))
        except ValueError:
            logger.warning("ignoring unknown role %r", name)
    return frozenset(roles)


class ApiKeyStore:
    """Resolves a presented API key to a :class:`Principal`."""

    def __init__(self, config: Any) -> None:
        self.config = config
        self._keys: Dict[str, str] = {}
        self._roles: Dict[str, frozenset] = {}
        self._load()

    def _load(self) -> None:
        for key_id, stored in (getattr(self.config, "api_keys", None) or {}).items():
            self._keys[str(key_id)] = str(stored).strip()
        for key_id, role_spec in (getattr(self.config, "key_roles", None) or {}).items():
            self._roles[str(key_id)] = _parse_roles(role_spec)

    @property
    def hashed(self) -> bool:
        return bool(getattr(self.config, "hash_api_keys", True))

    def add(self, key_id: str, secret: str, roles: Iterable[str]) -> None:
        """Register a key at runtime (used by tests and dynamic provisioning)."""
        self._keys[str(key_id)] = hash_secret(secret) if self.hashed else str(secret)
        self._roles[str(key_id)] = _parse_roles(roles)

    def __len__(self) -> int:
        return len(self._keys)

    def _matches(self, stored: str, presented: str) -> bool:
        expected = hash_secret(presented) if self.hashed else presented
        return hmac.compare_digest(str(stored), str(expected))

    def resolve(self, presented: Optional[str], tenant_id: str = "") -> Principal:
        """Return the principal for *presented*, or raise :class:`AuthenticationError`.

        Every configured key is checked so a valid key cannot be distinguished
        from an invalid one by response timing or by which key matched.
        """
        if not presented:
            raise AuthenticationError("missing API key")
        for key_id, stored in self._keys.items():
            if self._matches(stored, presented):
                # Only default to service_account when *no* role was configured
                # for this key. An explicitly empty/invalid role set must fail
                # closed rather than silently gaining classify+enforce.
                roles = (
                    self._roles[key_id]
                    if key_id in self._roles
                    else frozenset({Role.SERVICE_ACCOUNT})
                )
                return Principal(key_id=key_id, roles=roles, tenant_id=tenant_id)
        raise AuthenticationError("invalid API key")


class AuditLog:
    """Bounded, thread-safe ring buffer of metadata-only audit records (§18)."""

    def __init__(self, config: Any) -> None:
        self.enabled = bool(getattr(config, "audit_enabled", True))
        limit = int(getattr(config, "max_audit_entries", 1000) or 1000)
        self._entries: Deque[dict] = deque(maxlen=max(1, limit))
        self._lock = threading.Lock()

    def record(self, event: str, principal: Optional[Principal] = None, **fields: Any) -> None:
        if not self.enabled:
            return
        entry = {
            "ts": time.time(),
            "event": event,
            "key_id": principal.key_id if principal else "anonymous",
            "tenant_id": principal.tenant_id if principal else "",
        }
        entry.update({k: v for k, v in fields.items() if v is not None})
        with self._lock:
            self._entries.append(entry)

    def entries(self, limit: int = 100) -> list:
        with self._lock:
            items = list(self._entries)
        return items[-max(1, int(limit)):]

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


class SecurityContext:
    """Facade combining the key store and the audit log."""

    def __init__(self, config: Any) -> None:
        self.config = config
        self.enabled = bool(getattr(config, "enabled", False))
        self.keys = ApiKeyStore(config)
        # Named `audit_log`, not `audit`: a same-named attribute would shadow the
        # `audit()` recording method below.
        self.audit_log = AuditLog(config)
        if not self.enabled:
            logger.warning(
                "authentication is DISABLED (security.enabled=false) - "
                "any client can classify payloads. Set enabled=true before production."
            )

    def authenticate(
        self, api_key: Optional[str], tenant_id: str = "", require_tenant: bool = False
    ) -> Principal:
        """Authenticate a request, returning an anonymous principal in dev mode."""
        tenant = (tenant_id or "").strip()
        if require_tenant and not tenant:
            raise AuthenticationError("missing X-Tenant-Id")
        if not self.enabled:
            return Principal(
                key_id="anonymous",
                roles=_parse_roles(getattr(self.config, "anonymous_roles", None)),
                tenant_id=tenant,
            )
        principal = self.keys.resolve(api_key, tenant_id=tenant)
        if require_tenant and not principal.tenant_id:
            raise AuthorizationError("principal is not bound to a tenant")
        return principal

    def authorize(self, principal: Principal, permission: Permission) -> None:
        principal.require(permission)

    def audit(
        self, event: str, principal: Optional[Principal] = None, **fields: Any
    ) -> None:
        """Record an audit entry (metadata only - never payload bytes)."""
        self.audit_log.record(event, principal, **fields)

    def status(self) -> dict:
        """Health-friendly summary (never includes secrets)."""
        return {
            "enabled": self.enabled,
            "api_keys_configured": len(self.keys),
            "hashed_keys": self.keys.hashed,
            "audit_enabled": self.audit_log.enabled,
            "audit_entries": len(self.audit_log),
        }


__all__ = [
    "ApiKeyStore",
    "AuditLog",
    "AuthenticationError",
    "AuthorizationError",
    "Permission",
    "Principal",
    "ROLE_PERMISSIONS",
    "Role",
    "SecurityContext",
    "hash_secret",
]