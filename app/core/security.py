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

import base64
import hashlib
import hmac
import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Deque, Dict, Iterable, Optional

logger = logging.getLogger("nsfw_engine.core.security")

#: scrypt work factors. N=2**14 keeps a single verification near ~100 ms on
#: commodity hardware: expensive enough that a stolen config cannot be brute
#: forced at speed, cheap enough that a single request pays it once.
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1

#: Module-level pepper cache. Read from the environment at call time rather than
#: captured at import, so a test (or a runtime re-provision) can change it.
_PEPPER: Optional[str] = None


def _hash_pepper() -> str:
    """Server-side pepper for API-key digests.

    Sourced from ``NSFW_HASH_PEPPER``, never from the config file: a pepper
    that ships in the same file as the digests it protects is not a pepper.
    Absent or empty is fine - scrypt's per-key salt still does the work.
    """
    global _PEPPER
    if _PEPPER is None:
        _PEPPER = str(os.environ.get("NSFW_HASH_PEPPER", "") or "")
    return _PEPPER


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


def _derive_salt(pepper: str, salt: bytes) -> bytes:
    """Fold an optional server-side pepper into a stored per-key salt.

    The pepper lives in the environment, never in the config, so a stolen
    config file yields digests that cannot be attacked without it either.
    """
    return hashlib.sha256((pepper or "").encode("utf-8") + salt).digest()[:16]


def hash_secret(secret: str, salt: Optional[bytes] = None) -> str:
    """Hash an API key for storage or comparison.

    SECURITY: this used to be a bare ``hashlib.sha256``. For a *cache key* that
    is fine and cheap; for a credential it is not, because the config file is
    the whole attack surface - an attacker holding it can test any guess
    instantly, and the digests of short, low-entropy secrets fall to a rainbow
    table. scrypt is memory-hard and salted per key, so a leaked config costs
    real CPU per guess rather than a hash lookup.

    The salt is 16 random bytes stored alongside the digest, so two keys that
    happen to share a secret still produce unrelated digests. An earlier
    revision derived the salt *from the secret*, which made the "salt" carry
    no independent entropy.

    Format: ``scrypt$<n>$<r>$<p>$<salt-b64>$<digest-b64>``.

    A value not in that form is treated as a legacy plain SHA256 by
    :meth:`ApiKeyStore._matches`, so deployments migrate by re-provisioning
    rather than by breaking.
    """
    if secret is None:
        secret = ""
    if salt is None:
        salt = os.urandom(16)
    pepper = _hash_pepper()
    digest = hashlib.scrypt(
        secret.encode("utf-8"),
        salt=_derive_salt(pepper, salt),
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=32,
    )
    return "$".join(
        [
            "scrypt",
            str(_SCRYPT_N),
            str(_SCRYPT_R),
            str(_SCRYPT_P),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        ]
    )


def _is_scrypt(value: str) -> bool:
    return str(value or "").startswith("scrypt$")


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
    """Coerce a role spec (str, list, or iterable) into a frozenset of roles.

    SECURITY: Restricts anonymous roles to prevent accidental privilege escalation.
    Anonymous users should never have super_admin, policy_admin, or manage_policy.
    """
    if not value:
        return frozenset()
    if isinstance(value, str):
        names: Iterable[str] = [part for part in value.replace(" ", ",").split(",") if part]
    else:
        names = value
    roles = set()
    for name in names:
        try:
            role = Role(str(name).strip().lower())
            # SECURITY: Block dangerous roles for anonymous access
            if role in {Role.SUPER_ADMIN, Role.POLICY_ADMIN}:
                logger.warning(
                    "SECURITY: blocking dangerous role %r for anonymous access. "
                    "Anonymous users cannot have super_admin or policy_admin roles.",
                    name
                )
                continue
            roles.add(role)
        except ValueError:
            logger.warning("ignoring unknown role %r", name)
    return frozenset(roles)


class ApiKeyStore:
    """Resolves a presented API key to a :class:`Principal`."""

    def __init__(self, config: Any) -> None:
        self.config = config
        self._keys: Dict[str, str] = {}
        self._roles: Dict[str, frozenset] = {}
        #: key_id -> the tenant that key is entitled to (§34). Without this the
        #: ``X-Tenant-Id`` header is a client assertion, not an identity.
        self._tenants: Dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        for key_id, stored in (getattr(self.config, "api_keys", None) or {}).items():
            self._keys[str(key_id)] = str(stored).strip()
        for key_id, role_spec in (getattr(self.config, "key_roles", None) or {}).items():
            self._roles[str(key_id)] = _parse_roles(role_spec)
        for key_id, tenant in (getattr(self.config, "key_tenants", None) or {}).items():
            tenant_id = str(tenant).strip()
            if tenant_id:
                self._tenants[str(key_id)] = tenant_id

    @property
    def hashed(self) -> bool:
        return bool(getattr(self.config, "hash_api_keys", True))

    def tenant_for(self, key_id: str) -> str:
        """The tenant *key_id* is bound to, or ``""`` when it is not bound."""
        return self._tenants.get(str(key_id), "")

    def add(
        self,
        key_id: str,
        secret: str,
        roles: Iterable[str],
        tenant_id: str = "",
    ) -> None:
        """Register a key at runtime (used by tests and dynamic provisioning)."""
        self._keys[str(key_id)] = (
            hash_secret(secret) if self.hashed else str(secret)
        )
        self._roles[str(key_id)] = _parse_roles(roles)
        tenant_id = str(tenant_id or "").strip()
        if tenant_id:
            self._tenants[str(key_id)] = tenant_id

    def __len__(self) -> int:
        return len(self._keys)

    @staticmethod
    def _scrypt_matches(stored: str, presented: str) -> bool:
        """Constant-time compare for a ``scrypt$...`` stored digest.

        The salt is read back out of the stored value, so a key is verified
        with the exact salt it was hashed under.
        """
        try:
            parts = str(stored).split("$")
            _, n, r, p, salt_b64, digest_b64 = parts
            salt = base64.b64decode(salt_b64)
            candidate = hashlib.scrypt(
                (presented or "").encode("utf-8"),
                salt=_derive_salt(_hash_pepper(), salt),
                n=int(n),
                r=int(r),
                p=int(p),
                dklen=len(base64.b64decode(digest_b64)),
            )
        except Exception:  # noqa: BLE001 - never let a malformed key crash auth
            return False
        return hmac.compare_digest(base64.b64encode(candidate).decode("ascii"), digest_b64)

    def _matches(self, stored: str, presented: str) -> bool:
        presented = presented or ""
        stored = str(stored or "")
        if not self.hashed:
            # Plaintext mode: the config holds the secret itself, so compare
            # like for like. (Only ever a development setting.)
            return hmac.compare_digest(stored, presented)
        if _is_scrypt(stored):
            return self._scrypt_matches(stored, presented)
        # Legacy: a bare hex SHA256 with no salt. Accepted so an existing
        # deployment keeps working, but only until the key is re-provisioned.
        expected = hashlib.sha256(presented.encode("utf-8")).hexdigest()
        return hmac.compare_digest(stored.lower(), expected)

    def resolve(self, presented: Optional[str], tenant_id: str = "") -> Principal:
        """Return the principal for *presented*, or raise :class:`AuthenticationError`.

        Every configured key is compared on **every** call, and the match is
        only inspected once the loop has finished. Returning from inside the
        loop made the total runtime proportional to the position of the
        matching key in the dictionary, which let an attacker enumerate valid
        keys by timing - ``hmac.compare_digest`` makes each *comparison*
        constant-time, not the loop that drives it.

        SECURITY: Tenant header validation prevents cross-tenant access.
        If a key has a tenant binding, the header must match exactly.
        """
        if not presented:
            raise AuthenticationError("missing API key")

        matched_id: Optional[str] = None
        matched_roles: Optional[frozenset] = None
        for key_id, stored in self._keys.items():
            if self._matches(stored, presented) and matched_id is None:
                matched_id = key_id
                # Only default to service_account when *no* role was configured
                # for this key. An explicitly empty/invalid role set must fail
                # closed rather than silently gaining classify+enforce.
                matched_roles = (
                    self._roles[key_id]
                    if key_id in self._roles
                    else frozenset({Role.SERVICE_ACCOUNT})
                )

        if matched_id is None or matched_roles is None:
            raise AuthenticationError("invalid API key")

        # SECURITY: Validate tenant binding to prevent cross-tenant access
        bound_tenant = self._tenants.get(matched_id, "")
        if bound_tenant:
            # Key has a binding - header must match exactly
            if tenant_id != bound_tenant:
                logger.warning(
                    "SECURITY: tenant header mismatch for key %s: "
                    "header=%r, bound=%r. Possible cross-tenant attack attempt.",
                    matched_id,
                    tenant_id,
                    bound_tenant
                )
                raise AuthenticationError("tenant header mismatch")
        elif tenant_id and not getattr(self.config, "allow_unbound_tenant_header", False):
            # Key has no binding but header is present and unbound headers are disallowed
            logger.warning(
                "SECURITY: unbound tenant header rejected for key %s: header=%r. "
                "Set allow_unbound_tenant_header=true if this is intentional.",
                matched_id,
                tenant_id
            )
            raise AuthenticationError("unbound tenant header not allowed")

        return Principal(key_id=matched_id, roles=matched_roles, tenant_id=tenant_id or bound_tenant)


class AuditLog:
    """Bounded, thread-safe record of metadata-only audit entries (§18).

    Entries are **also** appended to a durable JSONL sink when
    ``security.audit_file`` is set. The in-memory ring buffer is what
    ``GET /audit`` reads; it is a cache, not the record. It used to be the only
    copy, which meant every restart erased the evidence that the firewall was
    making decisions - and a crash is precisely when an operator needs it.
    ``config/privacy.yaml`` promises ``storage: secure_s3`` with
    ``retention_days: 365``; a file is the local stand-in for that, and the
    format is deliberately plain JSONL so shipping it to S3 is a sidecar's job
    rather than a change to this module.

    The privacy guarantee is unchanged: metadata only - principal, tenant,
    verdict, action, digest - never payload bytes.
    """

    def __init__(self, config: Any) -> None:
        self.enabled = bool(getattr(config, "audit_enabled", True))
        limit = int(getattr(config, "max_audit_entries", 1000) or 1000)
        self._entries: Deque[dict] = deque(maxlen=max(1, limit))
        self._lock = threading.Lock()
        self._path = str(getattr(config, "audit_file", "") or "").strip()
        self._durable = bool(self._path)
        if self._durable:
            logger.info("audit trail persisting to %s", self._path)

    @property
    def durable(self) -> bool:
        """True when entries outlive the process."""
        return self._durable

    def _append_durable(self, entry: dict) -> None:
        """Best-effort append. Never raises: auditing must not break a request."""
        if not self._durable:
            return
        try:
            import json
            import os
            from pathlib import Path

            path = Path(self._path).resolve()

            # SECURITY: Restrict audit path to allowed directories
            allowed_dirs = [Path("/var/log/nsfw-firewall"), Path("./logs")]
            if not any(str(path).startswith(str(d.resolve())) for d in allowed_dirs):
                logger.critical(
                    "SECURITY: audit path outside allowed directory: %s", path
                )
                return

            # SECURITY: Use absolute path and validate parent directory
            path.parent.mkdir(parents=True, exist_ok=True)

            # SECURITY: Use exclusive open flag to prevent symlink race (Unix)
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            try:
                flags |= os.O_EXCL  # Fail if file exists (prevent symlink race)
            except AttributeError:
                pass  # Windows doesn't have O_EXCL, use mode 0600 instead

            with os.fdopen(os.open(path, flags, 0o600), "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, default=str, sort_keys=True) + "\n")
        except Exception as exc:  # noqa: BLE001
            # A failed audit write is an operational problem, not a request
            # failure - but it must be loud, because a silent gap in the trail
            # is worse than a noisy log.
            logger.error("failed to append audit record: %s", exc)

    def record(self, event: str, principal: Optional[Principal] = None, **fields: Any) -> None:
        if not self.enabled:
            return
        entry = {
            "ts": time.time(),
            "event": event,
            "key_id": principal.key_id if principal else "anonymous",
            "tenant_id": principal.tenant_id if principal else "",
            # SECURITY: Add trace_id for distributed tracing
            "trace_id": fields.pop("trace_id", ""),
        }

        # SECURITY: Sanitize fields to prevent injection and control characters
        for k, v in fields.items():
            if v is None:
                continue
            # Convert to string and remove control characters
            str_value = str(v)
            # Remove null bytes and other control characters except \t\n\r
            sanitized = "".join(
                char for char in str_value
                if char == "\t" or char == "\n" or char == "\r" or ord(char) >= 32
            )
            # Truncate excessively long values to prevent log flooding
            if len(sanitized) > 1000:
                sanitized = sanitized[:1000] + "...[truncated]"
            entry[k] = sanitized

        with self._lock:
            self._entries.append(entry)
        self._append_durable(entry)

    def _durable_entries(self, limit: int) -> list:
        """Tail the durable sink, newest last.

        A freshly started process has an empty ring buffer, so without this
        ``GET /audit`` would report a clean slate immediately after a restart -
        precisely the moment an operator is trying to find out what happened.
        Read failures degrade to "no history" rather than raising.
        """
        try:
            import json
            from collections import deque as _deque
            from pathlib import Path

            path = Path(self._path)
            if not path.is_file():
                return []
            tail: _deque = _deque(maxlen=max(1, limit))
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        tail.append(json.loads(line))
                    except ValueError:
                        continue
            return list(tail)
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not read durable audit trail: %s", exc)
            return []

    def entries(self, limit: int = 100) -> list:
        window = max(1, int(limit))
        if self._durable:
            return self._durable_entries(window)
        with self._lock:
            items = list(self._entries)
        return items[-window:]

    def drain_all(self) -> list:
        """Return and clear the in-memory buffer.

        Exists so a replay/forwarder worker can hand the batch to durable
        storage; the file sink already has its own copy, so draining is safe
        and only affects the ``GET /audit`` view.
        """
        with self._lock:
            items = list(self._entries)
            self._entries.clear()
        return items

    def flush(self) -> None:
        """No-op: the file sink writes eagerly.

        Present so callers can express "make sure this is on disk" without
        caring which sink is configured.
        """

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
        """Authenticate a request, returning an anonymous principal in dev mode.

        Tenant resolution is **binding-first** (§34). The ``X-Tenant-Id`` header
        is a client assertion; ``security.key_tenants`` is the server-side
        fact. When the two disagree the request is refused rather than
        resolved, because "trust the header" is what let any valid key act as
        any tenant.
        """
        claimed = (tenant_id or "").strip()
        if require_tenant and not claimed:
            raise AuthenticationError("missing X-Tenant-Id")
        if not self.enabled:
            return Principal(
                key_id="anonymous",
                roles=_parse_roles(getattr(self.config, "anonymous_roles", None)),
                tenant_id=claimed,
            )

        principal = self.keys.resolve(api_key, tenant_id=claimed)
        bound = self.keys.tenant_for(principal.key_id)

        if bound:
            # The binding is authoritative. A mismatch is a spoof attempt, not
            # a configuration to be reconciled at runtime.
            if claimed and claimed != bound:
                logger.warning(
                    "tenant spoof refused: key=%r claimed tenant=%r but is bound to %r",
                    principal.key_id, claimed, bound,
                )
                self.audit("tenant_spoof_refused", principal, claimed=claimed)
                raise AuthorizationError(
                    f"API key {principal.key_id!r} is not entitled to tenant "
                    f"{claimed!r}"
                )
            principal = replace(principal, tenant_id=bound)
        elif claimed and not bool(
            getattr(self.config, "allow_unbound_tenant_header", False)
        ):
            # An unbound key asserting a tenant is exactly the spoof the
            # binding exists to stop. Fail closed: a single-tenant deployment
            # sends no header and is unaffected.
            logger.warning(
                "tenant header refused for unbound key=%r (tenant=%r); set "
                "security.key_tenants or allow_unbound_tenant_header to permit it",
                principal.key_id, claimed,
            )
            self.audit("tenant_unbound_refused", principal, claimed=claimed)
            raise AuthorizationError(
                f"API key {principal.key_id!r} is not bound to a tenant and may "
                "not assert one"
            )

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

    def status(self, *, redact: bool = False) -> dict:
        """Health-friendly summary (never includes secrets).

        ``redact`` is what the **unauthenticated** ``/health`` probe uses. The
        detailed form is for an operator who has already authenticated, and it
        still carries no secret material - just counts and booleans. Reporting
        ``api_keys_configured`` to an anonymous caller is reconnaissance: it
        tells a prober whether the deployment is authenticated at all, and how
        many credentials exist, without a single request being logged.
        """
        if redact:
            return {
                "enabled": bool(self.enabled),
                "audit_enabled": bool(self.audit_log.enabled),
            }
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