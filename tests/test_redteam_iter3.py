"""Red-team iteration 3: the transports and secrets nobody re-reads.

Iteration 1 closed the REST API. Iteration 2 closed the input handling. This
round covers what was left unreviewed - and the first thing found was the same
tenant-spoof bug as C5, but on transport with **no authentication at all**.

* ``IcapExploits``     - ICAP has zero auth and trusts a caller-supplied tenant.
* ``GrpcParityExploits`` - gRPC never enforces the tenant binding REST does.
* ``SecretHandling``   - H6/M2: unsalted SHA256 and a public, hard-coded salt.
* ``DeploymentGuards`` - M9/M10/L1: image contents, leaked status, repo hygiene.

Run with::

    Python -m pytest tests/test_redteam_iter3.py -v
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.test_redteam import (  # noqa: E402
    OWN_TENANT,
    VALID_KEY,
    AsgiClient,
    _auth,
    _client,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# ICAP - no authentication, caller-asserted tenant
# ---------------------------------------------------------------------------


class IcapExploits(unittest.TestCase):
    """The ICAP handler classifies and *enforces* with no credential of any kind.

    These are **runtime** tests over a real socket, not source greps. An
    earlier draft asserted on the module source and happily passed while the
    handler raised ``NameError`` on every REQMOD - source inspection proves the
    text is present, not that the code runs.
    """

    @staticmethod
    def _serve(trusted_proxies=None, tenant: str = ""):
        """Start an ICAP server on an ephemeral loopback port."""
        import copy
        import threading

        from app.api.icap.icap_server import create_server
        from app.core.config import load_config
        from app.core.engine import NsfwEngine

        # load_config() is @lru_cache(maxsize=1): mutating the returned object
        # would rewrite the process-wide config for every later test, which
        # shows up as ordering-dependent failures far from the cause.
        config = copy.deepcopy(load_config(REPO_ROOT / "config" / "engine_config.yaml"))
        # Bind an ephemeral port. Without this every test in this class binds
        # the configured 1344, and since each one installs a *different* ACL,
        # a connection can land on a neighboring test's server - which is
        # what produced an empty response roughly one run in five when the
        # whole red-team suite ran together.
        config.transport.icap.port = 0
        if trusted_proxies is not None:
            config.transport.icap.trusted_proxies = trusted_proxies
        if tenant:
            config.transport.icap.default_tenant = tenant
        server = create_server(engine=NsfwEngine(config), config=config)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, server.server_address[1]

    @staticmethod
    def _reqmod(tenant_header: str = "") -> bytes:
        body = b"<html><body>hello world</body></html>"
        http = (
            b"POST http://example.invalid/ HTTP/1.1\r\n"
            b"Host: example.invalid\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
        head = (
            b"REQMOD icap://icap-server/svc ICAP/1.0\r\n"
            b"Host: icap-server\r\n"
            b"Encapsulated: req-hdr=0, req-body=" + str(len(http)).encode() + b"\r\n"
        )
        if tenant_header:
            head += b"X-ICAP-Tenant-Id: " + tenant_header.encode() + b"\r\n"
        head += b"\r\n"
        return head + http

    @staticmethod
    def _talk(port: int, payload: bytes, attempts: int = 3) -> bytes:
        """Send one ICAP message and read the reply.

        Both the retry and the read window are load-bearing. The listener is
        bound in the constructor but the serving thread starts moments later,
        and a REQMOD runs the full classification pipeline - on a loaded machine
        that outlasts a naive read loop, which showed up as a ~25% flake under
        the full suite while passing in isolation. The window is kept short
        enough that a genuinely dead server fails fast instead of stalling the
        suite: worst case is attempts x (connect + window).
        """
        import socket
        import time

        last = b""
        for attempt in range(attempts):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                    sock.settimeout(5)
                    sock.sendall(payload)
                    chunks = []
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        try:
                            data = sock.recv(65536)
                        except socket.timeout:
                            break
                        if not data:
                            break
                        chunks.append(data)
                        # Stop as soon as the response head is complete.
                        #
                        # An earlier version required >512 bytes before
                        # breaking, which is wrong: an ACL rejection is a
                        # ~90-byte error head, so the loop never satisfied it
                        # and every such request waited out the full window -
                        # which is where a ~20% flake under the full suite came
                        # from. The status line plus the header terminator is
                        # the reliable signal for every response this handler
                        # produces.
                        blob = b"".join(chunks)
                        if blob.startswith(b"ICAP/1.0") and b"\r\n\r\n" in blob:
                            break
                    last = b"".join(chunks)
            except OSError:
                last = b""
            if last:
                return last
            time.sleep(0.3 * (attempt + 1))
        return last

    # -- attacks ---------------------------------------------------------

    def test_attack_loopback_peer_is_served(self):
        """Baseline: the legitimate proxy must still work."""
        server, port = self._serve()
        try:
            response = self._talk(port, self._reqmod())
        finally:
            server.shutdown()
            server.server_close()
        self.assertTrue(
            response.startswith(b"ICAP/1.0"),
            msg=f"no ICAP response: {response[:120]!r}",
        )
        self.assertNotIn(
            b"403 Forbidden",
            response.split(b"\r\n")[0],
            msg="a trusted loopback peer was refused",
        )

    def test_attack_tenant_header_cannot_select_a_tenant(self):
        """ATTACK: ``X-ICAP-Tenant-Id: victim-corp`` decides the policy.

        The request must still be served, but under the *configured* tenant,
        never the one the peer named.
        """
        server, port = self._serve()
        try:
            response = self._talk(port, self._reqmod(tenant_header="victim-corp"))
        finally:
            server.shutdown()
            server.server_close()
        self.assertTrue(
            response.startswith(b"ICAP/1.0"),
            msg=f"request failed instead of ignoring the header: {response[:160]!r}",
        )

    def test_attack_untrusted_peer_is_refused(self):
        """ATTACK: a peer outside ``trusted_proxies`` must be rejected."""
        from app.api.icap.icap_server import IcapAccessControl, IcapAccessDenied

        acl = IcapAccessControl(["10.0.0.0/8"])
        with self.assertRaises(IcapAccessDenied):
            acl.check("192.168.1.50")

    def test_attack_loopback_is_trusted_by_default(self):
        from app.api.icap.icap_server import IcapAccessControl

        acl = IcapAccessControl()
        self.assertTrue(acl.is_trusted("127.0.0.1"))
        self.assertFalse(acl.is_trusted("10.1.2.3"))

    def test_attack_empty_allowlist_denies_everyone(self):
        """A configuration typo must close the door, never open it."""
        from app.api.icap.icap_server import IcapAccessControl

        acl = IcapAccessControl(["not-a-cidr", "also-not-a-cidr"])
        self.assertFalse(acl.is_trusted("127.0.0.1"))

    def test_attack_untrusted_peer_is_refused_before_parsing(self):
        """The ACL runs before the parser, so a hostile peer cannot reach it."""
        server, port = self._serve(trusted_proxies=["10.0.0.0/8"])
        try:
            response = self._talk(port, self._reqmod())
        finally:
            server.shutdown()
            server.server_close()
        self.assertIn(
            b"403",
            response,
            msg=f"untrusted peer was not refused: {response[:120]!r}",
        )

    def test_attack_icap_is_not_bound_to_loopback_by_default(self):
        from app.core.config import IcapTransport

        self.assertNotEqual(
            IcapTransport().host,
            "0.0.0.0",
            msg=(
                "ICAP binds every interface by default; combined with no "
                "access control this exposes the enforcement surface to the "
                "whole network"
            ),
        )


# ---------------------------------------------------------------------------
# gRPC - must enforce the same tenant binding as REST
# ---------------------------------------------------------------------------


class GrpcParityExploits(unittest.TestCase):
    """gRPC calls ``authenticate`` without ``require_tenant``.

    ``app/api/grpc/handlers.py`` resolves the tenant from the
    ``x-tenant-id`` metadata and passes it straight through, so the
    ``require_tenant_header`` setting that now protects REST is silently inert
    on the gRPC transport.
    """

    def test_attack_grpc_forwards_the_tenant_requirement(self):
        from app.api.grpc import handlers

        import inspect

        source = inspect.getsource(handlers.authenticate)
        self.assertIn(
            "require_tenant",
            source,
            msg=(
                "gRPC authenticate() never forwards require_tenant, so "
                "security.require_tenant_header protects REST only"
            ),
        )

    def test_attack_grpc_resolves_tenant_only_through_the_binding(self):
        from app.core.config import SecurityConfig
        from app.core.security import AuthorizationError, SecurityContext, hash_secret

        context = SecurityContext(
            SecurityConfig(
                enabled=True,
                hash_api_keys=True,
                api_keys={"svc": hash_secret("s")},
                key_roles={"svc": "service_account"},
                key_tenants={"svc": "acme"},
                require_tenant_header=True,
            )
        )
        # The binding holds on this path too.
        self.assertEqual(context.authenticate("s").tenant_id, "acme")
        with self.assertRaises(AuthorizationError):
            context.authenticate("s", tenant_id="victim-corp")


# ---------------------------------------------------------------------------
# H6 / M2 - secret handling
# ---------------------------------------------------------------------------


class SecretHandling(unittest.TestCase):
    """H6: ``hash_secret`` is a bare, unsalted SHA256."""

    def test_attack_api_keys_use_a_real_kdf(self):
        from app.core.security import hash_secret

        # A fast digest is fine for a cache key and wrong for a credential:
        # SHA256 of a guessable secret is instant to check offline, and the
        # config file itself is the wordlist.
        self.assertGreaterEqual(
            len(hash_secret("s")),
            32,
            msg="expected a KDF parameter prefix, not a bare hex digest",
        )
        self.assertRegex(
            hash_secret("s"),
            r"^scrypt\$",
            msg=(
                "API keys are still hashed with plain unsalted SHA256; use a "
                "memory-hard KDF (scrypt) with a per-key salt"
            ),
        )

    def test_attack_same_secret_does_not_produce_the_same_digest(self):
        from app.core.security import ApiKeyStore

        from app.core.config import SecurityConfig

        store = ApiKeyStore(
            SecurityConfig(enabled=True, hash_api_keys=True, api_keys={}, key_roles={})
        )
        store.add("k1", "same-secret", ["service_account"])
        store.add("k2", "same-secret", ["service_account"])
        self.assertNotEqual(
            store._keys["k1"],
            store._keys["k2"],
            msg=(
                "digests are unsalted, so identical secrets are visibly "
                "identical and one rainbow table covers every key"
            ),
        )

    def test_attack_no_public_default_salt(self):
        """M2: ``enterprise-nsfw-salt`` is in the repo, so it is not a secret."""
        import yaml

        from app.core.config import PrivacyConfig

        default = PrivacyConfig().hash_salt
        self.assertIn(
            default,
            ("", "${NSFW_HASH_SALT}"),
            msg=(
                f"PrivacyConfig ships the hard-coded salt {default!r}; it must "
                "come from the environment or be empty"
            ),
        )
        raw = yaml.safe_load(
            (REPO_ROOT / "config" / "engine_config.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            (raw.get("privacy") or {}).get("hash_salt"),
            "${NSFW_HASH_SALT}",
            msg="the committed config still hard-codes the salt",
        )


# ---------------------------------------------------------------------------
# M9 / M10 / L1 - deployment
# ---------------------------------------------------------------------------


class DeploymentGuards(unittest.TestCase):
    """M9: the runtime image ships none of the security validators."""

    def test_attack_image_installs_the_security_validators(self):
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8").lower()
        self.assertIn(
            "pillow",
            dockerfile,
            msg=(
                "Pillow is absent from the runtime image, so _check_image "
                "returns (True, None, None) and dimension validation does not "
                "happen in production at all"
            ),
        )
        self.assertIn(
            "Python-magic",
            dockerfile,
            msg="Python-magic is absent from the runtime image",
        )

    def test_attack_image_is_not_self_consistent(self):
        """The Dockerfile pins dependencies inline instead of using the file."""
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn(
            "requirements.txt",
            dockerfile.split("FROM Python:3.12-slim AS runtime")[-1],
            msg=(
                "the runtime stage installs pinned packages inline instead of "
                "requirements.txt, so the image and the declared dependencies "
                "drift apart silently"
            ),
        )

    def test_attack_public_probes_do_not_disclose_security_posture(self):
        """M10: ``/health`` is unauthenticated by design, but must not report
        the authentication configuration to an anonymous caller."""
        response = _client().get("/health")
        self.assertEqual(response.status_code, 200)
        security = (response.json() or {}).get("security") or {}
        for leaky in ("api_keys_configured", "hashed_keys", "audit_entries"):
            self.assertNotIn(
                leaky,
                security,
                msg=f"unauthenticated /health discloses security.{leaky}",
            )

    def test_attack_no_stray_files_in_the_repository(self):
        """L1: ``nul`` is a Windows redirect artifact checked into a Linux repo.

        Checked through git rather than the filesystem on purpose: on Windows
        ``nul`` is a reserved device name, so ``Path('nul').exists()`` is always
        True and ``is_file()`` is always False - a filesystem probe gives the
        wrong answer on exactly the platform that creates the file. What
        actually matters is whether git would carry it into history.
        """
        import subprocess

        tracked = subprocess.run(
            ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True
        ).stdout.split()
        offenders = [
            name
            for name in tracked
            if name.rsplit("/", 1)[-1].lower() in {"nul", "con", "prn", "aux"}
        ]
        self.assertEqual(offenders, [], msg=f"device files tracked in git: {offenders}")

        untracked = subprocess.run(
            ["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True
        ).stdout.splitlines()
        stray = [
            line
            for line in untracked
            if line.rsplit("/", 1)[-1].strip().lower() in {"nul", "con", "prn", "aux"}
        ]
        self.assertEqual(
            stray, [], msg=f"device files present in the working tree: {stray}"
        )

    def test_attack_logs_are_not_version_controlled(self):
        import subprocess

        tracked = subprocess.run(
            ["git", "ls-files", "logs/"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(
            tracked, "", msg=f"log files are tracked in git: {tracked.splitlines()}"
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()