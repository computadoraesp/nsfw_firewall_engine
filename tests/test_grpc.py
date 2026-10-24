"""Transport-layer tests: gRPC mappings, ICAP parsing and the REST app.

The gRPC tests are skipped automatically when ``grpcio`` / the generated stubs
are unavailable; the ICAP and REST tests run everywhere (stdlib + FastAPI).
"""

from __future__ import annotations

import io
import os
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.api.grpc import handlers  # noqa: E402
from app.api.icap.icap_server import (  # noqa: E402
    IcapParseError,
    build_allow_response,
    build_block_response,
    build_options_response,
    read_icap_message,
)
from app.core.config import load_config  # noqa: E402
from app.core.engine import ClassificationResult, NsfwEngine  # noqa: E402
from app.models.base import MediaType, Verdict  # noqa: E402
from tests.test_engine import SKIN, make_ppm, solid  # noqa: E402


class IcapParsingTests(unittest.TestCase):
    def _message(self, body: bytes, content_type: str) -> bytes:
        http_head = (
            "GET /media.ppm HTTP/1.1\r\n"
            "Host: example.test\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii")
        icap_head = (
            "REQMOD icap://proxy.local/nsfw-firewall ICAP/1.0\r\n"
            "Host: proxy.local\r\n"
            "Encapsulated: req-hdr=0, req-body=%d\r\n\r\n" % len(http_head)
        ).encode("ascii")
        return icap_head + http_head + body

    def test_parse_reqmod_message(self):
        body = make_ppm(4, 4, SKIN)
        raw = self._message(body, "image/x-portable-pixmap")
        request = read_icap_message(io.BytesIO(raw), max_body_bytes=1_000_000)
        self.assertEqual(request.method, "REQMOD")
        self.assertEqual(request.http_body, body)
        self.assertEqual(request.media_type(), MediaType.IMAGE)

    def test_parse_detects_html(self):
        body = b"<html><body>hello</body></html>"
        raw = self._message(body, "text/html; charset=utf-8")
        request = read_icap_message(io.BytesIO(raw), max_body_bytes=1_000_000)
        self.assertEqual(request.media_type(), MediaType.HTML)
        self.assertEqual(request.content_type, "text/html")

    def test_parse_respmode_uses_response_headers_and_body(self):
        body = make_ppm(4, 4, SKIN)
        request_head = (
            "GET http://example.test/media.ppm HTTP/1.1\r\n"
            "Host: example.test\r\n\r\n"
        ).encode("ascii")
        response_head = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: image/x-portable-pixmap\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii")
        icap_head = (
            "RESPMOD icap://proxy.local/nsfw-firewall ICAP/1.0\r\n"
            "Host: proxy.local\r\n"
            "Encapsulated: req-hdr=0, res-hdr=%d, res-body=%d\r\n\r\n"
            % (len(request_head), len(request_head) + len(response_head))
        ).encode("ascii")

        request = read_icap_message(
            io.BytesIO(icap_head + request_head + response_head + body),
            max_body_bytes=1_000_000,
        )

        self.assertEqual(request.method, "RESPMOD")
        self.assertEqual(request.http_body, body)
        self.assertEqual(request.media_type(), MediaType.IMAGE)
        self.assertEqual(request.request_url, "http://example.test/media.ppm")

    def test_options_request_needs_no_encapsulated_http_message(self):
        raw = b"OPTIONS icap://proxy.local/nsfw-firewall ICAP/1.0\r\nHost: proxy.local\r\n\r\n"
        request = read_icap_message(io.BytesIO(raw), max_body_bytes=1024)
        self.assertEqual(request.method, "OPTIONS")
        self.assertEqual(request.http_body, b"")

    def test_malformed_request_line_raises(self):
        raw = b"GARBAGE\r\n\r\n"
        with self.assertRaises(IcapParseError):
            read_icap_message(io.BytesIO(raw), max_body_bytes=1024)

    def test_body_exceeding_limit_raises(self):
        body = make_ppm(64, 64, SKIN)
        raw = self._message(body, "image/x-portable-pixmap")
        with self.assertRaises(IcapParseError):
            read_icap_message(io.BytesIO(raw), max_body_bytes=10)

    def test_allow_response_shape(self):
        response = build_allow_response("nsfw-firewall")
        self.assertIn(b"204 No Content", response)
        self.assertIn(b"Encapsulated: null-body=0", response)

    def test_options_response_advertises_supported_methods(self):
        response = build_options_response("nsfw-firewall")
        self.assertIn(b"ICAP/1.0 200 OK", response)
        self.assertIn(b"Methods: REQMOD, RESPMOD", response)
        self.assertIn(b"Allow: 204", response)
        self.assertIn(b"Encapsulated: null-body=0", response)

    def test_block_response_is_chunked(self):
        response = build_block_response("nsfw-firewall", Verdict.NSFW, 0.97)
        self.assertIn(b"ICAP/1.0 200 OK", response)
        self.assertIn(b"HTTP/1.1 403 Forbidden", response)
        self.assertIn(b"res-body=", response)
        self.assertTrue(response.endswith(b"0\r\n\r\n"))


class IcapServerTests(unittest.TestCase):
    """End-to-end ICAP round trip over a real loopback socket."""

    def _message(self, body: bytes, content_type: str) -> bytes:
        http_head = (
            "REQMOD /media.ppm HTTP/1.1\r\n"
            "Host: example.test\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "X-ICAP-Request-Url: http://example.test/media.ppm\r\n\r\n"
        ).encode("ascii")
        icap_head = (
            "REQMOD icap://proxy.local/nsfw-firewall ICAP/1.0\r\n"
            "Host: proxy.local\r\n"
            "Encapsulated: req-hdr=0, req-body=%d\r\n\r\n" % len(http_head)
        ).encode("ascii")
        return icap_head + http_head + body

    def _response_message(self, body: bytes, content_type: str) -> bytes:
        request_head = (
            "GET http://example.test/media.ppm HTTP/1.1\r\n"
            "Host: example.test\r\n\r\n"
        ).encode("ascii")
        response_head = (
            "HTTP/1.1 200 OK\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii")
        icap_head = (
            "RESPMOD icap://proxy.local/nsfw-firewall ICAP/1.0\r\n"
            "Host: proxy.local\r\n"
            "Encapsulated: req-hdr=0, res-hdr=%d, res-body=%d\r\n\r\n"
            % (len(request_head), len(request_head) + len(response_head))
        ).encode("ascii")
        return icap_head + request_head + response_head + body

    def _exchange(self, host: str, port: int, payload: bytes) -> bytes:
        import socket

        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks)

    def test_block_and_allow_round_trip(self):
        from app.api.icap.icap_server import IcapServer

        config = load_config()
        config.transport.icap.host = "127.0.0.1"
        config.transport.icap.port = 0  # ephemeral
        config.paths.fast_path_model = "models_onnx/__missing_fast__.onnx"
        config.paths.deep_path_model = "models_onnx/__missing_deep__.onnx"
        config.paths.multimodal_model = "models_onnx/__missing_multimodal__.onnx"
        engine = NsfwEngine(config)
        engine.classify = Mock(
            side_effect=[
                ClassificationResult(verdict=Verdict.NSFW, score=0.95),
                ClassificationResult(verdict=Verdict.SFW, score=0.05),
                ClassificationResult(verdict=Verdict.NSFW, score=0.95),
            ]
        )
        server = IcapServer(engine, config)
        host, port = server.server_address[:2]
        import threading

        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        thread.start()
        try:
            options = self._exchange(
                host,
                port,
                b"OPTIONS icap://proxy.local/nsfw-firewall ICAP/1.0\r\n"
                b"Host: proxy.local\r\n\r\n",
            )
            self.assertIn(b"ICAP/1.0 200 OK", options)
            self.assertIn(b"Methods: REQMOD, RESPMOD", options)

            blocked = self._exchange(
                host, port, self._message(make_ppm(16, 16, SKIN), "image/x-portable-pixmap")
            )
            self.assertIn(b"ICAP/1.0 200 OK", blocked)
            self.assertIn(b"403 Forbidden", blocked)

            allowed = self._exchange(
                host, port, self._message(make_ppm(16, 16, (0, 0, 0)), "image/x-portable-pixmap")
            )
            self.assertIn(b"ICAP/1.0 204 No Content", allowed)

            response_blocked = self._exchange(
                host,
                port,
                self._response_message(
                    make_ppm(16, 16, SKIN), "image/x-portable-pixmap"
                ),
            )
            self.assertIn(b"ICAP/1.0 200 OK", response_blocked)
            self.assertIn(b"403 Forbidden", response_blocked)
        finally:
            server.shutdown()
            server.server_close()


class HandlerMappingTests(unittest.TestCase):
    def test_media_type_from_name(self):
        self.assertEqual(handlers.media_type_from_name("image"), MediaType.IMAGE)
        self.assertEqual(handlers.media_type_from_name("html"), MediaType.HTML)
        self.assertEqual(handlers.media_type_from_name("nonsense"), MediaType.UNKNOWN)

    def test_grpc_availability_flag_is_bool(self):
        self.assertIsInstance(handlers.GRPC_AVAILABLE, bool)


class RestAppTests(unittest.TestCase):
    def _client_with_key(self):
        """Build a TestClient whose security context has one usable key.

        ``/classify`` has required ``Permission.CLASSIFY`` since the
        unauthenticated-classification hole was closed. This test exercises the
        happy path, not the auth path, so it must present a credential like any
        other caller. Keys are no longer committed to the repository, so one is
        provisioned here the way a deployment would via ``NSFW_API_KEYS``.
        """
        from fastapi.testclient import TestClient

        from app.api.rest.router import create_app
        from app.core.security import hash_secret

        config = load_config()
        config.security.enabled = True
        config.security.api_keys = {"test": hash_secret("integration-secret")}
        config.security.key_roles = {"test": "service_account"}
        # The key is bound to a tenant, as every real service account must be:
        # an unbound key asserting `X-Tenant-Id` is refused with 403, because
        # the header is a client assertion and the binding is the only fact.
        config.security.key_tenants = {"test": "acme"}
        engine = NsfwEngine(config)
        client = TestClient(create_app(engine=engine, config=config))
        return client, {"X-API-Key": "integration-secret", "X-Tenant-Id": "acme"}

    def test_create_app_and_health(self):
        try:
            client, _headers = self._client_with_key()
        except Exception as exc:  # noqa: BLE001
            self.skipTest(f"fastapi TestClient unavailable: {exc}")

        health = client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertIn("version", health.json())

        readiness = client.get("/v1/ready")
        self.assertEqual(readiness.status_code, 200)
        readiness_body = readiness.json()
        self.assertEqual(readiness_body["ready"], all(readiness_body["checks"].values()))
        self.assertEqual(
            readiness_body["models_loaded"],
            client.app.state.engine.health()["loaded_models_count"],
        )

    def test_classify_requires_a_credential(self):
        """The regression this endpoint carried: anonymous classification."""
        try:
            client, _headers = self._client_with_key()
        except Exception as exc:  # noqa: BLE001
            self.skipTest(f"fastapi TestClient unavailable: {exc}")

        import base64

        ppm = make_ppm(8, 8, SKIN)
        payload = {"image_base64": base64.b64encode(ppm).decode("ascii")}
        self.assertEqual(
            client.post("/classify", json=payload).status_code,
            401,
            msg="an anonymous caller was allowed to classify",
        )

    def test_classify_succeeds_with_a_credential(self):
        try:
            client, headers = self._client_with_key()
        except Exception as exc:  # noqa: BLE001
            self.skipTest(f"fastapi TestClient unavailable: {exc}")

        import base64

        ppm = make_ppm(8, 8, SKIN)
        payload = {"image_base64": base64.b64encode(ppm).decode("ascii")}
        response = client.post("/classify", json=payload, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn(response.json()["verdict"], ("NSFW", "REVIEW", "SFW"))


@unittest.skipUnless(handlers.GRPC_AVAILABLE, "grpcio / generated stubs unavailable")
class GrpcServerTests(unittest.TestCase):  # pragma: no cover - requires grpcio
    def test_create_server_returns_bound_address(self):
        from app.api.grpc.server import create_server
        from app.core.config import load_config as _load

        config = _load()
        config.transport.grpc.host = "127.0.0.1"
        config.transport.grpc.port = 0  # ephemeral
        engine = NsfwEngine(config)
        server, address = create_server(engine, config)
        self.assertIsNotNone(server)
        self.assertIn("127.0.0.1", address)


if __name__ == "__main__":
    unittest.main(verbosity=2)
