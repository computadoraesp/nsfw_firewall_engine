"""Transport-layer tests: gRPC mappings, ICAP parsing and the REST app.

The gRPC tests are skipped automatically when ``grpcio`` / the generated stubs
are unavailable; the ICAP and REST tests run everywhere (stdlib + FastAPI).
"""

from __future__ import annotations

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.api.grpc import handlers  # noqa: E402
from app.api.icap.icap_server import (  # noqa: E402
    IcapParseError,
    build_allow_response,
    build_block_response,
    read_icap_message,
)
from app.core.config import load_config  # noqa: E402
from app.core.engine import NsfwEngine  # noqa: E402
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
        server = IcapServer(NsfwEngine(config), config)
        host, port = server.server_address[:2]
        import threading

        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        thread.start()
        try:
            blocked = self._exchange(
                host, port, self._message(make_ppm(16, 16, SKIN), "image/x-portable-pixmap")
            )
            self.assertIn(b"ICAP/1.0 200 OK", blocked)
            self.assertIn(b"403 Forbidden", blocked)

            allowed = self._exchange(
                host, port, self._message(make_ppm(16, 16, (0, 0, 0)), "image/x-portable-pixmap")
            )
            self.assertIn(b"ICAP/1.0 204 No Content", allowed)
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
    def test_create_app_and_health(self):
        try:
            from fastapi.testclient import TestClient
        except Exception as exc:  # noqa: BLE001
            self.skipTest(f"fastapi TestClient unavailable: {exc}")

        from app.api.rest.router import create_app

        engine = NsfwEngine(load_config())
        try:
            client = TestClient(create_app(engine=engine))
        except Exception as exc:  # noqa: BLE001 - httpx missing
            self.skipTest(f"httpx unavailable: {exc}")

        health = client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertIn("version", health.json())

        # Classify a raw PPM body.
        import base64

        ppm = make_ppm(8, 8, SKIN)
        payload = {"image_base64": base64.b64encode(ppm).decode("ascii")}
        response = client.post("/classify", json=payload)
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
