"""ICAP server for the NSFW Firewall Engine (Squid / MITM interception).

Implements the subset of ICAP (RFC 3507) needed to intercept content flowing
through a caching proxy: ``REQMOD`` (request modification) and ``RESPMOD``
(response modification). Requests are parsed, the encapsulated HTTP body is
classified by the engine and the response instructs the proxy to either pass
the content through (``204 No Content``) or substitute a ``403 Forbidden``
(``200 OK`` with an encapsulated HTTP response).

Only the standard library is required, so the server runs in any deployment.
"""

from __future__ import annotations

import logging
import socketserver
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from app.core.config import EngineConfig, get_config
from app.core.engine import NsfwEngine
from app.models.base import MediaType, Verdict
from app.services.enforcement import IcapEnforcementAdapter

logger = logging.getLogger("nsfw_engine.api.icap.server")

_CRLF = b"\r\n"
_HEADER_TERMINATOR = b"\r\n\r\n"

#: Maps an HTTP Content-Type prefix to the internal media type.
_CONTENT_TYPE_MAP: Tuple[Tuple[str, MediaType], ...] = (
    ("image/", MediaType.IMAGE),
    ("video/", MediaType.VIDEO),
    ("text/html", MediaType.HTML),
    ("application/xhtml", MediaType.HTML),
    ("text/", MediaType.TEXT),
    ("application/json", MediaType.TEXT),
)


class IcapParseError(ValueError):
    """Raised when an ICAP message cannot be parsed."""


@dataclass
class IcapRequest:
    """A parsed ICAP request."""

    method: str
    uri: str
    version: str
    headers: Dict[str, str] = field(default_factory=dict)
    encapsulated: Dict[str, int] = field(default_factory=dict)
    http_headers: Dict[str, str] = field(default_factory=dict)
    http_body: bytes = b""

    @property
    def content_type(self) -> str:
        return self.http_headers.get("content-type", "").split(";")[0].strip().lower()

    def media_type(self) -> MediaType:
        for prefix, media in _CONTENT_TYPE_MAP:
            if self.content_type.startswith(prefix):
                return media
        # Fall back to sniffing a PPM/PNG/JPEG magic number.
        if self.http_body[:2] in (b"P6", b"P5") or self.http_body[:3] == b"\xff\xd8\xff":
            return MediaType.IMAGE
        if self.http_body[:8] == b"\x89PNG\r\n\x1a\n":
            return MediaType.IMAGE
        return MediaType.UNKNOWN

    @property
    def request_url(self) -> str:
        return self.http_headers.get("x-icap-request-url", self.uri)


def _parse_header_lines(lines: List[bytes]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or b":" not in line:
            continue
        key, _, value = line.partition(b":")
        headers[key.decode("ascii", "replace").strip().lower()] = value.decode(
            "utf-8", "replace"
        ).strip()
    return headers


def _parse_encapsulated(value: str) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for part in value.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, offset = part.partition("=")
        try:
            result[name.strip().lower()] = int(offset.strip())
        except ValueError:
            continue
    return result


#: Hard cap on the ICAP header block to avoid unbounded reads.
_MAX_HEADER_BYTES = 128 * 1024


def _read_until(rfile, terminator: bytes, limit: int = _MAX_HEADER_BYTES) -> bytes:
    buf = bytearray()
    while terminator not in buf:
        chunk = rfile.read(1)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            raise IcapParseError("header block exceeds maximum size")
    return bytes(buf)


def read_icap_message(rfile, max_body_bytes: int) -> IcapRequest:
    """Parse a single ICAP request from a socket file object.

    Supports the ``Encapsulated: req-hdr/req-body`` and ``res-hdr/res-body``
    layouts. Bodies are read using the embedded HTTP ``Content-Length``; chunked
    transfer encoding is not yet handled and is rejected explicitly.
    """
    header_block = _read_until(rfile, _HEADER_TERMINATOR)
    if not header_block.strip():
        raise IcapParseError("empty ICAP message")

    lines = header_block.split(_CRLF)
    request_line = lines[0].decode("ascii", "replace").strip()
    parts = request_line.split()
    if len(parts) < 3:
        raise IcapParseError(f"malformed ICAP request line: {request_line!r}")
    method, uri, version = parts[0], parts[1], parts[2]
    icap_headers = _parse_header_lines([ln for ln in lines[1:] if ln.strip()])

    if icap_headers.get("transfer-encoding", "").lower() == "chunked":
        raise IcapParseError("chunked ICAP bodies are not supported")

    # The encapsulated data begins immediately after the header terminator.
    http_head_block = _read_until(rfile, _HEADER_TERMINATOR)
    http_lines = http_head_block.split(_CRLF)
    http_headers = _parse_header_lines([ln for ln in http_lines[1:] if ln.strip()])

    http_body = b""
    content_length = http_headers.get("content-length")
    if content_length:
        try:
            length = int(content_length)
        except ValueError as exc:
            raise IcapParseError(f"invalid Content-Length: {content_length!r}") from exc
        if length > max_body_bytes:
            raise IcapParseError(
                f"body exceeds max_body_bytes ({length} > {max_body_bytes})"
            )
        if length > 0:
            http_body = rfile.read(length)

    return IcapRequest(
        method=method.upper(),
        uri=uri,
        version=version,
        headers=icap_headers,
        encapsulated=_parse_encapsulated(icap_headers.get("encapsulated", "")),
        http_headers=http_headers,
        http_body=http_body,
    )


# -- responses ---------------------------------------------------------------
_BLOCK_TEMPLATE = (
    "<!doctype html><html><head><title>Blocked</title></head><body>"
    "<h1>403 Forbidden</h1><p>This content was blocked by the NSFW firewall "
    "(verdict={verdict}, score={score:.3f}).</p></body></html>"
)


def build_allow_response(service_tag: str) -> bytes:
    """ICAP ``204 No Content`` - the proxy passes content through unchanged."""
    headers = [
        "ICAP/1.0 204 No Content",
        f"Server: {service_tag}",
        f'ISTag: "{service_tag}"',
        "Encapsulated: null-body=0",
        "",
        "",
    ]
    return _CRLF.join(h.encode("ascii") for h in headers)


def build_block_response(service_tag: str, verdict: "Verdict | str", score: float) -> bytes:
    """ICAP ``200 OK`` carrying an encapsulated HTTP ``403 Forbidden``."""
    verdict_value = verdict.value if isinstance(verdict, Verdict) else str(verdict)
    html = _BLOCK_TEMPLATE.format(verdict=verdict_value, score=score).encode("utf-8")
    res_headers = (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(html)).encode("ascii") + b"\r\n\r\n"
    )
    # res-body is chunked-encoded per the ICAP specification.
    chunked = b"%x\r\n" % len(html) + html + b"\r\n0\r\n\r\n"
    encapsulated = res_headers + chunked

    header = _CRLF.join(
        h.encode("ascii")
        for h in [
            "ICAP/1.0 200 OK",
            f"Server: {service_tag}",
            f'ISTag: "{service_tag}"',
            f"Encapsulated: res-hdr=0, res-body={len(res_headers)}",
            "",
        ]
    )
    return header + encapsulated


def build_error_response(service_tag: str, code: int, reason: str) -> bytes:
    body = reason.encode("utf-8")
    header = _CRLF.join(
        h.encode("ascii")
        for h in [
            f"ICAP/1.0 {code} {reason}",
            f"Server: {service_tag}",
            f"Encapsulated: opt-body=0",
            "",
        ]
    )
    return header + body


# -- request handler ---------------------------------------------------------
class IcapRequestHandler(socketserver.StreamRequestHandler):
    """Stream handler that classifies intercepted content and replies via ICAP."""

    timeout = 30
    # Injected by the server factory.
    engine: NsfwEngine
    config: EngineConfig

    def handle(self) -> None:  # noqa: D401 - socketserver API
        service_tag = self.config.transport.icap.service_tag
        try:
            request = read_icap_message(
                self.rfile, self.config.transport.icap.max_body_bytes
            )
        except IcapParseError as exc:
            logger.warning("ICAP parse error from %s: %s", self.client_address, exc)
            self._write(build_error_response(service_tag, 400, "Bad Request"))
            return
        except Exception as exc:  # noqa: BLE001
            logger.exception("ICAP read failure from %s", self.client_address)
            self._write(build_error_response(service_tag, 500, "Server Error"))
            return

        if request.method not in ("REQMOD", "RESPMOD"):
            logger.info("unsupported ICAP method %s", request.method)
            self._write(build_error_response(service_tag, 405, "Method Not Allowed"))
            return

        try:
            result = self._classify(request)
        except Exception as exc:  # noqa: BLE001
            logger.exception("classification failure")
            self._write(build_error_response(service_tag, 500, "Server Error"))
            return

        # Policy engine -> enforcement adapter (Sec. 19 / 30). The proxy only
        # ever sees an ICAP response, never a vendor-specific action.
        tenant_id = request.headers.get("x-icap-tenant-id", "")
        decision = self.engine.policy.decide(result, tenant_id=tenant_id)
        logger.info(
            "ICAP %s %s -> %s/%s (%.3f) in %.1fms",
            request.method,
            request.request_url,
            decision.verdict,
            decision.action.value,
            result.score,
            result.total_latency_ms,
        )
        adapter = IcapEnforcementAdapter(self.config.policy, service_tag)
        self._write(adapter.response_bytes(decision))

    def _classify(self, request: IcapRequest):
        media_type = request.media_type()
        if not request.http_body:
            # Nothing to inspect (e.g. a metadata-only REQMOD) -> allow.
            from app.core.engine import ClassificationResult

            return ClassificationResult(
                verdict=Verdict.SFW, media_type=media_type
            )
        url_hint = request.request_url
        return self.engine.classify(
            request.http_body,
            media_type=media_type,
            request_id=url_hint,
            text=(url_hint if media_type in (MediaType.TEXT, MediaType.HTML) else None),
        )

    def _write(self, payload: bytes) -> None:
        try:
            self.wfile.write(payload)
            self.wfile.flush()
        except OSError:  # pragma: no cover - client disconnected
            logger.debug("client %s closed the connection before reply", self.client_address)


class IcapServer(socketserver.ThreadingTCPServer):
    """Threaded ICAP server bound to the engine."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, engine: NsfwEngine, config: Optional[EngineConfig] = None) -> None:
        self.engine = engine
        self.config = config or engine.config
        host = self.config.transport.icap.host
        port = self.config.transport.icap.port
        handler = type(
            "BoundIcapHandler",
            (IcapRequestHandler,),
            {"engine": self.engine, "config": self.config},
        )
        super().__init__((host, port), handler)

    def serve_forever(self, poll_interval: float = 0.5) -> None:  # pragma: no cover
        logger.info(
            "ICAP server listening on %s:%s",
            self.config.transport.icap.host,
            self.config.transport.icap.port,
        )
        super().serve_forever(poll_interval)


def create_server(
    engine: Optional[NsfwEngine] = None, config: Optional[EngineConfig] = None
) -> IcapServer:
    """Convenience factory building an :class:`IcapServer`."""
    config = config or get_config()
    engine = engine or NsfwEngine(config)
    return IcapServer(engine, config)


if __name__ == "__main__":  # pragma: no cover - runtime entrypoint
    from app.core.logging_setup import setup_logging

    setup_logging()
    server = create_server()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("ICAP server interrupted - shutting down")
    finally:
        server.shutdown()


