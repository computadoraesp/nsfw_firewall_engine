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
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_target: str = ""
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
        return (
            self.headers.get("x-icap-request-url")
            or self.request_headers.get("x-icap-request-url")
            or self.http_headers.get("x-icap-request-url")
            or self.request_target
            or self.uri
        )


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
    if not value.strip():
        return result
    for part in value.split(","):
        part = part.strip()
        if not part or "=" not in part:
            raise IcapParseError("malformed Encapsulated header")
        name, _, offset = part.partition("=")
        try:
            parsed_offset = int(offset.strip())
        except ValueError as exc:
            raise IcapParseError("invalid Encapsulated offset") from exc
        name = name.strip().lower()
        if not name or name in result:
            raise IcapParseError("invalid or duplicate Encapsulated section")
        result[name] = parsed_offset
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


def _read_exact(rfile, size: int) -> bytes:
    data = rfile.read(size)
    if len(data) != size:
        raise IcapParseError("truncated encapsulated data")
    return data


def _parse_http_head(block: bytes) -> Tuple[str, Dict[str, str]]:
    if not block.endswith(_HEADER_TERMINATOR):
        raise IcapParseError("malformed encapsulated HTTP headers")
    lines = block[:-len(_HEADER_TERMINATOR)].split(_CRLF)
    if not lines or not lines[0]:
        raise IcapParseError("missing encapsulated HTTP start line")
    return lines[0].decode("ascii", "replace"), _parse_header_lines(lines[1:])


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

    encapsulated = _parse_encapsulated(icap_headers.get("encapsulated", ""))
    method = method.upper()
    if method not in ("REQMOD", "RESPMOD"):
        return IcapRequest(
            method=method,
            uri=uri,
            version=version,
            headers=icap_headers,
            encapsulated=encapsulated,
        )

    sections = sorted(encapsulated.items(), key=lambda item: item[1])
    if not sections or sections[0][1] != 0:
        raise IcapParseError("missing or invalid Encapsulated offsets")
    if any(offset < 0 for _, offset in sections) or any(
        sections[index][1] >= sections[index + 1][1]
        for index in range(len(sections) - 1)
    ):
        raise IcapParseError("Encapsulated offsets must be strictly increasing")
    if any(offset > max_body_bytes + _MAX_HEADER_BYTES for _, offset in sections):
        raise IcapParseError("Encapsulated offset exceeds configured size limits")

    request_headers: Dict[str, str] = {}
    response_headers: Dict[str, str] = {}
    request_target = ""
    body_headers: Dict[str, str] = {}
    http_body = b""
    for index, (section, offset) in enumerate(sections):
        next_offset = sections[index + 1][1] if index + 1 < len(sections) else None
        if section in ("req-hdr", "res-hdr"):
            if next_offset is None:
                raise IcapParseError(f"missing end offset for {section}")
            length = next_offset - offset
            if length > _MAX_HEADER_BYTES:
                raise IcapParseError("encapsulated HTTP headers exceed maximum size")
            start_line, parsed_headers = _parse_http_head(_read_exact(rfile, length))
            if section == "req-hdr":
                request_headers = parsed_headers
                request_line = start_line.split()
                request_target = request_line[1] if len(request_line) > 1 else ""
            else:
                response_headers = parsed_headers
        elif section in ("req-body", "res-body"):
            if index != len(sections) - 1:
                raise IcapParseError("encapsulated body must be the final section")
            if method == "REQMOD" and section != "req-body":
                raise IcapParseError("REQMOD must encapsulate req-body")
            if method == "RESPMOD" and section != "res-body":
                raise IcapParseError("RESPMOD must encapsulate res-body")
            body_headers = request_headers if section == "req-body" else response_headers
            break
        elif section == "null-body":
            break
        else:
            raise IcapParseError(f"unsupported Encapsulated section: {section}")

    http_headers = request_headers if method == "REQMOD" else response_headers
    has_body_section = any(
        section in ("req-body", "res-body") for section, _ in sections
    )
    content_length = body_headers.get("content-length")
    if body_headers.get("transfer-encoding", "").lower() == "chunked":
        raise IcapParseError("chunked HTTP bodies are not supported")
    if has_body_section and content_length is None:
        raise IcapParseError("encapsulated body requires Content-Length")
    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError as exc:
            raise IcapParseError(f"invalid Content-Length: {content_length!r}") from exc
        if length < 0:
            raise IcapParseError("Content-Length must not be negative")
        if length > max_body_bytes:
            raise IcapParseError(
                f"body exceeds max_body_bytes ({length} > {max_body_bytes})"
            )
        if length > 0:
            http_body = _read_exact(rfile, length)

    return IcapRequest(
        method=method,
        uri=uri,
        version=version,
        headers=icap_headers,
        encapsulated=encapsulated,
        http_headers=http_headers,
        request_headers=request_headers,
        request_target=request_target,
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


def build_options_response(service_tag: str) -> bytes:
    """Advertise the ICAP methods and response forms supported by this service."""
    headers = [
        "ICAP/1.0 200 OK",
        "Methods: REQMOD, RESPMOD",
        "Service: NSFW content adaptation service",
        f'ISTag: "{service_tag}"',
        "Options-TTL: 3600",
        "Allow: 204",
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
class IcapAccessDenied(Exception):
    """Raised when a peer is not permitted to use the ICAP service."""


class IcapAccessControl:
    """Decides whether a peer may open an ICAP session (§35 parity with REST).

    ICAP has no credential mechanism of its own - RFC 3507 has no header for
    one, and the usual deployment is a proxy on the same host talking over a
    trusted segment. That is exactly why the absence of any control here was a
    real hole rather than a design choice: the socket listened on every
    interface and handed the classification *and* enforcement surface to
    whoever reached the port.

    This restores the property REST has, using what the transport actually
    offers: the peer address. ``trusted_proxies`` is a CIDR allow-list that
    defaults to loopback, so a freshly started server is usable but not
    exposed, and widening it is an explicit, reviewable configuration change.
    """

    def __init__(self, trusted: Optional[List[str]] = None) -> None:
        import ipaddress

        self._nets = []
        for entry in trusted if trusted is not None else ["127.0.0.1/32", "::1/128"]:
            try:
                self._nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                logger.error("ignoring malformed trusted_proxies entry %r", entry)
        if not self._nets:
            # Never fall back to "allow all": a typo in the configuration must
            # close the door, not open it.
            logger.error(
                "no valid trusted_proxies configured - ICAP will refuse every peer"
            )

    def is_trusted(self, host: str) -> bool:
        import ipaddress

        if not host:
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(
            address in net
            for net in self._nets
            if address.version == net.version
        )

    def check(self, host: str) -> None:
        if not self.is_trusted(host):
            logger.warning("ICAP access denied for peer %s", host)
            raise IcapAccessDenied(f"peer {host} is not a trusted proxy")


class IcapRequestHandler(socketserver.StreamRequestHandler):
    """Stream handler that classifies intercepted content and replies via ICAP."""

    timeout = 30
    # Injected by the server factory.
    engine: NsfwEngine
    config: EngineConfig
    acl: IcapAccessControl

    def handle(self) -> None:  # noqa: D401 - socketserver API
        service_tag = self.config.transport.icap.service_tag

        # SECURITY: access control runs before a single byte is parsed, so an
        # untrusted peer cannot use the parser or the classifier at all.
        try:
            self.acl.check(self._peer_host())
        except IcapAccessDenied as exc:
            logger.warning("ICAP rejected: %s", exc)
            self._write(build_error_response(service_tag, 403, "Forbidden"))
            return

        # SECURITY: per-peer request budget. ICAP had no limiter at all, and
        # classification is CPU-bound inference, so one proxy could saturate
        # every thread for free. Keyed on the peer address because ICAP has no
        # credential to key on - the ACL above is what establishes identity.
        limiter = getattr(self, "rate_limiter", None)
        if limiter is not None:
            allowed, retry_after = limiter.check(f"icap:{self._peer_host()}")
            if not allowed:
                logger.warning("ICAP rate limit hit for %s", self._peer_host())
                self._write(build_error_response(service_tag, 429, "Too Many Requests"))
                return

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

        if request.method == "OPTIONS":
            self._write(build_options_response(service_tag))
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
        #
        # SECURITY: the tenant comes from configuration, never from the
        # message. The previous `X-ICAP-Tenant-Id` header let any peer select
        # whose rules applied to its own traffic.
        tenant_id = self.config.transport.icap.default_tenant
        if request.headers.get("x-icap-tenant-id") and not tenant_id:
            logger.warning(
                "ignoring X-ICAP-Tenant-Id from %s: set transport.icap.default_tenant",
                self._peer_host(),
            )
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

    def _peer_host(self) -> str:
        """Address of the connecting peer, as a bare IP string."""
        try:
            return self.client_address[0]
        except (AttributeError, IndexError, TypeError):  # pragma: no cover
            return ""

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
            {
                "engine": self.engine,
                "config": self.config,
                "acl": IcapAccessControl(self.config.transport.icap.trusted_proxies),
                "rate_limiter": self._build_limiter(),
            },
        )
        super().__init__((host, port), handler)

    def _build_limiter(self):
        """Per-peer token bucket, when rate limiting is enabled (§17)."""
        security = self.config.security
        if not getattr(security, "rate_limit_enabled", False):
            return None
        from app.core.resilience import RateLimiter

        return RateLimiter(
            rate=security.rate_limit_per_second,
            capacity=security.rate_limit_burst,
            max_keys=security.rate_limit_max_keys,
        )

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


def main() -> int:  # pragma: no cover - runtime entrypoint
    from app.core.logging_setup import setup_logging

    setup_logging()
    server = create_server()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("ICAP server interrupted - shutting down")
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover - runtime entrypoint
    raise SystemExit(main())
