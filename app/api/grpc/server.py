"""gRPC server entrypoint for the NSFW Firewall Engine.

Exposes :class:`NsfwEngine` over the ``nsfw.v1.NsfwEngine`` service. The
firewall connects here for ultra-low-latency synchronous classification.

Run directly:

    python -m app.api.grpc.server

Requires ``grpcio`` and the generated stubs (see ``app/api/grpc/handlers.py``
for the generation command).
"""

from __future__ import annotations

import logging
import signal
import sys
import time
from concurrent import futures
from typing import Optional

from app.api.grpc.handlers import GRPC_AVAILABLE, NsfwEngineServicer, pb_grpc
from app.core.config import EngineConfig, get_config
from app.core.engine import NsfwEngine
from app.core.logging_setup import setup_logging

logger = logging.getLogger("nsfw_engine.api.grpc.server")


def _server_credentials(config):
    """Build gRPC server credentials from the configured key material.

    Returns ``None`` when TLS is disabled, which the caller treats as a
    refusal rather than a convenience: this transport carries the API key, and
    ``add_insecure_port`` sends it across the network in cleartext.
    """
    tls = config.transport.grpc
    if not tls.tls_enabled:
        return None
    if not (tls.tls_cert_file and tls.tls_key_file):
        raise RuntimeError(
            "SECURITY: transport.grpc.tls_enabled is true but no "
            "tls_cert_file/tls_key_file were configured. This transport "
            "carries the API key; refusing to serve it in cleartext. Set the "
            "key material, or explicitly set tls_enabled=false for a "
            "loopback-only deployment."
        )

    import grpc  # type: ignore

    try:
        with open(tls.tls_cert_file, "rb") as handle:
            cert_bytes = handle.read()
        with open(tls.tls_key_file, "rb") as handle:
            key_bytes = handle.read()
        root_bytes = None
        if tls.tls_ca_file:
            with open(tls.tls_ca_file, "rb") as handle:
                root_bytes = handle.read()
    except OSError as exc:
        raise RuntimeError(
            f"SECURITY: gRPC TLS material could not be read: {exc}"
        ) from exc

    return grpc.ssl_server_credentials(
        [(cert_bytes, key_bytes)],
        root_certificates=root_bytes,
        require_client_auth=bool(tls.tls_require_client_auth),
    )


def create_server(engine: NsfwEngine, config: Optional[EngineConfig] = None):
    """Build (but do not start) a configured :class:`grpc.Server`."""
    if not GRPC_AVAILABLE:
        raise RuntimeError(
            "grpcio is not installed; cannot start the gRPC server. "
            "Install with: pip install grpcio grpcio-tools protobuf"
        )
    import grpc  # type: ignore

    config = config or engine.config

    # SECURITY: refuse to serve an unauthenticated-on-the-wire transport
    # unless an operator has explicitly accepted that trade-off.
    if (
        config.security.require_transport_tls
        and not config.transport.grpc.tls_enabled
        and config.transport.grpc.host not in ("127.0.0.1", "::1", "localhost")
    ):
        raise RuntimeError(
            "SECURITY: refusing to start gRPC on "
            f"{config.transport.grpc.host}:50051 without TLS. This transport "
            "carries the API key in its metadata, so an unencrypted listener "
            "exposes the credential to every hop on the path. Configure "
            "transport.grpc.tls_*, or bind to loopback, or set "
            "security.require_transport_tls=false."
        )

    options = [
        ("grpc.max_receive_message_length", config.transport.grpc.max_message_bytes),
        ("grpc.max_send_message_length", config.transport.grpc.max_message_bytes),
    ]
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=config.transport.grpc.max_workers),
        options=options,
    )
    pb_grpc.add_NsfwEngineServicer_to_server(NsfwEngineServicer(engine), server)
    address = f"{config.transport.grpc.host}:{config.transport.grpc.port}"

    credentials = _server_credentials(config)
    if credentials is not None:
        bound = server.add_secure_port(address, credentials)
        if not bound:
            raise RuntimeError(f"failed to bind gRPC TLS on {address}")
        logger.info("gRPC listening with TLS on %s", address)
    else:
        server.add_insecure_port(address)
        logger.warning(
            "gRPC listening WITHOUT TLS on %s - the API key crosses this "
            "connection in cleartext",
            address,
        )
    return server, address


def serve(config: Optional[EngineConfig] = None) -> None:  # pragma: no cover - runtime
    """Initialise the engine and serve until interrupted."""
    setup_logging()
    config = config or get_config()
    engine = NsfwEngine(config)
    server, address = create_server(engine, config)
    server.start()
    logger.info("gRPC server listening on %s", address)

    stopping = {"flag": False}

    def _handle_signal(signum, _frame):
        logger.info("received signal %s - shutting down", signum)
        stopping["flag"] = True

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    try:
        while not stopping["flag"]:
            time.sleep(0.5)
    finally:
        server.stop(grace=5).wait()
        logger.info("gRPC server stopped")


if __name__ == "__main__":  # pragma: no cover
    try:
        serve()
    except Exception as exc:  # noqa: BLE001
        print(f"fatal: {exc}", file=sys.stderr)
        raise
