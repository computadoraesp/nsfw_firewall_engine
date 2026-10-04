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


def create_server(engine: NsfwEngine, config: Optional[EngineConfig] = None):
    """Build (but do not start) a configured :class:`grpc.Server`."""
    if not GRPC_AVAILABLE:
        raise RuntimeError(
            "grpcio is not installed; cannot start the gRPC server. "
            "Install with: pip install grpcio grpcio-tools protobuf"
        )
    import grpc  # type: ignore

    config = config or engine.config
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
    server.add_insecure_port(address)
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
