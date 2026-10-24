"""FastAPI entrypoint for the NSFW firewall engine.

This module exists so ``uvicorn app.main:app`` and ``python -m app.main`` work.
The application itself is built by :func:`app.api.rest.router.create_app`, which
is the single wiring point for the engine, the security context, the rate
limiter and every router (the legacy aliases plus the ``/v1`` contract of §20).

Why this file was rewritten
---------------------------
A previous version carried its own ``/inspect`` endpoint, its own cache and its
own Prometheus counters, and imported from a package path
(``nsfw_firewall_engine.storage.cache``) that does not exist in this layout - so
``import app.main`` raised ``ModuleNotFoundError`` and nothing could have used
it. Worse, its metric names (``nsfw_requests_total``, ``nsfw_cache_hits_total``,
``nsfw_queue_depth``) collide with the real registry in
:mod:`app.core.metrics`: registering the same metric name twice against
Prometheus's default registry raises at import time. Keeping it would have been
a trap for the next person to try to run the server.

The retired version is kept at ``app/main.py.legacy`` for reference only; it is
not importable and is not on the packaging path.

Run locally::

    python -m app.main
"""

from __future__ import annotations

import logging
import os
import sys

# Load environment variables from .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv is optional

# Allow `python -m app.main` from a source checkout without installation.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.api.rest.router import create_app  # noqa: E402
from app.core.config import get_config  # noqa: E402
from app.core.engine import NsfwEngine  # noqa: E402
from app.core.logging_setup import setup_logging  # noqa: E402

logger = logging.getLogger("nsfw_engine.main")

#: The ASGI application object, for `uvicorn app.main:app`.
#:
#: Built lazily by :func:`get_app` so that importing this module stays cheap and
#: side-effect free for tooling that only needs the factory.
app = None


def get_app():
    """Return the configured ASGI app, building it on first use."""
    global app
    if app is None:
        settings = get_config()
        setup_logging(level=settings.observability.log_level)

        # SECURITY: Validate authentication is enabled in production
        is_production = settings.engine.environment == "production"
        if (
            is_production
            and getattr(settings.engine, "require_auth_in_production", True)
            and not settings.security.enabled
        ):
            logger.critical(
                "SECURITY VIOLATION: security.enabled=false in production environment. "
                "This allows unauthenticated access to all endpoints. "
                "Set security.enabled=true or set engine.require_auth_in_production=false "
                "if you understand the risks. Aborting startup."
            )
            raise RuntimeError(
                "SECURITY: Authentication must be enabled in production. "
                "Set security.enabled=true in config/engine_config.yaml"
            )
        #     )

        app = create_app(engine=NsfwEngine(settings))
        logger.info(
            "application ready (engine_mode=%s, firewall_mode=%s, security_enabled=%s)",
            settings.engine.mode,
            settings.firewall.mode,
            settings.security.enabled,
        )
    return app


def main() -> int:
    """Run the server.

    ``reload`` defaults to **False** and is opt-in via ``NSFW_RELOAD=1``. Reload
    is a development convenience that spawns a supervisor and watches the source
    tree; leaving it enabled in a container is a self-inflicted outage, because
    the watcher restarts the workers whenever any file under the app directory
    is touched.
    """
    import uvicorn

    settings = get_config()
    reload_enabled = os.environ.get("NSFW_RELOAD", "0") == "1"
    if reload_enabled:
        logger.warning("NSFW_RELOAD=1: auto-reload is enabled - do not use this in production")

    uvicorn.run(
        get_app(),
        host=settings.transport.rest.host,
        port=settings.transport.rest.port,
        reload=reload_enabled,
        log_level=settings.observability.log_level.lower(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
