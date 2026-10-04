# firewall/adapter.py
"""Enforcement adapters for the NSFW firewall engine.

The engine produces a *decision* (`ALLOW`, `BLOCK`, `REVIEW`, `QUARANTINE`).
An *adapter* translates that decision into concrete actions on the surrounding
network component (proxy, SWG, firewall, etc.).

Only a generic abstract base class is provided here; concrete implementations can
inherit from it and implement the low‑level calls for a specific vendor or
protocol (REST, gRPC, ICAP, iptables, etc.).
"""

from __future__ import annotations

import abc
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


class EnforcementAdapter(abc.ABC):
    """Base class for all enforcement adapters.

    Sub‑classes must implement the four core actions.  The ``context`` argument
    is a dictionary containing request metadata (tenant, user, url, scores, …).
    """

    @abc.abstractmethod
    def allow(self, context: Dict[str, Any]) -> None:
        """Permit the request to continue unchanged."""

    @abc.abstractmethod
    def block(self, context: Dict[str, Any], reason: str | None = None) -> None:
        """Terminate the request and optionally provide a reason to the client."""

    @abc.abstractmethod
    def quarantine(self, context: Dict[str, Any]) -> None:
        """Divert the request to a quarantine bucket for later review."""

    @abc.abstractmethod
    def redirect(self, context: Dict[str, Any], destination: str) -> None:
        """Redirect the request to another endpoint (e.g., a safe landing page)."""

    # ---------------------------------------------------------------------
    # Helper – default logging implementation (can be called via super())
    # ---------------------------------------------------------------------
    def _log_action(self, action: str, context: Dict[str, Any], **extra: Any) -> None:
        logger.info(
            "Enforcement action=%s, tenant=%s, user=%s, url=%s, extra=%s",
            action,
            context.get("tenant_id"),
            context.get("user_id"),
            context.get("url"),
            extra,
        )

# -------------------------------------------------------------------------
# Example concrete adapter – a no‑op implementation useful for testing.
# -------------------------------------------------------------------------

class LoggingAdapter(EnforcementAdapter):
    """Very simple adapter that only logs actions (useful for dev and tests)."""

    def allow(self, context: Dict[str, Any]) -> None:
        self._log_action("ALLOW", context)

    def block(self, context: Dict[str, Any], reason: str | None = None) -> None:
        self._log_action("BLOCK", context, reason=reason)

    def quarantine(self, context: Dict[str, Any]) -> None:
        self._log_action("QUARANTINE", context)

    def redirect(self, context: Dict[str, Any], destination: str) -> None:
        self._log_action("REDIRECT", context, destination=destination)

__all__ = ["EnforcementAdapter", "LoggingAdapter"]
