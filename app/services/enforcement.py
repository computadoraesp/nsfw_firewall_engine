"""Enforcement adapters for firewall / SWG integration (Sec. 5 / Sec. 30).

The policy engine produces a vendor-neutral :class:`PolicyDecision`; these
adapters translate it into what a concrete enforcement point expects:

* :class:`HttpEnforcementAdapter` - a status code, headers and a block page
  for a reverse proxy or an inline firewall.
* :class:`IcapEnforcementAdapter` - the ICAP responses consumed by Squid/mitm
  proxies (reusing the wire helpers in :mod:`app.api.icap.icap_server`).
* :class:`NginxEnforcementAdapter` - a ``deny``/``return`` snippet so an NGINX
  SWG can apply the same decision without a second policy implementation.

Keeping every translation here means swapping the classifier, the proxy or the
firewall vendor never touches the policy rules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from app.core.policy import PolicyAction, PolicyDecision

logger = logging.getLogger("nsfw_engine.services.enforcement")

#: Content-Security-Policy style hardening applied to every block page.
_BLOCK_HEADERS: Dict[str, str] = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-NSFW-Verdict": "blocked",
}


@dataclass
class EnforcementResponse:
    """A ready-to-send enforcement response."""

    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    action: PolicyAction = PolicyAction.ALLOW

    @property
    def is_blocking(self) -> bool:
        return self.action in (PolicyAction.BLOCK, PolicyAction.QUARANTINE)


def _escape(value: Any) -> str:
    """Minimal HTML escaping for values echoed into the block page."""
    text = str(value)
    for char, entity in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ('"', "&quot;")):
        text = text.replace(char, entity)
    return text


_BLOCK_PAGE = (
    "<!doctype html><html><head><title>Blocked</title></head><body>"
    "<h1>{status}</h1><p>{message}</p>"
    "<p>policy={policy} verdict={verdict} score={score:.3f}</p>"
    "</body></html>"
)


class BaseEnforcementAdapter:
    """Shared decision -> response mapping."""

    def __init__(self, config: Any) -> None:
        self.config = config

    def status_for(self, action: PolicyAction) -> int:
        if action is PolicyAction.QUARANTINE:
            return int(getattr(self.config, "quarantine_status_code", 451))
        return int(getattr(self.config, "block_status_code", 403))

    def should_block(self, decision: PolicyDecision) -> bool:
        return decision.action in (PolicyAction.BLOCK, PolicyAction.QUARANTINE)


class HttpEnforcementAdapter(BaseEnforcementAdapter):
    """Translate a decision into an HTTP response for an inline proxy."""

    def response_for(self, decision: PolicyDecision) -> EnforcementResponse:
        if not self.should_block(decision):
            return EnforcementResponse(status_code=200, headers={}, body=b"", action=decision.action)
        status_code = self.status_for(decision.action)
        reason = "451 Unavailable For Legal Reasons" if status_code == 451 else "403 Forbidden"
        html = _BLOCK_PAGE.format(
            status=reason,
            message=_escape(getattr(self.config, "block_message", "Blocked by policy")),
            policy=_escape(decision.policy_id),
            verdict=_escape(decision.verdict),
            score=max(0.0, min(1.0, float(decision.risk_score))),
        )
        headers = dict(_BLOCK_HEADERS)
        headers["Content-Length"] = str(len(html.encode("utf-8")))
        return EnforcementResponse(
            status_code=status_code,
            headers=headers,
            body=html.encode("utf-8"),
            action=decision.action,
        )


class IcapEnforcementAdapter(BaseEnforcementAdapter):
    """Translate a decision into ICAP responses for Squid / MITM proxies."""

    def __init__(self, config: Any, service_tag: Optional[str] = None) -> None:
        super().__init__(config)
        self.service_tag = service_tag or "nsfw-firewall"

    def response_bytes(self, decision: PolicyDecision) -> bytes:
        from app.api.icap.icap_server import build_allow_response, build_block_response

        if not self.should_block(decision):
            return build_allow_response(self.service_tag)
        return build_block_response(
            self.service_tag, decision.verdict, float(decision.risk_score)
        )


class NginxEnforcementAdapter(BaseEnforcementAdapter):
    """Render an NGINX SWG snippet enforcing the same decision."""

    def render(self, decision: PolicyDecision) -> str:
        if not self.should_block(decision):
            return "# decision=ALLOW - pass through\n"
        code = self.status_for(decision.action)
        return (
            f"# decision={decision.action.value} policy={decision.policy_id} "
            f"verdict={decision.verdict}\n"
            f"if ($nsfw_decision = '{decision.verdict}') {{\n"
            f"    add_header X-NSFW-Policy '{decision.policy_id}' always;\n"
            f"    return {code} /nsfw_blocked.html;\n"
            f"}}\n"
        )


#: Adapters keyed by enforcement point, for a registry-driven dispatch.
ADAPTERS = {
    "http": HttpEnforcementAdapter,
    "icap": IcapEnforcementAdapter,
    "nginx": NginxEnforcementAdapter,
}


def get_adapter(kind: str, config: Any, **kwargs: Any) -> BaseEnforcementAdapter:
    """Instantiate an enforcement adapter by name."""
    try:
        factory = ADAPTERS[kind.lower()]
    except KeyError as exc:
        raise ValueError(
            f"unknown enforcement adapter {kind!r}; available: {sorted(ADAPTERS)}"
        ) from exc
    return factory(config, **kwargs)


__all__ = [
    "ADAPTERS",
    "BaseEnforcementAdapter",
    "EnforcementResponse",
    "HttpEnforcementAdapter",
    "IcapEnforcementAdapter",
    "NginxEnforcementAdapter",
    "get_adapter",
]