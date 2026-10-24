"""Policy adapter for the transport/orchestrator layer (Sec. 19).

The rule engine itself lives in the top-level :mod:`policy` package, which owns
rule parsing, operators, the tenant registry and audit metadata. This module is
the thin bridge the engine/transports depend on: it flattens a
:class:`~app.core.engine.ClassificationResult` into a rule context, evaluates
it, and exposes a vendor-neutral action/decision.

Keeping the bridge separate avoids an import cycle (the rule engine must never
import the orchestrator) and means file-based and config-based policies are
evaluated by exactly the same code.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict

from policy.engine import PolicyRegistry, policy_from_config

from app.models.base import Verdict

logger = logging.getLogger("nsfw_engine.core.policy")


class PolicyAction(str, Enum):
    """Enforcement action returned to the firewall / SWG."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    QUARANTINE = "QUARANTINE"


#: Actions that stop traffic from reaching the client.
BLOCKING_ACTIONS = frozenset({PolicyAction.BLOCK, PolicyAction.QUARANTINE})

#: Rule-engine action -> public enum.
_ACTION_MAP: Dict[str, PolicyAction] = {
    "allow": PolicyAction.ALLOW,
    "block": PolicyAction.BLOCK,
    "review": PolicyAction.REVIEW,
    "quarantine": PolicyAction.QUARANTINE,
}


@dataclass
class PolicyDecision:
    """The auditable outcome of applying policy to a classification."""

    action: PolicyAction
    policy_id: str
    reason: str
    risk_score: float = 0.0
    verdict: str = Verdict.UNKNOWN.value
    media_type: str = "UNKNOWN"
    decided_by: str = "UNKNOWN"
    tenant_id: str = ""
    #: In audit mode (§30) the action the decision *would* have had.
    would_be_action: str = ""
    #: Operating mode this decision was made under.
    mode: str = "enforcement"
    #: The §19 dimensions this decision was evaluated against, so an auditor can
    #: reconstruct *why* a rule fired without replaying the request.
    matched_dimensions: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_blocking(self) -> bool:
        return self.action in BLOCKING_ACTIONS

    def as_dict(self) -> dict:
        return {
            "action": self.action.value,
            "policy_id": self.policy_id,
            "reason": self.reason,
            "risk_score": round(float(self.risk_score), 6),
            "verdict": self.verdict,
            "media_type": self.media_type,
            "decided_by": self.decided_by,
            "tenant_id": self.tenant_id,
            "is_blocking": self.is_blocking,
            "would_be_action": self.would_be_action,
            "mode": self.mode,
            "matched_dimensions": dict(self.matched_dimensions),
        }


class PolicyEngine:
    """Verdict -> action mapping, delegated to the :mod:`policy` rule engine."""

    def __init__(self, config: Any, firewall_config: Any = None) -> None:
        self.config = config
        # Firewall mode (§30). None => enforcement, preserving the pre-existing
        # single-argument construction used by tests and external callers.
        self.firewall_config = firewall_config
        self.mode = str(getattr(firewall_config, "mode", "enforcement") or "enforcement")
        self.report_would_be = bool(getattr(firewall_config, "report_would_be", True))
        self.registry = PolicyRegistry(policy_from_config(config))
        # Tenant overrides come from config; they only redirect behaviour, never
        # silently widen the global default.
        overrides_cfg = getattr(config, "tenant_overrides", None) or {}
        for tenant_id, overrides in overrides_cfg.items():
            if not isinstance(overrides, dict):
                continue
            self.registry.add_tenant_rules(
                tenant_id,
                [
                    {
                        "field": "verdict",
                        "operator": "==",
                        "value": str(verdict).upper(),
                        "action": str(action),
                        "description": f"tenant override for {tenant_id}",
                    }
                    for verdict, action in overrides.items()
                ],
            )

    @staticmethod
    def build_context(result: Any) -> Dict[str, Any]:
        """Flatten a classification result into the rule-engine context."""
        verdict = getattr(result, "verdict", Verdict.UNKNOWN)
        media_type = getattr(result, "media_type", "UNKNOWN")
        decided_by = getattr(result, "decided_by", "UNKNOWN")
        text = getattr(result, "text", None) or {}
        return {
            "verdict": verdict.value if hasattr(verdict, "value") else str(verdict),
            "score": float(getattr(result, "score", 0.0) or 0.0),
            "error": str(getattr(result, "error", "") or ""),
            "media_type": media_type.value if hasattr(media_type, "value") else str(media_type),
            "decided_by": decided_by.value if hasattr(decided_by, "value") else str(decided_by),
            "stages": len(getattr(result, "stages", []) or []),
            "text": text if isinstance(text, dict) else {},
            "from_cache": bool(getattr(result, "from_cache", False)),
        }

    def decide(
        self,
        result: Any,
        tenant_id: str = "",
        request_context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """Apply policy to a classification result.

        *result* only needs ``verdict``, ``score``, ``error``, ``media_type`` and
        ``decided_by``, so this works with the native result type and with test
        stubs alike.

        *request_context* carries the §19 dimensions the classification cannot
        know about the caller - tenant, user, groups, device, zone, url, domain
        and time. It is merged over the result-derived context, so a caller that
        does not supply one keeps the previous behaviour exactly.
        """
        context = self.build_context(result)
        if request_context:
            context.update(request_context)
        try:
            outcome = self.registry.evaluate(context, tenant_id=tenant_id)
            action = _ACTION_MAP.get(outcome.action, PolicyAction.ALLOW)
            reason = (
                f"{context['verdict']} -> {action.value} "
                f"({outcome.metadata.get('rule_description', 'default')})"
            )
            policy_id = outcome.policy_id
        except Exception:  # noqa: BLE001 - never let policy break a request
            logger.exception("policy evaluation failed")
            action = PolicyAction(str(self.config.fail_action).upper())
            reason = f"policy error, applying fail_action={action.value}"
            policy_id = self.config.default_policy_id
            # SECURITY ALERT: Log when fail_action is triggered - this indicates a problem
            logger.critical(
                "SECURITY ALERT: fail_action=%s triggered due to policy evaluation failure. "
                "Requests may be %s. Investigate immediately.",
                action.value,
                "blocked" if action == PolicyAction.BLOCK else "allowed",
            )

        return PolicyDecision(
            policy_id=policy_id,
            risk_score=context["score"],
            verdict=context["verdict"],
            media_type=context["media_type"],
            decided_by=context["decided_by"],
            tenant_id=tenant_id,
            # §19 audit trail: the caller dimensions this decision saw, so a
            # reviewer can see that a rule on `zone` fired *because* the request
            # arrived in that zone rather than for some unrelated reason.
            matched_dimensions={
                key: context.get(key)
                for key in (
                    "tenant_id",
                    "user_id",
                    "groups_csv",
                    "device_id",
                    "zone",
                    "url",
                    "domain",
                    "category",
                )
                if context.get(key)
            },
            **self._apply_firewall_mode(action, reason),
        )

    def _apply_firewall_mode(self, action: PolicyAction, reason: str) -> dict:
        """Simulate the decision in audit mode without changing enforcement.

        In audit mode the *classification and policy* still run exactly as they
        would in enforcement, but the returned action is forced to ALLOW and the
        suppressed action is reported in ``would_be_action`` so operators can
        tune thresholds against live traffic safely (§30).
        """
        if self.mode != "audit":
            return {"action": action, "reason": reason, "mode": "enforcement"}
        return {
            "action": PolicyAction.ALLOW,
            "would_be_action": action.value if self.report_would_be else "",
            "mode": "audit",
            "reason": f"{reason} [audit mode: simulated {action.value}, not enforced]",
        }


__all__ = ["PolicyAction", "PolicyDecision", "PolicyEngine", "BLOCKING_ACTIONS"]