# policy/engine.py
"""Policy engine core (pront.md §19).

Loads a policy definition (JSON or YAML) and evaluates a request context against
the ordered rule list. The **first matching rule wins**; if none match, the
policy's ``default_action`` applies.

Implemented behaviors
---------------------
* Declarative rules (``field`` / ``operator`` / ``value`` / ``action``) with
  numeric, string, membership and regex operators — no ``eval``, so a policy
  file can never execute code.
* **Tenant isolation**: a tenant-bound policy always wins over the global
  policy, and a tenant can never be served another tenant's policy (§37).
* **Auditable decisions**: every decision records which rule fired.
* **Fail-safe**: a malformed rule is skipped and logged; it never prevents the
  remaining rules, or the default action, from applying.

Expected file format::

    {
      "policy_id": "global",
      "description": "Default corporate policy",
      "default_action": "review",
      "rules": [
        {"field": "verdict", "operator": "==", "value": "NSFW", "action": "block"},
        {"field": "score", "operator": ">=", "value": 0.75, "action": "block"},
        {"field": "media_type", "operator": "in", "value": ["TEXT", "HTML"],
         "action": "allow"}
      ]
    }
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .models import Decision, Policy, Rule

logger = logging.getLogger(__name__)

#: Default policy used when no policy file is supplied.
DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "field": "verdict",
        "operator": "==",
        "value": "NSFW",
        "action": "block",
        "description": "Explicit content is blocked",
    },
    {
        "field": "score",
        "operator": ">=",
        "value": 0.75,
        "action": "block",
        "description": "Risk score at or above the hard threshold",
    },
    {
        "field": "verdict",
        "operator": "==",
        "value": "REVIEW",
        "action": "review",
        "description": "Ambiguous content is flagged for human review",
    },
    {
        "field": "verdict",
        "operator": "==",
        "value": "SFW",
        "action": "allow",
        "description": "Classified safe",
    },
]


def _load_raw(file_path: str | Path) -> Dict[str, Any]:
    """Read a JSON or YAML policy file into a dict."""
    path = Path(file_path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yml", ".yaml"):
        import yaml

        return yaml.safe_load(text) or {}
    return json.loads(text)


def _build_rules(raw_rules: Iterable[Dict[str, Any]]) -> List[Rule]:
    """Build rules, skipping (and logging) any malformed or unsafe entry."""
    rules: List[Rule] = []
    for raw in raw_rules or []:
        try:
            operator = str(raw.get("operator", "=="))
            value = raw.get("value")
            # SECURITY: a `matches` rule pairs an operator-supplied pattern with
            # request-controlled data. A catastrophic pattern like ``(a+)+$``
            # is a CPU sink reachable by anyone who can install a policy, so it
            # is rejected here - at install time, before it can be armed -
            # rather than being allowed to fire later against live traffic.
            if operator.strip().lower() == "matches":
                from .models import regex_is_safe

                if not regex_is_safe(str(value)):
                    logger.error(
                        "rejecting policy rule %r: the pattern is unsafe for the "
                        "'matches' operator (catastrophic backtracking or an "
                        "invalid expression)",
                        raw.get("field"),
                    )
                    continue
            rules.append(
                Rule(
                    field=str(raw["field"]),
                    operator=operator,
                    value=value,
                    action=str(raw.get("action", "allow")),
                    description=str(raw.get("description", "")),
                )
            )
        except (KeyError, TypeError) as exc:
            logger.warning("skipping malformed policy rule %r: %s", raw, exc)
    return rules


def policy_from_dict(raw: Dict[str, Any]) -> Policy:
    """Convert a raw policy mapping into a :class:`Policy`."""
    return Policy(
        policy_id=str(raw.get("policy_id", "default")),
        description=str(raw.get("description", "")),
        rules=_build_rules(raw.get("rules", [])),
        default_action=str(raw.get("default_action", "review")),
        tenant_id=str(raw.get("tenant_id", "")),
    )


def load_policy_file(file_path: str | Path) -> Policy:
    """Load a policy from a JSON or YAML file."""
    return policy_from_dict(_load_raw(file_path))


def default_policy() -> Policy:
    """Return the built-in default policy (no file required)."""
    return Policy(
        policy_id="default",
        description="Built-in default policy",
        rules=_build_rules(DEFAULT_RULES),
        default_action="review",
    )
def policy_from_config(policy_config: Any) -> Policy:
    """Build a rule-based :class:`Policy` from the typed engine config.

    This is the bridge used by the running engine: the verdict->action mapping
    in ``config/engine_config.yaml`` is expressed as ordered rules, so config
    and file-based policies share one evaluation model and one source of truth.
    """
    return Policy(
        policy_id=str(getattr(policy_config, "default_policy_id", "default")),
        description="Derived from config/engine_config.yaml (policy section)",
        rules=[
            # A failed or timed-out classification must NOT be enforced as if we
            # were confident about it - it goes straight to fail_action. This
            # rule comes first precisely so nothing can override it.
            Rule("error", "!=", "", getattr(policy_config, "fail_action", "allow")),
            Rule("verdict", "==", "NSFW", getattr(policy_config, "nsfw_action", "block")),
            Rule("verdict", "==", "REVIEW", getattr(policy_config, "review_action", "review")),
            Rule("verdict", "==", "SFW", getattr(policy_config, "sfw_action", "allow")),
            Rule(
                "verdict",
                "==",
                "UNKNOWN",
                getattr(policy_config, "fail_action", "allow"),
            ),
        ],
        default_action=str(getattr(policy_config, "fail_action", "allow")).lower(),
    )


class PolicyRegistry:
    """Holds the global policy plus optional tenant-specific overrides (§37)."""

    def __init__(self, global_policy: Optional[Policy] = None) -> None:
        self.global_policy = global_policy or default_policy()
        self._tenant_policies: Dict[str, Policy] = {}
        self._tenant_rules: Dict[str, List[Dict[str, Any]]] = {}

    def add_tenant(self, tenant_id: str, policy: Policy) -> None:
        if tenant_id:
            self._tenant_policies[tenant_id] = policy

    def add_tenant_rules(self, tenant_id: str, rules: Iterable[Dict[str, Any]]) -> None:
        """Register rule overrides for *tenant_id* from the config block."""
        if tenant_id:
            self._tenant_rules[tenant_id] = [
                rule.as_dict() for rule in _build_rules(rules)
            ]

    def policy_for(self, tenant_id: str = "") -> Policy:
        """Return the most specific policy for *tenant_id* (tenant > global)."""
        if tenant_id:
            explicit = self._tenant_policies.get(tenant_id)
            if explicit is not None:
                return explicit
            overrides = self._tenant_rules.get(tenant_id)
            if overrides:
                # A tenant override replaces the verdict mapping but keeps the
                # global default action, so a tenant can never widen access by
                # omission.
                return Policy(
                    policy_id=f"{self.global_policy.policy_id}:{tenant_id}",
                    description=f"Tenant override for {tenant_id}",
                    rules=_build_rules(overrides),
                    default_action=self.global_policy.default_action,
                    tenant_id=tenant_id,
                )
        return self.global_policy

    def evaluate(self, context: Dict[str, Any], tenant_id: str = "") -> Decision:
        """Evaluate *context* under the policy bound to *tenant_id*."""
        if tenant_id:
            context = {**context, "tenant_id": tenant_id}
        policy = self.policy_for(tenant_id)
        try:
            return policy.evaluate(context)
        except Exception as exc:  # noqa: BLE001 - fail-safe on the last resort
            logger.exception("policy evaluation failed for tenant %r", tenant_id)
            return Decision(
                policy_id=policy.policy_id,
                action=policy.default_action,
                metadata={"rule_description": f"evaluation_error: {exc}"},
            )


def evaluate_request(context: Dict[str, Any], policy: Policy) -> Decision:
    """Run a single :class:`Policy` against *context* (back-compat helper)."""
    return policy.evaluate(context)


__all__ = [
    "DEFAULT_RULES",
    "PolicyRegistry",
    "default_policy",
    "evaluate_request",
    "load_policy_file",
    "policy_from_config",
    "policy_from_dict",
]