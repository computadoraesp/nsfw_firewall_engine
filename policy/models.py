# policy/models.py
"""Data models for the policy engine.

Defines :class:`Rule`, :class:`Policy` and :class:`Decision` — the vocabulary
shared by the rule evaluator (:mod:`policy.engine`), the enforcement adapters and
the transports.

A *rule* is deliberately declarative (field / operator / value / action) rather
than a compiled lambda: policies then stay serialisable, reviewable by security
auditors, diffable in Git, and loadable from JSON/YAML at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: Actions a rule or default may produce.
ACTIONS = ("allow", "block", "review", "quarantine")

#: Comparison operators understood by :meth:`Rule.evaluate`.
OPERATORS = (">=", ">", "<=", "<", "==", "!=", "in", "not in", "contains", "matches")


@dataclass
class Rule:
    """A single rule within a policy.

    Attributes:
        field: Dotted path into the request context, e.g. ``"score"``,
            ``"verdict"``, ``"media_type"`` or ``"text.score"``.
        operator: One of :data:`OPERATORS`. ``==``/``!=`` compare numerically
            when both sides look numeric, otherwise as strings.
        value: The right-hand side of the comparison.
        action: Action when the rule matches (see :data:`ACTIONS`).
        description: Optional human-readable note for audit records.
    """

    field: str
    operator: str
    value: Any
    action: str
    description: str = ""

    def __post_init__(self) -> None:
        self.operator = (self.operator or "==").strip()
        self.action = (self.action or "allow").strip().lower()

    @staticmethod
    def _lookup(context: Dict[str, Any], path: str) -> Any:
        """Resolve a dotted path, returning ``None`` when absent."""
        current: Any = context
        for part in str(path or "").split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    @staticmethod
    def _as_number(value: Any) -> Optional[float]:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Return ``True`` when this rule matches *context*.

        Never raises: a missing field or unparseable operand yields ``False`` so
        one bad rule cannot break enforcement for the whole policy.
        """
        actual = self._lookup(context, self.field)
        if actual is None:
            return False

        op = self.operator
        try:
            if op in (">", ">=", "<", "<="):
                left = self._as_number(actual)
                right = self._as_number(self.value)
                if left is None or right is None:
                    return False
                return {
                    ">": left > right,
                    ">=": left >= right,
                    "<": left < right,
                    "<=": left <= right,
                }[op]

            if op in ("==", "!="):
                left_num = self._as_number(actual)
                right_num = self._as_number(self.value)
                equal = (
                    left_num == right_num
                    if left_num is not None and right_num is not None
                    else str(actual).strip().lower() == str(self.value).strip().lower()
                )
                return equal if op == "==" else not equal

            if op == "in":
                options = (
                    self.value if isinstance(self.value, (list, tuple, set)) else [self.value]
                )
                target = str(actual).strip().lower()
                return any(str(option).strip().lower() == target for option in options)

            if op == "not in":
                return not Rule("_", "in", self.value, "allow").evaluate(
                    {self.field: actual}
                )

            if op == "contains":
                # The rule value is a list: does the field's value appear in it?
                if isinstance(self.value, (list, tuple, set)):
                    target = str(actual).strip().lower()
                    return any(
                        str(item).strip().lower() == target for item in self.value
                    )
                # The field's value is a list: does it contain the needle?
                # Without this branch `{"field": "groups", "operator": "contains",
                # "value": "contractor"}` - the natural way to write a group rule
                # (§19) - silently never matched, because a list has no
                # `.lower()`. A rule that quietly never fires is worse than one
                # that is visibly broken.
                if isinstance(actual, (list, tuple, set)):
                    needle = str(self.value).strip().lower()
                    return any(str(item).strip().lower() == needle for item in actual)
                if isinstance(actual, str):
                    return str(self.value).strip().lower() in actual.lower()
                return False

            if op == "matches":
                import re

                return re.search(str(self.value), str(actual), re.IGNORECASE) is not None
        except Exception:  # noqa: BLE001 - a bad rule must not break enforcement
            return False
        return False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "operator": self.operator,
            "value": self.value,
            "action": self.action,
            "description": self.description,
        }
@dataclass
class Policy:
    """An ordered, tenant-scoped collection of rules.

    Rules are evaluated top-to-bottom and the **first match wins**, so ordering
    is the only precedence mechanism needed — the same mental model as a
    firewall ACL, which keeps policy review tractable.
    """

    policy_id: str
    description: str = ""
    rules: List[Rule] = field(default_factory=list)
    default_action: str = "review"
    #: Tenant this policy is bound to; ``"*"`` or empty means global.
    tenant_id: str = ""

    def __post_init__(self) -> None:
        self.default_action = (self.default_action or "review").strip().lower()

    def evaluate(self, context: Dict[str, Any]) -> "Decision":
        """Return the decision produced by the first matching rule."""
        for index, rule in enumerate(self.rules):
            try:
                if rule.evaluate(context):
                    return Decision(
                        policy_id=self.policy_id,
                        action=rule.action,
                        matched_rule=rule,
                        metadata={
                            "rule_index": str(index),
                            "rule_description": rule.description or rule.field,
                        },
                    )
            except Exception:  # noqa: BLE001 - skip a broken rule, keep enforcing
                continue
        return Decision(
            policy_id=self.policy_id,
            action=self.default_action,
            matched_rule=None,
            metadata={"rule_index": "-1", "rule_description": "default"},
        )


@dataclass
class Decision:
    """Auditable result of evaluating a :class:`Policy`."""

    policy_id: str
    action: str
    matched_rule: Optional[Rule] = None
    metadata: Dict[str, str] = field(default_factory=dict)

    @property
    def is_blocking(self) -> bool:
        return self.action in ("block", "quarantine")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "action": self.action,
            "matched_rule": self.matched_rule.as_dict() if self.matched_rule else None,
            "metadata": dict(self.metadata),
            "is_blocking": self.is_blocking,
        }


__all__ = ["ACTIONS", "OPERATORS", "Decision", "Policy", "Rule"]