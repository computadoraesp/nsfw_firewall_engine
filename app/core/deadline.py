"""Latency budgets and deadlines (§ timeouts, § engine.request_timeout_ms).

The configuration declares strict per-stage budgets (fast 10 ms, deep 40 ms,
multimodal 90 ms) and a global per-request budget. Until now those values were
carried around but never *applied*, which meant a slow or pathological payload
could occupy a worker far beyond the advertised budget.

Honesty note (this matters operationally)
-----------------------------------------
Pure Python cannot preempt a blocking native call - an ONNX Runtime ``run()`` or
a Pillow decode that has already started cannot be interrupted safely. So this
module implements **detect-and-fail-safe**, not hard preemption:

* the deadline is checked before each stage (so escalation stops early) and
  immediately after it completes (so an overrun is recorded);
* an overrun is surfaced as ``timed_out=True`` plus an error, which routes the
  request through the policy engine's ``fail_action``.

That means the *decision* is always bounded and always auditable, and a hard
budget that must never be exceeded belongs in front of the service (proxy, ICAP
socket timeout, container CPU limit) - which is exactly where the ICAP 30 s
socket timeout and the Helm resource limits already sit.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


class BudgetExceeded(RuntimeError):
    """Raised internally when a stage or request budget is exhausted."""


@dataclass
class Deadline:
    """A wall-clock budget shared across the stages of one request."""

    budget_ms: float = 0.0
    #: Optional per-stage budgets keyed by DecisionPath value.
    stage_budgets: dict = field(default_factory=dict)
    #: When False, per-stage overruns are recorded but are not treated as
    #: breaches. The engine disables this while running the heuristic fallback,
    #: because the per-stage budgets describe *model* SLOs (fast path < 10 ms)
    #: and measuring a Python stub against them would raise spurious
    #: fail_actions. The global request budget always applies.
    enforce_stage_budgets: bool = True
    started_at: float = field(default_factory=time.perf_counter)
    timed_out: bool = False
    #: Stage that consumed the budget, for the audit trail.
    breached_at: Optional[str] = None

    # -- clock ---------------------------------------------------------------
    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self.started_at) * 1000.0

    def remaining_ms(self) -> float:
        if self.budget_ms <= 0:
            return float("inf")
        return max(0.0, self.budget_ms - self.elapsed_ms())

    @property
    def expired(self) -> bool:
        return self.budget_ms > 0 and self.remaining_ms() <= 0.0

    # -- enforcement ---------------------------------------------------------
    def stage_budget_ms(self, path: str) -> float:
        return float(self.stage_budgets.get(path, 0.0) or 0.0)

    def check(self, path: str = "") -> None:
        """Raise :class:`BudgetExceeded` when the budget is already spent.

        Called *before* a stage so an exhausted budget prevents further (and
        progressively more expensive) work.
        """
        if self.expired:
            self._mark(path or "request")
            raise BudgetExceeded(
                f"request budget of {self.budget_ms:.0f}ms exhausted before {path or 'next stage'}"
            )

    def check_stage(self, path: str, elapsed_ms: float) -> bool:
        """Record a completed stage; return ``True`` if a breach was recorded.

        A stage that already ran cannot be undone, so the breach is recorded and
        the caller decides whether to escalate. Returns whether a breach was
        actually *recorded*, which is what :attr:`timed_out` reflects - a stage
        overrun on the heuristic fallback is ignored unless stage budgets are
        being enforced.
        """
        budget = self.stage_budget_ms(path)
        overran = bool(budget) and elapsed_ms > budget
        recorded = self.expired or (overran and self.enforce_stage_budgets)
        if recorded:
            self._mark(path)
        return recorded

    def _mark(self, where: str) -> None:
        self.timed_out = True
        self.breached_at = self.breached_at or where

    def as_dict(self) -> dict:
        return {
            "budget_ms": self.budget_ms,
            "elapsed_ms": round(self.elapsed_ms(), 3),
            "remaining_ms": (None if self.remaining_ms() == float("inf") else round(self.remaining_ms(), 3)),
            "timed_out": self.timed_out,
            "breached_at": self.breached_at,
        }


def build_deadline(config) -> Deadline:
    """Create a request deadline from the typed engine configuration."""
    timeouts = getattr(config, "timeouts", None)
    stage_budgets = {}
    if timeouts is not None:
        stage_budgets = {
            "FAST": float(getattr(timeouts, "fast_path_ms", 0) or 0),
            "DEEP": float(getattr(timeouts, "deep_path_ms", 0) or 0),
            "MULTIMODAL": float(getattr(timeouts, "multimodal_ms", 0) or 0),
            "PREMIUM": float(getattr(timeouts, "premium_ms", 0) or 0),
            "TEXT": float(getattr(timeouts, "text_ms", 0) or 0),
        }
    return Deadline(
        budget_ms=float(getattr(getattr(config, "engine", None), "request_timeout_ms", 0) or 0),
        stage_budgets=stage_budgets,
    )


__all__ = ["BudgetExceeded", "Deadline", "build_deadline"]