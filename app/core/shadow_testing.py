"""Shadow Testing Engine for Canary Deployments.

Tests new models in production without risk by shadowing requests.
Architecture:
- Primary model: Currently serving traffic
- Shadow model: New model under test
- Requests sent to both, only primary response used
- Results compared offline for statistical analysis
"""

import logging
import time
import statistics
import threading
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum
import numpy as np

logger = logging.getLogger("nsfw_engine.core.shadow_testing")


class ShadowDecision(Enum):
    """Decision for shadow model promotion."""
    PROMOTE = "promote"
    REJECT = "reject"
    CONTINUE = "continue"


@dataclass
class ShadowResult:
    """Result from shadow model inference."""
    model_id: str
    verdict: str
    confidence: float
    risk_score: float
    latency_ms: float
    timestamp: float


@dataclass
class ShadowComparison:
    """Comparison between primary and shadow model."""
    latency_diff_ms: float
    accuracy_diff: float
    fpr_diff: float
    fnr_diff: float
    disagreement_rate: float
    recommendation: ShadowDecision
    statistical_significance: float


class ShadowTestingEngine:
    """Engine for shadow testing new models."""

    def __init__(self, shadow_model_id: str, primary_model_id: str = "fast_path"):
        self.shadow_model_id = shadow_model_id
        self.primary_model_id = primary_model_id
        self.enabled = bool(shadow_model_id)
        self.results: List[ShadowResult] = []
        self.max_samples = 10000
        self._lock = threading.Lock()

    def should_enable_shadow(self) -> bool:
        """Determine if shadow testing should be enabled."""
        return self.enabled

    def record_shadow_result(
        self,
        verdict: str,
        confidence: float,
        risk_score: float,
        latency_ms: float
    ) -> None:
        """Record shadow model result."""
        if not self.enabled:
            return

        result = ShadowResult(
            model_id=self.shadow_model_id,
            verdict=verdict,
            confidence=confidence,
            risk_score=risk_score,
            latency_ms=latency_ms,
            timestamp=time.time()
        )

        self.results.append(result)

        # Limit results to prevent memory issues
        if len(self.results) > self.max_samples:
            self.results = self.results[-self.max_samples:]

    def compare_with_primary(
        self,
        primary_results: List[Dict[str, Any]]
    ) -> ShadowComparison:
        """Compare shadow model with primary model."""
        if len(self.results) < 100:
            return ShadowComparison(
                latency_diff_ms=0.0,
                accuracy_diff=0.0,
                fpr_diff=0.0,
                fnr_diff=0.0,
                disagreement_rate=0.0,
                recommendation=ShadowDecision.CONTINUE,
                statistical_significance=0.0
            )

        # Calculate metrics
        shadow_latencies = [r.latency_ms for r in self.results]
        primary_latencies = [r.get("latency_ms", 0) for r in primary_results]

        latency_diff = statistics.mean(shadow_latencies) - statistics.mean(primary_latencies)

        # Calculate disagreement rate
        shadow_verdicts = [r.verdict for r in self.results]
        primary_verdicts = [r.get("verdict", "UNKNOWN") for r in primary_results]
        disagreements = sum(1 for s, p in zip(shadow_verdicts, primary_verdicts) if s != p)
        disagreement_rate = disagreements / len(self.results)

        # Statistical significance (simplified t-test)
        statistical_significance = self._calculate_statistical_significance(
            shadow_latencies, primary_latencies
        )

        # Determine recommendation
        recommendation = self._determine_recommendation(
            latency_diff, disagreement_rate, statistical_significance
        )

        return ShadowComparison(
            latency_diff_ms=latency_diff,
            accuracy_diff=0.0,  # Would need ground truth
            fpr_diff=0.0,  # Would need ground truth
            fnr_diff=0.0,  # Would need ground truth
            disagreement_rate=disagreement_rate,
            recommendation=recommendation,
            statistical_significance=statistical_significance
        )

    def _calculate_statistical_significance(
        self,
        shadow_latencies: List[float],
        primary_latencies: List[float]
    ) -> float:
        """Calculate statistical significance using t-test approximation."""
        if len(shadow_latencies) < 30 or len(primary_latencies) < 30:
            return 0.0

        try:
            from scipy import stats
            t_stat, p_value = stats.ttest_ind(shadow_latencies, primary_latencies)
            return p_value
        except ImportError:
            # Fallback: simple z-score approximation
            shadow_mean = statistics.mean(shadow_latencies)
            primary_mean = statistics.mean(primary_latencies)
            shadow_std = statistics.stdev(shadow_latencies) if len(shadow_latencies) > 1 else 1.0
            primary_std = statistics.stdev(primary_latencies) if len(primary_latencies) > 1 else 1.0

            pooled_std = ((shadow_std**2 + primary_std**2) / 2) ** 0.5
            if pooled_std == 0:
                return 0.0

            z_score = abs(shadow_mean - primary_mean) / pooled_std
            # Approximate p-value from z-score
            if z_score > 2.58:
                return 0.01  # 99% confidence
            elif z_score > 1.96:
                return 0.05  # 95% confidence
            elif z_score > 1.64:
                return 0.10  # 90% confidence
            else:
                return 1.0

    def _determine_recommendation(
        self,
        latency_diff: float,
        disagreement_rate: float,
        statistical_significance: float
    ) -> ShadowDecision:
        """Determine promotion recommendation."""
        # If shadow is significantly slower, reject
        if latency_diff > 50 and statistical_significance < 0.05:
            return ShadowDecision.REJECT

        # If disagreement rate is too high, continue testing
        if disagreement_rate > 0.2:
            return ShadowDecision.CONTINUE

        # If shadow is faster and disagreement is low, promote
        if latency_diff < -10 and disagreement_rate < 0.05:
            return ShadowDecision.PROMOTE

        # Otherwise, continue testing
        return ShadowDecision.CONTINUE

    def reset_results(self) -> None:
        """Reset shadow testing results."""
        self.results = []
        logger.info("Shadow testing results reset")

    def get_statistics(self) -> Dict[str, Any]:
        """Get shadow testing statistics."""
        if not self.results:
            return {
                "enabled": self.enabled,
                "shadow_model_id": self.shadow_model_id,
                "samples": 0,
                "latency_ms": {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0},
                "verdict_distribution": {}
            }

        latencies = [r.latency_ms for r in self.results]
        verdicts = [r.verdict for r in self.results]
        verdict_dist = {v: verdicts.count(v) / len(verdicts) for v in set(verdicts)}

        return {
            "enabled": self.enabled,
            "shadow_model_id": self.shadow_model_id,
            "samples": len(self.results),
            "latency_ms": {
                "mean": statistics.mean(latencies),
                "std": statistics.stdev(latencies) if len(latencies) > 1 else 0.0,
                "min": min(latencies),
                "max": max(latencies)
            },
            "verdict_distribution": verdict_dist
        }
