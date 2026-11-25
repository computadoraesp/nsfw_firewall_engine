"""Model Drift Detection Engine.

Detects model degradation in production automatically.
Monitors FPR, FNR, accuracy, response time percentiles.
Alerts when metrics degrade beyond thresholds.
"""

import logging
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import statistics

logger = logging.getLogger("nsfw_engine.core.drift_detection")


class DriftStatus(Enum):
    """Drift detection status."""
    STABLE = "stable"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class DriftMetrics:
    """Current model performance metrics."""
    accuracy: float
    fpr: float
    fnr: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    timestamp: float


@dataclass
class DriftAlert:
    """Alert when drift is detected."""
    status: DriftStatus
    metric_name: str
    current_value: float
    baseline_value: float
    drift_percentage: float
    message: str


class DriftDetectionEngine:
    """Engine for detecting model drift in production."""

    def __init__(
        self,
        accuracy_threshold: float = 0.05,
        fpr_threshold: float = 0.1,
        fnr_threshold: float = 0.1,
        latency_threshold: float = 0.2
    ):
        self.accuracy_threshold = accuracy_threshold
        self.fpr_threshold = fpr_threshold
        self.fnr_threshold = fnr_threshold
        self.latency_threshold = latency_threshold

        self.baseline: Optional[DriftMetrics] = None
        self.current_metrics: List[DriftMetrics] = []
        self.max_history = 1000
        self.alerts: List[DriftAlert] = []

    def set_baseline(self, metrics: DriftMetrics) -> None:
        """Set baseline metrics for drift detection."""
        self.baseline = metrics
        logger.info("Drift detection baseline set: accuracy=%.4f, fpr=%.4f, fnr=%.4f",
                   metrics.accuracy, metrics.fpr, metrics.fnr)

    def record_metrics(self, metrics: DriftMetrics) -> None:
        """Record current model metrics."""
        self.current_metrics.append(metrics)

        # Limit history
        if len(self.current_metrics) > self.max_history:
            self.current_metrics = self.current_metrics[-self.max_history:]

        # Check for drift
        if self.baseline:
            alerts = self._check_drift(metrics)
            self.alerts.extend(alerts)

    def _check_drift(self, current: DriftMetrics) -> List[DriftAlert]:
        """Check if current metrics indicate drift."""
        if not self.baseline:
            return []

        alerts = []

        # Check accuracy drift
        acc_drift = (self.baseline.accuracy - current.accuracy) / self.baseline.accuracy
        if acc_drift > self.accuracy_threshold:
            status = DriftStatus.CRITICAL if acc_drift > self.accuracy_threshold * 2 else DriftStatus.WARNING
            alerts.append(DriftAlert(
                status=status,
                metric_name="accuracy",
                current_value=current.accuracy,
                baseline_value=self.baseline.accuracy,
                drift_percentage=acc_drift * 100,
                message=f"Accuracy degraded by {acc_drift * 100:.2f}%"
            ))

        # Check FPR drift
        fpr_drift = (current.fpr - self.baseline.fpr) / self.baseline.fpr if self.baseline.fpr > 0 else 0
        if fpr_drift > self.fpr_threshold:
            status = DriftStatus.CRITICAL if fpr_drift > self.fpr_threshold * 2 else DriftStatus.WARNING
            alerts.append(DriftAlert(
                status=status,
                metric_name="fpr",
                current_value=current.fpr,
                baseline_value=self.baseline.fpr,
                drift_percentage=fpr_drift * 100,
                message=f"FPR increased by {fpr_drift * 100:.2f}%"
            ))

        # Check FNR drift
        fnr_drift = (current.fnr - self.baseline.fnr) / self.baseline.fnr if self.baseline.fnr > 0 else 0
        if fnr_drift > self.fnr_threshold:
            status = DriftStatus.CRITICAL if fnr_drift > self.fnr_threshold * 2 else DriftStatus.WARNING
            alerts.append(DriftAlert(
                status=status,
                metric_name="fnr",
                current_value=current.fnr,
                baseline_value=self.baseline.fnr,
                drift_percentage=fnr_drift * 100,
                message=f"FNR increased by {fnr_drift * 100:.2f}%"
            ))

        # Check latency drift
        latency_drift = (current.latency_p95_ms - self.baseline.latency_p95_ms) / self.baseline.latency_p95_ms
        if latency_drift > self.latency_threshold:
            status = DriftStatus.CRITICAL if latency_drift > self.latency_threshold * 2 else DriftStatus.WARNING
            alerts.append(DriftAlert(
                status=status,
                metric_name="latency_p95",
                current_value=current.latency_p95_ms,
                baseline_value=self.baseline.latency_p95_ms,
                drift_percentage=latency_drift * 100,
                message=f"P95 latency increased by {latency_drift * 100:.2f}%"
            ))

        return alerts

    def get_drift_status(self) -> Dict[str, Any]:
        """Get current drift detection status."""
        if not self.current_metrics:
            return {
                "status": "no_data",
                "baseline": None,
                "current": None,
                "alerts": []
            }

        latest = self.current_metrics[-1]
        recent_alerts = [a for a in self.alerts if time.time() - a.timestamp < 3600] if self.alerts else []

        # Determine overall status
        critical_alerts = [a for a in recent_alerts if a.status == DriftStatus.CRITICAL]
        warning_alerts = [a for a in recent_alerts if a.status == DriftStatus.WARNING]

        if critical_alerts:
            overall_status = "critical"
        elif warning_alerts:
            overall_status = "warning"
        else:
            overall_status = "stable"

        return {
            "status": overall_status,
            "baseline": {
                "accuracy": self.baseline.accuracy if self.baseline else 0.0,
                "fpr": self.baseline.fpr if self.baseline else 0.0,
                "fnr": self.baseline.fnr if self.baseline else 0.0,
                "latency_p95_ms": self.baseline.latency_p95_ms if self.baseline else 0.0
            } if self.baseline else None,
            "current": {
                "accuracy": latest.accuracy,
                "fpr": latest.fpr,
                "fnr": latest.fnr,
                "latency_p50_ms": latest.latency_p50_ms,
                "latency_p95_ms": latest.latency_p95_ms,
                "latency_p99_ms": latest.latency_p99_ms
            },
            "alerts": [
                {
                    "status": a.status.value,
                    "metric": a.metric_name,
                    "current": a.current_value,
                    "baseline": a.baseline_value,
                    "drift_pct": a.drift_percentage,
                    "message": a.message
                }
                for a in recent_alerts
            ],
            "recent_samples": len(self.current_metrics)
        }

    def reset_alerts(self) -> None:
        """Reset drift alerts."""
        self.alerts = []
        logger.info("Drift detection alerts reset")

    def reset_baseline(self) -> None:
        """Reset baseline metrics."""
        self.baseline = None
        logger.info("Drift detection baseline reset")
