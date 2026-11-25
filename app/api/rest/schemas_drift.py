"""Model Drift Detection API schemas."""

from pydantic import BaseModel
from typing import Dict, Any, Optional, List


class DriftMetricsRequest(BaseModel):
    """Request to record drift metrics."""

    accuracy: float
    fpr: float
    fnr: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float


class DriftStatusResponse(BaseModel):
    """Response with drift detection status."""

    status: str
    baseline: Optional[Dict[str, float]]
    current: Optional[Dict[str, float]]
    alerts: List[Dict[str, Any]]
    recent_samples: int
