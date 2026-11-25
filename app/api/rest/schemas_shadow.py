"""Shadow Testing API schemas."""

from pydantic import BaseModel
from typing import Dict, Any, Optional


class ShadowTestConfigRequest(BaseModel):
    """Request to configure shadow test."""

    shadow_model_id: str
    primary_model_id: str = "fast_path"
    max_samples: int = 10000


class ShadowTestStatisticsResponse(BaseModel):
    """Response with shadow test statistics."""

    enabled: bool
    shadow_model_id: str
    samples: int
    latency_ms: Dict[str, float]
    verdict_distribution: Dict[str, float]


class ShadowTestComparisonResponse(BaseModel):
    """Response with shadow model comparison."""

    latency_diff_ms: float
    accuracy_diff: float
    fpr_diff: float
    fnr_diff: float
    disagreement_rate: float
    recommendation: str
    statistical_significance: float
