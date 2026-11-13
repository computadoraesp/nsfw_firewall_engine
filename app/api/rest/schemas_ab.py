"""A/B Testing API schemas."""

from pydantic import BaseModel
from typing import Dict, Any, Optional


class ABTestConfigRequest(BaseModel):
    """Request to configure A/B test."""

    shadow_model_id: str
    traffic_percentage: float = 0.1
    test_duration_hours: int = 24
    min_samples: int = 100


class ABTestStatisticsResponse(BaseModel):
    """Response with A/B test statistics."""

    primary: Dict[str, Any]
    shadow: Dict[str, Any]


class ABTestComparisonResponse(BaseModel):
    """Response with model comparison."""

    primary_accuracy: float
    shadow_accuracy: float
    primary_fpr: float
    shadow_fpr: float
    primary_fnr: float
    shadow_fnr: float
    recommendation: str
