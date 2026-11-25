"""Ensemble API schemas."""

from pydantic import BaseModel
from typing import List, Dict, Optional


class EnsembleConfigRequest(BaseModel):
    """Request to configure ensemble."""

    method: str = "weighted_average"
    model_weights: Dict[str, float] = {}


class EnsembleResultResponse(BaseModel):
    """Response with ensemble result."""

    verdict: str
    confidence: float
    risk_score: float
    method: str
    model_predictions: List[Dict[str, Any]]
