"""Explainability response schema."""

from pydantic import BaseModel
from typing import Dict, Any, Optional


class ExplainabilityResponse(BaseModel):
    """Response for explainability endpoint."""

    prediction_class: str
    confidence: float
    class_probabilities: Dict[str, float]
    feature_importance: Dict[str, float]
    explanation: str
    error: Optional[str] = None
