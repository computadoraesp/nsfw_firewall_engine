"""Model Versioning API schemas."""

from pydantic import BaseModel
from typing import Optional, List


class ModelVersionRequest(BaseModel):
    """Request to register a model version."""

    version: str
    model_id: str
    status: str = "candidate"
    accuracy: float = 0.0
    fpr: float = 0.0
    fnr: float = 0.0


class ModelVersionResponse(BaseModel):
    """Response with model version information."""

    version: str
    model_id: str
    status: str
    accuracy: float
    fpr: float
    fnr: float
    deployed_at: Optional[str]
    created_at: str
