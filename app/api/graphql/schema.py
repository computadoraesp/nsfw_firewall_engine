"""GraphQL API Schema.

Provides GraphQL interface for complex queries and efficient data fetching.
"""

from typing import Optional, List
from dataclasses import dataclass
from enum import Enum


class VerdictEnum(Enum):
    """Verdict enumeration."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class ModelStatusEnum(Enum):
    """Model status enumeration."""
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"
    BLOCKED = "blocked"


@dataclass
class ClassificationResult:
    """Classification result."""
    verdict: str
    confidence: float
    risk_score: float
    model_id: str
    stages: List[dict]


@dataclass
class ModelInfo:
    """Model information."""
    model_id: str
    status: str
    accuracy: Optional[float]
    fpr: Optional[float]
    fnr: Optional[float]


@dataclass
class HealthStatus:
    """Health status."""
    ready: bool
    models_loaded: bool
    cache_healthy: bool
    uptime_seconds: float


# GraphQL Schema Definition (simplified - no external dependencies)
GRAPHQL_SCHEMA = """
type ClassificationResult {
    verdict: String!
    confidence: Float!
    riskScore: Float!
    modelId: String!
    stages: [StageResult!]!
}

type StageResult {
    modelId: String!
    score: Float!
    latencyMs: Float!
}

type ModelInfo {
    modelId: String!
    status: String!
    accuracy: Float
    fpr: Float
    fnr: Float
}

type HealthStatus {
    ready: Boolean!
    modelsLoaded: Boolean!
    cacheHealthy: Boolean!
    uptimeSeconds: Float!
}

type Query {
    health: HealthStatus!
    models: [ModelInfo!]!
    classify(imageBase64: String!, mediaType: String!): ClassificationResult!
}

schema {
    query: Query
}
"""


class GraphQLResolver:
    """GraphQL query resolver."""

    def __init__(self, engine, security):
        self.engine = engine
        self.security = security

    def resolve_health(self) -> dict:
        """Resolve health query."""
        return {
            "ready": self.engine.ready,
            "modelsLoaded": len(self.engine.model_registry.models) > 0,
            "cacheHealthy": True,  # Simplified
            "uptimeSeconds": 0.0  # Would need uptime tracking
        }

    def resolve_models(self) -> List[dict]:
        """Resolve models query."""
        models = []
        for model_id, model in self.engine.model_registry.models.items():
            models.append({
                "modelId": model_id,
                "status": model.lifecycle_status.value,
                "accuracy": model.accuracy,
                "fpr": model.fpr,
                "fnr": model.fnr
            })
        return models

    def resolve_classify(self, image_base64: str, media_type: str) -> dict:
        """Resolve classify query."""
        import base64
        from app.api.grpc.handlers import media_type_from_name

        try:
            raw = base64.b64decode(image_base64)
            result = self.engine.classify(
                raw,
                media_type_from_name(media_type),
                request_id="graphql",
                text=None,
                html_context=None,
                tenant_id="default"
            )

            stages = []
            for stage_id, stage in result.stages.items():
                stages.append({
                    "modelId": stage_id,
                    "score": stage.score,
                    "latencyMs": stage.latency_ms
                })

            return {
                "verdict": result.verdict.value,
                "confidence": result.confidence,
                "riskScore": result.risk_score,
                "modelId": result.model_id,
                "stages": stages
            }
        except Exception as exc:
            raise ValueError(f"Classification failed: {exc}")
