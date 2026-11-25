"""Ensemble and Stacking Engine for Model Fusion.

Combines predictions from multiple models for better accuracy.
Supports majority voting, weighted averaging, and stacking with meta-model.
"""

import logging
import statistics
import threading
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import numpy as np

logger = logging.getLogger("nsfw_engine.core.ensemble")


class EnsembleMethod(Enum):
    """Ensemble methods."""
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_AVERAGE = "weighted_average"
    STACKING = "stacking"


@dataclass
class ModelPrediction:
    """Prediction from a single model."""
    model_id: str
    verdict: str
    confidence: float
    risk_score: float


@dataclass
class EnsembleResult:
    """Result from ensemble prediction."""
    verdict: str
    confidence: float
    risk_score: float
    method: EnsembleMethod
    model_predictions: List[ModelPrediction]


class EnsembleEngine:
    """Engine for ensemble and stacking of model predictions."""

    def __init__(self, method: EnsembleMethod = EnsembleMethod.WEIGHTED_AVERAGE):
        self.method = method
        self.model_weights: Dict[str, float] = {}
        self.enabled = True
        self._lock = threading.Lock()

    def set_model_weights(self, weights: Dict[str, float]) -> None:
        """Set weights for weighted averaging."""
        total = sum(weights.values())
        if total == 0:
            raise ValueError("Total weight cannot be zero")
        # Normalize weights
        self.model_weights = {k: v / total for k, v in weights.items()}
        logger.info("Set model weights: %s", self.model_weights)

    def ensemble(self, predictions: List[ModelPrediction]) -> EnsembleResult:
        """Combine predictions from multiple models."""
        if not predictions:
            raise ValueError("No predictions to ensemble")

        if len(predictions) == 1:
            return EnsembleResult(
                verdict=predictions[0].verdict,
                confidence=predictions[0].confidence,
                risk_score=predictions[0].risk_score,
                method=self.method,
                model_predictions=predictions
            )

        if self.method == EnsembleMethod.MAJORITY_VOTE:
            return self._majority_vote(predictions)
        elif self.method == EnsembleMethod.WEIGHTED_AVERAGE:
            return self._weighted_average(predictions)
        elif self.method == EnsembleMethod.STACKING:
            return self._stacking(predictions)
        else:
            raise ValueError(f"Unknown ensemble method: {self.method}")

    def _majority_vote(self, predictions: List[ModelPrediction]) -> EnsembleResult:
        """Majority voting ensemble."""
        verdicts = [p.verdict for p in predictions]
        verdict_counts = {v: verdicts.count(v) for v in set(verdicts)}
        winning_verdict = max(verdict_counts, key=verdict_counts.get)

        # Average confidence and risk score for winning verdict
        winning_preds = [p for p in predictions if p.verdict == winning_verdict]
        avg_confidence = statistics.mean([p.confidence for p in winning_preds])
        avg_risk_score = statistics.mean([p.risk_score for p in winning_preds])

        return EnsembleResult(
            verdict=winning_verdict,
            confidence=avg_confidence,
            risk_score=avg_risk_score,
            method=EnsembleMethod.MAJORITY_VOTE,
            model_predictions=predictions
        )

    def _weighted_average(self, predictions: List[ModelPrediction]) -> EnsembleResult:
        """Weighted averaging ensemble."""
        if not self.model_weights:
            # Equal weights if not set
            weights = {p.model_id: 1.0 for p in predictions}
            total = sum(weights.values())
            self.model_weights = {k: v / total for k, v in weights.items()}

        # Calculate weighted average
        weighted_confidence = 0.0
        weighted_risk_score = 0.0
        verdict_weights = {"SAFE": 0.0, "NSFW": 0.0, "REVIEW": 0.0}

        for pred in predictions:
            weight = self.model_weights.get(pred.model_id, 0.0)
            weighted_confidence += pred.confidence * weight
            weighted_risk_score += pred.risk_score * weight
            verdict_weights[pred.verdict] += weight

        # Determine verdict by highest weight
        winning_verdict = max(verdict_weights, key=verdict_weights.get)

        return EnsembleResult(
            verdict=winning_verdict,
            confidence=weighted_confidence,
            risk_score=weighted_risk_score,
            method=EnsembleMethod.WEIGHTED_AVERAGE,
            model_predictions=predictions
        )

    def _stacking(self, predictions: List[ModelPrediction]) -> EnsembleResult:
        """Stacking ensemble with meta-model (simplified)."""
        # In a real implementation, this would use a trained meta-model
        # For now, use weighted average as a proxy
        logger.warning("Stacking not fully implemented, using weighted average")
        return self._weighted_average(predictions)

    def get_ensemble_statistics(self) -> Dict[str, Any]:
        """Get ensemble engine statistics."""
        return {
            "method": self.method.value,
            "enabled": self.enabled,
            "model_weights": self.model_weights
        }
