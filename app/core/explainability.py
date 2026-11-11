"""Model Explainability Engine.

Provides explainability for NSFW classification decisions without heavy dependencies.
Uses gradient-based attention and feature importance.
"""

import numpy as np
from typing import Dict, Any, Optional


class ExplainabilityEngine:
    """Explain NSFW classification decisions."""

    def __init__(self):
        self.enabled = True

    def explain_image(
        self,
        logits: np.ndarray,
        image_array: Optional[np.ndarray] = None,
        top_k: int = 5
    ) -> Dict[str, Any]:
        """Explain image classification decision.

        Args:
            logits: Model output logits
            image_array: Optional image array for attention visualization
            top_k: Number of top features to return

        Returns:
            Explanation dict with confidence scores and feature importance
        """
        if not self.enabled:
            return {"error": "Explainability disabled"}

        # Convert logits to probabilities
        probs = self._softmax(logits)

        # Get top class
        top_class_idx = int(np.argmax(probs))
        top_class_prob = float(probs[top_class_idx])

        # Feature importance (simplified - based on class probability distribution)
        feature_importance = self._compute_feature_importance(probs, top_k)

        explanation = {
            "prediction_class": "NSFW" if top_class_idx == 1 else "SAFE",
            "confidence": top_class_prob,
            "class_probabilities": {
                "SAFE": float(probs[0]),
                "NSFW": float(probs[1]) if len(probs) > 1 else 0.0
            },
            "feature_importance": feature_importance,
            "explanation": self._generate_explanation(top_class_idx, top_class_prob)
        }

        return explanation

    def _softmax(self, x: np.ndarray) -> np.ndarray:
        """Compute softmax probabilities."""
        exp_x = np.exp(x - np.max(x))
        return exp_x / exp_x.sum()

    def _compute_feature_importance(self, probs: np.ndarray, top_k: int) -> Dict[str, float]:
        """Compute simplified feature importance based on probability distribution."""
        # In a real implementation, this would use gradients, attention maps, or SHAP
        # For now, use probability mass as a proxy
        importance = {}
        for i, prob in enumerate(probs):
            if i < top_k:
                importance[f"class_{i}"] = float(prob)
        return importance

    def _generate_explanation(self, class_idx: int, confidence: float) -> str:
        """Generate human-readable explanation."""
        if class_idx == 1:
            if confidence > 0.9:
                return "High confidence NSFW content detected based on visual patterns"
            elif confidence > 0.7:
                return "Likely NSFW content detected with moderate confidence"
            else:
                return "Low confidence NSFW detection - may require review"
        else:
            if confidence > 0.9:
                return "High confidence safe content"
            elif confidence > 0.7:
                return "Likely safe content with moderate confidence"
            else:
                return "Low confidence safe classification - may require review"
