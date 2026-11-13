"""A/B Testing Framework for model evaluation.

Allows canary deployment of new models without production risk.
Routes a percentage of traffic to shadow model and compares results.
"""

import logging
import random
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("nsfw_engine.core.ab_testing")


class ModelVariant(Enum):
    """Model variant identifiers."""
    PRIMARY = "primary"
    SHADOW = "shadow"


@dataclass
class TestConfig:
    """Configuration for A/B test."""
    shadow_model_id: str
    traffic_percentage: float = 0.1  # 10% of traffic to shadow
    test_duration_hours: int = 24
    min_samples: int = 100
    statistical_significance: float = 0.95


@dataclass
class ModelComparison:
    """Comparison result between primary and shadow models."""
    primary_accuracy: float
    shadow_accuracy: float
    primary_fpr: float
    shadow_fpr: float
    primary_fnr: float
    shadow_fnr: float
    recommendation: str  # "promote", "reject", "continue"


class ABTestingEngine:
    """Engine for A/B testing model variants."""

    def __init__(self, config: Optional[TestConfig] = None):
        self.config = config or TestConfig(shadow_model_id="")
        self.enabled = bool(self.config.shadow_model_id)
        self.stats: Dict[str, Dict[str, Any]] = {
            ModelVariant.PRIMARY.value: {"correct": 0, "total": 0, "fp": 0, "fn": 0},
            ModelVariant.SHADOW.value: {"correct": 0, "total": 0, "fp": 0, "fn": 0},
        }

    def should_route_to_shadow(self) -> bool:
        """Determine if request should go to shadow model."""
        if not self.enabled:
            return False
        return random.random() < self.config.traffic_percentage

    def record_result(
        self,
        variant: ModelVariant,
        predicted_class: str,
        ground_truth: Optional[str] = None
    ) -> None:
        """Record classification result for statistics."""
        variant_key = variant.value
        self.stats[variant_key]["total"] += 1

        if ground_truth:
            if predicted_class == ground_truth:
                self.stats[variant_key]["correct"] += 1
            elif predicted_class == "NSFW" and ground_truth == "SAFE":
                self.stats[variant_key]["fp"] += 1
            elif predicted_class == "SAFE" and ground_truth == "NSFW":
                self.stats[variant_key]["fn"] += 1

    def get_statistics(self) -> Dict[str, Any]:
        """Get current test statistics."""
        result = {}
        for variant, stats in self.stats.items():
            total = stats["total"]
            if total == 0:
                result[variant] = {
                    "accuracy": 0.0,
                    "fpr": 0.0,
                    "fnr": 0.0,
                    "samples": 0
                }
                continue

            accuracy = stats["correct"] / total if total > 0 else 0.0
            fpr = stats["fp"] / total if total > 0 else 0.0
            fnr = stats["fn"] / total if total > 0 else 0.0

            result[variant] = {
                "accuracy": accuracy,
                "fpr": fpr,
                "fnr": fnr,
                "samples": total
            }

        return result

    def compare_models(self) -> ModelComparison:
        """Compare primary and shadow model performance."""
        stats = self.get_statistics()
        primary = stats[ModelVariant.PRIMARY.value]
        shadow = stats[ModelVariant.SHADOW.value]

        # Determine recommendation
        if shadow["samples"] < self.config.min_samples:
            recommendation = "continue"
        elif shadow["accuracy"] > primary["accuracy"] and shadow["fpr"] < primary["fpr"]:
            recommendation = "promote"
        elif shadow["accuracy"] < primary["accuracy"] * 0.95:
            recommendation = "reject"
        else:
            recommendation = "continue"

        return ModelComparison(
            primary_accuracy=primary["accuracy"],
            shadow_accuracy=shadow["accuracy"],
            primary_fpr=primary["fpr"],
            shadow_fpr=shadow["fpr"],
            primary_fnr=primary["fnr"],
            shadow_fnr=shadow["fnr"],
            recommendation=recommendation
        )

    def reset_statistics(self) -> None:
        """Reset test statistics."""
        self.stats = {
            ModelVariant.PRIMARY.value: {"correct": 0, "total": 0, "fp": 0, "fn": 0},
            ModelVariant.SHADOW.value: {"correct": 0, "total": 0, "fp": 0, "fn": 0},
        }
        logger.info("A/B testing statistics reset")
