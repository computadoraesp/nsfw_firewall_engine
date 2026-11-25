"""Model Versioning and Rollback System.

Semantic versioning for models (v1.0.0, v1.1.0).
Automatic rollback if metrics degrade.
Model lifecycle management.
"""

import logging
import re
import threading
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

logger = logging.getLogger("nsfw_engine.core.model_versioning")


class ModelLifecycleStatus(Enum):
    """Model lifecycle status."""
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"
    BLOCKED = "blocked"


@dataclass
class ModelVersion:
    """Model version information."""
    version: str
    model_id: str
    status: ModelLifecycleStatus
    accuracy: float
    fpr: float
    fnr: float
    deployed_at: datetime
    created_at: datetime


class ModelVersioningEngine:
    """Engine for model versioning and rollback."""

    def __init__(self):
        self.versions: Dict[str, ModelVersion] = {}
        self.current_version: Optional[str] = None
        self.rollback_threshold = 0.05  # 5% accuracy degradation triggers rollback
        self._lock = threading.Lock()

    def register_model(
        self,
        version: str,
        model_id: str,
        status: ModelLifecycleStatus = ModelLifecycleStatus.CANDIDATE,
        accuracy: float = 0.0,
        fpr: float = 0.0,
        fnr: float = 0.0
    ) -> None:
        """Register a new model version."""
        if not self._is_valid_version(version):
            raise ValueError(f"Invalid version format: {version}")

        model_version = ModelVersion(
            version=version,
            model_id=model_id,
            status=status,
            accuracy=accuracy,
            fpr=fpr,
            fnr=fnr,
            deployed_at=datetime.now() if status == ModelLifecycleStatus.PRODUCTION else datetime.min,
            created_at=datetime.now()
        )

        with self._lock:
            self.versions[version] = model_version
            # Limit versions to prevent memory DoS
            if len(self.versions) > 100:
                oldest = min(self.versions.keys())
                del self.versions[oldest]
        logger.info("Registered model version %s with status %s", version, status.value)

    def promote_to_production(self, version: str) -> bool:
        """Promote a model version to production."""
        with self._lock:
            if version not in self.versions:
                logger.error("Version %s not found", version)
                return False

            # Check if metrics are acceptable
            model = self.versions[version]
            if model.accuracy < 0.9:
                logger.warning("Cannot promote version %s: accuracy too low (%.4f)", version, model.accuracy)
                return False

            # Demote current production version
            if self.current_version and self.current_version in self.versions:
                self.versions[self.current_version].status = ModelLifecycleStatus.DEPRECATED

            # Promote new version
            model.status = ModelLifecycleStatus.PRODUCTION
            model.deployed_at = datetime.now()
            self.current_version = version

        logger.info("Promoted version %s to production", version)
        return True

    def rollback(self, target_version: Optional[str] = None) -> bool:
        """Rollback to a previous version."""
        with self._lock:
            if not self.current_version:
                logger.error("No current production version to rollback from")
                return False

            # Find best rollback candidate
            if target_version:
                if target_version not in self.versions:
                    logger.error("Target version %s not found", target_version)
                    return False
                rollback_version = target_version
            else:
                # Find most recent validated version
                rollback_version = self._find_best_rollback_candidate()
                if not rollback_version:
                    logger.error("No valid rollback candidate found")
                    return False

            # Perform rollback
            self.versions[self.current_version].status = ModelLifecycleStatus.BLOCKED
            self.versions[rollback_version].status = ModelLifecycleStatus.PRODUCTION
            self.versions[rollback_version].deployed_at = datetime.now()
            self.current_version = rollback_version

        logger.info("Rolled back from %s to %s", self.current_version, rollback_version)
        return True

    def check_rollback_needed(self, current_accuracy: float) -> bool:
        """Check if rollback is needed based on current metrics."""
        if not self.current_version:
            return False

        baseline = self.versions[self.current_version].accuracy
        degradation = (baseline - current_accuracy) / baseline if baseline > 0 else 0

        if degradation > self.rollback_threshold:
            logger.warning("Accuracy degraded by %.2f%%, rollback needed", degradation * 100)
            return True

        return False

    def get_version_info(self, version: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific version."""
        if version not in self.versions:
            return None

        model = self.versions[version]
        return {
            "version": model.version,
            "model_id": model.model_id,
            "status": model.status.value,
            "accuracy": model.accuracy,
            "fpr": model.fpr,
            "fnr": model.fnr,
            "deployed_at": model.deployed_at.isoformat() if model.deployed_at != datetime.min else None,
            "created_at": model.created_at.isoformat()
        }

    def list_versions(self, status: Optional[ModelLifecycleStatus] = None) -> List[Dict[str, Any]]:
        """List all versions, optionally filtered by status."""
        versions = []
        for version, model in self.versions.items():
            if status is None or model.status == status:
                versions.append(self.get_version_info(version))
        return sorted(versions, key=lambda x: x["version"], reverse=True)

    def get_current_version(self) -> Optional[str]:
        """Get current production version."""
        return self.current_version

    def _is_valid_version(self, version: str) -> bool:
        """Validate semantic version format (v1.0.0)."""
        pattern = r"^v\d+\.\d+\.\d+$"
        return bool(re.match(pattern, version))

    def _find_best_rollback_candidate(self) -> Optional[str]:
        """Find the best version to rollback to."""
        candidates = [
            v for v, m in self.versions.items()
            if m.status in [ModelLifecycleStatus.VALIDATED, ModelLifecycleStatus.PRODUCTION]
        ]

        if not candidates:
            return None

        # Sort by accuracy descending
        candidates.sort(key=lambda v: self.versions[v].accuracy, reverse=True)
        return candidates[0]
