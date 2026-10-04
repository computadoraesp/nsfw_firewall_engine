"""Evaluation harness (§35, §45).

Computes accuracy, precision, recall, F1 and ROC-AUC from a *labelled dataset*
so model-quality claims are measured rather than asserted.

Dataset manifest (JSON), resolved relative to the manifest file::

    {
      "name": "internal-smoke",
      "positive_label": "nsfw",
      "items": [
        {"path": "safe/cat.png", "label": "sfw"},
        {"path": "explicit/sample.png", "label": "nsfw"}
      ]
    }

No dataset ships with this repository (§40 forbids shipping content), so
:func:`evaluate_manifest` reports ``skipped`` rather than fabricating a score.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from app.core.calibration import expected_calibration_error

logger = logging.getLogger("nsfw_engine.benchmarks.evaluate")


@dataclass
class EvaluationReport:
    """Binary-classification metrics plus provenance."""

    dataset: str = ""
    samples: int = 0
    positives: int = 0
    negatives: int = 0
    threshold: float = 0.75
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    roc_auc: Optional[float] = None
    #: Area under the precision-recall curve (§24). Reported next to ROC-AUC
    #: because the two diverge sharply under class imbalance, and NSFW traffic
    #: is almost always heavily imbalanced - ROC-AUC flatters a detector that
    #: simply never fires, while PR-AUC does not.
    pr_auc: Optional[float] = None
    #: Expected Calibration Error (§24/§26). How far a score is from a literal
    #: probability. High ECE means the thresholds are being tuned against
    #: numbers that do not mean what they appear to mean.
    ece: Optional[float] = None
    skipped: bool = False
    reason: str = ""
    models_loaded: bool = False
    errors: List[str] = field(default_factory=list)

    # -- derived metrics -----------------------------------------------------
    @property
    def accuracy(self) -> Optional[float]:
        total = self.samples
        return round((self.true_positives + self.true_negatives) / total, 6) if total else None

    @property
    def precision(self) -> Optional[float]:
        predicted = self.true_positives + self.false_positives
        return round(self.true_positives / predicted, 6) if predicted else None

    @property
    def recall(self) -> Optional[float]:
        actual = self.true_positives + self.false_negatives
        return round(self.true_positives / actual, 6) if actual else None

    @property
    def f1(self) -> Optional[float]:
        precision, recall = self.precision, self.recall
        if precision is None or recall is None or (precision + recall) == 0:
            return None
        return round(2 * precision * recall / (precision + recall), 6)

    def confusion(self) -> Dict[str, int]:
        return {
            "tp": self.true_positives,
            "fp": self.false_positives,
            "tn": self.true_negatives,
            "fn": self.false_negatives,
        }

    # -- error-rate metrics (§24) -------------------------------------------
    # FPR and FNR are the two rates an NSFW deployment is actually judged on, and
    # neither is recoverable from precision/recall alone. A classifier can post a
    # respectable F1 while being useless in both directions: high recall means
    # little if it flags half of all safe traffic (a broken user experience), and
    # high precision means little if it misses most explicit content (a broken
    # product). §24 asks for them explicitly, and they are cheap to report.
    @property
    def false_positive_rate(self) -> Optional[float]:
        """Share of safe content incorrectly flagged. Lower is better."""
        negatives = self.true_negatives + self.false_positives
        return round(self.false_positives / negatives, 6) if negatives else None

    @property
    def false_negative_rate(self) -> Optional[float]:
        """Share of explicit content missed. Lower is better."""
        actual = self.true_positives + self.false_negatives
        return round(self.false_negatives / actual, 6) if actual else None

    @property
    def specificity(self) -> Optional[float]:
        """``1 - FPR``; the share of safe content correctly allowed."""
        rate = self.false_positive_rate
        return None if rate is None else round(1.0 - rate, 6)

    def as_dict(self) -> dict:
        return {
            "dataset": self.dataset,
            "skipped": self.skipped,
            "reason": self.reason,
            "samples": self.samples,
            "positives": self.positives,
            "negatives": self.negatives,
            "threshold": self.threshold,
            "models_loaded": self.models_loaded,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "specificity": self.specificity,
            "roc_auc": self.roc_auc,
            "pr_auc": self.pr_auc,
            "ece": self.ece,
            "confusion": self.confusion(),
            "errors": self.errors[:10],
        }

    def to_markdown(self) -> str:
        if self.skipped:
            return (
                f"## Evaluation (§35)\n\n**Skipped** - {self.reason}\n\n"
                "No quality claim can be made until a labelled dataset is supplied."
            )
        lines = [
            "## Evaluation (§35)",
            "",
            f"Dataset: **{self.dataset}** - {self.samples} samples "
            f"({self.positives} positive / {self.negatives} negative)",
            "",
            f"- Threshold: **{self.threshold}**",
            f"- Accuracy: **{self.accuracy}**",
            f"- Precision: **{self.precision}**",
            f"- Recall: **{self.recall}**",
            f"- F1: **{self.f1}**",
            f"- FPR (false positives): **{self.false_positive_rate}**",
            f"- FNR (false negatives): **{self.false_negative_rate}**",
            f"- Specificity: **{self.specificity}**",
            f"- ROC-AUC: **{self.roc_auc}**",
            f"- PR-AUC: **{self.pr_auc}**",
            f"- Calibration ECE: **{self.ece}**",
            f"- Confusion: {self.confusion()}",
        ]
        if not self.models_loaded:
            lines += [
                "",
                "> ⚠️ Evaluated with the **heuristic fallback** - these are pipeline "
                "numbers, not detector quality (§49).",
            ]
        if self.errors:
            lines += ["", f"> {len(self.errors)} item(s) could not be read and were skipped."]
        return "\n".join(lines)
def roc_auc(scores: Sequence[float], labels: Sequence[bool]) -> Optional[float]:
    """ROC-AUC via the rank-sum (Mann-Whitney U) identity.

    Returns ``None`` when only one class is present, because AUC is undefined
    there - reporting a number would be misleading.
    """
    positives = sum(1 for label in labels if label)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return None
    indexed = sorted(zip(scores, labels))
    rank_sum = 0.0
    index = 0
    while index < len(indexed):
        # Average ranks across ties.
        end = index
        while end + 1 < len(indexed) and indexed[end + 1][0] == indexed[index][0]:
            end += 1
        average_rank = (index + end) / 2.0 + 1.0
        for position in range(index, end + 1):
            if indexed[position][1]:
                rank_sum += average_rank
        index = end + 1
    return round((rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives), 6)


def pr_auc(scores: Sequence[float], labels: Sequence[bool]) -> Optional[float]:
    """Average Precision / PR-AUC by the step-wise interpolation of §24.

    Implemented as average precision rather than trapezoidal integration: AP is
    the metric actually reported under the name "PR-AUC" in the literature, and
    it does not reward the artificially optimistic segments trapezoidal
    interpolation produces between sparse precision points.

    Samples sharing a score are treated as one **group**. This matters more than
    it sounds: if equal scores were ordered by label, a model with no ranking
    ability at all would score 1.0, because every positive would be floated to
    the front of its tie group. Aggregating groups removes that artefact - an
    uninformative model collapses to the base rate, which is the honest answer.

    Returns ``None`` when no positive is present, because precision is undefined
    there - reporting a number would be misleading.
    """
    positives = sum(1 for label in labels if label)
    if positives == 0 or len(labels) != len(scores):
        return None

    ordered = sorted(zip(scores, labels), key=lambda pair: -pair[0])
    average_precision = 0.0
    true_positives = 0
    seen = 0
    previous_recall = 0.0
    index = 0
    while index < len(ordered):
        # Consume the whole group of samples sharing this score.
        score = ordered[index][0]
        end = index
        group_positives = 0
        while end < len(ordered) and ordered[end][0] == score:
            group_positives += 1 if ordered[end][1] else 0
            end += 1
        true_positives += group_positives
        seen += end - index
        recall = true_positives / positives
        precision = true_positives / seen
        average_precision += (recall - previous_recall) * precision
        previous_recall = recall
        index = end
    return round(average_precision, 6)


def load_manifest(path: str | Path) -> dict:
    """Read and validate a dataset manifest, resolving each item's path."""
    manifest_path = Path(path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    items = data.get("items") or []
    if not isinstance(items, list) or not items:
        raise ValueError(f"manifest {manifest_path} contains no items")
    base = manifest_path.parent
    for item in items:
        if "path" not in item or "label" not in item:
            raise ValueError(f"manifest item missing path/label: {item!r}")
        item["_resolved"] = str((base / item["path"]).resolve())
    return data


def evaluate_manifest(
    engine,
    manifest_path: str | Path,
    positive_label: Optional[str] = None,
    threshold: Optional[float] = None,
) -> EvaluationReport:
    """Score a labelled dataset through the full engine cascade."""
    manifest_path = Path(manifest_path)
    report = EvaluationReport(dataset=manifest_path.stem, models_loaded=False)
    try:
        manifest = load_manifest(manifest_path)
    except Exception as exc:  # noqa: BLE001
        report.skipped = True
        report.reason = f"could not load manifest: {exc}"
        return report

    report.models_loaded = bool(engine.health().get("loaded_models_count", 0))
    positive = positive_label or manifest.get("positive_label", "nsfw")
    report.threshold = float(
        threshold if threshold is not None else engine.config.thresholds.fast_path.hard_nsfw
    )

    scores: List[float] = []
    labels: List[bool] = []
    for item in manifest["items"]:
        try:
            payload = Path(item["_resolved"]).read_bytes()
            result = engine.classify(payload)
        except Exception as exc:  # noqa: BLE001 - unreadable items are reported
            report.errors.append(f"{item['path']}: {exc}")
            continue
        is_positive = str(item["label"]).strip().lower() == positive.strip().lower()
        scores.append(float(result.score))
        labels.append(is_positive)
        predicted = result.score >= report.threshold
        report.samples += 1
        report.positives += int(is_positive)
        report.negatives += int(not is_positive)
        if predicted and is_positive:
            report.true_positives += 1
        elif predicted and not is_positive:
            report.false_positives += 1
        elif not predicted and is_positive:
            report.false_negatives += 1
        else:
            report.true_negatives += 1

    if report.samples == 0:
        report.skipped = True
        report.reason = "no readable samples in the dataset"
        return report

    report.roc_auc = roc_auc(scores, labels)
    report.pr_auc = pr_auc(scores, labels)
    # ECE is measured on the scores the policy engine actually thresholds. §26
    # calibration exists precisely to bring this number down; if it is high, the
    # thresholds in config/engine_config.yaml are being read as probabilities
    # when they are not.
    report.ece = expected_calibration_error(scores, labels)
    return report


__all__ = [
    "EvaluationReport",
    "evaluate_manifest",
    "load_manifest",
    "pr_auc",
    "roc_auc",
]