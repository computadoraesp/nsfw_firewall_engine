"""Label sidecar for ONNX classifier artifacts (docs/MODEL_PROVENANCE.md §4).

An ONNX graph does not carry its class names. Two checkpoints can emit the
*identical* tensor while disagreeing about what index 0 means - and for a
2-class NSFW head that is the difference between blocking clean images and
letting explicit ones through, with no error anywhere.

A bare ``.onnx`` therefore cannot be trusted to interpret itself. This module
defines the sidecar that travels with the artifact::

    models_onnx/vit_nsfw.onnx
    models_onnx/vit_nsfw.labels.json   <- written by scripts/fetch_pretrained.py

The sidecar is hashed by ``scripts/verify_models.py`` alongside the graph, so
the class order is covered by the same anti-tampering review as the weights
(§38). Swapping a label file is as detectable as swapping the model.
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("nsfw_engine.adapters.labels")

SIDECAR_SUFFIX = ".labels.json"
SCHEMA_VERSION = 1

# Names that count as "explicit". Compared case-insensitively against the
#: label strings in the sidecar, never against the class *index* - the index
#: is exactly what the sidecar exists to establish.
EXPLICIT_LABEL_TOKENS: Tuple[str, ...] = (
    "nsfw",
    "porn",
    "pornographic",
    "hentai",
    "sexy",
    "explicit",
)

# Names that indicate a safe/neutral class. Present so a sidecar whose only
#: classes are explicit can be rejected: that would flag 100% of traffic.
SAFE_LABEL_TOKENS: Tuple[str, ...] = ("normal", "safe", "sfw", "neutral", "benign")


class LabelSidecarError(ValueError):
    """Raised when a sidecar exists but cannot be trusted."""


@dataclass(frozen=True)
class LabelSidecar:
    """Class metadata for one artifact."""

    #: Label name per class index, in the model's own output order.
    labels: Tuple[str, ...]
    # Input resolution the checkpoint was trained at. Feeding 224px to a 384px
    #: checkpoint degrades it silently, so this is recorded rather than assumed.
    input_size: Tuple[int, int] = (224, 224)
    #: Indices whose label is explicit, derived from *labels*.
    positive_indices: Tuple[int, ...] = ()
    #: Per-channel normalization used by the exported model.
    mean: Tuple[float, float, float] = (0.485, 0.456, 0.406)
    std: Tuple[float, float, float] = (0.229, 0.224, 0.225)

    def __post_init__(self) -> None:
        if len(self.input_size) != 2 or any(size <= 0 for size in self.input_size):
            raise LabelSidecarError("input_size must contain two positive dimensions")
        if len(self.mean) != 3 or len(self.std) != 3:
            raise LabelSidecarError("mean and std must each contain three channels")
        if not all(math.isfinite(value) for value in (*self.mean, *self.std)):
            raise LabelSidecarError("mean and std values must be finite")
        if any(value <= 0 for value in self.std):
            raise LabelSidecarError("std values must be greater than zero")
        if not self.labels:
            raise LabelSidecarError("sidecar declares no labels")
        if not any(
            token in str(label).strip().lower()
            for label in self.labels
            for token in SAFE_LABEL_TOKENS
        ):
            raise LabelSidecarError(
                f"none of {list(self.labels)} identifies a safe class; refusing "
                "to trust an ambiguous classifier"
            )
        if not self.positive_indices:
            raise LabelSidecarError(
                f"none of {list(self.labels)} is an explicit class; a detector "
                "whose every class is explicit would flag all traffic. Refusing "
                "to score rather than guessing (§49)."
            )
        if len(self.positive_indices) == len(self.labels):
            raise LabelSidecarError(
                "every class is explicit; the sidecar is missing its safe class"
            )
        for index in self.positive_indices:
            if not 0 <= index < len(self.labels):
                raise LabelSidecarError(
                    f"positive index {index} is out of range for "
                    f"{len(self.labels)} labels"
                )


def classify_labels(labels) -> Tuple[int, ...]:
    """Return the indices whose label names an explicit class."""
    return tuple(
        index
        for index, label in enumerate(labels)
        if any(
            token in str(label).strip().lower() for token in EXPLICIT_LABEL_TOKENS
        )
    )


def sidecar_path(artifact: str | Path) -> Path:
    """Return the sidecar path for *artifact* (``a.onnx`` -> ``a.labels.json``)."""
    path = Path(artifact)
    return path.with_suffix("").with_name(path.stem + SIDECAR_SUFFIX)


def build(
    labels,
    input_size=(224, 224),
    mean=(0.485, 0.456, 0.406),
    std=(0.229, 0.224, 0.225),
) -> LabelSidecar:
    """Create a validated sidecar from model labels and preprocessing metadata."""
    names = tuple(str(label) for label in labels)
    return LabelSidecar(
        labels=names,
        input_size=tuple(input_size),
        positive_indices=classify_labels(names),
        mean=tuple(float(value) for value in mean),
        std=tuple(float(value) for value in std),
    )


def write(artifact: str | Path, sidecar: LabelSidecar) -> Path:
    """Write the sidecar next to *artifact*; returns the path written."""
    path = sidecar_path(artifact)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "labels": list(sidecar.labels),
        "input_size": list(sidecar.input_size),
        "mean": list(sidecar.mean),
        "std": list(sidecar.std),
        "positive_indices": list(sidecar.positive_indices),
        "_comment": [
            "Class order for this artifact. Hash-checked by "
            "scripts/verify_models.py; editing it by hand fails that gate.",
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    logger.info("wrote label sidecar %s (%s)", path, list(sidecar.labels))
    return path


def read_payload(artifact: str | Path) -> Optional[dict]:
    """Return the raw sidecar payload, or ``None`` when absent."""
    path = sidecar_path(artifact)
    if not path.is_file():
        logger.debug("no label sidecar for %s", artifact)
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LabelSidecarError(f"unreadable sidecar {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise LabelSidecarError(f"sidecar {path} is not a JSON object")
    return payload


def load(artifact: str | Path) -> Optional[LabelSidecar]:
    """Load and validate the sidecar for *artifact*.

    Returns ``None`` when there is no sidecar - an absent sidecar is a normal
    state (the repo ships no weights), not an error. A sidecar that exists but
    is malformed, or whose labels would flag all traffic, *is* an error.

    ``positive_indices`` is always re-derived from the label names rather than
    trusted from the file: a hand-edited sidecar that marks the safe class as
    explicit must fail here, not silently block 100% of traffic.
    """
    payload = read_payload(artifact)
    if payload is None:
        return None
    path = sidecar_path(artifact)
    version = payload.get("schema_version")
    if version != SCHEMA_VERSION:
        raise LabelSidecarError(
            f"sidecar {path} has schema_version {version!r}, expected "
            f"{SCHEMA_VERSION}; regenerate it with scripts/fetch_pretrained.py"
        )
    try:
        size = tuple(int(v) for v in payload.get("input_size", (224, 224)))
        names = tuple(str(v) for v in payload.get("labels", ()))
        mean = tuple(float(v) for v in payload.get("mean", (0.485, 0.456, 0.406)))
        std = tuple(float(v) for v in payload.get("std", (0.229, 0.224, 0.225)))
    except (TypeError, ValueError) as exc:
        raise LabelSidecarError(f"sidecar {path} has a malformed field: {exc}") from exc
    return LabelSidecar(
        labels=names,
        input_size=size,
        positive_indices=classify_labels(names),
        mean=mean,
        std=std,
    )
#: Friendly aliases so callers can ``from adapters import load_labels``.
load_labels = load
write_labels = write

__all__ = [
    "LabelSidecar",
    "LabelSidecarError",
    "build",
    "classify_labels",
    "load",
    "load_labels",
    "read_payload",
    "sidecar_path",
    "write",
    "write_labels",
]