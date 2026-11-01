"""Score calibration (``pront.md`` §26).

Pipeline position::

    RAW OUTPUT -> CALIBRATION -> NORMALIZED SCORE -> FUSION -> POLICY

Every model emits a score on its own scale. NSFWJS is a sigmoid over a
MobileNet head, EfficientNet variants are frequently trained with heavy positive
oversampling, and the deterministic fallback in :mod:`app.models.base` is a pixel
ratio. Those numbers are *not* comparable and *not* probabilities, yet the
cascade compares them against shared thresholds and fuses them together.
Calibration is what makes that comparison mean something.

Three methods are implemented, exactly as §26 requires:

``temperature``
    One parameter. Sharpens or softens the logit while leaving the decision
    *order* untouched. The cheapest option and the safest default.
``platt``
    A logistic regression ``sigmoid(a * score + b)``. Two parameters; handles a
    systematic offset between the training distribution and production traffic.
``isotonic``
    A monotone step function fitted to the empirical reliability curve. The most
    expressive of the three, but it can only ever be fitted with a real labeled
    validation set.

All three are **monotonic**, so calibration can never change which sample ranks
above which. What it changes is *where the threshold sits*, which is precisely
the knob an operator tunes. ROC-AUC is therefore invariant under calibration -
a useful sanity property, asserted in the tests.

Calibration parameters are fitted by ``scripts/calibrate`` from a labeled
dataset and loaded from ``config/calibration.json``. Nothing is fitted at
startup: an unsupervised fit would be meaningless, and fitting on the traffic
being scored is how a model quietly teaches itself to under-report.
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger("nsfw_engine.core.calibration")

#: Guard rails. A degenerate parameter means a broken fit; clamping here keeps a
#: bad calibration file from silently inverting every score.
MIN_TEMPERATURE = 0.01
MAX_TEMPERATURE = 100.0
MIN_SLOPE = 1e-6
MAX_SLOPE = 1e6

#: Methods §26 permits, in increasing order of expressiveness.
METHODS = ("none", "temperature", "platt", "isotonic")

#: Lower bound used when *fitting* a temperature, deliberately above
#: :data:`MIN_TEMPERATURE` (which only guards `from_dict`).
#:
#: On a small or linearly separable validation set the NLL objective keeps
#: improving as T -> 0, because a saturated sigmoid reproduces the labels
#: perfectly. That fit is worthless in practice: every score collapses to 0 or 1,
#: the middle of the range stops carrying information, and the cascade can no
#: longer distinguish "just above" from "far above" the threshold. A floor of
#: 0.25 keeps the output in a usable dynamic range; a deployment that genuinely
#: needs sharper outputs should train the model, not sharpen the calibrator.
MIN_FIT_TEMPERATURE = 0.25


def _clip(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _sigmoid(x: float) -> float:
    """Numerically stable logistic function."""
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    exponent = math.exp(x)
    return exponent / (1.0 + exponent)


def _safe_log(value: float) -> float:
    """``log`` that returns a large negative number instead of raising."""
    if value <= 0.0:
        return -745.0  # ~log(smallest denormal), keeps the fit finite
    return math.log(value)


def _logit(p: float, epsilon: float = 1e-6) -> float:
    """Inverse logistic, clamped so a 0 or 1 label cannot produce infinity."""
    p = _clip(float(p), epsilon, 1.0 - epsilon)
    return _safe_log(p / (1.0 - p))


def expected_calibration_error(
    scores: Sequence[float], labels: Sequence[bool], bins: int = 10
) -> Optional[float]:
    """Expected Calibration Error (§24 ``calibration``).

    The samples are bucketed into *bins* equal-width confidence intervals; within
    each bucket the gap between the mean predicted probability and the observed
    positive rate is weighted by the bucket's population. Lower is better, and
    ``0.0`` means the reported score can be read as a literal probability.

    This is the metric that tells an operator whether a score of ``0.8`` really
    means "80% of the time this is explicit". Without it, thresholds are tuned
    against a number that has no probabilistic meaning.
    """
    if not scores or len(scores) != len(labels) or bins < 1:
        return None
    total = len(scores)
    error = 0.0
    for index in range(bins):
        low = index / bins
        high = (index + 1) / bins
        # The top bucket is closed so a score of exactly 1.0 is still counted.
        members = [
            (s, l)
            for s, l in zip(scores, labels)
            if (low <= s < high) or (index == bins - 1 and s == 1.0)
        ]
        if not members:
            continue
        mean_confidence = sum(s for s, _ in members) / len(members)
        observed_rate = sum(1 for _, label in members if label) / len(members)
        error += (len(members) / total) * abs(mean_confidence - observed_rate)
    return round(error, 6)


def _clean_pairs(
    scores: Sequence[float], labels: Sequence[bool]
) -> List[Tuple[float, bool]]:
    """Drop pairs whose score is not a usable float; keep the rest aligned."""
    pairs: List[Tuple[float, bool]] = []
    for score, label in zip(scores or (), labels or ()):
        try:
            value = float(score)
        except (TypeError, ValueError):
            continue
        if value != value:  # NaN
            continue
        pairs.append((_clip(value, 0.0, 1.0), bool(label)))
    return pairs


def _has_both_classes(pairs: Sequence[Tuple[float, bool]]) -> bool:
    return bool(pairs) and any(label for _, label in pairs) and any(
        not label for _, label in pairs
    )


def _negative_log_likelihood(
    pairs: Sequence[Tuple[float, bool]], transform
) -> float:
    """Mean negative log-likelihood of the labels under *transform*."""
    epsilon = 1e-12
    losses = []
    for score, label in pairs:
        p = _clip(transform(score), epsilon, 1.0 - epsilon)
        losses.append(-math.log(p) if label else -math.log(1.0 - p))
    return sum(losses) / len(losses)


@dataclass
class Calibrator:
    """A fitted calibration function (§26).

    Instances are safe to share across threads: the isotonic knots are a tuple
    and the linear parameters are floats, so :meth:`apply` performs no mutation.
    That matters because the same calibrator is consulted from every worker in
    the cascade.
    """

    method: str = "none"
    #: Temperature for ``method="temperature"``.
    temperature: float = 1.0
    #: Logistic coefficients for ``method="platt"`` (``sigmoid(a*x + b)``).
    slope: float = 1.0
    intercept: float = 0.0
    #: Monotone knots for ``method="isotonic"``: ``(x, calibrated_x)`` pairs.
    knots: Tuple[Tuple[float, float], ...] = ()
    #: Free-form provenance so an operator can see what was fitted on what.
    metadata: Dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        method = (self.method or "none").strip().lower()
        if method not in METHODS:
            raise ValueError(f"unknown calibration method {method!r}; expected one of {METHODS}")
        self.method = method
        self.temperature = _clip(float(self.temperature), MIN_TEMPERATURE, MAX_TEMPERATURE)
        self.slope = _clip(float(self.slope), MIN_SLOPE, MAX_SLOPE)
        self.intercept = float(self.intercept)
        self.knots = tuple((float(x), float(y)) for x, y in self.knots)

    # -- application ---------------------------------------------------------
    def apply(self, score: float) -> float:
        """Map a raw model score onto a calibrated probability in ``[0, 1]``.

        Always returns a float in range whatever the input, so a calibrator can
        never push a score outside the interval the policy thresholds assume.
        """
        try:
            value = float(score)
        except (TypeError, ValueError):
            return 0.0
        if math.isnan(value) or math.isinf(value):
            return 0.0

        if self.method == "none":
            calibrated = value
        elif self.method == "temperature":
            # Work in logit space so the result stays a probability.
            calibrated = _sigmoid(_logit(value) / self.temperature)
        elif self.method == "platt":
            calibrated = _sigmoid(self.slope * value + self.intercept)
        else:  # isotonic
            calibrated = self._isotonic(value)

        return float(_clip(calibrated, 0.0, 1.0))

    def _isotonic(self, value: float) -> float:
        """Piecewise-linear interpolation across the fitted knots."""
        if not self.knots:
            return value
        if value <= self.knots[0][0]:
            return self.knots[0][1]
        if value >= self.knots[-1][0]:
            return self.knots[-1][1]
        for (x0, y0), (x1, y1) in zip(self.knots, self.knots[1:]):
            if x0 <= value <= x1:
                if x1 == x0:
                    return y1
                return y0 + (value - x0) / (x1 - x0) * (y1 - y0)
        return value

    @property
    def is_identity(self) -> bool:
        """True when the calibrator is a no-op (``method="none"``)."""
        return self.method == "none"

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "temperature": round(self.temperature, 6),
            "slope": round(self.slope, 6),
            "intercept": round(self.intercept, 6),
            "knots": [[round(x, 6), round(y, 6)] for x, y in self.knots],
            "metadata": dict(self.metadata),
        }

    # -- persistence ---------------------------------------------------------
    to_dict = as_dict

    @classmethod
    def from_dict(cls, raw: dict) -> "Calibrator":
        """Rebuild a calibrator from its JSON form, tolerating a bad file.

        A corrupt or hand-edited calibration file must degrade to identity rather
        than take the engine down: an uncalibrated score is a quality problem, a
        failed import is an outage.
        """
        try:
            metadata = raw.get("metadata")
            return cls(
                method=str(raw.get("method", "none")),
                temperature=float(raw.get("temperature", 1.0)),
                slope=float(raw.get("slope", 1.0)),
                intercept=float(raw.get("intercept", 0.0)),
                knots=tuple(
                    (float(pair[0]), float(pair[1])) for pair in raw.get("knots") or []
                ),
                metadata=metadata if isinstance(metadata, dict) else {},
            )
        except Exception as exc:  # noqa: BLE001 - never fail startup on this
            logger.error("invalid calibration document, using identity: %s", exc)
            return cls()

    # -- fitting -------------------------------------------------------------
    @classmethod
    def fit_temperature(
        cls,
        scores: Sequence[float],
        labels: Sequence[bool],
        *,
        grid: Optional[Iterable[float]] = None,
        grid_points: int = 60,
    ) -> "Calibrator":
        """Fit the single temperature minimizing negative log-likelihood.

        A grid search is used deliberately. The objective is smooth and
        one-dimensional, but no closed form exists and a gradient step on a
        degenerate validation set (all one class) diverges. A bounded grid cannot
        diverge and is trivially reproducible across runs and platforms.
        """
        pairs = _clean_pairs(scores, labels)
        if not _has_both_classes(pairs):
            logger.warning("temperature fit needs both classes; falling back to identity")
            return cls()

        if grid is not None:
            candidates = list(grid)
        else:
            step = (MAX_TEMPERATURE - MIN_FIT_TEMPERATURE) / max(1, grid_points - 1)
            candidates = [MIN_FIT_TEMPERATURE + step * i for i in range(grid_points)]

        best_temperature, best_loss = 1.0, float("inf")
        for temperature in candidates:
            calibrator = cls(method="temperature", temperature=temperature)
            loss = _negative_log_likelihood(pairs, calibrator.apply)
            if loss < best_loss:
                best_temperature, best_loss = float(temperature), loss
        if best_temperature <= MIN_FIT_TEMPERATURE + 1e-9:
            logger.warning(
                "temperature fit hit the %.2f floor: the validation set is likely too "
                "small or separable, so the calibrator may be over-confident",
                MIN_FIT_TEMPERATURE,
            )
        return cls(
            method="temperature",
            temperature=best_temperature,
            metadata={
                "samples": len(pairs),
                "nll": round(best_loss, 6),
                "fitted_by": "grid_search",
            },
        )

    @classmethod
    def fit_platt(
        cls,
        scores: Sequence[float],
        labels: Sequence[bool],
        *,
        epochs: int = 500,
        learning_rate: float = 0.5,
        l2: float = 1e-4,
    ) -> "Calibrator":
        """Fit ``sigmoid(a * score + b)`` by regularized gradient descent.

        Full-batch gradient descent on two parameters is stable and converges in
        a few hundred steps at this problem size, and it needs no third-party
        solver - important because calibration must not add a heavy dependency to
        the request path.
        """
        pairs = _clean_pairs(scores, labels)
        if not _has_both_classes(pairs):
            logger.warning("platt fit needs both classes; falling back to identity")
            return cls()

        slope, intercept = 1.0, 0.0
        count = float(len(pairs))
        for _ in range(int(epochs)):
            d_slope = d_intercept = 0.0
            for score, label in pairs:
                error = _sigmoid(slope * score + intercept) - (1.0 if label else 0.0)
                d_slope += error * score
                d_intercept += error
            # L2 on the slope only: shrinking the intercept toward zero would
            # bias the prior and drag every score toward 0.5.
            d_slope = d_slope / count + l2 * slope
            d_intercept /= count
            slope -= learning_rate * d_slope
            intercept -= learning_rate * d_intercept
            if abs(d_slope) < 1e-10 and abs(d_intercept) < 1e-10:
                break

        slope = max(slope, MIN_SLOPE)
        return cls(
            method="platt",
            slope=slope,
            intercept=intercept,
            metadata={
                "samples": len(pairs),
                "nll": round(
                    _negative_log_likelihood(
                        pairs, cls(method="platt", slope=slope, intercept=intercept).apply
                    ),
                    6,
                ),
                "fitted_by": "gradient_descent",
            },
        )

    @classmethod
    def fit_isotonic(cls, scores: Sequence[float], labels: Sequence[bool]) -> "Calibrator":
        """Fit a monotone step function with the Pool Adjacent Violators algorithm.

        PAVA yields the isotonic regression of the labels on the scores under the
        squared loss, which is exactly the isotonic fit §26 asks for. It replaces
        scikit-learn's ``IsotonicRegression`` so calibration stays dependency-free
        (§48: reuse what exists, but do not take on a heavy dependency for a
        well-understood 20-line algorithm).
        """
        pairs = _clean_pairs(scores, labels)
        if len(pairs) < 2 or not _has_both_classes(pairs):
            logger.warning("isotonic fit needs both classes; falling back to identity")
            return cls()

        ordered = sorted(pairs)
        # Each block is [weight, sum_of_labels]; PAVA merges blocks that violate
        # monotonicity while keeping the block weight equal to the sample count.
        blocks: List[List[float]] = []
        for _score, label in ordered:
            blocks.append([1.0, 1.0 if label else 0.0])
            while len(blocks) > 1:
                previous, current = blocks[-2], blocks[-1]
                if previous[1] / previous[0] > current[1] / current[0]:
                    blocks[-2] = [previous[0] + current[0], previous[1] + current[1]]
                    blocks.pop()
                else:
                    break

        knots: List[Tuple[float, float]] = []
        cursor = 0
        for weight, positives in blocks:
            start = ordered[cursor][0]
            cursor += int(round(weight))
            end = ordered[max(0, min(cursor, len(ordered)) - 1)][0]
            level = _clip(positives / weight, 0.0, 1.0)
            for x in (start, end):
                if knots and abs(knots[-1][0] - x) < 1e-12:
                    knots[-1] = (x, level)
                else:
                    knots.append((x, level))
        if knots:
            # Anchor the ends so apply() is defined outside the observed range.
            if knots[0][0] > 0.0:
                knots.insert(0, (0.0, knots[0][1]))
            if knots[-1][0] < 1.0:
                knots.append((1.0, knots[-1][1]))
        return cls(
            method="isotonic",
            knots=tuple(knots),
            metadata={"samples": len(pairs), "fitted_by": "pava"},
        )

    @classmethod
    def fit(
        cls, method: str, scores: Sequence[float], labels: Sequence[bool]
    ) -> "Calibrator":
        """Dispatch to the named §26 method."""
        method = (method or "none").strip().lower()
        if method == "temperature":
            return cls.fit_temperature(scores, labels)
        if method == "platt":
            return cls.fit_platt(scores, labels)
        if method == "isotonic":
            return cls.fit_isotonic(scores, labels)
        if method == "none":
            return cls()
        raise ValueError(
            f"unknown calibration method {method!r}; expected one of {METHODS}"
        )


class CalibrationRegistry:
    """Per-model calibrators loaded from a JSON document (§26).

    Keyed by ``model_id`` so one model can be recalibrated without touching the
    others - which is the whole point of §50: models must be able to evolve
    without changing the firewall, the API or the policy.
    """

    def __init__(self, calibrators: Optional[Dict[str, Calibrator]] = None) -> None:
        self._calibrators: Dict[str, Calibrator] = dict(calibrators or {})

    def get(self, model_id: str) -> Calibrator:
        """Return the calibrator for *model_id*, or identity when unknown."""
        return self._calibrators.get(model_id or "", Calibrator())

    def set(self, model_id: str, calibrator: Calibrator) -> None:
        self._calibrators[model_id] = calibrator

    def apply(self, model_id: str, score: float) -> float:
        """Calibrate *score* for *model_id*; identity when none is registered."""
        return self.get(model_id).apply(score)

    @property
    def calibrated_models(self) -> List[str]:
        """Model ids that actually have a non-identity calibrator."""
        return sorted(
            model_id
            for model_id, calibrator in self._calibrators.items()
            if not calibrator.is_identity
        )

    def is_calibrated(self, model_id: str) -> bool:
        """True when *model_id* has a calibrator that would change its score."""
        calibrator = self._calibrators.get(model_id or "")
        return calibrator is not None and not calibrator.is_identity

    def as_dict(self) -> dict:
        return {
            model_id: calibrator.as_dict()
            for model_id, calibrator in sorted(self._calibrators.items())
        }

    def ece(
        self, model_id: str, scores: Sequence[float], labels: Sequence[bool]
    ) -> Optional[float]:
        """Expected Calibration Error of *model_id* over a labeled sample."""
        return expected_calibration_error(
            [self.apply(model_id, score) for score in scores], labels
        )

    @classmethod
    def load(cls, path: str | Path) -> "CalibrationRegistry":
        """Load a registry from JSON, returning an empty one when absent.

        An absent file is the normal state for a source checkout: nothing is
        calibrated until an operator runs ``scripts/calibrate`` against a
        labeled validation set.
        """
        target = Path(path)
        if not target.is_file():
            logger.info("no calibration file at %s; scores will be uncalibrated", target)
            return cls()
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.error("could not parse calibration file %s: %s", target, exc)
            return cls()
        entries = raw.get("calibrators") if isinstance(raw, dict) else raw
        if not isinstance(entries, dict):
            logger.error("calibration file %s has no 'calibrators' mapping", target)
            return cls()
        return cls(
            {
                str(model_id): Calibrator.from_dict(document)
                for model_id, document in entries.items()
                if isinstance(document, dict)
            }
        )

    def save(self, path: str | Path) -> Path:
        """Persist the registry as JSON."""
        target = Path(path)
        if target.parent != Path(""):
            target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps({"calibrators": self.as_dict()}, indent=2) + "\n",
            encoding="utf-8",
        )
        return target


__all__ = [
    "CalibrationRegistry",
    "Calibrator",
    "METHODS",
    "expected_calibration_error",
]