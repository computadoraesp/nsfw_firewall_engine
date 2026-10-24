"""Fit an operating threshold from shadow-traffic samples (§45).

Usage
-----
    # 1. See how much evidence has been collected
    python scripts/fit_threshold.py --shadow logs/shadow_samples.jsonl

    # 2. Describe the score distribution, without fitting
    python scripts/fit_threshold.py --shadow logs/shadow_samples.jsonl --report

    # 3. Fit once both classes are labelled
    python scripts/fit_threshold.py --shadow logs/shadow_samples.jsonl \
        --max-fpr 0.01 --out config/thresholds.json

This is the path to a defensible threshold when no labelled corpus exists: run
the engine in ``audit`` mode for a while, have a human label the samples, then
let the measured distribution - not a guess - decide where the line goes.

What it does NOT do is invent labels. ``--report`` is always safe; the fit
refuses to run until both classes are present, because a threshold fitted from
one class has an undefined precision or recall and would look confident while
being meaningless (§49).
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from pathlib import Path
from typing import List, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from benchmarks.evaluate import ShadowSampleStore  # noqa: E402

logger = logging.getLogger("nsfw_engine.scripts.fit_threshold")

DEFAULT_SHADOW = PROJECT_ROOT / "logs" / "shadow_samples.jsonl"
DEFAULT_OUTPUT = PROJECT_ROOT / "config" / "thresholds.json"


def _percentile(values: Sequence[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(round(q * (len(ordered) - 1)))))
    return ordered[index]
def report(store: ShadowSampleStore) -> dict:
    """Describe the labelled score distribution without fitting anything."""
    scores, labels = store.labelled()
    payload = dict(store.stats())
    payload["threshold_fit"] = False

    if not scores:
        payload["reason"] = (
            "no labelled samples yet - run in audit mode, then label them"
        )
        return payload

    positives = [s for s, l in zip(scores, labels) if l]
    negatives = [s for s, l in zip(scores, labels) if not l]
    payload["score"] = {
        "positive": _describe(positives),
        "negative": _describe(negatives),
    }
    # The single most useful diagnostic: if these overlap, no threshold on this
    # model separates the classes for this traffic, and the answer is a better
    # model rather than a better threshold.
    payload["separable"] = bool(
        positives and negatives and min(positives) > max(negatives)
    )
    if not payload["separable"]:
        payload["reason"] = (
            "the two classes overlap on this traffic: no threshold separates "
            "them. Tune the model, not the threshold (§49)."
        )
    return payload


def _describe(values: Sequence[float]) -> dict:
    if not values:
        return {"n": 0, "min": None, "p50": None, "max": None}
    return {
        "n": len(values),
        "min": round(min(values), 6),
        "p50": round(_percentile(values, 0.5), 6),
        "max": round(max(values), 6),
    }


def fit_threshold(
    scores: Sequence[float],
    labels: Sequence[bool],
    max_fpr: float = 0.01,
) -> dict:
    """Return the lowest threshold whose FPR stays at or below *max_fpr*.

    The rule is deliberately conservative: the line sits at the quantile of the
    *negative* scores, so at most ``max_fpr`` of known-safe traffic is admitted.
    Capping false positives is worth some recall, because a firewall that blocks
    ordinary images gets switched off.
    """
    positives = [s for s, l in zip(scores, labels) if l]
    negatives = [s for s, l in zip(scores, labels) if not l]
    if not positives or not negatives:
        raise ValueError(
            "a threshold cannot be fitted from one class: need at least one "
            "labelled positive and one labelled negative"
        )

    negatives = sorted(negatives, reverse=True)
    # How many negatives may sit at or above the line.
    allowed = min(max(int(len(negatives) * max_fpr), 0), len(negatives) - 1)
    # The comparison is ``score >= threshold``, so a threshold equal to the
    # boundary sample would admit it *plus* any ties with it - which silently
    # doubles the false-positive rate. Stepping one ULP above keeps the count
    # exact.
    threshold = math.nextafter(negatives[allowed], math.inf)

    predicted = [s >= threshold for s in scores]
    tp = sum(1 for p, l in zip(predicted, labels) if p and l)
    fp = sum(1 for p, l in zip(predicted, labels) if p and not l)
    fn = sum(1 for p, l in zip(predicted, labels) if not p and l)
    tn = sum(1 for p, l in zip(predicted, labels) if not p and not l)
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    return {
        "threshold": round(float(threshold), 6),
        "max_fpr_target": max_fpr,
        "samples": len(scores),
        "positives": len(positives),
        "negatives": len(negatives),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 6) if precision is not None else None,
        "recall": round(recall, 6) if recall is not None else None,
        "false_positive_rate": round(fp / len(negatives), 6),
        "false_negative_rate": round(fn / len(positives), 6),
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fit an NSFW threshold from shadow-traffic samples (§45)."
    )
    parser.add_argument("--shadow", default=str(DEFAULT_SHADOW))
    parser.add_argument("--report", action="store_true",
                        help="describe the distribution; do not fit")
    parser.add_argument("--max-fpr", type=float, default=0.01,
                        help="highest tolerated FPR on safe content (default 0.01)")
    parser.add_argument("--out", default=None, help="write the fitted threshold here")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args(argv)
    store = ShadowSampleStore(Path(args.shadow))

    if args.report or not store.stats()["fit_ready"]:
        payload = report(store)
        if not args.report and not payload.get("fit_ready", False):
            payload["reason"] = (
                "not enough labelled evidence yet: need at least one positive "
                "and one negative label"
            )
        print(json.dumps(payload, indent=2))
        return 0

    scores, labels = store.labelled()
    try:
        fitted = fit_threshold(scores, labels, max_fpr=args.max_fpr)
    except ValueError as exc:
        print(json.dumps({"error": str(exc), **store.stats()}, indent=2))
        return 1

    fitted["source"] = str(Path(args.shadow))
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(fitted, indent=2) + "\n", encoding="utf-8")
        fitted["written_to"] = str(out)
    print(json.dumps(fitted, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())