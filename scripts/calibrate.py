"""Fit score-calibration parameters from a labeled dataset (§26).

Usage::

    # Fit the cascade temperature and write config/calibration.json
    Python scripts/calibrate.py --dataset datasets/my-eval.json --method temperature

    # Compare every §26 method and pick the best by ECE
    Python scripts/calibrate.py --dataset datasets/my-eval.json --method all

    # Report only, writing nothing
    Python scripts/calibrate.py --dataset datasets/my-eval.json --method platt --dry-run

Why this is a separate script and not part of the engine:

* Calibration needs a **labeled** set. This repository ships no dataset (§40
  forbids shipping explicit content, and third-party corpora are
  LEGAL_REVIEW_REQUIRED per §4), so the fit cannot happen at build time.
* Fitting on the *live* traffic being scored is the classic way a detector
  quietly teaches itself to under-report. The fit is deliberately an explicit,
  operator-run, reproducible step.

The manifest format is the one ``benchmarks/evaluate.py`` consumes (see
``datasets/eval.example.json``), so one corpus can serve both evaluation and
calibration::

    {"name": "...", "positive_label": "nsfw",
     "items": [{"path": "images/safe/x.jpg", "label": "sfw"}, ...]}

The reported ``ECE before`` / ``ECE after`` pair is the evidence that a
calibrator is doing something: §49 forbids quality claims without measurement.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.core.calibration import (  # noqa: E402
    METHODS,
    CalibrationRegistry,
    Calibrator,
    expected_calibration_error,
)
from benchmarks.evaluate import load_manifest  # noqa: E402

logger = logging.getLogger("nsfw_engine.scripts.calibrate")

DEFAULT_OUTPUT = PROJECT_ROOT / "config" / "calibration.json"


def collect_scores(
    engine, manifest_path: Path, positive_label: Optional[str] = None
) -> Tuple[List[float], List[bool], List[str]]:
    """Score every manifest item, returning ``(scores, labels, errors)``.

    The score used is the **final** one the engine produced - the value the
    policy engine actually thresholds. Calibrating the cascade output is what
    changes enforcement behavior; calibrating an intermediate stage only matters
    once that stage's score is the one a threshold is compared against.
    """
    manifest = load_manifest(manifest_path)
    positive = (positive_label or manifest.get("positive_label", "nsfw")).strip().lower()

    scores: List[float] = []
    labels: List[bool] = []
    errors: List[str] = []
    for item in manifest["items"]:
        try:
            payload = Path(item["_resolved"]).read_bytes()
            result = engine.classify(payload)
        except Exception as exc:  # noqa: BLE001 - reported, never fatal
            errors.append(f"{item['path']}: {type(exc).__name__}: {exc}")
            continue
        scores.append(float(result.score))
        labels.append(str(item["label"]).strip().lower() == positive)
    return scores, labels, errors


def _Markdown_table(rows: Sequence[Sequence[str]], headers: Sequence[str]) -> str:
    """Render a GitHub-flavored Markdown table for the comparison report."""
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def _fit_all(
    engine,
    args,
    scores: Sequence[float],
    labels: Sequence[bool],
    ece_before: Optional[float],
) -> List[Tuple[str, Calibrator, Optional[float]]]:
    """Fit every requested method, annotating each with its metadata (§22)."""
    health = engine.health()
    dataset_name = Path(args.dataset).stem
    positives = sum(1 for label in labels if label)
    fit_methods = [m for m in METHODS if m != "none"] if args.method == "all" else [args.method]

    comparisons: List[Tuple[str, Calibrator, Optional[float]]] = []
    for method in fit_methods:
        calibrator = Calibrator.fit(method, list(scores), list(labels))
        calibrated = [calibrator.apply(score) for score in scores]
        ece_after = expected_calibration_error(calibrated, list(labels), bins=args.bins)
        # Metadata records what the fit actually saw, so a stale calibration
        # document is detectable from the file alone (§22 provenance discipline).
        calibrator.metadata.update(
            {
                "dataset": dataset_name,
                "samples": len(scores),
                "positives": positives,
                "ece_before": ece_before,
                "ece_after": ece_after,
                # A fit taken while running on the heuristic fallback is a
                # demonstration, not a production calibration. Recording this
                # keeps the distinction visible to whoever inherits the file.
                "models_loaded": bool(health.get("loaded_models_count", 0)),
            }
        )
        comparisons.append((method, calibrator, ece_after))
    return comparisons


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fit score-calibration parameters from a labeled dataset (§26)."
    )
    parser.add_argument(
        "--dataset", required=True, type=Path, help="labeled dataset manifest (JSON)"
    )
    parser.add_argument(
        "--method",
        default="temperature",
        choices=(*METHODS, "all"),
        help="calibration method to fit (default: temperature)",
    )
    parser.add_argument(
        "--positive-label",
        default=None,
        help="label treated as positive; defaults to the manifest's positive_label",
    )
    parser.add_argument(
        "--output", type=Path, default=DEFAULT_OUTPUT, help="where to write the document"
    )
    parser.add_argument(
        "--model-id",
        default="cascade",
        help="key the fitted calibrator is stored under (matches stage model ids)",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="fit every method and report them side by side",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="report the fit without writing anything"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    parser.add_argument("--bins", type=int, default=10, help="reliability bins for ECE")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from app.core.engine import NsfwEngine

    engine = NsfwEngine()
    try:
        scores, labels, errors = collect_scores(engine, args.dataset, args.positive_label)
    except Exception as exc:  # noqa: BLE001
        print(f"could not read dataset {args.dataset}: {exc}", file=sys.stderr)
        return 2

    if errors:
        print(f"[!] {len(errors)} item(s) could not be scored and were skipped:")
        for message in errors[:5]:
            print(f"    {message}")
    if len(scores) < 4:
        print(
            f"need at least 4 readable samples to fit a calibrator, got {len(scores)}",
            file=sys.stderr,
        )
        return 2

    positives = sum(1 for label in labels if label)
    if positives == 0 or positives == len(labels):
        print(
            "the dataset has only one class; a calibrator cannot be fitted "
            "(both positives and negatives are required)",
            file=sys.stderr,
        )
        return 2

    ece_before = expected_calibration_error(scores, labels, bins=args.bins)
    health = engine.health()
    comparisons = _fit_all(engine, args, scores, labels, ece_before)
    # Rank by ECE so the winner is the best-calibrated option, not the first one
    # tried. Ties keep the original order, which puts the cheaper methods first.
    ranked = sorted(comparisons, key=lambda row: (row[2] is None, row[2]))

    if args.compare or args.method == "all":
        if args.json:
            print(json.dumps(
                {
                    "dataset": Path(args.dataset).stem,
                    "samples": len(scores),
                    "positives": positives,
                    "ece_before": ece_before,
                    "fits": [
                        {"method": method, "ece_after": ece, "parameters": cal.as_dict()}
                        for method, cal, ece in ranked
                    ],
                },
                indent=2,
            ))
        else:
            print("\n=== Calibration comparison (§26) ===\n")
            print(f"dataset:  {args.dataset}")
            print(f"samples:  {len(scores)}  (positives: {positives})")
            print(f"models loaded: {health.get('loaded_models_count', 0)}")
            if not health.get("loaded_models_count"):
                print(
                    "[!] No ONNX models are loaded, so these scores come from the\n"
                    "    heuristic fallback. The fit is valid as a demonstration but\n"
                    "    must be redone once real weights are deployed (§4/§40)."
                )
            print(f"\nECE before calibration: {ece_before}")
            print("\nRanked by Expected Calibration Error (lower is better):\n")
            print(_Markdown_table(
                [
                    [
                        method,
                        "n/a" if ece is None else f"{ece:.6f}",
                        "n/a" if ece_before is None else f"{ece_before:.6f}",
                        "yes"
                        if ece_before is not None and ece is not None and ece < ece_before
                        else "no",
                    ]
                    for method, _calibrator, ece in ranked
                ],
                ["method", "ECE after", "ECE before", "improved"],
            ))
            best_method, _best_calibrator, best_ece = ranked[0]
            print(f"\nBest: {best_method} (ECE {best_ece})")
    else:
        method, calibrator, ece_after = comparisons[0]
        if args.json:
            print(json.dumps(
                {
                    "dataset": Path(args.dataset).stem,
                    "samples": len(scores),
                    "ece_before": ece_before,
                    "ece_after": ece_after,
                    "fit": calibrator.as_dict(),
                },
                indent=2,
            ))
        else:
            print("\n=== Calibration fit (§26) ===\n")
            print(f"dataset:     {args.dataset}")
            print(f"samples:     {len(scores)} (positives: {positives})")
            print(f"method:      {method}")
            print(f"ECE before:  {ece_before}")
            print(f"ECE after:   {ece_after}")
            for key, value in calibrator.as_dict().items():
                if key not in ("knots", "metadata"):
                    print(f"  {key}: {value}")

    if args.dry_run:
        print("\n[dry-run] nothing written")
        return 0

    best_method, best_calibrator, _best_ece = ranked[0]
    registry = CalibrationRegistry()
    registry.set(args.model_id, best_calibrator)
    written = registry.save(args.output)
    print(f"\nwrote {written} (method: {best_method}, key: {args.model_id})")
    print(
        "Enable it with `calibration.enabled: true` in config/engine_config.yaml. "
        "Until that flag is set the document is inert."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
