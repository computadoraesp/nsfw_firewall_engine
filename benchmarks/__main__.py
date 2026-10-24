"""Benchmark / evaluation CLI (§25, §35, §45, §49).

Usage::

    python -m benchmarks --iterations 200          # latency + throughput matrix
    python -m benchmarks --json                    # machine-readable report
    python -m benchmarks --dataset datasets/eval.json   # precision/recall/F1

The tool prints exactly what it measured on *this* machine and refuses to
present heuristic-fallback numbers as detector performance.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from benchmarks.evaluate import evaluate_manifest, evaluate_synthetic
from benchmarks.harness import run_benchmark


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks",
        description="Measure NSFW Firewall Engine latency, throughput and accuracy.",
    )
    parser.add_argument("--iterations", type=int, default=100, help="timed requests")
    parser.add_argument("--warmup", type=int, default=10, help="untimed warmup requests")
    parser.add_argument(
        "--use-cache",
        action="store_true",
        help="include cache hits (default: measure inference, not lookups)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of markdown")
    parser.add_argument(
        "--csv", action="store_true", help="emit CSV (§25) instead of markdown"
    )
    parser.add_argument(
        "--html", action="store_true", help="emit a self-contained HTML report (§25)"
    )
    parser.add_argument(
        "--dataset",
        default=None,
        help="path to a labelled dataset manifest for precision/recall (§35)",
    )
    parser.add_argument("--positive-label", default=None, help="label treated as positive")
    parser.add_argument("--threshold", type=float, default=None, help="decision threshold")
    parser.add_argument(
        "--synthetic-eval",
        type=int,
        default=0,
        metavar="N",
        help=(
            "run the §35 metrics on N synthetic labelled images per class. This "
            "proves the metric path works and shows the model separates the two "
            "groups; it is NOT a quality measurement - use --dataset for that"
        ),
    )
    parser.add_argument(
        "--out",
        default=None,
        help="write the markdown report to this file (e.g. docs/BENCHMARK_MATRIX.md)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    # Windows consoles default to cp1252 and cannot encode the markdown report
    # symbols (em dash, warning sign). Fall back gracefully instead of crashing.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - not all streams support reconfigure
            pass

    from app.core.engine import NsfwEngine
    from app.core.logging_setup import setup_logging

    setup_logging()
    engine = NsfwEngine()

    report = run_benchmark(
        engine,
        iterations=args.iterations,
        warmup=args.warmup,
        use_cache=args.use_cache,
    )

    if args.dataset:
        evaluation = evaluate_manifest(
            engine, args.dataset, args.positive_label, args.threshold
        )
    elif args.synthetic_eval:
        evaluation = evaluate_synthetic(
            engine, per_class=max(2, int(args.synthetic_eval)),
            threshold=args.threshold,
        )
    else:
        evaluation = None

    sections = {"benchmark": report.as_dict()}
    if evaluation is not None:
        sections["evaluation"] = evaluation.as_dict()

    if args.json:
        print(json.dumps(sections, indent=2))
        return 0

    if args.csv:
        from benchmarks.reporting import to_csv

        text = to_csv(sections)
    elif args.html:
        from benchmarks.reporting import to_html

        text = to_html(sections)
    else:
        markdown = [report.to_markdown()]
        if evaluation is not None:
            markdown.append("")
            markdown.append(evaluation.to_markdown())
        text = "\n".join(markdown)

    if args.out:
        from pathlib import Path

        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())