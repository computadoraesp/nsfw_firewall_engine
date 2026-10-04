"""Quantize ONNX models to INT8 for the Fast-Path (and optionally others).

Uses ``onnxruntime.quantization.quantize_dynamic`` which needs only the ONNX
model (no calibration dataset) and is ideal for the Fast-Path Model A.

Usage
-----
    python scripts/quantize_models.py --model models_onnx/fast_path_mobilenetv3.onnx
    python scripts/quantize_models.py --all --weights qint8
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Iterable, List, Optional

from app.core.config import get_config

logger = logging.getLogger("nsfw_engine.scripts.quantize_models")

#: Maps a CLI weight-type choice to the onnxruntime ``QuantType`` attribute.
_WEIGHT_TYPE_ATTR = {
    "qint8": "QInt8",
    "quint8": "QUInt8",
}


def _require_quantizer():
    try:
        from onnxruntime.quantization import QuantType, quantize_dynamic  # type: ignore

        return quantize_dynamic, QuantType
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "onnxruntime is required for quantization. Install with: "
            "pip install onnxruntime"
        ) from exc


def quantized_path(source: Path) -> Path:
    """Return the conventional ``*.int8.onnx`` destination for a source model."""
    return source.with_suffix("").with_name(source.stem + ".int8.onnx")


def quantize(
    source: str | Path,
    destination: Optional[str | Path] = None,
    weight_type: str = "qint8",
) -> Path:
    """Dynamically quantize *source* to INT8 and write *destination*."""
    quantize_dynamic, QuantType = _require_quantizer()

    source = Path(source)
    if not source.exists():
        raise FileNotFoundError(f"model not found: {source}")
    destination = Path(destination) if destination else quantized_path(source)
    destination.parent.mkdir(parents=True, exist_ok=True)

    qtype = getattr(QuantType, _WEIGHT_TYPE_ATTR.get(weight_type, "QInt8"))

    logger.info("quantizing %s -> %s (weight_type=%s)", source, destination, weight_type)
    quantize_dynamic(
        model_input=str(source),
        model_output=str(destination),
        weight_type=qtype,
    )
    logger.info("wrote %s", destination)
    return destination


def _all_models() -> List[Path]:
    config = get_config()
    candidates = [
        config.model_path(config.paths.fast_path_model),
        config.model_path(config.paths.deep_path_model),
        config.model_path(config.paths.multimodal_model),
    ]
    return [path for path in candidates if path.exists()]


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Quantize ONNX models to INT8.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--model", help="path to a single .onnx model")
    group.add_argument("--all", action="store_true", help="quantize every configured model")
    parser.add_argument("--output", default=None, help="optional explicit output path")
    parser.add_argument(
        "--weights",
        default="qint8",
        choices=["qint8", "quint8"],
        help="dynamic quantization weight type",
    )
    return parser.parse_args(argv)


def _run(targets: Iterable[Path], output: Optional[str], weights: str) -> int:
    failures = 0
    count = 0
    for target in targets:
        count += 1
        try:
            quantize(target, destination=output if count == 1 else None, weight_type=weights)
        except Exception as exc:  # noqa: BLE001
            logger.error("quantization failed for %s: %s", target, exc)
            failures += 1
    return 1 if failures else 0


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args(argv)
    targets = _all_models() if args.all else [Path(args.model)]
    if not targets:
        logger.error("no models found to quantize")
        return 1
    return _run(targets, args.output, args.weights)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
