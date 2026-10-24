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
        model_input=_prepare_for_quantization(source),
        model_output=str(destination),
        weight_type=qtype,
    )
    _verify_quantized(destination, source)
    logger.info("wrote %s", destination)
    return destination


def _verify_quantized(quantized: Path, original: Path) -> None:
    """Load *quantized* and refuse to ship an artifact no runtime can execute.

    Dynamic quantization can succeed and still yield a dead graph. On a
    transformer with a convolutional patch-embedding, ``quantize_dynamic``
    rewrites the ``Conv`` into ``ConvInteger``, which the CPU execution
    provider does not implement::

        [ONNXRuntimeError] NOT_IMPLEMENTED : Could not find an implementation
        for ConvInteger(10) node with name 'node_conv2d_quant'

    Writing that file would look like a successful speedup while the engine
    crashed on the first request. So the artifact is loaded and run here, and a
    failure is raised with the remedy rather than discovered in production.
    """
    try:
        import numpy as np
        import onnxruntime
    except Exception as exc:  # noqa: BLE001
        logger.warning("post-quantization check skipped (missing deps: %s)", exc)
        return

    try:
        session = onnxruntime.InferenceSession(
            str(quantized), providers=["CPUExecutionProvider"]
        )
        spec = session.get_inputs()[0]
        shape = [d if isinstance(d, int) and d > 0 else 1 for d in spec.shape[1:]]
        if len(shape) != 3:
            raise RuntimeError(f"unexpected input rank in {quantized.name}")
        probe = np.zeros([1, *shape], dtype=np.float32)
        session.run(None, {spec.name: probe})
    except Exception as exc:  # noqa: BLE001
        # Delete the dead artifact. Leaving a file that looks like a successful
        # speedup on disk is worse than having none: the next operator would
        # mount it and only discover the failure at request time.
        try:
            quantized.unlink()
        except OSError:
            pass
        raise RuntimeError(
            f"quantization produced {quantized.name}, but ONNX Runtime cannot "
            f"execute it on the CPU provider: {exc}. A transformer whose "
            "convolutional patch-embedding is rewritten to ConvInteger has no "
            "CPU kernel, and neither does a graph whose input shape this tool "
            "cannot infer. Do NOT deploy this artifact - delete it and keep the "
            "FP32 graph, or quantize a CNN-based detector instead of a ViT."
        ) from exc
    logger.info("quantized artifact loads and runs on the CPU provider")


def _prepare_for_quantization(source: Path) -> str:
    """Return a quantizer-safe copy of *source*, and why it was needed.

    ``quantize_dynamic`` runs ONNX shape inference before rewriting, and it
    fails outright with::

        [ShapeInferenceError] Inferred shape and existing shape differ in
        dimension 0: (192) vs (2)

    when the graph carries ``value_info`` entries whose recorded shapes no
    longer agree with the ops. This happens on exports that wrap a classifier
    to reorder its outputs (see ``OrderedLogits`` in
    ``scripts/fetch_pretrained.py``): the slice leaves a stale transposed
    ``[2, 192]`` annotation on the head weight that the quantizer then reads as
    a real shape constraint.

    ``value_info`` is *inferred* metadata - it documents shapes, it does not
    define them - so dropping it loses no information and lets the quantizer
    re-infer everything from the graph itself. The copy is written next to the
    original and reused if it already exists, so repeated runs stay cheap.
    """
    import onnx  # local: only the INT8 path needs the protobuf API

    prepared = source.with_name(source.stem + ".quantizable.onnx")
    if prepared.exists():
        return str(prepared)
    model = onnx.load(str(source))
    if model.graph.value_info:
        logger.info(
            "stripping %d value_info entries before quantization (stale inferred "
            "shapes make quantize_dynamic's shape inference fail)",
            len(model.graph.value_info),
        )
        del model.graph.value_info[:]
    prepared.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(model, str(prepared))
    return str(prepared)


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
