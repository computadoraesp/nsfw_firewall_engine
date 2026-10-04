"""Export PyTorch models to ONNX for the NSFW Firewall Engine.

This utility wraps the standard ``torch.onnx.export`` flow with the defaults
used by this project (opset 17, dynamic batch axis, optional FP16 conversion on
GPU). The actual network definitions are intentionally *not* shipped: wire your
trained checkpoints into :data:`MODEL_REGISTRY`.

Usage
-----
    python scripts/convert_to_onnx.py --model fast_path --checkpoint ckpt.pt \
        --output models_onnx/fast_path_mobilenetv3.onnx --opset 17 --fp16
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

logger = logging.getLogger("nsfw_engine.scripts.convert_to_onnx")

#: Input shape (N, C, H, W) expected by each model path.
DEFAULT_INPUT_SHAPES: Dict[str, Tuple[int, int, int, int]] = {
    "fast_path": (1, 3, 224, 224),
    "deep_path": (1, 3, 384, 384),
    "multimodal": (1, 3, 224, 224),
}


def _require_torch():
    try:
        import torch  # type: ignore

        return torch
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "PyTorch is required for ONNX export. Install with: pip install torch"
        ) from exc


def load_model(model_name: str, checkpoint: Optional[str] = None):
    """Instantiate a model by name and load its weights.

    Extend :data:`MODEL_REGISTRY` with real builders, e.g.::

        MODEL_REGISTRY["fast_path"] = lambda: torchvision.models.mobilenet_v3_small(num_classes=2)
    """
    torch = _require_torch()
    builder = MODEL_REGISTRY.get(model_name)
    if builder is None:
        raise KeyError(
            f"no builder registered for model {model_name!r}; "
            f"available: {sorted(MODEL_REGISTRY)}"
        )
    model = builder()
    if checkpoint:
        state = torch.load(checkpoint, map_location="cpu")
        state = state.get("state_dict", state) if isinstance(state, dict) else state
        model.load_state_dict(state, strict=False)
    model.eval()
    return model


#: Map of model name -> zero-arg callable returning an ``nn.Module`` in eval mode.
#: Populate this in a deployment-specific module or by editing this file.
MODEL_REGISTRY: Dict[str, Callable[[], object]] = {}


def export(
    model,
    output_path: str | Path,
    input_shape: Tuple[int, int, int, int] = (1, 3, 224, 224),
    opset: int = 17,
    fp16: bool = False,
    input_name: str = "input",
    output_name: str = "logits",
) -> Path:
    """Export *model* to ONNX, optionally converting to FP16."""
    torch = _require_torch()
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    dummy = torch.randn(*input_shape)
    dynamic_axes = {
        input_name: {0: "batch"},
        output_name: {0: "batch"},
    }
    logger.info("exporting to %s (opset=%d, fp16=%s)", output_path, opset, fp16)
    torch.onnx.export(
        model,
        dummy,
        str(output_path),
        input_names=[input_name],
        output_names=[output_name],
        dynamic_axes=dynamic_axes,
        opset_version=opset,
        do_constant_folding=True,
    )
    if fp16:
        _convert_fp16(output_path)
    logger.info("wrote %s", output_path)
    return output_path


def _convert_fp16(path: Path) -> None:
    try:
        import onnx  # type: ignore
        from onnxconverter_common import float16  # type: ignore
    except Exception as exc:  # noqa: BLE001
        logger.warning("FP16 conversion skipped (missing deps: %s)", exc)
        return
    model = onnx.load(str(path))
    model_fp16 = float16.convert_float_to_float16(model)
    onnx.save(model_fp16, str(path))
    logger.info("converted %s to FP16", path)


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export a PyTorch model to ONNX.")
    parser.add_argument("--model", required=True, choices=sorted(DEFAULT_INPUT_SHAPES))
    parser.add_argument("--checkpoint", default=None, help="path to a .pt/.pth checkpoint")
    parser.add_argument("--output", required=True, help="destination .onnx path")
    parser.add_argument("--opset", type=int, default=17)
    parser.add_argument("--fp16", action="store_true", help="convert weights to FP16")
    parser.add_argument(
        "--input-shape",
        type=int,
        nargs=4,
        default=None,
        metavar=("N", "C", "H", "W"),
        help="override the default input shape",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args(argv)
    shape = tuple(args.input_shape) if args.input_shape else DEFAULT_INPUT_SHAPES[args.model]
    try:
        model = load_model(args.model, args.checkpoint)
        export(model, args.output, input_shape=shape, opset=args.opset, fp16=args.fp16)
    except Exception as exc:  # noqa: BLE001
        logger.error("export failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
