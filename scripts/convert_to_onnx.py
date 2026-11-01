"""Export PyTorch models to ONNX for the NSFW Firewall Engine.

This utility wraps the standard ``torch.onnx.export`` flow with the defaults
used by this project (opset 17, dynamic batch axis, optional FP16 conversion on
GPU). The network definitions are built here from ``torchvision``, but the
*weights* are never shipped (§40) - pass ``--checkpoint`` with an NSFW
fine-tuned state_dict for the stage you are exporting.

Usage
-----
    Python scripts/convert_to_onnx.py --model fast_path --checkpoint ckpt.pt \
        --output models_onnx/fast_path_mobilenetv3.onnx --opset 17 --fp16

Note that torchvision's ImageNet weights are NOT an NSFW detector (§49). A
checkpoint trained for the 2-class head *must* be supplied for the export to
mean anything; exporting the untrained head is refused unless
``--allow-untrained`` is passed.
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


def load_model(
    model_name: str,
    checkpoint: Optional[str] = None,
    allow_untrained: bool = False,
):
    """Instantiate a model by name and load its weights.

    A checkpoint is mandatory unless *allow_untrained* is set: the builders
    produce a randomly initialized 2-class head, and exporting that would ship
    an artifact that scores noise while looking exactly like a trained model
    (§49). ``strict=True`` is used deliberately - a partially loaded checkpoint
    means the architecture and the weights disagree, which is a hard error, not
    something to warn about.
    """
    torch = _require_torch()
    builder = MODEL_REGISTRY.get(model_name)
    if builder is None:
        raise KeyError(
            f"no builder registered for model {model_name!r}; "
            f"available: {sorted(MODEL_REGISTRY)}"
        )
    if not checkpoint and not allow_untrained:
        raise ValueError(
            f"refusing to export model {model_name!r} without --checkpoint: the "
            "2-class head would be randomly initialized and the resulting ONNX "
            "would be indistinguishable from a trained detector. Pass "
            "--allow-untrained only to smoke-test the export pipeline."
        )
    model = builder()
    if checkpoint:
        checkpoint_path = Path(checkpoint)
        if not checkpoint_path.exists():
            raise FileNotFoundError(f"checkpoint not found: {checkpoint_path}")
        state = torch.load(str(checkpoint_path), map_location="cpu", weights_only=False)
        state = state.get("state_dict", state) if isinstance(state, dict) else state
        model.load_state_dict(_strip_prefixes(state), strict=True)
        logger.info("loaded checkpoint %s into %s", checkpoint_path, model_name)
    else:
        logger.warning(
            "exporting %s with RANDOMLY initialized weights - this artifact is "
            "not a detector",
            model_name,
        )
    model.eval()
    return model


def _require_torchvision():
    try:
        import torchvision  # type: ignore

        return torchvision
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "torchvision is required to build the model definitions. Install "
            "with: pip install torchvision"
        ) from exc


# --------------------------------------------------------------------------- #
# Model builders (§41).
#
# Each builder returns an ``nn.Module`` with a 2-class head, which is the shape
# ``app.core.onnx_runtime.to_probability`` expects: 2 outputs -> channel index 1
# is NSFW. The architectures come from torchvision (Apache-2.0); only the
# *architecture* is licensed here, never the weights (§4).
#
# Builders are lazy so that importing this script never imports torch - CI
# byte-compiles and unit-tests the tooling without a 2 GB dependency installed.
# --------------------------------------------------------------------------- #
def build_fast_path():
    """MobileNetV3-Small, 2-class head - Fast-Path (Model A)."""
    tv = _require_torchvision()
    return tv.models.mobilenet_v3_small(num_classes=2)


def build_deep_path():
    """EfficientNet-B0, 2-class head - Deep-Path (Model B)."""
    tv = _require_torchvision()
    return tv.models.efficientnet_b0(num_classes=2)


def build_multimodal():
    """ResNet-50 trunk with a 2-class head - Multimodal (Model C).

    The fused CLIP visual+text encoder is a deployment-specific module; this
    trunk export keeps the slot buildable so the cascade can be exercised. Wrap
    the real encoder in ``adapters/`` before promoting it (§22).
    """
    tv = _require_torchvision()
    return tv.models.resnet50(num_classes=2)


#: Map of model name -> zero-arg callable returning an ``nn.Module`` in eval mode.
MODEL_REGISTRY: Dict[str, Callable[[], object]] = {
    "fast_path": build_fast_path,
    "deep_path": build_deep_path,
    "multimodal": build_multimodal,
}

#: Every registered builder must produce this many outputs; ``to_probability``
#: reads channel index 1 as NSFW and anything else silently mislabels traffic.
EXPECTED_NUM_CLASSES = 2


def _strip_prefixes(state):
    """Drop DataParallel / fine-tuning prefixes so ``strict=True`` can be used."""
    if not isinstance(state, dict):
        return state
    for prefix in ("module.", "model.", "net."):
        if any(str(k).startswith(prefix) for k in state):
            state = {
                (k[len(prefix):] if str(k).startswith(prefix) else k): v
                for k, v in state.items()
            }
    return state


def export(
    model,
    output_path: str | Path,
    input_shape: Tuple[int, int, int, int] = (1, 3, 224, 224),
    opset: int = 17,
    fp16: bool = False,
    input_name: str = "input",
    output_name: str = "logits",
    dynamic_batch: bool = True,
) -> Path:
    """Export *model* to ONNX, optionally converting to FP16.

    ``dynamic_batch=False`` pins the batch axis to 1. That is required before
    dynamic INT8 quantization: ``quantize_dynamic`` runs shape inference, and
    ONNX Runtime's shape inference on a symbolic batch dimension can infer a
    different width for the quantized head than the graph declares, which fails
    with ``Inferred shape and existing shape differ in dimension 0``. The
    cascade classifies one payload per request, so a static batch costs nothing.
    """
    torch = _require_torch()
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    dummy = torch.randn(*input_shape)
    # A symbolic batch axis is what breaks quantize_dynamic's shape inference,
    # so it is opt-out rather than opt-in.
    dynamic_shapes = (
        {"pixel_values": {0: torch.export.Dim("batch")}}
        if dynamic_batch
        else None
    )
    logger.info("exporting to %s (opset=%d, fp16=%s)", output_path, opset, fp16)
    torch.onnx.export(
        model,
        dummy,
        str(output_path),
        input_names=[input_name],
        output_names=[output_name],
        dynamic_shapes=dynamic_shapes,
        opset_version=opset,
        external_data=False,
        do_constant_folding=True,
    )
    if fp16:
        _convert_fp16(output_path)
    logger.info("wrote %s", output_path)
    verify_export(output_path, input_shape)
    return output_path


def verify_export(path: str | Path, input_shape: Tuple[int, int, int, int]) -> None:
    """Load the freshly written artifact and assert the inference contract.

    This is the only place that proves the export is actually consumable by
    ``app.core.onnx_runtime``: an ONNX file that no session can open, or whose
    output width disagrees with :data:`EXPECTED_NUM_CLASSES`, would otherwise be
    discovered at request time and silently downgraded to the skin-tone
    heuristic.
    """
    try:
        import onnxruntime  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "onnxruntime is required to validate an exported model; install the "
            "project runtime dependencies before exporting"
        ) from exc

    import numpy as np  # local import: keeps the export path torch-only

    session = onnxruntime.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    inputs = session.get_inputs()
    outputs = session.get_outputs()
    if not inputs:
        raise ValueError(f"exported model {path} declares no inputs")
    logger.info(
        "exported %s: input=%s output=%s",
        Path(path).name,
        [(i.name, i.shape) for i in inputs],
        [(o.name, o.shape) for o in outputs],
    )

    if len(outputs) != 1:
        raise ValueError(
            f"exported model {path} has {len(outputs)} outputs; the engine reads "
            "a single logits tensor (to_probability)"
        )
    width = outputs[0].shape[-1]
    if isinstance(width, int) and width < EXPECTED_NUM_CLASSES:
        # A wider head is legitimate - some detectors are multi-class (safe /
        # hentai / porn / sexy / drawing) and the adapter sums the explicit
        # indices named in the label sidecar. What is never acceptable is a
        # *narrower* head, because the runtime contract reads index 1 as NSFW.
        raise ValueError(
            f"exported model {path} emits {width} classes; the runtime reads "
            f"index 1 as NSFW, so a head narrower than 2 would be mislabeled. "
            "Wrap it in the matching adapters/ normalizer before promoting it."
        )

    probe = np.zeros((1, *input_shape[1:]), dtype=np.float32)
    result = session.run(None, {inputs[0].name: probe})[0]
    if result.ndim < 2 or result.shape[-1] < EXPECTED_NUM_CLASSES:
        raise ValueError(
            f"smoke inference from {path} returned shape {result.shape}; expected "
            f"a batch of at least {EXPECTED_NUM_CLASSES}-class logits"
        )
    if not np.all(np.isfinite(result)):
        raise ValueError(f"smoke inference from {path} returned non-finite logits")
    logger.info(
        "smoke inference ok: shape=%s dtype=%s classes=%s",
        result.shape, result.dtype, int(result.shape[-1]),
    )


def _convert_fp16(path: Path) -> None:
    try:
        import onnx  # type: ignore
        from onnxconverter_common import float16  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "FP16 export requires onnxconverter-common; install "
            "the fp16-export extra"
        ) from exc
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
        "--allow-untrained",
        action="store_true",
        help="export with a randomly initialized head (pipeline smoke-test only)",
    )
    parser.add_argument(
        "--static-batch",
        action="store_true",
        help="pin the batch axis to 1 (required before INT8 quantization)",
    )
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
        model = load_model(args.model, args.checkpoint, allow_untrained=args.allow_untrained)
        export(
            model,
            args.output,
            input_shape=shape,
            opset=args.opset,
            fp16=args.fp16,
            dynamic_batch=not args.static_batch,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("export failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
