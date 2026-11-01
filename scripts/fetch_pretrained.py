"""Fetch a pretrained, license-cleared NSFW model and export it to ONNX (§41).

This repo never trains and never vendors weights (§40). This script is the
supported way to turn a public Hugging Face checkpoint into the ``.onnx``
artifact the engine mounts, so that provenance (§4) and the SHA256 lockfile
(§38) can be recorded before anything is deployed.

Usage
-----
    # 1. premium_vit - Apache-2.0 on BOTH code and weights
    Python scripts/fetch_pretrained.py --model premium_vit

    # 2. Inspect what would be downloaded, download nothing
    Python scripts/fetch_pretrained.py --model premium_vit --dry-run

    # 3. Record the lockfile after reviewing the artifact
    Python scripts/verify_models.py --write

Every source below is checked against its declared license *at fetch time*: if
Hugging Face reports anything other than the expected license, the script
refuses rather than downloading a side-load with unclear terms.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("nsfw_engine.scripts.fetch_pretrained")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@dataclass(frozen=True)
class Source:
    """A downloadable, license-cleared upstream model."""

    #: Key accepted by ``--model`` and by the adapter registry.
    key: str
    #: Hugging Face repository id.
    repo_id: str
    #: license the repo MUST declare for the download to proceed (§4).
    expected_license: str
    #: Destination artifact, relative to ``models_onnx/``.
    artifact: str
    #: ``timm`` or ``transformers`` - which library owns the architecture.
    loader: str
    #: ONNX input resolution the engine must pre-process to.
    input_size: int
    #: ONNX output labels, in order. Index 1 is NSFW for the engine contract.
    labels: tuple
    #: Upstream labels in the checkpoint's original output order.
    checkpoint_labels: tuple
    #: Files needed to load the checkpoint; large optimizer/extra files stay out.
    files: tuple
    #: Model-specific normalization from the upstream image processor.
    image_mean: tuple = (0.5, 0.5, 0.5)
    image_std: tuple = (0.5, 0.5, 0.5)
    #: timm architecture name; unused for Transformers checkpoints.
    architecture: Optional[str] = None
    #: Advisory note recorded in the provenance table.
    note: str = ""


#: Only Apache-2.0 and MIT entries are listed. Nudita (AGPL-3.0) and
#: OpenNSFW2 (unclear weight terms) are deliberately absent: adding them here
#: would be the "just enable it and route around §4" path that ``blocked``
#: exists to prevent.
SOURCES: Dict[str, Source] = {
    "premium_vit": Source(
        key="premium_vit",
        repo_id="Marqo/nsfw-image-detection-384",
        expected_license="apache-2.0",
        artifact="vit_nsfw.onnx",
        loader="timm",
        input_size=384,
        labels=("SFW", "NSFW"),
        checkpoint_labels=("NSFW", "SFW"),
        files=("config.json", "model.safetensors"),
        architecture="vit_tiny_patch16_384",
        note="ViT/timm, 384px, Apache-2.0 code AND weights - the one to ship first.",
    ),
    "premium_vit_224": Source(
        key="premium_vit_224",
        repo_id="Falconsai/nsfw_image_detection",
        expected_license="apache-2.0",
        artifact="vit_nsfw_224.onnx",
        loader="transformers",
        input_size=224,
        labels=("normal", "nsfw"),
        checkpoint_labels=("normal", "nsfw"),
        files=("config.json", "model.safetensors", "preprocessor_config.json"),
        note="ViT-base 224px, Apache-2.0, ~1.2M downloads. Lower resolution.",
    ),
    # §45: the practical fast path. A CNN, unlike the ViT, so INT8 dynamic
    # quantization actually loads on the CPU provider - ConvInteger is only
    # generated for transformer patch-embeddings. 224px and 4M parameters put
    # this in the single-digit-millisecond range that the Fast-Path SLO
    # (< 10 ms) describes. Five classes, so the label sidecar carries the full
    # order and the adapter sums the explicit ones.
    "fast_efficientnet": Source(
        key="fast_efficientnet",
        repo_id="viddexa/nsfw-detection-2-nano",
        expected_license="apache-2.0",
        artifact="fast_efficientnet.onnx",
        loader="transformers",
        input_size=224,
        labels=("safe", "hentai", "porn", "sexy", "drawing"),
        checkpoint_labels=("safe", "hentai", "porn", "sexy", "drawing"),
        files=("config.json", "model.safetensors", "preprocessor_config.json"),
        image_mean=(0.485, 0.456, 0.406),
        image_std=(0.47853944, 0.4732864, 0.47434163),
        note="EfficientNet 4M params, 224px, Apache-2.0. INT8-quantizable.",
    ),
    # §45 deep path. Same family and the same five classes as the fast path but
    # at 380px, so it is genuinely more capable on borderline content rather
    # than the same model run twice. That is what makes the cascade's escalate
    # decision meaningful (§41 cost-aware triage).
    "deep_efficientnet": Source(
        key="deep_efficientnet",
        repo_id="viddexa/nsfw-detection-2-mini",
        expected_license="apache-2.0",
        artifact="deep_efficientnet.onnx",
        loader="transformers",
        input_size=380,
        labels=("safe", "hentai", "porn", "sexy", "drawing"),
        checkpoint_labels=("safe", "hentai", "porn", "sexy", "drawing"),
        files=("config.json", "model.safetensors", "preprocessor_config.json"),
        image_mean=(0.485, 0.456, 0.406),
        image_std=(0.47853944, 0.4732864, 0.47434163),
        note="EfficientNet 17.7M params, 380px, Apache-2.0. Deployed as Deep-Path.",
    ),
}


def resolve(key: str) -> Source:
    try:
        return SOURCES[key]
    except KeyError:
        raise KeyError(
            f"unknown model {key!r}; available: {sorted(SOURCES)}"
        ) from None


def _require_hub():
    try:
        from huggingface_hub import HfApi, snapshot_download  # type: ignore

        return HfApi, snapshot_download
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "huggingface_hub is required to fetch pretrained weights. Install "
            "with: pip install '.[model-export]'"
        ) from exc


def _verified_repo_info(source: Source) -> Tuple[str, str]:
    """Return the declared license and immutable commit after checking the gate."""
    HfApi, _ = _require_hub()
    info = HfApi().model_info(source.repo_id)
    card_data = getattr(info, "cardData", None)
    declared = str(getattr(card_data, "license", "") or "").lower().strip()
    if not declared:
        raise RuntimeError(
            f"{source.repo_id} declares no license field; refusing (§4). Record it "
            "in docs/MODEL_PROVENANCE.md manually or pick a cleared source."
        )
    if declared != source.expected_license:
        raise RuntimeError(
            f"{source.repo_id} declares license {declared!r}, expected "
            f"{source.expected_license!r}. Refusing to download - re-run the "
            "legal review before shipping this artifact."
        )
    revision = str(getattr(info, "sha", "") or "").strip()
    if not revision:
        raise RuntimeError(
            f"{source.repo_id} returned no immutable commit SHA; refusing an "
            "unreproducible model download."
        )
    logger.info("license verified: %s -> %s at %s", source.repo_id, declared, revision)
    return declared, revision


def check_license(source: Source) -> str:
    """Return the upstream license, or refuse when it is not what we expect.

    A license that *changed upstream* is exactly the case where an audit trail
    written months ago silently stops being true, so the declared value is
    re-read on every fetch instead of being trusted from a hardcoded table.
    """
    return _verified_repo_info(source)[0]


def _download_snapshot(
    source: Source, revision: str, cache_dir: Optional[Path] = None
) -> Path:
    """Download only required files from the exact revision whose license passed."""
    _, snapshot_download = _require_hub()
    path = snapshot_download(
        repo_id=source.repo_id,
        revision=revision,
        cache_dir=str(cache_dir) if cache_dir else None,
        allow_patterns=list(source.files),
    )
    snapshot = Path(path)
    missing = [name for name in source.files if not (snapshot / name).is_file()]
    if missing:
        raise RuntimeError(
            f"{source.repo_id}@{revision} is missing required model files: {missing}"
        )
    logger.info("cached %s at %s", source.repo_id, snapshot)
    return snapshot


def download(source: Source, cache_dir: Optional[Path] = None) -> Path:
    """Verify the license, then download a minimal, commit-pinned snapshot."""
    _, revision = _verified_repo_info(source)
    return _download_snapshot(source, revision, cache_dir)


def _checkpoint_labels(source: Source, local_dir: Path) -> Tuple[str, ...]:
    """Read and validate class order from the downloaded model configuration."""
    config_path = local_dir / "config.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read model config {config_path}: {exc}") from exc

    if source.loader == "timm":
        labels = config.get("label_names")
    else:
        id2label = config.get("id2label")
        if isinstance(id2label, dict):
            try:
                labels = [
                    id2label.get(str(i), id2label.get(i))
                    for i in range(len(id2label))
                ]
            except (TypeError, ValueError):
                labels = None
        else:
            labels = None
    if not isinstance(labels, list):
        raise RuntimeError(
            f"{config_path} does not declare a supported checkpoint label mapping"
        )
    expected = tuple(label.strip().casefold() for label in source.checkpoint_labels)
    actual = tuple(str(label).strip().casefold() for label in labels or ())
    if actual != expected:
        raise RuntimeError(
            f"{source.repo_id} checkpoint labels {labels!r} do not match the "
            f"reviewed order {source.checkpoint_labels!r}"
        )
    if len(source.labels) != len(actual) or {
        label.casefold() for label in source.labels
    } != set(actual):
        raise RuntimeError(
            f"ONNX labels {source.labels!r} must be a permutation of checkpoint "
            f"labels {labels!r}"
        )
    return tuple(str(label) for label in labels)


def _output_indices(source: Source, checkpoint_labels: Tuple[str, ...]) -> Tuple[int, ...]:
    """Map the upstream head into the output order recorded in the sidecar."""
    normalized = {label.strip().casefold(): index for index, label in enumerate(checkpoint_labels)}
    try:
        return tuple(
            normalized[label.strip().casefold()] for label in source.labels
        )
    except KeyError as exc:
        raise RuntimeError(
            f"ONNX label {exc.args[0]!r} is absent from the checkpoint"
        ) from exc


def build_pytorch_module(source: Source, local_dir: Path):
    """Load local weights and expose logits in the engine's reviewed class order."""
    checkpoint_labels = _checkpoint_labels(source, local_dir)
    output_indices = _output_indices(source, checkpoint_labels)

    if source.loader == "timm":
        try:
            import timm  # type: ignore
            from safetensors.torch import load_file  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("install the model-export dependencies") from exc
        if not source.architecture:
            raise RuntimeError(f"{source.key} does not declare a timm architecture")
        model = timm.create_model(
            source.architecture, pretrained=False, num_classes=len(source.labels)
        )
        state = load_file(str(local_dir / "model.safetensors"), device="cpu")
        model.load_state_dict(state, strict=True)
    else:
        try:
            from transformers import AutoModelForImageClassification  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("install the model-export dependencies") from exc
        model = AutoModelForImageClassification.from_pretrained(
            str(local_dir), local_files_only=True, use_safetensors=True
        )
        configured_labels = tuple(
            str(model.config.id2label.get(i, model.config.id2label.get(str(i), "")))
            for i in range(len(source.labels))
        )
        if tuple(label.casefold() for label in configured_labels) != tuple(
            label.casefold() for label in source.checkpoint_labels
        ):
            raise RuntimeError(
                f"loaded Transformers labels {configured_labels!r} do not match "
                f"{source.checkpoint_labels!r}"
            )

    import torch  # type: ignore

    class OrderedLogits(torch.nn.Module):
        def __init__(self, wrapped):
            super().__init__()
            self.wrapped = wrapped

        def forward(self, pixel_values):
            output = self.wrapped(pixel_values)
            logits = output.logits if hasattr(output, "logits") else output
            if isinstance(logits, (tuple, list)):
                logits = logits[0]
            return logits[..., list(output_indices)]

    return OrderedLogits(model).eval()


def provenance_record(
    source: Source,
    artifact: Path,
    license_value: str,
    revision: Optional[str] = None,
) -> str:
    """Render the row to paste into ``docs/MODEL_PROVENANCE.md`` (§4)."""
    return json.dumps(
        {
            "key": source.key,
            "source": f"https://huggingface.co/{source.repo_id}",
            "revision": revision,
            "artifact": artifact.name,
            "weights_license": license_value,
            "input_size": source.input_size,
            "labels": list(source.labels),
            "image_mean": list(source.image_mean),
            "image_std": list(source.image_std),
            "note": source.note,
        },
        indent=2,
    )
def export_source(
    source: Source,
    output_dir: Optional[Path] = None,
    cache_dir: Optional[Path] = None,
    opset: int = 17,
    fp16: bool = False,
    dynamic_batch: bool = True,
) -> Tuple[Path, str, str]:
    """Fetch, export to ONNX and run the post-export contract check (§41)."""
    from scripts.convert_to_onnx import export
    from adapters.labels import build as build_sidecar
    from adapters.labels import write as write_sidecar

    license_value, revision = _verified_repo_info(source)
    local_dir = _download_snapshot(source, revision, cache_dir=cache_dir)
    model = build_pytorch_module(source, local_dir)

    output_dir = Path(output_dir or PROJECT_ROOT / "models_onnx")
    destination = output_dir / source.artifact
    size = (source.input_size, source.input_size)
    logger.info(
        "exporting %s -> %s (input=%s, labels=%s)",
        source.repo_id, destination, size, source.labels,
    )
    # export() runs verify_export(), which rejects a head whose width does not
    # match what the engine will read - the check that catches a bad export
    # here rather than at request time.
    export(
        model,
        destination,
        input_shape=(1, 3, *size),
        opset=opset,
        fp16=fp16,
        dynamic_batch=dynamic_batch,
    )
    sidecar = write_sidecar(
        destination,
        build_sidecar(
            source.labels,
            size,
            mean=source.image_mean,
            std=source.image_std,
        ),
    )
    logger.info("wrote label sidecar %s", sidecar)
    logger.info("model source commit: %s (license: %s)", revision, license_value)
    logger.info("now record provenance and run: verify_models.py --write")
    return destination, license_value, revision


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch a license-cleared pretrained NSFW model and export ONNX."
    )
    parser.add_argument("--model", required=True, choices=sorted(SOURCES))
    parser.add_argument(
        "--output-dir", default=None, help="destination (default: models_onnx/)"
    )
    parser.add_argument("--cache-dir", default=None, help="huggingface cache dir")
    parser.add_argument("--opset", type=int, default=17)
    parser.add_argument("--fp16", action="store_true")
    parser.add_argument(
        "--static-batch",
        action="store_true",
        help="pin the batch axis to 1; required before INT8 quantization",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="verify the license and print the plan; download nothing",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args(argv)
    source = resolve(args.model)
    try:
        if args.dry_run:
            license_value, revision = _verified_repo_info(source)
            print(f"source:  {source.repo_id}")
            print(f"revision: {revision}")
            print(f"license: {license_value} (expected {source.expected_license})")
            print(f"labels:  {source.labels}")
            print(f"input:   {source.input_size}x{source.input_size}")
            print(f"target:  models_onnx/{source.artifact}")
            print(f"note:    {source.note}")
            return 0
        artifact, license_value, revision = export_source(
            source,
            output_dir=args.output_dir,
            cache_dir=args.cache_dir,
            opset=args.opset,
            fp16=args.fp16,
            dynamic_batch=not args.static_batch,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("fetch failed: %s", exc)
        return 1
    print(provenance_record(source, artifact, license_value, revision))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())