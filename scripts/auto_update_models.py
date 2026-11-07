#!/usr/bin/env python3
"""
Automatic Model Weights Updater

Downloads latest model weights from PyTorch Hub periodically,
converts to ONNX, and replaces existing models if new version available.

Usage:
    python scripts/auto_update_models.py --model fast_path
    python scripts/auto_update_models.py --model deep_path --check-only
"""

import argparse
import hashlib
import json
import logging
import shutil
import sys
from pathlib import Path
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Model registry with PyTorch Hub URLs
MODEL_REGISTRY = {
    "fast_path": {
        "torchvision_model": "mobilenet_v3_small",
        "weights_class": "MobileNet_V3_Small_Weights",
        "output_name": "fast_path_mobilenetv3.onnx",
        "input_size": 224,
    },
    "deep_path": {
        "torchvision_model": "efficientnet_b0",
        "weights_class": "EfficientNet_B0_Weights",
        "output_name": "deep_path_efficientnetb0.onnx",
        "input_size": 224,
    },
}

# Path to model registry file
REGISTRY_FILE = Path("models_onnx/registry.json")
# Path to models directory
MODELS_DIR = Path("models_onnx")


def get_model_hash(model_path: Path) -> str:
    """Calculate SHA256 hash of model file."""
    if not model_path.exists():
        return None
    sha256 = hashlib.sha256()
    with model_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def load_registry() -> dict:
    """Load model registry with current hashes."""
    if REGISTRY_FILE.exists():
        with REGISTRY_FILE.open("r") as f:
            return json.load(f)
    return {}


def save_registry(registry: dict):
    """Save model registry."""
    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with REGISTRY_FILE.open("w") as f:
        json.dump(registry, f, indent=2)


def download_and_convert_model(model_name: str, config: dict, check_only: bool = False) -> bool:
    """Download latest model from PyTorch Hub and convert to ONNX."""
    try:
        import torch
        from torchvision.models import mobilenet_v3_small, efficientnet_b0
        from torchvision.models import MobileNet_V3_Small_Weights, EfficientNet_B0_Weights
    except ImportError as e:
        logger.error(f"PyTorch/torchvision not available: {e}")
        return False

    output_path = MODELS_DIR / config["output_name"]
    current_hash = get_model_hash(output_path)

    logger.info(f"Checking for updates for {model_name}...")

    # Download latest weights
    if config["torchvision_model"] == "mobilenet_v3_small":
        weights = MobileNet_V3_Small_Weights.DEFAULT
        model = mobilenet_v3_small(weights=weights)
    elif config["torchvision_model"] == "efficientnet_b0":
        weights = EfficientNet_B0_Weights.DEFAULT
        model = efficientnet_b0(weights=weights)
    else:
        logger.error(f"Unknown model: {config['torchvision_model']}")
        return False

    model.eval()
    input_size = config["input_size"]
    dummy_input = torch.randn(1, 3, input_size, input_size)

    # Export to temporary file
    temp_path = MODELS_DIR / f"{config['output_name']}.tmp"
    torch.onnx.export(
        model,
        dummy_input,
        temp_path,
        export_params=True,
        opset_version=17,
        do_constant_folding=True,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={
            "input": {0: "batch_size"},
            "output": {0: "batch_size"}
        }
    )

    new_hash = get_model_hash(temp_path)

    # Check if model changed
    if current_hash == new_hash:
        logger.info(f"No updates available for {model_name} (hash unchanged)")
        temp_path.unlink()
        return False

    if check_only:
        logger.info(f"Update available for {model_name} (hash changed)")
        logger.info(f"Current hash: {current_hash}")
        logger.info(f"New hash: {new_hash}")
        temp_path.unlink()
        return True

    # Backup old model
    if output_path.exists():
        backup_path = MODELS_DIR / f"{config['output_name']}.backup"
        shutil.copy(output_path, backup_path)
        logger.info(f"Backed up old model to {backup_path}")

    # Replace with new model
    shutil.move(temp_path, output_path)
    logger.info(f"Updated {model_name} successfully")
    logger.info(f"Old hash: {current_hash}")
    logger.info(f"New hash: {new_hash}")

    # Update registry
    registry = load_registry()
    registry[model_name] = {
        "hash": new_hash,
        "updated_at": datetime.utcnow().isoformat(),
        "source": "pytorch_hub",
        "model": config["torchvision_model"],
    }
    save_registry(registry)

    return True


def main():
    parser = argparse.ArgumentParser(description="Auto-update model weights from PyTorch Hub")
    parser.add_argument(
        "--model",
        choices=["fast_path", "deep_path", "all"],
        default="all",
        help="Model to update (default: all)"
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Only check for updates, don't download"
    )
    args = parser.parse_args()

    models_to_update = [args.model] if args.model != "all" else MODEL_REGISTRY.keys()

    logger.info(f"Starting model update check for: {', '.join(models_to_update)}")

    updated = False
    for model_name in models_to_update:
        if model_name not in MODEL_REGISTRY:
            logger.error(f"Unknown model: {model_name}")
            continue

        config = MODEL_REGISTRY[model_name]
        if download_and_convert_model(model_name, config, args.check_only):
            updated = True

    if args.check_only:
        if updated:
            logger.info("Updates are available. Run without --check-only to apply.")
            sys.exit(1)
        else:
            logger.info("No updates available.")
            sys.exit(0)
    else:
        if updated:
            logger.info("Model updates applied successfully.")
            logger.info("Restart the service to load new models.")
            sys.exit(0)
        else:
            logger.info("No model updates needed.")
            sys.exit(0)


if __name__ == "__main__":
    main()
