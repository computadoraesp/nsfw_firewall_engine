#!/usr/bin/env python3
"""
Generate dummy test images for corpus evaluation.

Creates minimal test images for benchmarking without requiring external datasets.
"""

import os
from pathlib import Path
import numpy as np
from PIL import Image

CORPUS_DIR = Path("benchmarks/corpus")
SAFE_DIR = CORPUS_DIR / "safe"
NSFW_DIR = CORPUS_DIR / "nsfw"

def create_dummy_image(path: Path, color: tuple):
    """Create a dummy RGB image."""
    img_array = np.full((224, 224, 3), color, dtype=np.uint8)
    img = Image.fromarray(img_array)
    img.save(path)

def create_corpus():
    """Create minimal test corpus."""
    SAFE_DIR.mkdir(parents=True, exist_ok=True)
    NSFW_DIR.mkdir(parents=True, exist_ok=True)

    # Create 10 safe images (blue for safe)
    for i in range(10):
        create_dummy_image(SAFE_DIR / f"safe_{i:03d}.jpg", (100, 150, 200))

    # Create 5 nsfw images (red for nsfw - placeholder)
    for i in range(5):
        create_dummy_image(NSFW_DIR / f"nsfw_{i:03d}.jpg", (200, 100, 50))

    # Create labels.json
    labels = {
        "version": "1.0",
        "created": "2026-11-08",
        "images": {}
    }

    for i in range(10):
        labels["images"][f"safe/safe_{i:03d}.jpg"] = {
            "label": "safe",
            "source": "dummy",
            "license": "mit"
        }

    for i in range(5):
        labels["images"][f"nsfw/nsfw_{i:03d}.jpg"] = {
            "label": "nsfw",
            "source": "dummy",
            "license": "mit"
        }

    import json
    with (CORPUS_DIR / "labels.json").open("w") as f:
        json.dump(labels, f, indent=2)

    print(f"Created corpus at {CORPUS_DIR}")
    print(f"Safe images: 10")
    print(f"NSFW images: 5")
    print(f"Labels: labels.json")

if __name__ == "__main__":
    create_corpus()
