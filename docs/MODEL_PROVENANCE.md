# Model Provenance

This document records the provenance of every ONNX model artifact used by the NSFW Firewall Engine.

| Model | Source (URL / repo) | License | Checkpoint commit / tag | SHA‑256 of ONNX artifact | Conversion script (version) |
|-------|----------------------|---------|--------------------------|--------------------------|------------------------------|
| fast_path (MobileNetV3‑Small) | https://github.com/pytorch/vision (MobileNetV3‑Small) | MIT / Apache‑2.0 | `v0.1.0` (tag) | <SHA‑256‑PLACEHOLDER> | `scripts/convert_to_onnx.py` |
| deep_path (EfficientNet‑B0) | https://github.com/pytorch/vision (EfficientNet‑B0) | MIT / Apache‑2.0 | `v0.1.0` (tag) | <SHA‑256‑PLACEHOLDER> | `scripts/convert_to_onnx.py` |
| multimodal (ResNet‑50) | https://github.com/pytorch/vision (ResNet‑50) | MIT / Apache‑2.0 | `v0.1.0` (tag) | <SHA‑256‑PLACEHOLDER> | `scripts/convert_to_onnx.py` |
| text_path (DistilBERT) | https://github.com/huggingface/transformers (DistilBERT) | Apache‑2.0 | `v0.1.0` (tag) | N/A (ONNX not yet generated) | N/A (conversion TBD) |

> **How to use**
> 1. When a new checkpoint is downloaded, record its upstream URL, license, and commit/tag.
> 2. After running `scripts/convert_to_onnx.py`, compute the SHA‑256 of the resulting `.onnx` file (e.g., `sha256sum <file>`).
> 3. Fill the corresponding row and commit the updated file.

*This table is the single source of truth for model provenance; CI can be extended to validate the SHA‑256 against the entry.*
