# models_onnx/

Compiled / optimized ONNX artifacts consumed by `app.core.onnx_runtime`.

> The binary `.onnx` files are **not** committed to the repository (they are
> large, license-bound artifacts). This directory documents the expected
> contract and how to produce them. Missing or failed models are skipped; if no
> model can decide, the engine returns `REVIEW` rather than using a heuristic.

## Label sidecar (required)

A graph does not carry its class names. Two checkpoints can emit the
**identical tensor** while disagreeing about what index 0 means — and for a
2-class head that is the difference between blocking clean images and letting
explicit ones through, with no error anywhere.

Every artifact therefore ships a sidecar:

| File | Meaning |
|------|---------|
| `fast_path_mobilenetv3.onnx` | MobileNetV3-Small, 2-class head, INT8/FP16 |
| `fast_path_mobilenetv3.labels.json` | `["safe", "nsfw"]`, `input_size: [224,224]` |

`input_size` matters: feeding 224px to a 384px checkpoint degrades it silently.
The sidecar also records per-channel `mean` and `std`; evaluators use these
values rather than assuming ImageNet normalization.

An adapter with **no** sidecar returns `None` — it refuses to score rather than
guess the class order, so the cascade escalates instead of acting on a possibly
inverted reading (§49).

Both files are hashed by `scripts/verify_models.py` (`--write` records them
together), so editing the class order is as detectable as editing the weights
(§38).

## Expected artifacts

| File | Stage | Target latency | Notes |
|------|-------|----------------|-------|
| `fast_path_mobilenetv3.onnx` | Fast-Path (Model A) | < 10 ms | MobileNetV3-Small, 2-class head, INT8/FP16 |
| `vit_nsfw.onnx` | Deep-Path (Model B) | ~57 ms CPU mean measured locally | Marqo ViT, 384px, 2-class head; accuracy not yet evaluated |
| `fast_efficientnet.onnx` | Quarantined | — | Viddexa Nano graph; ONNX/PyTorch parity failed |
| `deep_efficientnet.onnx` | Quarantined | — | Viddexa 5-class graph; ONNX/PyTorch parity failed |
| `multimodal_clip.onnx` | Multimodal (Model C) | 50–90 ms | CLIP visual+text encoder, fused head |
| `text_distilbert.onnx` | Text-Path | < 15 ms | DistilBERT classifier; text input, not an image tensor |

### External adapters (§41) — `default_model_path` in `adapters/vision.py`

| File | Stage | §22 status | Notes |
|------|-------|-------------|-------|
| `vit_nsfw.onnx` | `premium_vit` | `candidate` | Same Marqo graph as Deep-Path; disabled to avoid duplicate inference |
| `nsfwjs_mobilenetv2.onnx` | `fast_path` | `candidate` | MIT code; weight provenance unclear |
| `clip_zeroshot.onnx` | `multimodal` | `candidate` | MIT code and weights |
| `opennsfw2_resnet50.onnx` | `deep_path` | **`blocked`** | ⚠️ Do not add — weight terms are `LEGAL_REVIEW_REQUIRED` (§4) |
| *(none)* | `rejected` / `nudita` | **`blocked`** | 🚫 Must never be loaded — AGPL-3.0 |

> **The local runtime currently uses `vit_nsfw.onnx` in Deep-Path.** It is the
> only local graph with verified PyTorch/ONNX parity, but its accuracy benchmark
> has not been run. Adding a `blocked` artifact is not merely
> discouraged: `adapters/base.py` refuses to load one, so it would sit on disk
> inert and fail `verify_models.py` as an unvetted side-load.

## Input / output contract

* **Input**  – `float32` tensor `NCHW`, normalized according to that model's
  sidecar (or the configured default if the artifact has no sidecar).
  * Fast-Path resize: `224x224`
  * Deep-Path resize: `384x384`
  * Multimodal resize: `224x224`
  * Dynamic batch axis (`N`) is expected.
  * Text-Path differs: `input_ids` + `attention_mask`, not an image tensor.
  * The Hugging Face ViT adapter reads the model-specific normalization from
    its sidecar (the current candidates use mean/std of `[0.5, 0.5, 0.5]`).
* **Output** – logits. The engine collapses outputs to a probability as follows:
  * 1 value  → sigmoid(logit)
  * 2 values → class logits, channel index `1` is NSFW
  * N values → requires a sidecar; explicit class probabilities are summed.

> ⚠️ The same output tensor interpreted differently per model silently destroys
> accuracy. NSFWJS exports a 6-class head, so its normalisation is *not* the
> generic rule above — it is implemented explicitly in
> `adapters/vision.py::NSFWJSAdapter.normalize` and must be matched whenever an
> artifact is re-exported.

## Producing the artifacts

```bash
# Install model-fetch/export tooling separately from the runtime. Install a
# platform-specific PyTorch build first if you need CUDA/ROCm acceleration.
Python -m pip install -e ".[model-export]"
# Optional, only when using --fp16:
Python -m pip install -e ".[fp16-export]"

# 0. Easiest path: fetch a license-cleared checkpoint, export it AND write
#    its label sidecar. Verify the license with --dry-run first.
Python scripts/fetch_pretrained.py --model premium_vit --dry-run
Python scripts/fetch_pretrained.py --model premium_vit

# 1. Or export a local checkpoint yourself. The builders are already
#    registered in scripts/convert_to_onnx.py (MODEL_REGISTRY) - MobileNetV3-
#    Small for fast_path, EfficientNet-B0 for deep_path, ResNet-50 trunk for
#    multimodal, all with a 2-class head. --checkpoint is MANDATORY: exporting
#    without one produces a randomly initialized head that is refused by default.
Python scripts/convert_to_onnx.py --model fast_path \
    --checkpoint checkpoints/mobilenetv3_nsfw.pt \
    --output models_onnx/fast_path_mobilenetv3.onnx --opset 17 --fp16

# 1b. Architecture smoke-test only (the artifact is NOT a detector):
Python scripts/convert_to_onnx.py --model fast_path \
    --output /tmp/probe.onnx --allow-untrained

# 2. Quantize the fast path to INT8
Python scripts/quantize_models.py --model models_onnx/fast_path_mobilenetv3.onnx

# 3. Record provenance FIRST (§4), then write and check the SHA256 lockfile.
#    This hashes the .onnx AND its .labels.json together.
Python scripts/verify_models.py --write
Python scripts/verify_models.py            # must now pass
```

The downloader checks the declared Hugging Face license before fetching,
pins the download to the same immutable model revision, and fetches only the
configuration and safetensors required by the selected loader. It validates
the checkpoint's class labels before export. For Marqo, the exporter reorders
the upstream `[NSFW, SFW]` logits to the engine contract `[SFW, NSFW]`.
The sidecar emitted with the graph records that output order, input size, and
the model's normalization. The model card reports a proprietary training
dataset; an Apache-2.0 repository declaration does not independently establish
training-data provenance or satisfy organization-specific review requirements.

The exporter verifies its own output before returning: it reloads the `.onnx`,
asserts a single logits output whose width matches the 2-class contract, and
runs one zero-input smoke inference with ONNX Runtime. Export now fails if that
runtime verification is unavailable. At request time, failed inference is
marked as a fallback and cannot produce an allow/block decision.

The checkpoint is the only part you must source yourself: **torchvision's
ImageNet weights are not an NSFW detector**, so `--checkpoint` must point at a
fine-tuned state_dict for the 2-class head (§40 - this project consumes
pretrained models, it does not train them).

Step 3 is not optional. Without the lockfile, `verify_models.py` treats every
`.onnx` on disk as an unvetted side-load, and the anti-tampering gate (§38) has
nothing to check against.
