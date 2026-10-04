# models_onnx/

Compiled / optimized ONNX artifacts consumed by `app.core.onnx_runtime`.

> The binary `.onnx` files are **not** committed to the repository (they are
> large, license-bound artifacts). This directory documents the expected
> contract and how to produce them. When a model file is absent the engine
> transparently falls back to a deterministic heuristic so the cascade,
> thresholds and transports remain fully exercisable.

## Expected artifacts

| File | Stage | Target latency | Notes |
|------|-------|----------------|-------|
| `fast_path_mobilenetv3.onnx` | Fast-Path (Model A) | < 10 ms | MobileNetV3-Small, 2-class head, INT8/FP16 |
| `deep_path_efficientnet.onnx` | Deep-Path (Model B) | 20–40 ms | EfficientNet-B0/B1, 2-class head |
| `multimodal_clip.onnx` | Multimodal (Model C) | 50–90 ms | CLIP visual+text encoder, fused head |
| `text_distilbert.onnx` | Text-Path | < 15 ms | DistilBERT classifier; text input, not an image tensor |

### External adapters (§41) — `default_model_path` in `adapters/vision.py`

| File | Stage | §22 status | Notes |
|------|-------|-------------|-------|
| `vit_nsfw.onnx` | `premium_vit` | `candidate` | **Apache-2.0 code and weights — the one to ship first** |
| `nsfwjs_mobilenetv2.onnx` | `fast_path` | `candidate` | MIT code; weight provenance unclear |
| `clip_zeroshot.onnx` | `multimodal` | `candidate` | MIT code and weights |
| `opennsfw2_resnet50.onnx` | `deep_path` | **`blocked`** | ⚠️ Do not add — weight terms are `LEGAL_REVIEW_REQUIRED` (§4) |
| *(none)* | `rejected` / `nudita` | **`blocked`** | 🚫 Must never be loaded — AGPL-3.0 |

> **Start with `vit_nsfw.onnx`.** It is the only candidate whose licence is clear
> on both code and weights, so it needs no legal review — only the benchmark
> that has not been run yet. Adding a `blocked` artifact is not merely
> discouraged: `adapters/base.py` refuses to load one, so it would sit on disk
> inert and fail `verify_models.py` as an unvetted side-load.

## Input / output contract

* **Input**  – `float32` tensor `NCHW`, ImageNet-normalized.
  * Fast-Path resize: `224x224`
  * Deep-Path resize: `384x384`
  * Multimodal resize: `224x224`
  * Dynamic batch axis (`N`) is expected.
  * Text-Path differs: `input_ids` + `attention_mask`, not an image tensor.
* **Output** – logits. The engine collapses outputs to a probability as follows:
  * 1 value  → sigmoid(logit)
  * 2 values → softmax/sigmoid, channel index `1` is NSFW
  * N values → mean of channels `1..`

> ⚠️ The same output tensor interpreted differently per model silently destroys
> accuracy. NSFWJS exports a 6-class head, so its normalisation is *not* the
> generic rule above — it is implemented explicitly in
> `adapters/vision.py::NSFWJSAdapter.normalise` and must be matched whenever an
> artifact is re-exported.

## Producing the artifacts

```bash
# 1. Export from PyTorch (register a builder in scripts/convert_to_onnx.py)
python scripts/convert_to_onnx.py --model fast_path \
    --checkpoint checkpoints/mobilenetv3.pt \
    --output models_onnx/fast_path_mobilenetv3.onnx --opset 17 --fp16

# 2. Quantize the fast path to INT8
python scripts/quantize_models.py --model models_onnx/fast_path_mobilenetv3.onnx

# 3. Record provenance FIRST (§4), then write and check the SHA256 lockfile
python scripts/verify_models.py --write
python scripts/verify_models.py            # must now pass
```

Step 3 is not optional. Without the lockfile, `verify_models.py` treats every
`.onnx` on disk as an unvetted side-load, and the anti-tampering gate (§38) has
nothing to check against.
