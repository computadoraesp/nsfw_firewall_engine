# Model Registry (§46)

Runtime view of every model the engine can load. Mirrors `GET /health` →
`models_loaded` / `text_model_loaded`, and the richer `GET /v1/models` → `status`
and `may_serve` (§22), so this table and the running service cannot silently
disagree.

**Status legend**

*Built-in cascade stages* — `⚠️ stub` = no weights mounted, the evaluator uses the
documented heuristic · `✅ loaded` = artifact present and inference ready.

*External adapters* (§22 lifecycle) — `candidate` = registered and runnable but
never benchmarked · `validated` / `production` = promoted after measurement ·
`deprecated` = superseded, still loadable for rollback but **not serving** ·
`blocked` = must never run (license / security / integrity), **no path back**.

## Built-in model paths

| Key | Config path | Stage | Architecture | Input | Status | License |
|-----|-------------|-------|--------------|-------|--------|---------|
| `fast_path_mobilenetv3` | `paths.fast_path_model` | 1 | MobileNetV3-Small | `1x3x224x224` | ⚠️ stub | weights LEGAL_REVIEW_REQUIRED |
| `deep_path_efficientnet` | `paths.deep_path_model` | 2 | EfficientNet-B0/B1 | `1x3x384x384` | ⚠️ stub | weights LEGAL_REVIEW_REQUIRED |
| `multimodal_clip` | `paths.multimodal_model` | 3 | CLIP visual+text | `1x3x224x224` | ⚠️ stub | MIT (code) |
| `text_distilbert` | `paths.text_model` | 1b | DistilBERT classifier | `input_ids`, `attention_mask` | ⚠️ stub | Apache-2.0 |

## External adapters (§41)

Registered through the `adapters` package; interchangeable without touching the
engine, API or policy (§50). Lifecycle transitions are enforced by
`adapters/base.py` — `candidate → production` is refused with a `409`, because a
promotion that skips benchmarking is a claim nobody measured (§49).

| Stage | Adapter | Artifact | Upstream | Code license | Weights | §22 status | Serves? |
|-------|---------|----------|----------|--------------|---------|-------------|---------|
| `fast_path` | `nsfwjs` | `nsfwjs_mobilenetv2.onnx` | NSFWJS (MIT) | MIT | MIT | `candidate` | yes |
| `deep_path` | `opennsfw2` | `opennsfw2_resnet50.onnx` | OpenNSFW2 | Apache-2.0 | ⚠️ LEGAL_REVIEW_REQUIRED | **`blocked`** | **no** |
| `multimodal` | `clip_zeroshot` | `clip_zeroshot.onnx` | CLIP (MIT) | MIT | MIT | `candidate` | yes |
| `premium_vit` | `hf_vit_nsfw` | **`vit_nsfw.onnx`** | HF ViT NSFW | **Apache-2.0** | **Apache-2.0** | `candidate` | yes |
| `rejected` | `nudita` | — | Nudita | **AGPL-3.0** | ⚠️ LEGAL_REVIEW_REQUIRED | **`blocked`** | **no** |

> **Why `blocked` and not merely unused.** `opennsfw2` is blocked pending a license
> review of its weights; `nudita` is blocked because AGPL-3.0 is copyleft and
> loading it in-process would impose those terms on this engine. `blocked` is
> terminal — there is no legal transition back — which is precisely what stops
> someone "just enabling" Nudita to route around the AGPL boundary (§4).

> **`premium_vit` is the one to ship first.** It is the only entry with a clear
> license on **both** code and weights, so nothing is blocking it except the
> benchmark that has not been run yet. It is `candidate` — not `production` —
> purely because it is unmeasured.

## Registering an artifact

1. Add the file under `models_onnx/` (mounted read-only in Compose/Helm).
2. Record source, commit, SHA256 and licenses in
   [`MODEL_PROVENANCE.md`](./MODEL_PROVENANCE.md) **before** deploying.
3. Bump `engine.version` (or `PREPROCESS_VERSION`) so cached decisions from the
   previous model are invalidated (ADR-0004).
4. Regenerate benchmarks and re-check the §45 criteria.
5. Restart; `GET /health` should show `loaded_models_count` increasing, and
   `GET /v1/ready` should turn `true`.
6. Only once a labeled benchmark exists, walk the lifecycle:
   `candidate → validated → production` via
   `POST /v1/models/{stage}/status` (requires `MANAGE_POLICY`).

## Registering an artifact

1. Add the file under `models_onnx/` (mounted read-only in Compose/Helm).
2. Record source, commit, SHA256 and licenses in
   [`MODEL_PROVENANCE.md`](./MODEL_PROVENANCE.md) **before** deploying.
3. Bump `engine.version` (or `PREPROCESS_VERSION`) so cached decisions from the
   previous model are invalidated (ADR-0004).
4. Regenerate benchmarks and re-check the §45 criteria.
5. Restart; `GET /health` should show `loaded_models_count` increasing and
   `healthy: true`.

## Output contract

All evaluators collapse raw outputs to an NSFW probability in `[0, 1]`
(`app/core/onnx_runtime.to_probability`):

| Output shape | Interpretation |
|--------------|----------------|
| 1 value | `sigmoid(logit)` |
| 2 values | class index `1` is NSFW |
| N values | mean of channels `1..` after sigmoid |

> ⚠️ The same output tensor interpreted differently per model silently destroys
> accuracy. If you export a multi-class head (e.g. NSFWJS' 6 classes), wrap it
> in the matching `adapters/` class so the normalisation is explicit.