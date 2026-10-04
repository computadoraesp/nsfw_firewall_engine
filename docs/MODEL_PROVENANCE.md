# Model Provenance

Required by `pront.md` §4 and §46. Every model artifact consumed by the engine
must be registered here **before** deployment.

## §22 lifecycle status

Every registered model carries one of five lifecycle states. The state is
**enforced**, not decorative: `candidate -> production` is refused, and a
`blocked` model cannot be restored. The transition table lives in
`adapters/base.py`.

| Status | Meaning | Serves traffic? |
| --- | --- | --- |
| `candidate` | Registered and runnable, never benchmarked | Yes, but not yet trustworthy |
| `validated` | Benchmarked and within tolerance | Yes |
| `production` | Promoted after measurement | Yes |
| `deprecated` | Superseded; kept loadable so a rollback is possible | **No** |
| `blocked` | Must never run (licence / security / integrity) | **No**, and no path back |

`deprecated` and `blocked` are deliberately different states. A deprecated model
can be restored; a blocked one cannot. That distinction is what stops someone
"just enabling" Nudita to route around the AGPL boundary in §4.

### Current statuses

| Stage | Model | Licence | Status | Reason |
| --- | --- | --- | --- | --- |
| `fast_path` | nsfwjs | MIT (code) | `candidate` | Weights trained on a third-party corpus; provenance unclear |
| `deep_path` | OpenNSFW2 | Apache-2.0 code, weights `LEGAL_REVIEW_REQUIRED` | `blocked` | Weight terms unclear for commercial redistribution (§4) |
| `multimodal` | CLIP zero-shot | MIT | `candidate` | Unbenchmarked |
| `text` | text_distilbert | Apache-2.0 (candidate) | `candidate` | No weights present |
| `premium_vit` | HF ViT NSFW | **Apache-2.0 (code + weights)** | `candidate` | Clean licence; held only by the benchmark that has not been run |
| `rejected` | Nudita | AGPL-3.0 | `blocked` | Copyleft would infect this engine (§4) |

`premium_vit` is the only entry with a clean licence on **both** code and
weights, which makes it the one worth downloading and benchmarking first.

### Changing a status

```bash
# Requires an API key with policy_admin or security_operator.
curl -X POST localhost:8080/v1/models/premium_vit/status \
  -H "X-API-Key: $KEY" \
  -d '{"status":"validated","reason":"benchmarked on eval-2026-10: FPR 0.004"}'
```

Promotion is a two-hop walk (`candidate -> validated -> production`) on purpose.
The two hops record the evidence separately, so a model cannot reach production
without somebody having written down why.

`GET /v1/models` reports `status` and `may_serve` for every entry — including the
blocked ones — so an operator can see *why* a model is not scoring anything
instead of finding it silently absent.

## Current state: no weights are shipped

`models_onnx/` contains **no binary artifacts** — only the expected contract
(see `models_onnx/README.md`). When a model file is absent the engine logs
`load '<name>' as stub` and that evaluator falls back to a **deterministic
skin-tone / keyword heuristic**. This keeps the cascade, thresholds, policy
engine and transports exercisable in CI, but the heuristic is **not** a trained
detector and must never be used for production enforcement.

Operational signals: `GET /v1/ready` → per-check readiness (use this for
Kubernetes probes), `GET /v1/health` → liveness, `GET /health` → the legacy
liveness alias, `GET /metrics` → `nsfw_models_loaded`. Treat `ready: false` as
**not ready** for production traffic.

## Licence-cleared candidates that exist today

The earlier blanket `LEGAL_REVIEW_REQUIRED` was too coarse. It was applied to
*every* candidate because the two most-cited sources (GantMan/nsfw_model,
Yahoo Open NSFW) genuinely are ambiguous — but several alternatives carry an
**explicit, unambiguous permissive licence** covering the weights themselves.
Verified 2026-10-04:

| Model | Architecture | Licence | ONNX? | Verdict |
|-------|--------------|---------|-------|---------|
| [`AdamCodd/vit-base-nsfw-detector`](https://huggingface.co/AdamCodd/vit-base-nsfw-detector) | ViT-base | **Apache-2.0** (stated on the model card) | Yes | **Cleared** — best fit for §10 Premium Path; loads through the existing ONNX session manager with no new dependency |
| [`Falconsai/nsfw_image_detection`](https://huggingface.co/Falconsai/nsfw_image_detection) | ViT | **Apache-2.0** (stated) | export required | **Cleared** — 85M+ downloads, strongest community validation of the set |
| [`Marqo/nsfw-image-detection-384`](https://huggingface.co/Marqo/nsfw-image-detection-384) | ViT/timm, 384px | **Apache-2.0** (stated) | export required | **Cleared** — higher input resolution, useful for the Deep Path |

> The Hugging Face `Not-For-All-Audiences` tag on these repos is a **content
> warning**, not a licence term. It does not restrict redistribution or
> commercial use. Distinguish it from an actual `license:` field, which is what
> this table records.

**So the blocker is resolved, not permanent.** The remaining work is mechanical:
export to ONNX, verify the SHA256, benchmark, and promote. See
`adapters/vision.py::HuggingFaceViTAdapter`, which is wired and ready.


## Registered artifacts

| Key | Expected file | Stage | Role | Weights license | Status |
|-----|---------------|-------|------|-----------------|--------|
| `fast_path_mobilenetv3` | `models_onnx/fast_path_mobilenetv3.onnx` | 1 | MobileNetV3-Small, 2-class head, INT8/FP16 | **LEGAL_REVIEW_REQUIRED** | not shipped |
| `deep_path_efficientnet` | `models_onnx/deep_path_efficientnet.onnx` | 2 | EfficientNet-B0/B1, 2-class head | **LEGAL_REVIEW_REQUIRED** | not shipped |
| `multimodal_clip` | `models_onnx/multimodal_clip.onnx` | 3 | CLIP visual+text encoder, fused head | **LEGAL_REVIEW_REQUIRED** | not shipped |
| `text_distilbert` | `models_onnx/text_distilbert.onnx` | 1b | DistilBERT text classifier | Apache-2.0 (candidate) | not shipped |

## Candidate sources and licensing status

Per §2/§4 these were evaluated. **None are vendored today.** See
[`REUSE_MATRIX.md`](./REUSE_MATRIX.md) for the full REUSE/ADAPT/WRAP/REJECT
decision table.

| Project | Code license | Weights license | Status |
|---------|--------------|-----------------|--------|
| NSFWJS | MIT | MIT (bundled `.onnx`) | Usable via adapter; download at build time |
| OpenNSFW2 | Apache-2.0 | ⚠️ **LEGAL_REVIEW_REQUIRED** — upstream Yahoo/tensorflow `open_nsfw` weight terms are not clearly permissive for commercial redistribution | Preferred Deep-Path candidate *if cleared* |
| Nudita | **AGPL-3.0** | ⚠️ **LEGAL_REVIEW_REQUIRED** | **Rejected** — AGPL is incompatible with a proprietary engine; could only run out-of-process |
| CLIP (OpenAI) | MIT | MIT | Usable for the Multimodal path |
| DistilBERT | Apache-2.0 | Apache-2.0 | Clean fit for the text path |
| MobileNetV3 / EfficientNet | Apache-2.0 | varies by checkpoint | Architectures fine; **weights provenance must be recorded per checkpoint** |

## Rules for adding an artifact

1. Record it here **before** deploying: source URL, exact commit/tag, SHA256 of
   the `.onnx`, license of code *and* weights, and the fine-tuning dataset.
2. Verify the SHA256 in CI; a mismatch must fail the deployment.
3. Bump `engine.version` (or `PREPROCESS_VERSION` in `app/core/cache.py`) when
   the model or preprocessing changes — the decision-cache key embeds both, so
   stale decisions are never served across a model swap (§29/§50).
4. Re-run the benchmark matrix (§25) and update the §45 criteria before
   promoting a model to production. **No claims without benchmarks (§49).**
5. If licensing is uncertain, stop: **LEGAL_REVIEW_REQUIRED**.

## Datasets

This project does not train models (§40: pretrained → adapters only). If you
fine-tune, record dataset name, license, sampling strategy and any
content-tagging consent constraints here.

## Audit hashing

`privacy.log_content_hashes` enables SHA256 (optionally salted with
`privacy.hash_salt`) of inspected payloads for zero-retention audit trails.
Raw payloads are **never** persisted (`privacy.retain_raw_payloads: false`).