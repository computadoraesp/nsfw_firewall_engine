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
| `premium_vit` | HF ViT NSFW | **Apache-2.0 (code + weights)** | `candidate` | Latency measured locally; accuracy awaits a labelled evaluation |
| `rejected` | Nudita | AGPL-3.0 | `blocked` | Copyleft would infect this engine (§4) |

`premium_vit` is the current download/export candidate: Hugging Face declares
Apache-2.0 for the repository and weights. Its model card says training used a
proprietary dataset, so the repository licence check is not a substitute for
reviewing training-data provenance against the deployment's legal requirements.
The downloader records the exact checked revision, validates the checkpoint
class order, and writes the ONNX label/preprocessing sidecar; it does not
promote the model or certify its accuracy.

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

## Current state: local candidate, connected to Deep-Path

Model binaries are gitignored and are not shipped with a clean checkout. This
workspace has fetched and exported Marqo locally; its ONNX graph and label
sidecar are pinned in `models_onnx/models.lock.json` and configured for the
Deep-Path. It has passed a PyTorch/ONNX parity check but has not been
accuracy-validated. Fast-Path and Multimodal artifacts are absent, so those
stages are skipped; absent or failed models no longer produce a skin-tone
heuristic score.

| Stage | Configured artifact | Runtime status |
|---|---|---|
| Fast | `fast_path_mobilenetv3.onnx` | Missing; skipped |
| Deep | `vit_nsfw.onnx` (Marqo, 384px) | Active candidate; parity passed, accuracy pending |
| Multimodal | `multimodal_clip.onnx` | Missing; skipped |
| Premium | `vit_nsfw.onnx` | Disabled to avoid running the same Marqo graph twice |

The local Viddexa `fast_efficientnet.onnx` and `deep_efficientnet.onnx` files
remain hash-verified research artifacts, not runtime models. Re-exporting them
reproduced the local graphs, but their ONNX outputs were nearly invariant to
the input and materially disagreed with PyTorch. They are quarantined until
that discrepancy is resolved. Model-specific normalization in a valid sidecar
is now applied by the evaluator; this does not fix those graphs.

If no valid model contributes, the image verdict is `REVIEW`, not a heuristic
allow/block. The current model's thresholds are still provisional and must be
validated against an authorized labelled corpus before production promotion.

### Fetched artifact record

| Property | Value |
|----------|-------|
| Source | [`Marqo/nsfw-image-detection-384`](https://huggingface.co/Marqo/nsfw-image-detection-384) |
| Immutable revision | `0c26ec22111b83f106d72a55f611ec35962bcb65` |
| Weights licence declared by source | Apache-2.0 |
| Training-data caveat | The model card reports a proprietary training dataset; assess its provenance for the intended deployment |
| ONNX artifact | `models_onnx/vit_nsfw.onnx`, 22,453,985 bytes |
| ONNX SHA-256 | `220b87eaa0289d89b77241d4b3dfb295b8dcbc3a2e931af9580bfa2004a955d8` |
| Output labels | `["SFW", "NSFW"]`; NSFW is index 1 |
| Input / normalization | Batch 1 at 384×384; mean and standard deviation `[0.5, 0.5, 0.5]` |
| Runtime smoke test | Passed on ONNX Runtime CPU provider; one output with 2 finite logits |
| Source parity check | ONNX logits match the pinned PyTorch model on synthetic inputs (max absolute error `8.35e-7`) |
| Local latency sample | 5 warmups, 50 synthetic 384×384 inputs; CPU mean 56.798 ms, p50 55.287 ms, p95 64.739 ms, p99 68.472 ms |
| Accuracy evaluation | Not performed; no labelled evaluation dataset was available |

The latency figures include adapter preprocessing and ONNX inference on this
machine; synthetic inputs do not establish accuracy or production suitability.
The model remains `candidate`, and `thresholds.premium.enabled` remains `false`.

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

A **label sidecar** (`<artifact>.labels.json`) is required alongside every
multi-class graph: an ONNX file does not carry its class names, and two
checkpoints can emit an identical tensor while disagreeing about what index 0
means. The sidecar pins the class order (and the trained input resolution) and
is hashed by `scripts/verify_models.py` together with the graph, so editing
the class order is as detectable as editing the weights (§38). An adapter
without a usable sidecar **refuses to score** rather than guess (§49).

| Key | Expected file | Stage | Role | Weights license | Status |
|-----|---------------|-------|------|-----------------|--------|
| `fast_path_mobilenetv3` | `models_onnx/fast_path_mobilenetv3.onnx` | 1 | MobileNetV3-Small, 2-class head (not deployed) | **LEGAL_REVIEW_REQUIRED** | not shipped |
| `fast_efficientnet` | `models_onnx/fast_efficientnet.onnx` | research only | EfficientNet 4M params, 224px, 5-class | Apache-2.0 | quarantined: export parity failed |
| `deep_efficientnet` | `models_onnx/deep_efficientnet.onnx` | research only | EfficientNet 17.7M params, 380px, 5-class | Apache-2.0 | quarantined: export parity failed |
| `marqo_nsfw_vit` | `models_onnx/vit_nsfw.onnx` | 2 | ViT/timm, 384px, 2-class head | Apache-2.0 | active candidate; accuracy pending |
| `multimodal_clip` | `models_onnx/multimodal_clip.onnx` | 3 | CLIP visual+text encoder, fused head | **LEGAL_REVIEW_REQUIRED** | not shipped |
| `text_distilbert` | `models_onnx/text_distilbert.onnx` | 1b | DistilBERT text classifier | Apache-2.0 (candidate) | not shipped |
| `premium_vit` | `models_onnx/vit_nsfw.onnx` | premium | ViT/timm `vit_tiny_patch16_384`, 384px | **Apache-2.0** | fetched locally |

### Label sidecars

The active Marqo binary head is interpreted using the labels and normalization
in its sidecar. The Viddexa five-class sidecars describe quarantined artifacts;
their thresholds and previously measured synthetic scores must not be used to
claim operating performance for the active model. Threshold calibration still
requires an authorized, labelled corpus.

| Artifact sidecar | Labels (index order) | Input | Written by |
|---|---|---|---|
| `vit_nsfw.labels.json` | `["SFW", "NSFW"]` | 384×384 | `scripts/fetch_pretrained.py --model premium_vit` |
| `vit_nsfw_224.labels.json` | `["normal", "nsfw"]` | 224×224 | `scripts/fetch_pretrained.py --model premium_vit_224` |
| `fast_efficientnet.labels.json` | `["safe", "hentai", "porn", "sexy", "drawing"]` | 224×224 | `scripts/fetch_pretrained.py --model fast_efficientnet` |

> **Multi-class heads are softmax-normalised, then summed.** This handling
> remains for the quarantined five-class Viddexa artifacts. The active Marqo
> graph is binary, and its sidecar explicitly identifies the NSFW class.

> ⚠️ The NSFWJS export ships a **6-class** head (`porn, hentai, sexy, neutral,
> drawing, other`), so it must **not** be given a 2-class sidecar: the indices
> would not correspond. It is normalised explicitly in
> `adapters/vision.py::NSFWJSAdapter.normalise` instead.

`verify_models.py --write` prints how many graphs and sidecars it pinned, and
flags any sidecar whose graph is absent.

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