# Reuse Matrix (§3)

Mandatory reuse/adapt/wrap/replace/build decisions. Every row states its
justification; see [`MODEL_PROVENANCE.md`](./MODEL_PROVENANCE.md) for licensing
gates and [`adr/`](./adr) for long-form decisions.

Legend — **Action**: `REUSE` (vendor as-is) · `ADAPT` (wrap + modify) ·
`WRAP` (thin adapter, no fork) · `REPLACE` (build in-house) · `BUILD` (new code).

## Inference runtime

| Component | Project | License | Code | Model | Quality | Perf | Maint. | Risk | Action |
|-----------|---------|---------|------|-------|---------|------|-------|------|--------|
| ONNX Runtime | microsoft/onnxruntime | MIT | Yes | n/a | High | High (TensorRT/CUDA/OpenVINO EPs) | Active | Low | **REUSE** |
| PyTorch | pytorch/pytorch | BSD-3 | Export-time only | n/a | High | n/a (build) | Active | Low | **REUSE** (build only) |

*Why:* ONNX Runtime gives one artifact across CPU/GPU/TensorRT behind a single
`InferenceSession` API — exactly the §50 requirement that models evolve without
changing firewall/API/policy. Provider options come from
`config/engine_config.yaml` (`app/core/onnx_runtime.py`).

## Vision classifiers

| Component | Project | License | Code | Model | Quality | Perf | Maint. | Risk | Action |
|-----------|---------|---------|------|-------|---------|------|-------|------|--------|
| NSFWJS | @nsfwjs/nsfwjs | MIT | Yes | MIT | Good | ~20 ms | Moderate | Low | **WRAP** (§2) |
| OpenNSFW2 | LambdaNetworks/OpenNSFW2 | Apache-2.0 | Yes | ⚠️ LEGAL_REVIEW_REQUIRED | High | ~50 ms | Moderate | Med | **ADAPT** (blocked) |
| Nudita | tumtam/nudita | **AGPL-3.0** | **No** | ⚠️ LEGAL_REVIEW_REQUIRED | Medium | ~100 ms | Low | **High** | **REJECT** |
| MobileNetV3 | torchvision | Apache-2.0 | Yes | per-checkpoint | Good | <10 ms INT8 | Active | Low | **ADAPT** (Fast) |
| EfficientNet | torchvision | Apache-2.0 | Yes | per-checkpoint | High | 20–40 ms | Active | Low | **ADAPT** (Deep) |
| CLIP | openai/CLIP | MIT | Yes | MIT | High | 50–90 ms | Active | Low | **WRAP** (Multimodal) |
| HF ViT NSFW | HuggingFace (ViT-base) | **Apache-2.0** | Yes | **Apache-2.0** | High | 20–40 ms | Active | Low | **ADAPT** (`premium_vit`) — the only clean-license candidate |
| Skin-tone heuristic | this repo | — | n/a | n/a | **Not a detector** | ~1 ms | n/a | Med | **REPLACE** when weights land |

*Why:* Nudita is rejected outright — AGPL-3.0 code cannot be incorporated into
this engine; at most it could run out-of-process behind gRPC. The heuristic is a
*development* stub that keeps the cascade, policy and transports testable without
weights; `GET /health` reports unhealthy while any model is missing.

> **`premium_vit` is the row to act on.** It is the only entry with an explicit
> permissive license on **both** code and weights, so it clears §4 without a legal
> review. Every other candidate is held up by either license ambiguity
> (`opennsfw2`), copyleft (`nudita`) or unclear weight provenance
> (`nsfwjs`). Converting it is the single highest-value next step — see
> [`MODEL_PROVENANCE.md`](./MODEL_PROVENANCE.md).

## Text

| Component | Project | License | Code | Model | Quality | Perf | Risk | Action |
|-----------|---------|---------|------|-------|---------|------|------|--------|
| DistilBERT | huggingface/transformers | Apache-2.0 | Yes | Apache-2.0 | High | <15 ms | Low | **WRAP** (Text-Path) |
| Keyword/URL lexicon | this repo | — | n/a | n/a | Low alone; good fusion partner | ~0 ms | Low | **REUSE** (fallback + fusion) |

*Why:* §40 forbids training from scratch; DistilBERT is a permitted pretrained
adapter. The lexicon remains as a deterministic floor so text never depends on a
model being present.

## Transports & services

| Component | Project | License | Quality | Perf | Maint. | Risk | Action |
|-----------|---------|---------|---------|------|-------|------|--------|
| FastAPI / Uvicorn | encode/* | MIT / BSD-3 | High | High | Active | Low | **REUSE** |
| gRPC | grpc/grpc | Apache-2.0 | High | Lowest latency | Active | Low | **REUSE** |
| ICAP (RFC 3507) | stdlib `socketserver` | PSF | Good | Good | n/a | Low | **BUILD** (~350 lines) |
| Squid | squid-cache/squid | GPL-2.0 | High | High | Active | Low | **WRAP** (ICAP target) |
| Prometheus client | prometheus/client_Python | Apache-2.0 | High | Negligible | Active | Low | **REUSE** + built-in fallback |
| Grafana | grafana/grafana | AGPL-3.0 | High | n/a | Active | Med | **WRAP** (container only) |
| Redis / Kafka | redis / apache/kafka | BSD-3 / Apache-2.0 | High | High | Active | Low | **WRAP** (interface only) |
| Kubernetes | kubernetes | Apache-2.0 | High | n/a | Active | Low | **REUSE** |

*Why:* the ICAP server is implemented directly because only REQMOD/RESPMOD with
`Content-Length` bodies is needed — a full ICAP library would be larger than the
subset and add a dependency for no benefit. Prometheus is used when installed
and otherwise replaced by an in-process exposition with identical metric names,
so scraping never fails (§31).

## Security & content inspection

| Component | Project | License | Quality | Risk | Action |
|-----------|---------|---------|---------|------|--------|
| Pillow | Python-pillow | MIT-CMU | High | Med (decoder CVEs) | **WRAP** (optional + size caps) |
| OpenCV | opencv/opencv | Apache-2.0 | High | Med (decoder CVEs) | **WRAP** (optional) |
| libmagic | file/file | BSD-2-Clause | High | Low | **WRAP** (optional) |
| MIME allow-list + SHA256 audit | this repo | — | Good | Low | **BUILD** (§16/§18) |
| Policy rule engine | this repo | — | Good | Low | **BUILD** (§19) |

*Why:* decoders are the largest attack surface (§17/§38), so they are optional,
size- and dimension-capped, and always backed by a non-fatal fallback path.

## Explicitly NOT reused

- **Nudita** — AGPL-3.0 incompatibility (above).
- **Proprietary NGFW/SWG** — §1 requires the core stay vendor-independent.
- **Any model trained from scratch** — forbidden by §40.