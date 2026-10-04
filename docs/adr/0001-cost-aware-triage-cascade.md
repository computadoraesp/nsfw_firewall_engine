# ADR-0001 — Cost-aware triage cascade (Fast → Deep → Multimodal)

* **Status:** Accepted
* **Date:** 2024
* **Spec:** `pront.md` §5–§13, §44 (MVP)

## Context

Classifying every request with a premium Vision-Transformer costs 50–90 ms and
far more CPU/GPU than a firewall line rate can absorb. Most traffic is
unambiguously safe or obviously explicit.

## Decision

Run a **cascade**, deciding at the cheapest sufficient tier:

1. **Fast-Path** (MobileNetV3, INT8/FP16) — every request.
2. **Deep-Path** (EfficientNet) — only when the Fast score falls inside the
   inconclusive band `[hard_sfw, hard_nsfw]`.
3. **Multimodal** (CLIP + text fusion) — the final arbiter, reached only by
   genuinely ambiguous content.

Thresholds are per-stage and configurable (`config/engine_config.yaml` →
`thresholds.*`), so the cascade can be re-tuned without touching code.

## Alternatives

| Option | Why not |
|--------|---------|
| Single premium model | 10–20× the cost/latency; poor fit for line-rate firewall use |
| Single fast model | Recall collapses on hard negatives (art, swimwear, medical) |
| Binary cascade (fast + deep) | Loses the text/multimodal signal required by §7/§11 |
| Always run everything | Simplest code, worst cost profile |

## Consequences

* **Positive:** predictable p95 latency; the bulk of traffic costs one small model.
* **Negative:** a wrong Fast-Path decision outside its band is *not* corrected
  (by design — the band exists so confident decisions stand).
* **Trade-off:** threshold tuning becomes a first-class operational task;
  `GET /config` and the per-request `overrides` exist to support it.

## Security / license impact

No new dependencies; reuses ONNX Runtime (MIT). Model weights remain subject to
[`MODEL_PROVENANCE.md`](../MODEL_PROVENANCE.md).