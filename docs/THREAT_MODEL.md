# Threat Model (§17 / §38)

Scope: the engine and its three transports (gRPC, ICAP, REST), the policy layer,
the content inspector and the model/cache paths. Threats are rated
**Likelihood × Impact** (H/M/L).

| # | Threat | L | I | Mitigation | Status |
|---|--------|---|---|------------|--------|
| 1 | **Malicious media** (decoder RCE via crafted JPEG/PNG) | M | H | Pillow/OpenCV are **optional and capped**; `max_image_bytes`, `max_image_dim`, `max_pixels` enforced *before* decoding; content inspector validates magic bytes and dimensions; a decoder crash degrades to the heuristic rather than propagating | Mitigated |
| 2 | **Decompression / resource-exhaustion bomb** | H | H | `preprocessing.max_pixels` (64 MP) + `Image.MAX_IMAGE_PIXELS`; ICAP `max_body_bytes` (32 MiB); gRPC message caps (16 MiB); video `max_frames` + early exit | Mitigated |
| 3 | **SSRF** | M | H | The engine **never fetches URLs** — it inspects supplied bytes only. URLs are parsed as *text signals*, never dereferenced | Mitigated by design |
| 4 | **MIME spoofing** (header says image, bytes are something else) | H | M | Magic-byte detection is authoritative, not `Content-Type`; allow-list check with `enforce_mime` on the enforcement path | Mitigated |
| 5 | **Cache poisoning / staleness** | M | H | Cache key binds `model_version` + `preprocess_version`; TTL/LRU; overrides bypass the cache (ADR-0004) | Mitigated |
| 6 | **Policy bypass** | M | H | Policy is a separate, declarative, first-match-wins rule layer outside inference; fail action is explicit (`policy.fail_action`); tenant overrides cannot widen the global default | Mitigated |
| 7 | **Tenant escape / cross-tenant leakage** | L | H | Tenant policy resolution is tenant-scoped; audit records carry `tenant_id`; payloads are never persisted. API keys can be pinned to a tenant and `require_tenant_header` forces `X-Tenant-Id` on every data request | Mitigated |
| 8 | **Malicious / tampered model artifact** | M | H | Models are mounted read-only (Compose/Helm); `scripts/verify_models.py` enforces a committed SHA256 lockfile and **fails** on a mismatch, a missing artifact, or any unvetted `.onnx` on disk | Mitigated — run the script as a CI gate / container pre-flight |
| 9 | **Model poisoning via training data** | L | H | §40 forbids training in this project; fine-tuning is out of scope and would require dataset provenance | N/A here |
| 10 | **Credential / secret leakage in logs** | M | H | Structured JSON logging logs **metadata and decisions only**; `privacy.retain_raw_payloads: false`; hashes may be salted | Mitigated |
| 11 | **Supply-chain (dependency compromise)** | M | H | Pinned versions; `THIRD_PARTY_NOTICES.md`; optional deps isolated behind import checks; images run as non-root UID 10001 with read-only root FS in Helm | Mitigated |
| 12 | **API abuse / DoS** (gRPC, ICAP, REST) | M | M | Message/body caps, socket timeouts (ICAP 30 s), threaded server, `request_timeout_ms` budget, HPA + probes | Mitigated |
| 13 | **TLS-inspection abuse** | L | H | The engine does **not** perform interception; it is an ICAP/REST *target*. Certificates and interception policy stay with the proxy | Out of scope |
| 14 | **Heuristic mistaken for a detector** | M | **H** | Documented stub; `healthy: false` and `/v1/ready` → `false` while any model is stubbed; liveness (`/v1/health`) is deliberately kept **separate** from readiness so a pod is withdrawn from the Service rather than killed | Mitigated (relies on operator discipline) |
| 15 | **Spoofed §19 context headers** | M | M | `X-User-Groups` / `X-Zone` / `X-Device-Id` are client-assertable. The authenticated principal always outranks headers, and **authorisation never reads them** — permissions come from the API key. Documented as advisory; safe only for rules that tighten enforcement | Accepted, documented |
| 16 | **Undecidable request silently allowed** | M | **H** | §33 dead-letter queue: any result carrying an `error` is captured with its SHA256 (never the payload), so the request is recoverable instead of vanishing. Policy still resolves it via `fail_action` | Mitigated |
| 17 | **Unbenchmarked model promoted to production** | L | **H** | §22 enforces an illegal-transition table: `candidate → production` returns `409`, and `blocked` is terminal. Promotion is a two-hop walk that records its own evidence (§49) | Mitigated |

## Residual risks / accepted risks

1. **`security.enabled` ships as `false`** so the service boots without secrets.
   The engine logs a warning on every start and reports it on `/health`. This is
   a *deployment* responsibility: set `enabled: true` and provision hashed API
   keys before any exposure. Authentication and RBAC are implemented
   (`app/core/security.py`) and verified end-to-end, but a default-off switch is
   the one thing code alone cannot enforce.
   → **Mitigated in the pipeline:** `scripts/production_gate.py` now refuses to
   certify a deployment that leaves this off. It still cannot *change* the
   default, so the gate must actually be run.
2. **Model artifact integrity** is automated *and* wired into CI
   (`scripts/verify_models.py` runs in the `contract gates` job, failing on a
   mismatch, a missing artifact, or an unvetted `.onnx`).
3. **`policy.fail_action: ALLOW`** is fail-open: a total inference outage lets
   traffic through. Intentional default (availability), but regulated deployments
   should set it to `BLOCK`.
   → **Mitigated in the pipeline:** the production gate flags `fail_open` as a
   `BLOCKER`, so it cannot be promoted silently.
4. **Content-inspection completeness** depends on which optional decoders are
   installed; without Pillow/OpenCV, dimension checks rely on the PPM/Preprocessor
   path.
5. **No TLS/mTLS termination** — transport security remains the reverse proxy's
   job; terminate TLS *and* ideally mTLS in front of this service.
6. **Latency budgets are detect-and-fail-safe, not hard preemption.** Python
   cannot interrupt an in-flight native decode/inference call, so a pathological
   payload can exceed its budget before it is noticed. The *decision* is always
   bounded and fails into `policy.fail_action`; a hard ceiling belongs in front
   of the service (ICAP socket timeout, container CPU limits — both present).
7. **No labelled evaluation corpus** exists yet, so §49 quality claims (FPR/FNR,
   PR-AUC, ECE) cannot be produced, and every model is stuck at `candidate`. This
   is a data gap, not a code gap — see
   [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).

## Verification

Security-relevant behaviours are covered by the automated suite (438 tests):

| Suite | Covers |
|-------|--------|
| `tests/test_security.py` | Role/permission matrix, constant-time API-key resolution, fail-closed on an invalid role spec, probes-stay-public, tenant binding, audit bounding, secret-leak checks |
| `tests/test_policy_pipeline.py` | Policy fail-actions, tenant isolation, cache keying, MIME advisory-vs-enforced, oversize rejection, HTML escaping |
| `tests/test_resilience.py` | Rate limiting, circuit breaker, bounded retries, idempotency, **dead-letter queue**, **model lifecycle transitions**, **§19 context dimensions** |
| `tests/test_grpc.py` | gRPC and ICAP parsing, chunked-encoding rejection, body size caps, allow/block round trip |
| `tests/test_queue_and_openapi.py` | `/v1` contract, batch per-item isolation, RBAC on tenant-scoped reads |
| `tests/test_config_integrity.py` | Dead and contradictory configuration keys |

CI additionally runs `scripts/fuzz.py` (§37) over the ICAP, MIME and HTML parsers,
and `bandit` for common vulnerability classes.