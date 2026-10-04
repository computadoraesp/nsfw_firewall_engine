# Implementation Plan (§43 / §46)

Phased plan derived from `pront.md` §43. **Status** reflects the code that
actually exists in this repository today — verified by the test suite, not
asserted.

## What is still missing, and why

Everything in this repository that can be implemented **without external
artifacts** is implemented and tested. What remains is blocked on inputs that
cannot be conjured by code:

| Outstanding | Blocked on |
| --- | --- |
| Real model weights in `models_onnx/` | A published, licence-cleared checkpoint must be downloaded and converted. `/v1/ready` stays `false` and `scripts/production_gate.py` fails with `no_model_weights` until then. |
| §49 benchmark evidence (FPR/FNR/PR-AUC/ECE) | Requires a labelled evaluation corpus. No dataset exists in this repo, and one cannot be synthesised and then used to certify quality. |
| Calibration fitting and stacking optimisation | Both need the weights *and* the labelled data. The machinery is built and tested; there is simply nothing to fit against. |
| `premium_vit` promotion `candidate → validated` | Blocked behind the two rows above. The lifecycle machinery will refuse the jump until the measurement exists. |

Two environment issues are **not** code gaps and were left alone:

* `fastapi.testclient.TestClient` is broken in this environment — the installed
  `starlette` and `httpx` are incompatible (`httpx.BaseTransport` missing).
  Tests therefore call the endpoint functions directly or use
  `httpx.ASGITransport`.
* `docker build`, `helm lint` and a live container start have never been run;
  no Docker daemon or Helm binary is available here. The manifests and charts
  are syntactically valid and lint-clean by inspection only.

## Dead-letter queue (§33)

`DeadLetterQueue` in `app/core/resilience.py`, enabled by default.

A firewall that fails to decide a request must **fail closed** (so undecided
traffic is not silently allowed) and **not lose it** (so the client can retry
once the dependency recovers). The DLQ is where the second obligation lives.

Two decisions worth knowing:

* **Payloads are never stored.** A letter carries the SHA256 digest and nothing
  else. Retaining content that failed to classify would make the failure path a
  store full of precisely the material the firewall exists to filter.
* **Bounded by TTL *and* count**, like `IdempotencyStore`. An unbounded queue is
  a memory-exhaustion target, and a dropped letter beats an OOM kill.

`GET /v1/dead-letters` requires `READ_AUDIT` (not `CLASSIFY`) and defaults to
`drain=false`, because the removal is irreversible. Every classification that
returns `result.error` publishes a letter — that is exactly the request whose
policy outcome is `fail_action`, i.e. the one that passed through uninspected.

`call_with_retries()` provides the bounded-retry half of §33. Linear backoff is
deliberate: at 2–3 attempts and millisecond delays exponential buys no
congestion relief while making the worst-case latency — what a firewall is
measured on — noticeably worse.

## Production gate (§43 / §46)

`python scripts/production_gate.py --strict`

The defaults are development-safe on purpose (`security.enabled: false`,
`policy.fail_action: ALLOW`) so the service boots without secrets. The danger
is that nothing marks that as *not production*. A deployment carrying the
defaults looks perfectly healthy: probes pass, and the only symptom is that
every request is unauthenticated and every internal error fails **open**.

The gate refuses to certify a configuration that would do that. It has no
warnings tier — a firewall that is merely *probably* safe is not safe. It
reuses `verify_models.scan_artifacts()` so there is exactly one definition of
"a weight file exists".

CI runs it without `--strict`, asserting only that it still *detects*
`security_disabled` and `fail_open`. If the step ever reports PASS, the gate
has stopped working and the check is worthless.

## Policy dimensions (§19)

`app/core/request_context.py` builds the caller-side dimensions the rule engine
evaluates against: `tenant_id`, `user_id`, `groups`, `device_id`, `zone`,
`url`, `domain`, `category` and a derived `time` facet. They arrive from the
authenticated principal first and the `X-*` request headers second, so a client
cannot assert its own identity.

```yaml
# A kiosk in the EU blocks everything; contractors are flagged for review;
# anything at night gets a second look.
rules:
  - {field: zone,   operator: '==',      value: kiosk, action: block}
  - {field: groups, operator: contains,  value: contractor, action: review}
  - {field: time.night, operator: '==',  value: true, action: review}
  - {field: verdict, operator: '==',     value: NSFW, action: block}
```

`time` is exposed as derived numbers and booleans (`hour`, `weekday`,
`is_weekend`, `business_hours`, `night`) rather than as a bespoke operator, so
policies stay declarative data and remain reviewable in Git.

> **Security note.** Header-supplied dimensions (`X-User-Groups`, `X-Zone`,
> `X-Device-Id`) are *advisory and spoofable*. They are safe for rules that only
> ever tighten enforcement, and unsafe for rules that relax it based on an
> asserted group. Authorisation itself never reads them — permissions come from
> the API key.

## Phase 1 — Research ✅
- Open-source survey, license analysis and the reuse matrix
  → [`REUSE_MATRIX.md`](./REUSE_MATRIX.md)
- Third-party notices + weights provenance
  → [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md),
    [`MODEL_PROVENANCE.md`](./MODEL_PROVENANCE.md)
- ADRs for the load-bearing decisions → [`adr/`](./adr)

## Phase 2 — Core ✅
- Typed configuration (`app/core/config.py`) validated with pydantic
- ONNX session manager with provider negotiation + provider options
- Decode/resize/normalize preprocessing with security caps
- Structured JSON logging
- **Cost-aware cascade** Fast → Deep → Multimodal (ADR-0001)

## Phase 3 — Image ✅
- Three-stage evaluators with deterministic, *documented* fallbacks
- External-model adapter contract (§41) → `adapters/`
- Content inspector: magic bytes, MIME allow-list, bomb/size caps, SHA256 audit

## Phase 4 — Video ✅ (decode left to an optional dependency)
- Frame sampling: `uniform` **and** `scene_change` (§14). Scene-change picks frames
  where the picture changes most, merged with a regular baseline sample so static
  footage is still inspected — uniform sampling is timestamp-based and can step
  straight over a short explicit insert.
- Temporal aggregation: `max` (default) / `mean` / `percentile` / `weighted` (§14).
  `max` is the firewall default: averaging dilutes a 5-second insert across 120
  safe frames into a clean bill of health.
- `max_frames` cap, early exit on the first frame past `early_exit_score`.

## Phase 5 — Text ✅
- Keyword/URL/HTML signal analyzer
- DistilBERT ONNX adapter with graceful fallback
- Configurable multimodal fusion (`weighted` / `max` / `noisy_or`) → `app/core/fusion.py`
- **Full §12 HTML context**: URL, domain (+ path slug), `<title>`, `<meta>`
  (name/property/http-equiv, including OpenGraph), `<img alt>`, RTA/`Preroll`
  self-rating, and visible copy → `app/services/html_context.py`. Parsed with
  the stdlib `html.parser` (no new dependency) and hard-bounded against hostile
  markup. Context is **advisory**: the strongest context-only case scores 0.15,
  far below any threshold, so it can never be sole evidence. Wired into
  `classify(..., url=, domain=)` and surfaced on `/v1/inspect` as `context`.

## Phase 6 — Multimodal ✅
- CLIP adapter, text/visual fusion, REVIEW floor on strong text signals

## Phase 7 — Policy & enforcement ✅
- Declarative rule engine with tenant registry (ADR-0002)
- Enforcement adapters: HTTP, ICAP, NGINX
- `/enforce` endpoint for inline firewalls/SWGs

## Phase 8 — Enterprise hardening ✅ (partial — see residual risks)
- Authentication + RBAC + audit (`app/core/security.py`)
- **Rate limiting** (§17): per-`(tenant, principal)` token bucket, bounded bucket
  table, explicit `429` + `Retry-After`. Never a silent fail-open.
- **Circuit breaker + bounded retries** (§33): three-state breaker with a bounded
  half-open probe budget → `app/core/resilience.py`
- **Idempotency** (§33): TTL- and count-bounded store keyed by
  `(tenant, request_id)`; a retry replays the original decision and is marked
  `idempotent_replay`. Errors are never remembered.
- Content-addressed decision cache (ADR-0004)
- Prometheus metrics + Grafana dashboard, covering the full §31 name list
  (`requests_total`, `enforcement_total`, `queue_depth`, `pipeline_latency`,
  `worker_errors`, `cpu_utilization_ratio`, `memory_usage_bytes`, …). CPU/RSS are
  read from `/proc` with no `psutil` dependency.
- Docker Compose, Helm chart — readiness uses `/v1/ready`, liveness `/v1/health`
- Threat model → [`THREAT_MODEL.md`](./THREAT_MODEL.md)
- OpenAPI contract artifact + `--check` CI gate
- **CI pipeline** (`.github/workflows/ci.yml`): tests on 3.11/3.12, the three
  contract gates, and §37 security testing (bandit, pip-audit, gitleaks, CycloneDX
  SBOM, Trivy container scan)

## Phase 9 — Benchmarks & evaluation ✅ (harnesses) / ⛔ (weights, data)
- Latency + throughput harness → `python -m benchmarks`
- Full §24 metric set: accuracy, precision, recall, F1, **FPR, FNR, specificity,
  ROC-AUC, PR-AUC**, confusion matrix and **calibration ECE**
- **Score calibration** (§26): temperature / Platt / isotonic (PAVA), fitted by
  `scripts/calibrate.py` against a labelled validation set, applied in the cascade
  *before* fusion → `app/core/calibration.py`
- **All four §25 output formats**: Markdown (default), `--json`, `--csv`, `--html`
  (self-contained, no remote fetches, carries the §49 heuristic-fallback caveat)
- Generated matrix → [`BENCHMARK_MATRIX.md`](./BENCHMARK_MATRIX.md)

## Phase 10 — Optimization ⏳
Blocked on model artifacts: real quantization (INT8/FP16) for the fast path,
TensorRT engine caching, batching, and per-stage SLO tuning with real weights.
Stacking / meta-classifier fusion (§27) is also still open — the current fusion
strategies are the deterministic ones §13 asks you to start with.

## Security testing (§37)
`python scripts/fuzz.py` drives mutation-based inputs into the three parsers that
consume attacker-controlled bytes before any policy decision: the ICAP request
parser, MIME sniffing, and the §12 HTML extractor. It asserts *safety*
properties — no unexpected exception, bounded time — because a firewall parser
that crashes or hangs is an outage reachable with one packet. Seeded and
deterministic, so a finding reproduces exactly; wired into CI. 3,000 inputs
across the three targets are currently clean.

## API surface
The stable, versioned contract is `app/api/rest/v1.py` (§20):
`POST /v1/inspect`, `POST /v1/classify`, `POST /v1/batch`, `GET /v1/models`,
`GET /v1/policies`, `POST /v1/policies`, `GET /v1/health`, `GET /v1/ready`.
The un-versioned routes are frozen aliases kept for backwards compatibility.

## Not implemented (and why)

| Item | Reason |
|------|--------|
| Real ONNX weights | Not shipped: large + license-bound. `LEGAL_REVIEW_REQUIRED` on OpenNSFW2/Nudita weights (§4) |
| Training / fine-tuning | Forbidden by §40 — pretrained → adapters only |
| TLS interception | Must stay with the proxy; the engine is an ICAP/REST *target* only |
| Redis/Kafka backends | Interface + wrappers implemented (`app/services/queue.py`); no broker deployed in this repo |
| Auth on gRPC | RBAC is implemented for REST; gRPC relies on an authenticating proxy / mTLS (documented residual risk) |
| mTLS termination (§17) | Belongs at the ingress (NGINX/Sidecar); documented, not implemented in-process |
| Stacking / meta-classifier fusion (§27) | Needs real weights and a labelled set to fit; deterministic fusion is in place |
| Multilingual text models (§11) | DistilBERT (English) + lexicon fallback only; a multilingual adapter needs its own licence review |
| `nsfw_gpu_utilization_ratio` (§31) | Declared but never set: there is no dependency-free portable way to read it, and publishing a hardcoded `0` on a GPU node would look like a real measurement. Feed it from `nvidia-smi` via your own exporter |
| §39 directory layout | The spec's tree (`apps/`, `engine/`, `multimodal/`, `queues/`, `infra/`, `training/`, `evaluation/`) is not reproduced literally; the code is organised by concern under `app/` and top-level packages. Renaming now would be churn without a functional gain, so the deviation is recorded rather than silently accepted |

## How to keep this honest

1. Never edit a number in `BENCHMARK_MATRIX.md` by hand — regenerate it:
   `python -m benchmarks --out docs/BENCHMARK_MATRIX.md`.
2. Re-run `python -m benchmarks --dataset <manifest>` whenever a model changes,
   and update §45 criteria from the measured output.
3. Add a model to `MODEL_PROVENANCE.md` **before** deploying it.
4. `python scripts/export_openapi.py --check` in CI keeps the API contract honest.
5. Fit calibration against a **validation** split, never the set you report on:
   `python scripts/calibrate.py --dataset <manifest> --method all` ranks the §26
   methods by Expected Calibration Error and writes the winner to
   `config/calibration.json`. Then flip `calibration.enabled: true` in
   `config/engine_config.yaml` — until you do, the document is inert.