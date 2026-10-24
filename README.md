# NSFW Firewall Engine

> **Language / Idioma:** **English** · [Español](README.es.md)

A production-oriented, **triage-based** NSFW classification service designed to
sit behind a web proxy / firewall and inspect images, video frames, text and
HTML at line rate.

> ### ⚠️ Current status: one local visual model is active
>
> Model binaries are gitignored and absent from a clean checkout. This workspace
> has Marqo's `vit_nsfw.onnx` wired into the Deep stage at 384×384; it passes
> PyTorch/ONNX parity but has no labelled accuracy evaluation. Fast and
> Multimodal models are absent, and the Viddexa exports are quarantined after
> failing parity checks. Missing or failed stages now request review instead
> of substituting a skin-tone heuristic. Premium is disabled to avoid running
> the same Marqo model twice.
>
> See the candidate's immutable revision, licence caveat, local latency result,
> and SHA256 in [`MODEL_PROVENANCE.md`](docs/MODEL_PROVENANCE.md).

**572 tests passing · 2 skipped** · 19 REST paths · ~8,800 lines of application code ·
Apache-2.0 project code (model weights are licence-bound — see
[`MODEL_PROVENANCE.md`](docs/MODEL_PROVENANCE.md))

---

## Table of contents

**Orientation**

1. [How the classification works](#how-the-classification-works)
2. [Features](#features)
3. [What is still missing](#what-is-still-missing)
4. [How this was built](#how-this-was-built)
5. [Project layout](#project-layout)

**Getting started**

6. [Quick start](#quick-start)
7. [Configuration](#configuration)
8. [Usage](#usage)
9. [API](#api)
10. [Testing and CI gates](#testing-and-ci-gates)

**Concepts**

11. [Policy engine](#policy-engine)
12. [Model lifecycle](#model-lifecycle)
13. [Dead-letter queue and retries](#dead-letter-queue-and-retries)
14. [Firewall modes](#firewall-modes)
15. [Authentication and RBAC](#authentication-and-rbac)

**Operations**

16. [Observability](#observability)
17. [Configuration reference](#configuration-reference)
18. [Model integrity](#model-integrity)
19. [Production gate](#production-gate)
20. [Deployment](#deployment)
21. [Extending the models](#extending-the-models)
22. [Benchmarks and evaluation](#benchmarks-and-evaluation)

**Reference**

23. [Notes and limitations](#notes-and-limitations)
24. [Further reading](#further-reading)

---

## How the classification works

The engine supports a cost-aware **cascade**. In this checkout, only Marqo ViT
is mounted; the other stages are configuration targets, not operational
detectors:

```
payload ──▶ Fast       [unavailable; escalates]
        ──▶ Deep       [Marqo ViT active; may decide]
        ──▶ Multimodal [unavailable; skipped]
                         └─ REVIEW if no model decides
```

The configured Fast and Multimodal artifacts are absent, so an inconclusive
Marqo result ends in `REVIEW`. Text analysis remains available, but it does not
replace a missing visual model.

**Design goal, not a current performance claim.** The cascade is intended to let
an available fast model terminate clear cases before expensive models run. That
cost profile is not currently achieved: Fast and Multimodal weights are absent,
and the sole active Marqo model has not been evaluated on a labelled corpus
([ADR-0001](docs/adr/0001-cost-aware-triage-cascade.md)).

**Missing-model behavior.** An unavailable or failed stage cannot make an
allow/block decision. The cascade continues where possible and otherwise returns
`REVIEW`; it never substitutes a skin-tone heuristic
([ADR-0003](docs/adr/0003-graceful-degradation.md)).

## Features

### Classification
* **Three-tier cascade support** – Fast → Deep → Multimodal; currently only the
  Deep stage has a mounted model (Marqo ViT). Missing stages cannot decide.
* **ONNX Runtime** with automatic execution-provider negotiation
  (TensorRT → CUDA → OpenVINO → CPU), including per-provider tuning options.
* **DistilBERT text path** plus configurable multimodal fusion
  (`weighted` / `max` / `noisy_or`).
* **Video pipeline** with `uniform` **and** scene-change frame sampling (§14) and
  `max`/`mean`/`percentile`/`weighted` temporal aggregation. `max` is the default:
  averaging dilutes a 5-second insert across 120 safe frames into a clean bill
  of health.
* **Score calibration** (§26) — temperature, Platt and isotonic, applied *before*
  fusion, with `scripts/calibrate.py` to fit.

### Policy & safety
* **Declarative policy engine** (`policy/`) – ordered, auditable rules map verdicts
  to `ALLOW/BLOCK/REVIEW/QUARANTINE`, with per-tenant overrides.
* **Full §19 dimensions** – rules can match on `tenant_id`, `user_id`, `groups`,
  `device_id`, `zone`, `url`, `domain`, `category` and a derived `time` facet
  (`hour`, `weekday`, `is_weekend`, `business_hours`, `night`).
* **Firewall modes** (§30) – `enforcement`, or `audit` to simulate decisions on
  live traffic without blocking (`would_be_action` reports what was suppressed).
* **Dead-letter queue** (§33) — requests the engine could not decide are captured,
  bounded and TTL-scoped, **without ever retaining the payload**.

### Platform
* **Three transports** – gRPC (low latency), ICAP (Squid/MITM), REST (ops & audit).
* **Versioned REST contract** (`/v1/*`, §20) with a committed OpenAPI document
  and a CI gate that fails if it drifts.
* **Authentication, RBAC and audit** (`app/core/security.py`) – hashed API keys,
  six roles from §35, metadata-only audit log. Probes stay public. gRPC accepts
  the same keys via request metadata.
* **Latency budgets** (`app/core/deadline.py`) – per-stage and per-request
  budgets are actually enforced; a breach routes through `policy.fail_action`.
* **Distributed decision cache** (`cache.type: redis`) – shares the JSON-safe
  payload and key contract with the in-process cache; degrades to memory when no
  client is available.
* **Rate limiting** (§17), **circuit breaking** and **bounded retries** (§33), and
  **idempotency** keyed by `(tenant, request_id)` so a client retry cannot produce
  contradictory audit entries.
* **Model lifecycle** (§22) — five enforced states with an illegal-transition
  table, so a model cannot reach `production` without having been benchmarked.
* **Model integrity gate** (`scripts/verify_models.py`) – SHA256 lockfile that
  detects tampered, missing or unvetted artifacts.
* **Production readiness gate** (`scripts/production_gate.py`) – refuses to
  certify a deployment that is unauthenticated, fails open, or has no weights.

### Observability
* **Prometheus metrics** (`GET /metrics`) that work with or without
  `prometheus_client` installed, plus a provisioned Grafana dashboard.
* **Optional OpenTelemetry tracing** (`observability.enable_tracing`) – no-op
  when disabled or unavailable; `classify` is spanned when active.
* **Structured JSON logging** and a rotating file handler.
* **External model adapters** (`adapters/`) – one contract for NSFWJS,
  OpenNSFW2, CLIP; Nudita is inert by design (AGPL-3.0).

### Input handling
* **Content inspection** – magic-byte MIME sniffing, decompression-bomb and size
  limits, SHA256 audit hashing (raw payloads are never stored).
* **HTML context extraction** (§12) – title, meta/OpenGraph, alt text, RTA/Preroll
  directives and URL/domain, behind a bounded parser.
* **Enforcement adapters** – the same decision rendered as an HTTP response, an
  ICAP message, or an NGINX `return` snippet.
* **Graceful degradation** – if models/runtime/optional decoders are absent the
  engine falls back to documented heuristics so the pipeline stays operational
  *and visibly reports itself unhealthy*.
* **Benchmark & evaluation harnesses** (`benchmarks/`) – every published number
  is reproducible via `python -m benchmarks`.
* **Fuzzing harness** (`scripts/fuzz.py`) over ICAP, MIME and HTML parsing — the
  three surfaces reachable by anyone who can send one packet.

---

## What is still missing

Everything that can be implemented **without external artifacts** is implemented
and tested. What remains is blocked on inputs that code cannot conjure:

| Outstanding | Blocked on |
|---|---|
| Real weights in `models_onnx/` | A published, licence-cleared checkpoint must be downloaded and converted. `/v1/ready` stays `false` and the production gate fails with `no_model_weights` until then. |
| §49 benchmark evidence (FPR/FNR/PR-AUC/ECE) | Requires a labelled evaluation corpus. None exists, and a synthesised dataset must not then be used to certify quality. |
| Calibration fitting & stacking optimisation | Both need weights **and** labelled data. The machinery is built and tested; there is nothing to fit against. |
| `premium_vit` promotion to `validated` | Blocked behind the two rows above. The lifecycle refuses the jump until the measurement exists. |

Two environment limitations are **not** code gaps:

* `fastapi.testclient.TestClient` is broken here — the installed `starlette` and
  `httpx` are incompatible (`httpx.BaseTransport` is missing). Tests therefore
  invoke endpoint functions directly or use `httpx.ASGITransport`.
* `docker build`, `helm lint` and a live container start have never been executed:
  no Docker daemon or Helm binary is available. The chart and the flat manifests
  are syntactically valid, but only by inspection.

---

## How this was built

The specification (`pront.md`, ~50 numbered requirements) was audited section by
section against the code, and each requirement was classified as
**implemented-and-tested**, **implemented-but-unverifiable** (needs weights), or
**not implemented**. Work was then done in risk order.

Three principles shaped the result:

**1. A setting that does nothing is worse than no setting.**
`engine.fail_mode` and `policy.fail_action` both existed; only the latter was ever
read. An operator could set `fail_mode: BLOCK` and get fail-**open** behaviour.
`scripts/audit_config.py` now hunts for exactly this class of bug. The deprecated
alias is reconciled against the authoritative one at load time.

**2. Enumerate status; never trust a label.**
An early version recorded `record_enforcement` and imported it in the router, but
never called it — so the block counter was permanently zero while appearing fully
implemented. The lesson shaped §22: a lifecycle status is only meaningful if
illegal states are *rejected*. `candidate → production` now returns `409`,
because a promotion that skips benchmarking is a claim nobody measured. The same
reasoning caught a rule-engine bug where `contains` against a list field silently
never matched — a policy that quietly never fires is more dangerous than one that
is visibly broken.

**3. Never retain the content the firewall exists to filter.**
The dead-letter queue stores a SHA256 digest and never the bytes. Applying the
same rule to the HTML context extractor (§12) is why only metadata is retained,
which is what makes the audit log safe under
`privacy.retain_raw_payloads: false`.

Load-bearing design decisions have their own ADRs:

| ADR | Decision |
|---|---|
| [0001](docs/adr/0001-cost-aware-triage-cascade.md) | Cost-aware triage cascade |
| [0002](docs/adr/0002-declarative-policy-rules.md) | Declarative policy rules as data, not code |
| [0003](docs/adr/0003-graceful-degradation.md) | Graceful degradation on missing dependencies |
| [0004](docs/adr/0004-cache-key-model-version.md) | Cache key includes the model version |

## Project layout

```
nsfw_firewall_engine/
├── config/
│   ├── engine_config.yaml        # thresholds, timeouts, paths, transport, cache, policy
│   ├── logging_config.yaml       # structured logging definition
│   ├── privacy.yaml / quantization.yaml / hardware.yaml
├── proto/
│   └── nsfw_engine.proto         # gRPC / protobuf contract
├── policy/                       # declarative rule engine (§19)
│   ├── models.py                 #   Rule / Policy / Decision
│   └── engine.py                 #   rule evaluation + tenant registry
├── adapters/                     # external-model contract (§41)
│   ├── base.py                   #   BaseAdapter + §22 ModelStatus lifecycle
│   ├── registry.py               #   stage -> adapter table + set_status()
│   └── vision.py                 #   NSFWJS / OpenNSFW2 / CLIP / ViT / Nudita
├── content/
│   └── mime_detector.py          # magic-byte MIME, bomb checks, SHA256 audit (§16/§18)
├── models_onnx/                  # compiled ONNX artifacts (see its README)
├── deploy/
│   ├── helm/nsfw-firewall/       # Helm chart
│   ├── k8s/manifests.yaml        # flat manifests for clusters without Helm (§32)
│   ├── prometheus/prometheus.yml
│   └── grafana/
├── docs/                         # reuse matrix, provenance, threat model, ADRs
├── app/
│   ├── core/
│   │   ├── engine.py             # NsfwEngine triage orchestrator
│   │   ├── policy.py             # result -> rule-context bridge
│   │   ├── request_context.py    # §19 caller dimensions (zone/groups/time/…)
│   │   ├── resilience.py         # rate limit, breaker, retries, DLQ, idempotency (§33)
│   │   ├── fusion.py             # weighted/max/noisy_or multimodal fusion
│   │   ├── cache.py              # content-addressed decision cache (§29)
│   │   ├── calibration.py        # temperature / Platt / isotonic (§26)
│   │   ├── metrics.py            # Prometheus exposition (§31)
│   │   ├── onnx_runtime.py       # session manager + provider negotiation
│   │   ├── preprocessor.py       # decode / resize / normalize
│   │   ├── security.py           # API keys, RBAC, audit (§35)
│   │   ├── config.py             # typed configuration loading
│   │   └── logging_setup.py      # JSON logging
│   ├── models/
│   │   ├── base.py               # shared types + fallback heuristic
│   │   ├── fast_path.py          # Model A – MobileNetV3
│   │   ├── deep_path.py          # Model B – EfficientNet
│   │   ├── multimodal_path.py    # Model C – CLIP (+ text fusion)
│   │   └── text_path.py          # DistilBERT text classifier
│   ├── services/
│   │   ├── text_analyzer.py      # HTML/text signal extraction
│   │   ├── html_context.py       # §12 title/meta/alt/RTA context (metadata only)
│   │   ├── video_pipeline.py     # frame sampling + aggregation
│   │   ├── content_inspector.py  # MIME/bomb/size gate for the API layer
│   │   └── enforcement.py        # HTTP / ICAP / NGINX enforcement adapters
│   └── api/
│       ├── grpc/ (server.py, handlers.py)
│       ├── icap/ (icap_server.py)
│       └── rest/ (router.py, v1.py, schemas.py)
├── scripts/
│   ├── convert_to_onnx.py, quantize_models.py
│   ├── calibrate.py              # fit §26 calibration
│   ├── verify_models.py          # SHA256 lockfile gate (§22/§38)
│   ├── audit_config.py           # dead / contradictory settings
│   ├── production_gate.py        # refuses an unsafe production config
│   ├── export_openapi.py         # contract + drift gate (§20/§46)
│   └── fuzz.py                   # ICAP / MIME / HTML fuzzing (§37)
├── benchmarks/                   # evaluation + reporting (§25)
├── tests/                        # test suite
├── pyproject.toml                # package metadata, dependencies and CLI entry points
├── docker-compose.yml
├── Dockerfile
└── README.md
```

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# 1. Provide models (optional – engine falls back to heuristics otherwise)
#    See models_onnx/README.md.

# 2. Generate the gRPC stubs (needed only for the gRPC transport)
python -m grpc_tools.protoc -I proto --python_out=proto --grpc_python_out=proto proto/nsfw_engine.proto

# 3. Run a transport
nsfw-firewall-rest                 # REST  on :8080
nsfw-firewall-grpc                 # gRPC  on :50051
nsfw-firewall-icap                 # ICAP  on :1344
```

For a non-editable installation without development tools, use `pip install .`.
The install includes declared dependencies and default configuration files;
ONNX weights remain external. `pip install -r requirements.txt` remains available
for repository-based installations.

## Configuration

All tuning lives in `config/engine_config.yaml`. Decision thresholds are
per-stage and expressed as NSFW probabilities in `[0, 1]`:

| Stage | `hard_nsfw` | `hard_sfw` | Behaviour |
|-------|-------------|------------|-----------|
| Fast  | 0.85 | 0.15 | outside the band → immediate verdict; inside → escalate |
| Deep  | 0.80 | 0.20 | same, one level deeper |
| Multimodal | 0.75 (`hard_nsfw`) / 0.40 (`review`) | – | final arbiter |

Override the config path with `NSFW_ENGINE_CONFIG`. Per-request overrides are
accepted by every transport (`ThresholdOverrides` / `overrides`).

## Usage

### REST

```bash
curl -s localhost:8080/health
curl -s localhost:8080/metrics | head                 # Prometheus exposition
curl -s -X POST localhost:8080/classify/raw?media_type=IMAGE \
     --data-binary @photo.jpg | jq .
curl -s -X POST localhost:8080/classify/text \
     -H 'content-type: application/json' \
     -d '{"text":"<html><body>free porn</body></html>","media_type":"HTML"}' | jq .
# Firewall/SWG: get the enforcement response (status, headers, block page)
curl -s -X POST 'localhost:8080/enforce?tenant_id=acme' \
     -H 'content-type: application/json' \
     -d '{"image_base64":"<base64>"}' | jq .
```

Every response carries the enforced `action` (`ALLOW`/`BLOCK`/`REVIEW`/`QUARANTINE`),
the `policy_id` that produced it, `from_cache`, the payload `content_sha256` and
the sniffed `detected_mime`. Payloads that violate size/dimension/bomb limits are
rejected with `400` before any decoder runs.

## Authentication and RBAC

`security.enabled` ships **true** by default for security. The service enforces
authentication and validates dependencies at startup. **For production deployment:**

```bash
# Generate API keys via environment variables (RECOMMENDED)
export NSFW_API_KEYS='{"svc":"<sha256-hex>"}'
export NSFW_KEY_TENANTS='{"svc":"acme"}'

# Or use config (NOT RECOMMENDED for production - do not commit secrets)
python -c "import hashlib;print(hashlib.sha256(b'MY_SECRET').hexdigest())"   # -> paste into api_keys
```

```yaml
security:
  enabled: true
  require_auth_in_production: true  # Enforce auth in production environment
  api_keys: {}                      # INJECT VIA ENVIRONMENT: NSFW_API_KEYS
  key_roles:
    svc: "service_account"   # classify + enforce
    probe: "read_only"       # config only
    auditor: "auditor"       # config + audit log
    platform_admin: "super_admin"
  key_tenants: {}            # INJECT VIA ENVIRONMENT: NSFW_KEY_TENANTS
  require_tenant_header: true   # multi-tenant: force X-Tenant-Id
  allow_unbound_tenant_header: false  # fail-closed on tenant mismatch
  require_transport_tls: true  # Require TLS for credential-bearing transports
  rate_limit_enabled: true
  rate_limit_per_second: 10    # Adjust for production (development default)
  rate_limit_burst: 20         # Adjust for production (development default)
```

```bash
curl -s localhost:8080/health                       # 200 - probes stay public
curl -s localhost:8080/config -H 'X-API-Key: $SECRET'          # 200
curl -s localhost:8080/classify -H 'X-API-Key: wrong' ...       # 401
curl -s localhost:8080/audit -H 'X-API-Key: $READONLY'         # 403 (needs READ_AUDIT)
curl -s localhost:8080/me -H 'X-API-Key: $SECRET' | jq .        # roles + permissions
```

| Role | Permissions |
|------|-------------|
| `super_admin` | all |
| `policy_admin` | classify, enforce, read_config, read_audit, manage_policy |
| `security_operator` | classify, enforce, read_config, read_audit |
| `auditor` | read_config, read_audit |
| `read_only` | read_config |
| `service_account` | classify, enforce |

## Configuration reference

| Section | Purpose |
|---------|---------|
| `engine.mode` | `triage` (cascade) or `fast_only` |
| `engine.request_timeout_ms` | **Enforced** per-request budget; a breach sets `timed_out` and routes through `policy.fail_action` |
| `timeouts.*` | Per-stage budgets (**Enforced** only when real models are loaded — they describe model SLOs, not the heuristic stub) |
| `thresholds.*` | Per-stage decision bands and text-fusion weight/strategy |
| `policy.*` | Verdict → action, incl. `fail_action` and `tenant_overrides` |
| `firewall.mode` | `enforcement` or `audit` (§30) |
| `security.*` | API keys, roles, audit (§35) |
| `cache.*` | Decision cache type (`memory`/`redis`), TTL/capacity, Redis URL/prefix (§29) |
| `onnx.providers` | Execution providers + per-provider options |
| `observability.*` | Prometheus port, `enable_tracing` (OpenTelemetry), log level/format |

> `engine.fail_mode` is **deprecated** and reconciled against
> `policy.fail_action` (which is authoritative) at load time — a disagreement is
> logged, so the two can never silently diverge. Run
> `python scripts/audit_config.py` to check for dead or contradictory settings;
> `config/hardware.yaml`, `privacy.yaml` and `quantization.yaml` are **design
> references, not runtime config**.

## Firewall modes

```yaml
firewall:
  mode: "audit"        # simulate everything, block nothing
```

In `audit` mode classification and policy run unchanged, but the enforced action
is forced to `ALLOW` and the suppressed action is reported as
`would_be_action` — the safe way to tune thresholds against live traffic.

## Model integrity

```bash
python scripts/verify_models.py            # verify against models.lock.json
python scripts/verify_models.py --write    # (re)generate after reviewing artifacts
```

Fails on a **mismatch**, a **missing** artifact, or any `.onnx` present but not
listed (unvetted side-load). Run it as a CI gate and as a container pre-flight.

## Benchmarks and evaluation

```bash
python -m benchmarks --iterations 200 --out docs/BENCHMARK_MATRIX.md
python -m benchmarks --dataset datasets/eval.example.json   # precision/recall/F1/AUC
python -m benchmarks --json                                  # machine-readable
```

Reports refuse to present heuristic-fallback numbers as detector performance and
report *skipped* instead of fabricating scores when no labelled dataset exists.

## Deployment

```bash
# Local stack: engine + Prometheus + Grafana
docker compose up --build
#   REST      : http://localhost:8080
#   Metrics   : http://localhost:8080/metrics
#   Prometheus: http://localhost:9090
#   Grafana   : http://localhost:3000  (admin/admin)

# Kubernetes — Helm
helm upgrade --install nsfw ./deploy/helm/nsfw-firewall \
  --set image.repository=nsfw-firewall-engine --set image.tag=1.0.0

# Kubernetes — flat manifests (§32), for clusters without Helm
kubectl apply -f deploy/k8s/manifests.yaml
```

The chart ships non-root + read-only-rootfs security context, startup/readiness/
liveness probes, a PodDisruptionBudget and topology spreading (HA), an optional
HPA and ServiceMonitor, and mounts models from a PVC/emptydir — never baked into
the image. ONNX artifacts are licence-bound and large, so they are mounted at
runtime (see `models_onnx/README.md` and `docs/MODEL_PROVENANCE.md`).

**Probe split.** Liveness uses `/health` and readiness uses `/v1/ready`. This is
deliberate: a liveness probe tied to model readiness would *kill* a pod merely
because weights are missing, converting a degraded-but-honest deployment into an
outage loop. Readiness removes it from the Service — it stops receiving traffic
but stays alive so an operator can read `/v1/ready` and diagnose.

### In-process (Python)

```python
from app.core.engine import NsfwEngine
from app.models.base import MediaType

engine = NsfwEngine()                       # loads config/engine_config.yaml
result = engine.classify(open("photo.jpg", "rb").read(), MediaType.IMAGE)
print(result.verdict, result.score, result.decided_by)
```

### ICAP (Squid)

`docker compose up --build` starts the ICAP server on `localhost:1344`,
separate from the REST process. Point Squid at both adaptation services to
inspect uploads and responses:

```
icap_enable on
icap_service nsfw_req reqmod_precache icap://127.0.0.1:1344/nsfw-firewall
icap_service nsfw_res respmod_precache icap://127.0.0.1:1344/nsfw-firewall
adaptation_access nsfw_req allow all
adaptation_access nsfw_res allow all
```

The ICAP listener does not authenticate clients: restrict port `1344` to the
trusted proxy network. TLS inspection and identity-header trust remain the
proxy's responsibility.

## Testing and CI gates

```bash
python -m unittest discover -s tests -t .
# or, if pytest is installed:
python -m pytest tests -q
```

The suite runs without GPUs, ONNX models or `grpcio` (gRPC tests auto-skip).
Without a usable visual model, classification returns `REVIEW`; a targeted
integration test exercises the local Marqo ONNX graph when it is present.

Every gate CI runs, and what it protects:

| Gate | Protects |
|---|---|
| `python -m unittest` / `pytest` | Behaviour of every module |
| `python -m compileall` | Every module imports |
| `scripts/export_openapi.py --check` | The committed contract matches the code (§20/§46) |
| `scripts/audit_config.py --strict` | No dead or contradictory settings |
| `scripts/verify_models.py` | SHA256 lockfile; no tampered or side-loaded weights |
| `scripts/fuzz.py --iterations 1000` | ICAP / MIME / HTML parsers against hostile input (§37) |
| `scripts/production_gate.py` | The gate itself still detects an unsafe config |
| `bandit` + security review | Common vulnerability classes |

---

## Further reading

| Document | Contents |
|---|---|
| [`IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) | Per-requirement status; what is blocked and why |
| [`MODEL_PROVENANCE.md`](docs/MODEL_PROVENANCE.md) | §22 status table, licence review, promotion procedure |
| [`THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Attack surface and accepted residual risks |
| [`REUSE_MATRIX.md`](docs/REUSE_MATRIX.md) | Which upstream projects were evaluated, and which were rejected |
| [`THIRD_PARTY_NOTICES.md`](docs/THIRD_PARTY_NOTICES.md) | Attribution for every dependency |
| [`BENCHMARK_MATRIX.md`](docs/BENCHMARK_MATRIX.md) | Reproducible measurements |
| [`MODEL_REGISTRY.md`](docs/MODEL_REGISTRY.md) | Stage → artifact contract |
| [`models_onnx/README.md`](models_onnx/README.md) | What to drop in `models_onnx/`, and how |
| [`pront.md`](pront.md) | The specification this was built against |

## Extending the models

1. Builders are already registered in `scripts/convert_to_onnx.py` (`MODEL_REGISTRY`): MobileNetV3-Small / EfficientNet-B0 / ResNet-50 trunk, each with a 2-class head. Add an entry there only for a new stage.
2. Export: `python scripts/convert_to_onnx.py --model fast_path --checkpoint checkpoints/<stage>.pt --output models_onnx/fast_path_mobilenetv3.onnx`.
3. Quantize: `python scripts/quantize_models.py --model models_onnx/fast_path_mobilenetv3.onnx`.
4. Restart the engine; provider negotiation and fallbacks are automatic.

## Notes and limitations

* Binary model artifacts are **not** shipped. Without a usable visual model
  the engine returns `REVIEW`; the legacy skin-tone heuristic is not used for
  enforcement.
* The ICAP server negotiates capabilities with `OPTIONS` and handles
  `REQMOD`/`RESPMOD` flows with `Content-Length` bodies; it does not advertise
  `Preview` support and explicitly rejects chunked transfer encoding.
* Video container decoding is left to an optional dependency (PyAV/OpenCV); the
  pipeline consumes decoded frames or individual encoded frames.

---

## Security Hardening

The engine includes multiple security layers that have been hardened against common attack vectors through multiple iterations of aggressive security evaluation.

### Implemented Security Measures

| Threat | Mitigation | Status | Iteration |
|--------|-----------|--------|-----------|
| **Fail-open bypass** | `policy.fail_action: BLOCK` - errors result in blocking traffic | ✅ Active | 1 |
| **Authentication bypass** | Enforced in production, validation at startup | ✅ Active | 1 |
| **Rate limiting** | Per-IP + per-tenant/principal limiting (pre/post-auth) | ✅ Active | 1 |
| **Resource exhaustion** | Max image dimensions (32 MP), size limits (20 MB), video duration (10 min) | ✅ Active | 1 |
| **Decompression bombs** | Pillow MAX_IMAGE_PIXELS enforcement | ✅ Active | 1 |
| **ReDoS attacks** | URL/hostname length caps (253/2048 chars) before regex | ✅ Active | 1 |
| **Cache poisoning** | Model-version sanitization (alphanumeric + .-_, max 64 chars) | ✅ Active | 1 |
| **Circuit breakers** | Fail-closed when circuit opens | ✅ Active | 1 |
| **Dead-letter queue overflow** | Bounded by TTL + count, never stores payloads | ✅ Active | 1 |
| **Network exposure** | gRPC/ICAP on loopback (127.0.0.1), trusted proxy whitelist | ✅ Active | 1 |
| **TLS enforcement** | Required for credential-bearing transports | ✅ Active | 1 |
| **Tenant isolation** | Key-to-tenant binding, header validation | ✅ Active | 1 |
| **Audit trail** | Persistent JSONL, metadata-only (no payloads) | ✅ Active | 1 |
| **Secrets management** | Hash salt/pepper via environment variables | ⚠️ Requires config | 1 |
| **IP rate limiting bounds** | Max 10,000 buckets with LRU eviction | ✅ Active | 2 |
| **Metrics protection** | Warning when unprotected in production | ✅ Active | 2 |
| **Anonymous role restrictions** | Blocks super_admin/policy_admin for anonymous | ✅ Active | 2 |
| **Audit log sanitization** | Control chars removed, 1000 char limit | ✅ Active | 2 |
| **Tenant binding enforcement** | Strict validation with mismatch logging | ✅ Active | 2 |

### Security Iterations

**Iteration 1 (2026-10-18):**
- Fixed fail-open bypass, authentication enforcement, rate limiting
- Added resource limits, ReDoS protection, cache sanitization
- Configured circuit breakers, video temp file protection
- **Result:** 75-80% of critical vulnerabilities mitigated

**Iteration 2 (2026-10-18):**
- Fixed IP rate limiting state explosion (bounded buckets)
- Added metrics protection warning in production
- Restricted anonymous users from dangerous roles
- Sanitized audit log fields against injection
- Enforced strict tenant binding validation
- **Result:** 85-90% of critical vulnerabilities mitigated

See `docs/SECURITY_HARDENING_ITERATION_2.md` for detailed analysis.

### Security Stress Testing

Run the security stress suite to verify hardening:

```bash
python scripts/stress_test_security.py
```

Current test results: **6/9 tests passing** (authentication, rate limiting, ReDoS, cache poisoning, memory exhaustion, DLQ flood)

See `scripts/stress_test_security.py` for test details and `docs/THREAT_MODEL.md` for the full threat analysis.

---

## Production Deployment Checklist

### Pre-Deployment Requirements

#### 1. Secrets Configuration (REQUIRED)

All secrets must be set via environment variables - **never commit secrets to the repository**:

```bash
# API Keys and Tenant Binding
export NSFW_API_KEYS='{"svc":"<sha256-hex>","monitoring":"<sha256-hex>"}'
export NSFW_KEY_TENANTS='{"svc":"acme","monitoring":"platform"}'

# Cryptographic Salts (prevents rainbow table attacks)
export NSFW_HASH_SALT="<random-32-byte-string>"
export NSFW_HASH_PEPPER="<random-32-byte-string>"

# Metrics Protection
export NSFW_METRICS_TOKEN="<random-32-byte-string>"

# Audit Trail Persistence
export NSFW_AUDIT_FILE="/var/log/nsfw-firewall/audit.jsonl"

# TLS Certificates (gRPC)
export NSFW_TLS_CERT_FILE="/path/to/cert.pem"
export NSFW_TLS_KEY_FILE="/path/to/key.pem"
export NSFW_TLS_CA_FILE="/path/to/ca.pem"  # Optional, for mTLS
```

#### 2. Configuration Changes (REQUIRED)

Remove any development/test keys from `config/engine_config.yaml`:

```yaml
security:
  api_keys: {}  # MUST BE EMPTY - inject via NSFW_API_KEYS
  key_tenants: {}  # MUST BE EMPTY - inject via NSFW_KEY_TENANTS
```

Set production-appropriate rate limits:

```yaml
security:
  rate_limit_per_second: 100  # Adjust based on traffic patterns
  rate_limit_burst: 200       # Adjust based on traffic patterns
```

#### 3. Environment Setting (REQUIRED)

```yaml
engine:
  environment: "production"  # NOT "development" or "staging"
```

#### 4. Dependency Validation (REQUIRED)

Ensure security dependencies are installed:

```bash
pip install Pillow python-magic
```

The engine will **refuse to start** in production without these dependencies.

#### 5. Model Verification (REQUIRED)

```bash
python scripts/verify_models.py
```

This validates SHA256 hashes against `models.lock.json`.

#### 6. Production Gate (REQUIRED)

```bash
python scripts/production_gate.py --strict
```

This blocks deployment if:
- Authentication is disabled
- Fail-open is configured
- No model weights are present
- Configuration has contradictions

### Deployment Validation

#### 1. Start the Service

```bash
# Using environment variables
NSFW_ENGINE_CONFIG=config/engine_config.yaml \
NSFW_API_KEYS='{"svc":"<sha256>"}' \
NSFW_KEY_TENANTS='{"svc":"acme"}' \
NSFW_HASH_SALT="<salt>" \
python -m app.main
```

#### 2. Verify Health

```bash
curl http://localhost:8080/health
# Should return 200 with security_enabled=true
```

#### 3. Verify Authentication

```bash
# Should return 401 without key
curl http://localhost:8080/v1/config

# Should return 200 with valid key
curl -H "X-API-Key: <secret>" http://localhost:8080/v1/config
```

#### 4. Verify Rate Limiting

```bash
# Send burst of requests
for i in {1..30}; do curl -H "X-API-Key: <secret>" http://localhost:8080/v1/config; done
# Should receive 429 after burst
```

#### 5. Run Security Stress Test

```bash
python scripts/stress_test_security.py
# All tests should pass with production configuration
```

### Post-Deployment Monitoring

#### 1. Configure Prometheus Alerts

Create alerts for:
- High rate limit rejections
- Circuit breaker openings
- Authentication failures
- Dead-letter queue depth
- Model inference errors
- High latency (> 500ms P95)

#### 2. Monitor Audit Trail

```bash
# Check audit file is being written
tail -f $NSFW_AUDIT_FILE
```

#### 3. Verify Metrics Scraping

```bash
curl http://localhost:8080/metrics
# Verify all series are present
```

### Security Checklist Summary

- [ ] All secrets configured via environment variables
- [ ] Test API keys removed from `config/engine_config.yaml`
- [ ] `engine.environment` set to "production"
- [ ] `security.enabled: true`
- [ ] `policy.fail_action: BLOCK`
- [ ] Pillow and python-magic installed
- [ ] Models verified with `verify_models.py`
- [ ] Production gate passes with `--strict`
- [ ] TLS certificates configured
- [ ] Rate limits set for production traffic
- [ ] Authentication verified working
- [ ] Rate limiting verified working
- [ ] Security stress test passes
- [ ] Prometheus alerts configured
- [ ] Audit trail persistent storage configured
- [ ] Metrics token configured
- [ ] gRPC/ICAP bound to loopback (127.0.0.1)
- [ ] Trusted proxy whitelist configured
- [ ] Tenant binding enabled (`allow_unbound_tenant_header: false`)

### Security Review Frequency

- **Monthly**: Review audit logs for authentication failures and rate limit violations
- **Quarterly**: Rotate API keys and secrets, update TLS certificates
- **Annually**: Full security audit, penetration testing, dependency updates

---

## API

### Versioned surface (`/v1`, §20)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/inspect` | Binary payload → decision + §19 context |
| `POST` | `/v1/classify` | Alias of `inspect` |
| `POST` | `/v1/classify/text` | Text/HTML → decision + §12 context |
| `POST` | `/v1/batch` | Up to `MAX_BATCH_ITEMS`; per-item errors, never aborts |
| `GET` | `/v1/models` | Registry with `status` and `may_serve` per model |
| `POST` | `/v1/models/{stage}/status` | §22 lifecycle transition (`MANAGE_POLICY`) |
| `GET` | `/v1/dead-letters` | §33 queue; `READ_AUDIT`, non-destructive by default |
| `GET` · `POST` | `/v1/policies` | Active ruleset / tenant install |
| `GET` | `/v1/health` · `/v1/ready` | Liveness / readiness (`ready` is `false` without weights) |

### Legacy surface

`/classify`, `/classify/text`, `/classify/raw`, `/enforce`, `/config`, `/audit`,
`/me`, `/health`, `/metrics`.

```bash
curl -s -X POST localhost:8080/v1/inspect \
  -H 'content-type: application/json' \
  -d '{"content_base64":"<base64>","media_type":"IMAGE","url":"https://cdn/x.jpg"}' | jq .
```

The machine-readable contract is committed at
[`docs/openapi.json`](docs/openapi.json); `scripts/export_openapi.py --check`
fails if it drifts from the code.

---

## Policy engine

`app/core/request_context.py` builds the caller-side dimensions a rule resolves
against: `tenant_id`, `user_id`, `groups`, `device_id`, `zone`, `url`, `domain`,
`category` and a derived `time` facet. They come from the authenticated principal
first and `X-*` request headers second, so a client cannot assert its own
identity.

```yaml
# A kiosk blocks everything; contractors are flagged for review;
# anything at night gets a second look.
rules:
  - {field: zone,       operator: '==',     value: kiosk,      action: block}
  - {field: groups,     operator: contains, value: contractor, action: review}
  - {field: time.night, operator: '==',     value: true,       action: review}
  - {field: verdict,    operator: '==',     value: NSFW,        action: block}
```

`time` is exposed as derived numbers and booleans (`hour`, `weekday`,
`is_weekend`, `business_hours`, `night`) rather than as a bespoke operator, so
policies stay declarative data — reviewable and diffable in Git
([ADR-0002](docs/adr/0002-declarative-policy-rules.md)).

> **Security note.** Header-supplied dimensions (`X-User-Groups`, `X-Zone`,
> `X-Device-Id`) are *advisory and spoofable*. They are safe for rules that only
> ever tighten enforcement and unsafe for rules that *relax* it based on an
> asserted group. Authorisation never reads them — permissions come from the API
> key. A group-based exemption needs a signed assertion (mTLS subject, JWT
> claim), not a plain header.

Every decision carries `matched_dimensions`, so an auditor can see *why* a rule
fired without replaying the request.

---

## Model lifecycle

Each registered model has one of five states, and the state is **enforced**:

| Status | Meaning | Serves traffic? |
|---|---|---|
| `candidate` | Registered, never benchmarked | Yes, but not trustworthy |
| `validated` | Benchmarked and within tolerance | Yes |
| `production` | Promoted after measurement | Yes |
| `deprecated` | Superseded; kept loadable for rollback | **No** |
| `blocked` | Must never run (licence / security / integrity) | **No**, and no path back |

`candidate → production` returns **409**. Promotion is a two-hop walk so each
step records its own evidence, which is how §49's "no claims without benchmarks"
ends up in the data model rather than in a comment.

`deprecated` and `blocked` are deliberately different: a deprecated model can be
restored, a blocked one cannot. That is what stops someone "just enabling"
Nudita to route around the AGPL boundary in §4.

```bash
curl -X POST localhost:8080/v1/models/premium_vit/status \
  -H "X-API-Key: $KEY" \
  -d '{"status":"validated","reason":"benchmarked on eval-2026-10: FPR 0.004"}'
```

`GET /v1/models` reports `status` and `may_serve` for every entry *including the
blocked ones*, so an operator can see why a model is not scoring anything instead
of finding it silently absent. Full table in
[`MODEL_PROVENANCE.md`](docs/MODEL_PROVENANCE.md).

---

## Dead-letter queue and retries

A firewall that fails to decide a request must **fail closed** (so undecided
traffic is not silently allowed) and **not lose it** (so the client can retry
once the dependency recovers). The DLQ is where the second obligation lives.

```bash
curl -s localhost:8080/v1/dead-letters | jq '.stats'        # inspect
curl -s 'localhost:8080/v1/dead-letters?drain=true' | jq   # replay drain (irreversible)
```

Two decisions worth knowing:

* **Payloads are never stored.** A letter carries the SHA256 digest and nothing
  else. Retaining content that failed to classify would make the failure path a
  store full of precisely the material the firewall exists to filter.
* **Bounded by TTL *and* count**, like the idempotency store. An unbounded queue
  is a memory-exhaustion target, and a dropped letter beats an OOM kill.

`call_with_retries()` provides bounded retries. Backoff is **linear** on purpose:
at 2–3 attempts and millisecond delays, exponential buys no real congestion
relief while making the worst-case latency — what a firewall is measured on —
noticeably worse.

---

## Observability

`GET /metrics` works with or without `prometheus_client` installed; a built-in
exposition backend guarantees scraping never fails.

| Series | Answers |
|---|---|
| `nsfw_requests_total` | Request rate per tenant and endpoint |
| `nsfw_request_errors_total` | 5xx rate (only real faults, not 4xx) |
| `nsfw_queue_depth` | Requests in flight — saturation vs. burst |
| `nsfw_queue_latency_seconds` | Time queued before the handler ran |
| `nsfw_startup_time_seconds` | Boot time, *including* model loading |
| `nsfw_enforcement_total` | ALLOW / BLOCK / REVIEW / QUARANTINE counts |
| `nsfw_dead_letter_total` | Undecidable requests, by reason |
| `nsfw_pipeline_latency_seconds` | End-to-end latency by verdict |

`queue_latency` is the series that distinguishes *"the engine is saturated"* from
*"the model is slow"* — request duration alone conflates the two, leaving an
operator tuning concurrency with nothing to act on.

---

## Production gate

```bash
python scripts/production_gate.py            # report
python scripts/production_gate.py --strict   # exit 1 on findings
```

The defaults are development-safe on purpose (`security.enabled: false`,
`policy.fail_action: ALLOW`) so the service boots without secrets. The danger is
that nothing marks that as *not production*: a deployment carrying the defaults
looks perfectly healthy — probes pass — while every request is unauthenticated
and every internal error fails **open**.

The gate refuses to certify a configuration that would do that. It has no
warnings tier — a firewall that is merely *probably* safe is not safe. It reuses
`verify_models.scan_artifacts()` so there is exactly one definition of "a weight
file exists" in the repo.

```
  [BLOCKER] security_disabled   security.enabled=false: every classification
                               request is unauthenticated.
  [BLOCKER] fail_open           policy.fail_action=ALLOW: if the engine errors,
                               policy resolves to ALLOW. Set it to BLOCK.
  [BLOCKER] no_model_weights    No ONNX weights found; falling back to a
                               heuristic, which is not a trained detector (§49).
```

CI runs it without `--strict`, asserting only that it still *detects*
`security_disabled` and `fail_open`. If the step ever reports PASS, the gate has
stopped working and the check is worthless.
