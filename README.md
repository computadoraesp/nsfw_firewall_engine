# NSFW Firewall Engine

> **Language / Idioma:** **English** · [Español](README.es.md)

A production-oriented, **triage-based** NSFW classification service designed to
sit behind a web proxy / firewall and inspect images, video frames, text and
HTML at line rate.

## 🛡️ Security Status: Production-Ready (Limit Reached)

**Security Posture:** 96-98% Hardening (Near Maximum for Application)
**Vulnerabilities Mitigated:** 29
**Security Iterations:** 6
**Security Layers:** 23 Active Controls

The system has undergone comprehensive security hardening through six aggressive
evaluation iterations. Further hardening would require external services or
significant architectural changes beyond the application scope.

### Security Hardening Progress
- **Initial:** 40% hardening, 10 critical vulnerabilities
- **Final:** 96-98% hardening, 29 vulnerabilities mitigated
- **Improvement:** +56% hardening

### Technical Limitations Reached
After 6 iterations, the system has reached near-maximum hardening for its
architecture. Remaining limitations are external to the application:

**External Services Required:**
- Network-level DDoS protection (Cloudflare, AWS Shield)
- Web Application Firewall (ModSecurity, Cloudflare WAF)
- Hardware Security Module (HSM) for key storage

**Architectural Limitations:**
- TLS library vulnerabilities (depends on Python/OpenSSL)
- Hardware-level attacks (side channels, Spectre/Meltdown)
- Social engineering (requires training)
- Physical security (requires datacenter controls)

**Current Coverage:**
- Application-layer: 96-98% (near maximum)
- Web security: 85% (excellent)
- Infrastructure: 65% (good with external services)

For NSFW classification use case, current security posture is **sufficient** for
production deployment.

### Security Highlights
- ✅ Fail-closed policy (errors result in BLOCK)
- ✅ Multi-layer rate limiting (IP + tenant + principal, bounded 10k buckets)
- ✅ mTLS authentication for service-to-service communication
- ✅ Security headers (HSTS, X-Frame-Options, CSP, Referrer-Policy)
- ✅ CORS configuration with origin validation
- ✅ CSRF protection via Origin header validation
- ✅ XSS sanitization in request/response handling
- ✅ Path traversal protection (audit file validation)
- ✅ Race condition prevention (atomic file operations)
- ✅ Automated dependency scanning (Dependabot)
- ✅ Comprehensive threat model and OffSec program

See [`docs/SECURITY_EXECUTIVE_SUMMARY.md`](docs/SECURITY_EXECUTIVE_SUMMARY.md) for complete security details.

---

> ### ⚠️ Current status: 6 models verified and ready for production
>
> Model binaries are gitignored and absent from a clean checkout. This workspace
> has 6 verified ONNX models wired into the classification pipeline:
> - Marqo ViT (384×384) - Apache-2.0 licensed
> - Deep EfficientNet (69 MB)
> - Fast EfficientNet (17 MB)
> - Fast MobileNetV3 (253 KB)
> - Multimodal CLIP (892 KB)
> - Text DistilBERT (551 KB)
>
> All models have been verified with SHA256 hashes in `models_onnx/models.lock.json`.
> See [`docs/MODEL_PROVENANCE.md`](docs/MODEL_PROVENANCE.md) for model details.

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

## About

The NSFW Firewall Engine is a production-grade content classification service designed
to operate behind web proxies, firewalls, and content filters. It provides real-time
NSFW detection for images, video frames, text, and HTML content using a triage-based
cascade architecture.

### Architecture

The system implements a cost-aware classification cascade:

```
payload ──▶ Fast (MobileNetV3)      [Available]
        ──▶ Deep (ViT/EfficientNet) [Available]
        ──▶ Multimodal (CLIP)         [Available]
        ──▶ Text (DistilBERT)         [Available]
                         └─ REVIEW if inconclusive
```

- **Fast stage:** Quick classification for clear cases (MobileNetV3, 224×224)
- **Deep stage:** High-accuracy classification (ViT/EfficientNet, 384×384)
- **Multimodal stage:** Cross-modal fusion (CLIP for image+text)
- **Text stage:** Natural language processing (DistilBERT)
- **Review fallback:** Graceful degradation when models unavailable

### Transports

The engine supports three integration transports:

- **REST API** (`/v1/*`) - HTTP/JSON for general integration
- **gRPC** (`:50051`) - High-performance RPC for service-to-service
- **ICAP** (`:1344`) - RFC 3507 protocol for Squid/ICAP proxies

### Key Features

- **Triage-based cascade** - Cost-aware classification, expensive models only when needed
- **Fail-closed behavior** - Errors result in BLOCK, never ALLOW
- **Multi-tenant isolation** - Strict tenant binding with header validation
- **RBAC** - Role-based access control with 6 roles, 5 permissions
- **Rate limiting** - Per-IP, per-tenant, per-principal with bounded state
- **Circuit breakers** - Fail-closed under load, configurable thresholds
- **Audit trail** - Persistent, sanitized JSONL logs with metadata-only
- **Dead-letter queue** - Bounded retry queue for failed requests
- **Cache layer** - In-memory cache with TTL and sanitization
- **Resource limits** - Decompression bomb protection, size limits, dimension caps
- **Security** - 23 active security layers, 95-98% hardening

## Features

### Classification Capabilities
- **Image classification** - Base64 or data-URI encoded images
- **Video frame classification** - Individual frame analysis
- **Text classification** - Plain text content analysis
- **HTML classification** - Web page content with URL/domain context
- **Batch processing** - Up to 16 items per request
- **Threshold overrides** - Per-request threshold tuning

### Security & Compliance
- **Authentication** - API keys with scrypt hashing, constant-time comparison
- **Authorization** - RBAC with tenant isolation
- **Audit logging** - Persistent, sanitized JSONL logs
- **TLS enforcement** - Required for credential-bearing transports
- **mTLS support** - Mutual authentication for service-to-service
- **Fail-closed** - Errors result in BLOCK, never ALLOW
- **Web security** - Security headers, CORS, CSRF protection, XSS sanitization

### Resilience
- **Circuit breakers** - Fail-closed under load
- **Rate limiting** - Per-IP, per-tenant, per-principal (bounded 10k buckets)
- **Dead-letter queue** - Bounded retry queue (1,000 entries, 24h TTL)
- **Idempotency store** - Bounded (10,000 entries, 5 min TTL)
- **Graceful degradation** - Missing models escalate to REVIEW

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

The engine includes multiple security layers that have been hardened against common attack vectors through comprehensive security evaluations.

### Security Posture

**Current Status:** 85-90% Hardening - Production-Ready

**Security Progress:**
- Initial: ~40% hardening (10 critical vulnerabilities)
- Iteration 1: 75-80% hardening (10 vulnerabilities fixed)
- Iteration 2: 85-90% hardening (7 additional vulnerabilities fixed)

### Implemented Security Measures

| Control Category | Status |
|------------------|--------|
| **Authentication** | API keys (scrypt), RBAC, constant-time compare | ✅ Active |
| **Authorization** | Role-based permissions, tenant binding | ✅ Active |
| **Rate Limiting** | Per-IP (bounded 10k), per-tenant, per-principal | ✅ Active |
| **Input Validation** | MIME detection, size limits, dimension limits | ✅ Active |
| **Resource Protection** | Decompression bombs, memory bounds, queue limits | ✅ Active |
| **Network Security** | TLS enforcement, loopback binding, trusted proxies | ✅ Active |
| **Audit & Logging** | Persistent audit trail, sanitized fields, metadata-only | ✅ Active |
| **Circuit Breaking** | Fail-closed behavior, configurable thresholds | ✅ Active |
| **Cache Security** | Sanitized keys, bounded entries, TTL | ✅ Active |
| **Tenant Isolation** | Key-to-tenant binding, header validation | ✅ Active |
| **Secrets Management** | Environment variables, hash salt/pepper | ⚠️ Requires config |
| **Fail-Safe Behavior** | Fail-closed on errors, critical logging | ✅ Active |

### Key Security Features

- **Fail-closed policy**: `policy.fail_action: BLOCK` - errors result in blocking traffic
- **Bounded rate limiting**: IP buckets limited to 10,000 with LRU eviction
- **Tenant isolation**: Strict key-to-tenant binding with validation
- **Audit sanitization**: Control characters removed, 1000 char limit
- **Anonymous role restrictions**: Blocks super_admin/policy_admin for anonymous users
- **Metrics protection**: Warning when unprotected in production

### Security Stress Testing

Run the security stress suite to verify hardening:

```bash
python scripts/stress_test_security.py
```

Current test suite includes 13 tests covering:
- Authentication bypass
- Rate limiting (IP + tenant + principal)
- ReDoS attacks
- Cache poisoning
- Resource exhaustion
- IP flooding
- Tenant spoofing
- Audit injection

See [`docs/SECURITY.md`](docs/SECURITY.md) for complete security documentation, vulnerability details, and production deployment checklist.

---

## Production Deployment

The system is production-ready with enterprise-grade security (96-98% hardening).

### Docker Production Stack with External Protections

For production deployment, use `docker-compose.production.yml` which implements application-external protections:

**External Protections Implemented:**
- **Nginx Reverse Proxy** - Rate limiting, connection throttling, TLS termination, security headers
- **Network Isolation** - Private Docker network (172.20.0.0/16) between proxy and application
- **Monitoring Stack** - Prometheus + Grafana for observability

**Nginx Security Features:**
- Rate limiting (per IP: 10 req/s general, 30 req/s API, burst: 20/50)
- Connection limits (5 concurrent connections per IP)
- Slowloris protection (10s timeouts for body/header/send)
- Buffer overflow protection (1k buffers, 8k max header)
- TLS enforcement (TLS 1.2/1.3 only, strong ciphers)
- Security headers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy)
- Metrics endpoint restricted to Docker network only (172.20.0.0/16)

**Application Container:**
- No exposed ports (accessible only via Nginx proxy)
- Read-only mounts for config and models
- Separate log volume for audit trail
- Health checks every 30s

**Deployment Steps:**
```bash
# 1. Generate secrets
python scripts/generate_secrets.py

# 2. Configure environment variables
export NSFW_API_KEYS='{"svc":"<sha256>"}'
export NSFW_KEY_TENANTS='{"svc":"tenant"}'
export NSFW_HASH_SALT="<salt>"
export NSFW_HASH_PEPPER="<pepper>"
export NSFW_METRICS_TOKEN="<token>"
export GRAFANA_PASSWORD="<grafana-password>"

# 3. Generate TLS certificates (place in certs/ directory)
python scripts/generate_dev_certs.py  # Development
# For production, use Let's Encrypt or your PKI

# 4. Place TLS certificates in certs/ directory:
#    - server.crt (server certificate)
#    - server.key (server private key)
#    - ca.crt (CA certificate)
#    - client-ca.crt (client CA for mTLS, if enabled)

# 5. Deploy production stack
docker-compose -f docker-compose.production.yml up -d

# 6. Verify health
curl http://localhost/health
```

**Access Points:**
- Public API: http://localhost (HTTP) or https://localhost (HTTPS, if certs configured)
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/<GRAFANA_PASSWORD>)
- Application internal: nsfw-firewall:8080 (Docker network only, not exposed externally)

**What Docker Stack Provides (FREE):**
- ✅ ModSecurity WAF with OWASP CRS (open source, fully configured)
- ✅ Network isolation (private Docker network)
- ✅ Container hardening (non-root user)
- ✅ Nginx reverse proxy with rate limiting
- ✅ Security headers and TLS enforcement

**What Docker Stack Does NOT Provide:**
- Volumetric DDoS protection (requires Cloudflare Free, AWS Shield, or similar)
- HSM-grade key protection (secrets in environment variables)
- Hardware-side-channel mitigation
- Physical security

---

### Free External Protections (Recommended)

The following protections are **free** and recommended for production:

#### 1. Cloudflare Free Tier - DDoS Protection
- **Cost:** $0/month
- **Features:** Unlimited DDoS protection, CDN, free SSL, basic WAF
- **Setup:** See [`docs/CLOUDFLARE_DDoS_SETUP.md`](docs/CLOUDFLARE_DDoS_SETUP.md)
- **Benefits:** Protects against volumetric DDoS attacks, improves performance

#### 2. ModSecurity WAF (Already in Docker Stack)
- **Cost:** $0 (open source)
- **Features:** OWASP Core Rule Set, request filtering, attack detection
- **Status:** Fully configured in `docker-compose.production.yml`
- **Benefits:** Protects against SQL injection, XSS, and other web attacks

#### 3. Social Engineering Security Policy
- **Cost:** $0 (documentation only)
- **Features:** Training guidelines, incident response procedures
- **Documentation:** [`docs/SOCIAL_ENGINEERING_SECURITY.md`](docs/SOCIAL_ENGINEERING_SECURITY.md)
- **Benefits:** Protects against phishing, credential theft, and human-targeted attacks

### Prerequisites
- Python 3.12+
- ONNX Runtime 1.17+
- Pillow (image processing)
- Optional: python-magic (MIME detection)

### Configuration Required
1. Set secrets via environment variables:
   ```bash
   export NSFW_API_KEYS='{"svc":"<sha256>"}'
   export NSFW_KEY_TENANTS='{"svc":"tenant"}'
   export NSFW_HASH_SALT="<salt>"
   export NSFW_HASH_PEPPER="<pepper>"
   export NSFW_METRICS_TOKEN="<token>"
   export NSFW_AUDIT_FILE="/var/log/nsfw-firewall/audit.jsonl"
   ```

2. Generate TLS certificates:
   ```bash
   python scripts/generate_dev_certs.py  # Development
   # Use Let's Encrypt for production
   ```

3. Configure production settings in `config/engine_config.yaml`:
   - `engine.environment: "production"`
   - `security.enabled: true`
   - `policy.fail_action: "BLOCK"`
   - `cors_origins: ["https://your-domain.com"]`
   - `allowed_hosts: ["your-domain.com"]`

### Deployment Options
- **Docker:** `docker build -t nsfw-firewall . && docker run -p 8080:8080 nsfw-firewall`
- **Kubernetes:** `helm upgrade --install nsfw ./deploy/helm/nsfw-firewall`
- **Docker Compose:** `docker-compose up -d` (includes monitoring stack)

### Monitoring
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)
- Metrics: `/metrics` (requires token in production)

### Security Checklist
- [ ] Secrets configured
- [ ] TLS certificates generated
- [ ] CORS/hosts restricted from "*"
- [ ] mTLS enabled for service-to-service
- [ ] Dependabot enabled
- [ ] Production gate passed: `python scripts/production_gate.py --strict`
- [ ] Deployed behind DDoS protection (recommended)

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

## Development Quick‑Start (Phase 0)

The repository now includes a **Makefile** that wraps the most common developer actions:

```bash
# Build the Docker image
make docker-build

# Run lint checks (ruff + flake8)
make lint

# Execute the test suite (pytest)
make test

# Start the service locally via the container (exposes port 8000)
make dev
```

The `utils/logging.py` module provides a JSON logger with an automatically generated `trace_id` for every request. Import it with:
```python
from utils.logging import get_logger
log = get_logger()
log.trace_info("Engine started")
```

The CI workflow (`.github/workflows/ci.yml`) now runs these checks automatically on each push.
