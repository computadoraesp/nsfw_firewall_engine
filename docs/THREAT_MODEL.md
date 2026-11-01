# Threat Model

## Scope
- **In‑scope components**: API Service (REST/gRPC/ICAP), Model Inference, Policy Engine, Decision Core, Cache Layer, Ingress Proxies (Squid, NGINX, Envoy, HAProxy).
- **Out‑of‑scope**: Underlying cloud provider infrastructure, OS kernel, hardware failures, user‑generated malicious content that never reaches the service (e.g., phishing emails).

## Threat Actors
| Actor | Motivation | Capability |
|-------|------------|------------|
| External attacker | Bypass NSFW detection, cause denial‑of‑service | Network access, crafted image payloads |
| Malicious insider | Extract model weights, tamper policy rules | Direct repo access |
| Automated bots | Flood service with traffic to exhaust resources | Scripted HTTP/gRPC/ICAP requests |
| Third‑party proxy misconfiguration | Improper forwarding leading to data leakage | Limited control over proxy config |

## Attack Surface
1. **Ingress Layer** – HTTP, gRPC, ICAP endpoints. Potential for protocol‑specific attacks (e.g., malformed ICAP headers, HTTP request smuggling).
2. **Model Loading** – Loading untrusted ONNX files could lead to remote code execution if the runtime is vulnerable.
3. **Policy Engine** – YAML rule injection, unsafe regex patterns.
4. **Cache Layer** – Cache poisoning, stale data exposure.
5. **Observability Interfaces** – Logs and metrics endpoints could expose internal state.

## Threat Scenarios & Mitigations
| # | Scenario | Impact | Mitigation |
|---|----------|--------|------------|
| 1 | **Malformed payload** (oversized image, unsupported MIME) | Crash, DoS | Strict MIME validation, configurable max payload size, graceful error handling |
| 2 | **ONNX model tampering** (replace with malicious model) | Arbitrary code exec / inaccurate classification | SHA‑256 checksum verification on start‑up (recorded in `MODEL_PROVENANCE.md`), read‑only mount for model directory |
| 3 | **Policy rule injection** (YAML with `!!Python/object`) | Privilege escalation, rule bypass | Use safe YAML loader (`yaml.safe_load`), schema validation before loading |
| 4 | **Cache poisoning** (inject crafted key/value) | Incorrect allow/deny decisions | Sign cache entries with HMAC keyed by `model_version`, enforce TTL, validate on read |
| 5 | **Rate‑limit evasion** (bot sends many small requests) | Resource exhaustion | Global request rate limiting (token bucket), per‑tenant quotas, back‑pressure via 429 responses |
| 6 | **Side‑channel leakage via logs** (include raw payload) | Privacy breach | Ensure logs contain only hashes or metadata, never raw image bytes |
| 7 | **Proxy misconfiguration** (open relay) | Unauthenticated external access | Require TLS mutual auth for gRPC/ICAP, restrict source IPs for admin endpoints |

## Security Controls
- **Defense‑in‑depth**: Validation at ingress, model loading, policy evaluation, and post‑processor stages.
- **Transport security**: TLS 1.3 for all external endpoints; optional mTLS for internal service‑to‑service calls.
- **Authentication & Authorization**: API keys or JWT for tenant identification; role‑based access for admin APIs.
- **Monitoring & Alerting**: Prometheus alerts on error spikes, high latency, abnormal request patterns; OpenTelemetry trace propagation.
- **Patch Management**: Regular updates of ONNX runtime and dependent libraries.
- **Backup & Recovery**: Store `MODEL_PROVENANCE.md` and policy files in version‑controlled repo; enable automated rollback.

## Open Issues / Future Work
- Formal pen‑test report (external audit).
- Automated threat‑model validation CI step (e.g., tfsec‑like for config).
- Integration with secret management for API keys.

---
*Document version: 0.1 – created 2026‑10‑25.*
