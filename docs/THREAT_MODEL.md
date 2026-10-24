# Threat Model (§17 / §38)

Scope: the engine and its three transports (gRPC, ICAP, REST), the policy
layer, the content inspector, the shared caches and the model paths. Threats
are rated **Likelihood × Impact** (H/M/L).

> **Status: revised after five adversarial iterations.** This document used to
> describe controls that did not exist — it claimed MIME enforcement "on the
> enforcement path" when the allow-list was consulted nowhere, described tenant
> escape as "mitigated" when nothing bound a key to a tenant, and stated
> `policy.fail_action: ALLOW` when the shipped value is `BLOCK`. A threat model
> that overstates its own coverage is worse than none, because an operator
> reads it as assurance. Every row below reflects code that is covered by an
> executable test.

| # | Threat | L | I | Mitigation | Status |
|---|--------|---|---|------------|--------|
| 1 | **Malicious media** (decoder RCE via crafted JPEG/PNG) | M | H | `max_image_bytes`, `max_image_dim`, `max_pixels` enforced *before* decoding; Pillow and libmagic are **required in the runtime image**, not optional — a missing Pillow used to silently disable dimension validation. MIME allow-list is enforced on the classification path, so ZIP/PDF/ELF/EXE never reach a native decoder | Mitigated |
| 2 | **Decompression / resource-exhaustion bomb** | H | H | `preprocessing.max_pixels` (32 MP) checked against the **real** pixel count, because Pillow only raises above 2× `MAX_IMAGE_PIXELS` and merely warns in between — the 64–128 MP band used to pass; video `max_video_duration_s` and `max_frames`; ICAP `max_body_bytes`; gRPC message caps | Mitigated |
| 3 | **SSRF** | M | H | The engine **never fetches URLs** — it inspects supplied bytes only. URLs are parsed as *text signals*, never dereferenced | Mitigated by design |
| 4 | **MIME spoofing** | H | M | Magic-byte detection is authoritative, not `Content-Type`; the allow-list is enforced (`enforce_mime=True`) and callers check `allowed`, not only `valid`. Unidentifiable payloads (`application/octet-stream`) are refused rather than passed to a decoder | Mitigated |
| 5 | **Cache poisoning / staleness** | M | H | Key binds `model_version` + `preprocess_version` + **tenant**; overrides bypass the cache; failures are never stored. Only the *classification* is cached — `action`/`policy_id` are blanked on a hit and re-derived per tenant | Mitigated |
| 6 | **Policy bypass** | M | H | Declarative first-match-wins rules; no `eval`. Replacing the **global** policy requires `SUPER_ADMIN`. `matches` patterns are screened for catastrophic backtracking at install time and the subject is truncated | Mitigated |
| 7 | **Tenant escape / cross-tenant leakage** | M | H | `security.key_tenants` binds a key to a tenant and the binding is **authoritative** — a disagreeing `X-Tenant-Id` is refused, and an unbound key may not assert one. Policy reads/writes fail closed; the decision cache is partitioned per tenant | Mitigated |
| 8 | **Credential exposure** | M | H | API keys are scrypt-hashed with a per-key random salt and an environment pepper; they are **never committed** (the repository previously shipped the digest of the word `test`). gRPC **requires TLS** — it used to call `add_insecure_port` on `0.0.0.0`, sending the key in cleartext | Mitigated |
| 9 | **Malicious / tampered model artifact** | M | H | Models are mounted read-only; `scripts/verify_models.py` enforces a committed SHA256 lockfile and fails on mismatch, missing artifact, or unvetted `.onnx` | Mitigated — run as a CI gate |
| 10 | **Model poisoning via training data** | L | H | §40 forbids training in this project | N/A here |
| 11 | **Secret leakage in logs** | M | H | Structured logging carries metadata and decisions only; `retain_raw_payloads: false`. Content digests are salted from `${NSFW_HASH_SALT}` — the committed literal was a constant, not a salt | Mitigated |
| 12 | **API abuse / DoS** | H | H | Token bucket on **all three transports** (gRPC and ICAP had none). ICAP additionally enforces a per-peer budget. Prometheus labels are cardinality-bounded and tenants pseudonymised | Mitigated |
| 13 | **ReDoS** | M | H | The HTML stripper used a `.*?` pattern with `DOTALL` that was quadratic in the unclosed-tag case (measured 4× time per 2× input); rewritten as an unrolled loop and input-capped. Policy regexes screened at install time | Mitigated |
| 14 | **Unauthenticated classification** | H | H | Every data endpoint on every transport requires a permission. `/classify/text` and `/classify/raw` previously had **no** security dependency whatsoever | Mitigated |
| 15 | **Spoofed §19 context headers** | M | M | `X-User-Groups` / `X-Zone` / `X-Device-Id` are client-assertable. The authenticated principal always outranks headers and **authorisation never reads them** | Accepted, documented |
| 16 | **Undecidable request silently allowed** | M | H | Dead-letter queue captures any result carrying an `error`, with its SHA256 and never the payload; the cache refuses to store failures so one tenant's error cannot become another's | Mitigated |
| 17 | **Heuristic mistaken for a detector** | M | **H** | Stub models report `healthy: false` and `/v1/ready` → `false`; liveness is deliberately separate from readiness so a pod is withdrawn rather than killed | Mitigated (operator discipline) |
| 18 | **Audit trail destruction** | M | H | Append-only JSONL sink so records outlive the process. The trail was a `deque` in RAM — every restart erased the evidence, exactly when it is wanted | Mitigated |
| 19 | **Transport-level enumeration** | M | M | ICAP is bound to loopback behind `transport.icap.trusted_proxies` (a CIDR allow-list that fails **closed** on a typo), and its tenant comes from `transport.icap.default_tenant` rather than a request header. gRPC and ICAP both default to loopback. `/health` no longer reports `api_keys_configured`; `/metrics` tenant labels are pseudonymised and the scrape can require `observability.metrics_token` | Mitigated |

## Verified by attack, not by assertion

`tests/test_redteam*.py` is an exploit harness: each test performs the real
attack over a real ASGI app or a real socket and asserts the security property.
A failure means the vulnerability is **live**, not that the test is wrong.

| Suite | Attacks |
|-------|---------|
| `test_redteam.py` | Unauthenticated classification, tenant spoofing (header and query-parameter), policy cross-tenant read/write, metric cardinality, fail-open config |
| `test_redteam_iter2.py` | ReDoS complexity, unbounded input, base64 smuggling, MIME allow-list, decompression bombs, video guards, path traversal |
| `test_redteam_iter3.py` | ICAP access control and tenant header (over a live socket), gRPC/REST parity, KDF, repo hygiene |
| `test_redteam_iter4.py` | Cleartext credentials, missing throttles, audit durability, metric disclosure |
| `test_redteam_iter5.py` | Cross-tenant cache isolation, policy regex safety |
| `test_redteam_iter6.py` | Redis index desync, concurrency regression, this document's accuracy |

## Residual risks

1. **Credentials must be provisioned externally.** `security.api_keys` ships
   empty and keys arrive via `NSFW_API_KEYS`. A deployment that starts with none
   is *correctly* refused by `scripts/production_gate.py` — but the gate has to
   actually be run. This is a deployment responsibility code cannot enforce.
2. **gRPC TLS material is an operator action.** The server now refuses to start
   without it, so the failure mode is a loud refusal rather than a silent
   plaintext listener.
3. **Content-inspection completeness still depends on the installed decoders.**
   They are now required in the image, but a slim image that drops them will
   fall back to the PPM path.
4. **Latency budgets are detect-and-fail-safe, not hard preemption.** Python
   cannot interrupt an in-flight native decode. The *decision* is always bounded
   and fails into `policy.fail_action`; a hard ceiling belongs in front of the
   service.
5. **No labelled evaluation corpus**, so §49 quality claims cannot be produced
   and every model is stuck at `candidate`. A data gap, not a code gap — see
   [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).
6. **The shipped ONNX artifacts do not load with the pinned runtime** (model IR
   14 vs onnxruntime's maximum of 13). The engine degrades to a stub, which is
   fail-safe but means the deep path is not actually running in this checkout.
7. **The Redis backend is covered only by an in-memory fake.** The pipeline
   semantics were exercised against a stand-in, not a live Redis; run the store
   against a real instance before relying on it.

## Verification

Security-relevant behaviour is covered by the automated suite, plus the red-team
harness above. CI additionally runs `scripts/fuzz.py` (§37) over the ICAP, MIME
and HTML parsers, `bandit`, and `scripts/production_gate.py`.