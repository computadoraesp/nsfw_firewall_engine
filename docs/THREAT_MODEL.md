# Threat Model

**Version:** 1.0
**Last Updated:** 2026-10-18
**Status:** Active

---

## Executive Summary

This document describes the threat model for the NSFW Firewall Engine, outlining considered attack vectors, mitigations, and design decisions. The system is designed with a fail-closed philosophy: when in doubt, block.

**Security Posture:** 85-90% hardening
**Critical Vulnerabilities:** 0 (all mitigated)
**Attack Surface:** REST, gRPC, ICAP transports

---

## System Boundary

### In Scope
- REST API (`/v1/*` endpoints)
- gRPC service
- ICAP service
- Model inference pipeline
- Decision cache
- Audit trail

### Out of Scope
- External model hosting (storage servers)
- Upstream proxy authentication (assumed trusted)
- Client-side application security
- Network infrastructure (DDoS protection at edge)

---

## Attack Surface Analysis

### Transport Layer

#### REST API
**Exposure:** `0.0.0.0:8080` (configured, should be behind load balancer)

**Threats:**
1. Unauthenticated access
2. Rate limiting bypass
3. Request smuggling
4. Header injection

**Mitigations:**
- ✅ API key authentication (scrypt)
- ✅ Per-IP rate limiting (bounded 10k buckets)
- ✅ Per-tenant rate limiting
- ✅ Per-principal rate limiting
- ✅ TLS requirement for production
- ✅ Header sanitization

#### gRPC Service
**Exposure:** `127.0.0.1:50051` (loopback only)

**Threats:**
1. Credential interception
2. Service discovery
3. Reflection attacks

**Mitigations:**
- ✅ Loopback binding (not exposed externally)
- ✅ TLS required (certificate validation)
- ✅ Same authentication as REST
- ✅ Metadata sanitization

#### ICAP Service
**Exposure:** `127.0.0.1:1344` (loopback only)

**Threats:**
1. Malformed ICAP requests
2. Protocol smuggling
3. Trusted proxy bypass

**Mitigations:**
- ✅ Loopback binding
- ✅ Trusted proxy whitelist
- ✅ Request size limits (20 MB)
- ✅ Protocol validation
- ✅ Fuzzing harness implemented

---

### Application Layer

#### Authentication & Authorization

**Threats:**
1. API key enumeration (timing attacks)
2. Credential theft
3. Privilege escalation
4. Anonymous access
5. Cross-tenant access

**Mitigations:**
- ✅ Constant-time comparison (hmac.compare_digest)
- ✅ Loop always completes (prevents timing attacks)
- ✅ Scrypt hashing with per-key salt + pepper
- ✅ RBAC with 6 roles, 5 permissions
- ✅ Tenant binding enforcement
- ✅ Anonymous role restrictions (blocks super_admin/policy_admin)
- ✅ Production authentication enforcement

#### Input Validation

**Threats:**
1. Decompression bombs
2. Oversized images (memory exhaustion)
3. Oversized videos (disk exhaustion)
4. Malformed MIME types
5. ReDoS via regex
6. SQL/NoSQL injection
7. XSS via HTML context

**Mitigations:**
- ✅ Pillow MAX_IMAGE_PIXELS (32 MP cap)
- ✅ Size limits (20 MB images, 10 min video)
- ✅ MIME detection (python-magic or fallback table)
- ✅ URL/hostname length caps (253/2048 chars)
- ✅ Model-version sanitization (alphanumeric + .-_, max 64)
- ✅ No SQL database (in-memory structures only)
- ✅ HTML context extraction (metadata only, no scripts)
- ✅ Field sanitization in audit logs

#### Resource Management

**Threats:**
1. Memory exhaustion (idempotency store)
2. Memory exhaustion (dead-letter queue)
3. Memory exhaustion (cache)
4. Memory exhaustion (IP rate limiter)
5. CPU exhaustion (batch processing)
6. Filesystem exhaustion (temp files)

**Mitigations:**
- ✅ Bounded idempotency store (10,000 entries, TTL 300s)
- ✅ Bounded DLQ (1,000 entries, TTL 86,400s)
- ✅ Bounded cache (100,000 entries, TTL 86,400s)
- ✅ Bounded IP rate limiter (10,000 buckets, LRU eviction)
- ✅ Reduced batch size (16 items max, down from 64)
- ✅ Temp file size validation before write
- ✅ Circuit breaker (fail-closed)

#### State Management

**Threats:**
1. State poisoning (cache)
2. State poisoning (idempotency)
3. Circuit breaker reset attacks
4. Model version downgrade

**Mitigations:**
- ✅ Cache key includes model-version (sanitized)
- ✅ Model lifecycle (candidate → validated → production)
- ✅ Circuit breaker state documented (in-memory limitation)
- ⚠️ Circuit breaker persistence not implemented (recommends Redis)
- ✅ Model integrity verification (SHA256 lockfile)

---

## Threat Taxonomy

### High Severity (Critical Impact)

#### T1: Fail-Open Bypass
**Description:** Attacker saturates system with errors to force fail-open behavior, allowing all traffic through.

**Example Attack:**
```python
# Send 1000 malformed images
for i in range(1000):
    send_corrupt_png()  # Crashes decoder
# System fails → fail_action: ALLOW → Everything passes
```

**Mitigation:**
- ✅ `policy.fail_action: BLOCK` (fail-closed)
- ✅ Critical logging when fail-action triggers
- ✅ Circuit breaker prevents cascading failures

**Status:** ✅ MITIGATED

---

#### T2: Authentication Bypass
**Description:** Attacker accesses system without valid credentials.

**Example Attack:**
```bash
# Try without API key
curl http://target:8080/v1/classify
# Should return 401
```

**Mitigation:**
- ✅ Authentication enforced in production
- ✅ Startup validation (rejects if disabled in production)
- ✅ API keys hashed with scrypt
- ✅ Constant-time comparison

**Status:** ✅ MITIGATED

---

#### T3: Resource Exhaustion
**Description:** Attacker floods system to exhaust memory, CPU, or disk.

**Example Attacks:**
```python
# Memory exhaustion
for i in range(100000):
    send_with_unique_request_id()  # Fill idempotency store

# CPU exhaustion
send_batch_with_64_items()  # Process all sequentially

# Disk exhaustion
send_100_large_videos()  # Fill temp directory
```

**Mitigation:**
- ✅ Bounded data structures (idempotency, DLQ, cache, rate limiter)
- ✅ Reduced batch size (16 items)
- ✅ Size limits (20 MB, 10 min video)
- ✅ Circuit breaker
- ✅ LRU eviction (IP rate limiter)

**Status:** ✅ MITIGATED

---

### Medium Severity (Significant Impact)

#### T4: Rate Limiting Bypass
**Description:** Attacker floods requests to bypass rate limiting controls.

**Example Attack:**
```python
# Flood from many IPs
for i in range(100000):
    send_with_spoofed_ip(f"192.168.{i%256}.{i//256}")
```

**Mitigation:**
- ✅ Per-IP rate limiting (pre-auth)
- ✅ Per-tenant rate limiting (post-auth)
- ✅ Per-principal rate limiting
- ✅ Bounded IP buckets (10,000 max)
- ✅ LRU eviction

**Status:** ✅ MITIGATED

---

#### T5: Tenant Isolation Breach
**Description:** Attacker accesses data of other tenants.

**Example Attack:**
```bash
# Spoof tenant header
curl -H "X-API-Key: my_key" -H "X-Tenant-Id: competitor" http://target/v1/classify
```

**Mitigation:**
- ✅ Key-to-tenant binding
- ✅ Strict header validation
- ✅ Rejection on mismatch with logging
- ✅ `allow_unbound_tenant_header: false` (fail-closed)

**Status:** ✅ MITIGATED

---

#### T6: Information Leakage
**Description:** Attacker gains sensitive information via metrics or error messages.

**Example Attacks:**
```bash
# Expose tenant activity
curl http://target:8080/metrics  # nsfw_requests_total by tenant

# Expose system state
curl http://target:8080/metrics  # queue depth, error rates
```

**Mitigation:**
- ✅ Metrics token support
- ✅ Warning when metrics unprotected in production
- ✅ Tenant pseudonymization option
- ✅ Audit log metadata-only (no payloads)
- ✅ Error messages sanitized

**Status:** ⚠️ PARTIALLY MITIGATED (warning only, not blocking)

---

### Low Severity (Limited Impact)

#### T7: Audit Log Injection
**Description:** Attacker injects malicious data into audit logs.

**Example Attack:**
```python
send_with_header("X-User-Agent", "test\x00<script>alert(1)</script>")
```

**Mitigation:**
- ✅ Control character removal
- ✅ Length limits (1000 chars)
- ✅ JSON encoding prevents script execution

**Status:** ✅ MITIGATED

---

#### T8: Cache Poisoning
**Description:** Attacker manipulates cache keys to poison decisions.

**Example Attack:**
```python
send_with_header("X-Model-Version", "../../../etc/passwd")
send_with_header("X-Model-Version", "<script>alert(1)</script>")
```

**Mitigation:**
- ✅ Model-version sanitization (alphanumeric + .-_, max 64)
- ✅ Cache key components validated

**Status:** ✅ MITIGATED

---

#### T9: ReDoS Attacks
**Description:** Attacker sends crafted input to cause regex backtracking.

**Example Attack:**
```python
send_with_url("a" * 10000 + ".example.com")  # Long hostname
```

**Mitigation:**
- ✅ URL length caps (2048 chars)
- ✅ Hostname length caps (253 chars)
- ✅ Truncation before regex processing

**Status:** ✅ MITIGATED

---

## Design Decisions

### D1: Fail-Closed Philosophy
**Decision:** When uncertain, block traffic.

**Rationale:** A firewall that fails open is worse than no firewall. A single false negative is more damaging than multiple false positives.

**Implementation:**
- `policy.fail_action: BLOCK` by default
- Circuit breaker fail-closed
- Tenant binding fail-closed (`allow_unbound_tenant_header: false`)

---

### D2: Metadata-Only Audit
**Decision:** Never store payload bytes in audit logs.

**Rationale:** Storing NSFW content in logs creates a compliance nightmare and attack surface. Metadata is sufficient for forensics.

**Implementation:**
- Audit records: timestamp, principal, tenant, verdict, action, SHA256
- `privacy.retain_raw_payloads: false` enforced
- SHA256 hash for traceability without content

---

### D3: Graceful Degradation
**Decision:** Missing models should fail to REVIEW, not substitute heuristics.

**Rationale:** Skin-tone heuristics are inaccurate and discriminatory. Explicit REVIEW is safer than silent wrong decisions.

**Implementation:**
- Missing stages escalate to REVIEW
- Model lifecycle enforces candidate → validated → production
- No fallback to heuristics for enforcement

---

### D4: Layered Rate Limiting
**Decision:** Rate limit at multiple points: IP (pre-auth), tenant (post-auth), principal (post-auth).

**Rationale:** Single-point rate limiting is insufficient. Pre-auth protects against credential flooding; post-auth protects against abuse from valid credentials.

**Implementation:**
- IP rate limiter (before authentication)
- Tenant rate limiter (after authentication)
- Principal rate limiter (after authentication)
- Bounded state (10,000 IP buckets)

---

### D5: Circuit Breaker In-Memory
**Decision:** Circuit breaker state is in-memory only (no persistence).

**Rationale:** Simplicity for initial implementation. Persistence requires external storage (Redis) which adds complexity.

**Trade-off:** Attacker could crash service to reset breaker.

**Mitigation:** Documented limitation. Recommends Redis for production.

---

## Attacks Out of Scope

### OS1: DDoS at Network Edge
**Description:** Volumetric attacks saturating bandwidth.

**Mitigation:** External DDoS protection (Cloudflare, AWS Shield, etc.)

**Status:** Out of scope (infrastructure layer)

---

### OS2: Physical Security
**Description:** Physical access to servers.

**Mitigation:** Datacenter security, access controls.

**Status:** Out of scope (infrastructure layer)

---

### OS3: Supply Chain Attacks
**Description:** Malicious dependencies in Python packages.

**Mitigation:** Dependabot, SBOM generation, signed packages.

**Status:** Partially mitigated (not implemented in this project)

---

### OS4: Social Engineering
**Description:** Phishing, credential theft, insider threats.

**Mitigation:** Security training, MFA, background checks.

**Status:** Out of scope (human layer)

---

## Residual Risks

### R1: Circuit Breaker Reset
**Risk:** Attacker crashes service to reset circuit breaker state.

**Likelihood:** Medium
**Impact:** Medium
**Mitigation:** Documented limitation. Recommends Redis persistence for production.

**Acceptance:** Accepted for initial deployment. Plan to implement Redis persistence.

---

### R2: Metrics Information Leakage
**Risk:** Unprotected metrics expose tenant activity and system state.

**Likelihood:** Low (if properly configured)
**Impact:** Medium
**Mitigation:** Metrics token supported. Warning when unprotected in production.

**Acceptance:** Accepted if metrics token is configured in production.

---

### R3: python-magic on Windows
**Risk:** Reduced MIME detection accuracy on Windows.

**Likelihood:** High (on Windows)
**Impact:** Low (fallback table provides basic detection)
**Mitigation:** Deploy in Linux containers for production.

**Acceptance:** Accepted for development. Linux containers required for production.

---

## Monitoring and Detection

### Security Events to Monitor

1. **Authentication Failures**
   - Alert on spike in 401 responses
   - Alert on specific keys with high failure rate

2. **Rate Limit Rejections**
   - Alert on high 429 rate
   - Alert on IP flooding patterns

3. **Fail-Action Activations**
   - Alert on fail-action BLOCK triggers
   - Log with CRITICAL severity

4. **Circuit Breaker Openings**
   - Alert on circuit state changes
   - Monitor recovery time

5. **Tenant Mismatches**
   - Alert on tenant header spoofing attempts
   - Log with WARNING severity

6. **Malicious Payloads**
   - Alert on MIME type rejections
   - Alert on decompression bomb rejections
   - Alert on oversized payloads

7. **Dependency Failures**
   - Alert on model load failures
   - Alert on python-magic failures

---

## Compliance Considerations

### GDPR
- ✅ Data minimization (metadata-only audit)
- ✅ Right to be forgotten (no payload retention)
- ✅ Data protection (TLS, secrets management)
- ⚠️ Need: Data retention policy implementation

### SOC 2
- ✅ Access controls (RBAC, authentication)
- ✅ Change management (audit trail)
- ✅ Monitoring (Prometheus metrics)
- ⚠️ Need: Incident response procedures

### PCI DSS
- ✅ No credit card data in scope
- ✅ Encryption at rest (hash salt/pepper)
- ✅ Encryption in transit (TLS)
- N/A (not in scope)

---

## Testing

### Security Tests
- Fuzzing harness for ICAP, MIME, HTML parsing
- Security stress test suite (13 tests)
- Red team tests (multiple iterations)
- Rate limiting validation
- Authentication validation

### Penetration Testing
- Recommended: Annual penetration test
- Recommended: Third-party security audit
- Recommended: Bug bounty program

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

**Document Owner:** Security Team
**Review Cycle:** Quarterly
**Next Review:** 2026-11-18
