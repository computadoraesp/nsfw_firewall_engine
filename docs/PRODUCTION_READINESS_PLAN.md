# Production Readiness Plan

**Document Version:** 1.0
**Last Updated:** 2026-10-18
**Status:** Draft - Requires Implementation

---

## Executive Summary

This document outlines the complete plan to make the NSFW Firewall Engine production-ready. The system has been security-hardened with ~75-80% of critical vulnerabilities mitigated, but requires additional configuration and validation before production deployment.

**Current State:**
- ✅ Security hardening implemented (fail-closed, authentication, rate limiting, resource limits)
- ✅ 6/9 security tests passing
- ⚠️ Development configuration in place (test keys, missing secrets)
- ⚠️ Python-magic temporarily disabled (Windows compatibility issue)

**Production Goal:**
- Remove all development/test artifacts
- Configure all secrets via environment variables
- Enable all security dependencies
- Verify all security controls are functional
- Establish monitoring and alerting

---

## Phase 1: Secrets and Configuration

### 1.1 Remove Development Artifacts

**Priority:** CRITICAL
**Time Estimate:** 30 minutes

**Actions:**
1. Remove test API key from `config/engine_config.yaml`:
   ```yaml
   security:
     api_keys: {}  # Remove test_key entry
     key_tenants: {}  # Remove test-tenant entry
   ```

2. Remove test key reference from `scripts/stress_test_security.py` (or document it as dev-only)

3. Verify no plaintext secrets in any committed files:
   ```bash
   grep -r "test_key" config/
   grep -r "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" .
   ```

**Validation:**
- No API keys in `config/engine_config.yaml`
- No SHA256 hashes of "test" in the repository
- `Python scripts/audit_config.py --strict` passes

---

### 1.2 Configure Environment Variables

**Priority:** CRITICAL
**Time Estimate:** 1 hour

**Required Variables:**

```bash
# API Keys (generate one per service/component)
export NSFW_API_KEYS='{
  "classifier_svc": "<sha256-of-secret>",
  "monitoring_svc": "<sha256-of-secret>",
  "admin_svc": "<sha256-of-secret>"
}'

# Tenant Binding (map keys to tenants)
export NSFW_KEY_TENANTS='{
  "classifier_svc": "acme-corp",
  "monitoring_svc": "platform",
  "admin_svc": "platform"
}'

# Cryptographic Salts (prevents rainbow table attacks)
export NSFW_HASH_SALT="$(openssl rand -hex 32)"
export NSFW_HASH_PEPPER="$(openssl rand -hex 32)"

# Metrics Protection (bearer token for /metrics)
export NSFW_METRICS_TOKEN="$(openssl rand -hex 32)"

# Audit Trail Persistence
export NSFW_AUDIT_FILE="/var/log/nsfw-firewall/audit.jsonl"

# TLS Certificates (gRPC transport)
export NSFW_TLS_CERT_FILE="/etc/ssl/certs/nsfw-firewall-cert.pem"
export NSFW_TLS_KEY_FILE="/etc/ssl/private/nsfw-firewall-key.pem"
export NSFW_TLS_CA_FILE="/etc/ssl/certs/ca.pem"  # Optional, for mTLS
```

**Key Generation Script:**

```bash
#!/bin/bash
# generate-secrets.sh

# Generate API keys
for key in classifier_svc monitoring_svc admin_svc; do
  secret=$(openssl rand -hex 32)
  hash=$(echo -n "$secret" | sha256sum | cut -d' ' -f1)
  echo "$key: $hash (secret: $secret)"
done

# Generate salts
echo "NSFW_HASH_SALT: $(openssl rand -hex 32)"
echo "NSFW_HASH_PEPPER: $(openssl rand -hex 32)"
echo "NSFW_METRICS_TOKEN: $(openssl rand -hex 32)"
```

**Validation:**
- All environment variables set in production environment
- System starts with environment variables
- API authentication works with generated keys
- `/metrics` requires token when configured

---

### 1.3 Set Production Environment

**Priority:** CRITICAL
**Time Estimate:** 15 minutes

**Configuration Change:**

```yaml
engine:
  environment: "production"  # Change from "development"
```

**Validation:**
- `security.require_auth_in_production` enforcement is active
- Service rejects startup if authentication is disabled
- Dependency validation is enforced (Pillow, Python-magic)

---

## Phase 2: Security Dependencies

### 2.1 Enable Python-magic

**Priority:** HIGH
**Time Estimate:** 2-4 hours

**Current Issue:**
- `Python-magic` import causes hanging on Windows
- Temporarily disabled in `content/mime_detector.py`

**Root Cause Analysis:**
1. Check if libmagic binaries are installed:
   ```bash
   # Linux
   dpkg -l | grep libmagic
   # Windows (via WSL or MSYS2)
   pacman -Qs libmagic
   ```

2. Test import isolation:
   ```Python
   import magic
   print(magic.from_buffer(b'\x89PNG\r\n\x1a\n'))
   ```

**Resolution Options:**

**Option A: Install libmagic binaries (Linux)**
```bash
# Debian/Ubuntu
sudo apt-get install libmagic1

# RHEL/CentOS
sudo yum install file-devel

# Alpine
apk add file-dev
```

**Option B: Use alternative MIME detection (Windows)**
- Keep Python-magic disabled
- Rely on Pillow for image types
- Extend magic-byte table for additional formats
- Accept reduced MIME detection accuracy

**Option C: Containerize (Recommended for Production)**
- Deploy in Linux container (Docker/Kubernetes)
- Linux has native libmagic support
- No Windows-specific issues

**Validation:**
- `Python-magic` imports successfully
- MIME detection works for all configured types
- No hanging on startup
- `validate_security_dependencies()` passes

---

### 2.2 Verify Pillow Installation

**Priority:** HIGH
**Time Estimate:** 15 minutes

**Action:**
```bash
pip install Pillow>=12.0.0
Python -c "from PIL import Image; print(Image.__version__)"
```

**Validation:**
- Pillow imports successfully
- Image dimension validation works
- Decompression bomb protection active (MAX_IMAGE_PIXELS)

---

## Phase 3: TLS and Network Configuration

### 3.1 Generate TLS Certificates

**Priority:** CRITICAL
**Time Estimate:** 1 hour

**For Development/Staging (Self-Signed):**

```bash
# Generate CA
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem

# Generate server certificate
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server-csr.pem
openssl x509 -req -days 365 -in server-csr.pem -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem

# Verify
openssl x509 -in server-cert.pem -text -noout
```

**For Production (Use Certificate Authority):**
- Obtain certificates from Let's Encrypt, DigiCert, or internal CA
- Configure proper certificate chain
- Set up automatic renewal (certbot for Let's Encrypt)

**Validation:**
- Certificates are valid (not expired)
- Certificate chain is complete
- TLS handshake succeeds
- gRPC server starts with TLS enabled

---

### 3.2 Verify Network Binding

**Priority:** HIGH
**Time Estimate:** 30 minutes

**Current Configuration:**
```yaml
transport:
  grpc:
    host: "127.0.0.1"  # Loopback only
  icap:
    host: "127.0.0.1"  # Loopback only
    trusted_proxies:
      - "127.0.0.1/32"
      - "::1/128"
  rest:
    host: "0.0.0.0"  # All interfaces
```

**Validation:**
- gRPC and ICAP are NOT accessible from external networks
- REST is accessible behind load balancer
- Load balancer terminates TLS before REST
- Trusted proxy whitelist matches proxy IP ranges

**If proxy is on different host:**
```yaml
transport:
  icap:
    host: "0.0.0.0"  # Allow remote connections
    trusted_proxies:
      - "10.0.0.0/8"  # Internal network
      - "172.16.0.0/12"
      - "192.168.0.0/16"
```

---

## Phase 4: Rate Limiting Configuration

### 4.1 Set Production Rate Limits

**Priority:** HIGH
**Time Estimate:** 1 hour (analysis) + 15 minutes (configuration)

**Current Development Settings:**
```yaml
security:
  rate_limit_per_second: 10
  rate_limit_burst: 20
```

**Production Calculation:**

**Step 1: Estimate Traffic**
- Expected requests per second: ______
- Peak burst factor: ______ (typically 2-3x)
- Number of tenants: ______

**Step 2: Calculate Per-Tenant Limits**
```
per_tenant_rps = total_rps / number_of_tenants
per_tenant_burst = per_tenant_rps * burst_factor
```

**Example:**
- Total traffic: 1000 req/s
- Tenants: 10
- Burst factor: 2
- Per-tenant: 100 req/s, burst 200

**Configuration:**
```yaml
security:
  rate_limit_per_second: 100  # Per tenant
  rate_limit_burst: 200
  rate_limit_max_keys: 10000  # Maximum concurrent tenant buckets
```

**IP Rate Limiting (dependencies.py):**
```Python
# Update for production
_IP_RATE = 10.0  # tokens per second (development: 0.5)
_IP_CAPACITY = 50  # burst size (development: 5)
```

**Validation:**
- Load test with expected traffic pattern
- Verify legitimate traffic passes
- Verify abuse is throttled
- Monitor 429 responses in production

---

## Phase 5: Monitoring and Alerting

### 5.1 Configure Prometheus Metrics

**Priority:** HIGH
**Time Estimate:** 2 hours

**Current Metrics:**
- `nsfw_requests_total` - Request rate per tenant/endpoint
- `nsfw_request_errors_total` - 5xx rate
- `nsfw_queue_depth` - Requests in flight
- `nsfw_queue_latency_seconds` - Queue time
- `nsfw_startup_time_seconds` - Boot time
- `nsfw_enforcement_total` - ALLOW/BLOCK/REVIEW/QUARANTINE
- `nsfw_dead_letter_total` - Undecidable requests
- `nsfw_pipeline_latency_seconds` - End-to-end latency

**Additional Security Metrics (to add):**
- `nsfw_auth_failures_total` - Authentication failures
- `nsfw_rate_limit_rejections_total` - Rate limit 429s
- `nsfw_circuit_breaker_state` - 0=closed, 1=open, 2=half-open
- `nsfw_malicious_payloads_total` - Rejected payloads (MIME, size, bomb)
- `nsfw_dependency_failures_total` - External dependency failures

**Prometheus Configuration:**

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'nsfw-firewall'
    metrics_path: '/metrics'
    scheme: https
    bearer_token: '${NSFW_METRICS_TOKEN}'
    static_configs:
      - targets: ['nsfw-firewall:8080']
```

**Validation:**
- Prometheus successfully scrapes metrics
- All expected series are present
- Metrics include tenant labels (pseudonymized if enabled)

---

### 5.2 Configure Grafana Dashboard

**Priority:** MEDIUM
**Time Estimate:** 3 hours

**Required Panels:**

1. **Request Rate**
   - Total requests per second
   - Per-tenant breakdown
   - Per-endpoint breakdown

2. **Latency**
   - P50, P95, P99 latency
   - Per-stage latency (Fast/Deep/Multimodal)
   - Queue latency

3. **Error Rate**
   - 5xx error rate
   - Authentication failures
   - Rate limit rejections

4. **Enforcement**
   - ALLOW/BLOCK/REVIEW/QUARANTINE rates
   - NSFW score distribution
   - Per-tenant enforcement patterns

5. **Health**
   - Circuit breaker state
   - Dead-letter queue depth
   - Model availability

6. **Security**
   - Rate limit rejections by IP
   - Malicious payload rejections
   - Dependency failures

**Validation:**
- Dashboard loads without errors
- All panels display data
- Alerts fire on test conditions

---

### 5.3 Configure Alerts

**Priority:** HIGH
**Time Estimate:** 2 hours

**Critical Alerts (PagerDuty/On-call):**

```yaml
# Alertmanager configuration
groups:
  - name: nsfw_firewall_critical
    rules:
      - alert: HighErrorRate
        expr: rate(nsfw_request_errors_total[5m]) > 0.05
        for: 5m
        annotations:
          summary: "High error rate on NSFW firewall"

      - alert: CircuitBreakerOpen
        expr: nsfw_circuit_breaker_state == 1
        for: 1m
        annotations:
          summary: "Circuit breaker is open"

      - alert: DeadLetterQueueOverflow
        expr: nsfw_dead_letter_total > 100
        for: 5m
        annotations:
          summary: "Dead-letter queue is overflowing"

      - alert: AuthenticationFailureSpike
        expr: rate(nsfw_auth_failures_total[5m]) > 10
        for: 5m
        annotations:
          summary: "Authentication failure spike detected"
```

**Warning Alerts (Email/Slack):**

```yaml
  - name: nsfw_firewall_warning
    rules:
      - alert: HighLatency
        expr: histogram_quantile(0.95, nsfw_pipeline_latency_seconds) > 0.5
        for: 10m
        annotations:
          summary: "P95 latency exceeds 500ms"

      - alert: RateLimitRejections
        expr: rate(nsfw_rate_limit_rejections_total[5m]) > 1
        for: 10m
        annotations:
          summary: "High rate of rejections"

      - alert: ModelUnavailable
        expr: nsfw_model_availability == 0
        for: 5m
        annotations:
          summary: "Model is unavailable"
```

**Validation:**
- Alerts fire on test conditions
- Alert routing is correct (critical vs warning)
- Alert suppression/maintenance mode works

---

## Phase 6: Audit and Compliance

### 6.1 Configure Persistent Audit Trail

**Priority:** HIGH
**Time Estimate:** 1 hour

**Configuration:**

```bash
# Create audit directory
sudo mkdir -p /var/log/nsfw-firewall
sudo chown nsfw-firewall:nsfw-firewall /var/log/nsfw-firewall
sudo chmod 750 /var/log/nsfw-firewall

# Set environment variable
export NSFW_AUDIT_FILE="/var/log/nsfw-firewall/audit.jsonl"
```

**Log Rotation (logrotate):**

```bash
# /etc/logrotate.d/nsfw-firewall
/var/log/nsfw-firewall/audit.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 nsfw-firewall nsfw-firewall
    postrotate
        # Send to S3/external storage
        aws s3 cp /var/log/nsfw-firewall/audit.jsonl.1 s3://audit-bucket/
    endscript
}
```

**Validation:**
- Audit file is created and written
- File permissions are correct (640)
- Log rotation works
- External backup (S3) configured

---

### 6.2 Verify Audit Log Content

**Priority:** MEDIUM
**Time Estimate:** 30 minutes

**Check that audit entries include:**
- Timestamp
- Tenant ID (pseudonymized if configured)
- Principal (key ID)
- Action performed
- Verdict
- Media type
- Content SHA256 (not the payload itself)
- Matched policy dimensions

**Validation:**
```bash
# Check recent audit entries
tail -n 10 /var/log/nsfw-firewall/audit.jsonl | jq .

# Verify no payload bytes
grep -r "content_base64" /var/log/nsfw-firewall/  # Should find nothing
```

---

## Phase 7: Testing and Validation

### 7.1 Run Production Gate

**Priority:** CRITICAL
**Time Estimate:** 15 minutes

```bash
Python scripts/production_gate.py --strict
```

**Expected Output:**
```
✓ security_enabled
✓ fail_closed
✓ model_weights_present
✓ configuration_valid
```

**If any check fails:**
- Do NOT deploy
- Fix the issue
- Re-run the gate
- Only deploy when all checks pass

---

### 7.2 Run Security Stress Test

**Priority:** HIGH
**Time Estimate:** 30 minutes

```bash
Python scripts/stress_test_security.py
```

**Expected Results:**
- 9/9 tests passing
- No vulnerabilities detected

**If tests fail:**
- Investigate the failure
- Fix the vulnerability
- Re-run the test
- Only deploy when all tests pass

---

### 7.3 Load Testing

**Priority:** HIGH
**Time Estimate:** 2 hours

**Tool:** Locust, k6, or Apache Bench

**Test Scenarios:**

1. **Baseline Load**
   - 100 req/s sustained for 10 minutes
   - P95 latency < 500ms
   - Error rate < 0.1%

2. **Peak Load**
   - 500 req/s sustained for 5 minutes
   - P95 latency < 1000ms
   - Error rate < 1%

3. **Burst Test**
   - 1000 req/s for 30 seconds
   - Rate limiting activates
   - Service remains responsive

4. **Failure Test**
   - Kill one pod in multi-pod deployment
   - Requests continue to other pods
   - No errors from client perspective

**Validation:**
- All load tests pass
- Latency SLAs met
- Rate limiting works under load
- Circuit breaker doesn't open falsely

---

### 7.4 Model Verification

**Priority:** CRITICAL
**Time Estimate:** 15 minutes

```bash
Python scripts/verify_models.py
```

**Expected Output:**
```
✓ fast_path_mobilenetv3.onnx - SHA256 matches
✓ marqo_nsfw_vit.onnx - SHA256 matches
✓ multimodal_clip.onnx - SHA256 matches
✓ text_distilbert.onnx - SHA256 matches
```

**If verification fails:**
- Do NOT deploy
- Investigate model tampering
- Restore from trusted source
- Re-verify

---

## Phase 8: Deployment

### 8.1 Pre-Deployment Checklist

**Priority:** CRITICAL
**Time Estimate:** 30 minutes

Check all items before deployment:

- [ ] All secrets configured via environment variables
- [ ] Test API keys removed from config
- [ ] `engine.environment` set to "production"
- [ ] `security.enabled: true`
- [ ] `policy.fail_action: BLOCK`
- [ ] Pillow and Python-magic installed
- [ ] Models verified with `verify_models.py`
- [ ] Production gate passes with `--strict`
- [ ] TLS certificates configured and valid
- [ ] Rate limits set for production traffic
- [ ] Authentication verified working
- [ ] Rate limiting verified working
- [ ] Security stress test passes (9/9)
- [ ] Prometheus alerts configured
- [ ] Audit trail persistent storage configured
- [ ] Metrics token configured
- [ ] gRPC/ICAP bound to loopback or trusted network
- [ ] Trusted proxy whitelist configured
- [ ] Tenant binding enabled
- [ ] Load testing completed
- [ ] Rollback plan documented

---

### 8.2 Deployment Strategy

**Priority:** CRITICAL
**Time Estimate:** 1 hour

**Option A: Blue-Green Deployment (Recommended)**

1. Deploy new version to green environment
2. Run smoke tests on green
3. Switch traffic to green
4. Monitor for 30 minutes
5. If issues: switch back to blue
6. If success: decommission blue

**Option B: Rolling Update (Kubernetes)**

```bash
kubectl set image deployment/nsfw-firewall \
  nsfw-firewall=nsfw-firewall:1.0.0 \
  --record

# Monitor rollout
kubectl rollout status deployment/nsfw-firewall

# If issues, rollback
kubectl rollout undo deployment/nsfw-firewall
```

**Option C: Canary Deployment**

1. Deploy to 10% of pods
2. Monitor for 15 minutes
3. If success: deploy to 50%
4. Monitor for 30 minutes
5. If success: deploy to 100%

---

### 8.3 Post-Deployment Validation

**Priority:** CRITICAL
**Time Estimate:** 30 minutes

**Immediate Checks (5 minutes):**
- [ ] Pods are healthy (kubectl get pods)
- [ ] Service is accessible
- [ ] Health endpoint returns 200
- [ ] Metrics are being scraped
- [ ] No errors in logs

**Short-Term Checks (30 minutes):**
- [ ] Request rate matches expected traffic
- [ ] Error rate is < 0.1%
- [ ] P95 latency is < 500ms
- [ ] No circuit breaker openings
- [ ] Dead-letter queue is empty
- [ ] Authentication failures are low
- [ ] Audit log is being written

**Long-Term Checks (24 hours):**
- [ ] Monitor all alerts
- [ ] Review audit logs for anomalies
- [ ] Check rate limit effectiveness
- [ ] Verify model performance
- [ ] Confirm no memory leaks

---

## Phase 9: Maintenance and Operations

### 9.1 Secret Rotation Schedule

**Priority:** MEDIUM
**Time Estimate:** 2 hours per rotation

**Schedule:**
- API keys: Quarterly
- Hash salt/pepper: Annually
- Metrics token: Quarterly
- TLS certificates: Before expiration (automated with certbot)

**Rotation Procedure:**
1. Generate new secrets
2. Update environment variables
3. Graceful restart of service
4. Verify authentication works
5. Monitor for failures
6. Decommission old secrets after 24 hours

---

### 9.2 Dependency Updates

**Priority:** MEDIUM
**Time Estimate:** 4 hours per update cycle

**Monthly:**
- Update Python packages (`pip install -U --upgrade-strategy eager`)
- Review security advisories
- Test updates in staging
- Deploy to production if no breaking changes

**Quarterly:**
- Update ONNX Runtime
- Update base Docker image
- Review model updates
- Run full test suite

---

### 9.3 Security Audit Schedule

**Priority:** MEDIUM
**Time Estimate:** 40 hours per audit

**Annual:**
- External penetration testing
- Code security review
- Dependency vulnerability scan
- Threat model update
- Compliance audit (if applicable)

---

## Rollback Plan

### Trigger Conditions

Rollback immediately if:
- Error rate > 5% for 5 minutes
- P95 latency > 2000ms for 5 minutes
- Circuit breaker opens
- Authentication system fails
- Model inference fails
- Data corruption detected
- Security incident detected

### Rollback Procedure

**Kubernetes:**
```bash
# Immediate rollback
kubectl rollout undo deployment/nsfw-firewall

# Verify
kubectl rollout status deployment/nsfw-firewall
kubectl get pods
```

**Docker:**
```bash
# Stop new version
docker stop nsfw-firewall-new

# Start old version
docker start nsfw-firewall-old

# Verify
curl http://localhost:8080/health
```

**Post-Rollback:**
1. Monitor for 30 minutes
2. Investigate root cause
3. Fix the issue
4. Re-run tests
5. Schedule new deployment

---

## Timeline Summary

| Phase | Tasks | Time Estimate | Priority |
|-------|-------|--------------|----------|
| Phase 1 | Secrets and Configuration | 2 hours | CRITICAL |
| Phase 2 | Security Dependencies | 3-5 hours | HIGH |
| Phase 3 | TLS and Network | 1.5 hours | HIGH |
| Phase 4 | Rate Limiting | 1.25 hours | HIGH |
| Phase 5 | Monitoring and Alerting | 7 hours | HIGH |
| Phase 6 | Audit and Compliance | 1.5 hours | HIGH |
| Phase 7 | Testing and Validation | 3 hours | CRITICAL |
| Phase 8 | Deployment | 2 hours | CRITICAL |
| Phase 9 | Maintenance Plan | 2 hours | MEDIUM |
| **Total** | **All Phases** | **23-25 hours** | - |

**Critical Path:** Phase 1 → Phase 7 → Phase 8 (6.5 hours minimum)

---

## Success Criteria

The system is production-ready when:

1. ✅ All secrets are configured via environment variables
2. ✅ No development artifacts in production config
3. ✅ Security dependencies are installed and validated
4. ✅ TLS is configured and enforced
5. ✅ Rate limiting is tuned for production traffic
6. ✅ Monitoring and alerting are configured
7. ✅ Audit trail is persistent and backed up
8. ✅ Production gate passes with `--strict`
9. ✅ Security stress test passes (9/9)
10. ✅ Load testing meets SLAs
11. ✅ Models are verified and SHA256 matches
12. ✅ Deployment is successful
13. ✅ Post-deployment validation passes

---

## References

- [README.md](../README.md) - Main documentation
- [THREAT_MODEL.md](THREAT_MODEL.md) - Security threat analysis
- [MODEL_PROVENANCE.md](MODEL_PROVENANCE.md) - Model lifecycle and verification
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) - Feature implementation status

---

**Document Owner:** Security Team
**Approval Required:** CTO, Security Lead
**Next Review:** 2026-11-18
