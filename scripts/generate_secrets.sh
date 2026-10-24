#!/bin/bash
# generate_secrets.sh
# Generate secrets for NSFW Firewall Engine production deployment
# WARNING: Keep the output secure - do not commit to version control

set -e

echo "============================================================"
echo "NSFW Firewall Engine - Secret Generation"
echo "============================================================"
echo ""

# Function to generate random hex string
generate_hex() {
    openssl rand -hex 32
}

# Function to generate API key secret and hash
generate_api_key() {
    local key_id=$1
    local secret=$(generate_hex)
    local hash=$(echo -n "$secret" | sha256sum | cut -d' ' -f1)
    echo "$key_id:"
    echo "  secret: $secret"
    echo "  sha256: $hash"
    echo ""
}

echo "=== API Keys ==="
echo ""
generate_api_key "classifier_svc"
generate_api_key "monitoring_svc"
generate_api_key "admin_svc"

echo "=== Cryptographic Salts ==="
echo ""
echo "NSFW_HASH_SALT: $(generate_hex)"
echo "NSFW_HASH_PEPPER: $(generate_hex)"
echo ""

echo "=== Metrics Token ==="
echo ""
echo "NSFW_METRICS_TOKEN: $(generate_hex)"
echo ""

echo "============================================================"
echo "Environment Variable Configuration"
echo "============================================================"
echo ""
echo "Copy the following to your environment:"
echo ""
echo "# API Keys (replace <sha256> with actual hashes above)"
echo 'export NSFW_API_KEYS='"'"'{"classifier_svc":"<sha256>","monitoring_svc":"<sha256>","admin_svc":"<sha256>"}'"'"'
echo ""
echo "# Tenant Binding"
echo 'export NSFW_KEY_TENANTS='"'"'{"classifier_svc":"acme-corp","monitoring_svc":"platform","admin_svc":"platform"}'"'"'
echo ""
echo "# Cryptographic Salts (use the generated values)"
echo 'export NSFW_HASH_SALT="<value>"'
echo 'export NSFW_HASH_PEPPER="<value>"'
echo ""
echo "# Metrics Token"
echo 'export NSFW_METRICS_TOKEN="<value>"'
echo ""
echo "# Audit Trail"
echo 'export NSFW_AUDIT_FILE="/var/log/nsfw-firewall/audit.jsonl"'
echo ""
echo "# TLS Certificates (generate separately)"
echo 'export NSFW_TLS_CERT_FILE="/path/to/cert.pem"'
echo 'export NSFW_TLS_KEY_FILE="/path/to/key.pem"'
echo 'export NSFW_TLS_CA_FILE="/path/to/ca.pem"'
echo ""
echo "============================================================"
echo "IMPORTANT SECURITY NOTES"
echo "============================================================"
echo ""
echo "1. Store these secrets securely (e.g., HashiCorp Vault, AWS Secrets Manager)"
echo "2. Rotate secrets quarterly"
echo "3. Never commit secrets to version control"
echo "4. Keep the plaintext API key secrets in a secure location"
echo "5. Only the SHA256 hashes go into NSFW_API_KEYS environment variable"
echo ""
