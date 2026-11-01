#!/usr/bin/env Python3
"""
generate_secrets.py
Generate secrets for NSFW Firewall Engine production deployment
WARNING: Keep the output secure - do not commit to version control
"""

import secrets
import hashlib
import json


def generate_hex(length=64):
    """Generate random hex string (32 bytes = 64 hex chars)"""
    return secrets.token_hex(32)


def generate_api_key(key_id):
    """Generate API key secret and hash"""
    secret = generate_hex()
    hash_digest = hashlib.sha256(secret.encode()).hexdigest()
    return {
        "key_id": key_id,
        "secret": secret,
        "sha256": hash_digest
    }


def main():
    print("=" * 60)
    print("NSFW Firewall Engine - Secret Generation")
    print("=" * 60)
    print()

    # Generate API keys
    print("=== API Keys ===")
    print()
    api_keys = {}
    key_tenants = {}

    for key_id in ["classifier_svc", "monitoring_svc", "admin_svc"]:
        key_data = generate_api_key(key_id)
        print(f"{key_id}:")
        print(f"  secret: {key_data['secret']}")
        print(f"  sha256: {key_data['sha256']}")
        print()
        api_keys[key_id] = key_data['sha256']

    # Map keys to tenants
    key_tenants = {
        "classifier_svc": "acme-corp",
        "monitoring_svc": "platform",
        "admin_svc": "platform"
    }

    # Generate salts
    print("=== Cryptographic Salts ===")
    print()
    hash_salt = generate_hex()
    hash_pepper = generate_hex()
    print(f"NSFW_HASH_SALT: {hash_salt}")
    print(f"NSFW_HASH_PEPPER: {hash_pepper}")
    print()

    # Generate metrics token
    print("=== Metrics Token ===")
    print()
    metrics_token = generate_hex()
    print(f"NSFW_METRICS_TOKEN: {metrics_token}")
    print()

    # Print environment configuration
    print("=" * 60)
    print("Environment Variable Configuration")
    print("=" * 60)
    print()
    print("Copy the following to your environment:")
    print()
    print(f"# API Keys")
    print(f'export NSFW_API_KEYS=\'{json.dumps(api_keys)}\'')
    print()
    print(f"# Tenant Binding")
    print(f'export NSFW_KEY_TENANTS=\'{json.dumps(key_tenants)}\'')
    print()
    print(f"# Cryptographic Salts")
    print(f'export NSFW_HASH_SALT="{hash_salt}"')
    print(f'export NSFW_HASH_PEPPER="{hash_pepper}"')
    print()
    print(f"# Metrics Token")
    print(f'export NSFW_METRICS_TOKEN="{metrics_token}"')
    print()
    print(f"# Audit Trail")
    print(f'export NSFW_AUDIT_FILE="/var/log/nsfw-firewall/audit.jsonl"')
    print()
    print(f"# TLS Certificates (generate separately)")
    print(f'export NSFW_TLS_CERT_FILE="/path/to/cert.pem"')
    print(f'export NSFW_TLS_KEY_FILE="/path/to/key.pem"')
    print(f'export NSFW_TLS_CA_FILE="/path/to/ca.pem"')
    print()

    print("=" * 60)
    print("IMPORTANT SECURITY NOTES")
    print("=" * 60)
    print()
    print("1. Store these secrets securely (e.g., HashiCorp Vault, AWS Secrets Manager)")
    print("2. Rotate secrets quarterly")
    print("3. Never commit secrets to version control")
    print("4. Keep the plaintext API key secrets in a secure location")
    print("5. Only the SHA256 hashes go into NSFW_API_KEYS environment variable")
    print()


if __name__ == "__main__":
    main()
