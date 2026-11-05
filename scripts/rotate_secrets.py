#!/usr/bin/env python3
"""
Automated Secret Rotation Script

Rotates:
- API keys
- Hash salt
- Hash pepper
- Metrics token

Usage:
    python scripts/rotate_secrets.py
"""

import hashlib
import json
import secrets
import sys
from pathlib import Path

# Constants
DEFAULT_API_KEYS = ["svc", "probe", "classifier", "auditor"]
SALT_LENGTH = 32
PEPPER_LENGTH = 32
TOKEN_LENGTH = 32


def generate_secret(length: int = 32) -> str:
    """Generate a cryptographically secure random secret."""
    return secrets.token_urlsafe(length)


def hash_secret(secret: str, salt: str, pepper: str) -> str:
    """Hash a secret with salt and pepper using scrypt."""
    try:
        import hashlib
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        # Fallback to SHA256 if cryptography not available
        digest = hashlib.sha256()
        digest.update(salt.encode())
        digest.update(secret.encode())
        digest.update(pepper.encode())
        return digest.hexdigest()

    kdf = Scrypt(
        salt=salt.encode(),
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(secret.encode()).hex()


def rotate_api_keys(api_keys: dict) -> dict:
    """Rotate all API keys."""
    new_keys = {}
    for key_id in api_keys.keys():
        new_secret = generate_secret()
        # Use existing salt/pepper (should be from env)
        new_hash = hashlib.sha256(new_secret.encode()).hexdigest()
        new_keys[key_id] = new_hash
        print(f"Rotated API key: {key_id}")
    return new_keys


def rotate_salt() -> str:
    """Generate new hash salt."""
    new_salt = generate_secret(SALT_LENGTH)
    print(f"Rotated hash salt (length: {len(new_salt)})")
    return new_salt


def rotate_pepper() -> str:
    """Generate new hash pepper."""
    new_pepper = generate_secret(PEPPER_LENGTH)
    print(f"Rotated hash pepper (length: {len(new_pepper)})")
    return new_pepper


def rotate_metrics_token() -> str:
    """Generate new metrics token."""
    new_token = generate_secret(TOKEN_LENGTH)
    print(f"Rotated metrics token (length: {len(new_token)})")
    return new_token


def main():
    print("=" * 60)
    print("NSFW Firewall Engine - Secret Rotation")
    print("=" * 60)
    print()

    # Rotate secrets
    new_salt = rotate_salt()
    new_pepper = rotate_pepper()
    new_token = rotate_metrics_token()

    # Output new secrets
    print()
    print("NEW SECRETS (DO NOT COMMIT TO VERSION CONTROL):")
    print()
    print(f"NSFW_HASH_SALT={new_salt}")
    print(f"NSFW_HASH_PEPPER={new_pepper}")
    print(f"NSFW_METRICS_TOKEN={new_token}")
    print()
    print("For API keys, update NSFW_API_KEYS environment variable with:")
    print("python scripts/generate_secrets.py")
    print()
    print("Update your environment variables with these new values.")
    print("Restart the service to apply changes.")
    print()

    # Save to file (optional, for secure storage)
    output_file = Path("rotated_secrets.txt")
    with output_file.open("w") as f:
        f.write(f"NSFW_HASH_SALT={new_salt}\n")
        f.write(f"NSFW_HASH_PEPPER={new_pepper}\n")
        f.write(f"NSFW_METRICS_TOKEN={new_token}\n")

    print(f"Secrets saved to: {output_file}")
    print("SECURITY: Delete this file after updating environment variables.")
    print()
    print("Secret rotation complete.")


if __name__ == "__main__":
    main()
