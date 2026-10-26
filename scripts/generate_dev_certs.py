"""Generate self-signed TLS certificates for development/testing.
DO NOT use these certificates in production!
"""

import os
import subprocess
from pathlib import Path

CERT_DIR = Path("certs")
CERT_FILE = CERT_DIR / "nsfw-firewall.crt"
KEY_FILE = CERT_DIR / "nsfw-firewall.key"
CA_FILE = CERT_DIR / "ca.crt"

print("=" * 50)
print("NSFW Firewall Engine - TLS Certificate Generator")
print("=" * 50)
print()
print("WARNING: These are self-signed certificates for development only!")
print("For production, use certificates from a trusted CA (Let's Encrypt, etc.)")
print()

# Create certs directory
CERT_DIR.mkdir(exist_ok=True)

# Generate private key
print("[1/3] Generating private key...")
subprocess.run([
    "openssl", "genrsa", "-out", str(KEY_FILE), "2048"
], check=True)

# Generate self-signed certificate
print("[2/3] Generating self-signed certificate...")
subprocess.run([
    "openssl", "req", "-new", "-x509",
    "-key", str(KEY_FILE),
    "-out", str(CERT_FILE),
    "-days", "365",
    "-subj", "/C=US/ST=State/L=City/O=Organization/OU=IT/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"
], check=True)

# Copy cert as CA for self-signed setup
print("[3/3] Copying certificate as CA...")
import shutil
shutil.copy(CERT_FILE, CA_FILE)

print()
print("=" * 50)
print("Certificates generated successfully!")
print("=" * 50)
print()
print("Files created:")
print(f"  - {CERT_FILE}")
print(f"  - {KEY_FILE}")
print(f"  - {CA_FILE}")
print()
print("Environment variables to set:")
print(f"  set NSFW_TLS_CERT_FILE={CERT_FILE}")
print(f"  set NSFW_TLS_KEY_FILE={KEY_FILE}")
print(f"  set NSFW_TLS_CA_FILE={CA_FILE}")
print()
print("WARNING: Do not use these certificates in production!")
