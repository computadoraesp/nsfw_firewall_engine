#!/bin/bash
# Generate self-signed TLS certificates for development/testing
# DO NOT use these certificates in production!

set -e

CERT_DIR="./certs"
CERT_FILE="$CERT_DIR/nsfw-firewall.crt"
KEY_FILE="$CERT_DIR/nsfw-firewall.key"
CA_FILE="$CERT_DIR/ca.crt"

echo "=========================================="
echo "NSFW Firewall Engine - TLS Certificate Generator"
echo "=========================================="
echo ""
echo "WARNING: These are self-signed certificates for development only!"
echo "For production, use certificates from a trusted CA (Let's Encrypt, etc.)"
echo ""

# Create certs directory
mkdir -p "$CERT_DIR"

# Generate private key
echo "[1/3] Generating private key..."
openssl genrsa -out "$KEY_FILE" 2048

# Generate self-signed certificate
echo "[2/3] Generating self-signed certificate..."
openssl req -new -x509 -key "$KEY_FILE" -out "$CERT_FILE" -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=IT/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

# Copy cert as CA for self-signed setup
echo "[3/3] Copying certificate as CA..."
cp "$CERT_FILE" "$CA_FILE"

echo ""
echo "=========================================="
echo "Certificates generated successfully!"
echo "=========================================="
echo ""
echo "Files created:"
echo "  - $CERT_FILE"
echo "  - $KEY_FILE"
echo "  - $CA_FILE"
echo ""
echo "Environment variables to set:"
echo "  export NSFW_TLS_CERT_FILE=\"$CERT_FILE\""
echo "  export NSFW_TLS_KEY_FILE=\"$KEY_FILE\""
echo "  export NSFW_TLS_CA_FILE=\"$CA_FILE\""
echo ""
echo "WARNING: Do not use these certificates in production!"
