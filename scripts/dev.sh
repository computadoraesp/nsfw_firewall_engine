#!/bin/bash
# Development helper script for NSFW Firewall Engine

set -e

echo "=========================================="
echo "NSFW Firewall Engine - Development"
echo "=========================================="
echo ""

# Check Python version
echo "[1/5] Checking Python version..."
Python --version || Python3 --version

# Install dependencies
echo "[2/5] Installing dependencies..."
pip install -e ".[dev]" || pip install -r requirements.txt

# Generate test secrets
echo "[3/5] Generating test secrets..."
Python scripts/generate_secrets.py

# Set environment variables
echo "[4/5] Setting environment variables..."
export NSFW_API_KEYS='{"test_key":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}'
export NSFW_KEY_TENANTS='{"test_key":"test-tenant"}'
export NSFW_HASH_SALT="test-salt-32-bytes-123456789012345678901234"
export NSFW_HASH_PEPPER="test-pepper-32-bytes-abcdef1234567890abcdef"
export NSFW_ENGINE_CONFIG="config/engine_config.yaml"

# Run configuration validation
echo "[5/5] Validating configuration..."
Python scripts/production_gate.py || echo "Note: Production gate may fail in development mode"

echo ""
echo "=========================================="
echo "Development environment ready!"
echo "=========================================="
echo ""
echo "To start the server:"
echo "  Python -m app.main"
echo ""
echo "To run security tests:"
echo "  Python scripts/stress_test_security.py"
echo ""
echo "To run unit tests:"
echo "  Python -m pytest tests/"
echo ""
