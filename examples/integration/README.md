# Integration Examples Directory

This directory contains ready-to-use configuration examples for integrating
the NSFW Firewall Engine with various proxies and firewalls.

## Available Integrations

- **SQUID_ICAP.md** - Squid proxy with ICAP protocol
- **NGINX_REST.md** - NGINX reverse proxy with REST API
- **ENVOY_REST.md** - Envoy proxy with REST API (coming soon)

## Quick Start

1. Choose your proxy/firewall
2. Copy the configuration from the corresponding .md file
3. Adjust hostnames, ports, and authentication as needed
4. Reload your proxy configuration
5. Test the integration

## Common Requirements

All integrations assume:
- NSFW Firewall Engine is running on `127.0.0.1`
- REST API on port `8080`
- ICAP service on port `1344`
- gRPC service on port `50051`

## Testing

After configuration, test with:

```bash
# Health check
curl http://127.0.0.1:8080/health

# Classification test
curl -X POST http://127.0.0.1:8080/v1/classify \
  -H "Content-Type: application/json" \
  -d '{"image_base64":"<base64>","media_type":"IMAGE"}'
```

## Troubleshooting

**Connection refused:**
- Ensure NSFW Firewall Engine is running
- Check port bindings in config/engine_config.yaml

**Authentication failures:**
- Verify API key is configured
- Check authentication header format

**Rate limiting:**
- Adjust rate limits in proxy and engine config
- Monitor with `/metrics` endpoint

## Support

For issues or questions:
- See README.md for API documentation
- See docs/THREAT_MODEL.md for security considerations
- See docs/PRODUCTION_READINESS_PLAN.md for deployment guide
