# Squid ICAP Integration Example

This directory contains ready-to-use configuration examples for integrating
the NSFW Firewall Engine with various proxies and firewalls.

## Squid ICAP Configuration

### Quick Start

1. Ensure the NSFW Firewall Engine ICAP server is running on `127.0.0.1:1344`
2. Add the following to your Squid configuration (`/etc/squid/squid.conf`)

### Configuration

```squid
# ========================================
# NSFW Firewall Engine ICAP Integration
# ========================================

# Enable ICAP adaptation
icap_enable on

# Define ICAP service for request modification (uploads)
icap_service nsfw_req reqmod_precache icap://127.0.0.1:1344/nsfw-firewall

# Define ICAP service for response modification (downloads)
icap_service nsfw_res respmod_precache icap://127.0.0.1:1344/nsfw-firewall

# Apply ICAP service to all traffic
adaptation_access nsfw_req allow all
adaptation_access nsfw_res allow all

# ICAP Options
icap_service_service_failure on down

# Recommended: Increase ICAP timeout for large files
icap_client_pconn_connections 32
icap_client_pconn_timeout 60
icap_service_failure_limit 10 off
icap_preview_enable off
```

### Testing

```bash
# Test ICAP connection
squid -k parse

# Reload Squid configuration
squid -k reconfigure

# Check ICAP service status
squid -k mgr:icap
```

### Monitoring

```bash
# View ICAP statistics
squidclient mgr:icap

# View adaptation statistics
squidclient mgr:adaptation
```

### Advanced Configuration

#### Selective ICAP (Specific Networks)

```squid
# Only apply to specific networks
acl local_network src 192.168.0.0/16
acl external_network src 0.0.0.0/0.0

adaptation_access nsfw_req allow local_network
adaptation_access nsfw_req deny external_network
```

#### ICAP with Authentication

```squid
# Send authentication information to ICAP service
icap_service nsfw_req reqmod_precache icap://127.0.0.1:1344/nsfw-firewall \
  options-TLS \
  options-TLS-Options no-ssl-verify-peer

# Include auth credentials in ICAP header
icap_send_client_username on
```

### Troubleshooting

**ICAP service unreachable:**
```bash
# Check if NSFW Firewall Engine is running
curl http://127.0.0.1:1344/health

# Check Squid logs
tail -f /var/log/squid/cache.log
```

**Requests not being filtered:**
```bash
# Verify ICAP is enabled
squid -k parse | grep icap_enable

# Check adaptation status
squidclient mgr:adaptation
```

### References

- Squid ICAP Documentation: http://www.squid-cache.org/Doc/config/icap.html
- NSFW Firewall Engine ICAP Protocol: See `app/api/icap/`
