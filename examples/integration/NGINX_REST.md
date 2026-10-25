# NGINX REST Integration Example

This document shows how to integrate the NSFW Firewall Engine with NGINX as a reverse proxy.

## Quick Start

1. Ensure the NSFW Firewall Engine REST API is running on `127.0.0.1:8080`
2. Add the following to your NGINX configuration

## Basic Reverse Proxy Configuration

```nginx
# ========================================
# NSFW Firewall Engine - NGINX Integration
# ========================================

upstream nsfw_firewall {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name example.com;

    # Rate limiting zone
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req zone=api_limit burst=20 nodelay;

    # Timeouts
    proxy_connect_timeout 5s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;

    # Headers to proxy
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # NSFW Firewall Engine - Classify uploads
    location /api/classify {
        limit_req zone=api_limit burst=20 nodelay;

        proxy_pass http://nsfw_firewall/v1/classify;
        proxy_pass_request_body on;
        proxy_set_header Content-Type $content_type;

        # Client body size limit (match engine config)
        client_max_body_size 20M;
    }

    # NSFW Firewall Engine - Classify text/HTML
    location /api/classify-text {
        limit_req zone=api_limit burst=20 nodelay;

        proxy_pass http://nsfw_firewall/v1/classify/text;
        proxy_set_header Content-Type application/json;
    }

    # NSFW Firewall Engine - Enforce (firewall decision)
    location /api/enforce {
        limit_req zone=api_limit burst=20 nodelay;

        proxy_pass http://nsfw_firewall/v1/enforce;
        proxy_set_header Content-Type application/json;
    }

    # Health check (no auth required)
    location /health {
        proxy_pass http://nsfw_firewall/health;
        access_log off;
    }

    # Metrics (configure token in production)
    location /metrics {
        proxy_pass http://nsfw_firewall/metrics;
        # Only allow from monitoring network
        allow 127.0.0.1;
        allow 10.0.0.0/8;
        deny all;
    }
}
```

## Advanced Configuration

### With Authentication

```nginx
# API key authentication (example - use secure method in production)
map $http_x_api_key $api_key_set {
    default 0;
    "your-secure-api-key" 1;
}

server {
    # ... other config ...

    location /api/classify {
        if ($api_key_set = 0) {
            return 401;
        }

        proxy_pass http://nsfw_firewall/v1/classify;
        proxy_set_header X-API-Key $http_x_api_key;
    }
}
```

### With TLS Termination

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    # ... proxy configuration ...
}
```

### With Caching (Allowed Responses Only)

```nginx
# Cache zone for safe content
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=nsfw_cache:10m inactive=60m;

server {
    # ... other config ...

    location /api/classify {
        proxy_pass http://nsfw_firewall/v1/classify;

        # Only cache ALLOW responses
        proxy_cache nsfw_cache;
        proxy_cache_valid 200 10m;
        proxy_cache_background_update on;
        proxy_cache_use_stale error timeout updating;

        # Bypass cache for POST requests
        proxy_cache_methods GET HEAD;
    }
}
```

### Tenant Routing

```nginx
# Extract tenant from subdomain
map $host $tenant_id {
    default "default";
    "~*^(?<tenant>[^.]+)\.example\.com$" $tenant;
}

server {
    # ... other config ...

    location /api/classify {
        proxy_pass http://nsfw_firewall/v1/classify;
        proxy_set_header X-Tenant-Id $tenant_id;
    }
}
```

## Monitoring

```nginx
# Add to http block for status monitoring
http {
    # ... other config ...

    # Stub status for monitoring
    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location /nginx_status {
            stub_status;
            allow 127.0.0.1;
            deny all;
        }
    }
}
```

Check status:
```bash
curl http://127.0.0.1:8080/nginx_status
```

## Testing

```bash
# Test configuration
nginx -t

# Reload configuration
nginx -s reload

# Test classification
curl -X POST http://localhost/api/classify \
  -H "Content-Type: application/json" \
  -d '{"image_base64":"<base64>","media_type":"IMAGE"}'
```

## Docker Deployment

```dockerfile
FROM nginx:alpine

COPY nginx.conf /etc/nginx/nginx.conf
COPY ssl/ /etc/nginx/ssl/

EXPOSE 80 443
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  nginx:
    build: ./nginx
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - nsfw-firewall
    networks:
      - nsfw-network

  nsfw-firewall:
    build: .
    ports:
      - "8080:8080"
    networks:
      - nsfw-network

networks:
  nsfw-network:
    driver: bridge
```

## Troubleshooting

**502 Bad Gateway:**
```bash
# Check if NSFW Firewall Engine is running
curl http://127.0.0.1:8080/health

# Check NGINX error log
tail -f /var/log/nginx/error.log
```

**413 Request Entity Too Large:**
```bash
# Check client_max_body_size in NGINX config
# Check max_image_bytes in engine config (20 MB)
```

**Rate Limiting Too Aggressive:**
```nginx
# Adjust rate limit
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=20r/s;
limit_req zone=api_limit burst=40 nodelay;
```

## References

- NGINX Reverse Proxy: https://nginx.org/en/docs/http/ngx_http_proxy_module.html
- NSFW Firewall Engine REST API: See README.md
