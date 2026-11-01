# Cloudflare Free Tier DDoS Protection Setup

This guide explains how to configure Cloudflare's free tier to protect the NSFW Firewall Engine from volumetric DDoS attacks.

## Why Cloudflare Free Tier?

Cloudflare's free tier provides:
- **Unmetered DDoS protection** against L3/L4/L7 attacks
- **Global CDN** for faster response times
- **SSL/TLS termination** (free SSL certificates)
- **Basic WAF rules** (complementary to ModSecurity)
- **Rate limiting** (additional layer)
- **No cost** for the features we need

## Prerequisites

- A Cloudflare account (free)
- A domain name (or use Cloudflare's free subdomain)
- Access to DNS settings

## Setup Steps

### 1. Add Your Site to Cloudflare

1. Log in to Cloudflare
2. Click "Add a Site"
3. Enter your domain (e.g., `nsfw.yourdomain.com`)
4. Select the **Free** plan
5. Cloudflare will scan your existing DNS records

### 2. Configure DNS Records

For each DNS record that points to your NSFW Firewall Engine:

| Type | Name | Content | Proxy Status |
|------|------|---------|--------------|
| A | nsfw | YOUR_SERVER_IP | **Proxied** (orange cloud) |
| CNAME | api | nsfw.yourdomain.com | **Proxied** (orange cloud) |

**Important:** The "Proxied" status (orange cloud) is what enables Cloudflare's protection.

### 3. Configure SSL/TLS

1. Go to **SSL/TLS** in Cloudflare dashboard
2. Set mode to **Full** (not Full Strict, as self-signed certs are used internally)
3. Enable **Always Use HTTPS**
4. Enable **Automatic HTTPS Rewrites**

### 4. Configure Firewall Rules

Go to **Security** > **WAF** and create the following rules:

#### Rule 1: Block Known Bad Bots
```
Field: User Agent
Operator: contains
Value: bot, crawler, spider
Action: Block
```

#### Rule 2: Rate Limiting (Additional Layer)
```
When: requests > 100 per minute
Then: Block for 5 minutes
```

#### Rule 3: Geographic Blocking (Optional)
```
If IP country is in {CN, RU, KP}
Then: Block
```

### 5. Configure Rate Limiting (Advanced)

Go to **Security** > **Rate Limiting Rules**:

```
Name: API Rate Limit
Expression: (http.request.uri.path matches "^/v1/.*")
Rate Limit: 50 requests per minute
Action: Block
Period: 5 minutes
```

### 6. Enable Bot Fight Mode

Go to **Security** > **Bot Fight Mode** and enable it. This is free and provides basic bot protection.

### 7. Configure Caching (Optional)

For static assets or repeated classification results (if appropriate):

1. Go to **Caching** > **Configuration**
2. Set **Caching Level** to **Standard**
3. **Important:** Do NOT cache API endpoints with sensitive data

### 8. Test Configuration

```bash
# Test that Cloudflare is protecting your site
curl -I https://nsfw.yourdomain.com/health

# Should see Cloudflare headers:
# CF-Cache-Status
# CF-RAY
# Server: cloudflare
```

## Cloudflare vs Application Protections

| Protection | Cloudflare | Application |
|------------|------------|-------------|
| Volumetric DDoS | ✅ Yes | ❌ No |
| Application-level rate limiting | ✅ Yes | ✅ Yes |
| SQL Injection | ✅ Yes | N/A (no SQL) |
| XSS | ✅ Yes | ✅ Yes (input sanitization) |
| CSRF | ✅ Yes | ✅ Yes (Origin validation) |
| Authentication | ❌ No | ✅ Yes |
| Authorization | ❌ No | ✅ Yes |
| Business logic | ❌ No | ✅ Yes |

## Recommended Cloudflare Settings for NSFW Firewall

### Security Level
- **Security Level:** High
- **Bot Fight Mode:** On
- **Challenge Passage:** 30 minutes

### Performance
- **Auto Minify:** On (HTML, CSS, JS)
- **Brotli:** On
- **HTTP/3 (with QUIC):** On

### Speed
- **Rocket Loader:** Off (may interfere with API)
- **Always Online:** Off (API should fail closed)

## Troubleshooting

### Cloudflare Blocking Legitimate Requests

If Cloudflare blocks legitimate API requests:

1. Check **Security** > **Overview** for blocked requests
2. Adjust WAF rules to be less aggressive
3. Add IP ranges to **Security** > **WAF** > **Allowlists**

### SSL Errors

If you see SSL errors:

1. Check SSL/TLS mode (should be "Full", not "Full Strict")
2. Verify your server certificate is valid
3. Check that your origin server is listening on port 443

### Rate Limiting Too Aggressive

If rate limiting blocks legitimate traffic:

1. Go to **Security** > **Rate Limiting Rules**
2. Adjust thresholds (e.g., 100 req/min instead of 50)
3. Add whitelist for trusted IP ranges

## Cost

All features described here are **100% free**:
- Cloudflare Free plan: $0/month
- DDoS protection: Unlimited
- SSL certificates: Free (Let's Encrypt)
- CDN: Unlimited bandwidth
- Basic WAF: Free

## Limitations of Free Tier

The following features require paid plans:
- Advanced WAF rulesets
- Image optimization
- Mobile optimization
- Web Application Firewall managed rules
- Rate limiting beyond basic rules

For NSFW Firewall Engine, the free tier is **sufficient** for production use.

## Additional Resources

- [Cloudflare Free Tier Features](https://www.cloudflare.com/plans/)
- [Cloudflare DDoS Protection](https://www.cloudflare.com/ddos/)
- [Cloudflare WAF Documentation](https://developers.cloudflare.com/waf/)
