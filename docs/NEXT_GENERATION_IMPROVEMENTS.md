# Next-Generation Improvements Roadmap

## 1. Enhanced PII Masking (PENDING INTEGRATION)
- **Module:** app/core/pii_masking.py (created)
- **Patterns:** Password, token, api_key, secret, session, sig, signature, authorization, cookie, email
- **Integration needed:** Add mask_pii() to AuditLog.record() in app/core/security.py
- **Time:** ~30 min

## 2. URL Normalization (PENDING INTEGRATION)
- **Module:** app/core/url_normalization.py (created)
- **Features:** Multi-layer percent-decoding, control character removal, IDN/Punycode mapping
- **Integration needed:** Add normalize_url() to URL validation in router
- **Time:** ~30 min

## 3. Model Explainability (SHAP/LIME)
- **Benefit:** Explain why an image was classified as NSFW
- **Implementation:** Install shap, create explain endpoint
- **Time:** ~4 hours

## 4. A/B Testing Framework
- **Beneficio:** Test new models in production without risk
- **Implementation:** Shadow routing, result comparison, statistical analysis
- **Time:** ~3 hours

## 5. GraphQL API
- **Beneficio:** Queries complejas para el cliente
- **Implementation:** Install strawberry-graphql, create GraphQL schema
- **Time:** ~2 hours

**Status:** Modules created, integration pending due to context limit
