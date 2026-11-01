# Architecture Overview

This document provides a high‑level view of the NSFW Firewall Engine and its main components.

```
+-------------------+      +-----------------+      +-------------------+
|   Ingress Proxy  | ---> |   API Service   | ---> |  Model Inference  |
| (Squid/NGINX…)   |      | (REST/gRPC/ICAP)|      | (ONNX models)    |
+-------------------+      +-----------------+      +-------------------+
        |                         |                        |
        |                         |                        |
        v                         v                        v
+-------------------+      +-----------------+      +-------------------+
|   Policy Engine   | <---|   Decision Core | <--- |  Post‑Processor   |
+-------------------+      +-----------------+      +-------------------+
        |                         |
        v                         v
+-------------------+      +-----------------+
|   Observability   |      |   Cache Layer   |
| (Logs, Metrics)   |      | (Redis/Memcached) |
+-------------------+      +-----------------+
```

**Key layers**
1. **Ingress** – optional proxy (Squid, NGINX, Envoy, HAProxy) that forwards image payloads to the service via HTTP, gRPC, or ICAP.
2. **API Service** – thin HTTP/gRPC/ICAP server exposing `/v1/ready`, `/v1/classify`, etc.
3. **Decision Core** – orchestrates policy evaluation, model cascade, caching, and reputation checks.
4. **Model Inference** – loads ONNX models (MobileNetV3, EfficientNet, CLIP, DistilBERT) and returns probabilistic scores.
5. **Policy Engine** – declarative YAML rules that can allow/deny based on tenant, device, zone, risk score, etc.
6. **Post‑Processor** – calibration, thresholding, and final response formatting.
7. **Observability** – structured JSON logs (with `trace_id`), Prometheus metrics, optional OpenTelemetry export.
8. **Cache Layer** – optional Redis/Memcached for decision caching.

The architecture is deliberately modular so individual components can be replaced (e.g., swap the model cascade, add a new proxy, or enable edge privacy mode).
