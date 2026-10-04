# ADR-0003 — Graceful degradation everywhere; optional dependencies are never required

* **Status:** Accepted
* **Spec:** `pront.md` §16–§17, §38, §47

## Context

This engine sits on a firewall's hot path. A missing optional dependency
(`onnxruntime`, `Pillow`, `libmagic`, `grpcio`, `prometheus_client`) or a
missing model artifact must not take the service down, and — critically — must
not silently turn into a *false sense of security*. Several defects found during
implementation came from exactly this pressure: a hard `import magic` that broke
import, and a Pillow-missing path that rejected every image payload.

## Decision

1. **Every optional dependency is guarded** by an import check with a working
   fallback:
   * image decode → OpenCV → Pillow → built-in PPM decoder;
   * MIME sniffing → libmagic → built-in magic-number table;
   * metrics → `prometheus_client` → in-process exposition with identical names;
   * gRPC → module still imports; only server construction raises.
2. **Degradation is always *visible*.** The engine reports
   `models_loaded`/`text_model_loaded` on `/health`, logs `load '<name>' as stub`,
   exports `nsfw_models_loaded`, and returns `healthy: false` while any model is
   a stub. Operators and orchestrators can act on it.
3. **Security checks never become fatal for the wrong reason.** Missing Pillow
   *skips* dimension validation (the engine's own `Preprocessor` enforces
   `max_image_dim`/`max_image_bytes` before any decoder runs) rather than
   rejecting all traffic. A MIME mismatch is *advisory* on the classify path and
   *enforced* on the enforcement path (`enforce_mime`).
4. **No silent widening.** A failed classification applies
   `policy.fail_action` (fail-open by default, fail-closed configurable) and is
   counted in `nsfw_errors_total`.

## Alternatives

| Option | Why not |
|--------|---------|
| Hard-fail on missing optional deps | Simpler, but a missing optional lib becomes an outage on the firewall path |
| Reject everything when a model is absent | "Secure", but that is a self-inflicted DoS and still not detection |
| Pretend the heuristic is a real detector | Unacceptable: it is a documented development stub, never enforcement |

## Consequences

* **Positive:** the suite runs in minimal CI; deployments boot without GPU or
  media stacks; optional upgrades are safe.
* **Negative:** more code paths to test — hence explicit tests for every fallback.
* **Security impact:** the main risk is an operator ignoring `healthy: false`.
  Mitigation: probes gate traffic on a dedicated readiness endpoint, and the
  docs state the heuristic is not a detector.

> **Amendment (2026-10).** This ADR originally read *"Helm probes gate traffic on
> `/health`"*. That was imprecise, and the deployment config has since been made
> precise: **liveness** uses `/v1/health` (is this process up?) while **readiness**
> uses `/v1/ready` (can this replica actually serve?). Tying liveness to model
> readiness would *kill* a pod merely because weights are missing, turning a
> degraded-but-honest deployment into an outage loop. The decision recorded here
> — degradation must stay visible without becoming fatal — is unchanged; only the
> mechanism that surfaces it is more precise.

## License impact

None; the fallbacks are first-party code.