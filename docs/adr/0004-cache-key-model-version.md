# ADR-0004 — Cache keys bind a decision to the model that produced it

* **Status:** Accepted
* **Spec:** `pront.md` §29

## Context

A content-addressed decision cache gives large wins on enterprise traffic, where
the same media is re-fetched constantly. The danger is **cache poisoning by
staleness**: re-quantise a model or change preprocessing, and cached decisions
from the *previous* model keep being served, so the deployed model and the
enforced behavior silently diverge. §29 states the rule explicitly:
*"Never return cached results from different models."*

## Decision

Key = `sha256(payload)[+salt] : model_version : preprocess_version`
(`app/core/cache.py`).

* `privacy.hash_salt` is applied when `log_content_hashes` is enabled, so audit
  hashes are not trivially correlatable.
* **Only metadata is cached** (verdict / score / action / stages) — never the
  payload — which keeps the cache compatible with `retain_raw_payloads: false`.
* Requests carrying threshold **overrides bypass the cache entirely**: a cached
  decision was produced under different thresholds.
* TTL + LRU eviction (`cache.ttl_seconds`, `cache.max_entries`), thread-safe via
  a lock. `type: redis` is a documented future backend, not yet implemented.

## Alternatives

| Option | Why not |
|--------|---------|
| Key on SHA256 of content only | Violates §29 — stale decisions across model swaps |
| Key on a random UUID | No dedup benefit; unbounded growth |
| Redis always | Extra operational dependency for an in-process win; defer until §33 needs it |

## Consequences

* **Positive:** safe model swaps — bumping `engine.version` or
  `PREPROCESS_VERSION` implicitly invalidates every entry.
* **Negative:** a model/version bump discards the whole cache (a cold-start
  latency spike). Acceptable and deliberate.
* **Security impact:** cache keys never embed raw content, so the cache cannot
  become a content-retention violation; `from_cache` is surfaced in responses.

## License impact

None.