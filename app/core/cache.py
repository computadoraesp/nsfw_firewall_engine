"""Content-addressed decision cache (Sec. 29).

The cache key is ``sha256(payload) + model_version + preprocess_version``. That
suffix is deliberate: the spec forbids returning a cached decision that was
produced by a *different* model, so swapping or re-quantising a model implicitly
changes every key and stale results can never be served.

Only metadata (verdict / score / policy) is stored - never the payload itself,
which keeps the cache compatible with the zero-retention privacy policy.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("nsfw_engine.core.cache")

#: Bumped whenever the preprocessing pipeline changes shape/normalisation.
PREPROCESS_VERSION = "1"


def payload_hash(data: bytes, salt: str = "") -> str:
    """SHA256 of the payload (optionally salted for audit-trail privacy)."""
    digest = hashlib.sha256()
    if salt:
        digest.update(salt.encode("utf-8"))
    digest.update(data or b"")
    return digest.hexdigest()


def cache_key(
    payload_hash_value: str,
    model_version: str = "",
    preprocess_version: str = PREPROCESS_VERSION,
) -> str:
    """Composite key binding a decision to the model that produced it."""
    return f"{payload_hash_value}:{model_version or 'unknown'}:{preprocess_version}"


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return float(self.hits) / total if total else 0.0

    def as_dict(self) -> dict:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "size": self.size,
            "hit_rate": round(self.hit_rate, 6),
        }


class _RedisStore:
    """Redis-backed decision store (§29) with an injectable client.

    Only *metadata* is stored - the same JSON-safe payload as the in-process
    cache - so a distributed cache never becomes a content-retention problem.
    The client is injectable so this is testable without a running broker, and
    the backend degrades to "unavailable" when ``redis`` is not installed.
    """

    def __init__(self, client: Any, ttl_seconds: float, max_entries: int, prefix: str) -> None:
        self.client = client
        self.ttl = max(1, int(ttl_seconds or 86400))
        self.max_entries = max(0, int(max_entries or 0))
        self.prefix = prefix

    @property
    def _index(self) -> str:
        return f"{self.prefix}:index"

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        import json

        raw = self.client.get(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            logger.warning("discarding undecodable cache entry %s", str(key)[:16])
            self.client.delete(key)
            return None

    def put(self, key: str, value: Any) -> None:
        import json

        if self.max_entries:
            # Approximate bound: Redis exposes no cheap per-key size, so this is
            # a sampled count rather than an exact one.
            try:
                full = int(self.client.llen(self._index)) >= self.max_entries
            except Exception:  # noqa: BLE001
                full = False
            if full:
                self._evict_oldest()
        self.client.setex(key, self.ttl, json.dumps(value))
        self.client.lpush(self._index, key)
        self.client.ltrim(self._index, 0, max(0, self.max_entries or 1000) - 1)

    def delete(self, key: str) -> None:
        self.client.delete(key)
        try:
            self.client.lrem(self._index, 0, key)
        except Exception:  # noqa: BLE001
            pass

    def clear(self) -> None:
        for key in self.client.lrange(self._index, 0, -1) or []:
            try:
                self.client.delete(key)
            except Exception:  # noqa: BLE001
                continue
        self.client.delete(self._index)

    def size(self) -> int:
        try:
            return int(self.client.llen(self._index))
        except Exception:  # noqa: BLE001
            return 0

    def _evict_oldest(self) -> None:
        oldest = self.client.rpop(self._index) if hasattr(self.client, "rpop") else None
        if oldest:
            try:
                self.client.delete(oldest)
            except Exception:  # noqa: BLE001
                pass


def _build_redis_store(config: Any) -> Optional[_RedisStore]:
    """Create the Redis store, or ``None`` when redis is unavailable."""
    url = os.environ.get("NSFW_REDIS_URL", str(getattr(config, "url", "") or ""))
    if not url:
        return None
    try:
        import redis  # type: ignore
    except Exception as exc:  # noqa: BLE001 - optional dependency
        logger.info("redis cache requested but the client is unavailable (%s)", exc)
        return None
    try:
        client = redis.Redis.from_url(url)
        client.ping()
    except Exception as exc:  # noqa: BLE001
        logger.warning("redis cache unavailable (%s); continuing without it", exc)
        return None
    return _RedisStore(
        client,
        getattr(config, "ttl_seconds", 86400),
        getattr(config, "max_entries", 0),
        str(getattr(config, "prefix", "nsfw:decision")),
    )


class DecisionCache:
    """Thread-safe TTL + LRU cache for classification decisions.

    Uses the in-process store by default, or Redis when ``cache.type`` is
    ``redis`` and a client is available. Both share the same key contract, so a
    deployment can move between them without changing decision semantics.
    """

    def __init__(self, config: Any) -> None:
        self.config = config
        self.enabled = bool(getattr(config, "enabled", False))
        self.ttl_seconds = float(getattr(config, "ttl_seconds", 0) or 0)
        self.max_entries = int(getattr(config, "max_entries", 0) or 0)
        self._entries: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()
        self._lock = threading.Lock()
        self.stats = CacheStats()

        self.backend = str(getattr(config, "type", "memory") or "memory").lower()
        self._remote: Optional[_RedisStore] = None
        if self.enabled and self.backend == "redis":
            self._remote = _build_redis_store(config)
            if self._remote is None:
                logger.warning(
                    "cache.type=redis but no client is available; using the in-process cache"
                )
                self.backend = "memory"

    @property
    def distributed(self) -> bool:
        return self._remote is not None

    # -- internals -----------------------------------------------------------
    def _expired(self, stored_at: float) -> bool:
        return bool(self.ttl_seconds) and (time.time() - stored_at) > self.ttl_seconds

    # -- public API ----------------------------------------------------------
    def get(self, key: str) -> Optional[Any]:
        """Return a cached decision or ``None`` (counting hit/miss)."""
        if not self.enabled or not key:
            return None
        if self._remote is not None:
            value = self._remote.get(key)
            with self._lock:
                if value is None:
                    self.stats.misses += 1
                else:
                    self.stats.hits += 1
            return value
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self.stats.misses += 1
                return None
            stored_at, value = entry
            if self._expired(stored_at):
                self._entries.pop(key, None)
                self.stats.evictions += 1
                self.stats.misses += 1
                self.stats.size = len(self._entries)
                return None
            self._entries.move_to_end(key)
            self.stats.hits += 1
            return value

    def put(self, key: str, value: Any) -> None:
        """Store a decision, evicting expired then oldest entries."""
        if not self.enabled or not key:
            return
        if self._remote is not None:
            self._remote.put(key, value)
            return
        with self._lock:
            self._entries[key] = (time.time(), value)
            self._entries.move_to_end(key)
            if self.max_entries:
                while len(self._entries) > self.max_entries:
                    self._entries.popitem(last=False)
                    self.stats.evictions += 1
            self.stats.size = len(self._entries)

    def get_or_compute(
        self, key: str, producer: Callable[[], Any]
    ) -> tuple[Any, bool]:
        """Return ``(value, was_cached)`` computing via *producer* on a miss."""
        cached = self.get(key)
        if cached is not None:
            return cached, True
        value = producer()
        self.put(key, value)
        return value, False

    def invalidate(self, key: Optional[str] = None) -> None:
        """Drop one key, or the whole cache when *key* is ``None``."""
        if self._remote is not None:
            if key is None:
                self._remote.clear()
            else:
                self._remote.delete(key)
            return
        with self._lock:
            if key is None:
                self._entries.clear()
            else:
                self._entries.pop(key, None)
            self.stats.size = len(self._entries)

    def snapshot(self) -> dict:
        """A short summary for ``/health`` and the Prometheus gauges."""
        with self._lock:
            local_size = len(self._entries)
        data = self.stats.as_dict()
        data["size"] = self._remote.size() if self._remote is not None else local_size
        data["enabled"] = self.enabled
        data["backend"] = self.backend
        data["distributed"] = self.distributed
        return data


__all__ = [
    "PREPROCESS_VERSION",
    "DecisionCache",
    "CacheStats",
    "cache_key",
    "payload_hash",
]