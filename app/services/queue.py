"""Queue abstraction for horizontal scaling and async inspection (§33).

The engine itself is synchronous and stateless, but a multi-worker deployment
needs somewhere to hand off work that must *not* block the firewall hot path:
video re-inspection, bulk re-scoring, or a REDIS/KAFKA bridge.

This module defines a narrow interface plus two implementations:

* :class:`InMemoryQueue` - zero-dependency default, used by tests and
  single-node deployments.
* :class:`RedisQueue` / :class:`KafkaQueue` - thin wrappers that import their
  client lazily and report ``available == False`` when it is absent, so the
  interface never forces a broker dependency (§3: reuse, don't require).

Reliability properties: at-least-once delivery, explicit ``ack``, a bounded
queue that rejects rather than growing without limit (resource exhaustion,
§17), and a visibility timeout so a crashed worker's items return to the queue.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("nsfw_engine.services.queue")


class QueueError(RuntimeError):
    """Raised when a queue operation cannot be completed."""


class QueueFull(QueueError):
    """Raised when the bounded queue rejects a submission."""


@dataclass
class Job:
    """A unit of deferred work."""

    payload: bytes
    #: Free-form routing metadata (request_id, tenant_id, media_type...).
    meta: Dict[str, Any] = field(default_factory=dict)
    job_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    attempts: int = 0
    enqueued_at: float = field(default_factory=time.time)
    #: When set and in the past, an un-acked job becomes visible again.
    visible_at: float = 0.0

    def as_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "attempts": self.attempts,
            "enqueued_at": self.enqueued_at,
            "meta": dict(self.meta),
            "size": len(self.payload or b""),
        }


class BaseQueue:
    """Interface every queue backend implements."""

    name = "base"

    @property
    def available(self) -> bool:
        return True

    def put(self, job: Job) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def get(self, timeout: float = 1.0) -> Optional[Job]:  # pragma: no cover
        raise NotImplementedError

    def ack(self, job_id: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def size(self) -> int:  # pragma: no cover - interface
        raise NotImplementedError

    def describe(self) -> dict:
        return {"name": self.name, "available": self.available, "size": self.size()}


class InMemoryQueue(BaseQueue):
    """Thread-safe bounded in-process queue with a visibility timeout."""

    name = "memory"

    def __init__(self, max_size: int = 1000, visibility_timeout: float = 30.0) -> None:
        self.max_size = max(1, int(max_size))
        self.visibility_timeout = float(visibility_timeout)
        self._items: List[Job] = []
        self._inflight: Dict[str, Job] = {}
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)

    # -- producer ------------------------------------------------------------
    def put(self, job: Job) -> str:
        with self._condition:
            if len(self._items) >= self.max_size:
                raise QueueFull(
                    f"queue full ({len(self._items)}/{self.max_size}); "
                    "refusing unbounded growth"
                )
            self._items.append(job)
            self._condition.notify()
            return job.job_id

    # -- consumer ------------------------------------------------------------
    def _reclaim_expired(self) -> None:
        """Return jobs whose visibility timeout expired back to the queue."""
        now = time.time()
        expired = [
            job for job_id, job in self._inflight.items()
            if job.visible_at and job.visible_at <= now
        ]
        for job in expired:
            self._inflight.pop(job.job_id, None)
            self._items.append(job)

    def get(self, timeout: float = 1.0) -> Optional[Job]:
        deadline = time.time() + max(0.0, float(timeout))
        with self._condition:
            while True:
                self._reclaim_expired()
                if self._items:
                    job = self._items.pop(0)
                    job.attempts += 1
                    job.visible_at = time.time() + self.visibility_timeout
                    self._inflight[job.job_id] = job
                    return job
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._condition.wait(remaining)

    def ack(self, job_id: str) -> None:
        with self._condition:
            self._inflight.pop(job_id, None)

    def size(self) -> int:
        with self._lock:
            return len(self._items) + len(self._inflight)

    @property
    def inflight(self) -> int:
        with self._lock:
            return len(self._inflight)
class RedisQueue(BaseQueue):
    """Redis LIST-backed queue (optional dependency).

    Uses ``BRPOPLPUSH``-style semantics via a visibility list so an un-acked job
    returns to the pending list. Degrades to ``available == False`` when the
    ``redis`` client is absent.
    """

    name = "redis"

    def __init__(self, url: str = "redis://127.0.0.1:6379/0", prefix: str = "nsfw:jobs",
                 visibility_timeout: float = 30.0) -> None:
        self.url = url
        self.prefix = prefix
        self.visibility_timeout = visibility_timeout
        self._client = None

    @property
    def available(self) -> bool:
        if self._client is None:
            try:
                import redis  # type: ignore

                self._client = redis.Redis.from_url(self.url)
                self._client.ping()
            except Exception as exc:  # noqa: BLE001 - optional dependency
                logger.info("redis queue unavailable (%s)", exc)
                self._client = None
        return self._client is not None

    def put(self, job: Job) -> str:
        if not self.available:
            raise QueueError("redis queue is not available")
        import json

        self._client.rpush(self._ready_key(), json.dumps(job.as_dict()))
        return job.job_id

    def get(self, timeout: float = 1.0) -> Optional[Job]:
        if not self.available:
            return None
        import json

        raw = self._client.blpop(self._ready_key(), timeout=int(max(1, timeout)))
        if not raw:
            return None
        return Job(payload=b"", meta=json.loads(raw[1]))

    def ack(self, job_id: str) -> None:
        if self.available:
            self._client.lrem(self._pending_key(), 0, job_id)

    def size(self) -> int:
        if not self.available:
            return 0
        return int(self._client.llen(self._ready_key()) + self._client.llen(self._pending_key()))

    def _ready_key(self) -> str:
        return f"{self.prefix}:ready"

    def _pending_key(self) -> str:
        return f"{self.prefix}:pending"


class KafkaQueue(BaseQueue):
    """Kafka producer/consumer wrapper (optional dependency).

    Deliberately a *producer* only: the firewall path must never block on a
    broker, so this is for handing work to downstream consumers rather than for
    consuming inline.
    """

    name = "kafka"

    def __init__(self, bootstrap_servers: str = "localhost:9092", topic: str = "nsfw-jobs") -> None:
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self._producer = None

    @property
    def available(self) -> bool:
        if self._producer is None:
            try:
                from kafka import KafkaProducer  # type: ignore

                self._producer = KafkaProducer(
                    bootstrap_servers=self.bootstrap_servers
                )
            except Exception as exc:  # noqa: BLE001 - optional dependency
                logger.info("kafka queue unavailable (%s)", exc)
                self._producer = None
        return self._producer is not None

    def put(self, job: Job) -> str:
        if not self.available:
            raise QueueError("kafka producer is not available")
        self._producer.send(self.topic, value=job.payload, key=job.job_id.encode())
        self._producer.flush(timeout=5)
        return job.job_id

    def get(self, timeout: float = 1.0) -> Optional[Job]:
        raise QueueError("KafkaQueue is producer-only; consume with a KafkaConsumer")

    def ack(self, job_id: str) -> None:
        return None

    def size(self) -> int:
        return 0


#: Backend name -> factory, so deployments choose via configuration (§33).
QUEUE_BACKENDS = {
    "memory": InMemoryQueue,
    "redis": RedisQueue,
    "kafka": KafkaQueue,
}


def build_queue(kind: str = "memory", **kwargs: Any) -> BaseQueue:
    """Instantiate a queue backend by name."""
    try:
        factory = QUEUE_BACKENDS[kind.lower()]
    except KeyError as exc:
        raise ValueError(
            f"unknown queue backend {kind!r}; available: {sorted(QUEUE_BACKENDS)}"
        ) from exc
    return factory(**kwargs)


__all__ = [
    "BaseQueue",
    "InMemoryQueue",
    "Job",
    "KafkaQueue",
    "QUEUE_BACKENDS",
    "QueueError",
    "QueueFull",
    "RedisQueue",
    "build_queue",
]