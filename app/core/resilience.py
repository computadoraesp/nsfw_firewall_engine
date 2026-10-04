"""Rate limiting and circuit breaking (§17, §33).

Two guards that sit between the network and the CPU:

``TokenBucket``
    Per-principal request throttle (§17 ``rate limiting``). Classification is
    CPU-bound inference: an unbounded request rate is a denial-of-service vector
    that costs nothing to mount and can saturate every worker. A token bucket is
    used rather than a fixed window because a fixed window lets a caller send
    2x the limit across a boundary, and rather than a sliding log because it
    would need one entry per request.

``CircuitBreaker``
    Stops calling a dependency that is failing (§33 ``circuit breakers``). Once
    a stage has failed ``failure_threshold`` times in a row the breaker opens and
    calls fail fast for ``recovery_timeout`` seconds instead of each one paying
    the full timeout. This is what keeps a slow/hung model from turning every
    request into a thread blocked on a dead socket.

Both reject explicitly rather than degrading quietly. A rate-limited request
gets a ``429``, never a silent allow: "allow when we are too busy" is exactly
the policy bypass §38 warns about.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("nsfw_engine.core.resilience")


class RateLimitExceeded(Exception):
    """Raised when a principal exceeds its configured rate (§17)."""

    def __init__(self, retry_after: float, limit: int) -> None:
        super().__init__(
            f"rate limit exceeded: {limit} requests; retry in {retry_after:.2f}s"
        )
        self.retry_after = round(float(retry_after), 3)
        self.limit = limit


class CircuitOpen(Exception):
    """Raised when a call is rejected by an open breaker (§33)."""

    def __init__(self, name: str, retry_after: float) -> None:
        super().__init__(f"circuit '{name}' is open; retry in {retry_after:.2f}s")
        self.name = name
        self.retry_after = round(float(retry_after), 3)


class TokenBucket:
    """A thread-safe token bucket rate limiter (§17).

    Tokens refill continuously at ``rate`` per second, capped at ``capacity``.
    ``capacity`` is therefore also the largest instantaneous burst allowed, which
    is what makes the limiter meaningful for a firewall: a proxy flushing a
    batch of cached decisions after a restart is a legitimate burst, while a
    sustained flood is not.
    """

    def __init__(
        self, rate: float, capacity: Optional[float] = None, now: Optional[float] = None
    ) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else max(1.0, rate))
        self._tokens = self.capacity
        self._updated = float(now if now is not None else time.monotonic())
        self._lock = threading.Lock()

    def _refill(self, now: float) -> None:
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._updated = now

    def allow(self, cost: float = 1.0, now: Optional[float] = None) -> Tuple[bool, float]:
        """Try to spend *cost* tokens.

        Returns ``(allowed, retry_after_seconds)``. On success ``retry_after`` is
        ``0.0``; on refusal it is how long until enough tokens exist, which the
        REST layer surfaces as the ``Retry-After`` header.
        """
        moment = float(now if now is not None else time.monotonic())
        with self._lock:
            self._refill(moment)
            if self._tokens >= cost:
                self._tokens -= cost
                return True, 0.0
            deficit = cost - self._tokens
            return False, max(0.0, deficit / self.rate)

    @property
    def tokens(self) -> float:
        with self._lock:
            self._refill(time.monotonic())
            return self._tokens


@dataclass
class BreakerState:
    failures: int = 0
    opened_at: Optional[float] = None
    success_streak: int = 0
    #: Probe slots reserved by ``allows`` while half-open and not yet reported.
    probes_in_flight: int = 0


class CircuitBreaker:
    """A three-state circuit breaker (§33).

    ``closed`` -> (threshold failures) -> ``open`` -> (recovery timeout) ->
    ``half_open`` -> (one probe succeeds) -> ``closed``.

    ``half_open`` admits exactly ``half_open_max_calls`` probes; anything beyond
    that is rejected immediately. Letting unlimited traffic through during
    recovery is how a recovering-but-still-broken dependency gets knocked over
    again.
    """

    def __init__(
        self,
        name: str = "default",
        *,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 1,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if recovery_timeout <= 0:
            raise ValueError("recovery_timeout must be positive")
        self.name = name
        self.failure_threshold = int(failure_threshold)
        self.recovery_timeout = float(recovery_timeout)
        self.half_open_max_calls = max(1, int(half_open_max_calls))
        self._state = "closed"
        self._data = BreakerState()
        self._lock = threading.Lock()

    # -- state ---------------------------------------------------------------
    @property
    def state(self) -> str:
        with self._lock:
            self._maybe_half_open(time.monotonic())
            return self._state

    def _maybe_half_open(self, now: float) -> None:
        if self._state != "open" or self._data.opened_at is None:
            return
        if now - self._data.opened_at >= self.recovery_timeout:
            self._state = "half_open"
            self._data.failures = 0
            self._data.success_streak = 0
            logger.info("circuit '%s' entering half-open", self.name)

    def allows(self, now: Optional[float] = None) -> Tuple[bool, float]:
        """Whether a call may proceed, plus the retry delay when it may not.

        In ``half_open`` this call **reserves** a probe slot. Reserving (rather
        than merely permitting) is what makes the bound real: if ``allows`` only
        reported permission, a burst of concurrent callers would all see
        "allowed" and the recovering dependency would be hit by every one of
        them - exactly the thundering herd the half-open state exists to prevent.

        The reservation is released by the subsequent ``record_success`` or
        ``record_failure``; a caller that is admitted and then never reports back
        leaves the slot consumed, which fails safe (the breaker stays limited).
        """
        moment = float(now if now is not None else time.monotonic())
        with self._lock:
            self._maybe_half_open(moment)
            if self._state == "closed":
                return True, 0.0
            if self._state == "open":
                elapsed = moment - (self._data.opened_at or moment)
                return False, max(0.0, self.recovery_timeout - elapsed)
            # half_open: admit a bounded number of probes.
            if self._data.probes_in_flight >= self.half_open_max_calls:
                return False, self.recovery_timeout
            self._data.probes_in_flight += 1
            return True, 0.0

    # -- accounting ----------------------------------------------------------
    def record_success(self) -> None:
        with self._lock:
            # Release the probe slot this call may have reserved.
            self._data.probes_in_flight = max(0, self._data.probes_in_flight - 1)
            self._data.success_streak += 1
            if self._state == "half_open":
                self._state = "closed"
                self._data = BreakerState()
                logger.info("circuit '%s' closed again", self.name)
            else:
                self._data.failures = 0

    def record_failure(self) -> None:
        with self._lock:
            # Release the probe slot this call may have reserved.
            self._data.probes_in_flight = max(0, self._data.probes_in_flight - 1)
            self._data.success_streak = 0
            self._data.failures += 1
            if self._state == "half_open":
                # A probe failed: go straight back to open and restart the timer.
                self._state = "open"
                self._data.opened_at = time.monotonic()
                logger.warning("circuit '%s' re-opened after a failed probe", self.name)
            elif self._data.failures >= self.failure_threshold:
                self._state = "open"
                self._data.opened_at = time.monotonic()
                logger.error(
                    "circuit '%s' opened after %d consecutive failures",
                    self.name, self._data.failures,
                )

    def reset(self) -> None:
        """Force the breaker closed (used by tests and by an operator)."""
        with self._lock:
            self._state = "closed"
            self._data = BreakerState()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "name": self.name,
                "state": self._state,
                "failures": self._data.failures,
                "failure_threshold": self.failure_threshold,
                "recovery_timeout": self.recovery_timeout,
            }


class IdempotencyStore:
    """Bounded, TTL-scoped record of completed request ids (§33).

    A firewall sits on a network path where clients retry. Squid re-sends on a
    dropped connection, an NGFW re-queues on a timeout, and a load balancer
    retries to a second replica. Without idempotency each retry is a fresh
    classification: usually merely wasteful, but it also inflates every
    per-tenant counter and, worse, can produce *contradictory* audit entries for
    what the operator believes is one request.

    The store maps ``request_id`` to the decision that was returned, so a retry
    replays the original answer instead of re-deciding. Entries are bounded by
    both TTL and count: an unbounded map keyed by client-supplied ids is a
    memory-exhaustion target (§38).
    """

    def __init__(self, ttl_seconds: float = 300.0, max_entries: int = 10_000) -> None:
        self.ttl_seconds = float(ttl_seconds)
        self.max_entries = max(1, int(max_entries))
        self._entries: "OrderedDict[str, Tuple[float, Any]]" = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _key(tenant_id: str, request_id: str) -> str:
        return f"{tenant_id or '-'}:{request_id}"

    def get(self, tenant_id: str, request_id: str) -> Optional[Any]:
        """Return a stored decision, or ``None`` when absent or expired.

        The tenant is part of the key on purpose (§34): two tenants using the
        same client-supplied ``request_id`` must not see each other's decisions.
        """
        if not request_id:
            return None
        key = self._key(tenant_id, request_id)
        now = time.time()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            stored_at, value = entry
            if now - stored_at > self.ttl_seconds:
                self._entries.pop(key, None)
                return None
            self._entries.move_to_end(key)
            return value

    def remember(self, tenant_id: str, request_id: str, value: Any) -> None:
        """Record a completed decision. No-op for an empty ``request_id``."""
        if not request_id:
            return
        key = self._key(tenant_id, request_id)
        now = time.time()
        with self._lock:
            self._entries[key] = (now, value)
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
            # Opportunistic expiry sweep: O(n) but amortised over one insert per
            # request, which is cheaper than a sweeper thread.
            if len(self._entries) > self.max_entries // 2:
                cutoff = now - self.ttl_seconds
                for existing in [
                    k for k, (ts, _v) in self._entries.items() if ts < cutoff
                ]:
                    self._entries.pop(existing, None)

    def forget(self, tenant_id: str, request_id: str) -> None:
        with self._lock:
            self._entries.pop(self._key(tenant_id, request_id), None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "entries": len(self._entries),
                "ttl_seconds": self.ttl_seconds,
                "max_entries": self.max_entries,
            }


@dataclass
class DeadLetter:
    """One request that could not be decided (§33 ``dead-letter queue``).

    Deliberately does **not** carry the payload. This is an NSFW firewall: the
    content that failed to classify is precisely the material least entitled to
    be retained. Only the SHA256 digest is kept, which is enough to correlate a
    letter with a log line or a client-side record without being a copy of the
    material itself.

    Attributes:
        request_id: Client-supplied id, or empty when none was given.
        tenant_id: Owning tenant (§34).
        endpoint: Which endpoint rejected it.
        reason: ``circuit_open`` | ``retries_exhausted`` | ``timeout`` | ...
        error: Short, already-truncated description of the failure.
        content_sha256: Digest of the payload; empty when unknown.
        attempts: How many delivery attempts were made before giving up.
        media_type: Declared media type, if known.
    """

    request_id: str
    tenant_id: str
    endpoint: str
    reason: str
    error: str = ""
    content_sha256: str = ""
    attempts: int = 1
    media_type: str = ""
    queued_at: float = 0.0

    def as_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "endpoint": self.endpoint,
            "reason": self.reason,
            "error": self.error,
            "content_sha256": self.content_sha256,
            "attempts": self.attempts,
            "media_type": self.media_type,
            "queued_at": round(self.queued_at, 3),
        }


class DeadLetterQueue:
    """Bounded, TTL-scoped queue of requests that could not be decided (§33).

    A firewall cannot simply drop a request it failed to decide. Two obligations
    pull in opposite directions:

    * **Fail closed**, so an undecided request is not silently allowed (§38);
    * **Do not lose the request**, so the client can retry once the dependency
      recovers.

    A dead-letter queue is where the second obligation lives. Without it the only
    record of a failed classification is a log line nobody is watching at 03:00 -
    and the content passes uninspected in the meantime.

    Two deliberate design choices:

    ``No payload retention.``
        Entries hold a SHA256 digest, never the bytes. Retaining failed NSFW
        content would turn the failure path into a store full of exactly the
        material the firewall exists to filter.

    ``Bounded by TTL *and* count.``
        Same reasoning as :class:`IdempotencyStore` (§38): an unbounded queue is
        a memory-exhaustion target, and dropping a letter is far better than an
        OOM kill of the whole process.
    """

    def __init__(self, max_entries: int = 1_000, ttl_seconds: float = 86_400.0) -> None:
        self.max_entries = max(1, int(max_entries))
        self.ttl_seconds = float(ttl_seconds)
        self._entries: "OrderedDict[str, DeadLetter]" = OrderedDict()
        self._lock = threading.Lock()
        self._sequence = 0
        self._reason_counts: Dict[str, int] = {}

    def publish(
        self,
        *,
        tenant_id: str = "",
        endpoint: str = "",
        reason: str = "unknown",
        error: str = "",
        request_id: str = "",
        content_sha256: str = "",
        attempts: int = 1,
        media_type: str = "",
    ) -> Optional[DeadLetter]:
        """Enqueue a failed request; returns the letter stored.

        Never raises: a full queue must not turn a handled failure into a new
        one. The oldest letter is evicted instead, because losing the *oldest*
        undelivered request is least harmful - that client timed out long ago,
        whereas the newest may still be retrying.
        """
        letter = DeadLetter(
            request_id=request_id or "",
            tenant_id=tenant_id or "",
            endpoint=endpoint or "",
            reason=reason or "unknown",
            error=str(error)[:512],
            content_sha256=content_sha256 or "",
            attempts=max(1, int(attempts)),
            media_type=media_type or "",
            queued_at=time.time(),
        )
        with self._lock:
            self._sequence += 1
            key = f"{self._sequence}:{letter.tenant_id}:{letter.request_id}"
            self._entries[key] = letter
            self._entries.move_to_end(key)
            self._reason_counts[letter.reason] = self._reason_counts.get(letter.reason, 0) + 1
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
            return letter

    def drain(self, limit: int = 100) -> "List[DeadLetter]":
        """Remove and return up to *limit* letters, oldest first.

        Removes on read rather than peeking: a replay driver that crashed between
        read and delivery would otherwise replay the same letters forever.
        """
        taken: List[DeadLetter] = []
        with self._lock:
            while self._entries and len(taken) < max(0, int(limit)):
                taken.append(self._entries.popitem(last=False)[1])
        return taken

    def peek(self, limit: int = 100) -> "List[DeadLetter]":
        """Return up to *limit* letters without removing them."""
        with self._lock:
            return list(self._entries.values())[: max(0, int(limit))]

    def stats(self) -> dict:
        """Snapshot for ``/health`` and ``/metrics``."""
        with self._lock:
            cutoff = time.time() - self.ttl_seconds
            live = sum(1 for letter in self._entries.values() if letter.queued_at >= cutoff)
            return {
                "size": len(self._entries),
                "live": live,
                "expired": len(self._entries) - live,
                "max_entries": self.max_entries,
                "ttl_seconds": self.ttl_seconds,
                "published": sum(self._reason_counts.values()),
                "by_reason": dict(self._reason_counts),
            }

    def purge_expired(self) -> int:
        """Drop letters older than the TTL; returns how many were removed."""
        with self._lock:
            cutoff = time.time() - self.ttl_seconds
            stale = [k for k, letter in self._entries.items() if letter.queued_at < cutoff]
            for key in stale:
                self._entries.pop(key, None)
            return len(stale)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


def call_with_retries(
    operation,
    *,
    attempts: int = 3,
    backoff_seconds: float = 0.05,
    on_retry=None,
    retry_on: Tuple[type, ...] = (Exception,),
    sleeper=time.sleep,
) -> Any:
    """Run *operation*, retrying transient failures (§33 ``bounded retries``).

    Retries must be **bounded**; an unbounded loop against a broken dependency
    turns one bad dependency into one hung request per worker, which is strictly
    worse than failing fast.

    The backoff is linear rather than exponential on purpose. The delays here are
    milliseconds and the retry count is two or three, so exponential backoff buys
    no real congestion relief while making the worst-case latency noticeably
    worse - and worst-case latency is exactly what a firewall is measured on.

    ``retry_on`` defaults to every ``Exception``, which is only appropriate
    because callers pass an operation that is already wrapped by a circuit
    breaker; when the breaker is open the call raises :class:`CircuitOpen`
    immediately and this loop is never entered. Narrow it for a specific
    transient error.

    Raises:
        The last exception, once ``attempts`` is exhausted.
    """
    total = max(1, int(attempts))
    last: Optional[BaseException] = None
    for attempt in range(1, total + 1):
        try:
            return operation()
        except retry_on as exc:  # noqa: PERF203 - the retry is the point
            last = exc
            if attempt >= total:
                break
            delay = backoff_seconds * attempt
            if on_retry is not None:
                try:
                    on_retry(attempt, exc)
                except Exception:  # noqa: BLE001 - reporting must not mask the retry
                    pass
            if delay > 0:
                sleeper(delay)
    assert last is not None  # total >= 1 guarantees we either returned or raised
    raise last


class RateLimiter:
    """Per-key token buckets, created on demand (§17).

    Keys are ``(tenant, principal)`` so one tenant cannot exhaust another's
    budget (§34 isolation), falling back to the anonymous key when a deployment
    runs with authentication disabled.

    Idle buckets are evicted so a long-running process cannot accumulate one
    entry per client that ever connected.
    """

    def __init__(
        self,
        rate: float,
        capacity: Optional[float] = None,
        max_keys: int = 10_000,
    ) -> None:
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else max(1.0, rate))
        self.max_keys = int(max_keys)
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    @staticmethod
    def key_for(tenant_id: str = "", principal_id: str = "") -> str:
        return f"{tenant_id or '-'}:{principal_id or 'anonymous'}"

    def check(self, key: str, cost: float = 1.0) -> Tuple[bool, float]:
        """Throttle *key*; returns ``(allowed, retry_after_seconds)``."""
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self.max_keys:
                    self._evict_locked()
                bucket = TokenBucket(self.rate, self.capacity)
                self._buckets[key] = bucket
        return bucket.allow(cost)

    def _evict_locked(self) -> None:
        """Drop the buckets closest to full - they are the least active.

        A full bucket has refilled completely, which means its owner has not
        called recently. This keeps memory bounded without needing a background
        sweeper thread.
        """
        if not self._buckets:
            return
        surplus = len(self._buckets) - self.max_keys + max(1, self.max_keys // 10)
        ranked = sorted(self._buckets.items(), key=lambda item: -item[1].tokens)
        for key, _bucket in ranked[:surplus]:
            self._buckets.pop(key, None)
        logger.warning("rate-limiter bucket table full; evicted %d idle entries", surplus)

    def reset(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "rate_per_second": self.rate,
                "capacity": self.capacity,
                "tracked_keys": len(self._buckets),
            }


__all__ = [
    "CircuitBreaker",
    "CircuitOpen",
    "DeadLetter",
    "DeadLetterQueue",
    "IdempotencyStore",
    "RateLimitExceeded",
    "RateLimiter",
    "TokenBucket",
    "call_with_retries",
]

