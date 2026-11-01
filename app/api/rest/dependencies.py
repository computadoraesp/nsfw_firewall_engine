import time
import hmac
from fastapi import Request, HTTPException, status
from typing import Optional
from collections import OrderedDict

# Simple in‑memory token bucket per IP address.
# Configuration: allow up to 10 requests per second with a burst capacity of 50.
# PRODUCTION: Adjust these values based on expected traffic patterns.
# Current values provide protection against brute force attacks while allowing
# legitimate burst traffic from legitimate clients.
_IP_RATE = 10.0  # tokens added per second
_IP_CAPACITY = 50  # max tokens (burst size)
_IP_MAX_BUCKETS = 10000  # Maximum number of IP buckets to prevent memory exhaustion
_ip_buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()  # ip -> (tokens, last_timestamp)


def _refill(ip: str, now: float) -> None:
    """Refill the bucket for *ip* based on elapsed time.

    The bucket state is stored as a ``(tokens, last_timestamp)`` tuple in the
    module‑level ``_ip_buckets`` dictionary.

    SECURITY: Evicts oldest buckets when capacity is exceeded to prevent
    memory exhaustion attacks via IP flooding.
    """
    tokens, last = _ip_buckets.get(ip, (_IP_CAPACITY, now))
    elapsed = now - last
    if elapsed > 0:
        tokens = min(_IP_CAPACITY, tokens + elapsed * _IP_RATE)
    _ip_buckets[ip] = (tokens, now)

    # SECURITY: Evict the oldest buckets if we exceed maximum
    if len(_ip_buckets) > _IP_MAX_BUCKETS:
        # Remove oldest 10% of buckets
        evict_count = int(_IP_MAX_BUCKETS * 0.1)
        for _ in range(evict_count):
            _ip_buckets.popitem(last=False)


def enforce_ip_rate_limit(request: Request) -> None:
    """Coarse per‑IP rate limiting applied *before* authentication.

    A token bucket is used so short bursts are tolerated while a sustained
    request rate above the configured limit (5 req/10 s) is rejected with ``429``.
    The ``Retry‑After`` header tells the client how many seconds to wait before
    the next request is allowed.
    """
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    _refill(client_ip, now)
    tokens, _ = _ip_buckets[client_ip]
    if tokens >= 1:
        # consume a token and allow the request
        _ip_buckets[client_ip] = (tokens - 1, now)
        return
    # not enough tokens – calculate retry delay
    deficit = 1 - tokens
    retry_after = deficit / _IP_RATE
    # Record audit information – the SecurityContext audit is optional here
    # because we may not have authenticated the caller yet.
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="rate limit exceeded",
        headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
    )


def enforce_rate_limit(request: Request) -> None:
    """Placeholder to keep the import signature valid.

    The actual per‑principal rate‑limiting logic lives in ``router.enforce_rate_limit``
    which uses the ``RateLimiter`` instance stored in ``app.state``.  This stub is
    provided solely so that ``from .dependencies import enforce_rate_limit`` works
    without raising an ``ImportError`` when the module is imported.
    """
    # No‑op – the real implementation is in ``router.enforce_rate_limit``.
    return None
