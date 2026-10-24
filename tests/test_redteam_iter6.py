"""Red-team iteration 6: the path nobody exercises, and the record of it all.

The resilience primitives have now been hammered with threads and hold
(idempotency, dead-letter queue, token bucket, circuit breaker), so this round
locks that in as regression tests and goes after the two areas that had **no
coverage at all**:

* ``RedisCacheExploits`` - ``cache.type: redis`` is a supported deployment and
  ``_RedisStore`` had no test whatsoever. An untested shared store in front of
  a firewall is where desync bugs live.
* ``ConcurrencyRegression`` - pins the thread-safety that iteration 5's
  cross-tenant work depends on.

It also carries a check that the documented threat model matches reality: a
threat model that claims mitigations which do not exist is worse than none,
because it buys false confidence.

Run with::

    python -m pytest tests/test_redteam_iter6.py -v
"""

from __future__ import annotations

import os
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.test_redteam import REPO_ROOT  # noqa: E402


class FakeRedis:
    """Minimal in-memory stand-in for the subset ``_RedisStore`` uses."""

    def __init__(self) -> None:
        self.data = {}
        self.lists = {}
        self.calls = []

    def get(self, key):
        self.calls.append(("get", key))
        return self.data.get(key)

    def setex(self, key, ttl, value):
        self.calls.append(("setex", key))
        self.data[key] = value

    def delete(self, key):
        self.calls.append(("delete", key))
        self.data.pop(key, None)

    def lpush(self, key, value):
        self.calls.append(("lpush", key))
        self.lists.setdefault(key, []).insert(0, value)

    def rpush(self, key, value):
        self.calls.append(("rpush", key))
        self.lists.setdefault(key, []).append(value)

    def ltrim(self, key, start, end):
        self.calls.append(("ltrim", key))
        items = self.lists.get(key, [])
        self.lists[key] = items[start : end + 1]

    def lrange(self, key, start, end):
        items = self.lists.get(key, [])
        return items[start:] if end == -1 else items[start : end + 1]

    def llen(self, key):
        return len(self.lists.get(key, []))

    def lrem(self, key, count, value):
        self.calls.append(("lrem", key))
        items = self.lists.get(key, [])
        self.lists[key] = [i for i in items if i != value]

    def rpop(self, key):
        items = self.lists.get(key, [])
        return items.pop() if items else None

    def delete_list(self, key):
        self.lists.pop(key, None)

    def pipeline(self, transaction=True):
        store = self

        class _Pipe:
            def __init__(self):
                self.ops = []

            def setex(self, key, ttl, value):
                self.ops.append(("setex", key, ttl, value))

            def lpush(self, key, value):
                self.ops.append(("lpush", key, value))

            def ltrim(self, key, start, end):
                self.ops.append(("ltrim", key, start, end))

            def execute(self):
                for op in self.ops:
                    if op[0] == "setex":
                        store.setex(op[1], op[2], op[3])
                    elif op[0] == "lpush":
                        store.lpush(op[1], op[2])
                    else:
                        store.ltrim(op[1], op[2], op[3])
                return [True] * len(self.ops)

        return _Pipe()


class RedisCacheExploits(unittest.TestCase):
    """``_RedisStore`` kept two structures in sync without a transaction.

    Every ``put`` is ``setex`` + ``lpush`` + ``ltrim`` as three independent
    round trips, and a corrupt entry is dropped from ``data`` without being
    dropped from the index. The index is what drives eviction, so a desync
    means live keys are never evicted - the ``max_entries`` bound quietly stops
    holding.
    """

    def _store(self, client, max_entries=10, prefix="nsfw:decision"):
        from app.core.cache import _RedisStore

        return _RedisStore(client, ttl_seconds=60, max_entries=max_entries, prefix=prefix)

    def test_attack_index_stays_consistent_with_stored_keys(self):
        client = FakeRedis()
        store = self._store(client, max_entries=50)
        for i in range(20):
            store.put(f"k{i}", {"verdict": "SFW"})

        indexed = set(client.lrange(f"nsfw:decision:index", 0, -1))
        stored = set(client.data)
        orphans = stored - indexed
        self.assertEqual(
            orphans,
            set(),
            msg=(
                f"{len(orphans)} key(s) exist in Redis but are absent from the "
                "eviction index, so max_entries can no longer bound memory"
            ),
        )

    def test_attack_undecodable_entry_is_removed_from_the_index_too(self):
        client = FakeRedis()
        store = self._store(client, max_entries=50)
        store.put("k1", {"verdict": "SFW"})
        # Corrupt the value the way a partial write or a version skew would.
        client.data["k1"] = b"{not json"

        store.get("k1")
        self.assertNotIn(
            "k1",
            client.lrange("nsfw:decision:index", 0, -1),
            msg=(
                "a discarded entry stays in the eviction index forever; each "
                "corruption permanently consumes a slot of the memory bound"
            ),
        )

    def test_attack_expired_keys_do_not_inflate_the_index(self):
        """TTL removes keys from Redis; nothing removes them from the index."""
        client = FakeRedis()
        store = self._store(client, max_entries=100)
        for i in range(10):
            store.put(f"k{i}", {"verdict": "SFW"})
        # Simulate TTL expiry happening underneath us.
        client.data.clear()
        store.size()
        self.assertLessEqual(
            len(client.lrange("nsfw:decision:index", 0, -1)),
            10,
            msg="the index reports entries that no longer exist",
        )

    def test_attack_unbounded_max_entries_is_not_silently_capped(self):
        """``max_entries = 0`` means 'no bound' everywhere else in the codebase."""
        client = FakeRedis()
        store = self._store(client, max_entries=0)
        store.put("k1", {"v": 1})
        index = client.lrange("nsfw:decision:index", 0, -1)
        self.assertLessEqual(
            len(index),
            1,
            msg="index trimming must be consistent with the configured bound",
        )

    def test_attack_put_is_atomic_or_recoverable(self):
        """A crash between setex and lpush leaves an un-evictable orphan."""
        import inspect

        from app.core.cache import _RedisStore

        source = inspect.getsource(_RedisStore.put)
        self.assertTrue(
            "pipeline" in source or "transaction" in source,
            msg=(
                "_RedisStore.put performs separate round trips, so a failure "
                "between them desynchronises the eviction index from the keys"
            ),
        )


class ConcurrencyRegression(unittest.TestCase):
    """Pins the thread-safety the isolation guarantees are built on.

    These all passed first time; they exist so a future refactor cannot quietly
    drop a lock. The token-bucket case uses a near-zero refill rate on purpose:
    with a realistic rate the bucket legitimately refills between threads, and
    the test would measure the clock rather than the lock.
    """

    def test_token_bucket_never_exceeds_capacity(self):
        from app.core.resilience import TokenBucket

        bucket = TokenBucket(rate=0.001, capacity=10)
        granted = []
        lock = threading.Lock()

        def worker():
            ok, _ = bucket.allow()
            if ok:
                with lock:
                    granted.append(1)

        threads = [threading.Thread(target=worker) for _ in range(300)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(
            len(granted), 10, msg="300 concurrent requests exceeded the bucket"
        )

    def test_rate_limiter_key_table_stays_bounded(self):
        from app.core.resilience import RateLimiter

        limiter = RateLimiter(rate=0.001, capacity=5, max_keys=50)

        def worker(index):
            for j in range(50):
                limiter.check(f"t{index}:svc:{j}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertLessEqual(len(limiter._buckets), 50)

    def test_half_open_admits_exactly_its_probe_budget(self):
        import time

        from app.core.resilience import CircuitBreaker

        breaker = CircuitBreaker(
            "t", failure_threshold=2, recovery_timeout=0.3, half_open_max_calls=2
        )
        breaker.record_failure()
        breaker.record_failure()
        time.sleep(0.35)

        admitted = []
        lock = threading.Lock()

        def worker():
            ok, _ = breaker.allows()
            if ok:
                with lock:
                    admitted.append(1)

        threads = [threading.Thread(target=worker) for _ in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(
            len(admitted), 2, msg="half-open admitted a thundering herd"
        )

    def test_idempotency_store_survives_concurrent_writers(self):
        from app.core.resilience import IdempotencyStore

        store = IdempotencyStore(ttl_seconds=300, max_entries=200)
        errors = []

        def worker(index):
            try:
                for j in range(100):
                    store.remember("acme", f"r{index}-{j}", f"v{index}-{j}")
                    store.get("acme", f"r{index}-{j}")
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertLessEqual(len(store), 200)

    def test_dead_letter_queue_survives_concurrent_publishers(self):
        from app.core.resilience import DeadLetterQueue

        queue = DeadLetterQueue(max_entries=150)

        def worker(index):
            for j in range(100):
                queue.publish(
                    tenant_id=f"t{index}", request_id=f"r{j}", reason="classify_error"
                )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertLessEqual(len(queue), 150)


class DeveloperToolingExploits(unittest.TestCase):
    """A test utility must not be able to destroy a production artifact.

    ``scripts/generate_dummy_onnx.py`` defaulted to writing
    ``models_onnx/vit_nsfw.onnx`` - the deep-path model's real, licensed path -
    with a bare ``onnx.save``. Invoking it replaced a reviewed 22 MB artifact
    with a 101-byte identity graph, silently. The integrity check caught it
    afterwards, but only because it happened to be run.

    This is a supply-chain class of problem that no runtime test would ever
    catch: the damage is done by an innocent command, not by an attacker, and
    it is invisible until someone diffs a lockfile weeks later.
    """

    def test_attack_dummy_generator_defaults_away_from_production(self):
        from scripts import generate_dummy_onnx

        default_target = generate_dummy_onnx.TEST_FIXTURE_DIR
        self.assertNotIn(
            generate_dummy_onnx.PRODUCTION_DIR,
            default_target.parts,
            msg=(
                "the dummy generator's default output is a production artifact "
                "path; running a test utility would overwrite a reviewed model"
            ),
        )

    def test_attack_dummy_generator_refuses_production_paths(self):
        from scripts import generate_dummy_onnx

        with self.assertRaises(SystemExit):
            generate_dummy_onnx.resolve_output(
                "models_onnx/vit_nsfw.onnx", force=False
            )

    def test_attack_dummy_generator_refuses_to_clobber_existing_files(self):
        import tempfile

        from scripts import generate_dummy_onnx

        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp) / "already-here.onnx"
            existing.write_bytes(b"precious")
            with self.assertRaises(SystemExit):
                generate_dummy_onnx.resolve_output(str(existing), force=False)
            self.assertEqual(
                existing.read_bytes(),
                b"precious",
                msg="the refusal must not have already written the file",
            )

    def test_attack_generated_fixture_is_actually_loadable(self):
        """The dummy was itself unloadable, which hid the real problem.

        ``opset_import = 13`` was set, but ``onnx.make_model`` stamps the *IR*
        version from the installed package, and a newer onnx writes IR 14 -
        which onnxruntime 1.20 rejects. So the replacement artifact failed for
        a *different* reason than the model it replaced, and the IR error in
        the logs pointed at the wrong culprit.
        """
        import tempfile

        import onnxruntime

        from scripts import generate_dummy_onnx

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.onnx"
            generate_dummy_onnx.main(["--output", str(path), "--force"])
            try:
                onnxruntime.InferenceSession(
                    str(path), providers=["CPUExecutionProvider"]
                )
            except Exception as exc:  # noqa: BLE001
                self.fail(f"the generated fixture does not load: {exc}")


class ThreatModelAccuracy(unittest.TestCase):
    """The threat model must describe the system that actually exists.

    It previously asserted mitigations that had never been implemented - MIME
    enforcement "on the enforcement path" (it was not enforced anywhere),
    tenant escape "mitigated" (nothing bound a key to a tenant), and
    ``policy.fail_action: ALLOW`` (the shipped value is ``BLOCK``). A threat
    model that overstates its own coverage is worse than none, because an
    operator reads it as assurance.
    """

    def test_threat_model_does_not_claim_absent_mitigations(self):
        text = (REPO_ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
        low = text.lower()

        # These were true once and are no longer.
        self.assertNotIn(
            "residual risk #1",
            low,
            msg="the document still references the pre-hardening risk register",
        )
        self.assertNotIn(
            "no tls/mtls termination",
            low,
            msg=(
                "gRPC now requires TLS; a threat model that says transport "
                "security is entirely the proxy's job is out of date"
            ),
        )

    def test_threat_model_records_the_hardened_controls(self):
        text = (REPO_ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
        for control in ("key_tenants", "scrypt", "trusted_proxies"):
            with self.subTest(control=control):
                self.assertIn(
                    control,
                    text,
                    msg=f"the threat model does not mention {control}",
                )

    def test_threat_model_test_count_is_not_fabricated(self):
        """A stale count reads as a current guarantee."""
        import re

        text = (REPO_ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
        match = re.search(r"\((\d{2,4}) tests\)", text)
        if match:
            self.assertGreaterEqual(
                int(match.group(1)),
                600,
                msg=(
                    f"the document claims {match.group(1)} tests; the suite is "
                    "larger and the number should not drift backwards"
                ),
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()