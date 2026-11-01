"""Red-team iteration 5: isolation between tenants inside the engine.

Iterations 1-4 closed who may talk to the engine. This round attacks what
happens *after* a request is authenticated and classified: the shared state
one tenant can reach through another's traffic.

* ``CacheIsolationExploits`` - the decision cache key carries no tenant, so
  every tenant shares one entry space.
* ``PolicyEngineExploits``   - the rule engine compiles operator-controlled
  regexes and runs them against attacker data.

Run with::

    Python -m pytest tests/test_redteam_iter5.py -v
"""

from __future__ import annotations

import copy
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.test_redteam import REPO_ROOT  # noqa: E402

#: Bytes shared by both tenants in the cross-tenant scenarios.
SHARED = b"<html><body>content both tenants request</body></html>"


def _engine():
    import sys as _sys

    _sys.path.insert(0, str(REPO_ROOT))
    from app.core.config import load_config
    from app.core.engine import NsfwEngine

    config = copy.deepcopy(load_config(REPO_ROOT / "config" / "engine_config.yaml"))
    config.cache.enabled = True
    return NsfwEngine(config)


class CacheIsolationExploits(unittest.TestCase):
    """The cache key is built from payload + inference inputs, with no tenant.

    ``_cache_key_for`` hashes ``media_type``, ``text``, ``url`` and ``domain``.
    The tenant is not among them, so two tenants submitting identical bytes
    address the same cache entry. That leaks the classification, and - worse -
    it lets one tenant poison the failure state everyone else is served.
    """

    @classmethod
    def setUpClass(cls):
        cls.engine = _engine()

    def test_attack_cache_key_is_tenant_scoped(self):
        from app.models.base import MediaType

        engine = _engine()
        key_a = engine._cache_key_for(SHARED, MediaType.HTML, None, "", "", "acme")
        key_b = engine._cache_key_for(SHARED, MediaType.HTML, None, "", "", "globex")
        self.assertNotEqual(
            key_a,
            key_b,
            msg=(
                "two tenants addressing the same content produce the same cache "
                "key: the decision cache is a shared, un-partitioned namespace"
            ),
        )

    def test_attack_cache_key_accepts_a_tenant(self):
        import inspect

        from app.core.engine import NsfwEngine

        source = inspect.signature(NsfwEngine._cache_key_for)
        self.assertIn(
            "tenant_id",
            source.parameters,
            msg="_cache_key_for has no way to partition by tenant",
        )

    def test_attack_failures_are_never_written_to_the_cache(self):
        """A transient failure must not be memoised for the whole TTL.

        This was worth checking carefully rather than assuming: if a deadline
        breach *were* cached, one tenant's slow request would fail every other
        tenant's identical request for the cache lifetime, and with a
        fail-closed policy that is a free denial of service. An earlier draft
        of this test forced the poison with a direct ``cache.put`` and proved
        nothing - the engine already refuses to store failures, and no caller
        can reach the cache to write one.
        """
        from app.models.base import MediaType

        engine = _engine()
        # Bytes the engine cannot decode, so the failure path really runs.
        undecodable = b"\x00\x01\x02\x03" * 8
        result = engine.classify(undecodable, MediaType.UNKNOWN)
        key = engine._cache_key_for(undecodable, MediaType.UNKNOWN, None, "", "")
        self.assertIsNone(
            engine.cache.get(key),
            msg=(
                "a failed classification was stored in the cache; with a "
                "fail-closed policy one tenant's error would become every "
                "other tenant's BLOCK for the TTL"
            ),
        )
        self.assertTrue(result.error or result.verdict is not None)

    def test_attack_a_poisoned_entry_cannot_cross_a_tenant_boundary(self):
        """Even a hand-planted entry stays inside its tenant's namespace.

        Defence in depth behind the "failures are never cached" rule above:
        the cache is not a write surface reachable by a tenant, but the key is
        partitioned anyway, so a stale or foreign entry cannot be served.
        """
        from app.models.base import MediaType

        engine = _engine()
        acme_key = engine._cache_key_for(SHARED, MediaType.HTML, None, "", "", "acme")
        engine.cache.put(
            acme_key,
            {"verdict": "NSFW", "score": 0.99, "action": "BLOCK",
             "policy_id": "acme-strict", "error": "", "text": None,
             "decided_by": "DEEP", "media_type": "HTML"},
        )
        globex = engine.classify(SHARED, MediaType.HTML, tenant_id="globex")
        self.assertFalse(
            globex.from_cache,
            msg="globex was served acme's cached entry",
        )
        self.assertNotEqual(getattr(globex, "policy_id", ""), "acme-strict")

    def test_attack_poisoned_cache_entry_does_not_carry_a_stale_action(self):
        """A cached ``action``/``policy_id`` is another tenant's enforcement."""
        from app.models.base import MediaType

        engine = _engine()
        key = engine._cache_key_for(SHARED, MediaType.HTML, None, "", "")
        engine.cache.put(
            key,
            {
                "verdict": "NSFW",
                "decided_by": "DEEP",
                "media_type": "HTML",
                "score": 0.99,
                "action": "BLOCK",
                "policy_id": "victim-strict-policy",
                "text": None,
                "error": "",
            },
        )
        served = engine.classify(SHARED, MediaType.HTML)
        self.assertNotEqual(
            getattr(served, "policy_id", ""),
            "victim-strict-policy",
            msg="a cached entry carried another tenant's policy_id to this one",
        )


class PolicyEngineExploits(unittest.TestCase):
    """The rule engine runs an operator-supplied regex over request data.

    ``Rule.evaluate`` maps ``matches`` to ``re.search(value, actual)``. The
    pattern comes from a policy document (runtime-installable through
    ``POST /v1/policies``), the subject is attacker-supplied content, and
    nothing bounds either. A catastrophic pattern - ``(a+)+$`` - turns any
    request into a CPU sink.
    """

    def test_attack_policy_regex_is_bounded(self):
        import inspect

        from policy.models import Rule

        source = inspect.getsource(Rule.evaluate)
        self.assertNotIn(
            "re.search(str(self.value), str(actual)",
            source,
            msg=(
                "the matches operator compiles and runs an unbounded regex "
                "against request-controlled data: ReDoS reachable from a "
                "policy document"
            ),
        )

    def test_attack_catastrophic_pattern_is_rejected_at_install_time(self):
        from policy.engine import policy_from_dict

        document = {
            "policy_id": "redos",
            "default_action": "review",
            "rules": [
                {"field": "url", "operator": "matches", "value": "(a+)+$", "action": "block"}
            ],
        }
        policy = policy_from_dict(document)
        self.assertEqual(
            policy.rules,
            [],
            msg=(
                "a catastrophic-backtracking pattern was accepted at install "
                "time; it must be rejected before it can be armed"
            ),
        )

    def test_attack_regex_subject_is_length_bounded(self):
        from policy.models import Rule

        rule = Rule("url", "matches", "https?://.*", "block")
        try:
            rule.evaluate({"url": "https://example.invalid/" + "a" * 5_000_000})
        except Exception as exc:  # noqa: BLE001
            self.fail(f"regex evaluation raised instead of degrading: {exc!r}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()