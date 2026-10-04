"""Production-readiness gate (``pront.md`` §43 / §46).

The default configuration boots **development-safe, not production-safe**:
``security.enabled`` is ``False`` and ``policy.fail_action`` is ``ALLOW``. Both
are deliberate - a service that refuses to start without secrets cannot be run
locally or in CI.

The danger is that nothing distinguishes the two cases. A deployment can be
promoted to production carrying the defaults and look completely healthy: the
liveness probe passes, ``/v1/ready`` may even report fine, and the only symptom
is that every classification is unauthenticated and every internal error fails
*open*. That is the worst possible failure mode for a firewall - it fails by
letting traffic through, silently.

This script refuses to pass a configuration that would do that.

Usage::

    python scripts/production_gate.py              # report
    python scripts/production_gate.py --strict     # exit 1 on findings
    python scripts/production_gate.py --config path/to/engine_config.yaml

Every finding is a *hard* failure. This gate has no warnings tier: a firewall
that is merely *probably* safe is not safe.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

Finding = Tuple[str, str, str]  # (severity, code, message)


def evaluate(config) -> List[Finding]:
    """Return every production-blocking finding for *config*.

    Returns a list rather than raising so the caller can report all problems at
    once - fixing them one restart at a time is how a deployment ends up
    half-hardened.
    """
    findings: List[Finding] = []

    # 1. Authentication must be on.
    if not config.security.enabled:
        findings.append((
            "BLOCKER",
            "security_disabled",
            "security.enabled=false: every classification request is "
            "unauthenticated. Any client can submit content and read verdicts.",
        ))

    # 2. Keys must actually exist. `enabled=true` with an empty key map is a
    #    configuration mistake that locks every legitimate caller out while
    #    looking correctly configured.
    if config.security.enabled and not config.security.api_keys:
        findings.append((
            "BLOCKER",
            "no_api_keys",
            "security.enabled=true but security.api_keys is empty: no caller "
            "can authenticate. Either provision keys or set security.enabled=false.",
        ))

    # 3. Fail-open is only acceptable when it is a deliberate, recorded choice.
    if str(config.policy.fail_action).upper() == "ALLOW":
        findings.append((
            "BLOCKER",
            "fail_open",
            "policy.fail_action=ALLOW: if the engine errors, policy resolves to "
            "ALLOW. A firewall should fail CLOSED. Set policy.fail_action=BLOCK.",
        ))

    # 4. Hashing keys, when enabled.
    if config.security.enabled and config.security.api_keys and not config.security.hash_api_keys:
        findings.append((
            "BLOCKER",
            "keys_stored_in_plaintext",
            "security.hash_api_keys=false: api_keys values are stored in the "
            "config file as usable credentials.",
        ))

    # 5. No real weights. `/v1/ready` stays false and the heuristic fallback
    #    decides policy - which is not a detector. Reuses verify_models' scanner
    #    so there is exactly one definition of "a weight file exists" in the
    #    repo; a second one here would drift.
    try:
        from scripts.verify_models import scan_artifacts

        artifacts = scan_artifacts()
        if not artifacts:
            findings.append((
                "BLOCKER",
                "no_model_weights",
                "No ONNX weights found. The engine falls back to a "
                "deterministic heuristic, which is not a trained detector. "
                "Publish a model before serving production traffic (§49).",
            ))
    except Exception as exc:  # noqa: BLE001
        findings.append((
            "BLOCKER",
            "weights_undeterminable",
            f"Could not determine whether weights are present: {exc}. "
            "Refusing to certify: an unknown model state is not a safe one.",
        ))

    return findings


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Production readiness gate.")
    parser.add_argument("--config", help="Path to engine_config.yaml")
    parser.add_argument("--strict", action="store_true",
                        help="Exit 1 when any finding is reported")
    args = parser.parse_args(argv)

    from app.core.config import load_config

    config = load_config(args.config) if args.config else load_config()
    findings = evaluate(config)

    print("Production readiness gate")
    print("=" * 60)
    if not findings:
        print("PASS - configuration is production-safe.")
        return 0

    print(f"{len(findings)} blocking finding(s):\n")
    for severity, code, message in findings:
        print(f"  [{severity}] {code}")
        for line in _wrap(message, 56):
            print(f"      {line}")
        print()

    print("Refusing to certify this deployment as production-ready.")
    print("See docs/THREAT_MODEL.md for the residual risks these settings cover.")
    return 1 if args.strict else 0


def _wrap(text: str, width: int) -> List[str]:
    import textwrap

    return textwrap.wrap(text, width=width) or [""]


if __name__ == "__main__":
    raise SystemExit(main())