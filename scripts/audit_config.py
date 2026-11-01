"""Audit the configuration surface for dead or contradictory settings.

This exists because the project accumulated config keys that were *declared but
never read* - documentation that quietly lied to operators. The worst example
was `engine.fail_mode`: an operator could set it to BLOCK and get fail-**open**
behavior, because only `policy.fail_action` was ever consulted.

Usage::

    Python scripts/audit_config.py            # human-readable report
    Python scripts/audit_config.py --strict   # exit 1 when problems are found

Checks:
* config files in ``config/`` that the code never loads;
* top-level keys in the YAML that ``EngineConfig`` does not model (silently
  dropped by pydantic);
* engine-config fields whose names never appear in the runtime source, which is
  the signature of a setting that does nothing;
* known duplicate switches (e.g. fail_mode vs fail_action).

Known limitation: the "fields never read" check is a heuristic name search.
Fields with common names (``cache``, ``policy``, ``transport``, ``video``) match
plenty of unrelated usages, so it under-reports rather than over-reports. The
other three checks are exact.
"""

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import yaml  # noqa: E402

from app.core.config import load_config  # noqa: E402

#: Config files the runtime actually reads.
LOADED_CONFIG_FILES = {"engine_config.yaml", "logging_config.yaml"}

#: Source trees scanned when looking for a field being *used*.
SOURCE_GLOBS = ("app/**/*.py", "policy/*.py", "content/*.py", "adapters/*.py")

#: Fields that are consumed indirectly (via getattr / model_dump / logging
#: setup), so a literal name search is not meaningful for them.
INDIRECT_FIELDS = {"environment", "url", "prefix"}

#: Config files that are *design references*, not runtime configuration: they
#: document hardware targets, quantization plans and the privacy policy, and are
#: never meant to be parsed at startup. Listing them here keeps ``--strict``
#: meaningful in CI - otherwise the gate would always fail on three files that
#: are correct by design, and the real regressions would be drowned out.
REFERENCE_CONFIG_FILES = {"hardware.yaml", "privacy.yaml", "quantization.yaml"}


def _source_blob() -> str:
    """Concatenate runtime sources, EXCLUDING config.py.

    config.py is where every field is *defined*, so including it would give each
    field at least one hit and make "never read" undetectable. Only genuine
    usages elsewhere should count.
    """
    parts = []
    for pattern in SOURCE_GLOBS:
        for path in PROJECT_ROOT.glob(pattern):
            if path.name == "config.py":
                continue
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def audit() -> dict:
    """Return a structured audit report."""
    import logging

    logging.disable(logging.CRITICAL)
    config = load_config()
    logging.disable(logging.NOTSET)

    raw = yaml.safe_load(
        (PROJECT_ROOT / "config" / "engine_config.yaml").read_text(encoding="utf-8")
    ) or {}
    modelled = set(config.model_dump())
    blob = _source_blob()

    unmodelled = sorted(set(raw) - modelled)
    # Split the unloaded files: a reference file is expected to be unread, while
    # an *unknown* extra file means someone dropped a config in and assumed it
    # was being applied.
    never_loaded = sorted(
        path.name
        for path in (PROJECT_ROOT / "config").glob("*.yaml")
        if path.name not in LOADED_CONFIG_FILES
    )
    reference_files = sorted(set(never_loaded) & REFERENCE_CONFIG_FILES)
    unexpected_files = sorted(set(never_loaded) - REFERENCE_CONFIG_FILES)

    never_read = []
    for name in sorted(modelled):
        if name in INDIRECT_FIELDS:
            continue
        # Appearances beyond the config module itself are what we care about.
        hits = len(re.findall(rf"\b{re.escape(name)}\b", blob))
        if hits <= 1:  # only the definition
            never_read.append(name)

    duplicates = []
    if getattr(config.engine, "fail_mode", None) != config.policy.fail_action:
        duplicates.append(
            "engine.fail_mode != policy.fail_action (policy is authoritative; "
            "the validator reconciles this)"
        )

    return {
        "unmodelled_yaml_keys": unmodelled,
        "config_files_never_loaded": never_loaded,
        "reference_config_files": reference_files,
        "unexpected_config_files": unexpected_files,
        "fields_never_read": never_read,
        "contradictions": duplicates,
    }


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    strict = "--strict" in argv
    report = audit()

    print("=== Config audit ===\n")
    print(f"YAML keys not modelled by EngineConfig: {report['unmodelled_yaml_keys'] or 'none'}")
    print(
        "Config files never loaded:              "
        f"{report['unexpected_config_files'] or 'none'}"
    )
    print(
        "Reference files (expected to be unread): "
        f"{report['reference_config_files'] or 'none'}"
    )
    print(f"EngineConfig fields never read:         {report['fields_never_read'] or 'none'}")
    print(f"Contradictory settings:                 {report['contradictions'] or 'none'}")

    # Only *actionable* findings gate CI. Reference config files are correct by
    # design and fields never read are a review hint, not a failure.
    blocking = sum(
        len(report[key])
        for key in ("unmodelled_yaml_keys", "unexpected_config_files", "contradictions")
    )
    advisory = len(report["fields_never_read"])
    print(f"\nBlocking findings: {blocking}   Advisory findings: {advisory}")
    if blocking:
        print(
            "\nEach blocking finding means a setting in config/engine_config.yaml is\n"
            "either ignored by the code or duplicated by another switch."
        )
    if advisory:
        print(
            "\nAdvisory: EngineConfig fields never read - review whether each should\n"
            "be wired up or removed."
        )
    return 1 if (blocking and strict) else 0


if __name__ == "__main__":
    sys.exit(main())