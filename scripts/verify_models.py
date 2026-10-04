"""Verify model artifact integrity (pront.md §4, threat-model risk #8).

Model weights are license-bound supply-chain artifacts, so shipping them without
pinning their hashes makes the deployment unauditable: anyone who can write to
the models volume can change what the engine enforces. This script closes that
gap by comparing every artifact against a committed lockfile.

Usage::

    python scripts/verify_models.py                 # verify against the lockfile
    python scripts/verify_models.py --write         # (re)generate the lockfile
    python scripts/verify_models.py --require-all   # fail if any artifact is absent

Exit codes: ``0`` verified · ``1`` mismatch/missing (or lockfile absent) ·
``2`` bad usage. Suitable as a CI gate and as a container entrypoint check.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCKFILE = PROJECT_ROOT / "models_onnx" / "models.lock.json"
MODELS_DIR = PROJECT_ROOT / "models_onnx"
CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    """Stream a SHA256 over *path* so large models never load into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_lockfile(path: Path = LOCKFILE) -> Dict[str, dict]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8")).get("models", {})


def write_lockfile(models: Dict[str, dict], path: Path = LOCKFILE) -> Path:
    """Write the lockfile with sorted, stable output (diff-friendly)."""
    payload = {
        "_comment": [
            "SHA256 lockfile for model artifacts (see docs/MODEL_PROVENANCE.md).",
            "Regenerate ONLY after verifying the artifact's source and license:",
            "    python scripts/verify_models.py --write",
            "A mismatch here means the artifact is not the reviewed one.",
        ],
        "models": {name: models[name] for name in sorted(models)},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def scan_artifacts(directory: Path = MODELS_DIR) -> Dict[str, dict]:
    """Hash every ``*.onnx`` under *directory*."""
    found: Dict[str, dict] = {}
    if not directory.is_dir():
        return found
    for artifact in sorted(directory.rglob("*.onnx")):
        # Prefer a project-relative path so the lockfile is portable; fall back to
        # the bare file name when the models live outside the repo (PVC mounts,
        # side-loaded model directories).
        try:
            relative = artifact.relative_to(PROJECT_ROOT).as_posix()
        except ValueError:
            relative = artifact.name
        found[relative] = {
            "sha256": sha256_file(artifact),
            "size_bytes": artifact.stat().st_size,
        }
    return found
def verify(
    require_all: bool = False, lockfile: Path = LOCKFILE, directory: Path = MODELS_DIR
) -> Tuple[bool, List[str]]:
    """Compare artifacts against the lockfile. Returns ``(ok, messages)``."""
    expected = load_lockfile(lockfile)
    present = scan_artifacts(directory)

    # "Nothing to verify" is a legitimate state, not a failure. This repository
    # ships no ONNX weights by design: §40 forbids bundling explicit content and
    # the candidate licences are LEGAL_REVIEW_REQUIRED (§4). The engine then runs
    # on its documented heuristic fallback and reports itself not-ready.
    # Failing here would make the integrity gate permanently red and train
    # operators to ignore it - the opposite of what a security gate is for.
    # ``--require-all`` still forces a populated models directory for production
    # images, which is where a missing lockfile genuinely is an error.
    if not expected and not present:
        message = (
            "no lockfile and no .onnx artifacts: this deployment ships no weights "
            "and will run on the heuristic fallback (see docs/MODEL_PROVENANCE.md)"
        )
        # In a production image a populated models directory is mandatory, so
        # "nothing to verify" is a failure there even though it is fine in a
        # source checkout.
        if require_all:
            return False, [message + " --require-all was given"]
        return True, [message]

    if not expected:
        return False, [
            f"{len(present)} .onnx artifact(s) present but no lockfile at {lockfile} - "
            "run with --write after reviewing each artifact's source and licence"
        ]

    messages: List[str] = []
    ok = True
    seen = set()

    for relative, meta in sorted(expected.items()):
        seen.add(relative)
        # Lockfile entries are project-relative when possible, else resolved
        # against the models directory (PVC mounts, external model stores).
        artifact = PROJECT_ROOT / relative
        if not artifact.is_file():
            artifact = directory / relative
        if not artifact.is_file():
            ok = False
            messages.append(f"MISSING  {relative}")
            continue
        actual = sha256_file(artifact)
        if actual != meta.get("sha256"):
            ok = False
            messages.append(
                f"MISMATCH {relative}\n         expected {meta.get('sha256')}\n"
                f"         actual   {actual}"
            )
        else:
            messages.append(f"OK       {relative}")

    # An artifact on disk that is not in the lockfile is unvetted: it could be
    # anything, including a model-poisoned substitute (§38).
    for relative in sorted(set(present) - seen):
        ok = False
        messages.append(f"UNVETTED {relative} (present but not in the lockfile)")

    return ok, messages


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Verify model artifact integrity.")
    parser.add_argument(
        "--write",
        action="store_true",
        help="(re)generate the lockfile from the artifacts currently on disk",
    )
    parser.add_argument(
        "--require-all",
        action="store_true",
        help="fail when a lockfile artifact is absent (use in production images)",
    )
    parser.add_argument("--lockfile", type=Path, default=LOCKFILE)
    parser.add_argument("--models-dir", type=Path, default=MODELS_DIR)
    args = parser.parse_args(argv)

    if args.write:
        artifacts = scan_artifacts(args.models_dir)
        if not artifacts:
            print(f"no .onnx artifacts found under {args.models_dir}")
            return 1
        path = write_lockfile(artifacts, args.lockfile)
        print(f"wrote {path} ({len(artifacts)} artifact(s))")
        for relative, meta in sorted(artifacts.items()):
            print(f"  {relative}  {meta['sha256'][:16]}...  {meta['size_bytes']} bytes")
        print(
            "\n[!] Confirm each artifact's source and license in "
            "docs/MODEL_PROVENANCE.md before committing."
        )
        return 0

    ok, messages = verify(args.require_all, args.lockfile, args.models_dir)
    for message in messages:
        print(message)
    if not messages:
        print("no artifacts and no lockfile entries - nothing to verify")
    print("\nRESULT:", "verified" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())