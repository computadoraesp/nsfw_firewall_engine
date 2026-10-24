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

# The adapters package lives at the repo root; make it importable when this
# script is run directly (python scripts/verify_models.py).
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from adapters.labels import sidecar_path  # noqa: E402

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
    """Hash every ``*.onnx`` *and* its ``*.labels.json`` under *directory*.

    Label sidecars are hashed for the same reason as the graphs: the class order
    decides whether an output means "NSFW" or "safe", so an attacker able to
    rewrite ``vit_nsfw.labels.json`` could invert every decision without
    touching a single weight (§38).
    """
    found: Dict[str, dict] = {}
    if not directory.is_dir():
        return found
    for artifact in sorted(directory.rglob("*.onnx")):
        # ``quantize_models.py`` stages a ``*.quantizable.onnx`` copy so
        # quantize_dynamic's shape inference can run. It is a build
        # intermediate, never a deployed artifact, so it must not enter the
        # lockfile: pinning it would make ``--require-all`` fail once the
        # operator cleans up the temporary, and would imply a review for a file
        # nobody ships.
        if artifact.name.endswith(".quantizable.onnx"):
            continue
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
        sidecar = sidecar_path(artifact)
        if sidecar.is_file():
            try:
                sidecar_relative = sidecar.relative_to(PROJECT_ROOT).as_posix()
            except ValueError:
                sidecar_relative = sidecar.name
            found[sidecar_relative] = {
                "sha256": sha256_file(sidecar),
                "size_bytes": sidecar.stat().st_size,
                "role": "label-sidecar",
                "of": relative,
            }
        # A graph over ~2GB keeps its tensor data in a sibling ``.onnx.data``.
        # Hashing only the graph would seal a file that is nearly empty while
        # leaving the actual weights unsealed, so both halves are pinned (§38).
        data = artifact.with_suffix(artifact.suffix + ".data")
        if data.is_file():
            try:
                data_relative = data.relative_to(PROJECT_ROOT).as_posix()
            except ValueError:
                data_relative = data.name
            found[data_relative] = {
                "sha256": sha256_file(data),
                "size_bytes": data.stat().st_size,
                "role": "onnx-external-data",
                "of": relative,
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


def check_loadable(directory: Path = MODELS_DIR) -> List[str]:
    """Report artifacts that pass the hash check but cannot be loaded.

    Integrity and loadability are different properties, and a lockfile only
    proves the first. A model exported with a newer opset than the pinned
    onnxruntime supports will hash-match perfectly and then fail to load at
    inference time - the engine quietly falls back to a stub, `/v1/ready`
    reports false, and the deployment looks healthy right up until the point
    where the deep path is not running at all.

    That is a silent accuracy regression, so it is reported here rather than
    discovered during an incident.
    """
    messages: List[str] = []
    try:
        import onnxruntime  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        return [f"onnxruntime unavailable, cannot check loadability ({exc})"]

    for path in sorted(Path(directory).glob("*.onnx")):
        try:
            import onnxruntime as ort  # type: ignore

            session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
            del session
        except Exception as exc:  # noqa: BLE001
            messages.append(f"UNLOADABLE {path.name} ({type(exc).__name__}: {exc})")
    return messages


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
    parser.add_argument(
        "--check-loadable",
        action="store_true",
        help=(
            "also confirm each graph actually loads under the installed "
            "onnxruntime; a hash match does not imply the opset is supported"
        ),
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
        graphs = sorted(k for k, m in artifacts.items() if m.get("role") != "label-sidecar")
        sidecars = sorted(
            k for k, m in artifacts.items() if m.get("role") == "label-sidecar"
        )
        externals = sorted(
            k for k, m in artifacts.items() if m.get("role") == "onnx-external-data"
        )
        print(f"wrote {path} ({len(artifacts)} artifact(s))")
        for relative, meta in sorted(artifacts.items()):
            marker = ""
            if meta.get("role") == "label-sidecar":
                # Say out loud that the class order is now pinned too: an
                # operator who does not know the sidecar is hash-locked may not
                # realise that editing it would fail the next deploy (§38).
                marker = f"  [label sidecar for {meta.get('of')}]"
            elif meta.get("role") == "onnx-external-data":
                marker = f"  [tensor data for {meta.get('of')}]"
            print(
                f"  {relative}  {meta['sha256'][:16]}...  "
                f"{meta['size_bytes']} bytes{marker}"
            )
        print(
            f"\n[*] {len(graphs)} graph(s), {len(sidecars)} label sidecar(s) and "
            f"{len(externals)} external tensor file(s) pinned. A sidecar fixes "
            "its artifact's class order; without it the adapter refuses to "
            "score rather than guess (§49)."
        )
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

    if args.check_loadable:
        print("\n[*] checking that each graph loads under the installed runtime")
        loadability = check_loadable(args.models_dir)
        for message in loadability:
            print(message)
        if loadability:
            ok = False
            print(
                "\n[!] An artifact can be hash-correct and still unloadable when\n"
                "    it was exported with a newer opset than the pinned\n"
                "    onnxruntime supports. The engine degrades to a stub, so the\n"
                "    affected stage silently stops scoring. Re-export at a\n"
                "    supported opset or pin a runtime that accepts it."
            )

    print("\nRESULT:", "verified" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())