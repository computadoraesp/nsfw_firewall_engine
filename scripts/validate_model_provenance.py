"""Validate MODEL_PROVENANCE.md SHA‑256 entries against actual ONNX files.

The script parses the Markdown table in ``docs/MODEL_PROVENANCE.md`` and for each row
with a non‑empty ``SHA‑256 of ONNX artifact`` column it computes the SHA‑256 hash of the
corresponding file in ``models_onnx/`'. (The file name is derived from the *Model* column.)
If any hash differs, the script prints a warning and exits with a non‑zero status.

Typical usage:
    Python scripts/validate_model_provenance.py --check
"""

import argparse
import hashlib
import pathlib
import re
import sys
from typing import List, Tuple

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROVENANCE_MD = ROOT / "docs" / "MODEL_PROVENANCE.md"
MODELS_DIR = ROOT / "models_onnx"

TABLE_LINE_RE = re.compile(r"^\|\s*(?P<model>[^|]+)\|\s*(?P<source>[^|]*)\|\s*(?P<license>[^|]*)\|\s*(?P<commit>[^|]*)\|\s*(?P<sha>[^|]*)\|\s*(?P<script>[^|]*)\|")

def parse_table(md_path: pathlib.Path) -> List[Tuple[str, str]]:
    """Return a list of (model_name, sha256) for rows that specify a SHA‑256.

    ``model_name`` is the raw content of the *Model* column (e.g. ``fast_path (MobileNetV3‑Small)``).
    The function does **not** attempt to normalize the name – the caller decides how to map it
    to a file in ``models_onnx/``.
    """
    rows: List[Tuple[str, str]] = []
    with md_path.open(encoding="utf-8") as f:
        for line in f:
            m = TABLE_LINE_RE.match(line)
            if m:
                model = m.group("model").strip()
                sha = m.group("sha").strip()
                if sha:
                    rows.append((model, sha))
    return rows

def guess_filename(model_desc: str) -> pathlib.Path:
    """Derive a plausible ONNX filename from the *Model* description.

    The description usually follows the pattern ``<stage> (Human‑Readable)``.
    We extract the first word before any whitespace or parenthesis as the base name
    and append ``.onnx``.  Examples:
        ``fast_path (MobileNetV3‑Small)`` -> ``fast_path.onnx``
        ``deep_path (EfficientNet‑B0)``   -> ``deep_path.onnx``
        ``multimodal (ResNet‑50)``        -> ``multimodal.onnx``
    If the file does not exist, the caller can decide what to do.
    """
    base = model_desc.split()[0]
    return MODELS_DIR / f"{base}.onnx"

def compute_sha256(file_path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def validate() -> int:
    rows = parse_table(PROVENANCE_MD)
    if not rows:
        print("[INFO] No SHA‑256 entries found in MODEL_PROVENANCE.md – nothing to validate.")
        return 0
    exit_code = 0
    for model_desc, expected_sha in rows:
        candidate = guess_filename(model_desc)
        if not candidate.exists():
            print(f"[WARN] Expected ONNX file not found for '{model_desc}': {candidate}")
            exit_code = 1
            continue
        actual_sha = compute_sha256(candidate)
        if actual_sha.lower() != expected_sha.lower():
            print(f"[ERROR] SHA‑256 mismatch for {candidate.name}: expected {expected_sha}, got {actual_sha}")
            exit_code = 1
        else:
            print(f"[OK] {candidate.name} matches recorded SHA‑256.")
    return exit_code

def main() -> None:
    parser = argparse.ArgumentParser(description="Validate MODEL_PROVENANCE.md SHA‑256 hashes.")
    parser.add_argument("--check", action="store_true", help="Run validation and exit with status.")
    args = parser.parse_args()
    if args.check:
        sys.exit(validate())
    else:
        parser.print_help()
        sys.exit(0)

if __name__ == "__main__":
    main()
