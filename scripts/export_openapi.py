"""Export the OpenAPI schema for the REST API (§46).

The engine serves ``/openapi.json`` at runtime, but enterprise consumers need a
committed, diffable contract artifact for gateway generation, client SDKs and
contract testing. This script writes it to disk.

Usage::

    Python scripts/export_openapi.py                       # docs/openapi.json
    Python scripts/export_openapi.py --output out.json     # custom path
    Python scripts/export_openapi.py --check               # fail if stale (CI)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

# Allow `Python scripts/export_openapi.py` from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "docs" / "openapi.json"


def build_schema() -> dict:
    """Build the OpenAPI document from the live FastAPI app."""
    from app.api.rest.router import create_app

    return create_app().openapi()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Export the NSFW engine OpenAPI schema.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero when the committed schema is out of date (CI gate)",
    )
    args = parser.parse_args(argv)

    schema = build_schema()
    payload = json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    if args.check:
        if not args.output.exists():
            print(f"missing schema: {args.output}")
            return 1
        if args.output.read_text(encoding="utf-8") != payload:
            print(f"stale schema: {args.output} - re-run without --check")
            return 1
        print(f"schema up to date: {args.output}")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(payload, encoding="utf-8")
    print(f"wrote {args.output} ({len(schema.get('paths', {}))} paths)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())