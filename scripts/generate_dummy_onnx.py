"""Generate a minimal dummy ONNX model **for tests**.

The model is an identity graph: input -> output. It satisfies a runtime
loader's structural expectations and nothing more. It has no business running
in production.

SECURITY: this script used to default to ``models_onnx/vit_nsfw.onnx`` - the
deep-path model's real, licensed production path - and called ``onnx.save``
on it with no confirmation. Running it silently replaced a reviewed 22 MB
artifact with a 101-byte stub, and the only thing that noticed was the
integrity check afterwards. A developer utility must not be able to destroy a
production artifact by being invoked, so:

* the default output lives under ``.test-fixtures/``, never in ``models_onnx/``;
* an existing file is **never** overwritten without ``--force``;
* targeting anything inside ``models_onnx/`` is refused outright unless the
  operator names the file *and* passes ``--force``;
* ``ir_version`` is pinned explicitly. Setting ``opset_import`` to 13 is not
  enough: ``onnx.make_model`` stamps the *IR* version from the installed
  ``onnx`` package, and a newer ``onnx`` writes IR 14 - which the pinned
  onnxruntime rejects outright. That is what made the original dummy
  unloadable, so a fixture the tests could not even load.

Usage::

    python scripts/generate_dummy_onnx.py                       # test fixture
    python scripts/generate_dummy_onnx.py --output path.onnx    # explicit path
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import onnx
from onnx import TensorProto, helper

#: IR version accepted by onnxruntime 1.20.x (IR 14 is rejected).
SAFE_IR_VERSION = 9

#: Directory reserved for generated fixtures. Kept out of ``models_onnx`` so a
#: stray run can never be mistaken for, or mistaken as, a reviewed artifact.
TEST_FIXTURE_DIR = Path(".test-fixtures")

#: The directory that holds licensed, hash-pinned production artifacts.
PRODUCTION_DIR = Path("models_onnx")


def create_identity_model(
    input_name: str, output_name: str, dim: int = 3
) -> onnx.ModelProto:
    """An identity graph that a loader accepts and nothing can learn from."""
    input_tensor = helper.make_tensor_value_info(input_name, TensorProto.FLOAT, [1, dim])
    output_tensor = helper.make_tensor_value_info(output_name, TensorProto.FLOAT, [1, dim])

    model = helper.make_model(
        helper.make_graph(
            nodes=[helper.make_node("Identity", inputs=[input_name], outputs=[output_name])],
            name="IdentityGraph",
            inputs=[input_tensor],
            outputs=[output_tensor],
        ),
        # Pinned: the installed `onnx` would otherwise stamp its own, and a
        # fixture the runtime cannot load is not a fixture.
        ir_version=SAFE_IR_VERSION,
    )
    model.opset_import[0].version = 13
    return model


def resolve_output(raw: str | None, force: bool) -> Path:
    """Decide where the fixture goes, refusing to endanger a real artifact."""
    target = Path(raw) if raw else (TEST_FIXTURE_DIR / "identity_fixture.onnx")

    in_production = PRODUCTION_DIR in target.parts or target.parts[:1] == PRODUCTION_DIR.parts
    if in_production and not force:
        raise SystemExit(
            f"refusing to write into {PRODUCTION_DIR}/ without --force.\n"
            "That directory holds licensed, hash-pinned production artifacts "
            "(see docs/MODEL_PROVENANCE.md). Writing there silently replaced a "
            "reviewed model with a stub once already.\n"
            "\nIf you really mean to replace an artifact, re-fetch it with:\n"
            "    python scripts/fetch_pretrained.py --help"
        )

    if target.exists() and not force:
        raise SystemExit(
            f"{target} already exists. Pass --force to overwrite it, or "
            "choose another --output."
        )
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a dummy identity ONNX fixture (tests only)."
    )
    parser.add_argument(
        "--output",
        default=None,
        help=f"destination path (default: {TEST_FIXTURE_DIR}/identity_fixture.onnx)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="allow overwriting an existing file or writing into models_onnx/",
    )
    args = parser.parse_args(argv)

    target = resolve_output(args.output, args.force)
    target.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(create_identity_model("input", "output"), str(target))
    print(f"dummy ONNX fixture written to {target} (ir_version={SAFE_IR_VERSION})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())