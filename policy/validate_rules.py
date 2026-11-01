import argparse
import sys
import yaml
from pathlib import Path

def load_yaml(file_path: Path):
    """Load a YAML file safely.

    Returns the parsed data or raises a yaml.YAMLError.
    """
    with file_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def validate_policy_file(file_path: Path) -> bool:
    """Validate a single policy YAML file.

    Currently, this stub checks that the file can be parsed and that the top‑level
    keys contain at least ``rules`` and ``metadata`` (optional). Extend with schema
    validation as needed.
    """
    try:
        data = load_yaml(file_path)
    except yaml.YAMLError as exc:
        print(f"[ERROR] {file_path}: YAML parse error – {exc}", file=sys.stderr)
        return False

    if not isinstance(data, dict):
        print(f"[ERROR] {file_path}: Expected a mapping at top level.", file=sys.stderr)
        return False

    # Very light‑weight checks – actual schema validation can be added later.
    if "rules" not in data:
        print(f"[WARN] {file_path}: missing 'rules' key – may be intentional.")
    # metadata is optional but if present should be a mapping.
    if "metadata" in data and not isinstance(data["metadata"], dict):
        print(f"[ERROR] {file_path}: 'metadata' must be a mapping.", file=sys.stderr)
        return False

    print(f"[OK] {file_path}")
    return True

def main():
    parser = argparse.ArgumentParser(
        description="Validate policy YAML files in the 'policy/' directory."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["policy"],
        help="Files or directories to validate. Defaults to the project's policy/ folder.",
    )
    args = parser.parse_args()

    any_failed = False
    for path_str in args.paths:
        path = Path(path_str)
        if not path.exists():
            print(f"[ERROR] Path does not exist: {path}", file=sys.stderr)
            any_failed = True
            continue
        if path.is_file():
            if not validate_policy_file(path):
                any_failed = True
        else:
            for yaml_file in path.rglob("*.yaml"):
                if not validate_policy_file(yaml_file):
                    any_failed = True

    sys.exit(1 if any_failed else 0)

if __name__ == "__main__":
    main()
