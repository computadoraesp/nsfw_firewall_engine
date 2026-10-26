"""Generate a minimal evaluation corpus for testing.

This script creates a minimal corpus structure with placeholder images
for initial testing. For production evaluation, populate with real
images following the corpus structure.
"""

import json
from pathlib import Path
from typing import Dict

CORPUS_DIR = Path(__file__).parent.parent / "benchmarks" / "corpus"
LABELS_FILE = CORPUS_DIR / "labels.json"


def create_corpus_structure():
    """Create corpus directory structure."""
    directories = ["safe", "suggestive", "nsfw", "uncertain"]
    for dirname in directories:
        (CORPUS_DIR / dirname).mkdir(parents=True, exist_ok=True)
        print(f"Created: {CORPUS_DIR / dirname}")


def create_placeholder_labels():
    """Create placeholder labels.json."""
    labels = {
        "version": "1.0",
        "created": "2026-10-18",
        "note": "Placeholder labels - populate with real images",
        "images": {
            "safe/image001.jpg": {
                "label": "safe",
                "source": "placeholder",
                "license": "CC0"
            },
            "suggestive/image001.jpg": {
                "label": "suggestive",
                "source": "placeholder",
                "license": "CC0"
            },
            "nsfw/image001.jpg": {
                "label": "nsfw",
                "source": "placeholder",
                "license": "private"
            },
            "uncertain/image001.jpg": {
                "label": "uncertain",
                "source": "placeholder",
                "license": "CC0"
            }
        }
    }

    with open(LABELS_FILE, "w") as f:
        json.dump(labels, f, indent=2)
    print(f"Created: {LABELS_FILE}")


def create_gitignore():
    """Create .gitignore for corpus to prevent committing NSFW content."""
    gitignore_content = """# Never commit NSFW content
nsfw/
suggestive/
uncertain/

# Allow safe images for testing
!safe/

# Lockfile
labels.json
"""
    (CORPUS_DIR / ".gitignore").write_text(gitignore_content)
    print(f"Created: {CORPUS_DIR / '.gitignore'}")


def main():
    """Generate minimal corpus structure."""
    print("Generating minimal corpus structure...")
    create_corpus_structure()
    create_placeholder_labels()
    create_gitignore()
    print("\nCorpus structure created.")
    print(f"Location: {CORPUS_DIR}")
    print("\nNext steps:")
    print("1. Add safe images to benchmarks/corpus/safe/")
    print("2. For NSFW/suggestive content, use secure storage")
    print("3. Update labels.json with real image paths")
    print("4. Run: python benchmarks/evaluate.py --corpus benchmarks/corpus")


if __name__ == "__main__":
    main()
