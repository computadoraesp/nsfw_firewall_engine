# Evaluation Corpus

This directory contains the evaluation dataset for the NSFW Firewall Engine.

## Purpose

The corpus is used for:
- Model evaluation (FPR/FNR/PR-AUC)
- Threshold calibration
- Benchmark reproducibility
- Model validation (candidate → validated → production)

## Structure

```
benchmarks/corpus/
├── README.md              # This file
├── nsfw/                  # NSFW content (100+ images)
├── suggestive/            # Suggestive/borderline content (50+ images)
├── safe/                  # Safe content (200+ images)
├── uncertain/             # Uncertain/hard cases (50+ images)
└── labels.json            # Ground truth labels
```

## Adding Images

**IMPORTANT:** Do not commit NSFW content to the repository. Use environment-specific datasets.

### Adding Safe Images

```bash
# Add safe images
cp your_safe_images/* benchmarks/corpus/safe/

# Update labels.json
Python scripts/update_corpus_labels.py
```

### Adding Sensitive Images

For production evaluation, store sensitive content in a secure location:

```bash
# Use encrypted storage or secure network share
SECURE_CORPUS="/secure/nsfw-firewall-corpus"

# Copy and organize
mkdir -p $SECURE_CORPUS/{nsfw,suggestive,safe,uncertain}
```

## Dataset Requirements

**Minimum Sizes:**
- NSFW: 100 images
- Suggestive: 50 images
- Safe: 200 images
- Uncertain: 50 images

**Image Requirements:**
- JPEG or PNG format
- Resolution: 224x224 to 384x384 (match model input)
- File size: < 5 MB per image
- License: MIT, Apache-2.0, CC-BY, or similar

## Label Format

`labels.json` structure:

```json
{
  "version": "1.0",
  "created": "2026-10-18",
  "images": {
    "safe/image001.jpg": {
      "label": "safe",
      "source": "unsplash",
      "license": "CC0"
    },
    "nsfw/image001.jpg": {
      "label": "nsfw",
      "source": "internal",
      "license": "private"
    }
  }
}
```

## Running Evaluation

```bash
# Run evaluation with corpus
Python benchmarks/evaluate.py --corpus benchmarks/corpus

# Calculate metrics
Python benchmarks/evaluate.py --corpus benchmarks/corpus --metrics

# Calibrate thresholds
Python scripts/fit_threshold.py --corpus benchmarks/corpus
```

## Privacy and Licensing

**Privacy:**
- NSFW content must NOT be committed to Git
- Use `.gitignore` to exclude sensitive directories
- Store NSFW content in secure, access-controlled storage
- Consider using synthetic or anonymized data where possible

**Licensing:**
- Only use images with permissive licenses
- Document source and license for each image
- Respect copyright and usage terms
- For commercial use, ensure commercial licenses

## Public Corpus Options

For initial testing, consider these public datasets:

**Safe Images:**
- Unsplash (CC0 license)
- Pexels (free for commercial use)
- Pixabay (free for commercial use)

**NSFW Images:**
- **DO NOT** download from public sources without explicit permission
- Create internal corpus with properly licensed content
- Consult legal team before using NSFW content for evaluation

## Corpus Template

A minimal corpus template is provided for initial testing:

```bash
# Create minimal test corpus
mkdir -p benchmarks/corpus/{safe,suggestive}
# Add 10 safe images from public sources
# Run initial evaluation
Python benchmarks/evaluate.py --corpus benchmarks/corpus --quick
```

## References

- [docs/MODEL_PROVENANCE.md](../docs/MODEL_PROVENANCE.md) - Model lifecycle
- [benchmarks/evaluate.py](../benchmarks/evaluate.py) - Evaluation script
- [scripts/fit_threshold.py](../scripts/fit_threshold.py) - Threshold calibration
