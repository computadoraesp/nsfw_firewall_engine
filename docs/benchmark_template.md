# Benchmark Template

This document outlines the structure for reproducible benchmark reports once evaluation data and model artifacts are available.

## Dataset Summary
- **Dataset name**: 
- **Source / license**: 
- **Number of samples**: 
- **Class distribution**:
  - `nsfw`: 
  - `suggestive`: 
  - `safe`: 
  - `uncertain`: 

## Evaluation Metrics
| Model | FPR | FNR | PR‑AUC | ECE | Calibration method |
|-------|-----|-----|--------|-----|-------------------|
| fast_path (MobileNetV3‑Small) |  |  |  |  |  |
| deep_path (EfficientNet‑B0) |  |  |  |  |  |
| multimodal (ResNet‑50) |  |  |  |  |  |
| text_path (DistilBERT) |  |  |  |  |  |

## Calibration Details
- Method used (Platt, isotonic, temperature scaling, etc.)
- Validation set size
- Hyper‑parameters

## Reproducibility
- Command used for inference (e.g., `Python -m benchmarks --dataset ...`)
- Library versions (Python, ONNX Runtime, NumPy, etc.)
- Random seed(s)

*When the benchmark is run, fill in the tables and commit this file.*
