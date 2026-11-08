# Model Drift Detection

Monitors model performance in production to detect degradation.

## Metrics Tracked
- False Positive Rate (FPR)
- False Negative Rate (FNR)
- Overall Accuracy
- Response time percentiles

## Detection
- Sliding window analysis (last 1000 predictions)
- Threshold-based alerts (FPR > 0.05, FNR > 0.1)
- Prometheus alerts configured

## Implementation
Add to app/core/drift_detection.py:
- Sliding window metrics collector
- Statistical tests (Kolmogorov-Smirnov)
- Alert generation

Status: Documentation completed, implementation pending (~3 hours)
