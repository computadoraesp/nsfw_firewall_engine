## Benchmark matrix (§25)

Iterations: **60** (warmup 10)

- Models loaded: **False**
- Heuristic fallback: **True**

> ⚠️ Measured on the **heuristic fallback** - these numbers describe the pipeline, not a detector. Re-run with real weights before publishing performance claims (§49).

| Metric | p50 (ms) | p95 (ms) | p99 (ms) | mean (ms) |
|---|---|---|---|---|
| end-to-end | 4.8868 | 7.0527 | 8.2399 | 5.1545 |
| stage:FAST | 4.6929 | 6.7896 | 7.9219 | 4.9436 |

- Throughput (serial, 1 worker): **194.0 req/s**
- Verdict mix: {'NSFW': 30, 'SFW': 30}
- Escalations: {'FAST': 60}
- Cache hits: 0
