# Shadow Testing (Canary Deployments)

Test new models in production without risk by shadowing requests.

## Architecture
- Primary model: Currently serving traffic
- Shadow model: New model under test
- Requests sent to both, only primary response used
- Results compared offline

## Implementation
Add to app/core/shadow_testing.py:
- Request duplicator
- Dual model inference
- Result comparison
- Statistical analysis (t-test, chi-square)

## Metrics Compared
- Latency difference
- Accuracy difference
- FPR/FNR difference
- Decision disagreement rate

## Deployment
1. Deploy shadow model alongside primary
2. Enable shadow mode in config
3. Collect data for 24-48 hours
4. Analyze results
5. Promote if metrics better

Status: Documentation completed, implementation pending (~5 hours)
