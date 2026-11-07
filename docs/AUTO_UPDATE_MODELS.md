# Automatic Model Weights Update

## Overview

The NSFW Firewall Engine can automatically update model weights from PyTorch Hub on a scheduled basis. This ensures you always have the latest available weights without manual intervention.

## How It Works

1. **Weekly Check:** GitHub Actions runs every Monday at 00:00 UTC
2. **Hash Comparison:** Compares current model hash with latest from PyTorch Hub
3. **Automatic Update:** If new version available, downloads and converts to ONNX
4. **Backup:** Old model is backed up before replacement
5. **Registry:** Update timestamp and hash recorded in `models_onnx/registry.json`

## Manual Usage

### Check for Updates (No Download)
```bash
python scripts/auto_update_models.py --model all --check-only
```

### Update Specific Model
```bash
python scripts/auto_update_models.py --model fast_path
```

### Update All Models
```bash
python scripts/auto_update_models.py --model all
```

## Supported Models

| Model Name | PyTorch Model | Output File |
|------------|---------------|-------------|
| fast_path | MobileNetV3-Small | fast_path_mobilenetv3.onnx |
| deep_path | EfficientNet-B0 | deep_path_efficientnetb0.onnx |

## GitHub Actions Workflow

The workflow `.github/workflows/auto_update_models.yml` runs weekly and:
1. Checks for updates
2. If updates available, downloads and converts
3. Commits and pushes new models to repository
4. Creates backup of old models

## Configuration

### Schedule
Default: Every Monday at 00:00 UTC
Modify in `.github/workflows/auto_update_models.yml`:
```yaml
schedule:
  - cron: '0 0 * * 1'  # Weekly
```

### Add New Models
Edit `scripts/auto_update_models.py` and add to `MODEL_REGISTRY`:
```python
MODEL_REGISTRY = {
    "new_model": {
        "torchvision_model": "model_name",
        "weights_class": "WeightsClass",
        "output_name": "output.onnx",
        "input_size": 224,
    },
}
```

## Registry File

The registry file `models_onnx/registry.json` tracks:
- Current model hash
- Last update timestamp
- Source (PyTorch Hub)
- Model name

Example:
```json
{
  "fast_path": {
    "hash": "abc123...",
    "updated_at": "2026-11-07T00:00:00",
    "source": "pytorch_hub",
    "model": "mobilenet_v3_small"
  }
}
```

## Benefits

- **Automatic:** No manual intervention required
- **Safe:** Backups created before replacement
- **Traceable:** Registry tracks all updates
- **Rollback:** Old models backed up with `.backup` extension
- **Scheduled:** Weekly checks for new versions

## Rollback

If a new model causes issues, rollback using backup:
```bash
cd models_onnx
mv fast_path_mobilenetv3.onnx fast_path_mobilenetv3.onnx.new
mv fast_path_mobilenetv3.onnx.backup fast_path_mobilenetv3.onnx
```

## Security

- Models downloaded from official PyTorch Hub
- Hash verification ensures integrity
- Only trusted PyTorch/TorchVision models supported
- No arbitrary model downloads
