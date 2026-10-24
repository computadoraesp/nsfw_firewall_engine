#!/usr/bin/env python
"""
download_and_convert.py

Descarga los checkpoints desde Hugging Face y los exporta a ONNX
con opset_version=14 (compatible con onnxruntime ≥ 1.17).

Uso:
    python scripts/download_and_convert.py
"""

import os
import torch
# Ensure stdout uses UTF-8 to avoid cp1252 encoding errors
os.environ["PYTHONIOENCODING"] = "utf-8"
# Disable verbose Unicode prints from torch.onnx exporter
os.environ["TORCH_ONNX_VERBOSE"] = "0"
from pathlib import Path
from huggingface_hub import snapshot_download, hf_hub_download

# Directorio donde guardaremos los *.onnx
ONNX_DIR = Path(__file__).resolve().parents[1] / "models_onnx"
ONNX_DIR.mkdir(parents=True, exist_ok=True)

def export_to_onnx(model, dummy_input, onnx_path, opset=18):
    torch.onnx.export(
        model,
        dummy_input,
        str(onnx_path),
        export_params=True,
        opset_version=opset,
        do_constant_folding=True,
        verbose=False,
        input_names=["input"],
        output_names=["logits"],
    )
    print(f"[ONNX saved] {onnx_path}")

def download_vit_nsfw():
    from transformers import AutoModel
    model = AutoModel.from_pretrained("google/vit-base-patch16-224")
    dummy = torch.randn(1, 3, 224, 224)  # size used by the public ViT model
    export_to_onnx(model, dummy, ONNX_DIR / "vit_nsfw.onnx")

def download_fast_path():
    from torchvision import models
    model = models.mobilenet_v3_small(pretrained=True).features
    model.eval()
    dummy = torch.randn(1, 3, 224, 224)
    export_to_onnx(model, dummy, ONNX_DIR / "fast_path_mobilenetv3.onnx")

def download_multimodal_clip():
    from transformers import CLIPModel
    model = CLIPModel.from_pretrained("openai/clip-vit-base-patch32")
    # Exportar solo la parte visual (vision_model)
    vision = model.vision_model
    dummy = torch.randn(1, 3, 224, 224)
    export_to_onnx(vision, dummy, ONNX_DIR / "multimodal_clip.onnx")

def download_text_distilbert():
    from transformers import DistilBertModel
    model = DistilBertModel.from_pretrained("distilbert-base-uncased")
    dummy = torch.randint(0, 30522, (1, 128))  # longitud típica de texto
    export_to_onnx(model, dummy, ONNX_DIR / "text_distilbert.onnx")

if __name__ == "__main__":
    # Instala dependencias de huggingface si no están presentes
    try:
        import transformers, torchvision
    except ImportError:
        raise RuntimeError(
            "Instala dependencias primero: pip install transformers[torch] torchvision huggingface_hub"
        )

    print("Downloading and converting models...")
    download_vit_nsfw()
    download_fast_path()
    download_multimodal_clip()
    download_text_distilbert()
    print("\n[DONE] All ONNX models are available at:", ONNX_DIR)
