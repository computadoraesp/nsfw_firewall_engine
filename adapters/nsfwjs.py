# adapters/nsfwjs.py
"""Adapter for the fast‑path MobileNet model (NSFWJS).

The adapter uses the shared :class:`models.onnx_session.ONNXModelManager` to
obtain an ONNX Runtime session for the ``fast_path`` model and provides a simple
``predict`` function that accepts raw image bytes and returns the model output.

The expected output shape for the MobileNet model (as used by NSFWJS) is a
vector of class probabilities, e.g. ``["neutral", "sexy", "porn", "explicit"]``.
The wrapper extracts the first output tensor and returns it as a ``dict`` with
human‑readable keys.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from nsfw_firewall_engine.models.onnx_session import manager as onnx_manager

logger = logging.getLogger(__name__)

# Mapping of MobileNet output indices to category names – matches NSFWJS.
_MOBILE_NET_LABELS = ["neutral", "sexy", "porn", "explicit"]


def predict(image_bytes: bytes) -> Dict[str, float]:
    """Run the fast‑path MobileNet model on ``image_bytes``.

    The function expects a pre‑processed image tensor (e.g. 224×224 RGB, float32
    normalized).  For simplicity the preprocessing step is omitted – callers
    should transform the raw bytes using ``content.mime_detector`` and a
    ``preprocess_image`` helper before invoking this adapter.
    """
    # Obtain a thread‑local session for the fast_path model.
    session = onnx_manager.get_session("fast_path")

    # The ONNX model expects a named input – we query the model for the input name.
    input_name = session.get_inputs()[0].name

    # In a real implementation you would decode the image, resize, normalize, and
    # convert to a numpy array of shape (1, 3, 224, 224). Here we assume the caller
    # already provides the correctly shaped ``numpy`` array in ``image_bytes``
    # (encoded as raw bytes for the placeholder).
    # For the stub we simply pass the raw bytes; ONNX Runtime will raise if the
    # shape is wrong – this is acceptable for a placeholder.
    result = session.run(None, {input_name: image_bytes})
    # ``result`` is a list of output arrays – we take the first one.
    probs = result[0].flatten().tolist()
    # Map to label dict (clip length in case shape differs).
    return {label: probs[i] if i < len(probs) else 0.0 for i, label in enumerate(_MOBILE_NET_LABELS)}

__all__ = ["predict"]
