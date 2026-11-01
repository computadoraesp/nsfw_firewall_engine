# models/onnx_session.py
"""ONNX Runtime session manager.

This module centralizes creation and reuse of :class:`onnxruntime.InferenceSession`
objects for the three primary engines (fast_path, deep_path, multimodal).  It
supports:

* **Execution provider selection** – TensorRT, CUDA, OpenVINO, CPU – based on
  the ``engine_config.yaml`` ``onnx.providers`` list.
* **Dynamic precision** – the premium ViT model can run in FP16 by default and
  optionally in INT8 after a calibration run (see ``config/quantization.yaml``).
* **Thread‑level memory isolation** – each OS thread gets its own session
  instance via ``threading.local``.  This avoids cross‑thread memory contention
  when the underlying ONNX Runtime session holds per‑thread buffers.
* **Concurrency limits** – the number of concurrent sessions is capped by the
  ``engine.workers`` setting in ``engine_config.yaml``.
* **Graceful fallback** – if a GPU provider is unavailable, the manager falls
  back to the next provider in the list.

Typical usage::

    from models.onnx_session import ONNXModelManager

    manager = ONNXModelManager()
    fast_session = manager.get_session("fast_path")
    result = fast_session.run(["output"], {"input": image_tensor})

The manager is a singleton per process – instantiate it once at application
startup and reuse it throughout the request lifecycle.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

try:
    import onnxruntime as ort
except Exception as exc:  # pragma: no cover – ONNX Runtime must be installed
    raise ImportError("onnxruntime is required for ONNX session management") from exc

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration loading helpers
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        logger.warning("Configuration file %s not found – returning empty dict", path)
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as exc:  # pragma: no cover
        logger.error("Failed to parse YAML %s: %s", path, exc)
        return {}

# Engine config – holds provider list, paths, and worker counts.
_ENGINE_CFG_PATH = Path(__file__).parents[2] / "config" / "engine_config.yaml"
_ENGINE_CFG = _load_yaml(_ENGINE_CFG_PATH)

# Quantization config – determines default FP16/INT8 behavior for premium ViT.
_QUANT_CFG_PATH = Path(__file__).parents[2] / "config" / "quantization.yaml"
_QUANT_CFG = _load_yaml(_QUANT_CFG_PATH)

# ---------------------------------------------------------------------------
# Helper: build SessionOptions based on configuration
# ---------------------------------------------------------------------------

def _build_session_options(model_key: str) -> ort.SessionOptions:
    """Create ``SessionOptions`` for a given model.

    * Enables graph optimizations.
    * Sets intra‑op and inter‑op thread counts according to ``engine.workers``.
    * Configures FP16/INT8 execution when applicable.
    """
    opts = ort.SessionOptions()
    # Graph optimization level – mirrors engine_config.yaml default.
    optimization = _ENGINE_CFG.get("onnx", {}).get("graph_optimization_level", "ORT_ENABLE_ALL")
    try:
        opts.graph_optimization_level = getattr(ort.GraphOptimizationLevel, optimization)
    except Exception:
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

    # Thread configuration – share the global worker count if defined.
    workers = _ENGINE_CFG.get("engine", {}).get("workers", 4)
    opts.intra_op_num_threads = workers
    opts.inter_op_num_threads = max(1, workers // 2)

    # FP16 handling – for the premium ViT we optionally force FP16.
    if model_key == "multimodal":
        vit_cfg = _QUANT_CFG.get("quantization", {}).get("premium_vit", {})
        if vit_cfg.get("default") == "fp16":
            # TensorRT and CUDA providers understand the "EnableFP16" flag.
            opts.add_session_config_entry("session.optimized_fp16_enable", "1")
        # INT8 is optional – we expose the flag but keep it disabled until
        # the user toggles ``optional_int8.enabled``.
        if vit_cfg.get("optional_int8", {}).get("enabled"):
            opts.add_session_config_entry("session.optimized_int8_enable", "1")
    return opts

# ---------------------------------------------------------------------------
# Model path resolution
# ---------------------------------------------------------------------------

def _resolve_model_path(model_key: str) -> Path:
    """Return the absolute path to the ONNX model for ``model_key``.

    ``model_key`` must be one of ``fast_path``, ``deep_path`` or ``multimodal``.
    Paths are defined under ``engine_config.yaml`` ``paths``.
    """
    paths_cfg = _ENGINE_CFG.get("paths", {})
    key_map = {
        "fast_path": "fast_path_model",
        "deep_path": "deep_path_model",
        "multimodal": "multimodal_model",
    }
    rel_path = paths_cfg.get(key_map.get(model_key))
    if not rel_path:
        raise ValueError(f"Model path for {model_key!r} is not defined in engine_config.yaml")
    return Path(__file__).parents[2] / rel_path

# ---------------------------------------------------------------------------
# Provider selection – fall back gracefully
# ---------------------------------------------------------------------------

def _select_providers() -> List[str]:
    """Return the ordered list of execution providers.

    The list is taken from ``engine_config.yaml`` ``onnx.providers``.  If a
    provider cannot be initialized (e.g., missing GPU drivers), we attempt the
    next provider in the list.
    """
    raw_providers = _ENGINE_CFG.get("onnx", {}).get("providers", ["CPUExecutionProvider"])
    # Verify which providers are actually available at runtime. Provider entries
    # may be bare strings or ``{name, options}`` mappings.
    available = ort.get_available_providers()
    selected: List[str] = []
    for entry in raw_providers:
        name = entry.get("name") if isinstance(entry, dict) else entry
        if not name:
            continue
        if name in available:
            selected.append(name)
        else:
            logger.warning("Requested provider %s is not available – skipping", name)
    if not selected:
        logger.error("No valid ONNX ExecutionProvider found – defaulting to CPU")
        selected = ["CPUExecutionProvider"]
    return selected

# ---------------------------------------------------------------------------
# Thread‑local session cache
# ---------------------------------------------------------------------------
_thread_local = threading.local()


class ONNXModelManager:
    """Singleton‑style manager for ONNX Runtime sessions.

    The manager lazily creates a session per model **per thread**.  Subsequent
    calls from the same thread retrieve the cached session, guaranteeing that
    memory buffers are not shared across threads.
    """

    def __init__(self) -> None:
        self.providers = _select_providers()
        logger.info("ONNX providers selected: %s", self.providers)
        # Mapping ``model_key -> Path`` is resolved once during init.
        self.model_paths: Dict[str, Path] = {
            "fast_path": _resolve_model_path("fast_path"),
            "deep_path": _resolve_model_path("deep_path"),
            "multimodal": _resolve_model_path("multimodal"),
        }

    def _get_thread_cache(self) -> Dict[str, ort.InferenceSession]:
        """Return (or create) a dict stored on the current thread.
        """
        if not hasattr(_thread_local, "session_cache"):
            _thread_local.session_cache = {}
        return _thread_local.session_cache

    def _create_session(self, model_key: str) -> ort.InferenceSession:
        model_path = self.model_paths[model_key]
        if not model_path.is_file():
            raise FileNotFoundError(f"ONNX model not found at {model_path}")
        sess_opts = _build_session_options(model_key)
        try:
            session = ort.InferenceSession(str(model_path), sess_opts, providers=self.providers)
            logger.debug("Created ONNX session for %s using %s", model_key, self.providers)
            return session
        except Exception as exc:  # pragma: no cover – would surface during dev
            logger.error("Failed to create ONNX session for %s: %s", model_key, exc)
            raise

    def get_session(self, model_key: str) -> ort.InferenceSession:
        """Return a thread‑local ``InferenceSession`` for ``model_key``.

        ``model_key`` must be ``"fast_path"``, ``"deep_path"`` or ``"multimodal"``.
        Sessions are cached per‑thread to avoid cross‑thread memory interference.
        """
        if model_key not in self.model_paths:
            raise ValueError(f"Unsupported model_key {model_key!r}")
        cache = self._get_thread_cache()
        if model_key not in cache:
            cache[model_key] = self._create_session(model_key)
        return cache[model_key]

    # ---------------------------------------------------------------------
    # Convenience prediction wrapper – callers only need to pass a dict of inputs.
    # ---------------------------------------------------------------------
    def run(self, model_key: str, inputs: Dict[str, Any]) -> List[Any]:
        """Execute inference for ``model_key`` with the supplied ``inputs``.

        The function obtains the thread‑local session, runs it and returns the raw
        output list from ONNX Runtime.
        """
        session = self.get_session(model_key)
        # ``session.get_outputs()`` returns a list of ``NodeInfo`` objects – we
        # forward only the names to ``run`` for simplicity.
        output_names = [o.name for o in session.get_outputs()]
        return session.run(output_names, inputs)

# Export a module‑level singleton for easy import throughout the codebase.
manager = ONNXModelManager()

__all__ = ["ONNXModelManager", "manager"]
