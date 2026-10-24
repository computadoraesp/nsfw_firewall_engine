"""ONNX Runtime session management for the NSFW Firewall Engine.

This module centralises everything related to loading and executing ONNX
models. It negotiates the best available execution provider (TensorRT, CUDA,
OpenVINO or CPU) and applies the tuning options from the engine configuration.

If ``onnxruntime`` is not installed (e.g. in a lightweight test environment) or
a model file is missing, the manager degrades gracefully: :meth:`load` returns
a stub session and the model evaluators transparently switch to their
deterministic heuristic fallback. This keeps the cascade logic testable
end-to-end without GPUs or model artifacts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

import numpy as np

from app.core.config import OnnxConfig

logger = logging.getLogger("nsfw_engine.core.onnx_runtime")


def onnxruntime_available() -> bool:
    """Return True when the ``onnxruntime`` package can be imported."""
    try:
        import onnxruntime  # type: ignore  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


class OnnxRuntimeError(RuntimeError):
    """Raised when a session cannot be created or executed."""


@dataclass
class LoadedSession:
    """Wrapper around an ``onnxruntime.InferenceSession`` (or its absence)."""

    name: str
    session: Any = None
    path: Optional[Path] = None
    providers: List[str] = field(default_factory=list)
    is_stub: bool = False
    input_name: Optional[str] = None

    def run(self, tensor: np.ndarray) -> np.ndarray:
        if self.session is None:
            raise OnnxRuntimeError(f"session {self.name!r} is a stub (no runtime)")
        inputs = {self.input_name or self.session.get_inputs()[0].name: tensor}
        outputs = self.session.run(None, inputs)
        return np.asarray(outputs[0])


class OnnxSessionManager:
    """Creates and caches ONNX Runtime inference sessions."""

    def __init__(self, config: OnnxConfig) -> None:
        self.config = config
        self._ort = None
        self._available_providers: List[str] = []
        self._sessions: dict[str, LoadedSession] = {}
        self._init_runtime()

    # -- runtime discovery ---------------------------------------------------
    def _init_runtime(self) -> None:
        if not onnxruntime_available():
            logger.warning(
                "onnxruntime not installed - evaluators will use heuristic fallback"
            )
            return
        import onnxruntime as ort  # type: ignore

        self._ort = ort
        self._available_providers = list(ort.get_available_providers())
        logger.info("onnxruntime available providers: %s", self._available_providers)

    @property
    def runtime_available(self) -> bool:
        return self._ort is not None

    @property
    def available_providers(self) -> List[str]:
        return list(self._available_providers)

    def active_providers(self) -> List[str]:
        """Providers actually used by the most recently loaded real session."""
        for session in self._sessions.values():
            if not session.is_stub and session.providers:
                return list(session.providers)
        return list(self._available_providers)

    # -- provider negotiation ------------------------------------------------
    def resolve_providers(self) -> List[str]:
        """Intersect the requested providers with what the runtime supports."""
        if not self._available_providers:
            return []
        requested = self.config.provider_names
        resolved = [p for p in requested if p in self._available_providers]
        if not resolved:
            if "CPUExecutionProvider" in self._available_providers:
                resolved = ["CPUExecutionProvider"]
            else:
                resolved = [self._available_providers[0]]
        return resolved

    def _provider_options(self, providers: List[str]) -> List[dict]:
        """Build the per-provider option list aligned with *providers*."""
        configured = self.config.provider_options
        return [dict(configured.get(name, {})) for name in providers]

    def _session_options(self) -> Any:
        ort = self._ort
        options = ort.SessionOptions()
        options.intra_op_num_threads = self.config.intra_op_num_threads
        options.inter_op_num_threads = self.config.inter_op_num_threads
        level = getattr(
            ort.GraphOptimizationLevel, self.config.graph_optimization_level, None
        )
        if level is not None:
            options.graph_optimization_level = level
        return options

    # -- loading -------------------------------------------------------------
    def load(self, name: str, model_path: str | Path) -> LoadedSession:
        """Load (or fetch from cache) a model as a :class:`LoadedSession`."""
        key = str(model_path)
        if key in self._sessions:
            return self._sessions[key]

        path = Path(model_path)
        if self._ort is None or not path.exists():
            reason = (
                "runtime missing" if self._ort is None else f"model file missing: {path}"
            )
            logger.warning("load '%s' as stub (%s)", name, reason)
            session = LoadedSession(name=name, session=None, path=path, is_stub=True)
            self._sessions[key] = session
            return session

        providers = self.resolve_providers()
        provider_options = self._provider_options(providers)
        try:
            ort_session = self._ort.InferenceSession(
                str(path),
                sess_options=self._session_options(),
                providers=providers,
                provider_options=provider_options,
            )
            input_name = ort_session.get_inputs()[0].name
            session = LoadedSession(
                name=name,
                session=ort_session,
                path=path,
                providers=list(ort_session.get_providers()),
                is_stub=False,
                input_name=input_name,
            )
            logger.info("loaded model '%s' with providers %s", name, session.providers)
        except Exception as exc:  # noqa: BLE001
            logger.error("failed to load model '%s' (%s): %s", name, path, exc)
            session = LoadedSession(name=name, session=None, path=path, is_stub=True)
        self._sessions[key] = session
        return session

    def unload_all(self) -> None:
        self._sessions.clear()


def softmax(x: np.ndarray) -> np.ndarray:
    """Numerically stable softmax over the last axis.

    Subtracts the max before exponentiating, which is what keeps this finite
    when a classifier emits large-magnitude logits. Required for multi-class
    heads: their channels are mutually exclusive and must sum to 1, whereas a
    per-class sigmoid does not and would report ~0.5 for every channel of a
    near-uniform prediction.
    """
    array = np.asarray(x, dtype=np.float32)
    shifted = array - np.max(array, axis=-1, keepdims=True)
    exp = np.exp(shifted)
    return exp / np.clip(np.sum(exp, axis=-1, keepdims=True), 1e-12, None)


def sigmoid(x: np.ndarray) -> np.ndarray:
    """Numerically stable logistic squashing."""
    return 1.0 / (1.0 + np.exp(-np.clip(x, -60.0, 60.0)))


def to_probability(outputs: np.ndarray) -> float:
    """Collapse arbitrary model output into an NSFW probability in [0, 1].

    Handles the common cases: a single logit, a two-class softmax, or a
    pre-activated probability.
    """
    flat = np.asarray(outputs, dtype=np.float32).reshape(-1)
    if flat.size == 0:
        return 0.0
    if flat.size == 1:
        return float(sigmoid(flat[0]))
    probs = sigmoid(flat)
    if flat.size == 2:
        return float(probs[1])
    return float(np.clip(np.mean(probs[1:]), 0.0, 1.0))

