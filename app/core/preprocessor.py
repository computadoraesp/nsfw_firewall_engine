"""Fast image normalization for the NSFW Firewall Engine.

The preprocessor turns raw encoded bytes into normalized ``float32`` NCHW
tensors ready for ONNX Runtime. It prefers high-performance decoders when they
are installed:

* ``cv2`` (OpenCV) - fastest, SIMD accelerated.
* ``PIL`` (Pillow / Pillow-SIMD) - widely available.

When neither is importable it falls back to a dependency-free decoder that
supports binary PPM (``P6``) images. This keeps the engine (and the test-suite)
fully functional in minimal environments while still exercising the exact
tensor-shaping and normalization path used in production.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Sequence, Tuple

import numpy as np

logger = logging.getLogger("nsfw_engine.core.preprocessor")


class PreprocessingError(ValueError):
    """Raised when an input cannot be decoded or is out of bounds."""


def _try_import_cv2():  # pragma: no cover - trivial import guard
    try:
        import cv2  # type: ignore

        return cv2
    except Exception:  # noqa: BLE001 - any import failure means "unavailable"
        return None


def _try_import_pil():  # pragma: no cover - trivial import guard
    try:
        from PIL import Image  # type: ignore

        return Image
    except Exception:  # noqa: BLE001
        return None


@dataclass
class Preprocessor:
    """Decodes, resizes and normalizes images into model input tensors."""

    mean: Tuple[float, float, float] = (0.485, 0.456, 0.406)
    std: Tuple[float, float, float] = (0.229, 0.224, 0.225)
    max_image_bytes: int = 20 * 1024 * 1024
    max_image_dim: int = 8192
    _backend: str = field(init=False, default="none")

    def __post_init__(self) -> None:
        self._cv2 = _try_import_cv2()
        self._pil = _try_import_pil()
        if self._cv2 is not None:
            self._backend = "opencv"
        elif self._pil is not None:
            self._backend = "pillow"
        else:
            self._backend = "ppm-fallback"
        logger.debug("preprocessor backend=%s", self._backend)

    # -- decoding ------------------------------------------------------------
    def decode(self, data: bytes) -> np.ndarray:
        """Decode encoded image bytes into an ``HWC`` ``uint8`` RGB array."""
        if not data:
            raise PreprocessingError("empty image payload")
        if len(data) > self.max_image_bytes:
            raise PreprocessingError(
                f"image exceeds max_image_bytes ({len(data)} > {self.max_image_bytes})"
            )

        if self._cv2 is not None:
            return self._decode_cv2(data)
        if self._pil is not None:
            return self._decode_pil(data)
        return self._decode_ppm(data)

    def _decode_cv2(self, data: bytes) -> np.ndarray:
        buf = np.frombuffer(data, dtype=np.uint8)
        img = self._cv2.imdecode(buf, self._cv2.IMREAD_COLOR)
        if img is None:
            raise PreprocessingError("OpenCV could not decode the image")
        img = self._cv2.cvtColor(img, self._cv2.COLOR_BGR2RGB)
        return self._check_dims(img)

    def _decode_pil(self, data: bytes) -> np.ndarray:
        import io

        try:
            with self._pil.open(io.BytesIO(data)) as image:
                image = image.convert("RGB")
                img = np.asarray(image, dtype=np.uint8)
        except Exception as exc:  # noqa: BLE001
            raise PreprocessingError(f"Pillow could not decode the image: {exc}") from exc
        return self._check_dims(img)

    def _decode_ppm(self, data: bytes) -> np.ndarray:
        """Dependency-free binary PPM (P6) decoder."""
        if not data.startswith(b"P6"):
            raise PreprocessingError(
                "no image decoder available; only binary PPM (P6) is supported "
                "in the fallback backend"
            )
        idx = 2
        tokens: list[bytes] = []
        size = len(data)
        while len(tokens) < 3:
            while idx < size and data[idx : idx + 1].isspace():
                idx += 1
            if idx < size and data[idx : idx + 1] == b"#":
                while idx < size and data[idx : idx + 1] != b"\n":
                    idx += 1
                continue
            start = idx
            while idx < size and not data[idx : idx + 1].isspace():
                idx += 1
            tokens.append(data[start:idx])
        idx += 1  # consume the single whitespace separating header and raster
        if len(tokens) != 3:
            raise PreprocessingError("malformed PPM header")
        width, height, maxval = (int(t) for t in tokens)
        if maxval != 255:
            raise PreprocessingError("only 8-bit PPM (maxval 255) is supported")
        expected = width * height * 3
        raster = data[idx : idx + expected]
        if len(raster) != expected:
            raise PreprocessingError("truncated PPM raster data")
        img = np.frombuffer(raster, dtype=np.uint8).reshape(height, width, 3)
        return self._check_dims(np.ascontiguousarray(img))

    def _check_dims(self, img: np.ndarray) -> np.ndarray:
        height, width = img.shape[:2]
        if max(height, width) > self.max_image_dim:
            raise PreprocessingError(
                f"image dimension {width}x{height} exceeds max_image_dim ({self.max_image_dim})"
            )
        return img

    # -- geometry / normalization -------------------------------------------
    def resize(self, img: np.ndarray, size: Sequence[int]) -> np.ndarray:
        """Bilinear resize of an ``HWC`` array to ``(width, height) == size``."""
        target_w, target_h = int(size[0]), int(size[1])
        src_h, src_w = img.shape[:2]
        if (src_h, src_w) == (target_h, target_w):
            return img.astype(np.uint8, copy=False)

        ys = (np.arange(target_h) + 0.5) * (src_h / target_h) - 0.5
        xs = (np.arange(target_w) + 0.5) * (src_w / target_w) - 0.5
        ys = np.clip(ys, 0, src_h - 1)
        xs = np.clip(xs, 0, src_w - 1)

        y0 = np.floor(ys).astype(np.int32)
        x0 = np.floor(xs).astype(np.int32)
        y1 = np.clip(y0 + 1, 0, src_h - 1)
        x1 = np.clip(x0 + 1, 0, src_w - 1)

        wy = (ys - y0).reshape(-1, 1, 1)
        wx = (xs - x0).reshape(1, -1, 1)
        src = img.astype(np.float32)

        top = src[y0][:, x0] * (1 - wx) + src[y0][:, x1] * wx
        bottom = src[y1][:, x0] * (1 - wx) + src[y1][:, x1] * wx
        out = top * (1 - wy) + bottom * wy
        return np.clip(out + 0.5, 0, 255).astype(np.uint8)

    def normalize(self, img: np.ndarray) -> np.ndarray:
        """Convert ``HWC`` uint8 RGB to normalized ``CHW`` float32."""
        arr = img.astype(np.float32) / 255.0
        mean = np.asarray(self.mean, dtype=np.float32).reshape(1, 1, 3)
        std = np.asarray(self.std, dtype=np.float32).reshape(1, 1, 3)
        arr = (arr - mean) / std
        return np.transpose(arr, (2, 0, 1))

    # -- high level ----------------------------------------------------------
    def to_tensor(self, data: bytes, size: Sequence[int]) -> np.ndarray:
        """Decode + resize + normalize into a batched NCHW tensor."""
        img = self.decode(data)
        img = self.resize(img, size)
        chw = self.normalize(img)
        return chw[np.newaxis, ...].astype(np.float32)

    def array_to_tensor(self, img: np.ndarray, size: Sequence[int]) -> np.ndarray:
        """Same as :meth:`to_tensor` but from an already-decoded array."""
        resized = self.resize(img, size)
        chw = self.normalize(resized)
        return chw[np.newaxis, ...].astype(np.float32)
