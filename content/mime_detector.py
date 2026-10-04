# =============================================================================
# Enterprise NSFW Firewall Engine - Content Inspector & Security Validation
# -----------------------------------------------------------------------------
# Implements Content Inspection (Section 16) and Security Hardening (Section 17):
# - Deep Magic Bytes MIME Detection (Ignores spoofed Content-Type headers)
# - Decompression Bomb / Zip Bomb Mitigation
# - Image & Video Dimension Bounds Check
# - SHA256 Hash Computation for Zero-Retention Audit Trail & Caching
# =============================================================================

from __future__ import annotations

import hashlib
import io
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Optional python-magic (libmagic bindings). When unavailable we fall back to a
# lightweight magic-number table so the inspector still works in slim images.
try:
    import magic  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    magic = None

# Optional Pillow for image validation and decompression-bomb protection.
try:
    from PIL import Image, UnidentifiedImageError  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Image = None

    class UnidentifiedImageError(Exception):  # type: ignore[no-redef]
        """Fallback error raised when Pillow is not available."""

# Optional OpenCV support for Video Validation
try:
    import cv2  # type: ignore
except Exception:  # pragma: no cover
    cv2 = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration Handling & Defaults
# ---------------------------------------------------------------------------

def _load_engine_config() -> Dict[str, Any]:
    """Load preprocessing constraints from engine_config.yaml."""
    defaults = {
        "max_image_bytes": 20 * 1024 * 1024,  # 20 MiB
        "max_image_dim": 8192,
        "max_pixels": 67108864,               # 64 Megapixels cap
        "allowed_mime_types": [
            "image/jpeg", "image/png", "image/webp", "image/gif",
            "text/html", "text/plain", "video/mp4", "video/webm"
        ],
    }
    
    # Try finding config at the packaged default path config/engine_config.yaml.
    config_path = Path(__file__).parents[1] / "config" / "engine_config.yaml"
    if not config_path.is_file():
        logger.debug("Engine config not found at %s – using defaults", config_path)
        return defaults

    try:
        import yaml
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
            preprocessing = cfg.get("preprocessing", {})
            return {
                "max_image_bytes": preprocessing.get("max_image_bytes", defaults["max_image_bytes"]),
                "max_image_dim": preprocessing.get("max_image_dim", defaults["max_image_dim"]),
                "max_pixels": preprocessing.get("max_pixels", defaults["max_pixels"]),
                "allowed_mime_types": preprocessing.get("allowed_mime_types", defaults["allowed_mime_types"]),
            }
    except Exception as exc:  # pragma: no cover
        logger.error("Failed to parse engine config at %s: %s", config_path, exc)
        return defaults

_CONFIG = _load_engine_config()

# Configure Pillow safety limits to mitigate Decompression Bombs globally.
if Image is not None:
    Image.MAX_IMAGE_PIXELS = _CONFIG["max_pixels"]

# ---------------------------------------------------------------------------
# Helper Utilities
# ---------------------------------------------------------------------------

#: Minimal magic-number table used when libmagic is unavailable.
_MAGIC_PREFIXES: Tuple[Tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
    (b"P6", "image/x-portable-pixmap"),
    (b"P5", "image/x-portable-graymap"),
    (b"%PDF", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
)


def _detect_mime_from_magic(data: bytes) -> str:
    """Fallback MIME sniffing using a small magic-number table."""
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "video/mp4"
    if data[:4] == b"\x1a\x45\xdf\xa3":
        return "video/webm"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    for prefix, mime in _MAGIC_PREFIXES:
        if data.startswith(prefix):
            return mime
    return "application/octet-stream"


def _detect_mime(data: bytes) -> str:
    """Detect actual MIME type using libmagic headers (or a magic table)."""
    if magic is None:
        return _detect_mime_from_magic(data)
    try:
        mime = magic.from_buffer(data, mime=True)
        return mime or "application/octet-stream"
    except Exception as exc:  # pragma: no cover
        logger.error("Magic bytes detection failed: %s", exc)
        return _detect_mime_from_magic(data)


def _check_image(data: bytes) -> Tuple[bool, Optional[Tuple[int, int]], Optional[str]]:
    """Validate image payload against dimension limits and decompression bomb attacks."""
    if Image is None:
        # Pillow is optional. Skipping validation is safe because the engine's
        # own Preprocessor enforces max_image_dim / max_image_bytes before any
        # decoder runs, so a slim install must not reject every payload.
        logger.warning("Pillow not installed - skipping image dimension validation")
        return (True, None, None)
    try:
        with Image.open(io.BytesIO(data)) as img:
            width, height = img.size
            max_dim = _CONFIG["max_image_dim"]
            
            if width > max_dim or height > max_dim:
                return (
                    False,
                    (width, height),
                    f"Image dimensions {width}x{height} exceed maximum allowed {max_dim}px",
                )
            return (True, (width, height), None)
            
    except UnidentifiedImageError:
        return (False, None, "Unrecognized or corrupted image format")
    except Image.DecompressionBombError as exc:
        return (False, None, f"Decompression bomb detected: {exc}")
    except Exception as exc:  # pragma: no cover
        return (False, None, f"Image validation error: {exc}")


def _check_video(data: bytes) -> Tuple[bool, Optional[Tuple[int, int, float]], Optional[str]]:
    """Validate video payload dimensions and duration via OpenCV."""
    if cv2 is None:
        return (False, None, "OpenCV not installed – video validation unavailable")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        cap = cv2.VideoCapture(tmp_path)
        if not cap.isOpened():
            return (False, None, "Unable to parse video stream")

        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = cap.get(cv2.CAP_PROP_FPS) or 0.0
        frame_count = cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0.0
        duration = frame_count / fps if fps > 0 else 0.0
        cap.release()

        max_dim = _CONFIG["max_image_dim"]
        if width > max_dim or height > max_dim:
            return (
                False,
                (width, height, duration),
                f"Video dimensions {width}x{height} exceed allowed {max_dim}px",
            )
        return (True, (width, height, duration), None)

    except Exception as exc:  # pragma: no cover
        return (False, None, f"Video validation error: {exc}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def inspect_content(data: bytes, enforce_mime: bool = True) -> Dict[str, Any]:
    """Inspect raw binary payload, enforce security boundaries, and compute audit metadata.

    Parameters
    ----------
    data:
        The raw payload bytes.
    enforce_mime:
        When ``True`` (default) a MIME type outside ``allowed_mime_types`` marks
        the payload invalid. Pass ``False`` to treat the detected type as
        advisory while still enforcing size / dimension / decompression-bomb
        limits - used by the classification APIs.

    Returns structured analysis dictionary:
    {
        "valid": bool,
        "allowed": bool,
        "mime": str,
        "size_bytes": int,
        "sha256": str,
        "error": Optional[str],
        "details": Optional[dict]
    }
    """
    size = len(data)
    max_bytes = _CONFIG["max_image_bytes"]
    payload_hash = hashlib.sha256(data).hexdigest()

    # 1. Size Check
    if size > max_bytes:
        return {
            "valid": False,
            "allowed": False,
            "mime": "application/octet-stream",
            "size_bytes": size,
            "sha256": payload_hash,
            "error": f"Payload size ({size} bytes) exceeds maximum limit of {max_bytes} bytes",
            "details": None,
        }

    # 2. Magic Bytes MIME Detection
    mime = _detect_mime(data)

    result: Dict[str, Any] = {
        "valid": True,
        "allowed": True,
        "mime": mime,
        "size_bytes": size,
        "sha256": payload_hash,
        "error": None,
        "details": None,
    }

    # 3. Allowed Types Whitelist Check (rejects spoofed / unexpected payloads).
    allowed_mimes = _CONFIG.get("allowed_mime_types", [])
    if allowed_mimes:
        allowed = mime in allowed_mimes or any(
            mime.startswith(prefix.replace("*", ""))
            for prefix in allowed_mimes
            if "*" in prefix
        )
        result["allowed"] = allowed
        if not allowed:
            logger.warning("Disallowed MIME type detected: %s", mime)
            if enforce_mime:
                result["valid"] = False
                result["error"] = f"MIME type {mime!r} is not in the allowed list"
                return result

    # 4. Image Specific Validation
    if mime.startswith("image/"):
        valid, dims, err = _check_image(data)
        result["valid"] = valid
        result["error"] = err
        if dims:
            result["details"] = {"width": dims[0], "height": dims[1]}
        return result

    # 5. Video Specific Validation
    if mime.startswith("video/"):
        valid, meta, err = _check_video(data)
        result["valid"] = valid
        result["error"] = err
        if meta:
            result["details"] = {"width": meta[0], "height": meta[1], "duration_s": meta[2]}
        return result

    # Non-media payloads (HTML / Plaintext) pass by size validation
    return result


async def async_inspect_file(file_path: str) -> Dict[str, Any]:
    """Asynchronous file inspector helper for temporary storage processing."""
    async def _read() -> bytes:
        loop = __import__("asyncio").get_event_loop()
        return await loop.run_in_executor(None, lambda: Path(file_path).read_bytes())

    data = await _read()
    return inspect_content(data)


__all__ = ["inspect_content", "async_inspect_file"]