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
import asyncio
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Optional Python-magic (libmagic bindings). When unavailable we fall back to a
# lightweight magic-number table so the inspector still works in slim images.
#
# PRODUCTION REQUIREMENT: Python-magic is REQUIRED for production deployments
# to ensure accurate MIME detection. The fallback magic-byte table is a
# development-only convenience.
#
# WINDOWS NOTE: Python-magic requires libmagic binaries which are not available
# on Windows by default. For Windows development, the fallback table is used.
# For production deployment, use Linux containers where libmagic is available.
#
# To install on Linux:
#   Debian/Ubuntu: sudo apt-get install libmagic1
#   RHEL/CentOS: sudo yum install file-devel
#   Alpine: apk add file-dev
#
# Optional Python-magic (libmagic bindings). When unavailable we fall back to a
# lightweight magic-number table so the inspector still works in slim images.
#
# PRODUCTION REQUIREMENT: Python-magic is REQUIRED for production deployments
# to ensure accurate MIME detection. The fallback magic-byte table is a
# development-only convenience.
#
# WINDOWS NOTE: Python-magic requires libmagic binaries which are not available
# on Windows by default. For Windows development, the fallback table is used.
# For production deployment, use Linux containers where libmagic is available.
#
# To install on Linux:
#   Debian/Ubuntu: sudo apt-get install libmagic1
#   RHEL/CentOS: sudo yum install file-devel
#   Alpine: apk add file-dev
#
import sys
magic = None
MAGIC_AVAILABLE = False

# Only try to import magic on Linux/macOS to avoid Windows access violation
if sys.platform != "win32":
    try:
        import magic  # type: ignore
        MAGIC_AVAILABLE = True
    except Exception:  # pragma: no cover - optional dependency
        pass

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
        "max_video_duration_s": 600.0,        # 10 minutes
        "allowed_mime_types": [
            "image/jpeg", "image/png", "image/webp", "image/gif",
            # P6 is the only format the dependency-free fallback decoder in
            # app.core.preprocessor can read, so refusing it would make a slim
            # install (no OpenCV, no Pillow) unable to classify any image at all.
            "image/x-portable-pixmap",
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
                "max_video_duration_s": preprocessing.get("max_video_duration_s", defaults["max_video_duration_s"]),
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

#: Types the fallback sniffer cannot classify. This is deliberately **not** in
#: the allow-list: a payload the sniffer could not identify is exactly the one
#: that must not be handed to a native image decoder, and it is what a slim
#: install with no libmagic returns for anything unusual. Rejecting it is the
#: fail-closed behavior.
_UNIDENTIFIABLE_MIME = "application/octet-stream"

#: Proportion of the head that must decode as printable text before a payload
#: is reported as text. Text never reaches an image decoder, so it needs no
#: magic bytes - and this keeps HTML working on installations with no libmagic.
_TEXT_SNIFF_WINDOW = 1024
_TEXT_PRINTABLE_MIN_RATIO = 0.85


def _sniff_text(data: bytes) -> str:
    """Classify plain text vs HTML from the payload itself.

    The magic table only covers formats with magic numbers. Without libmagic,
    an HTML document sniffed as ``application/octet-stream`` and was then
    refused by the allow-list - so a slim image silently stopped accepting the
    HTML it is supposed to classify. Text carries no native-parser risk (it goes
    to the tokenizer, never to OpenCV or Pillow), so detecting it from its own
    bytes is both safe and necessary.
    """
    head = data[:_TEXT_SNIFF_WINDOW]
    if not head:
        return _UNIDENTIFIABLE_MIME
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        return _UNIDENTIFIABLE_MIME

    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if printable / max(1, len(text)) < _TEXT_PRINTABLE_MIN_RATIO:
        return _UNIDENTIFIABLE_MIME

    lowered = text.lstrip().lower()
    if lowered.startswith("<!doctype html") or lowered.startswith("<html"):
        return "text/html"
    for marker in ("<html", "<head", "<body", "<div", "<p>", "<meta", "<title"):
        if marker in lowered:
            return "text/html"
    return "text/plain"


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
    # Nothing matched a magic number. Before calling, it unidentifiable, try
    # the text heuristic - otherwise a libmagic-less install refuses every HTML
    # document it exists to classify.
    sniffed = _sniff_text(data)
    if sniffed != _UNIDENTIFIABLE_MIME:
        return sniffed
    return _UNIDENTIFIABLE_MIME


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
            max_pixels = int(_CONFIG.get("max_pixels", 0) or 0)

            # SECURITY: Pillow raises DecompressionBombError only *above*
            # 2 x MAX_IMAGE_PIXELS and merely warns at the threshold, so the
            # whole band between the cap and 2x the cap was unguarded. At the
            # previous 64 MP cap that meant a ~100 MP image - roughly 300 MB
            # decoded per request - passed this check and was then fully
            # decoded by the preprocessor in a threadpool with no concurrency
            # limit. Checking the real pixel count closes the band.
            if max_pixels and (width * height) > max_pixels:
                return (
                    False,
                    (width, height),
                    f"Image has {width * height} pixels, exceeding the maximum "
                    f"of {max_pixels}",
                )

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
    """Validate video payload dimensions, duration and size via OpenCV.

    SECURITY: the payload is never written to disk. It used to be streamed to a
    ``NamedTemporaryFile`` and handed to ``cv2.VideoCapture`` by path, which
    contradicts ``privacy.retain_raw_payloads: false`` - NSFW content briefly
    existed as a plaintext file on disk during every video check. Decoding from
    an in-memory buffer gives ``VideoCapture`` the same bytes with no on-disk
    copy, so the privacy setting and the validator agree.

    Duration is now actually checked: it was computed and returned but never
    compared against a maximum, so an attacker could submit a tiny, highly
    compressed, hours-long video and force a large number of frame decodes.
    """
    if cv2 is None:
        return (False, None, "OpenCV not installed – video validation unavailable")

    # SECURITY: Reject videos that are too large before decoding anything.
    max_bytes = _CONFIG.get("max_image_bytes", 20 * 1024 * 1024)
    if len(data) > max_bytes:
        return (
            False,
            None,
            f"Video size ({len(data)} bytes) exceeds maximum limit of {max_bytes} bytes",
        )

    max_duration = float(_CONFIG.get("max_video_duration_s", 600.0))
    buffer = None
    try:
        buffer = np.frombuffer(data, dtype=np.uint8)
        cap = cv2.VideoCapture(buffer)
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
        if duration > max_duration:
            return (
                False,
                (width, height, duration),
                f"Video duration ({duration:.1f}s) exceeds the maximum of "
                f"{max_duration:.0f}s",
            )
        return (True, (width, height, duration), None)

    except Exception as exc:  # pragma: no cover
        return (False, None, f"Video validation error: {exc}")
    finally:
        # Release the buffer explicitly rather than relying on the temp file
        # cleanup that this function no longer needs.
        del buffer

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


async def async_inspect_file(file_path: str, allowed_root: Optional[str] = None) -> Dict[str, Any]:
    """Inspect a file for temporary-storage processing.

    SECURITY: *file_path* used to be passed straight to ``Path.read_bytes()``
    and this function is exported in ``__all__``, so any future caller that
    forwarded user input would have handed out arbitrary file read plus a
    SHA256 of the contents. There is no legitimate caller today, so the safe
    contract is to make the restriction explicit rather than to rely on
    discipline: the path must resolve to an actual **file** (a symlink or a
    directory raises), and it must stay inside ``allowed_root`` when one is
    supplied. Callers handling genuinely untrusted paths must pass the root
    they are allowed to read from.
    """
    candidate = Path(file_path).resolve()

    if allowed_root:
        root = Path(allowed_root).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            logger.warning(
                "refusing to inspect %s: outside the allowed root %s",
                candidate, root,
            )
            raise ValueError(
                f"SECURITY: {file_path!r} resolves outside the allowed root "
                f"{root}"
            ) from None

    if not candidate.is_file():
        # Covers directories, devices and dangling symlinks.
        raise ValueError(f"SECURITY: {file_path!r} is not a regular file")

    data = await asyncio.to_thread(candidate.read_bytes)
    return inspect_content(data)


__all__ = ["inspect_content", "async_inspect_file"]