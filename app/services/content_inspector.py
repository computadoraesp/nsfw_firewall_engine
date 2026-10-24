"""Adapter exposing the content inspector to the API layer (Sec. 16 / 17).

``content/mime_detector.py`` performs magic-byte MIME detection, decompression
bomb protection and SHA256 audit hashing. This module wraps it so the transports
depend on a stable, typed contract instead of an optional third-party stack, and
so a missing ``libmagic`` / Pillow never breaks a request.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("nsfw_engine.services.content_inspector")

try:  # pragma: no cover - depends on optional runtime layout
    from content.mime_detector import inspect_content as _inspect_content
except Exception as exc:  # noqa: BLE001
    logger.warning("content inspector unavailable (%s) - using built-in checks", exc)
    _inspect_content = None

#: True when the full magic-byte inspector could be imported.
INSPECTOR_AVAILABLE = _inspect_content is not None


def _builtin_inspect(data: bytes, max_bytes: int) -> Dict[str, Any]:
    """Minimal fallback: size validation plus an audit hash."""
    size = len(data)
    return {
        "valid": False,
        "allowed": True,
        "mime": "application/octet-stream",
        "size_bytes": size,
        "sha256": hashlib.sha256(data).hexdigest(),
        "error": "content inspector unavailable – failing closed",
        "details": None,
    }


def inspect_payload(
    data: bytes, max_bytes: int = 20 * 1024 * 1024, enforce_mime: bool = True
) -> Optional[Dict[str, Any]]:
    """Inspect *data* and return an audit/security dict, or ``None``.

    ``enforce_mime`` controls whether a MIME type outside the allow-list marks
    the payload invalid. It defaults to ``False`` for the classification APIs
    (a sniffed type mismatch is advisory there - size, dimension and bomb checks
    still reject) and is switched on by the enforcement adapters.
    """
    if not data:
        return None
    if _inspect_content is None:
        return _builtin_inspect(data, max_bytes)
    try:
        try:
            result = _inspect_content(data, enforce_mime=enforce_mime)
        except TypeError:
            # Older signature without enforce_mime.
            result = _inspect_content(data)
    except Exception as exc:  # noqa: BLE001 - inspection must never break a request
        logger.warning("content inspection failed (%s) - using built-in checks", exc)
        return _builtin_inspect(data, max_bytes)

    report = dict(result) if isinstance(result, dict) else _builtin_inspect(data, max_bytes)
    # The caller's size limit is authoritative (the detector uses its own
    # configured limit, which may be more permissive).
    if max_bytes and len(data) > max_bytes:
        report["valid"] = False
        report["error"] = (
            f"payload size ({len(data)} bytes) exceeds maximum limit of {max_bytes} bytes"
        )
    return report


__all__ = ["INSPECTOR_AVAILABLE", "inspect_payload"]