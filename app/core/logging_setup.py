"""Structured JSON logging for the NSFW Firewall Engine.

Provides :class:`JsonFormatter` (referenced from ``config/logging_config.yaml``)
plus :func:`setup_logging`, which wires up the standard ``logging`` module from
that YAML definition.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import logging.config
import os
from pathlib import Path
from typing import Any

import yaml

from app.core.config import get_logging_config_path, PROJECT_ROOT

logger = logging.getLogger("nsfw_engine.core.logging_setup")


class JsonFormatter(logging.Formatter):
    """Render each log record as a single JSON object per line."""

    default_time_format = "%Y-%m-%dT%H:%M:%S"

    def __init__(
        self,
        fields: list[str] | None = None,
        rename: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.fields = fields or [
            "timestamp",
            "level",
            "logger",
            "message",
            "module",
            "funcName",
            "lineno",
        ]
        self.rename = rename or {}

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()
        timestamp = datetime_from_record(record)
        base = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": record.message,
            "module": record.module,
            "funcName": record.funcName,
            "lineno": record.lineno,
        }
        # Apply any configured renames (e.g. asctime -> timestamp).
        for old, new in self.rename.items():
            if old in base and new not in base:
                base[new] = base.pop(old)

        payload: dict[str, Any] = {key: base.get(key) for key in self.fields}

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        # Include any structured extras attached by callers.
        for key, value in record.__dict__.items():
            if key in _RESERVED_RECORD_FIELDS or key.startswith("_"):
                continue
            if key not in payload:
                payload[key] = value

        return json.dumps(payload, ensure_ascii=False, default=str)


def datetime_from_record(record: logging.LogRecord) -> str:
    return _dt.datetime.fromtimestamp(record.created).strftime(JsonFormatter.default_time_format)


# Standard LogRecord attributes that must not be duplicated as "extras".
_RESERVED_RECORD_FIELDS = frozenset(
    logging.LogRecord(name="", level=0, pathname="", lineno=0, msg="", args=(), exc_info=None).__dict__
) | {"message", "asctime", "taskName"}


def setup_logging(config_path: str | os.PathLike[str] | None = None, level: str | None = None) -> None:
    """Configure the root logging system from ``config/logging_config.yaml``.

    *level* overrides the configured log level - typically
    ``observability.log_level`` from the engine configuration, which is applied
    after ``dictConfig`` so the YAML hierarchy is still honored.

    Falls back to a minimal console-only JSON configuration if the YAML file is
    missing, so that the engine can always log something useful.
    """
    path = Path(config_path) if config_path else get_logging_config_path()

    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        # Resolve relative log paths against the project root and make sure the
        # directory exists before dictConfig tries to open the file handler.
        for handler in data.get("handlers", {}).values():
            filename = handler.get("filename")
            if filename:
                resolved = Path(filename)
                if not resolved.is_absolute():
                    resolved = PROJECT_ROOT / resolved
                resolved.parent.mkdir(parents=True, exist_ok=True)
                handler["filename"] = str(resolved)
        logging.config.dictConfig(data)
        if level:
            _apply_level(level)
        return

    # Fallback configuration.
    logger = logging.getLogger("nsfw_engine")
    logger.setLevel(getattr(logging, str(level).upper(), logging.DEBUG) if level else logging.DEBUG)
    if not logger.handlers:
        stream = logging.StreamHandler()
        stream.setFormatter(JsonFormatter())
        logger.addHandler(stream)


def _apply_level(level: str) -> None:
    """Force a numeric level onto the ``nsfw_engine``/``app`` logger trees."""
    numeric = getattr(logging, str(level).upper(), None)
    if not isinstance(numeric, int):
        logger.warning("invalid log level %r, keeping the configured level", level)
        return
    for name in ("nsfw_engine", "app"):
        logging.getLogger(name).setLevel(numeric)
