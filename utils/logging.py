import logging
import uuid
import json
from typing import Optional

class JsonFormatter(logging.Formatter):
    """JSON log formatter that includes a ``trace_id`` field.

    The formatter emits a single‑line JSON object for each log record.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Base payload
        payload = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Include any extra attributes that are not part of the LogRecord default set
        extra = {
            k: v for k, v in record.__dict__.items()
            if k not in ("name", "msg", "args", "levelname", "levelno", "pathname", "filename", "module",
                         "exc_info", "exc_text", "stack_info", "lineno", "funcName", "created", "msecs",
                         "relativeCreated", "thread", "threadName", "processName", "process", "message")
        }
        payload.update(extra)
        return json.dumps(payload, ensure_ascii=False)

def get_logger(name: str = "nsfw_firewall", trace_id: Optional[str] = None) -> logging.Logger:
    """Return a JSON logger.

    Args:
        name: Logger name (defaults to ``nsfw_firewall``).
        trace_id: Optional identifier for the request. If omitted a new UUID4 is generated.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.propagate = False
    # Attach trace_id to the logger by using ``extra`` on each call via a wrapper.
    # Provide a convenience method ``info`` that injects the trace_id.
    def _log_with_trace(level_func, msg, *args, **kwargs):
        _trace = trace_id or str(uuid.uuid4())
        level_func(msg, *args, extra={"trace_id": _trace}, **kwargs)

    # Monkey‑patch common methods to auto‑inject trace_id.
    logger.trace_info = lambda msg, *a, **kw: _log_with_trace(logger.info, msg, *a, **kw)
    logger.trace_debug = lambda msg, *a, **kw: _log_with_trace(logger.debug, msg, *a, **kw)
    logger.trace_warning = lambda msg, *a, **kw: _log_with_trace(logger.warning, msg, *a, **kw)
    logger.trace_error = lambda msg, *a, **kw: _log_with_trace(logger.error, msg, *a, **kw)
    logger.trace_critical = lambda msg, *a, **kw: _log_with_trace(logger.critical, msg, *a, **kw)
    return logger
