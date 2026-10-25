"""Middleware for tracing and logging."""

import uuid
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("nsfw_engine.api.rest.middleware")


class TraceIDMiddleware(BaseHTTPMiddleware):
    """Add trace_id to all requests for distributed tracing."""

    async def dispatch(self, request: Request, call_next):
        # Generate or extract trace_id
        trace_id = request.headers.get("X-Trace-ID", str(uuid.uuid4()))

        # Add to request state for use in endpoints
        request.state.trace_id = trace_id

        # Add to response header
        response = await call_next(request)
        response.headers["X-Trace-ID"] = trace_id

        return response
