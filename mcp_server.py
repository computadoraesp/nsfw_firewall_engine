#!/usr/bin/env python3
"""
MCP Server for NSFW Firewall Engine

Implements Model Context Protocol for integration with Claude, Cursor, Continue.
Allows debugging and inspection of the firewall via MCP tools.

Usage:
    python mcp_server.py
"""

import asyncio
import json
import logging
from typing import Any
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    logger.warning("MCP SDK not available. Install with: pip install mcp")


class NsfwFirewallMCP:
    """MCP Server for NSFW Firewall Engine debugging."""

    def __init__(self):
        self.server = Server("nsfw-firewall-mcp", "0.1.0")
        self._register_tools()

    def _register_tools(self):
        """Register MCP tools for firewall debugging."""

        @self.server.tool()
        async def get_health() -> list[TextContent]:
            """Get current health status of the firewall."""
            try:
                from app.core.config import get_config
                from app.core.engine import NsfwEngine

                config = get_config()
                engine = NsfwEngine(config)
                health = engine.health(redact=True)

                return [TextContent(
                    type="text",
                    text=json.dumps(health, indent=2)
                )]
            except Exception as e:
                logger.error(f"Health check failed: {e}")
                return [TextContent(
                    type="text",
                    text=f"Error: {str(e)}"
                )]

        @self.server.tool()
        async def get_config_summary() -> list[TextContent]:
            """Get configuration summary (sensitive data redacted)."""
            try:
                from app.core.config import get_config

                config = get_config()
                summary = {
                    "engine_mode": config.engine.mode,
                    "firewall_mode": config.firewall.mode,
                    "security_enabled": config.security.enabled,
                    "rate_limit_enabled": config.resilience.rate_limit_enabled,
                    "cache_enabled": config.cache.enabled,
                }

                return [TextContent(
                    type="text",
                    text=json.dumps(summary, indent=2)
                )]
            except Exception as e:
                logger.error(f"Config summary failed: {e}")
                return [TextContent(
                    type="text",
                    text=f"Error: {str(e)}"
                )]

        @self.server.tool()
        async def classify_image(image_base64: str) -> list[TextContent]:
            """Classify a base64-encoded image.

            Args:
                image_base64: Base64-encoded image data
            """
            try:
                import base64
                from app.core.config import get_config
                from app.core.engine import NsfwEngine

                config = get_config()
                engine = NsfwEngine(config)

                image_data = base64.b64decode(image_base64)
                result = engine.classify({
                    "content_base64": image_base64,
                    "content_type": "image/jpeg"
                })

                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2)
                )]
            except Exception as e:
                logger.error(f"Classification failed: {e}")
                return [TextContent(
                    type="text",
                    text=f"Error: {str(e)}"
                )]

        @self.server.tool()
        async def get_audit_entries(limit: int = 10) -> list[TextContent]:
            """Get recent audit entries.

            Args:
                limit: Number of entries to return (default: 10)
            """
            try:
                from app.core.config import get_config

                config = get_config()
                audit_file = Path(config.observability.audit_file)

                if not audit_file.exists():
                    return [TextContent(
                        type="text",
                        text="No audit file found"
                    )]

                entries = []
                with audit_file.open("r") as f:
                    for i, line in enumerate(f):
                        if i >= limit:
                            break
                        entries.append(json.loads(line))

                return [TextContent(
                    type="text",
                    text=json.dumps(entries, indent=2)
                )]
            except Exception as e:
                logger.error(f"Audit retrieval failed: {e}")
                return [TextContent(
                    type="text",
                    text=f"Error: {str(e)}"
                )]


async def main():
    """Run the MCP server."""
    if not MCP_AVAILABLE:
        logger.error("MCP SDK not available. Install with: pip install mcp")
        return

    mcp = NsfwFirewallMCP()

    async with stdio_server() as (read_stream, write_stream):
        await mcp.server.run(
            read_stream,
            write_stream,
            mcp.server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
