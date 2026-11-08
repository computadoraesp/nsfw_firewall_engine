# AiSOC Integration Plan

## Implemented

### 1. MCP Server (Model Context Protocol) ✅
- File: `mcp_server.py`
- Tools: health check, config summary, classify image, audit entries
- Usage: `python mcp_server.py`
- Integration: Connects with Claude, Cursor, Continue

## Pending (Requires Additional Work)

### 2. Detection Rules Engine
- Requires integrating AiSOC's 7015 rule library
- Estimated: 4 hours
- Priority: Medium

### 3. Telemetry/Alert Fusion
- Requires Prometheus/Grafana integration with AiSOC
- Estimated: 3 hours
- Priority: Medium

### 4. Investigation Ledger
- Requires custom ledger implementation
- Estimated: 5 hours
- Priority: Low

## MCP Server Usage

Install MCP SDK:
```bash
pip install mcp
```

Run server:
```bash
python mcp_server.py
```

Available tools:
- `get_health`: Get firewall health status
- `get_config_summary`: Get configuration (redacted)
- `classify_image`: Classify base64 image
- `get_audit_entries`: Get recent audit logs
