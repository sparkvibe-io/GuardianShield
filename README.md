# GuardianShield

Universal AI security layer — an open-source MCP server for code scanning, PII detection, prompt injection defense, secret detection, and audit logging.

## Install

```bash
pip install guardianshield
```

## Quick Start

```bash
# Register with Claude Code
claude mcp add guardianshield -- guardianshield-mcp

# Or run directly
guardianshield-mcp
```

## Editor Integration

```bash
# Claude Code
claude mcp add guardianshield -- guardianshield-mcp

# VS Code (.vscode/mcp.json)
{"servers": {"guardianshield": {"type": "stdio", "command": "guardianshield-mcp"}}}

# Cursor (.cursor/mcp.json)
{"mcpServers": {"guardianshield": {"command": "guardianshield-mcp"}}}

# Claude Desktop (claude_desktop_config.json)
{"mcpServers": {"guardianshield": {"command": "guardianshield-mcp"}}}
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `scan_code` | Scan code for vulnerabilities (SQL injection, XSS, command injection, path traversal) |
| `scan_input` | Check user/agent input for prompt injection attempts |
| `scan_output` | Check AI output for PII leaks and content violations |
| `check_secrets` | Detect hardcoded secrets and credentials |
| `get_profile` | Get current safety profile configuration |
| `set_profile` | Switch safety profile (general, education, healthcare, finance, children) |
| `audit_log` | Query the security audit log |
| `get_findings` | Retrieve past findings with filters |
| `shield_status` | Get GuardianShield health and configuration status |

## License

Apache 2.0
