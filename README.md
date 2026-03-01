# GuardianShield

<!-- mcp-name: io.github.sparkvibe-io/GuardianShield -->

[![PyPI version](https://img.shields.io/pypi/v/guardianshield?v=1)](https://pypi.org/project/guardianshield/)
[![Python](https://img.shields.io/pypi/pyversions/guardianshield?v=1)](https://pypi.org/project/guardianshield/)
[![License](https://img.shields.io/github/license/sparkvibe-io/GuardianShield)](https://github.com/sparkvibe-io/GuardianShield/blob/main/LICENSE)
[![Tests](https://img.shields.io/badge/tests-1396%20passing-brightgreen)]()

Universal AI security layer — an open-source MCP server for code scanning, PII detection, prompt injection defense, secret detection, dependency auditing, and audit logging.

**Zero dependencies** · **21 MCP tools** · **5 safety profiles** · **108+ detection patterns**

## Features

- **Code Vulnerability Scanning** — SQL injection, XSS, command injection, path traversal with CWE IDs and auto-fix remediation
- **Dependency Security** — Version-aware CVE matching against OSV.dev for PyPI, npm, Go, and Packagist ecosystems
- **Manifest Parsing** — Auto-detects 11 formats (requirements.txt, package.json, yarn.lock, go.mod, composer.json, and more)
- **Prompt Injection Defense** — 9+ detection patterns for instruction override, role hijacking, ChatML injection
- **PII Detection** — Email, SSN, credit card, phone, IP — with automatic redaction in findings
- **Secret Detection** — AWS keys, GitHub tokens, Stripe keys, JWTs, passwords, connection strings
- **Safety Profiles** — 5 built-in profiles (general, education, healthcare, finance, children)
- **Audit Logging** — SQLite-backed scan history with finding retrieval and filtering

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

### Scanning

| Tool | Description |
|------|-------------|
| `scan_code` | Scan source code for vulnerabilities and hardcoded secrets |
| `scan_file` | Scan a single file (auto-detects language from extension) |
| `scan_directory` | Recursively scan a directory with filtering and progress streaming |
| `scan_input` | Check user/agent input for prompt injection attempts |
| `scan_output` | Check AI output for PII leaks and content violations |
| `check_secrets` | Detect hardcoded secrets and credentials |

### Dependency Security

| Tool | Description |
|------|-------------|
| `check_dependencies` | Check packages for known CVEs via OSV.dev (PyPI, npm, Go, Packagist) |
| `sync_vulnerabilities` | Sync the local OSV vulnerability database |
| `parse_manifest` | Parse any supported manifest file (11 formats) into dependency objects |
| `scan_dependencies` | Scan a directory for manifest files and check all deps for vulnerabilities |

### False Positive Management

| Tool | Description |
|------|-------------|
| `mark_false_positive` | Mark a finding as false positive (flags future matches) |
| `list_false_positives` | List active false positive records with optional filter |
| `unmark_false_positive` | Remove a false positive record by fingerprint |

### Engine Management

| Tool | Description |
|------|-------------|
| `list_engines` | List available analysis engines with capabilities |
| `set_engine` | Set active analysis engines for code scanning |

### Configuration & Utilities

| Tool | Description |
|------|-------------|
| `get_profile` | Get current safety profile configuration |
| `set_profile` | Switch safety profile (general, education, healthcare, finance, children) |
| `test_pattern` | Test a regex pattern against sample code for custom pattern development |
| `audit_log` | Query the security audit log |
| `get_findings` | Retrieve past findings with filters |
| `shield_status` | Get health, configuration, and OSV cache statistics |

## Configuration

Set environment variables to customize behavior:

| Variable | Description | Default |
|----------|-------------|---------|
| `GUARDIANSHIELD_PROFILE` | Default safety profile | `general` |
| `GUARDIANSHIELD_AUDIT_PATH` | Path to SQLite audit database | `~/.guardianshield/audit.db` |
| `GUARDIANSHIELD_DEBUG` | Enable debug logging (`1`) | disabled |

## Documentation

Full documentation: [sparkvibe-io.github.io/GuardianShield](https://sparkvibe-io.github.io/GuardianShield/)

## License

Apache 2.0
