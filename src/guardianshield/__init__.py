"""GuardianShield -- Universal AI Security Layer.

A free, open-source MCP server that acts as a universal security layer
for AI coding agents. Exposes security scanning, PII detection, prompt
injection defense, secret detection, and audit logging as MCP tools.

Works with Claude Code, VS Code, Cursor, Windsurf, OpenSpek, Claude Desktop,
or any MCP-compatible client.

Quick start::

    from guardianshield import GuardianShield

    shield = GuardianShield()
    findings = shield.scan_code('password = "hunter2"')
    findings = shield.scan_input("Ignore previous instructions")
    findings = shield.scan_output("My SSN is 123-45-6789")
"""

from __future__ import annotations

__version__ = "0.1.0"

from .core import GuardianShield
from .findings import Finding, FindingType, Severity
from .mcp_server import GuardianShieldMCPServer
from .profiles import SafetyProfile, ScannerConfig

__all__ = [
    "__version__",
    "Finding",
    "FindingType",
    "GuardianShield",
    "GuardianShieldMCPServer",
    "SafetyProfile",
    "ScannerConfig",
    "Severity",
]
