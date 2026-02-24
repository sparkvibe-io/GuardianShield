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

__version__ = "0.2.0"

from .config import ProjectConfig, discover_config
from .core import GuardianShield
from .dedup import DedupResult, FindingDeduplicator
from .findings import Finding, FindingType, Range, Remediation, Severity
from .mcp_server import GuardianShieldMCPServer
from .osv import Dependency, OsvCache, check_dependencies
from .profiles import SafetyProfile, ScannerConfig

__all__ = [
    "__version__",
    "DedupResult",
    "Dependency",
    "Finding",
    "FindingDeduplicator",
    "FindingType",
    "GuardianShield",
    "GuardianShieldMCPServer",
    "OsvCache",
    "ProjectConfig",
    "Range",
    "Remediation",
    "SafetyProfile",
    "ScannerConfig",
    "Severity",
    "check_dependencies",
    "discover_config",
]
