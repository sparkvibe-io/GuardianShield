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

__version__ = "1.1.0b1"

from .config import ProjectConfig, discover_config
from .core import GuardianShield
from .dedup import DedupResult, FindingDeduplicator
from .engines import AnalysisEngine, EngineRegistry, RegexEngine
from .enrichment import enrich_finding
from .feedback import FalsePositiveDB
from .findings import Finding, FindingType, Range, Remediation, Severity
from .manifest import (
    parse_composer_json,
    parse_composer_lock,
    parse_go_mod,
    parse_go_sum,
    parse_manifest,
    parse_package_json,
    parse_package_lock_json,
    parse_pipfile_lock,
    parse_pnpm_lock_yaml,
    parse_pyproject_toml,
    parse_requirements_txt,
    parse_yarn_lock,
)
from .mcp_server import GuardianShieldMCPServer
from .osv import Dependency, OsvCache, check_dependencies
from .profiles import SafetyProfile, ScannerConfig

__all__ = [
    "__version__",
    "AnalysisEngine",
    "DedupResult",
    "Dependency",
    "EngineRegistry",
    "FalsePositiveDB",
    "Finding",
    "FindingDeduplicator",
    "FindingType",
    "GuardianShield",
    "GuardianShieldMCPServer",
    "OsvCache",
    "ProjectConfig",
    "Range",
    "RegexEngine",
    "Remediation",
    "SafetyProfile",
    "ScannerConfig",
    "Severity",
    "enrich_finding",
    "check_dependencies",
    "discover_config",
    "parse_composer_json",
    "parse_composer_lock",
    "parse_go_mod",
    "parse_go_sum",
    "parse_manifest",
    "parse_package_json",
    "parse_package_lock_json",
    "parse_pipfile_lock",
    "parse_pnpm_lock_yaml",
    "parse_pyproject_toml",
    "parse_requirements_txt",
    "parse_yarn_lock",
]
