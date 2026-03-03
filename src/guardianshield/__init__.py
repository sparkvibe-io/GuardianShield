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

__version__ = "1.2.1"

from .baseline import BaselineResult, filter_baseline_findings, load_baseline, save_baseline
from .ci import QualityGateConfig, QualityGateResult, check_quality_gate
from .config import ProjectConfig, discover_config
from .core import GuardianShield
from .dedup import DedupResult, FindingDeduplicator
from .deep_engine import DeepEngine
from .diff import DiffHunk, parse_unified_diff
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
from .pipeline import EngineTimingResult, merge_engine_findings
from .profiles import SafetyProfile, ScannerConfig
from .sarif import findings_to_sarif, findings_to_sarif_json
from .semantic_engine import SemanticEngine, is_test_file
from .suppression import SuppressionDirective, filter_suppressed_findings, parse_suppression_comment
from .triage import (
    available_finding_types,
    build_triage_prompt,
    get_all_triage_guides,
    get_triage_guide,
)

__all__ = [
    "__version__",
    "AnalysisEngine",
    "BaselineResult",
    "DedupResult",
    "DeepEngine",
    "Dependency",
    "DiffHunk",
    "EngineRegistry",
    "EngineTimingResult",
    "FalsePositiveDB",
    "Finding",
    "FindingDeduplicator",
    "FindingType",
    "GuardianShield",
    "GuardianShieldMCPServer",
    "OsvCache",
    "ProjectConfig",
    "QualityGateConfig",
    "QualityGateResult",
    "Range",
    "RegexEngine",
    "Remediation",
    "SafetyProfile",
    "ScannerConfig",
    "SemanticEngine",
    "Severity",
    "SuppressionDirective",
    "available_finding_types",
    "build_triage_prompt",
    "check_dependencies",
    "check_quality_gate",
    "discover_config",
    "enrich_finding",
    "filter_baseline_findings",
    "filter_suppressed_findings",
    "findings_to_sarif",
    "findings_to_sarif_json",
    "get_all_triage_guides",
    "get_triage_guide",
    "is_test_file",
    "load_baseline",
    "merge_engine_findings",
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
    "parse_suppression_comment",
    "parse_unified_diff",
    "parse_yarn_lock",
    "save_baseline",
]
