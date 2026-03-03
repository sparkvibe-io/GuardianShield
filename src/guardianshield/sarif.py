"""SARIF 2.1.0 export for GuardianShield findings.

Converts :class:`Finding` objects into the `SARIF 2.1.0
<https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>`_
format used by GitHub Code Scanning, VS Code SARIF Viewer, and other
security tooling.

Public API::

    from guardianshield.sarif import findings_to_sarif, findings_to_sarif_json

    sarif_dict = findings_to_sarif(findings)
    sarif_json = findings_to_sarif_json(findings)
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from .findings import Finding, Severity

# ---------------------------------------------------------------------------
# SARIF schema constants
# ---------------------------------------------------------------------------

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"
_TOOL_INFO_URI = "https://github.com/sparkvibe-io/GuardianShield"
_DEFAULT_TOOL_NAME = "GuardianShield"
_DEFAULT_TOOL_VERSION = "1.2.1"

# ---------------------------------------------------------------------------
# Severity → SARIF mapping
# ---------------------------------------------------------------------------

_LEVEL_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

_SCORE_MAP: dict[Severity, float] = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.1,
}


def _severity_to_sarif_level(severity: Severity) -> str:
    """Map a GuardianShield :class:`Severity` to a SARIF ``level`` string."""
    return _LEVEL_MAP.get(severity, "warning")


def _severity_to_score(severity: Severity) -> float:
    """Map a GuardianShield :class:`Severity` to a SARIF security-severity score."""
    return _SCORE_MAP.get(severity, 4.0)


# ---------------------------------------------------------------------------
# Rule ID and fingerprint
# ---------------------------------------------------------------------------


def _finding_rule_id(finding: Finding) -> str:
    """Generate a stable SARIF ``ruleId`` from a finding.

    Format: ``<finding_type>/<pattern_name>`` when pattern_name is available,
    otherwise just ``<finding_type>``.
    """
    base = finding.finding_type.value
    pattern_name = finding.metadata.get("pattern_name", "")
    if pattern_name:
        return f"{base}/{pattern_name}"
    return base


def _finding_fingerprint(finding: Finding) -> str:
    """Compute a stable SHA-256 fingerprint for a finding.

    Replicates the algorithm from :func:`dedup._fingerprint` so that
    SARIF ``partialFingerprints`` are consistent with dedup tracking.
    """
    parts = [
        finding.file_path or "",
        str(finding.line_number),
        finding.finding_type.value,
        finding.metadata.get("pattern_name", ""),
        finding.matched_text,
    ]
    key = ":".join(parts)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Rule builder
# ---------------------------------------------------------------------------


def _build_rule(finding: Finding, rule_id: str) -> dict[str, Any]:
    """Build a SARIF ``reportingDescriptor`` (rule) from a finding."""
    rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": finding.message},
        "properties": {
            "security-severity": str(_severity_to_score(finding.severity)),
        },
    }

    # Help text from remediation
    if finding.remediation is not None:
        rule["help"] = {"text": finding.remediation.description}
        if finding.remediation.before and finding.remediation.after:
            rule["help"]["markdown"] = (
                f"**Before:**\n```\n{finding.remediation.before}\n```\n\n"
                f"**After:**\n```\n{finding.remediation.after}\n```"
            )

    # CWE relationships
    if finding.cwe_ids:
        relationships = []
        for cwe_id in finding.cwe_ids:
            relationships.append({
                "target": {
                    "id": cwe_id,
                    "guid": None,
                    "toolComponent": {"name": "CWE", "index": 0},
                },
                "kinds": ["superset"],
            })
        rule["relationships"] = relationships

    return rule


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------


def _make_uri(file_path: str, base_path: str | None) -> str:
    """Convert a file path to a SARIF-compatible URI (forward slashes)."""
    rel = os.path.relpath(file_path, base_path) if base_path else file_path
    return rel.replace("\\", "/")


def _build_result(
    finding: Finding, rule_id: str, base_path: str | None
) -> dict[str, Any]:
    """Build a SARIF ``result`` object from a finding."""
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _severity_to_sarif_level(finding.severity),
        "message": {"text": finding.message},
        "partialFingerprints": {
            "primaryLocationLineHash": _finding_fingerprint(finding),
        },
    }

    # Location
    if finding.file_path is not None:
        uri = _make_uri(finding.file_path, base_path)
        region: dict[str, Any] = {}

        if finding.range is not None:
            # Range is 0-based (LSP) → SARIF is 1-based
            region["startLine"] = finding.range.start_line + 1
            region["startColumn"] = finding.range.start_col + 1
            region["endLine"] = finding.range.end_line + 1
            region["endColumn"] = finding.range.end_col + 1
        elif finding.line_number > 0:
            region["startLine"] = finding.line_number

        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
            }
        }
        if region:
            location["physicalLocation"]["region"] = region

        result["locations"] = [location]

    return result


# ---------------------------------------------------------------------------
# CWE taxonomy builder
# ---------------------------------------------------------------------------


def _build_cwe_taxonomy(cwe_ids: set[str]) -> dict[str, Any]:
    """Build a SARIF CWE taxonomy from collected CWE IDs."""
    taxa = []
    for cwe_id in sorted(cwe_ids):
        taxa.append({
            "id": cwe_id,
            "shortDescription": {"text": cwe_id},
        })

    return {
        "name": "CWE",
        "organization": "MITRE",
        "shortDescription": {"text": "Common Weakness Enumeration"},
        "taxa": taxa,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def findings_to_sarif(
    findings: list[Finding],
    tool_name: str = _DEFAULT_TOOL_NAME,
    tool_version: str = _DEFAULT_TOOL_VERSION,
    base_path: str | None = None,
) -> dict[str, Any]:
    """Convert a list of findings to a SARIF 2.1.0 log dict.

    Args:
        findings: The findings to export.
        tool_name: Name of the tool (default: ``"GuardianShield"``).
        tool_version: Version string (default: ``"1.2.1"``).
        base_path: If provided, file paths are made relative to this directory.

    Returns:
        A SARIF 2.1.0 log as a Python dict.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    all_cwe_ids: set[str] = set()

    for finding in findings:
        rule_id = _finding_rule_id(finding)

        # Collect unique rules
        if rule_id not in rules:
            rules[rule_id] = _build_rule(finding, rule_id)

        # Collect CWE IDs for taxonomy
        all_cwe_ids.update(finding.cwe_ids)

        # Build result
        results.append(_build_result(finding, rule_id, base_path))

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": _TOOL_INFO_URI,
                "rules": list(rules.values()),
            },
        },
        "results": results,
    }

    # Only include taxonomy if there are CWE references
    if all_cwe_ids:
        run["taxonomies"] = [_build_cwe_taxonomy(all_cwe_ids)]

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [run],
    }


def findings_to_sarif_json(
    findings: list[Finding],
    tool_name: str = _DEFAULT_TOOL_NAME,
    tool_version: str = _DEFAULT_TOOL_VERSION,
    base_path: str | None = None,
    indent: int | None = 2,
) -> str:
    """Convert a list of findings to a SARIF 2.1.0 JSON string.

    Args:
        findings: The findings to export.
        tool_name: Name of the tool (default: ``"GuardianShield"``).
        tool_version: Version string (default: ``"1.2.1"``).
        base_path: If provided, file paths are made relative to this directory.
        indent: JSON indentation (default: 2, use ``None`` for compact).

    Returns:
        A SARIF 2.1.0 JSON string.
    """
    sarif = findings_to_sarif(
        findings,
        tool_name=tool_name,
        tool_version=tool_version,
        base_path=base_path,
    )
    return json.dumps(sarif, indent=indent, ensure_ascii=False)
