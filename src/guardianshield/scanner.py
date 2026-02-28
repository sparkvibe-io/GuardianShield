"""Code vulnerability scanner.

Scans source code for common security vulnerabilities using regex-based
pattern matching. Detects SQL injection, XSS, command injection, path
traversal, and use of insecure functions.
"""

from __future__ import annotations

import os
import re

from guardianshield.findings import Finding, FindingType, Range, Remediation, Severity
from guardianshield.patterns import (
    COMMON_PATTERNS,
    EXTENSION_MAP,
    LANGUAGE_PATTERNS,
    REMEDIATION_MAP,
)
from guardianshield.patterns.python import PYTHON_PATTERNS

# ---------------------------------------------------------------------------
# Backward-compatible module-level pattern list.
# Code that imports ``VULNERABILITY_PATTERNS`` directly will still get the
# combined common + Python patterns (the original default).
# ---------------------------------------------------------------------------
VULNERABILITY_PATTERNS: list[
    tuple[str, re.Pattern[str], FindingType, Severity, str, float, list[str]]
] = COMMON_PATTERNS + PYTHON_PATTERNS

# Lines that are comments and should be skipped.
_COMMENT_RE = re.compile(r"""^\s*(?:#|//|/\*|\*)""")

# Severity ordering for sensitivity filtering.
_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def _min_severity_for_sensitivity(sensitivity: str) -> int:
    """Return the minimum severity order value for a given sensitivity level."""
    s = sensitivity.lower()
    if s == "low":
        # Only CRITICAL findings
        return _SEVERITY_ORDER[Severity.CRITICAL]
    if s == "medium":
        # Skip LOW (and INFO) -- i.e., MEDIUM and above
        return _SEVERITY_ORDER[Severity.MEDIUM]
    # "high" -- return everything
    return _SEVERITY_ORDER[Severity.INFO]


def scan_code(
    code: str,
    sensitivity: str = "medium",
    file_path: str | None = None,
    language: str | None = None,
) -> list[Finding]:
    """Scan source code for common security vulnerabilities.

    Args:
        code: The source code text to scan.
        sensitivity: Filtering level -- ``"low"`` returns only CRITICAL
            findings, ``"medium"`` (default) skips LOW/INFO, ``"high"``
            returns all findings.
        file_path: Optional path of the source file being scanned.
        language: Optional language hint (e.g. ``"python"``, ``"javascript"``).
            When omitted, the language is inferred from *file_path*'s
            extension.  If neither is provided, defaults to Python patterns
            for backward compatibility.

    Returns:
        A list of :class:`Finding` instances for detected vulnerabilities.
    """
    min_sev = _min_severity_for_sensitivity(sensitivity)
    findings: list[Finding] = []
    lines = code.splitlines()

    # Resolve language
    resolved_lang = None
    if language:
        resolved_lang = language.lower()
    elif file_path:
        ext = os.path.splitext(file_path)[1].lower()
        resolved_lang = EXTENSION_MAP.get(ext)

    # Build pattern list
    if resolved_lang and resolved_lang in LANGUAGE_PATTERNS:
        patterns = COMMON_PATTERNS + LANGUAGE_PATTERNS[resolved_lang]
    else:
        # Default: common + python (backward compatibility)
        patterns = COMMON_PATTERNS + PYTHON_PATTERNS

    for line_number, line in enumerate(lines, start=1):
        # Skip comment lines
        if _COMMENT_RE.match(line):
            continue

        for name, pattern, finding_type, severity, description, confidence, cwe_ids in patterns:
            if _SEVERITY_ORDER[severity] < min_sev:
                continue

            match = pattern.search(line)
            if match:
                range_obj = Range(
                    start_line=line_number - 1,
                    start_col=match.start(),
                    end_line=line_number - 1,
                    end_col=match.end(),
                )
                # Attach remediation if available for this pattern.
                remediation = None
                rem_data = REMEDIATION_MAP.get(name)
                if rem_data:
                    remediation = Remediation(
                        description=rem_data["description"],
                        before=rem_data.get("before", ""),
                        after=rem_data.get("after", ""),
                        auto_fixable=rem_data.get("auto_fixable", False),
                    )
                findings.append(
                    Finding(
                        finding_type=finding_type,
                        severity=severity,
                        message=description,
                        matched_text=match.group(0),
                        line_number=line_number,
                        file_path=file_path,
                        scanner="code_scanner",
                        metadata={"pattern_name": name},
                        range=range_obj,
                        confidence=confidence,
                        cwe_ids=list(cwe_ids),
                        remediation=remediation,
                    )
                )

    return findings
