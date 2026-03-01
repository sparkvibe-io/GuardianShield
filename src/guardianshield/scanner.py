"""Code vulnerability scanner.

Scans source code for common security vulnerabilities using regex-based
pattern matching. Detects SQL injection, XSS, command injection, path
traversal, and use of insecure functions.
"""

from __future__ import annotations

import os
import re

from guardianshield.enrichment import enrich_finding
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

# ---------------------------------------------------------------------------
# Cached combined pattern lists (language -> COMMON + language-specific).
# Built lazily on first use to avoid import-time issues.
# ---------------------------------------------------------------------------
_COMBINED_CACHE: dict[str, list] = {}


def _get_patterns(language: str | None) -> list:
    """Return the combined pattern list for a language, using a cache."""
    key = language or "_default_"
    cached = _COMBINED_CACHE.get(key)
    if cached is not None:
        return cached
    if language and language in LANGUAGE_PATTERNS:
        combined = COMMON_PATTERNS + LANGUAGE_PATTERNS[language]
    else:
        combined = COMMON_PATTERNS + PYTHON_PATTERNS
    _COMBINED_CACHE[key] = combined
    return combined


# ---------------------------------------------------------------------------
# Pre-built Remediation objects (pattern_name -> Remediation).
# Built once at module level to avoid per-match dict lookup + construction.
# ---------------------------------------------------------------------------
_REMEDIATION_CACHE: dict[str, Remediation] = {}

for _name, _data in REMEDIATION_MAP.items():
    _REMEDIATION_CACHE[_name] = Remediation(
        description=_data["description"],
        before=_data.get("before", ""),
        after=_data.get("after", ""),
        auto_fixable=_data.get("auto_fixable", False),
    )


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

    # Get cached pattern list and pre-filter by severity.
    all_patterns = _get_patterns(resolved_lang)
    patterns = [
        p for p in all_patterns
        if _SEVERITY_ORDER[p[3]] >= min_sev
    ]

    for line_number, line in enumerate(lines, start=1):
        # Skip comment lines
        if _COMMENT_RE.match(line):
            continue

        for name, pattern, finding_type, severity, description, confidence, cwe_ids in patterns:
            match = pattern.search(line)
            if match:
                range_obj = Range(
                    start_line=line_number - 1,
                    start_col=match.start(),
                    end_line=line_number - 1,
                    end_col=match.end(),
                )
                finding = Finding(
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
                    remediation=_REMEDIATION_CACHE.get(name),
                )
                finding.details["pattern_regex"] = pattern.pattern
                if resolved_lang:
                    finding.details["language"] = resolved_lang
                enrich_finding(finding, source=code)
                findings.append(finding)

    return findings
