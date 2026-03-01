"""Secret and credential detection scanner.

Scans text for hardcoded secrets, API keys, tokens, passwords, and other
credentials using compiled regex patterns.  Matched values are redacted
in the resulting :class:`~guardianshield.findings.Finding` objects so that
raw secrets are never stored or transmitted.
"""

from __future__ import annotations

import re

from guardianshield.enrichment import enrich_finding
from guardianshield.findings import Finding, FindingType, Range, Severity

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------
# Each entry: (name, compiled_regex, severity, description, confidence, cwe_ids)
#
# Patterns are compiled at module level so the cost is paid once on import.
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str, float, list[str]]] = [
    # 1. AWS Access Key ID  (always starts with AKIA, 20 uppercase alphanumeric)
    (
        "AWS Access Key",
        re.compile(r"(?<![A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])"),
        Severity.CRITICAL,
        "AWS access key ID detected",
        0.95,
        ["CWE-798"],
    ),
    # 2. AWS Secret Access Key (40-char base64-ish, usually follows known prefixes)
    (
        "AWS Secret Key",
        re.compile(
            r"""(?i)(?:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key|secret[_\-]?key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?"""
        ),
        Severity.CRITICAL,
        "AWS secret access key detected",
        0.9,
        ["CWE-798"],
    ),
    # 3. GitHub tokens (classic PATs, fine-grained PATs, OAuth, etc.)
    (
        "GitHub Token",
        re.compile(
            r"(?<![A-Za-z0-9_])(ghp_[A-Za-z0-9]{36,}|gho_[A-Za-z0-9]{36,}|ghs_[A-Za-z0-9]{36,}|ghr_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"
        ),
        Severity.HIGH,
        "GitHub personal access token detected",
        0.95,
        ["CWE-798"],
    ),
    # 4a. Stripe live keys (CRITICAL)
    (
        "Stripe Live Key",
        re.compile(r"(?<![A-Za-z0-9_])(sk_live_[A-Za-z0-9]{24,}|pk_live_[A-Za-z0-9]{24,})"),
        Severity.CRITICAL,
        "Stripe live API key detected",
        0.95,
        ["CWE-798"],
    ),
    # 4b. Stripe test keys (HIGH)
    (
        "Stripe Test Key",
        re.compile(r"(?<![A-Za-z0-9_])(sk_test_[A-Za-z0-9]{24,}|pk_test_[A-Za-z0-9]{24,})"),
        Severity.HIGH,
        "Stripe test API key detected",
        0.9,
        ["CWE-798"],
    ),
    # 5. Private keys (PEM-encoded)
    (
        "Private Key",
        re.compile(
            r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----"
        ),
        Severity.CRITICAL,
        "Private key detected",
        0.99,
        ["CWE-798"],
    ),
    # 6. JSON Web Tokens (three base64url sections separated by dots)
    (
        "JWT",
        re.compile(
            r"(?<![A-Za-z0-9_\-.])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,})(?![A-Za-z0-9_\-.])"
        ),
        Severity.MEDIUM,
        "JSON Web Token detected",
        0.85,
        ["CWE-798"],
    ),
    # 7. Slack tokens
    (
        "Slack Token",
        re.compile(r"(?<![A-Za-z0-9_])(xoxb-[A-Za-z0-9\-]{24,}|xoxp-[A-Za-z0-9\-]{24,}|xoxs-[A-Za-z0-9\-]{24,}|xoxa-[A-Za-z0-9\-]{24,})"),
        Severity.HIGH,
        "Slack token detected",
        0.9,
        ["CWE-798"],
    ),
    # 8. Generic password assignments  (password = "...", passwd = '...', etc.)
    #    The value must be at least 4 characters and must NOT look like a variable
    #    reference (no leading $ or all-caps ENV-style names).
    (
        "Password in Assignment",
        re.compile(
            r"""(?i)(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\s$][^"']{3,})["']"""
        ),
        Severity.MEDIUM,
        "Hardcoded password detected in assignment",
        0.6,
        ["CWE-798"],
    ),
    # 9. Database connection strings
    (
        "Connection String",
        re.compile(
            r"(?i)((?:mysql|postgres|postgresql|mongodb|mongodb\+srv|redis|amqp|amqps)://[^\s\"']{8,})"
        ),
        Severity.HIGH,
        "Database/service connection string with potential credentials detected",
        0.85,
        ["CWE-798"],
    ),
    # 10. Google API keys  (AIza followed by 35 chars)
    (
        "Google API Key",
        re.compile(r"(?<![A-Za-z0-9])(AIza[A-Za-z0-9_\-]{35})(?![A-Za-z0-9_\-])"),
        Severity.HIGH,
        "Google API key detected",
        0.9,
        ["CWE-798"],
    ),
    # 11. Generic API key / token assignments
    (
        "Generic API Key",
        re.compile(
            r"""(?i)(?:api_key|api_token|access_token|apikey|api_secret)\s*[=:]\s*["']([A-Za-z0-9_\-/+=]{8,})["']"""
        ),
        Severity.MEDIUM,
        "Generic API key or token detected in assignment",
        0.5,
        ["CWE-798"],
    ),
    # 12. Telegram Bot tokens  (<bot-id>:AA... where bot-id is numeric)
    (
        "Telegram Bot Token",
        re.compile(r"(?<![A-Za-z0-9])(\d{8,10}:AA[A-Za-z0-9_\-]{33,})(?![A-Za-z0-9_\-])"),
        Severity.HIGH,
        "Telegram bot token detected",
        0.9,
        ["CWE-798"],
    ),
]

# ---------------------------------------------------------------------------
# Severity threshold map for sensitivity levels
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_SENSITIVITY_THRESHOLD = {
    "low": _SEVERITY_ORDER[Severity.CRITICAL],     # only CRITICAL
    "medium": _SEVERITY_ORDER[Severity.MEDIUM],     # MEDIUM and above (skip LOW/INFO)
    "high": _SEVERITY_ORDER[Severity.INFO],          # everything
}

# ---------------------------------------------------------------------------
# Redaction helper
# ---------------------------------------------------------------------------

_PASSWORD_PATTERN_NAMES = {"Password in Assignment"}


def _redact(match_text: str, pattern_name: str) -> str:
    """Return a redacted version of the matched secret.

    For passwords the entire value is redacted.  For other key types the first
    four characters are preserved so the type can be identified while the rest
    is hidden.
    """
    if pattern_name in _PASSWORD_PATTERN_NAMES:
        return "***REDACTED***"
    if len(match_text) <= 4:
        return "***REDACTED***"
    return match_text[:4] + "***REDACTED***"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_secrets(
    text: str,
    sensitivity: str = "medium",
    file_path: str | None = None,
) -> list[Finding]:
    """Scan *text* for hardcoded secrets and credentials.

    Parameters
    ----------
    text:
        The source text to scan (may contain multiple lines).
    sensitivity:
        Controls which severity levels are returned:
        * ``"low"``  -- only ``CRITICAL`` findings.
        * ``"medium"`` -- ``MEDIUM``, ``HIGH``, and ``CRITICAL`` (default).
        * ``"high"`` -- all findings including ``LOW`` and ``INFO``.
    file_path:
        Optional file path to attach to each finding.

    Returns
    -------
    list[Finding]
        A list of findings with secrets redacted in *matched_text*.
    """
    sensitivity = sensitivity.lower()
    threshold = _SENSITIVITY_THRESHOLD.get(sensitivity, _SENSITIVITY_THRESHOLD["medium"])
    findings: list[Finding] = []

    lines = text.splitlines()
    for line_idx, line in enumerate(lines, start=1):
        for name, pattern, severity, description, confidence, cwe_ids in _SECRET_PATTERNS:
            # Skip if below sensitivity threshold
            if _SEVERITY_ORDER[severity] < threshold:
                continue

            for match in pattern.finditer(line):
                # Use the first capturing group if available, otherwise the
                # full match.
                raw = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                redacted = _redact(raw, name)
                range_obj = Range(
                    start_line=line_idx - 1,
                    start_col=match.start(),
                    end_line=line_idx - 1,
                    end_col=match.end(),
                )
                finding = Finding(
                    finding_type=FindingType.SECRET,
                    severity=severity,
                    message=description,
                    matched_text=redacted,
                    line_number=line_idx,
                    file_path=file_path,
                    scanner="secrets",
                    metadata={"secret_type": name},
                    range=range_obj,
                    confidence=confidence,
                    cwe_ids=list(cwe_ids),
                )
                finding.details["secret_type"] = name
                finding.details["exposure_risk"] = (
                    "critical" if severity in (Severity.CRITICAL, Severity.HIGH)
                    else "moderate"
                )
                enrich_finding(finding, source=text)
                findings.append(finding)

    return findings
