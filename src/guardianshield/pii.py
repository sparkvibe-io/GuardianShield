"""PII (Personally Identifiable Information) detection module.

Scans text for common PII patterns such as email addresses, SSNs,
credit card numbers, phone numbers, IP addresses, dates of birth,
and physical addresses. Supports optional Presidio backend for
enhanced detection.
"""

from __future__ import annotations

import re

from guardianshield.enrichment import enrich_finding
from guardianshield.findings import Finding, FindingType, Range, Severity

# ---------------------------------------------------------------------------
# Compiled regex patterns for PII detection
# Each entry: (name, compiled_regex, severity, description, pii_type_str,
#              confidence, cwe_ids)
# ---------------------------------------------------------------------------

PII_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str, str, float, list[str]]] = [
    (
        "Email Address",
        re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
        Severity.MEDIUM,
        "Email address detected",
        "email",
        0.85,
        ["CWE-359"],
    ),
    (
        "SSN",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        Severity.CRITICAL,
        "Social Security Number detected",
        "ssn",
        0.9,
        ["CWE-359"],
    ),
    (
        "Credit Card Number",
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        Severity.CRITICAL,
        "Credit card number detected",
        "credit_card",
        0.75,
        ["CWE-359"],
    ),
    (
        "US Phone Number",
        re.compile(
            r"(?:\+1[\s.-]?)?"
            r"(?:\(?\d{3}\)?[\s.-]?)"
            r"\d{3}[\s.-]?\d{4}\b"
        ),
        Severity.MEDIUM,
        "US phone number detected",
        "phone",
        0.65,
        ["CWE-359"],
    ),
    (
        "IPv4 Address",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        Severity.LOW,
        "IPv4 address detected",
        "ip_address",
        0.7,
        ["CWE-359"],
    ),
    (
        "Date of Birth",
        re.compile(
            r"(?i)(?:dob|date\s+of\s+birth|born\s+on)"
            r"[:\s]+\d{1,2}/\d{1,2}/\d{4}"
        ),
        Severity.MEDIUM,
        "Date of birth detected",
        "date_of_birth",
        0.6,
        ["CWE-359"],
    ),
    (
        "Physical Address",
        re.compile(
            r"\b\d{1,6}\s+[A-Za-z0-9.\s]+(?:Street|St|Avenue|Ave|Boulevard|Blvd"
            r"|Drive|Dr|Road|Rd|Lane|Ln|Way|Court|Ct|Circle|Cir|Place|Pl)"
            r"\.?(?:\s*,\s*[A-Za-z\s]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?\b",
            re.IGNORECASE,
        ),
        Severity.LOW,
        "Physical address detected",
        "physical_address",
        0.5,
        ["CWE-359"],
    ),
]

# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------

_REDACTION_MAP = {
    "email": "***@***.***",
    "ssn": "***-**-****",
    "credit_card": "****...****",
    "phone": "(***) ***-****",
    "ip_address": "***.***.***.***",
    "date_of_birth": "DOB: **/**/****",
    "physical_address": "*** [ADDRESS REDACTED]",
}


def _redact(pii_type: str) -> str:
    """Return a redacted placeholder for the given PII type."""
    return _REDACTION_MAP.get(pii_type, "***REDACTED***")


# ---------------------------------------------------------------------------
# Sensitivity helpers
# ---------------------------------------------------------------------------

def _severity_allowed(severity: Severity, sensitivity: str) -> bool:
    """Return True if *severity* should be reported at the given *sensitivity*.

    - ``"low"``  -- only CRITICAL findings
    - ``"medium"`` -- skip LOW (i.e. CRITICAL, HIGH, MEDIUM)
    - ``"high"``  -- everything
    """
    if sensitivity == "low":
        return severity == Severity.CRITICAL
    if sensitivity == "medium":
        return severity != Severity.LOW
    # "high" -- report all
    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_pii(
    text: str,
    sensitivity: str = "medium",
    use_presidio: bool = False,
) -> list[Finding]:
    """Scan *text* for PII and return a list of :class:`Finding` objects.

    Parameters
    ----------
    text:
        The text to scan (may contain multiple lines).
    sensitivity:
        Controls which severities are included in the results.
        ``"low"`` = CRITICAL only, ``"medium"`` = skip LOW,
        ``"high"`` = all findings.
    use_presidio:
        If ``True``, attempt to use the Presidio analyzer backend.
        Falls back to regex if Presidio is not installed.

    Returns
    -------
    list[Finding]
        A (possibly empty) list of findings, one per match.
    """
    if use_presidio:
        presidio_findings = _check_pii_presidio(text)
        if presidio_findings is not None:
            # Filter by sensitivity before returning.
            return [
                f
                for f in presidio_findings
                if _severity_allowed(f.severity, sensitivity)
            ]
        # Presidio not available -- fall through to regex.

    findings: list[Finding] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        for _name, pattern, severity, description, pii_type, confidence, cwe_ids in PII_PATTERNS:
            if not _severity_allowed(severity, sensitivity):
                continue
            for match in pattern.finditer(line):
                range_obj = Range(
                    start_line=line_number - 1,
                    start_col=match.start(),
                    end_line=line_number - 1,
                    end_col=match.end(),
                )
                finding = Finding(
                    finding_type=FindingType.PII_LEAK,
                    severity=severity,
                    message=f"{description} in line {line_number}",
                    matched_text=_redact(pii_type),
                    line_number=line_number,
                    scanner="pii_detector",
                    metadata={"pii_type": pii_type},
                    range=range_obj,
                    confidence=confidence,
                    cwe_ids=list(cwe_ids),
                )
                finding.details["pii_type"] = pii_type
                enrich_finding(finding, source=text)
                findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Optional Presidio backend
# ---------------------------------------------------------------------------

def _check_pii_presidio(text: str) -> list[Finding] | None:
    """Try to detect PII using the Presidio analyzer.

    Returns a list of findings on success, or ``None`` if Presidio is
    not installed (signalling the caller to fall back to regex).
    """
    try:
        from presidio_analyzer import AnalyzerEngine  # type: ignore[import-untyped]
    except ImportError:
        return None

    analyzer = AnalyzerEngine()
    results = analyzer.analyze(text=text, language="en")

    _presidio_type_map = {
        "EMAIL_ADDRESS": ("email", Severity.MEDIUM),
        "US_SSN": ("ssn", Severity.CRITICAL),
        "CREDIT_CARD": ("credit_card", Severity.CRITICAL),
        "PHONE_NUMBER": ("phone", Severity.MEDIUM),
        "IP_ADDRESS": ("ip_address", Severity.LOW),
        "DATE_TIME": ("date_of_birth", Severity.MEDIUM),
        "LOCATION": ("physical_address", Severity.LOW),
    }

    findings: list[Finding] = []
    lines = text.splitlines()
    for result in results:
        pii_type, severity = _presidio_type_map.get(
            result.entity_type, ("unknown", Severity.MEDIUM)
        )
        # Determine line number from character offset.
        char_count = 0
        line_number = 1
        for idx, line in enumerate(lines, start=1):
            if char_count + len(line) >= result.start:
                line_number = idx
                break
            char_count += len(line) + 1  # +1 for newline

        findings.append(
            Finding(
                finding_type=FindingType.PII_LEAK,
                severity=severity,
                message=f"{pii_type} detected by Presidio at offset {result.start}",
                matched_text=_redact(pii_type),
                line_number=line_number,
                scanner="pii_detector",
                metadata={"pii_type": pii_type},
            )
        )

    return findings
