"""CI quality gate evaluation for GuardianShield.

Provides :func:`check_quality_gate` to evaluate a list of findings against
configurable severity thresholds, producing a pass/fail/warn verdict
suitable for CI pipeline integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .findings import Finding, Severity

# Severity ordering for comparison
_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class QualityGateConfig:
    """Configuration for CI quality gate checks."""

    fail_on: Severity = Severity.HIGH  # fail if any finding at this level or above
    warn_on: Severity = Severity.MEDIUM  # warn if findings at this level
    max_findings: int | None = None  # optional absolute cap
    exclude_suppressed: bool = True  # skip suppressed findings


@dataclass
class QualityGateResult:
    """Result of a quality gate evaluation."""

    passed: bool = True
    exit_code: int = 0  # 0=pass, 1=fail, 2=error
    verdict: str = "pass"  # "pass", "fail", "warn"
    summary: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)


def check_quality_gate(
    findings: list[Finding],
    config: QualityGateConfig | None = None,
) -> QualityGateResult:
    """Evaluate findings against quality gate thresholds.

    Args:
        findings: List of findings to evaluate.
        config: Quality gate configuration. Uses defaults if None.

    Returns:
        QualityGateResult with pass/fail verdict and summary.
    """
    if config is None:
        config = QualityGateConfig()

    # Filter out suppressed findings if configured
    active_findings = findings
    if config.exclude_suppressed:
        active_findings = [
            f for f in findings if not f.metadata.get("suppressed", False)
        ]

    # Count by severity
    by_severity: dict[str, int] = {}
    for sev in Severity:
        count = sum(1 for f in active_findings if f.severity == sev)
        if count > 0:
            by_severity[sev.value] = count

    # Determine failures and warnings
    fail_threshold = _SEVERITY_ORDER[config.fail_on]
    warn_threshold = _SEVERITY_ORDER[config.warn_on]

    failures = [
        f
        for f in active_findings
        if _SEVERITY_ORDER[f.severity] >= fail_threshold
    ]
    warnings = [
        f
        for f in active_findings
        if warn_threshold <= _SEVERITY_ORDER[f.severity] < fail_threshold
    ]

    # Determine verdict
    passed = True
    verdict = "pass"
    exit_code = 0

    if failures or (config.max_findings is not None and len(active_findings) > config.max_findings):
        passed = False
        verdict = "fail"
        exit_code = 1
    elif warnings:
        verdict = "warn"
        # warn doesn't fail — still passes

    summary = {
        "total": len(active_findings),
        "by_severity": by_severity,
        "failures": len(failures),
        "warnings": len(warnings),
    }

    return QualityGateResult(
        passed=passed,
        exit_code=exit_code,
        verdict=verdict,
        summary=summary,
        findings=active_findings,
    )
