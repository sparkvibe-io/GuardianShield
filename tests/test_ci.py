"""Tests for guardianshield.ci — CI quality gate evaluation."""

from __future__ import annotations

from guardianshield.ci import (
    _SEVERITY_ORDER,
    QualityGateConfig,
    QualityGateResult,
    check_quality_gate,
)
from guardianshield.findings import Finding, FindingType, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    severity: Severity = Severity.HIGH,
    finding_type: FindingType = FindingType.SQL_INJECTION,
    suppressed: bool = False,
    **kwargs,
) -> Finding:
    """Create a minimal Finding for testing."""
    metadata = kwargs.pop("metadata", {})
    if suppressed:
        metadata["suppressed"] = True
    return Finding(
        finding_type=finding_type,
        severity=severity,
        message=f"Test {severity.value} finding",
        matched_text="test",
        line_number=1,
        file_path="test.py",
        scanner="test_scanner",
        metadata=metadata,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# TestQualityGateConfig
# ---------------------------------------------------------------------------

class TestQualityGateConfig:
    """Tests for QualityGateConfig defaults and custom values."""

    def test_default_fail_on(self):
        config = QualityGateConfig()
        assert config.fail_on == Severity.HIGH

    def test_default_warn_on(self):
        config = QualityGateConfig()
        assert config.warn_on == Severity.MEDIUM

    def test_default_max_findings(self):
        config = QualityGateConfig()
        assert config.max_findings is None

    def test_default_exclude_suppressed(self):
        config = QualityGateConfig()
        assert config.exclude_suppressed is True

    def test_custom_fail_on(self):
        config = QualityGateConfig(fail_on=Severity.CRITICAL)
        assert config.fail_on == Severity.CRITICAL

    def test_custom_warn_on(self):
        config = QualityGateConfig(warn_on=Severity.LOW)
        assert config.warn_on == Severity.LOW

    def test_custom_max_findings(self):
        config = QualityGateConfig(max_findings=5)
        assert config.max_findings == 5

    def test_custom_exclude_suppressed_false(self):
        config = QualityGateConfig(exclude_suppressed=False)
        assert config.exclude_suppressed is False


# ---------------------------------------------------------------------------
# TestQualityGateResult
# ---------------------------------------------------------------------------

class TestQualityGateResult:
    """Tests for QualityGateResult defaults."""

    def test_default_passed(self):
        result = QualityGateResult()
        assert result.passed is True

    def test_default_exit_code(self):
        result = QualityGateResult()
        assert result.exit_code == 0

    def test_default_verdict(self):
        result = QualityGateResult()
        assert result.verdict == "pass"

    def test_default_summary(self):
        result = QualityGateResult()
        assert result.summary == {}

    def test_default_findings(self):
        result = QualityGateResult()
        assert result.findings == []


# ---------------------------------------------------------------------------
# TestCheckQualityGate
# ---------------------------------------------------------------------------

class TestCheckQualityGate:
    """Tests for the check_quality_gate function."""

    def test_no_findings_passes(self):
        result = check_quality_gate([])
        assert result.passed is True
        assert result.exit_code == 0
        assert result.verdict == "pass"

    def test_no_findings_summary(self):
        result = check_quality_gate([])
        assert result.summary["total"] == 0
        assert result.summary["failures"] == 0
        assert result.summary["warnings"] == 0

    def test_high_finding_fails(self):
        findings = [_make_finding(Severity.HIGH)]
        result = check_quality_gate(findings)
        assert result.passed is False
        assert result.exit_code == 1
        assert result.verdict == "fail"

    def test_critical_finding_fails(self):
        findings = [_make_finding(Severity.CRITICAL)]
        result = check_quality_gate(findings)
        assert result.passed is False
        assert result.exit_code == 1
        assert result.verdict == "fail"

    def test_medium_finding_warns(self):
        findings = [_make_finding(Severity.MEDIUM)]
        result = check_quality_gate(findings)
        assert result.passed is True
        assert result.verdict == "warn"
        assert result.exit_code == 0

    def test_low_finding_passes(self):
        findings = [_make_finding(Severity.LOW)]
        result = check_quality_gate(findings)
        assert result.passed is True
        assert result.verdict == "pass"

    def test_info_finding_passes(self):
        findings = [_make_finding(Severity.INFO)]
        result = check_quality_gate(findings)
        assert result.passed is True
        assert result.verdict == "pass"

    def test_none_config_uses_defaults(self):
        result = check_quality_gate([], None)
        assert result.passed is True
        assert result.exit_code == 0

    def test_max_findings_exceeded_fails(self):
        config = QualityGateConfig(max_findings=1)
        findings = [_make_finding(Severity.LOW), _make_finding(Severity.LOW)]
        result = check_quality_gate(findings, config)
        assert result.passed is False
        assert result.exit_code == 1
        assert result.verdict == "fail"

    def test_max_findings_not_exceeded_passes(self):
        config = QualityGateConfig(max_findings=5)
        findings = [_make_finding(Severity.LOW), _make_finding(Severity.LOW)]
        result = check_quality_gate(findings, config)
        assert result.passed is True

    def test_max_findings_exact_boundary_passes(self):
        config = QualityGateConfig(max_findings=2)
        findings = [_make_finding(Severity.LOW), _make_finding(Severity.LOW)]
        result = check_quality_gate(findings, config)
        assert result.passed is True

    def test_findings_returned_in_result(self):
        findings = [_make_finding(Severity.LOW)]
        result = check_quality_gate(findings)
        assert len(result.findings) == 1

    def test_by_severity_in_summary(self):
        findings = [
            _make_finding(Severity.HIGH),
            _make_finding(Severity.MEDIUM),
            _make_finding(Severity.MEDIUM),
        ]
        result = check_quality_gate(findings)
        assert result.summary["by_severity"]["high"] == 1
        assert result.summary["by_severity"]["medium"] == 2

    def test_summary_total_count(self):
        findings = [_make_finding(Severity.LOW) for _ in range(3)]
        result = check_quality_gate(findings)
        assert result.summary["total"] == 3

    def test_failures_take_precedence_over_max_findings(self):
        config = QualityGateConfig(max_findings=100)
        findings = [_make_finding(Severity.HIGH)]
        result = check_quality_gate(findings, config)
        assert result.verdict == "fail"
        assert result.summary["failures"] == 1


# ---------------------------------------------------------------------------
# TestSeverityThresholds
# ---------------------------------------------------------------------------

class TestSeverityThresholds:
    """Tests for custom fail_on and warn_on thresholds."""

    def test_fail_on_critical_high_passes(self):
        config = QualityGateConfig(fail_on=Severity.CRITICAL)
        findings = [_make_finding(Severity.HIGH)]
        result = check_quality_gate(findings, config)
        assert result.passed is True

    def test_fail_on_critical_high_warns(self):
        config = QualityGateConfig(fail_on=Severity.CRITICAL, warn_on=Severity.HIGH)
        findings = [_make_finding(Severity.HIGH)]
        result = check_quality_gate(findings, config)
        assert result.verdict == "warn"

    def test_fail_on_medium_medium_fails(self):
        config = QualityGateConfig(fail_on=Severity.MEDIUM)
        findings = [_make_finding(Severity.MEDIUM)]
        result = check_quality_gate(findings, config)
        assert result.passed is False
        assert result.verdict == "fail"

    def test_fail_on_low_low_fails(self):
        config = QualityGateConfig(fail_on=Severity.LOW)
        findings = [_make_finding(Severity.LOW)]
        result = check_quality_gate(findings, config)
        assert result.passed is False
        assert result.verdict == "fail"

    def test_fail_on_info_info_fails(self):
        config = QualityGateConfig(fail_on=Severity.INFO)
        findings = [_make_finding(Severity.INFO)]
        result = check_quality_gate(findings, config)
        assert result.passed is False
        assert result.verdict == "fail"

    def test_warn_on_low_with_low_finding(self):
        config = QualityGateConfig(warn_on=Severity.LOW)
        findings = [_make_finding(Severity.LOW)]
        result = check_quality_gate(findings, config)
        assert result.verdict == "warn"
        assert result.passed is True

    def test_warn_on_info_with_info_finding(self):
        config = QualityGateConfig(warn_on=Severity.INFO)
        findings = [_make_finding(Severity.INFO)]
        result = check_quality_gate(findings, config)
        assert result.verdict == "warn"
        assert result.passed is True


# ---------------------------------------------------------------------------
# TestExcludeSuppressed
# ---------------------------------------------------------------------------

class TestExcludeSuppressed:
    """Tests for suppressed finding handling."""

    def test_suppressed_excluded_by_default(self):
        findings = [_make_finding(Severity.HIGH, suppressed=True)]
        result = check_quality_gate(findings)
        assert result.passed is True
        assert result.summary["total"] == 0

    def test_suppressed_counted_when_disabled(self):
        config = QualityGateConfig(exclude_suppressed=False)
        findings = [_make_finding(Severity.HIGH, suppressed=True)]
        result = check_quality_gate(findings, config)
        assert result.passed is False
        assert result.summary["total"] == 1

    def test_mixed_suppressed_and_active(self):
        findings = [
            _make_finding(Severity.HIGH, suppressed=True),
            _make_finding(Severity.LOW),
        ]
        result = check_quality_gate(findings)
        assert result.passed is True
        assert result.summary["total"] == 1
        assert len(result.findings) == 1

    def test_all_findings_suppressed_passes(self):
        findings = [
            _make_finding(Severity.HIGH, suppressed=True),
            _make_finding(Severity.CRITICAL, suppressed=True),
        ]
        result = check_quality_gate(findings)
        assert result.passed is True
        assert result.summary["total"] == 0

    def test_suppressed_not_in_returned_findings(self):
        findings = [
            _make_finding(Severity.HIGH, suppressed=True),
            _make_finding(Severity.LOW),
        ]
        result = check_quality_gate(findings)
        assert all(
            not f.metadata.get("suppressed", False) for f in result.findings
        )


# ---------------------------------------------------------------------------
# TestEdgeCases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge case tests."""

    def test_empty_findings_list(self):
        result = check_quality_gate([])
        assert result.passed is True
        assert result.summary["total"] == 0
        assert result.findings == []

    def test_severity_order_completeness(self):
        for sev in Severity:
            assert sev in _SEVERITY_ORDER

    def test_by_severity_omits_zero_counts(self):
        findings = [_make_finding(Severity.HIGH)]
        result = check_quality_gate(findings)
        assert "low" not in result.summary["by_severity"]
        assert "info" not in result.summary["by_severity"]

    def test_multiple_finding_types(self):
        findings = [
            _make_finding(Severity.HIGH, finding_type=FindingType.SQL_INJECTION),
            _make_finding(Severity.HIGH, finding_type=FindingType.XSS),
        ]
        result = check_quality_gate(findings)
        assert result.passed is False
        assert result.summary["failures"] == 2

    def test_warn_does_not_set_exit_code(self):
        findings = [_make_finding(Severity.MEDIUM)]
        result = check_quality_gate(findings)
        assert result.verdict == "warn"
        assert result.exit_code == 0
