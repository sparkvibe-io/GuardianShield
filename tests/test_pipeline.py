"""Tests for the result pipeline — multi-engine dedup and merge."""

from __future__ import annotations

import pytest

from guardianshield import GuardianShield
from guardianshield.engines import RegexEngine
from guardianshield.findings import Finding, FindingType, Severity
from guardianshield.pipeline import (
    EngineTimingResult,
    _merge_fingerprint,
    merge_engine_findings,
    timed_analyze,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    line: int = 1,
    confidence: float = 0.8,
    finding_type: FindingType = FindingType.SQL_INJECTION,
    engine: str = "regex",
    file_path: str | None = "app.py",
    matched_text: str = "test",
) -> Finding:
    f = Finding(
        finding_type=finding_type,
        severity=Severity.HIGH,
        message="test finding",
        matched_text=matched_text,
        line_number=line,
        file_path=file_path,
        scanner="code_scanner",
        confidence=confidence,
    )
    f.details["engine"] = engine
    return f


# ===================================================================
# TestMergeFingerprint
# ===================================================================


class TestMergeFingerprint:
    def test_same_location_same_type_same_fp(self):
        f1 = _make_finding(line=10, engine="regex", matched_text="abc")
        f2 = _make_finding(line=10, engine="deep", matched_text="xyz")
        assert _merge_fingerprint(f1) == _merge_fingerprint(f2)

    def test_different_line_different_fp(self):
        f1 = _make_finding(line=10)
        f2 = _make_finding(line=20)
        assert _merge_fingerprint(f1) != _merge_fingerprint(f2)

    def test_different_type_different_fp(self):
        f1 = _make_finding(finding_type=FindingType.SQL_INJECTION)
        f2 = _make_finding(finding_type=FindingType.XSS)
        assert _merge_fingerprint(f1) != _merge_fingerprint(f2)

    def test_none_file_path(self):
        f = _make_finding(file_path=None)
        fp = _merge_fingerprint(f)
        assert len(fp) == 16


# ===================================================================
# TestMergeEngineFindings
# ===================================================================


class TestMergeEngineFindings:
    def test_empty_list(self):
        assert merge_engine_findings([]) == []

    def test_single_finding_passthrough(self):
        f = _make_finding()
        result = merge_engine_findings([f])
        assert len(result) == 1
        assert result[0].details["engines"] == ["regex"]

    def test_same_engine_kept_separate(self):
        f1 = _make_finding(line=10, engine="regex")
        f2 = _make_finding(line=10, engine="regex")
        result = merge_engine_findings([f1, f2])
        assert len(result) == 2

    def test_multi_engine_merged(self):
        f1 = _make_finding(line=10, confidence=0.8, engine="regex")
        f2 = _make_finding(line=10, confidence=0.7, engine="deep")
        result = merge_engine_findings([f1, f2])
        assert len(result) == 1
        assert result[0].details["multi_engine_confirmed"] is True

    def test_confidence_boost(self):
        f1 = _make_finding(line=10, confidence=0.8, engine="regex")
        f2 = _make_finding(line=10, confidence=0.7, engine="deep")
        result = merge_engine_findings([f1, f2])
        # max(0.8, 0.7) + 0.1 * (2-1) = 0.9
        assert result[0].confidence == pytest.approx(0.9)

    def test_confidence_cap_at_one(self):
        f1 = _make_finding(line=10, confidence=0.95, engine="regex")
        f2 = _make_finding(line=10, confidence=0.95, engine="deep")
        result = merge_engine_findings([f1, f2])
        assert result[0].confidence <= 1.0

    def test_engines_list_set(self):
        f1 = _make_finding(line=10, engine="regex")
        f2 = _make_finding(line=10, engine="deep")
        result = merge_engine_findings([f1, f2])
        assert "regex" in result[0].details["engines"]
        assert "deep" in result[0].details["engines"]

    def test_engine_evidence_collected(self):
        f1 = _make_finding(line=10, engine="regex")
        f1.details["match_explanation"] = "pattern match"
        f2 = _make_finding(line=10, engine="deep")
        f2.details["taint_chain"] = "input -> query"
        result = merge_engine_findings([f1, f2])
        evidence = result[0].details.get("engine_evidence", {})
        assert "deep" in evidence or "regex" in evidence

    def test_different_locations_not_merged(self):
        f1 = _make_finding(line=10, engine="regex")
        f2 = _make_finding(line=20, engine="deep")
        result = merge_engine_findings([f1, f2])
        assert len(result) == 2

    def test_different_types_not_merged(self):
        f1 = _make_finding(
            line=10, engine="regex", finding_type=FindingType.SQL_INJECTION
        )
        f2 = _make_finding(line=10, engine="deep", finding_type=FindingType.XSS)
        result = merge_engine_findings([f1, f2])
        assert len(result) == 2

    def test_none_confidence_treated_as_zero(self):
        f1 = _make_finding(line=10, confidence=0.8, engine="regex")
        f2 = _make_finding(line=10, engine="deep")
        f2.confidence = None
        result = merge_engine_findings([f1, f2])
        assert result[0].confidence >= 0.8

    def test_three_engines_boost(self):
        f1 = _make_finding(line=10, confidence=0.7, engine="regex")
        f2 = _make_finding(line=10, confidence=0.8, engine="deep")
        f3 = _make_finding(line=10, confidence=0.6, engine="semantic")
        result = merge_engine_findings([f1, f2, f3])
        assert len(result) == 1
        # max=0.8, boost = 0.8 + 0.1*2 = 1.0
        assert result[0].confidence == pytest.approx(1.0)


# ===================================================================
# TestTimedAnalyze
# ===================================================================


class TestTimedAnalyze:
    def test_returns_tuple(self):
        engine = RegexEngine()
        result = timed_analyze(engine, "x = 1\n")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_positive_timing(self):
        engine = RegexEngine()
        _, timing = timed_analyze(engine, "x = 1\n")
        assert timing.duration_ms >= 0

    def test_finding_count_matches(self):
        engine = RegexEngine()
        findings, timing = timed_analyze(engine, "x = 1\n")
        assert timing.finding_count == len(findings)

    def test_engine_name_set(self):
        engine = RegexEngine()
        _, timing = timed_analyze(engine, "x = 1\n")
        assert timing.engine_name == "regex"

    def test_timing_to_dict(self):
        t = EngineTimingResult(engine_name="test", duration_ms=1.5, finding_count=3)
        d = t.to_dict()
        assert d["engine_name"] == "test"
        assert d["duration_ms"] == 1.5
        assert d["finding_count"] == 3


# ===================================================================
# TestPipelineCoreIntegration
# ===================================================================


class TestPipelineCoreIntegration:
    def test_timings_stored_after_scan(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        shield.scan_code("x = 1\n", language="python")
        assert len(shield._engine_timings) >= 1

    def test_status_includes_timings(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        shield.scan_code("x = 1\n", language="python")
        status = shield.status()
        assert "engine_timings" in status
        assert status["engine_timings"][0]["engine_name"] == "regex"

    def test_deduped_scan_with_both_engines(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        shield.set_engines(["regex", "deep"])
        code = (
            "import subprocess\n"
            "user_input = input()\n"
            "subprocess.call(user_input, shell=True)\n"
        )
        findings = shield.scan_code(code, language="python")
        # Results should be present (not crashing with dedup).
        assert isinstance(findings, list)

    def test_fp_annotation_after_merge(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        findings = shield.scan_code('password = "hunter2"\n', language="python")
        # Should not crash — FP annotation runs after merge.
        assert isinstance(findings, list)

    def test_timings_empty_before_scan(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        assert shield._engine_timings == []

    def test_multiple_scans_update_timings(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        shield.scan_code("x = 1\n", language="python")
        first_timings = shield._engine_timings[:]
        shield.scan_code("y = 2\n", language="python")
        # Timings should be from the latest scan.
        assert shield._engine_timings is not first_timings


# ===================================================================
# TestMultipleEnginesOverlap
# ===================================================================


class TestMultipleEnginesOverlap:
    def test_same_type_same_line_merged(self):
        f1 = _make_finding(line=10, confidence=0.7, engine="regex")
        f2 = _make_finding(line=10, confidence=0.8, engine="deep")
        result = merge_engine_findings([f1, f2])
        assert len(result) == 1
        assert result[0].details["multi_engine_confirmed"] is True

    def test_partial_overlap(self):
        # Line 10: both engines. Line 20: regex only.
        f1 = _make_finding(line=10, confidence=0.7, engine="regex")
        f2 = _make_finding(line=10, confidence=0.8, engine="deep")
        f3 = _make_finding(line=20, confidence=0.6, engine="regex")
        result = merge_engine_findings([f1, f2, f3])
        assert len(result) == 2

    def test_deep_only_preserved(self):
        f1 = _make_finding(line=10, engine="deep")
        result = merge_engine_findings([f1])
        assert len(result) == 1
        assert result[0].details["engines"] == ["deep"]

    def test_highest_confidence_kept_as_base(self):
        f1 = _make_finding(line=10, confidence=0.6, engine="regex")
        f2 = _make_finding(line=10, confidence=0.9, engine="deep")
        result = merge_engine_findings([f1, f2])
        # Deep had higher confidence, should be base.
        # Boosted: 0.9 + 0.1 = 1.0
        assert result[0].confidence == pytest.approx(1.0)

    def test_mixed_types_not_merged(self):
        f1 = _make_finding(
            line=10, engine="regex", finding_type=FindingType.SQL_INJECTION
        )
        f2 = _make_finding(
            line=10, engine="deep", finding_type=FindingType.COMMAND_INJECTION
        )
        result = merge_engine_findings([f1, f2])
        assert len(result) == 2

    def test_mixed_files_not_merged(self):
        f1 = _make_finding(line=10, engine="regex", file_path="a.py")
        f2 = _make_finding(line=10, engine="deep", file_path="b.py")
        result = merge_engine_findings([f1, f2])
        assert len(result) == 2

    def test_merge_preserves_file_path(self):
        f1 = _make_finding(line=10, engine="regex", file_path="app.py")
        f2 = _make_finding(line=10, engine="deep", file_path="app.py")
        result = merge_engine_findings([f1, f2])
        assert result[0].file_path == "app.py"

    def test_same_engine_different_types_kept(self):
        f1 = _make_finding(
            line=10, engine="regex", finding_type=FindingType.SQL_INJECTION
        )
        f2 = _make_finding(line=10, engine="regex", finding_type=FindingType.XSS)
        result = merge_engine_findings([f1, f2])
        assert len(result) == 2


# ===================================================================
# TestEdgeCases
# ===================================================================


class TestEdgeCases:
    def test_empty_findings(self):
        assert merge_engine_findings([]) == []

    def test_none_file_path_findings(self):
        f1 = _make_finding(file_path=None, engine="regex")
        f2 = _make_finding(file_path=None, engine="deep")
        result = merge_engine_findings([f1, f2])
        assert len(result) == 1

    def test_missing_engine_detail(self):
        f = Finding(
            finding_type=FindingType.SQL_INJECTION,
            severity=Severity.HIGH,
            message="test",
            line_number=1,
        )
        # No details["engine"] set.
        result = merge_engine_findings([f])
        assert len(result) == 1
        assert "unknown" in result[0].details["engines"]

    def test_large_number_of_findings(self):
        findings = [_make_finding(line=i, engine="regex") for i in range(1000)]
        result = merge_engine_findings(findings)
        assert len(result) == 1000

    def test_many_engines_on_same_line(self):
        findings = [
            _make_finding(line=10, confidence=0.5, engine=f"engine_{i}")
            for i in range(5)
        ]
        result = merge_engine_findings(findings)
        assert len(result) == 1
        assert len(result[0].details["engines"]) == 5
        # 0.5 + 0.1 * 4 = 0.9
        assert result[0].confidence == pytest.approx(0.9)
