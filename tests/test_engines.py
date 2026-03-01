"""Tests for the analysis engine abstraction (engines.py) and core integration."""

from __future__ import annotations

from typing import Any

import pytest

from guardianshield.core import GuardianShield
from guardianshield.engines import AnalysisEngine, EngineRegistry, RegexEngine
from guardianshield.findings import Finding, FindingType, Severity

# ---------------------------------------------------------------------------
# Fixtures — intentionally vulnerable code samples used to test
# that the security scanner correctly detects vulnerabilities.
# ---------------------------------------------------------------------------

VULNERABLE_CODE = 'query = "SELECT * FROM users WHERE id=" + user_id'
CLEAN_CODE = "x = 1 + 2"
# Intentionally insecure — tests that scanner detects dangerous eval usage:
EVAL_CODE = "result = eval(user_input)"


class DummyEngine:
    """Minimal engine for testing the registry with a custom engine."""

    @property
    def name(self) -> str:
        return "dummy"

    def analyze(
        self,
        code: str,
        language: str | None = None,
        sensitivity: str = "medium",
        file_path: str | None = None,
    ) -> list[Finding]:
        return [
            Finding(
                finding_type=FindingType.INSECURE_PATTERN,
                severity=Severity.LOW,
                message="Dummy finding",
                matched_text="dummy",
                scanner="dummy_engine",
                details={"engine": "dummy"},
            )
        ]

    def capabilities(self) -> dict[str, Any]:
        return {
            "description": "Dummy engine for testing",
            "analysis_type": "test",
            "supported_languages": [],
            "speed": "instant",
            "cross_line": False,
            "data_flow": False,
            "semantic": False,
        }


# ---------------------------------------------------------------------------
# TestAnalysisEngineProtocol
# ---------------------------------------------------------------------------


class TestAnalysisEngineProtocol:
    def test_regex_engine_is_analysis_engine(self):
        engine = RegexEngine()
        assert isinstance(engine, AnalysisEngine)

    def test_name_property(self):
        engine = RegexEngine()
        assert engine.name == "regex"

    def test_capabilities_keys(self):
        engine = RegexEngine()
        caps = engine.capabilities()
        assert "description" in caps
        assert "analysis_type" in caps
        assert "supported_languages" in caps
        assert "speed" in caps
        assert caps["cross_line"] is False
        assert caps["data_flow"] is False
        assert caps["semantic"] is False

    def test_capabilities_languages(self):
        engine = RegexEngine()
        caps = engine.capabilities()
        languages = caps["supported_languages"]
        assert "python" in languages
        assert "javascript" in languages

    def test_analyze_returns_findings_for_vulnerable_code(self):
        engine = RegexEngine()
        findings = engine.analyze(VULNERABLE_CODE)
        assert len(findings) > 0
        assert all(isinstance(f, Finding) for f in findings)

    def test_analyze_tags_findings_with_engine(self):
        engine = RegexEngine()
        findings = engine.analyze(VULNERABLE_CODE)
        for f in findings:
            assert f.details.get("engine") == "regex"

    def test_analyze_returns_empty_for_clean_code(self):
        engine = RegexEngine()
        findings = engine.analyze(CLEAN_CODE)
        assert findings == []

    def test_analyze_respects_sensitivity(self):
        engine = RegexEngine()
        high_findings = engine.analyze(VULNERABLE_CODE, sensitivity="high")
        low_findings = engine.analyze(VULNERABLE_CODE, sensitivity="low")
        assert len(high_findings) >= len(low_findings)

    def test_analyze_passes_file_path(self):
        engine = RegexEngine()
        findings = engine.analyze(
            VULNERABLE_CODE, file_path="test.py",
        )
        for f in findings:
            assert f.file_path == "test.py"

    def test_analyze_language_detection_from_file_path(self):
        engine = RegexEngine()
        findings = engine.analyze(EVAL_CODE, file_path="app.py")
        assert len(findings) > 0

    def test_dummy_engine_satisfies_protocol(self):
        engine = DummyEngine()
        assert isinstance(engine, AnalysisEngine)


# ---------------------------------------------------------------------------
# TestEngineRegistry
# ---------------------------------------------------------------------------


class TestEngineRegistry:
    def test_register_and_get(self):
        registry = EngineRegistry()
        engine = RegexEngine()
        registry.register(engine)
        assert registry.get("regex") is engine

    def test_duplicate_name_raises_value_error(self):
        registry = EngineRegistry()
        registry.register(RegexEngine())
        with pytest.raises(ValueError, match="already registered"):
            registry.register(RegexEngine())

    def test_unknown_name_raises_key_error(self):
        registry = EngineRegistry()
        with pytest.raises(KeyError, match="Unknown engine"):
            registry.get("nonexistent")

    def test_available_names_sorted(self):
        registry = EngineRegistry()
        registry.register(RegexEngine())
        registry.register(DummyEngine())
        assert registry.available_names == ["dummy", "regex"]

    def test_list_engines_without_enabled_names(self):
        registry = EngineRegistry()
        registry.register(RegexEngine())
        result = registry.list_engines()
        assert len(result) == 1
        assert result[0]["name"] == "regex"
        assert result[0]["enabled"] is True

    def test_list_engines_with_enabled_names(self):
        registry = EngineRegistry()
        registry.register(RegexEngine())
        registry.register(DummyEngine())
        result = registry.list_engines(enabled_names=["regex"])
        names = {e["name"] for e in result}
        assert names == {"dummy", "regex"}
        enabled = {e["name"]: e["enabled"] for e in result}
        assert enabled["regex"] is True
        assert enabled["dummy"] is False

    def test_enabled_engines_returns_correct_subset(self):
        registry = EngineRegistry()
        regex = RegexEngine()
        dummy = DummyEngine()
        registry.register(regex)
        registry.register(dummy)
        result = registry.enabled_engines(["regex"])
        assert len(result) == 1
        assert result[0] is regex

    def test_enabled_engines_skips_unknown(self):
        registry = EngineRegistry()
        registry.register(RegexEngine())
        result = registry.enabled_engines(["regex", "nonexistent"])
        assert len(result) == 1
        assert result[0].name == "regex"

    def test_non_protocol_raises_type_error(self):
        registry = EngineRegistry()
        with pytest.raises(TypeError, match="Expected an AnalysisEngine"):
            registry.register("not_an_engine")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# TestCoreEngineIntegration
# ---------------------------------------------------------------------------


class TestCoreEngineIntegration:
    def test_scan_code_tags_findings_with_engine(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        findings = shield.scan_code(VULNERABLE_CODE)
        code_findings = [
            f for f in findings if f.scanner == "code_scanner"
        ]
        assert len(code_findings) > 0
        for f in code_findings:
            assert f.details.get("engine") == "regex"

    def test_list_engines(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        engines = shield.list_engines()
        assert len(engines) == 1
        assert engines[0]["name"] == "regex"
        assert engines[0]["enabled"] is True
        assert "capabilities" in engines[0]

    def test_set_engines(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        result = shield.set_engines(["regex"])
        assert result == ["regex"]
        assert shield.profile.code_scanner.engines == ["regex"]

    def test_set_engines_unknown_raises(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        with pytest.raises(ValueError, match="Unknown engine"):
            shield.set_engines(["nonexistent"])

    def test_status_includes_engines(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        status = shield.status()
        assert "engines" in status
        assert len(status["engines"]) == 1
        assert status["engines"][0]["name"] == "regex"

    def test_scan_code_engines_override(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        findings = shield.scan_code(VULNERABLE_CODE, engines=["regex"])
        code_findings = [
            f for f in findings if f.scanner == "code_scanner"
        ]
        assert len(code_findings) > 0

    def test_custom_engine_registration_and_usage(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        shield.register_engine(DummyEngine())
        shield.set_engines(["dummy"])
        findings = shield.scan_code(CLEAN_CODE)
        # Dummy engine produces a finding even for clean code
        dummy_findings = [
            f for f in findings if f.details.get("engine") == "dummy"
        ]
        assert len(dummy_findings) == 1
        assert dummy_findings[0].message == "Dummy finding"
