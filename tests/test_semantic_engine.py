"""Tests for the SemanticEngine — structure-aware confidence adjustment."""

from __future__ import annotations

import pytest

from guardianshield import GuardianShield
from guardianshield.engines import AnalysisEngine
from guardianshield.findings import Finding, FindingType, Severity
from guardianshield.semantic_engine import (
    SemanticEngine,
    _find_called_functions,
    _find_dead_code_lines,
    _find_defined_functions,
    _find_js_calls,
    _find_js_functions,
    _find_try_except_ranges,
    _find_unused_import_lines,
    is_test_file,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    line: int = 1,
    confidence: float = 0.8,
    finding_type: FindingType = FindingType.SQL_INJECTION,
    engine: str = "regex",
    file_path: str | None = None,
) -> Finding:
    f = Finding(
        finding_type=finding_type,
        severity=Severity.HIGH,
        message="test finding",
        matched_text="test",
        line_number=line,
        scanner="code_scanner",
        confidence=confidence,
        file_path=file_path,
    )
    f.details["engine"] = engine
    return f


# ===================================================================
# TestIsTestFile
# ===================================================================


class TestIsTestFile:
    def test_none_path(self):
        assert is_test_file(None) is False

    def test_python_test_prefix(self):
        assert is_test_file("test_scanner.py") is True

    def test_python_test_suffix(self):
        assert is_test_file("scanner_test.py") is True

    def test_go_test_suffix(self):
        assert is_test_file("handler_test.go") is True

    def test_js_test_dot(self):
        assert is_test_file("utils.test.js") is True

    def test_ts_spec_dot(self):
        assert is_test_file("service.spec.ts") is True

    def test_ruby_spec_suffix(self):
        assert is_test_file("model_spec.rb") is True

    def test_tests_directory(self):
        assert is_test_file("tests/test_core.py") is True

    def test_dunder_tests_directory(self):
        assert is_test_file("src/__tests__/App.test.tsx") is True

    def test_conftest(self):
        assert is_test_file("tests/conftest.py") is True

    def test_production_file(self):
        assert is_test_file("src/guardianshield/scanner.py") is False

    def test_test_helper_rb(self):
        assert is_test_file("test_helper.rb") is True

    def test_spec_directory(self):
        assert is_test_file("spec/models/user_spec.rb") is True

    def test_tsx_test(self):
        assert is_test_file("Component.test.tsx") is True


# ===================================================================
# TestDeadCodeDetection
# ===================================================================


class TestDeadCodeDetection:
    def test_after_return(self):
        code = "def foo():\n    return 1\n    x = 2\n"
        dead = _find_dead_code_lines(code)
        assert 3 in dead

    def test_after_raise(self):
        code = "def foo():\n    raise ValueError()\n    x = 2\n"
        dead = _find_dead_code_lines(code)
        assert 3 in dead

    def test_after_break(self):
        code = "for i in range(10):\n    break\n    print(i)\n"
        dead = _find_dead_code_lines(code)
        assert 3 in dead

    def test_after_continue(self):
        code = "for i in range(10):\n    continue\n    print(i)\n"
        dead = _find_dead_code_lines(code)
        assert 3 in dead

    def test_no_dead_code(self):
        code = "def foo():\n    x = 1\n    return x\n"
        dead = _find_dead_code_lines(code)
        assert len(dead) == 0

    def test_syntax_error_graceful(self):
        code = "def foo(:\n"
        dead = _find_dead_code_lines(code)
        assert dead == set()

    def test_multiple_dead_lines(self):
        code = "def foo():\n    return 1\n    x = 2\n    y = 3\n"
        dead = _find_dead_code_lines(code)
        assert 3 in dead
        assert 4 in dead


# ===================================================================
# TestExceptionHandler
# ===================================================================


class TestExceptionHandler:
    def test_basic_except(self):
        code = (
            "try:\n"
            "    x = 1\n"
            "except ValueError:\n"
            "    y = 2\n"
        )
        ranges = _find_try_except_ranges(code)
        assert len(ranges) == 1
        start, end, names = ranges[0]
        assert start <= 4 <= end
        assert "ValueError" in names

    def test_bare_except(self):
        code = (
            "try:\n"
            "    x = 1\n"
            "except:\n"
            "    y = 2\n"
        )
        ranges = _find_try_except_ranges(code)
        assert len(ranges) == 1
        assert ranges[0][2] == []

    def test_multiple_exceptions(self):
        code = (
            "try:\n"
            "    x = 1\n"
            "except (ValueError, TypeError):\n"
            "    y = 2\n"
        )
        ranges = _find_try_except_ranges(code)
        assert len(ranges) == 1
        assert "ValueError" in ranges[0][2]
        assert "TypeError" in ranges[0][2]

    def test_line_outside_handler(self):
        code = (
            "x = 1\n"
            "try:\n"
            "    y = 2\n"
            "except:\n"
            "    z = 3\n"
        )
        ranges = _find_try_except_ranges(code)
        assert len(ranges) == 1
        start, end, _ = ranges[0]
        assert not (start <= 1 <= end)

    def test_syntax_error_graceful(self):
        assert _find_try_except_ranges("try:\n  except") == []


# ===================================================================
# TestUncalledFunction
# ===================================================================


class TestUncalledFunction:
    def test_defined_not_called(self):
        code = "def foo():\n    return 1\n\nx = 42\n"
        defined = _find_defined_functions(code)
        called = _find_called_functions(code)
        assert "foo" in defined
        assert "foo" not in called

    def test_defined_and_called(self):
        code = "def foo():\n    return 1\n\nfoo()\n"
        called = _find_called_functions(code)
        assert "foo" in called

    def test_method_call(self):
        code = "obj.method()\n"
        called = _find_called_functions(code)
        assert "method" in called

    def test_syntax_error_defined(self):
        assert _find_defined_functions("def (") == {}

    def test_syntax_error_called(self):
        assert _find_called_functions("foo(.") == set()

    def test_async_function(self):
        code = "async def handler():\n    await something()\n"
        defined = _find_defined_functions(code)
        assert "handler" in defined


# ===================================================================
# TestUnusedImport
# ===================================================================


class TestUnusedImport:
    def test_unused_import(self):
        code = "import os\n\nx = 42\n"
        unused = _find_unused_import_lines(code)
        assert 1 in unused

    def test_used_import(self):
        code = "import os\n\nos.path.exists('.')\n"
        unused = _find_unused_import_lines(code)
        assert len(unused) == 0

    def test_from_import_unused(self):
        code = "from os import path\n\nx = 42\n"
        unused = _find_unused_import_lines(code)
        assert 1 in unused

    def test_from_import_used(self):
        code = "from os import path\n\npath.exists('.')\n"
        unused = _find_unused_import_lines(code)
        assert len(unused) == 0

    def test_syntax_error_graceful(self):
        assert _find_unused_import_lines("import (") == set()

    def test_star_import_ignored(self):
        code = "from os import *\n\nx = 42\n"
        unused = _find_unused_import_lines(code)
        assert len(unused) == 0


# ===================================================================
# TestJSHeuristics
# ===================================================================


class TestJSHeuristics:
    def test_uncalled_js_function(self):
        code = "function unused() {\n  return 1;\n}\n\nconst x = 42;\n"
        funcs = _find_js_functions(code)
        calls = _find_js_calls(code)
        names = {f[0] for f in funcs}
        assert "unused" in names
        assert "unused" not in calls

    def test_exported_function_not_flagged(self):
        code = "export function handler() {\n  return 1;\n}\n"
        funcs = _find_js_functions(code)
        assert len(funcs) == 1
        assert funcs[0][3] is True  # is_exported

    def test_called_function(self):
        code = "function helper() {\n  return 1;\n}\n\nhelper();\n"
        calls = _find_js_calls(code)
        assert "helper" in calls

    def test_arrow_function(self):
        code = "const add = (a, b) => {\n  return a + b;\n}\n"
        funcs = _find_js_functions(code)
        names = {f[0] for f in funcs}
        assert "add" in names


# ===================================================================
# TestAdjustFindings
# ===================================================================


class TestAdjustFindings:
    def setup_method(self):
        self.engine = SemanticEngine()

    def test_test_file_reduces_confidence(self):
        findings = [_make_finding(confidence=0.8, file_path="tests/test_foo.py")]
        self.engine.adjust_findings(
            findings, "x = 1\n", language="python", file_path="tests/test_foo.py"
        )
        assert findings[0].confidence == pytest.approx(0.5)
        assert findings[0].details["semantic_adjusted"] is True

    def test_dead_code_reduces_confidence(self):
        code = "def foo():\n    return 1\n    x = dangerous()\n\nfoo()\n"
        findings = [_make_finding(line=3, confidence=0.8)]
        self.engine.adjust_findings(findings, code, language="python")
        assert findings[0].confidence == pytest.approx(0.5)

    def test_exception_handler_reduces_confidence(self):
        code = (
            "try:\n"
            "    x = 1\n"
            "except ValueError:\n"
            "    y = dangerous()\n"
        )
        findings = [_make_finding(line=4, confidence=0.8)]
        self.engine.adjust_findings(findings, code, language="python")
        assert findings[0].confidence == pytest.approx(0.65)

    def test_uncalled_function_reduces_confidence(self):
        code = "def unused():\n    x = dangerous()\n\ny = 42\n"
        findings = [_make_finding(line=2, confidence=0.8)]
        self.engine.adjust_findings(findings, code, language="python")
        assert findings[0].confidence == pytest.approx(0.6)

    def test_cumulative_adjustments(self):
        # test file (-0.3) + uncalled function (-0.2) = -0.5
        code = "def unused():\n    x = dangerous()\n"
        findings = [
            _make_finding(line=2, confidence=0.8, file_path="tests/test_foo.py")
        ]
        self.engine.adjust_findings(
            findings, code, language="python", file_path="tests/test_foo.py"
        )
        assert findings[0].confidence == pytest.approx(0.3)

    def test_floor_at_point_one(self):
        # test file (-0.3) + dead code (-0.3) + uncalled (-0.2) = -0.8
        code = "def unused():\n    return 1\n    x = dangerous()\n"
        findings = [
            _make_finding(line=3, confidence=0.5, file_path="tests/test_foo.py")
        ]
        self.engine.adjust_findings(
            findings, code, language="python", file_path="tests/test_foo.py"
        )
        assert findings[0].confidence == pytest.approx(0.1)

    def test_details_recorded(self):
        findings = [_make_finding(confidence=0.8, file_path="tests/test_foo.py")]
        self.engine.adjust_findings(
            findings, "x = 1\n", language="python", file_path="tests/test_foo.py"
        )
        adj = findings[0].details["semantic_adjustments"]
        assert len(adj) == 1
        assert adj[0]["reason"] == "test_file"
        assert adj[0]["delta"] == -0.3

    def test_no_adjustment_on_normal_code(self):
        code = "x = dangerous()\n"
        findings = [_make_finding(line=1, confidence=0.8)]
        self.engine.adjust_findings(findings, code, language="python")
        assert findings[0].confidence == 0.8
        assert "semantic_adjusted" not in findings[0].details

    def test_unused_import_reduces_confidence(self):
        code = "import os\n\nx = 42\n"
        findings = [_make_finding(line=1, confidence=0.8)]
        self.engine.adjust_findings(findings, code, language="python")
        assert findings[0].confidence == pytest.approx(0.55)

    def test_js_uncalled_reduces_confidence(self):
        code = "function unused() {\n  dangerous();\n}\n\nconst x = 42;\n"
        findings = [_make_finding(line=2, confidence=0.8)]
        self.engine.adjust_findings(findings, code, language="javascript")
        assert findings[0].confidence == pytest.approx(0.6)

    def test_empty_findings_no_crash(self):
        result = self.engine.adjust_findings([], "x = 1\n", language="python")
        assert result == []

    def test_none_confidence_defaults_to_half(self):
        findings = [_make_finding(confidence=0.8, file_path="tests/test_foo.py")]
        findings[0].confidence = None
        self.engine.adjust_findings(
            findings, "x = 1\n", language="python", file_path="tests/test_foo.py"
        )
        # Default 0.5 - 0.3 = 0.2
        assert findings[0].confidence == pytest.approx(0.2)


# ===================================================================
# TestSemanticEngineProtocol
# ===================================================================


class TestSemanticEngineProtocol:
    def test_isinstance_analysis_engine(self):
        engine = SemanticEngine()
        assert isinstance(engine, AnalysisEngine)

    def test_name(self):
        assert SemanticEngine().name == "semantic"

    def test_analyze_returns_empty(self):
        engine = SemanticEngine()
        result = engine.analyze("x = dangerous()\n", language="python")
        assert result == []

    def test_capabilities_keys(self):
        caps = SemanticEngine().capabilities()
        assert caps["analysis_type"] == "confidence_adjustment"
        assert caps["semantic"] is True
        assert caps["data_flow"] is False

    def test_capabilities_languages(self):
        caps = SemanticEngine().capabilities()
        assert "python" in caps["supported_languages"]
        assert "javascript" in caps["supported_languages"]

    def test_speed(self):
        caps = SemanticEngine().capabilities()
        assert caps["speed"] == "fast"


# ===================================================================
# TestCoreIntegration
# ===================================================================


class TestCoreIntegration:
    def test_semantic_engine_registered(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        names = shield.engine_registry.available_names
        assert "semantic" in names

    def test_list_engines_shows_semantic(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        engines = shield.list_engines()
        names = {e["name"] for e in engines}
        assert "semantic" in names
        sem = next(e for e in engines if e["name"] == "semantic")
        # Semantic is registered but NOT in default engines.
        assert sem["enabled"] is False

    def test_set_engines_with_semantic(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        result = shield.set_engines(["regex", "semantic"])
        assert "semantic" in result

    def test_scan_adjusts_test_file(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        shield.set_engines(["regex", "semantic"])
        code = 'password = "hunter2"\n'
        findings = shield.scan_code(
            code, file_path="tests/test_app.py", language="python"
        )
        adjusted = [f for f in findings if f.details.get("semantic_adjusted")]
        if adjusted:
            assert all(f.confidence < 0.8 for f in adjusted)

    def test_status_includes_engine(self, tmp_path):
        db = str(tmp_path / "audit.db")
        shield = GuardianShield(audit_path=db)
        status = shield.status()
        engine_names = {e["name"] for e in status["engines"]}
        assert "semantic" in engine_names
