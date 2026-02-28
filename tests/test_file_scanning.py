"""Tests for file-level scanning (Phase 2B).

NOTE: This file contains intentional vulnerability pattern strings as test
data for the GuardianShield security scanner. No vulnerable code is executed.
"""

import os

import pytest

from guardianshield.core import GuardianShield

# Sample code strings for testing. These contain patterns the scanner detects.
# They are written to temp files and scanned -- never executed.
_PY_VULN = "import random\ntoken = random.randint(0, 999)\n"
_JS_VULN = "obj.__proto__[k] = v;\n"
_PY_CLEAN = 'def hello():\n    return "world"\n'


@pytest.fixture
def shield():
    s = GuardianShield(profile="general", audit_path=":memory:")
    yield s
    s.close()


# -- scan_file ---------------------------------------------------------------

class TestScanFile:
    def test_scan_python_file(self, shield, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(_PY_VULN)
        findings = shield.scan_file(str(f))
        assert len(findings) >= 1
        assert findings[0].file_path == str(f)

    def test_scan_file_auto_detects_language(self, shield, tmp_path):
        f = tmp_path / "app.js"
        f.write_text(_JS_VULN)
        findings = shield.scan_file(str(f))
        patterns = [fi.metadata.get("pattern_name") for fi in findings]
        assert "js_prototype_pollution" in patterns

    def test_scan_file_with_explicit_language(self, shield, tmp_path):
        f = tmp_path / "code.txt"
        f.write_text(_PY_VULN)
        findings = shield.scan_file(str(f), language="python")
        assert len(findings) >= 1

    def test_scan_file_not_found(self, shield):
        with pytest.raises(FileNotFoundError):
            shield.scan_file("/nonexistent/path/file.py")

    def test_scan_file_is_directory(self, shield, tmp_path):
        with pytest.raises(IsADirectoryError):
            shield.scan_file(str(tmp_path))

    def test_scan_file_returns_list(self, shield, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 1\n")
        findings = shield.scan_file(str(f))
        assert isinstance(findings, list)

    def test_scan_file_clean_code_no_code_findings(self, shield, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text(_PY_CLEAN)
        findings = shield.scan_file(str(f))
        code_findings = [fi for fi in findings if fi.scanner == "code_scanner"]
        assert len(code_findings) == 0


# -- scan_directory ----------------------------------------------------------

class TestScanDirectory:
    def _make_project(self, tmp_path):
        """Create a tiny project with mixed file types."""
        (tmp_path / "app.py").write_text(_PY_VULN)
        (tmp_path / "util.py").write_text(_PY_CLEAN)
        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "index.js").write_text(_JS_VULN)
        (sub / "readme.md").write_text("# Hello\n")
        return tmp_path

    def test_scan_directory_finds_vulnerabilities(self, shield, tmp_path):
        self._make_project(tmp_path)
        findings = shield.scan_directory(str(tmp_path))
        scanners = {f.scanner for f in findings}
        assert "code_scanner" in scanners

    def test_scan_directory_respects_extensions_filter(self, shield, tmp_path):
        self._make_project(tmp_path)
        findings = shield.scan_directory(str(tmp_path), extensions=[".py"])
        for f in findings:
            if f.file_path and f.scanner == "code_scanner":
                assert f.file_path.endswith(".py")

    def test_scan_directory_excludes_patterns(self, shield, tmp_path):
        self._make_project(tmp_path)
        findings = shield.scan_directory(str(tmp_path), exclude=["src/*"])
        for f in findings:
            if f.file_path:
                assert "/src/" not in f.file_path

    def test_scan_directory_not_a_directory(self, shield, tmp_path):
        f = tmp_path / "file.py"
        f.write_text("x = 1")
        with pytest.raises(NotADirectoryError):
            shield.scan_directory(str(f))

    def test_scan_directory_empty_returns_empty(self, shield, tmp_path):
        findings = shield.scan_directory(str(tmp_path))
        assert findings == []

    def test_scan_directory_on_progress_callback(self, shield, tmp_path):
        (tmp_path / "a.py").write_text(_PY_VULN)
        (tmp_path / "b.py").write_text(_PY_CLEAN)
        progress_log = []

        def on_progress(fpath, done, total):
            progress_log.append((os.path.basename(fpath), done, total))

        shield.scan_directory(str(tmp_path), on_progress=on_progress)
        assert len(progress_log) == 2
        assert all(total == 2 for _, _, total in progress_log)

    def test_scan_directory_on_finding_callback(self, shield, tmp_path):
        (tmp_path / "vuln.py").write_text(_PY_VULN)
        finding_log = []

        def on_finding(f):
            finding_log.append(f)

        findings = shield.scan_directory(str(tmp_path), on_finding=on_finding)
        assert len(finding_log) == len(findings)

    def test_scan_directory_skips_hidden_dirs(self, shield, tmp_path):
        hidden = tmp_path / ".hidden"
        hidden.mkdir()
        (hidden / "secret.py").write_text(_PY_VULN)
        (tmp_path / "app.py").write_text(_PY_CLEAN)
        findings = shield.scan_directory(str(tmp_path))
        for f in findings:
            if f.file_path:
                assert ".hidden" not in f.file_path

    def test_scan_directory_skips_node_modules(self, shield, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "dep.js").write_text(_JS_VULN)
        (tmp_path / "app.js").write_text("var x = 1;\n")
        findings = shield.scan_directory(str(tmp_path))
        for f in findings:
            if f.file_path:
                assert "node_modules" not in f.file_path

    def test_scan_directory_default_extensions(self, shield, tmp_path):
        (tmp_path / "app.py").write_text(_PY_CLEAN)
        (tmp_path / "data.csv").write_text("a,b,c\n")
        findings = shield.scan_directory(str(tmp_path))
        assert isinstance(findings, list)

    def test_scan_directory_with_project_config_excludes(self, tmp_path):
        from guardianshield.config import ProjectConfig

        config = ProjectConfig(exclude_paths=["vendor/*"])
        s = GuardianShield(
            profile="general", audit_path=":memory:", project_config=config
        )
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        (vendor / "lib.py").write_text(_PY_VULN)
        (tmp_path / "app.py").write_text(_PY_VULN)
        findings = s.scan_directory(str(tmp_path))
        for f in findings:
            if f.file_path:
                assert "vendor" not in f.file_path
        s.close()

    def test_scan_directory_normalizes_extensions(self, shield, tmp_path):
        (tmp_path / "app.py").write_text(_PY_VULN)
        findings = shield.scan_directory(str(tmp_path), extensions=["py"])
        assert len(findings) >= 1
