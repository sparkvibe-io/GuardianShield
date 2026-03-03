"""Tests for guardianshield.baseline — baseline / delta scanning."""

from __future__ import annotations

import json
import os

import pytest

from guardianshield.baseline import (
    _BASELINE_VERSION,
    _DEFAULT_PATH,
    BaselineResult,
    filter_baseline_findings,
    load_baseline,
    save_baseline,
)
from guardianshield.dedup import _fingerprint
from guardianshield.findings import Finding, FindingType, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    *,
    line: int = 1,
    text: str = "secret",
    ftype: FindingType = FindingType.SECRET,
    file_path: str = "app.py",
    pattern_name: str = "hardcoded_secret",
) -> Finding:
    """Create a minimal Finding with distinct fingerprint inputs."""
    return Finding(
        finding_type=ftype,
        severity=Severity.HIGH,
        message=f"Found {ftype.value} at line {line}",
        matched_text=text,
        line_number=line,
        file_path=file_path,
        scanner="test",
        metadata={"pattern_name": pattern_name},
    )


def _make_three_findings() -> list[Finding]:
    """Return three findings with unique fingerprints."""
    return [
        _make_finding(line=1, text="password123", ftype=FindingType.SECRET),
        _make_finding(line=10, text="SELECT *", ftype=FindingType.SQL_INJECTION, pattern_name="sql_query"),
        _make_finding(line=20, text="dangerous_call", ftype=FindingType.COMMAND_INJECTION, pattern_name="cmd_call"),
    ]


# ---------------------------------------------------------------------------
# TestBaselineResult
# ---------------------------------------------------------------------------

class TestBaselineResult:
    """Tests for the BaselineResult dataclass."""

    def test_default_fields(self):
        result = BaselineResult()
        assert result.new == []
        assert result.unchanged == []
        assert result.fixed == []

    def test_fields_populated(self):
        f = _make_finding()
        result = BaselineResult(new=[f], unchanged=[], fixed=["abc123"])
        assert len(result.new) == 1
        assert result.new[0] is f
        assert result.fixed == ["abc123"]


# ---------------------------------------------------------------------------
# TestSaveBaseline
# ---------------------------------------------------------------------------

class TestSaveBaseline:
    """Tests for save_baseline()."""

    def test_creates_valid_json_file(self, tmp_path):
        findings = _make_three_findings()
        path = str(tmp_path / "baseline.json")
        save_baseline(findings, path=path)

        with open(path) as f:
            data = json.load(f)

        assert isinstance(data, dict)

    def test_correct_fingerprint_count(self, tmp_path):
        findings = _make_three_findings()
        path = str(tmp_path / "baseline.json")
        result = save_baseline(findings, path=path)

        assert result["fingerprints"] == 3
        assert result["path"] == path

    def test_default_path_when_none(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        findings = [_make_finding()]
        result = save_baseline(findings, path=None)

        assert result["path"] == _DEFAULT_PATH
        assert os.path.exists(tmp_path / _DEFAULT_PATH)

    def test_custom_path_with_subdirectory(self, tmp_path):
        path = str(tmp_path / "sub" / "dir" / "baseline.json")
        save_baseline([_make_finding()], path=path)

        assert os.path.exists(path)

    def test_empty_findings_list(self, tmp_path):
        path = str(tmp_path / "baseline.json")
        result = save_baseline([], path=path)

        assert result["fingerprints"] == 0
        with open(path) as f:
            data = json.load(f)
        assert data["fingerprints"] == []

    def test_file_contains_required_keys(self, tmp_path):
        path = str(tmp_path / "baseline.json")
        save_baseline([_make_finding()], path=path)

        with open(path) as f:
            data = json.load(f)

        assert "version" in data
        assert "created_at" in data
        assert "tool_version" in data
        assert "fingerprints" in data

    def test_version_is_correct(self, tmp_path):
        path = str(tmp_path / "baseline.json")
        save_baseline([_make_finding()], path=path)

        with open(path) as f:
            data = json.load(f)

        assert data["version"] == _BASELINE_VERSION

    def test_tool_version_matches_package(self, tmp_path):
        from guardianshield import __version__

        path = str(tmp_path / "baseline.json")
        save_baseline([_make_finding()], path=path)

        with open(path) as f:
            data = json.load(f)

        assert data["tool_version"] == __version__

    def test_fingerprints_are_strings(self, tmp_path):
        path = str(tmp_path / "baseline.json")
        save_baseline(_make_three_findings(), path=path)

        with open(path) as f:
            data = json.load(f)

        for fp in data["fingerprints"]:
            assert isinstance(fp, str)
            assert len(fp) > 0

    def test_fingerprints_match_dedup(self, tmp_path):
        findings = _make_three_findings()
        path = str(tmp_path / "baseline.json")
        save_baseline(findings, path=path)

        with open(path) as f:
            data = json.load(f)

        expected = [_fingerprint(f) for f in findings]
        assert data["fingerprints"] == expected


# ---------------------------------------------------------------------------
# TestLoadBaseline
# ---------------------------------------------------------------------------

class TestLoadBaseline:
    """Tests for load_baseline()."""

    def test_valid_file_returns_set(self, tmp_path):
        findings = _make_three_findings()
        path = str(tmp_path / "baseline.json")
        save_baseline(findings, path=path)

        result = load_baseline(path=path)

        assert isinstance(result, set)
        assert len(result) == 3

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_baseline(path="/nonexistent/path/baseline.json")

    def test_corrupt_json_non_dict(self, tmp_path):
        path = str(tmp_path / "bad.json")
        with open(path, "w") as f:
            json.dump([1, 2, 3], f)

        with pytest.raises(ValueError, match="expected JSON object"):
            load_baseline(path=path)

    def test_wrong_version(self, tmp_path):
        path = str(tmp_path / "bad.json")
        with open(path, "w") as f:
            json.dump({"version": "99.0", "fingerprints": []}, f)

        with pytest.raises(ValueError, match="Unsupported baseline version"):
            load_baseline(path=path)

    def test_missing_version(self, tmp_path):
        path = str(tmp_path / "bad.json")
        with open(path, "w") as f:
            json.dump({"fingerprints": []}, f)

        with pytest.raises(ValueError, match="Unsupported baseline version"):
            load_baseline(path=path)

    def test_empty_fingerprints_returns_empty_set(self, tmp_path):
        path = str(tmp_path / "baseline.json")
        with open(path, "w") as f:
            json.dump({"version": _BASELINE_VERSION, "fingerprints": []}, f)

        result = load_baseline(path=path)
        assert result == set()

    def test_missing_fingerprints_key_returns_empty_set(self, tmp_path):
        path = str(tmp_path / "baseline.json")
        with open(path, "w") as f:
            json.dump({"version": _BASELINE_VERSION}, f)

        result = load_baseline(path=path)
        assert result == set()

    def test_invalid_fingerprints_type(self, tmp_path):
        path = str(tmp_path / "bad.json")
        with open(path, "w") as f:
            json.dump({"version": _BASELINE_VERSION, "fingerprints": "not-a-list"}, f)

        with pytest.raises(ValueError, match="must be a list"):
            load_baseline(path=path)

    def test_default_path(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        findings = [_make_finding()]
        save_baseline(findings, path=None)

        result = load_baseline(path=None)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# TestFilterBaseline
# ---------------------------------------------------------------------------

class TestFilterBaseline:
    """Tests for filter_baseline_findings()."""

    def test_all_new_with_empty_baseline(self):
        findings = _make_three_findings()
        result = filter_baseline_findings(findings, set())

        assert len(result.new) == 3
        assert len(result.unchanged) == 0
        assert len(result.fixed) == 0

    def test_all_unchanged_when_all_in_baseline(self):
        findings = _make_three_findings()
        baseline = {_fingerprint(f) for f in findings}

        result = filter_baseline_findings(findings, baseline)

        assert len(result.new) == 0
        assert len(result.unchanged) == 3
        assert len(result.fixed) == 0

    def test_all_fixed_with_empty_findings(self):
        baseline = {"fp_aaa", "fp_bbb", "fp_ccc"}
        result = filter_baseline_findings([], baseline)

        assert len(result.new) == 0
        assert len(result.unchanged) == 0
        assert len(result.fixed) == 3
        assert result.fixed == sorted(baseline)

    def test_mixed_new_unchanged_fixed(self):
        f1 = _make_finding(line=1, text="old_secret")
        f2 = _make_finding(line=2, text="new_vuln", ftype=FindingType.XSS, pattern_name="xss_reflect")
        f3 = _make_finding(line=3, text="another_old", ftype=FindingType.SQL_INJECTION, pattern_name="sql_old")

        # Baseline has f1 and f3's fingerprints, plus one extra (removed)
        baseline = {_fingerprint(f1), _fingerprint(f3), "removed_fp"}

        # Current scan has f1 (unchanged) and f2 (new), f3 is gone
        result = filter_baseline_findings([f1, f2], baseline)

        assert len(result.new) == 1
        assert result.new[0] is f2
        assert len(result.unchanged) == 1
        assert result.unchanged[0] is f1
        assert "removed_fp" in result.fixed
        assert _fingerprint(f3) in result.fixed

    def test_empty_findings_empty_baseline(self):
        result = filter_baseline_findings([], set())

        assert result.new == []
        assert result.unchanged == []
        assert result.fixed == []

    def test_fixed_are_sorted(self):
        baseline = {"zzz_fp", "aaa_fp", "mmm_fp"}
        result = filter_baseline_findings([], baseline)

        assert result.fixed == ["aaa_fp", "mmm_fp", "zzz_fp"]

    def test_duplicate_findings_handled(self):
        f1 = _make_finding(line=1, text="dup")
        # Same finding twice in the list
        result = filter_baseline_findings([f1, f1], set())

        # Both appear in new (we don't dedup the findings list itself)
        assert len(result.new) == 2

    def test_findings_with_same_fingerprint_in_baseline(self):
        f1 = _make_finding(line=1, text="match")
        baseline = {_fingerprint(f1)}

        result = filter_baseline_findings([f1], baseline)

        assert len(result.unchanged) == 1
        assert len(result.new) == 0
        assert len(result.fixed) == 0


# ---------------------------------------------------------------------------
# TestRoundTrip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    """End-to-end round-trip tests: save -> load -> filter."""

    def test_same_findings_all_unchanged(self, tmp_path):
        findings = _make_three_findings()
        path = str(tmp_path / "baseline.json")

        save_baseline(findings, path=path)
        baseline = load_baseline(path=path)
        result = filter_baseline_findings(findings, baseline)

        assert len(result.new) == 0
        assert len(result.unchanged) == 3
        assert len(result.fixed) == 0

    def test_new_finding_detected(self, tmp_path):
        original = _make_three_findings()
        path = str(tmp_path / "baseline.json")

        save_baseline(original, path=path)
        baseline = load_baseline(path=path)

        new_finding = _make_finding(line=99, text="brand_new_vuln", ftype=FindingType.XSS, pattern_name="xss_new")
        current = [*original, new_finding]

        result = filter_baseline_findings(current, baseline)

        assert len(result.new) == 1
        assert result.new[0] is new_finding
        assert len(result.unchanged) == 3
        assert len(result.fixed) == 0

    def test_removed_finding_detected(self, tmp_path):
        original = _make_three_findings()
        path = str(tmp_path / "baseline.json")

        save_baseline(original, path=path)
        baseline = load_baseline(path=path)

        # Remove first finding
        removed_fp = _fingerprint(original[0])
        current = original[1:]

        result = filter_baseline_findings(current, baseline)

        assert len(result.new) == 0
        assert len(result.unchanged) == 2
        assert len(result.fixed) == 1
        assert removed_fp in result.fixed

    def test_complete_replacement(self, tmp_path):
        original = _make_three_findings()
        path = str(tmp_path / "baseline.json")

        save_baseline(original, path=path)
        baseline = load_baseline(path=path)

        # Completely different findings
        new_findings = [
            _make_finding(line=100, text="entirely_new_1", pattern_name="new_p1"),
            _make_finding(line=200, text="entirely_new_2", pattern_name="new_p2"),
        ]

        result = filter_baseline_findings(new_findings, baseline)

        assert len(result.new) == 2
        assert len(result.unchanged) == 0
        assert len(result.fixed) == 3

    def test_empty_baseline_all_new(self, tmp_path):
        path = str(tmp_path / "baseline.json")

        save_baseline([], path=path)
        baseline = load_baseline(path=path)

        findings = _make_three_findings()
        result = filter_baseline_findings(findings, baseline)

        assert len(result.new) == 3
        assert len(result.unchanged) == 0
        assert len(result.fixed) == 0
