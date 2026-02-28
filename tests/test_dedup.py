"""Tests for finding deduplication (Phase 3A).

NOTE: This file creates Finding objects with intentional vulnerability pattern
strings as test data. No vulnerable code is executed.
"""

from guardianshield.dedup import DedupResult, FindingDeduplicator, _fingerprint
from guardianshield.findings import Finding, FindingType, Severity

# -- Helpers ------------------------------------------------------------------

def _make_finding(
    file_path="app.py",
    line_number=1,
    finding_type=FindingType.SQL_INJECTION,
    pattern_name="test_pattern",
    matched_text="match",
    message="test",
    severity=Severity.HIGH,
):
    return Finding(
        finding_type=finding_type,
        severity=severity,
        message=message,
        matched_text=matched_text,
        line_number=line_number,
        file_path=file_path,
        scanner="code_scanner",
        metadata={"pattern_name": pattern_name},
    )


# -- _fingerprint tests ------------------------------------------------------

class TestFingerprint:
    def test_same_finding_produces_same_fingerprint(self):
        f1 = _make_finding()
        f2 = _make_finding()
        assert _fingerprint(f1) == _fingerprint(f2)

    def test_different_file_path_different_fingerprint(self):
        f1 = _make_finding(file_path="a.py")
        f2 = _make_finding(file_path="b.py")
        assert _fingerprint(f1) != _fingerprint(f2)

    def test_different_line_number_different_fingerprint(self):
        f1 = _make_finding(line_number=1)
        f2 = _make_finding(line_number=2)
        assert _fingerprint(f1) != _fingerprint(f2)

    def test_different_finding_type_different_fingerprint(self):
        f1 = _make_finding(finding_type=FindingType.SQL_INJECTION)
        f2 = _make_finding(finding_type=FindingType.SECRET)
        assert _fingerprint(f1) != _fingerprint(f2)

    def test_different_pattern_name_different_fingerprint(self):
        f1 = _make_finding(pattern_name="sql_injection")
        f2 = _make_finding(pattern_name="xss")
        assert _fingerprint(f1) != _fingerprint(f2)

    def test_different_matched_text_different_fingerprint(self):
        f1 = _make_finding(matched_text="foo")
        f2 = _make_finding(matched_text="bar")
        assert _fingerprint(f1) != _fingerprint(f2)

    def test_fingerprint_is_hex_string(self):
        fp = _fingerprint(_make_finding())
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_ignores_severity_and_message(self):
        f1 = _make_finding(severity=Severity.HIGH, message="msg1")
        f2 = _make_finding(severity=Severity.LOW, message="msg2")
        assert _fingerprint(f1) == _fingerprint(f2)

    def test_fingerprint_handles_none_file_path(self):
        f = _make_finding(file_path=None)
        fp = _fingerprint(f)
        assert isinstance(fp, str) and len(fp) == 16

    def test_missing_pattern_name_uses_empty_string(self):
        f = _make_finding()
        f.metadata = {}
        fp = _fingerprint(f)
        assert isinstance(fp, str) and len(fp) == 16


# -- DedupResult tests -------------------------------------------------------

class TestDedupResult:
    def test_default_fields(self):
        r = DedupResult()
        assert len(r.scan_id) == 12
        assert r.new == []
        assert r.unchanged == []
        assert r.removed == []
        assert r.all_findings == []

    def test_to_dict_counts(self):
        f1 = _make_finding(matched_text="a")
        f2 = _make_finding(matched_text="b")
        r = DedupResult(
            new=[f1],
            unchanged=[f2],
            removed=["abcd1234"],
            all_findings=[f1, f2],
        )
        d = r.to_dict()
        assert d["new_count"] == 1
        assert d["unchanged_count"] == 1
        assert d["removed_count"] == 1
        assert d["total"] == 2
        assert len(d["new"]) == 1
        assert d["removed_fingerprints"] == ["abcd1234"]

    def test_scan_id_is_unique(self):
        r1 = DedupResult()
        r2 = DedupResult()
        assert r1.scan_id != r2.scan_id


# -- FindingDeduplicator tests -----------------------------------------------

class TestFindingDeduplicator:
    def test_first_scan_all_new(self):
        dedup = FindingDeduplicator()
        findings = [_make_finding(line_number=i) for i in range(3)]
        result = dedup.deduplicate(findings)
        assert len(result.new) == 3
        assert len(result.unchanged) == 0
        assert len(result.removed) == 0
        assert result.all_findings == findings

    def test_second_scan_identical_all_unchanged(self):
        dedup = FindingDeduplicator()
        findings = [_make_finding(line_number=i) for i in range(3)]
        dedup.deduplicate(findings)
        result = dedup.deduplicate(findings)
        assert len(result.new) == 0
        assert len(result.unchanged) == 3
        assert len(result.removed) == 0

    def test_new_finding_detected(self):
        dedup = FindingDeduplicator()
        original = [_make_finding(line_number=1)]
        dedup.deduplicate(original)

        updated = [*original, _make_finding(line_number=2)]
        result = dedup.deduplicate(updated)
        assert len(result.new) == 1
        assert result.new[0].line_number == 2
        assert len(result.unchanged) == 1

    def test_removed_finding_detected(self):
        dedup = FindingDeduplicator()
        findings = [_make_finding(line_number=i) for i in range(3)]
        dedup.deduplicate(findings)

        fewer = [_make_finding(line_number=0)]
        result = dedup.deduplicate(fewer)
        assert len(result.removed) == 2
        assert len(result.unchanged) == 1
        assert len(result.new) == 0

    def test_mixed_changes(self):
        dedup = FindingDeduplicator()
        scan1 = [
            _make_finding(line_number=1, pattern_name="a"),
            _make_finding(line_number=2, pattern_name="b"),
        ]
        dedup.deduplicate(scan1)

        scan2 = [
            _make_finding(line_number=1, pattern_name="a"),  # unchanged
            _make_finding(line_number=3, pattern_name="c"),  # new
        ]
        result = dedup.deduplicate(scan2)
        assert len(result.unchanged) == 1
        assert len(result.new) == 1
        assert len(result.removed) == 1

    def test_empty_first_scan(self):
        dedup = FindingDeduplicator()
        result = dedup.deduplicate([])
        assert len(result.new) == 0
        assert len(result.unchanged) == 0
        assert len(result.removed) == 0

    def test_empty_second_scan_removes_all(self):
        dedup = FindingDeduplicator()
        findings = [_make_finding(line_number=i) for i in range(2)]
        dedup.deduplicate(findings)

        result = dedup.deduplicate([])
        assert len(result.new) == 0
        assert len(result.unchanged) == 0
        assert len(result.removed) == 2

    def test_reset_clears_baseline(self):
        dedup = FindingDeduplicator()
        findings = [_make_finding()]
        dedup.deduplicate(findings)
        assert len(dedup.previous_fingerprints) == 1

        dedup.reset()
        assert len(dedup.previous_fingerprints) == 0

        result = dedup.deduplicate(findings)
        assert len(result.new) == 1

    def test_previous_fingerprints_property(self):
        dedup = FindingDeduplicator()
        assert dedup.previous_fingerprints == set()

        findings = [_make_finding(line_number=1), _make_finding(line_number=2)]
        dedup.deduplicate(findings)
        assert len(dedup.previous_fingerprints) == 2

    def test_duplicate_findings_in_single_scan(self):
        """Two identical findings should collapse to one fingerprint."""
        dedup = FindingDeduplicator()
        f1 = _make_finding()
        f2 = _make_finding()  # same fingerprint
        result = dedup.deduplicate([f1, f2])
        # The dict will keep the last one, so only 1 unique fingerprint
        assert len(result.new) == 1
        # all_findings keeps original list
        assert len(result.all_findings) == 2

    def test_scan_id_changes_each_call(self):
        dedup = FindingDeduplicator()
        r1 = dedup.deduplicate([])
        r2 = dedup.deduplicate([])
        assert r1.scan_id != r2.scan_id

    def test_removed_fingerprints_are_sorted(self):
        dedup = FindingDeduplicator()
        findings = [_make_finding(line_number=i, pattern_name=f"p{i}") for i in range(5)]
        dedup.deduplicate(findings)
        result = dedup.deduplicate([])
        assert result.removed == sorted(result.removed)
