"""Tests for the SQLite audit log module."""

from __future__ import annotations

import os

from guardianshield.audit import AuditLog
from guardianshield.findings import Finding, FindingType, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    finding_type: FindingType = FindingType.SECRET,
    severity: Severity = Severity.HIGH,
    message: str = "test finding",
    **kwargs,
) -> Finding:
    return Finding(finding_type=finding_type, severity=severity, message=message, **kwargs)


def _db_path(tmp_path) -> str:  # noqa: ANN001
    return str(tmp_path / "audit.db")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_log_scan_returns_audit_id(tmp_path):
    log = AuditLog(db_path=_db_path(tmp_path))
    try:
        findings = [_make_finding()]
        audit_id = log.log_scan(
            scan_type="code",
            profile="default",
            input_hash="abc123",
            findings=findings,
        )
        assert isinstance(audit_id, int)
        assert audit_id >= 1
    finally:
        log.close()


def test_query_log_returns_logged_entries(tmp_path):
    log = AuditLog(db_path=_db_path(tmp_path))
    try:
        log.log_scan("code", "default", "aaa", [_make_finding()])
        log.log_scan("input", "strict", "bbb", [])

        entries = log.query_log()
        assert len(entries) == 2
        # Newest first
        assert entries[0]["scan_type"] == "input"
        assert entries[1]["scan_type"] == "code"
    finally:
        log.close()


def test_query_log_with_scan_type_filter(tmp_path):
    log = AuditLog(db_path=_db_path(tmp_path))
    try:
        log.log_scan("code", "default", "aaa", [_make_finding()])
        log.log_scan("input", "default", "bbb", [])
        log.log_scan("code", "default", "ccc", [_make_finding()])

        code_entries = log.query_log(scan_type="code")
        assert len(code_entries) == 2
        assert all(e["scan_type"] == "code" for e in code_entries)

        input_entries = log.query_log(scan_type="input")
        assert len(input_entries) == 1
        assert input_entries[0]["scan_type"] == "input"
    finally:
        log.close()


def test_get_findings_returns_findings(tmp_path):
    log = AuditLog(db_path=_db_path(tmp_path))
    try:
        findings = [
            _make_finding(message="finding A"),
            _make_finding(message="finding B"),
        ]
        audit_id = log.log_scan("code", "default", "aaa", findings)

        stored = log.get_findings(audit_id=audit_id)
        assert len(stored) == 2
        messages = {f["message"] for f in stored}
        assert messages == {"finding A", "finding B"}
    finally:
        log.close()


def test_get_findings_with_finding_type_filter(tmp_path):
    log = AuditLog(db_path=_db_path(tmp_path))
    try:
        findings = [
            _make_finding(finding_type=FindingType.SECRET, message="secret finding"),
            _make_finding(finding_type=FindingType.XSS, message="xss finding"),
        ]
        log.log_scan("code", "default", "aaa", findings)

        secrets = log.get_findings(finding_type="secret")
        assert len(secrets) == 1
        assert secrets[0]["message"] == "secret finding"

        xss = log.get_findings(finding_type="xss")
        assert len(xss) == 1
        assert xss[0]["message"] == "xss finding"
    finally:
        log.close()


def test_get_findings_with_severity_filter(tmp_path):
    log = AuditLog(db_path=_db_path(tmp_path))
    try:
        findings = [
            _make_finding(severity=Severity.CRITICAL, message="critical one"),
            _make_finding(severity=Severity.LOW, message="low one"),
            _make_finding(severity=Severity.CRITICAL, message="critical two"),
        ]
        log.log_scan("code", "default", "aaa", findings)

        critical = log.get_findings(severity="critical")
        assert len(critical) == 2
        assert all(f["severity"] == "critical" for f in critical)

        low = log.get_findings(severity="low")
        assert len(low) == 1
        assert low[0]["message"] == "low one"
    finally:
        log.close()


def test_stats_returns_correct_counts(tmp_path):
    log = AuditLog(db_path=_db_path(tmp_path))
    try:
        log.log_scan("code", "default", "aaa", [
            _make_finding(severity=Severity.HIGH, finding_type=FindingType.SECRET),
            _make_finding(severity=Severity.CRITICAL, finding_type=FindingType.XSS),
        ])
        log.log_scan("input", "strict", "bbb", [
            _make_finding(severity=Severity.HIGH, finding_type=FindingType.PROMPT_INJECTION),
        ])

        s = log.stats()
        assert s["total_scans"] == 2
        assert s["total_findings"] == 3
        assert s["findings_by_severity"]["high"] == 2
        assert s["findings_by_severity"]["critical"] == 1
        assert s["findings_by_type"]["secret"] == 1
        assert s["findings_by_type"]["xss"] == 1
        assert s["findings_by_type"]["prompt_injection"] == 1
        assert s["last_scan_time"] is not None
    finally:
        log.close()


def test_stats_empty_database(tmp_path):
    log = AuditLog(db_path=_db_path(tmp_path))
    try:
        s = log.stats()
        assert s["total_scans"] == 0
        assert s["total_findings"] == 0
        assert s["findings_by_severity"] == {}
        assert s["findings_by_type"] == {}
        assert s["last_scan_time"] is None
    finally:
        log.close()


def test_multiple_scans_and_findings(tmp_path):
    log = AuditLog(db_path=_db_path(tmp_path))
    try:
        id1 = log.log_scan("code", "default", "hash1", [
            _make_finding(finding_type=FindingType.SECRET, severity=Severity.HIGH),
        ])
        id2 = log.log_scan("input", "strict", "hash2", [
            _make_finding(finding_type=FindingType.PROMPT_INJECTION, severity=Severity.CRITICAL),
            _make_finding(finding_type=FindingType.PII_LEAK, severity=Severity.MEDIUM),
        ])
        id3 = log.log_scan("output", "default", "hash3", [
            _make_finding(finding_type=FindingType.PII_LEAK, severity=Severity.LOW),
        ])

        # Verify IDs are sequential
        assert id1 < id2 < id3

        # Verify finding counts in audit_log
        entries = log.query_log()
        assert len(entries) == 3
        counts = {e["scan_type"]: e["finding_count"] for e in entries}
        assert counts["code"] == 1
        assert counts["input"] == 2
        assert counts["output"] == 1

        # Verify findings per audit_id
        assert len(log.get_findings(audit_id=id1)) == 1
        assert len(log.get_findings(audit_id=id2)) == 2
        assert len(log.get_findings(audit_id=id3)) == 1

        # Verify total findings
        all_findings = log.get_findings()
        assert len(all_findings) == 4

        # Stats
        s = log.stats()
        assert s["total_scans"] == 3
        assert s["total_findings"] == 4
    finally:
        log.close()


def test_log_scan_with_metadata(tmp_path):
    log = AuditLog(db_path=_db_path(tmp_path))
    try:
        audit_id = log.log_scan(
            scan_type="secrets",
            profile="default",
            input_hash="deadbeef",
            findings=[],
            metadata={"source": "cli", "version": "0.1.0"},
        )
        entries = log.query_log()
        assert len(entries) == 1
        assert entries[0]["id"] == audit_id
        assert '"source"' in entries[0]["metadata"]
    finally:
        log.close()


def test_finding_fields_stored_correctly(tmp_path):
    log = AuditLog(db_path=_db_path(tmp_path))
    try:
        finding = _make_finding(
            finding_type=FindingType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            message="SQL injection in query",
            matched_text="SELECT * FROM users",
            line_number=42,
            file_path="app/db.py",
            scanner="code_scanner",
        )
        audit_id = log.log_scan("code", "default", "abc123", [finding])

        stored = log.get_findings(audit_id=audit_id)
        assert len(stored) == 1
        f = stored[0]
        assert f["finding_type"] == "sql_injection"
        assert f["severity"] == "critical"
        assert f["message"] == "SQL injection in query"
        assert f["matched_text"] == "SELECT * FROM users"
        assert f["line_number"] == 42
        assert f["file_path"] == "app/db.py"
        assert f["scanner"] == "code_scanner"
        assert f["finding_id"] == finding.finding_id
    finally:
        log.close()


def test_db_directory_created(tmp_path):
    nested = tmp_path / "a" / "b" / "c"
    db_path = str(nested / "audit.db")
    log = AuditLog(db_path=db_path)
    try:
        assert os.path.isdir(str(nested))
        log.log_scan("code", "default", "aaa", [])
        entries = log.query_log()
        assert len(entries) == 1
    finally:
        log.close()
