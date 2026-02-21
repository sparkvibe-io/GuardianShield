"""Tests for findings data models."""

import json

from guardianshield.findings import Finding, FindingType, Severity


def test_severity_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"


def test_finding_type_values():
    assert FindingType.SECRET.value == "secret"
    assert FindingType.SQL_INJECTION.value == "sql_injection"
    assert FindingType.PROMPT_INJECTION.value == "prompt_injection"
    assert FindingType.PII_LEAK.value == "pii_leak"
    assert FindingType.CONTENT_VIOLATION.value == "content_violation"


def test_finding_defaults():
    f = Finding(
        finding_type=FindingType.SECRET,
        severity=Severity.HIGH,
        message="Found a secret",
    )
    assert f.matched_text == ""
    assert f.line_number == 0
    assert f.file_path is None
    assert f.scanner == ""
    assert len(f.finding_id) == 12
    assert f.metadata == {}


def test_finding_to_dict():
    f = Finding(
        finding_type=FindingType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        message="SQL injection detected",
        matched_text="SELECT * FROM users",
        line_number=10,
        file_path="app.py",
        scanner="scanner",
    )
    d = f.to_dict()
    assert d["finding_type"] == "sql_injection"
    assert d["severity"] == "critical"
    assert d["message"] == "SQL injection detected"
    assert d["matched_text"] == "SELECT * FROM users"
    assert d["line_number"] == 10
    assert d["file_path"] == "app.py"


def test_finding_to_json():
    f = Finding(
        finding_type=FindingType.XSS,
        severity=Severity.MEDIUM,
        message="XSS risk",
    )
    j = f.to_json()
    data = json.loads(j)
    assert data["finding_type"] == "xss"
    assert data["severity"] == "medium"


def test_finding_round_trip():
    original = Finding(
        finding_type=FindingType.PII_LEAK,
        severity=Severity.HIGH,
        message="Email found",
        matched_text="***@***.com",
        line_number=5,
        file_path="output.txt",
        scanner="pii",
        metadata={"pii_type": "email"},
    )
    d = original.to_dict()
    restored = Finding.from_dict(d)
    assert restored.finding_type == original.finding_type
    assert restored.severity == original.severity
    assert restored.message == original.message
    assert restored.matched_text == original.matched_text
    assert restored.line_number == original.line_number
    assert restored.file_path == original.file_path
    assert restored.scanner == original.scanner
    assert restored.finding_id == original.finding_id
    assert restored.metadata == original.metadata


def test_finding_json_round_trip():
    original = Finding(
        finding_type=FindingType.SECRET,
        severity=Severity.CRITICAL,
        message="AWS key detected",
        matched_text="AKIA***REDACTED***",
        scanner="secrets",
    )
    j = original.to_json()
    data = json.loads(j)
    restored = Finding.from_dict(data)
    assert restored.finding_type == original.finding_type
    assert restored.severity == original.severity
    assert restored.finding_id == original.finding_id


def test_finding_unique_ids():
    f1 = Finding(finding_type=FindingType.SECRET, severity=Severity.LOW, message="a")
    f2 = Finding(finding_type=FindingType.SECRET, severity=Severity.LOW, message="b")
    assert f1.finding_id != f2.finding_id
