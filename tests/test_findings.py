"""Tests for findings data models."""

import json

from guardianshield.findings import (
    Finding,
    FindingType,
    Range,
    Remediation,
    Severity,
)


# -- Severity & FindingType enums ------------------------------------------

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


def test_dependency_vulnerability_type():
    assert FindingType.DEPENDENCY_VULNERABILITY.value == "dependency_vulnerability"
    assert FindingType("dependency_vulnerability") is FindingType.DEPENDENCY_VULNERABILITY


# -- Range dataclass -------------------------------------------------------

def test_range_creation():
    r = Range(start_line=0, start_col=5, end_line=0, end_col=15)
    assert r.start_line == 0
    assert r.start_col == 5
    assert r.end_line == 0
    assert r.end_col == 15


def test_range_to_lsp():
    r = Range(start_line=3, start_col=10, end_line=3, end_col=25)
    lsp = r.to_lsp()
    assert lsp == {
        "start": {"line": 3, "character": 10},
        "end": {"line": 3, "character": 25},
    }


def test_range_from_lsp():
    lsp = {
        "start": {"line": 7, "character": 0},
        "end": {"line": 7, "character": 42},
    }
    r = Range.from_lsp(lsp)
    assert r.start_line == 7
    assert r.start_col == 0
    assert r.end_line == 7
    assert r.end_col == 42


def test_range_round_trip():
    original = Range(start_line=10, start_col=4, end_line=12, end_col=0)
    restored = Range.from_lsp(original.to_lsp())
    assert restored == original


def test_range_multiline():
    r = Range(start_line=5, start_col=0, end_line=8, end_col=10)
    lsp = r.to_lsp()
    assert lsp["start"]["line"] != lsp["end"]["line"]
    restored = Range.from_lsp(lsp)
    assert restored == r


def test_range_zero_based():
    r = Range(start_line=0, start_col=0, end_line=0, end_col=1)
    lsp = r.to_lsp()
    assert lsp["start"]["line"] == 0
    assert lsp["start"]["character"] == 0


# -- Remediation dataclass -------------------------------------------------

def test_remediation_creation():
    rem = Remediation(
        description="Use parameterized queries",
        before='cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
        after='cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
        auto_fixable=False,
    )
    assert rem.description == "Use parameterized queries"
    assert "user_id" in rem.before
    assert "?" in rem.after
    assert rem.auto_fixable is False


def test_remediation_to_dict():
    rem = Remediation(
        description="Use secrets module",
        before="random.randint(0, 999999)",
        after="secrets.token_hex(16)",
        auto_fixable=True,
    )
    d = rem.to_dict()
    assert d["description"] == "Use secrets module"
    assert d["before"] == "random.randint(0, 999999)"
    assert d["after"] == "secrets.token_hex(16)"
    assert d["auto_fixable"] is True


def test_remediation_to_dict_omits_empty():
    rem = Remediation(description="Avoid dynamic code execution")
    d = rem.to_dict()
    assert "description" in d
    assert "before" not in d
    assert "after" not in d
    assert "auto_fixable" not in d


def test_remediation_from_dict():
    d = {
        "description": "Fix it",
        "before": "bad()",
        "after": "good()",
        "auto_fixable": True,
    }
    rem = Remediation.from_dict(d)
    assert rem.description == "Fix it"
    assert rem.before == "bad()"
    assert rem.after == "good()"
    assert rem.auto_fixable is True


def test_remediation_from_dict_tolerates_missing():
    d = {"description": "Do something"}
    rem = Remediation.from_dict(d)
    assert rem.description == "Do something"
    assert rem.before == ""
    assert rem.after == ""
    assert rem.auto_fixable is False


def test_remediation_round_trip():
    original = Remediation(
        description="Use textContent instead",
        before="elem.textContent = old_val",
        after="elem.textContent = new_val",
        auto_fixable=True,
    )
    restored = Remediation.from_dict(original.to_dict())
    assert restored.description == original.description
    assert restored.before == original.before
    assert restored.after == original.after
    assert restored.auto_fixable == original.auto_fixable


# -- Finding defaults ------------------------------------------------------

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
    # New v0.2 fields default to None/[]
    assert f.range is None
    assert f.confidence is None
    assert f.cwe_ids == []
    assert f.remediation is None


# -- Finding to_dict -------------------------------------------------------

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


def test_finding_to_dict_omits_none_fields():
    """New v0.2 fields should not appear in dict when unset."""
    f = Finding(
        finding_type=FindingType.XSS,
        severity=Severity.MEDIUM,
        message="XSS risk",
    )
    d = f.to_dict()
    assert "range" not in d
    assert "confidence" not in d
    assert "cwe_ids" not in d
    assert "remediation" not in d


def test_finding_to_dict_includes_v02_fields_when_set():
    f = Finding(
        finding_type=FindingType.SQL_INJECTION,
        severity=Severity.HIGH,
        message="SQL injection",
        range=Range(start_line=9, start_col=0, end_line=9, end_col=30),
        confidence=0.95,
        cwe_ids=["CWE-89"],
        remediation=Remediation(description="Use parameterized queries"),
    )
    d = f.to_dict()
    assert "range" in d
    assert d["range"]["start"]["line"] == 9
    assert d["confidence"] == 0.95
    assert d["cwe_ids"] == ["CWE-89"]
    assert d["remediation"]["description"] == "Use parameterized queries"


def test_finding_to_dict_empty_cwe_ids_omitted():
    f = Finding(
        finding_type=FindingType.XSS,
        severity=Severity.MEDIUM,
        message="XSS",
        cwe_ids=[],
    )
    d = f.to_dict()
    assert "cwe_ids" not in d


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


def test_finding_to_json_with_v02_fields():
    f = Finding(
        finding_type=FindingType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        message="Dynamic code execution detected",
        range=Range(start_line=0, start_col=5, end_line=0, end_col=20),
        confidence=0.99,
        cwe_ids=["CWE-94", "CWE-95"],
        remediation=Remediation(description="Avoid dynamic code execution"),
    )
    data = json.loads(f.to_json())
    assert data["range"]["start"]["character"] == 5
    assert data["confidence"] == 0.99
    assert data["cwe_ids"] == ["CWE-94", "CWE-95"]
    assert data["remediation"]["description"] == "Avoid dynamic code execution"


# -- Finding round-trips ---------------------------------------------------

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


def test_finding_round_trip_with_v02_fields():
    original = Finding(
        finding_type=FindingType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        message="SQL injection via f-string",
        matched_text='f"SELECT * FROM users WHERE id={uid}"',
        line_number=42,
        file_path="db.py",
        scanner="code_scanner",
        range=Range(start_line=41, start_col=4, end_line=41, end_col=45),
        confidence=0.92,
        cwe_ids=["CWE-89"],
        remediation=Remediation(
            description="Use parameterized queries",
            before='f"SELECT * FROM users WHERE id={uid}"',
            after='"SELECT * FROM users WHERE id=?", (uid,)',
            auto_fixable=False,
        ),
    )
    d = original.to_dict()
    restored = Finding.from_dict(d)
    assert restored.range is not None
    assert restored.range.start_line == 41
    assert restored.range.start_col == 4
    assert restored.confidence == 0.92
    assert restored.cwe_ids == ["CWE-89"]
    assert restored.remediation is not None
    assert restored.remediation.description == "Use parameterized queries"
    assert restored.remediation.auto_fixable is False


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


def test_finding_json_round_trip_with_v02_fields():
    original = Finding(
        finding_type=FindingType.DEPENDENCY_VULNERABILITY,
        severity=Severity.HIGH,
        message="CVE-2023-1234 in requests",
        confidence=1.0,
        cwe_ids=["CWE-400"],
        remediation=Remediation(description="Upgrade requests>=2.31.0"),
    )
    j = original.to_json()
    restored = Finding.from_dict(json.loads(j))
    assert restored.finding_type == FindingType.DEPENDENCY_VULNERABILITY
    assert restored.confidence == 1.0
    assert restored.cwe_ids == ["CWE-400"]
    assert restored.remediation is not None
    assert restored.remediation.description == "Upgrade requests>=2.31.0"


def test_finding_unique_ids():
    f1 = Finding(finding_type=FindingType.SECRET, severity=Severity.LOW, message="a")
    f2 = Finding(finding_type=FindingType.SECRET, severity=Severity.LOW, message="b")
    assert f1.finding_id != f2.finding_id


# -- Backward compatibility ------------------------------------------------

def test_from_dict_tolerates_missing_v02_fields():
    """Dicts serialized by v0.1 should still deserialize cleanly."""
    old_dict = {
        "finding_type": "secret",
        "severity": "high",
        "message": "AWS key",
        "matched_text": "AKIA***",
        "line_number": 1,
        "file_path": None,
        "scanner": "secrets",
        "finding_id": "abc123def456",
        "metadata": {},
    }
    f = Finding.from_dict(old_dict)
    assert f.range is None
    assert f.confidence is None
    assert f.cwe_ids == []
    assert f.remediation is None


def test_from_dict_with_known_fields_only():
    d = {
        "finding_type": "xss",
        "severity": "medium",
        "message": "XSS risk",
        "matched_text": "",
        "line_number": 0,
        "file_path": None,
        "scanner": "",
        "finding_id": "test12345678",
        "metadata": {},
        "cwe_ids": [],
    }
    f = Finding.from_dict(d)
    assert f.finding_type == FindingType.XSS


def test_dependency_vulnerability_finding():
    f = Finding(
        finding_type=FindingType.DEPENDENCY_VULNERABILITY,
        severity=Severity.CRITICAL,
        message="CVE-2024-0001 in flask 2.0.0",
        scanner="osv",
        confidence=1.0,
        cwe_ids=["CWE-79", "CWE-89"],
        remediation=Remediation(
            description="Upgrade flask to >=2.3.0",
            auto_fixable=True,
        ),
        metadata={"cve_id": "CVE-2024-0001", "ecosystem": "PyPI"},
    )
    d = f.to_dict()
    assert d["finding_type"] == "dependency_vulnerability"
    restored = Finding.from_dict(d)
    assert restored.finding_type == FindingType.DEPENDENCY_VULNERABILITY
    assert restored.cwe_ids == ["CWE-79", "CWE-89"]
    assert restored.remediation.auto_fixable is True


def test_finding_multiple_cwe_ids():
    f = Finding(
        finding_type=FindingType.XSS,
        severity=Severity.HIGH,
        message="XSS via unsafe rendering",
        cwe_ids=["CWE-79", "CWE-116"],
    )
    d = f.to_dict()
    assert d["cwe_ids"] == ["CWE-79", "CWE-116"]
    restored = Finding.from_dict(d)
    assert restored.cwe_ids == ["CWE-79", "CWE-116"]


def test_finding_confidence_bounds():
    f_low = Finding(
        finding_type=FindingType.SECRET,
        severity=Severity.LOW,
        message="maybe",
        confidence=0.1,
    )
    f_high = Finding(
        finding_type=FindingType.SECRET,
        severity=Severity.CRITICAL,
        message="certain",
        confidence=1.0,
    )
    assert f_low.confidence == 0.1
    assert f_high.confidence == 1.0
