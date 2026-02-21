"""Code vulnerability scanner.

Scans source code for common security vulnerabilities using regex-based
pattern matching. Detects SQL injection, XSS, command injection, path
traversal, and use of insecure functions.
"""

from __future__ import annotations

import re
from typing import Optional

from guardianshield.findings import Finding, FindingType, Severity

# ---------------------------------------------------------------------------
# Vulnerability patterns
# ---------------------------------------------------------------------------
# Each entry: (name, compiled_regex, finding_type, severity, description)

VULNERABILITY_PATTERNS: list[
    tuple[str, re.Pattern[str], FindingType, Severity, str]
] = [
    # ------------------------------------------------------------------
    # 1. SQL Injection - string formatting in SQL queries
    # ------------------------------------------------------------------
    (
        "sql_injection_string_format",
        re.compile(
            r"""(?:["'])\s*SELECT\s+.+?(?:"""
            r"""\+\s*\w"""  # "SELECT ... " + var
            r"""|%s["']\s*%\s*\w"""  # "SELECT ... %s" % var
            r""")""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.HIGH,
        "Possible SQL injection via string formatting in query construction.",
    ),
    # f-string SQL injection
    (
        "sql_injection_fstring",
        re.compile(
            r"""f["'](?:[^"']*?)SELECT\s+.+?\{""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.HIGH,
        "Possible SQL injection via f-string in query construction.",
    ),
    # ------------------------------------------------------------------
    # 2. SQL Injection - raw/unsanitized queries via cursor.execute
    # ------------------------------------------------------------------
    (
        "sql_injection_raw_query",
        re.compile(
            r"""(?:cursor|conn(?:ection)?|db)\s*\.\s*execute\s*\(\s*["'].*?["']\s*\+""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via unsanitized string concatenation in cursor.execute().",
    ),
    # cursor.execute with f-string
    (
        "sql_injection_raw_query_fstring",
        re.compile(
            r"""(?:cursor|conn(?:ection)?|db)\s*\.\s*execute\s*\(\s*f["']""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via f-string in cursor.execute().",
    ),
    # ------------------------------------------------------------------
    # 3. XSS - innerHTML assignment
    # ------------------------------------------------------------------
    (
        "xss_innerhtml",
        re.compile(r"""\.innerHTML\s*="""),
        FindingType.XSS,
        Severity.MEDIUM,
        "Potential XSS via innerHTML assignment.",
    ),
    # ------------------------------------------------------------------
    # 4. XSS - document.write()
    # ------------------------------------------------------------------
    (
        "xss_document_write",
        re.compile(r"""document\.write\s*\("""),
        FindingType.XSS,
        Severity.MEDIUM,
        "Potential XSS via document.write().",
    ),
    # ------------------------------------------------------------------
    # 5. XSS - unsanitized template rendering
    # ------------------------------------------------------------------
    (
        "xss_template_safe",
        re.compile(r"""\|\s*safe\b"""),
        FindingType.XSS,
        Severity.HIGH,
        "Potential XSS via |safe filter bypassing template auto-escaping.",
    ),
    (
        "xss_template_autoescape_off",
        re.compile(r"""\{%\s*autoescape\s+off\s*%\}"""),
        FindingType.XSS,
        Severity.HIGH,
        "Potential XSS via disabled auto-escaping in template.",
    ),
    (
        "xss_markup",
        re.compile(r"""Markup\s*\("""),
        FindingType.XSS,
        Severity.HIGH,
        "Potential XSS via Markup() wrapping raw HTML.",
    ),
    # ------------------------------------------------------------------
    # 6. Command Injection - os.system()
    # ------------------------------------------------------------------
    (
        "command_injection_os_system",
        re.compile(r"""os\.system\s*\("""),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Command injection risk via os.system().",
    ),
    # ------------------------------------------------------------------
    # 7. Command Injection - subprocess with shell=True
    # ------------------------------------------------------------------
    (
        "command_injection_subprocess_shell",
        re.compile(r"""subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True"""),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Command injection risk via subprocess with shell=True.",
    ),
    # ------------------------------------------------------------------
    # 8. Command Injection - eval()/exec() with non-literal args
    # ------------------------------------------------------------------
    (
        "command_injection_eval",
        re.compile(r"""\beval\s*\(\s*(?!["']\s*\))"""),
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        "Code execution risk via eval() with non-literal argument.",
    ),
    (
        "command_injection_exec",
        re.compile(r"""\bexec\s*\(\s*(?!["']\s*\))"""),
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        "Code execution risk via exec() with non-literal argument.",
    ),
    # ------------------------------------------------------------------
    # 9. Path Traversal - open() with user input concatenation
    # ------------------------------------------------------------------
    (
        "path_traversal_open",
        re.compile(r"""\bopen\s*\(\s*(?:\w+\s*\+|f["'])"""),
        FindingType.PATH_TRAVERSAL,
        Severity.MEDIUM,
        "Path traversal risk via open() with concatenated user input.",
    ),
    # ------------------------------------------------------------------
    # 10. Path Traversal - os.path.join with user-controlled segments
    # ------------------------------------------------------------------
    (
        "path_traversal_os_path_join",
        re.compile(r"""os\.path\.join\s*\(.*(?:request|user_input|input|params|args|data)\b"""),
        FindingType.PATH_TRAVERSAL,
        Severity.MEDIUM,
        "Path traversal risk via os.path.join with potentially user-controlled path segment.",
    ),
    # ------------------------------------------------------------------
    # 11. Insecure Function - pickle.loads() / pickle.load()
    # ------------------------------------------------------------------
    (
        "insecure_pickle",
        re.compile(r"""pickle\.loads?\s*\("""),
        FindingType.INSECURE_FUNCTION,
        Severity.HIGH,
        "Insecure deserialization via pickle.load(s)() can execute arbitrary code.",
    ),
    # ------------------------------------------------------------------
    # 12. Insecure Function - md5/sha1 for security purposes
    # ------------------------------------------------------------------
    (
        "insecure_hash",
        re.compile(r"""hashlib\.(?:md5|sha1)\s*\("""),
        FindingType.INSECURE_FUNCTION,
        Severity.LOW,
        "Use of weak hash algorithm (MD5/SHA1) which is unsuitable for security purposes.",
    ),
    # ------------------------------------------------------------------
    # 13. Insecure Function - random module for security
    # ------------------------------------------------------------------
    (
        "insecure_random",
        re.compile(
            r"""random\.(?:random|randint|choice|randrange|uniform)\s*\("""
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.MEDIUM,
        "Use of non-cryptographic random number generator. Use secrets module for security.",
    ),
]

# Lines that are comments and should be skipped.
_COMMENT_RE = re.compile(r"""^\s*(?:#|//|/\*|\*)""")

# Severity ordering for sensitivity filtering.
_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def _min_severity_for_sensitivity(sensitivity: str) -> int:
    """Return the minimum severity order value for a given sensitivity level."""
    s = sensitivity.lower()
    if s == "low":
        # Only CRITICAL findings
        return _SEVERITY_ORDER[Severity.CRITICAL]
    if s == "medium":
        # Skip LOW (and INFO) -- i.e., MEDIUM and above
        return _SEVERITY_ORDER[Severity.MEDIUM]
    # "high" -- return everything
    return _SEVERITY_ORDER[Severity.INFO]


def scan_code(
    code: str,
    sensitivity: str = "medium",
    file_path: Optional[str] = None,
    language: Optional[str] = None,
) -> list[Finding]:
    """Scan source code for common security vulnerabilities.

    Args:
        code: The source code text to scan.
        sensitivity: Filtering level -- ``"low"`` returns only CRITICAL
            findings, ``"medium"`` (default) skips LOW/INFO, ``"high"``
            returns all findings.
        file_path: Optional path of the source file being scanned.
        language: Optional language hint (currently unused but reserved for
            future language-specific rules).

    Returns:
        A list of :class:`Finding` instances for detected vulnerabilities.
    """
    min_sev = _min_severity_for_sensitivity(sensitivity)
    findings: list[Finding] = []
    lines = code.splitlines()

    for line_number, line in enumerate(lines, start=1):
        # Skip comment lines
        if _COMMENT_RE.match(line):
            continue

        for name, pattern, finding_type, severity, description in VULNERABILITY_PATTERNS:
            if _SEVERITY_ORDER[severity] < min_sev:
                continue

            match = pattern.search(line)
            if match:
                findings.append(
                    Finding(
                        finding_type=finding_type,
                        severity=severity,
                        message=description,
                        matched_text=match.group(0),
                        line_number=line_number,
                        file_path=file_path,
                        scanner="code_scanner",
                        metadata={"pattern_name": name},
                    )
                )

    return findings
