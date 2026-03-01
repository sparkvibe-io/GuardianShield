"""Go-specific vulnerability patterns."""

from __future__ import annotations

import re
from typing import Any

from guardianshield.findings import FindingType, Severity

# Each entry: (name, compiled_regex, finding_type, severity, description,
#              confidence, cwe_ids)
GO_PATTERNS: list[
    tuple[str, re.Pattern[str], FindingType, Severity, str, float, list[str]]
] = [
    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------
    (
        "go_sql_injection_sprintf",
        re.compile(
            r"""(?:fmt\.Sprintf|fmt\.Fprintf)\s*\("""
            r"""[^)]*?(?:"|`)"""
            r"""[^"`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via fmt.Sprintf in query construction. Use parameterized queries.",
        0.9,
        ["CWE-89"],
    ),
    (
        "go_sql_injection_concat",
        re.compile(
            r"""\.(?:Query|QueryRow|Exec|QueryContext|ExecContext)\s*\("""
            r"""[^,)]*\+""",
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via string concatenation in database query.",
        0.85,
        ["CWE-89"],
    ),
    # ------------------------------------------------------------------
    # Command Injection
    # ------------------------------------------------------------------
    (
        "go_command_injection_exec",
        re.compile(
            r"""exec\.Command\s*\(\s*(?:\w+\s*\+|fmt\.Sprintf|"[^"]*"\s*\+)""",
        ),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Command injection risk via exec.Command with dynamic arguments.",
        0.8,
        ["CWE-78"],
    ),
    (
        "go_command_injection_shell",
        re.compile(
            r"""exec\.Command\s*\(\s*"(?:/bin/(?:ba)?sh|cmd(?:\.exe)?)"\s*,"""
            r"""\s*"-c"\s*,""",
        ),
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        "Command injection risk via shell invocation with exec.Command.",
        0.9,
        ["CWE-78"],
    ),
    # ------------------------------------------------------------------
    # Path Traversal
    # ------------------------------------------------------------------
    (
        "go_path_traversal",
        re.compile(
            r"""(?:os\.Open|os\.ReadFile|os\.WriteFile|os\.Create|"""
            r"""ioutil\.ReadFile|ioutil\.WriteFile)\s*\(\s*"""
            r"""(?:\w+\s*\+|fmt\.Sprintf|filepath\.Join\s*\([^)]*"""
            r"""(?:request|req|params|query|input|user|r\.))""",
        ),
        FindingType.PATH_TRAVERSAL,
        Severity.HIGH,
        "Path traversal risk via file operation with user-controlled path.",
        0.7,
        ["CWE-22"],
    ),
    (
        "go_path_traversal_http_dir",
        re.compile(
            r"""http\.Dir\s*\(\s*(?:\w+\s*\+|fmt\.Sprintf)""",
        ),
        FindingType.PATH_TRAVERSAL,
        Severity.HIGH,
        "Path traversal risk via http.Dir with dynamic path.",
        0.75,
        ["CWE-22"],
    ),
    # ------------------------------------------------------------------
    # Insecure TLS
    # ------------------------------------------------------------------
    (
        "go_insecure_tls",
        re.compile(
            r"""InsecureSkipVerify\s*:\s*true""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.HIGH,
        "TLS certificate verification disabled. Vulnerable to MITM attacks.",
        0.95,
        ["CWE-295"],
    ),
    # ------------------------------------------------------------------
    # SSRF
    # ------------------------------------------------------------------
    (
        "go_ssrf",
        re.compile(
            r"""http\.(?:Get|Post|Head|PostForm)\s*\(\s*"""
            r"""(?:\w+\s*\+|fmt\.Sprintf)""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.HIGH,
        "Potential SSRF via HTTP request with user-controlled URL.",
        0.7,
        ["CWE-918"],
    ),
    # ------------------------------------------------------------------
    # Weak Crypto
    # ------------------------------------------------------------------
    (
        "go_weak_crypto",
        re.compile(
            r"""(?:md5|sha1)\.(?:New|Sum)\s*\(""",
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.LOW,
        "Use of weak hash algorithm (MD5/SHA1). Use SHA-256 or stronger for security.",
        0.6,
        ["CWE-328"],
    ),
    # ------------------------------------------------------------------
    # Template Injection
    # ------------------------------------------------------------------
    (
        "go_text_template_unescaped",
        re.compile(
            r"""text/template""",
        ),
        FindingType.XSS,
        Severity.MEDIUM,
        "Use of text/template which does not escape HTML. Use html/template for web output.",
        0.6,
        ["CWE-79"],
    ),
    # ------------------------------------------------------------------
    # Unsafe Deserialization
    # ------------------------------------------------------------------
    (
        "go_unsafe_deserialization",
        re.compile(
            r"""(?:gob|xml)\.NewDecoder\s*\(\s*(?:r\.Body|req\.Body|request\.Body|conn)""",
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.HIGH,
        "Unsafe deserialization from untrusted source. Validate and limit input.",
        0.7,
        ["CWE-502"],
    ),
    # ------------------------------------------------------------------
    # Hardcoded Credentials
    # ------------------------------------------------------------------
    (
        "go_hardcoded_password",
        re.compile(
            r"(?:password|passwd|secret|token|apiKey|api_key)\s*"
            r'(?::=|=)\s*"[^"]{4,}"',
            re.IGNORECASE,
        ),
        FindingType.SECRET,
        Severity.HIGH,
        "Potential hardcoded credential in source code.",
        0.7,
        ["CWE-798"],
    ),
    # ------------------------------------------------------------------
    # Unhandled Errors
    # ------------------------------------------------------------------
    (
        "go_unhandled_error",
        re.compile(
            r"""[a-zA-Z_]\w*\s*,\s*_\s*(?::=|=)\s*"""
            r"""(?:\w+\.(?:Query|Exec|Open|Read|Write|Close|Get|Post|Do|Dial))\s*\(""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.MEDIUM,
        "Error return value discarded with '_'. Unhandled errors can mask security issues.",
        0.6,
        ["CWE-391"],
    ),
]

# Remediation guidance keyed by pattern name.
GO_REMEDIATION: dict[str, dict[str, Any]] = {
    "go_sql_injection_sprintf": {
        "description": "Use parameterized queries with placeholders instead of fmt.Sprintf.",
        "before": 'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id=%s", userID))',
        "after": 'db.Query("SELECT * FROM users WHERE id=$1", userID)',
        "auto_fixable": False,
    },
    "go_sql_injection_concat": {
        "description": "Use parameterized queries with placeholders instead of string concatenation.",
        "before": 'db.Query("SELECT * FROM users WHERE name=" + name)',
        "after": 'db.Query("SELECT * FROM users WHERE name=$1", name)',
        "auto_fixable": False,
    },
    "go_command_injection_exec": {
        "description": "Avoid building command strings dynamically. Use a fixed command with validated arguments.",
        "before": 'exec.Command("ls " + userDir)',
        "after": 'exec.Command("ls", sanitizedDir)',
        "auto_fixable": False,
    },
    "go_command_injection_shell": {
        "description": "Avoid shell invocation. Use exec.Command with direct arguments.",
        "before": 'exec.Command("/bin/sh", "-c", userInput)',
        "after": 'exec.Command("ls", "-la", validatedPath)',
        "auto_fixable": False,
    },
    "go_path_traversal": {
        "description": "Validate and sanitize file paths. Use filepath.Clean and verify the path stays within the allowed directory.",
        "before": "os.Open(filepath.Join(baseDir, req.URL.Path))",
        "after": 'cleaned := filepath.Clean(userPath); if !strings.HasPrefix(filepath.Join(base, cleaned), base) { return error }',
        "auto_fixable": False,
    },
    "go_path_traversal_http_dir": {
        "description": "Use a fixed directory for http.Dir. Do not construct paths from user input.",
        "before": "http.Dir(userPath + \"/static\")",
        "after": 'http.Dir("/var/www/static")',
        "auto_fixable": False,
    },
    "go_insecure_tls": {
        "description": "Remove InsecureSkipVerify or set it to false. Use proper CA certificates.",
        "before": "TLSClientConfig: &tls.Config{InsecureSkipVerify: true}",
        "after": "TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}",
        "auto_fixable": True,
    },
    "go_ssrf": {
        "description": "Validate and whitelist URLs before making HTTP requests. Block internal/private IPs.",
        "before": "http.Get(userURL)",
        "after": 'if isAllowedURL(userURL) { http.Get(userURL) }',
        "auto_fixable": False,
    },
    "go_weak_crypto": {
        "description": "Use SHA-256 or stronger hash algorithms for security-sensitive operations.",
        "before": "h := md5.New()",
        "after": "h := sha256.New()",
        "auto_fixable": True,
    },
    "go_text_template_unescaped": {
        "description": "Use html/template instead of text/template for HTML output to auto-escape values.",
        "before": '"text/template"',
        "after": '"html/template"',
        "auto_fixable": True,
    },
    "go_unsafe_deserialization": {
        "description": "Validate input before deserializing. Set size limits and use safe formats like JSON.",
        "before": "gob.NewDecoder(r.Body).Decode(&data)",
        "after": "json.NewDecoder(io.LimitReader(r.Body, maxSize)).Decode(&data)",
        "auto_fixable": False,
    },
    "go_hardcoded_password": {
        "description": "Move credentials to environment variables or a secret manager.",
        "before": 'password := "mysecretpassword"',
        "after": 'password := os.Getenv("DB_PASSWORD")',
        "auto_fixable": False,
    },
    "go_unhandled_error": {
        "description": "Handle error return values explicitly. Log or return errors instead of discarding them.",
        "before": "result, _ := db.Query(query)",
        "after": "result, err := db.Query(query); if err != nil { return err }",
        "auto_fixable": False,
    },
}
