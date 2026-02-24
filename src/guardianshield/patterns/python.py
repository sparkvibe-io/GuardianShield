"""Python-specific vulnerability patterns."""

from __future__ import annotations

import re
from typing import Any, Dict

from guardianshield.findings import FindingType, Severity

# Each entry: (name, compiled_regex, finding_type, severity, description,
#              confidence, cwe_ids)
PYTHON_PATTERNS: list[
    tuple[str, re.Pattern[str], FindingType, Severity, str, float, list[str]]
] = [
    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------
    (
        "sql_injection_string_format",
        re.compile(
            r"""(?:["'])\s*SELECT\s+.+?(?:"""
            r"""\+\s*\w"""
            r"""|%s["']\s*%\s*\w"""
            r""")""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.HIGH,
        "Possible SQL injection via string formatting in query construction.",
        0.8,
        ["CWE-89"],
    ),
    (
        "sql_injection_fstring",
        re.compile(
            r"""f["'](?:[^"']*?)SELECT\s+.+?\{""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.HIGH,
        "Possible SQL injection via f-string in query construction.",
        0.85,
        ["CWE-89"],
    ),
    (
        "sql_injection_raw_query",
        re.compile(
            r"""(?:cursor|conn(?:ection)?|db)\s*\.\s*execute\s*\(\s*["'].*?["']\s*\+""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via unsanitized string concatenation in cursor.execute().",
        0.9,
        ["CWE-89"],
    ),
    (
        "sql_injection_raw_query_fstring",
        re.compile(
            r"""(?:cursor|conn(?:ection)?|db)\s*\.\s*execute\s*\(\s*f["']""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via f-string in cursor.execute().",
        0.9,
        ["CWE-89"],
    ),
    # ------------------------------------------------------------------
    # XSS (Python template engines)
    # ------------------------------------------------------------------
    (
        "xss_template_safe",
        re.compile(r"""\|\s*safe\b"""),
        FindingType.XSS,
        Severity.HIGH,
        "Potential XSS via |safe filter bypassing template auto-escaping.",
        0.8,
        ["CWE-79"],
    ),
    (
        "xss_template_autoescape_off",
        re.compile(r"""\{%\s*autoescape\s+off\s*%\}"""),
        FindingType.XSS,
        Severity.HIGH,
        "Potential XSS via disabled auto-escaping in template.",
        0.85,
        ["CWE-79"],
    ),
    (
        "xss_markup",
        re.compile(r"""Markup\s*\("""),
        FindingType.XSS,
        Severity.HIGH,
        "Potential XSS via Markup() wrapping raw HTML.",
        0.75,
        ["CWE-79"],
    ),
    # ------------------------------------------------------------------
    # Command Injection
    # ------------------------------------------------------------------
    (
        "command_injection_os_system",
        re.compile(r"""os\.system\s*\("""),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Command injection risk via os.system().",
        0.85,
        ["CWE-78"],
    ),
    (
        "command_injection_subprocess_shell",
        re.compile(
            r"""subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True"""
        ),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Command injection risk via subprocess with shell=True.",
        0.8,
        ["CWE-78"],
    ),
    (
        "command_injection_exec",
        re.compile(r"""\bexec\s*\(\s*(?!["']\s*\))"""),
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        "Code execution risk via exec() with non-literal argument.",
        0.7,
        ["CWE-94", "CWE-95"],
    ),
    # ------------------------------------------------------------------
    # Path Traversal
    # ------------------------------------------------------------------
    (
        "path_traversal_open",
        re.compile(r"""\bopen\s*\(\s*(?:\w+\s*\+|f["'])"""),
        FindingType.PATH_TRAVERSAL,
        Severity.MEDIUM,
        "Path traversal risk via open() with concatenated user input.",
        0.6,
        ["CWE-22"],
    ),
    (
        "path_traversal_os_path_join",
        re.compile(
            r"""os\.path\.join\s*\(.*(?:request|user_input|input|params|args|data)\b"""
        ),
        FindingType.PATH_TRAVERSAL,
        Severity.MEDIUM,
        "Path traversal risk via os.path.join with potentially user-controlled path segment.",
        0.5,
        ["CWE-22"],
    ),
    # ------------------------------------------------------------------
    # Insecure Functions
    # ------------------------------------------------------------------
    (
        "insecure_pickle",
        re.compile(r"""pickle\.loads?\s*\("""),
        FindingType.INSECURE_FUNCTION,
        Severity.HIGH,
        "Insecure deserialization via pickle.load(s)() can execute arbitrary code.",
        0.9,
        ["CWE-502"],
    ),
    (
        "insecure_hash",
        re.compile(r"""hashlib\.(?:md5|sha1)\s*\("""),
        FindingType.INSECURE_FUNCTION,
        Severity.LOW,
        "Use of weak hash algorithm (MD5/SHA1) which is unsuitable for security purposes.",
        0.6,
        ["CWE-328"],
    ),
    (
        "insecure_random",
        re.compile(
            r"""random\.(?:random|randint|choice|randrange|uniform)\s*\("""
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.MEDIUM,
        "Use of non-cryptographic random number generator. Use secrets module for security.",
        0.5,
        ["CWE-330"],
    ),
]

# Remediation guidance keyed by pattern name.
PYTHON_REMEDIATION: Dict[str, Dict[str, Any]] = {
    "sql_injection_string_format": {
        "description": "Use parameterized queries instead of string formatting.",
        "before": 'query = "SELECT * FROM users WHERE id=" + user_id',
        "after": 'cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
        "auto_fixable": False,
    },
    "sql_injection_fstring": {
        "description": "Use parameterized queries instead of f-strings.",
        "before": 'query = f"SELECT * FROM users WHERE id={user_id}"',
        "after": 'cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
        "auto_fixable": False,
    },
    "sql_injection_raw_query": {
        "description": "Use parameterized queries with placeholders.",
        "before": 'cursor.execute("SELECT * FROM users WHERE id=" + uid)',
        "after": 'cursor.execute("SELECT * FROM users WHERE id=?", (uid,))',
        "auto_fixable": False,
    },
    "sql_injection_raw_query_fstring": {
        "description": "Use parameterized queries with placeholders.",
        "before": 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
        "after": 'cursor.execute("SELECT * FROM users WHERE id=?", (uid,))',
        "auto_fixable": False,
    },
    "xss_template_safe": {
        "description": "Remove |safe filter and let the template engine auto-escape.",
        "before": "{{ user_input|safe }}",
        "after": "{{ user_input }}",
        "auto_fixable": True,
    },
    "xss_template_autoescape_off": {
        "description": "Remove autoescape off block to re-enable auto-escaping.",
        "before": "{% autoescape off %}{{ content }}{% endautoescape %}",
        "after": "{{ content }}",
        "auto_fixable": False,
    },
    "xss_markup": {
        "description": "Sanitize HTML before wrapping in Markup(), or use escape().",
        "before": "Markup(user_html)",
        "after": "Markup(bleach.clean(user_html))",
        "auto_fixable": False,
    },
    "command_injection_os_system": {
        "description": "Use subprocess.run() with a list of arguments instead of os.system().",
        "before": "os.system('ls ' + user_dir)",
        "after": "subprocess.run(['ls', user_dir], check=True)",
        "auto_fixable": False,
    },
    "command_injection_subprocess_shell": {
        "description": "Pass arguments as a list and remove shell=True.",
        "before": "subprocess.run(f'grep {pattern} {file}', shell=True)",
        "after": "subprocess.run(['grep', pattern, file])",
        "auto_fixable": False,
    },
    "command_injection_exec": {
        "description": "Avoid exec(). Use ast.literal_eval() for data or a safe DSL.",
        "before": "exec(user_code)",
        "after": "ast.literal_eval(user_code)  # for data only",
        "auto_fixable": False,
    },
    "path_traversal_open": {
        "description": "Validate and sanitize file paths. Use pathlib with resolve().",
        "before": "open(base_dir + user_file)",
        "after": "path = (Path(base_dir) / user_file).resolve(); assert path.is_relative_to(base_dir); open(path)",
        "auto_fixable": False,
    },
    "path_traversal_os_path_join": {
        "description": "Validate that resolved path stays within the expected directory.",
        "before": "os.path.join(base, request.args['file'])",
        "after": "path = os.path.realpath(os.path.join(base, filename)); assert path.startswith(os.path.realpath(base))",
        "auto_fixable": False,
    },
    "insecure_pickle": {
        "description": "Use json, msgpack, or a safe serializer instead of pickle.",
        "before": "data = pickle.loads(untrusted_bytes)",
        "after": "data = json.loads(untrusted_bytes)",
        "auto_fixable": False,
    },
    "insecure_hash": {
        "description": "Use SHA-256 or stronger for security-sensitive hashing.",
        "before": "hashlib.md5(data).hexdigest()",
        "after": "hashlib.sha256(data).hexdigest()",
        "auto_fixable": True,
    },
    "insecure_random": {
        "description": "Use the secrets module for security-sensitive random values.",
        "before": "token = random.randint(100000, 999999)",
        "after": "token = secrets.token_hex(16)",
        "auto_fixable": False,
    },
}
