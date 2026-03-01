"""PHP vulnerability patterns.

Covers Laravel/WordPress SaaS patterns: SQL injection, command injection,
XSS, file upload, eval, SSRF, weak crypto, type juggling, insecure
deserialization, and information disclosure.
"""

from __future__ import annotations

import re
from typing import Any

from guardianshield.findings import FindingType, Severity

# Each entry: (name, compiled_regex, finding_type, severity, description,
#              confidence, cwe_ids)
PHP_PATTERNS: list[
    tuple[str, re.Pattern[str], FindingType, Severity, str, float, list[str]]
] = [
    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------
    (
        "php_sql_injection_mysql_query",
        re.compile(
            r"""(?:mysql_query|mysqli_query)\s*\([^)]*\.\s*\$""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via string concatenation in mysql_query/mysqli_query.",
        0.9,
        ["CWE-89"],
    ),
    (
        "php_sql_injection_string_interpolation",
        re.compile(
            r"""(?:mysql_query|mysqli_query|->query)\s*\([^)]*["'][^"']*\$""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via variable interpolation in SQL query string.",
        0.85,
        ["CWE-89"],
    ),
    (
        "php_sql_injection_raw_expression",
        re.compile(
            r"""(?:DB::raw|whereRaw|selectRaw|orderByRaw|groupByRaw|havingRaw)\s*\([^)]*\$""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.HIGH,
        "SQL injection via Laravel raw expression with variable interpolation.",
        0.85,
        ["CWE-89"],
    ),
    # ------------------------------------------------------------------
    # Command Injection
    # ------------------------------------------------------------------
    (
        "php_command_injection_functions",
        re.compile(
            r"""\b(?:shell_exec|system|passthru|popen|proc_open)\s*\([^)]*\$""",
            re.IGNORECASE,
        ),
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        "Command injection via PHP command execution function with variable input.",
        0.9,
        ["CWE-78"],
    ),
    (
        "php_command_injection_backtick",
        re.compile(
            r"""`[^`]*\$[^`]*`""",
        ),
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        "Command injection via PHP backtick operator with variable interpolation.",
        0.85,
        ["CWE-78"],
    ),
    # ------------------------------------------------------------------
    # XSS
    # ------------------------------------------------------------------
    (
        "php_xss_echo_superglobal",
        re.compile(
            r"""\becho\s+[^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b""",
            re.IGNORECASE,
        ),
        FindingType.XSS,
        Severity.HIGH,
        "XSS via direct echo of superglobal variable without escaping.",
        0.9,
        ["CWE-79"],
    ),
    (
        "php_xss_blade_unescaped",
        re.compile(
            r"""\{!!\s*.*\$.*!!\}""",
        ),
        FindingType.XSS,
        Severity.HIGH,
        "XSS via Laravel Blade unescaped output ({!! !!}).",
        0.85,
        ["CWE-79"],
    ),
    # ------------------------------------------------------------------
    # File Upload
    # ------------------------------------------------------------------
    (
        "php_file_upload_no_validation",
        re.compile(
            r"""move_uploaded_file\s*\(\s*\$_FILES\b""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.HIGH,
        "File upload via move_uploaded_file() without apparent validation.",
        0.75,
        ["CWE-434"],
    ),
    # ------------------------------------------------------------------
    # Code Execution (eval / preg_replace /e)
    # ------------------------------------------------------------------
    (
        "php_eval_execution",
        re.compile(
            r"""\beval\s*\(\s*\$""",
            re.IGNORECASE,
        ),
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        "Code execution via eval() with variable input.",
        0.95,
        ["CWE-94", "CWE-95"],
    ),
    (
        "php_preg_replace_eval",
        re.compile(
            r"""preg_replace\s*\(\s*['"](.)[^'"]*\1[a-z]*e[a-z]*['"]""",
            re.IGNORECASE,
        ),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Code execution via preg_replace() with /e modifier.",
        0.8,
        ["CWE-94"],
    ),
    # ------------------------------------------------------------------
    # SSRF
    # ------------------------------------------------------------------
    (
        "php_ssrf_curl",
        re.compile(
            r"""curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.HIGH,
        "SSRF risk via curl_setopt with user-controlled URL.",
        0.8,
        ["CWE-918"],
    ),
    (
        "php_ssrf_file_get_contents",
        re.compile(
            r"""file_get_contents\s*\(\s*\$""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.MEDIUM,
        "SSRF risk via file_get_contents() with user-controlled URL or path.",
        0.7,
        ["CWE-918"],
    ),
    # ------------------------------------------------------------------
    # Path Traversal (include/require)
    # ------------------------------------------------------------------
    (
        "php_path_traversal_include",
        re.compile(
            r"""\b(?:include|include_once|require|require_once)\s*\(?\s*\$""",
            re.IGNORECASE,
        ),
        FindingType.PATH_TRAVERSAL,
        Severity.CRITICAL,
        "Path traversal and code execution via include/require with variable input.",
        0.9,
        ["CWE-22", "CWE-98"],
    ),
    # ------------------------------------------------------------------
    # Insecure Deserialization
    # ------------------------------------------------------------------
    (
        "php_insecure_unserialize",
        re.compile(
            r"""\bunserialize\s*\(\s*\$""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.CRITICAL,
        "Insecure deserialization via unserialize() with variable input.",
        0.9,
        ["CWE-502"],
    ),
    # ------------------------------------------------------------------
    # Weak Crypto
    # ------------------------------------------------------------------
    (
        "php_weak_password_hash",
        re.compile(
            r"""\b(?:md5|sha1)\s*\(\s*\$(?:_POST|_GET|_REQUEST|pass|password)""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.HIGH,
        "Weak hash (md5/sha1) used for password hashing. Use password_hash() instead.",
        0.85,
        ["CWE-328", "CWE-916"],
    ),
    # ------------------------------------------------------------------
    # Type Juggling
    # ------------------------------------------------------------------
    (
        "php_type_juggling",
        re.compile(
            r"""\$(?:_POST|_GET|_REQUEST|_COOKIE|password|token|hash|secret|key|api_key)\b[^=!<>]*[^=!<>]==[^=]""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.MEDIUM,
        "Loose comparison (==) with sensitive variable may allow type juggling bypass.",
        0.7,
        ["CWE-1025"],
    ),
    # ------------------------------------------------------------------
    # Information Disclosure
    # ------------------------------------------------------------------
    (
        "php_info_disclosure_phpinfo",
        re.compile(
            r"""\bphpinfo\s*\(""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.MEDIUM,
        "Information disclosure via phpinfo() exposes server configuration.",
        0.9,
        ["CWE-200"],
    ),
    (
        "php_info_disclosure_display_errors",
        re.compile(
            r"""(?:ini_set|display_errors)\s*\(?[^)]*['\"]?(?:display_errors|1|on|true)['\"]?""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_PATTERN,
        Severity.LOW,
        "Information disclosure via display_errors enabled in production.",
        0.65,
        ["CWE-209"],
    ),
]

# Remediation guidance keyed by pattern name.
PHP_REMEDIATION: dict[str, dict[str, Any]] = {
    "php_sql_injection_mysql_query": {
        "description": "Use prepared statements with PDO or mysqli.",
        "before": (
            '$result = mysqli_query($conn, "SELECT * FROM users WHERE id=" . $_GET["id"]);'
        ),
        "after": (
            '$stmt = $conn->prepare("SELECT * FROM users WHERE id=?");'
            ' $stmt->bind_param("i", $_GET["id"]); $stmt->execute();'
        ),
        "auto_fixable": False,
    },
    "php_sql_injection_string_interpolation": {
        "description": "Use parameterized queries instead of variable interpolation.",
        "before": (
            "$result = mysqli_query($conn, \"SELECT * FROM users WHERE name='$name'\");"
        ),
        "after": (
            '$stmt = $conn->prepare("SELECT * FROM users WHERE name=?");'
            ' $stmt->bind_param("s", $name); $stmt->execute();'
        ),
        "auto_fixable": False,
    },
    "php_sql_injection_raw_expression": {
        "description": "Use parameter bindings with Laravel raw expressions.",
        "before": 'DB::raw("SELECT * FROM users WHERE id=$id")',
        "after": 'DB::select("SELECT * FROM users WHERE id=?", [$id])',
        "auto_fixable": False,
    },
    "php_command_injection_functions": {
        "description": (
            "Use escapeshellarg()/escapeshellcmd() or avoid shell execution entirely."
        ),
        "before": 'system("convert " . $filename);',
        "after": 'system("convert " . escapeshellarg($filename));',
        "auto_fixable": False,
    },
    "php_command_injection_backtick": {
        "description": "Avoid backtick operator. Use escapeshellarg() if shell execution is needed.",
        "before": "$output = `ls $dir`;",
        "after": (
            '$output = shell_exec("ls " . escapeshellarg($dir));'
        ),
        "auto_fixable": False,
    },
    "php_xss_echo_superglobal": {
        "description": "Use htmlspecialchars() to escape output.",
        "before": 'echo $_GET["name"];',
        "after": 'echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");',
        "auto_fixable": False,
    },
    "php_xss_blade_unescaped": {
        "description": (
            "Use {{ }} (escaped) instead of {!! !!} (unescaped) in Blade templates."
        ),
        "before": "{!! $userContent !!}",
        "after": "{{ $userContent }}",
        "auto_fixable": True,
    },
    "php_file_upload_no_validation": {
        "description": "Validate file type, size, and extension before moving uploaded files.",
        "before": (
            'move_uploaded_file($_FILES["file"]["tmp_name"], $destination);'
        ),
        "after": (
            '$allowed = ["image/jpeg", "image/png"];'
            ' if (in_array($_FILES["file"]["type"], $allowed))'
            ' { move_uploaded_file($_FILES["file"]["tmp_name"], $destination); }'
        ),
        "auto_fixable": False,
    },
    "php_eval_execution": {
        "description": "Avoid eval(). Use json_decode() or a template engine instead.",
        "before": "eval($userCode);",
        "after": "$data = json_decode($userInput, true);",
        "auto_fixable": False,
    },
    "php_preg_replace_eval": {
        "description": "Use preg_replace_callback() instead of the /e modifier.",
        "before": 'preg_replace("/pattern/e", "$code", $input);',
        "after": (
            'preg_replace_callback("/pattern/",'
            " function($m) { return strtoupper($m[0]); }, $input);"
        ),
        "auto_fixable": False,
    },
    "php_ssrf_curl": {
        "description": "Validate and whitelist URLs before using them in curl requests.",
        "before": "curl_setopt($ch, CURLOPT_URL, $userUrl);",
        "after": (
            '$parsed = parse_url($userUrl);'
            ' if (in_array($parsed["host"], $allowedHosts))'
            " { curl_setopt($ch, CURLOPT_URL, $userUrl); }"
        ),
        "auto_fixable": False,
    },
    "php_ssrf_file_get_contents": {
        "description": "Validate URLs/paths against a whitelist before fetching.",
        "before": "$data = file_get_contents($userUrl);",
        "after": (
            "if (filter_var($userUrl, FILTER_VALIDATE_URL)"
            ' && in_array(parse_url($userUrl, PHP_URL_HOST), $allowed))'
            " { $data = file_get_contents($userUrl); }"
        ),
        "auto_fixable": False,
    },
    "php_path_traversal_include": {
        "description": "Use a whitelist of allowed files instead of dynamic includes.",
        "before": 'include($_GET["page"] . ".php");',
        "after": (
            '$allowed = ["home", "about", "contact"];'
            ' if (in_array($_GET["page"], $allowed))'
            ' { include($_GET["page"] . ".php"); }'
        ),
        "auto_fixable": False,
    },
    "php_insecure_unserialize": {
        "description": (
            "Use json_decode() instead of unserialize(), or restrict allowed classes."
        ),
        "before": '$data = unserialize($_POST["data"]);',
        "after": '$data = json_decode($_POST["data"], true);',
        "auto_fixable": False,
    },
    "php_weak_password_hash": {
        "description": "Use password_hash() and password_verify() for password hashing.",
        "before": "$hash = md5($password);",
        "after": "$hash = password_hash($password, PASSWORD_DEFAULT);",
        "auto_fixable": False,
    },
    "php_type_juggling": {
        "description": "Use strict comparison (===) instead of loose comparison (==).",
        "before": "if ($token == $expected) { ... }",
        "after": "if (hash_equals($expected, $token)) { ... }",
        "auto_fixable": True,
    },
    "php_info_disclosure_phpinfo": {
        "description": "Remove phpinfo() calls from production code.",
        "before": "phpinfo();",
        "after": "// Removed: phpinfo() should only be used in development",
        "auto_fixable": True,
    },
    "php_info_disclosure_display_errors": {
        "description": "Disable display_errors in production. Log errors instead.",
        "before": "ini_set('display_errors', 1);",
        "after": "ini_set('display_errors', 0); ini_set('log_errors', 1);",
        "auto_fixable": True,
    },
}
