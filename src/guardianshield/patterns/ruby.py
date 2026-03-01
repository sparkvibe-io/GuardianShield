"""Ruby / Rails vulnerability patterns."""

from __future__ import annotations

import re
from typing import Any

from guardianshield.findings import FindingType, Severity

# Each entry: (name, compiled_regex, finding_type, severity, description,
#              confidence, cwe_ids)
RUBY_PATTERNS: list[
    tuple[str, re.Pattern[str], FindingType, Severity, str, float, list[str]]
] = [
    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------
    (
        "rb_sql_injection_interpolation",
        re.compile(
            r"""\.(?:where|order|group|having|joins|select|from|pluck)\s*\(\s*["'].*#\{""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via string interpolation in ActiveRecord query.",
        0.9,
        ["CWE-89"],
    ),
    (
        "rb_sql_injection_find_by_sql",
        re.compile(
            r"""(?:find_by_sql|count_by_sql)\s*\(\s*["'].*#\{""",
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via string interpolation in find_by_sql/count_by_sql.",
        0.9,
        ["CWE-89"],
    ),
    (
        "rb_sql_injection_execute",
        re.compile(
            r"""(?:execute|exec_query|exec_update|exec_delete|exec_insert)\s*\(\s*["'].*#\{""",
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via string interpolation in raw SQL execute.",
        0.9,
        ["CWE-89"],
    ),
    # ------------------------------------------------------------------
    # Command Injection
    # ------------------------------------------------------------------
    (
        "rb_command_injection_system",
        re.compile(
            r"""\b(?:system|exec)\s*\(\s*["'].*#\{""",
        ),
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        "Command injection via string interpolation in system/exec call.",
        0.9,
        ["CWE-78"],
    ),
    (
        "rb_command_injection_backtick",
        re.compile(
            r"""`[^`]*#\{""",
        ),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Command injection via backtick execution with string interpolation.",
        0.8,
        ["CWE-78"],
    ),
    (
        "rb_command_injection_open3",
        re.compile(
            r"""Open3\.(?:capture2|capture2e|capture3|popen2|popen3|pipeline)\s*\(""",
        ),
        FindingType.COMMAND_INJECTION,
        Severity.MEDIUM,
        "Potential command injection via Open3 shell execution.",
        0.6,
        ["CWE-78"],
    ),
    # ------------------------------------------------------------------
    # XSS
    # ------------------------------------------------------------------
    (
        "rb_xss_raw",
        re.compile(
            r"""<%=\s*raw\s+""",
        ),
        FindingType.XSS,
        Severity.HIGH,
        "Potential XSS via raw() bypassing Rails HTML escaping.",
        0.85,
        ["CWE-79"],
    ),
    (
        "rb_xss_html_safe",
        re.compile(
            r"""\.html_safe\b""",
        ),
        FindingType.XSS,
        Severity.HIGH,
        "Potential XSS via html_safe marking string as safe without sanitization.",
        0.8,
        ["CWE-79"],
    ),
    # ------------------------------------------------------------------
    # Insecure Deserialization
    # ------------------------------------------------------------------
    (
        "rb_insecure_yaml_load",
        re.compile(
            r"""YAML\.load\s*\(""",
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.CRITICAL,
        "Insecure deserialization via YAML.load can execute arbitrary code. Use YAML.safe_load.",
        0.9,
        ["CWE-502"],
    ),
    (
        "rb_insecure_marshal_load",
        re.compile(
            r"""Marshal\.(?:load|restore)\s*\(""",
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.CRITICAL,
        "Insecure deserialization via Marshal.load can execute arbitrary code.",
        0.9,
        ["CWE-502"],
    ),
    # ------------------------------------------------------------------
    # Mass Assignment
    # ------------------------------------------------------------------
    (
        "rb_mass_assignment_permit_all",
        re.compile(
            r"""\.permit\s*!\s*$""",
            re.MULTILINE,
        ),
        FindingType.INSECURE_PATTERN,
        Severity.HIGH,
        "Mass assignment vulnerability via permit! allowing all parameters.",
        0.9,
        ["CWE-915"],
    ),
    # ------------------------------------------------------------------
    # Open Redirect
    # ------------------------------------------------------------------
    (
        "rb_open_redirect",
        re.compile(
            r"""redirect_to\s+params\s*\[""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.MEDIUM,
        "Potential open redirect via redirect_to with user-controlled parameter.",
        0.7,
        ["CWE-601"],
    ),
    # ------------------------------------------------------------------
    # Weak Cryptography
    # ------------------------------------------------------------------
    (
        "rb_weak_crypto",
        re.compile(
            r"""Digest::(?:MD5|SHA1)\b""",
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.LOW,
        "Use of weak hash algorithm (MD5/SHA1) unsuitable for security purposes.",
        0.6,
        ["CWE-328"],
    ),
    # ------------------------------------------------------------------
    # CSRF Disable
    # ------------------------------------------------------------------
    (
        "rb_csrf_disabled",
        re.compile(
            r"""skip_before_action\s+:verify_authenticity_token""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.HIGH,
        "CSRF protection disabled via skip_before_action :verify_authenticity_token.",
        0.9,
        ["CWE-352"],
    ),
    # ------------------------------------------------------------------
    # Path Traversal
    # ------------------------------------------------------------------
    (
        "rb_path_traversal_send_file",
        re.compile(
            r"""send_file\s+.*params\s*\[""",
        ),
        FindingType.PATH_TRAVERSAL,
        Severity.HIGH,
        "Path traversal risk via send_file with user-controlled parameter.",
        0.8,
        ["CWE-22"],
    ),
    # ------------------------------------------------------------------
    # Insecure Dynamic Evaluation
    # ------------------------------------------------------------------
    (
        "rb_dynamic_eval",
        re.compile(
            r"""\b(?:instance_eval|class_eval|module_eval)\s*\(\s*(?!["'][^"']*["']\s*\))""",
        ),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Code execution risk via instance_eval/class_eval/module_eval with dynamic argument.",
        0.75,
        ["CWE-94", "CWE-95"],
    ),
]

# Remediation guidance keyed by pattern name.
RUBY_REMEDIATION: dict[str, dict[str, Any]] = {
    "rb_sql_injection_interpolation": {
        "description": "Use parameterized queries with placeholder syntax.",
        "before": 'User.where("name = #{params[:name]}")',
        "after": "User.where('name = ?', params[:name])",
        "auto_fixable": False,
    },
    "rb_sql_injection_find_by_sql": {
        "description": "Use parameterized queries with array syntax.",
        "before": 'User.find_by_sql("SELECT * FROM users WHERE id = #{id}")',
        "after": "User.find_by_sql(['SELECT * FROM users WHERE id = ?', id])",
        "auto_fixable": False,
    },
    "rb_sql_injection_execute": {
        "description": "Use parameterized queries with sanitize_sql.",
        "before": 'connection.execute("DELETE FROM users WHERE id = #{id}")',
        "after": "connection.execute(sanitize_sql(['DELETE FROM users WHERE id = ?', id]))",
        "auto_fixable": False,
    },
    "rb_command_injection_system": {
        "description": "Use array form of system() to avoid shell interpretation.",
        "before": 'system("ls #{user_dir}")',
        "after": "system('ls', user_dir)",
        "auto_fixable": False,
    },
    "rb_command_injection_backtick": {
        "description": "Use Open3.capture2 with array arguments instead of backticks.",
        "before": '`git log #{branch}`',
        "after": "Open3.capture2('git', 'log', branch)",
        "auto_fixable": False,
    },
    "rb_command_injection_open3": {
        "description": "Ensure Open3 commands use array arguments, not shell strings.",
        "before": "Open3.capture2('ls ' + user_dir)",
        "after": "Open3.capture2('ls', user_dir)",
        "auto_fixable": False,
    },
    "rb_xss_raw": {
        "description": "Remove raw() and let Rails auto-escape, or use sanitize().",
        "before": "<%= raw user_input %>",
        "after": "<%= sanitize(user_input) %>",
        "auto_fixable": False,
    },
    "rb_xss_html_safe": {
        "description": "Remove html_safe and let Rails auto-escape, or use sanitize().",
        "before": "user_input.html_safe",
        "after": "sanitize(user_input)",
        "auto_fixable": False,
    },
    "rb_insecure_yaml_load": {
        "description": "Use YAML.safe_load instead of YAML.load.",
        "before": "YAML.load(user_data)",
        "after": "YAML.safe_load(user_data)",
        "auto_fixable": True,
    },
    "rb_insecure_marshal_load": {
        "description": "Avoid Marshal.load on untrusted data. Use JSON or YAML.safe_load.",
        "before": "Marshal.load(untrusted_bytes)",
        "after": "JSON.parse(untrusted_bytes)",
        "auto_fixable": False,
    },
    "rb_mass_assignment_permit_all": {
        "description": "Explicitly list permitted parameters instead of permit!.",
        "before": "params.require(:user).permit!",
        "after": "params.require(:user).permit(:name, :email)",
        "auto_fixable": False,
    },
    "rb_open_redirect": {
        "description": "Validate redirect URL against an allowlist or use only path.",
        "before": "redirect_to params[:url]",
        "after": "redirect_to url_from(params[:url]) || root_path",
        "auto_fixable": False,
    },
    "rb_weak_crypto": {
        "description": "Use SHA-256 or stronger for security-sensitive hashing.",
        "before": "Digest::MD5.hexdigest(data)",
        "after": "Digest::SHA256.hexdigest(data)",
        "auto_fixable": True,
    },
    "rb_csrf_disabled": {
        "description": "Remove skip_before_action for CSRF verification. Use protect_from_forgery.",
        "before": "skip_before_action :verify_authenticity_token",
        "after": "protect_from_forgery with: :exception",
        "auto_fixable": False,
    },
    "rb_path_traversal_send_file": {
        "description": "Validate file path and restrict to an allowed directory.",
        "before": "send_file params[:path]",
        "after": "send_file Rails.root.join('public', File.basename(params[:path]))",
        "auto_fixable": False,
    },
    "rb_dynamic_eval": {
        "description": "Avoid dynamic code evaluation. Use a safe alternative or allowlisted methods.",
        "before": "instance_eval(user_code)",
        "after": "# Use a safe DSL or method dispatch with allowlist",
        "auto_fixable": False,
    },
}
