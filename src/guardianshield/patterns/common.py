"""Cross-language vulnerability patterns.

These patterns match constructs that are common across multiple languages
(e.g. ``innerHTML`` appears in both Python template output and JavaScript).
"""

from __future__ import annotations

import re
from typing import Any

from guardianshield.findings import FindingType, Severity

# Each entry: (name, compiled_regex, finding_type, severity, description,
#              confidence, cwe_ids)
COMMON_PATTERNS: list[
    tuple[str, re.Pattern[str], FindingType, Severity, str, float, list[str]]
] = [
    # innerHTML assignment (JS / Python template output)
    (
        "xss_innerhtml",
        re.compile(r"""\.innerHTML\s*="""),
        FindingType.XSS,
        Severity.MEDIUM,
        "Potential XSS via innerHTML assignment.",
        0.7,
        ["CWE-79"],
    ),
    # document.write()
    (
        "xss_document_write",
        re.compile(r"""document\.write\s*\("""),
        FindingType.XSS,
        Severity.MEDIUM,
        "Potential XSS via document.write().",
        0.7,
        ["CWE-79"],
    ),
    # eval() with non-literal argument
    (
        "command_injection_eval",
        re.compile(r"""\beval\s*\(\s*(?!["']\s*\))"""),
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        "Code execution risk via eval() with non-literal argument.",
        0.7,
        ["CWE-94", "CWE-95"],
    ),
]

# Remediation guidance keyed by pattern name.
COMMON_REMEDIATION: dict[str, dict[str, Any]] = {
    "xss_innerhtml": {
        "description": "Use textContent for plain text or a sanitizer library (e.g. DOMPurify) for HTML.",
        "before": "element.innerHTML = userInput;",
        "after": "element.textContent = userInput;",
        "auto_fixable": False,
    },
    "xss_document_write": {
        "description": "Avoid document.write(). Use DOM APIs to insert content safely.",
        "before": "document.write(userContent);",
        "after": "document.getElementById('target').textContent = userContent;",
        "auto_fixable": False,
    },
    "command_injection_eval": {
        "description": "Avoid dynamic code execution. Use JSON.parse() for data or a safe alternative.",
        "before": "result = eval(user_expr)",
        "after": "result = json.loads(user_expr)  # or ast.literal_eval()",
        "auto_fixable": False,
    },
}
