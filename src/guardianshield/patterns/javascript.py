"""JavaScript / TypeScript vulnerability patterns."""

from __future__ import annotations

import re
from typing import Any, Dict

from guardianshield.findings import FindingType, Severity

# Each entry: (name, compiled_regex, finding_type, severity, description,
#              confidence, cwe_ids)
JAVASCRIPT_PATTERNS: list[
    tuple[str, re.Pattern[str], FindingType, Severity, str, float, list[str]]
] = [
    # 1. Dynamic code generation via Function constructor (CWE-94, CWE-95)
    (
        "js_function_constructor",
        re.compile(r"""\bnew\s+Function\s*\("""),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Dynamic code generation via Function constructor.",
        0.8,
        ["CWE-94", "CWE-95"],
    ),
    # 2. Shell command execution in Node.js (CWE-78)
    (
        "js_child_process_exec",
        re.compile(
            r"""(?:child_process|exec|execSync|spawn|spawnSync|execFile)\s*\("""
        ),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Shell command execution in Node.js child_process.",
        0.75,
        ["CWE-78"],
    ),
    # 3. Unsafe HTML rendering in React (CWE-79)
    (
        "js_dangerously_set_html",
        re.compile(r"""dangerouslySetInnerHTML\s*=\s*\{"""),
        FindingType.XSS,
        Severity.HIGH,
        "Unsafe HTML rendering via React dangerouslySetInnerHTML.",
        0.85,
        ["CWE-79"],
    ),
    # 4. Dynamic module loading (CWE-22)
    (
        "js_dynamic_require",
        re.compile(r"""require\s*\(\s*(?:\w+\s*\+|`[^`]*\$\{)"""),
        FindingType.PATH_TRAVERSAL,
        Severity.MEDIUM,
        "Dynamic module loading with user-controlled path.",
        0.65,
        ["CWE-22"],
    ),
    # 5. Template literal interpolation in queries (CWE-89)
    (
        "js_template_sql",
        re.compile(
            r"""`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+[^`]*\$\{""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.HIGH,
        "SQL injection via template literal interpolation.",
        0.85,
        ["CWE-89"],
    ),
    # 6. Prototype pollution via __proto__ (CWE-1321)
    (
        "js_prototype_pollution",
        re.compile(r"""__proto__\s*[\[.]"""),
        FindingType.INSECURE_PATTERN,
        Severity.HIGH,
        "Prototype pollution via __proto__ access.",
        0.8,
        ["CWE-1321"],
    ),
    # 7. DOM manipulation with unsanitized content (CWE-79)
    (
        "js_dom_insert_adjacent",
        re.compile(r"""\.insertAdjacentHTML\s*\("""),
        FindingType.XSS,
        Severity.MEDIUM,
        "DOM manipulation with potentially unsanitized HTML via insertAdjacentHTML.",
        0.7,
        ["CWE-79"],
    ),
]

# Remediation guidance keyed by pattern name.
JAVASCRIPT_REMEDIATION: Dict[str, Dict[str, Any]] = {
    "js_function_constructor": {
        "description": "Avoid new Function(). Use a safe parser or pre-compiled functions.",
        "before": 'const fn = new Function("return " + userInput);',
        "after": "const result = JSON.parse(userInput);",
        "auto_fixable": False,
    },
    "js_child_process_exec": {
        "description": "Use execFile() or spawn() with an argument array instead of shell execution.",
        "before": "child_process.exec('ls ' + userDir)",
        "after": "child_process.execFile('ls', [userDir])",
        "auto_fixable": False,
    },
    "js_dangerously_set_html": {
        "description": "Sanitize HTML with DOMPurify before rendering.",
        "before": "dangerouslySetInnerHTML={{ __html: userContent }}",
        "after": "dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }}",
        "auto_fixable": False,
    },
    "js_dynamic_require": {
        "description": "Use a whitelist of allowed modules instead of dynamic paths.",
        "before": "require(userPath + '/module')",
        "after": "const allowed = {'a': require('./a')}; allowed[key]",
        "auto_fixable": False,
    },
    "js_template_sql": {
        "description": "Use parameterized queries with placeholders.",
        "before": "`SELECT * FROM users WHERE id=${userId}`",
        "after": "db.query('SELECT * FROM users WHERE id=$1', [userId])",
        "auto_fixable": False,
    },
    "js_prototype_pollution": {
        "description": "Reject __proto__, constructor, and prototype keys in user input.",
        "before": "obj[key] = value  // key could be '__proto__'",
        "after": "if (!['__proto__', 'constructor', 'prototype'].includes(key)) obj[key] = value;",
        "auto_fixable": False,
    },
    "js_dom_insert_adjacent": {
        "description": "Sanitize HTML before inserting with insertAdjacentHTML.",
        "before": "el.insertAdjacentHTML('beforeend', userHtml)",
        "after": "el.insertAdjacentHTML('beforeend', DOMPurify.sanitize(userHtml))",
        "auto_fixable": False,
    },
}
