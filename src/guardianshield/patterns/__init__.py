"""Language-specific vulnerability pattern sets."""

from guardianshield.patterns.common import COMMON_PATTERNS, COMMON_REMEDIATION
from guardianshield.patterns.python import PYTHON_PATTERNS, PYTHON_REMEDIATION
from guardianshield.patterns.javascript import JAVASCRIPT_PATTERNS, JAVASCRIPT_REMEDIATION

# Map of language identifier -> pattern list.
# Keys should be lowercase.  Multiple aliases can point to the same list.
LANGUAGE_PATTERNS: dict[str, list] = {
    "python": PYTHON_PATTERNS,
    "py": PYTHON_PATTERNS,
    "javascript": JAVASCRIPT_PATTERNS,
    "js": JAVASCRIPT_PATTERNS,
    "typescript": JAVASCRIPT_PATTERNS,
    "ts": JAVASCRIPT_PATTERNS,
    "jsx": JAVASCRIPT_PATTERNS,
    "tsx": JAVASCRIPT_PATTERNS,
}

# File extension -> language identifier mapping
EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}

# Combined remediation map (all languages).
REMEDIATION_MAP: dict[str, dict] = {
    **COMMON_REMEDIATION,
    **PYTHON_REMEDIATION,
    **JAVASCRIPT_REMEDIATION,
}

__all__ = [
    "COMMON_PATTERNS",
    "COMMON_REMEDIATION",
    "PYTHON_PATTERNS",
    "PYTHON_REMEDIATION",
    "JAVASCRIPT_PATTERNS",
    "JAVASCRIPT_REMEDIATION",
    "LANGUAGE_PATTERNS",
    "EXTENSION_MAP",
    "REMEDIATION_MAP",
]
