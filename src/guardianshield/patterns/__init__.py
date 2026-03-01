"""Language-specific vulnerability pattern sets."""

from guardianshield.patterns.common import COMMON_PATTERNS, COMMON_REMEDIATION
from guardianshield.patterns.csharp import CSHARP_PATTERNS, CSHARP_REMEDIATION
from guardianshield.patterns.go import GO_PATTERNS, GO_REMEDIATION
from guardianshield.patterns.java import JAVA_PATTERNS, JAVA_REMEDIATION
from guardianshield.patterns.javascript import JAVASCRIPT_PATTERNS, JAVASCRIPT_REMEDIATION
from guardianshield.patterns.php import PHP_PATTERNS, PHP_REMEDIATION
from guardianshield.patterns.python import PYTHON_PATTERNS, PYTHON_REMEDIATION
from guardianshield.patterns.ruby import RUBY_PATTERNS, RUBY_REMEDIATION

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
    "csharp": CSHARP_PATTERNS,
    "cs": CSHARP_PATTERNS,
    "ruby": RUBY_PATTERNS,
    "rb": RUBY_PATTERNS,
    "php": PHP_PATTERNS,
    "java": JAVA_PATTERNS,
    "go": GO_PATTERNS,
    "golang": GO_PATTERNS,
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
    ".cs": "csharp",
    ".rb": "ruby",
    ".rake": "ruby",
    ".gemspec": "ruby",
    ".php": "php",
    ".java": "java",
    ".go": "go",
}

# Combined remediation map (all languages).
REMEDIATION_MAP: dict[str, dict] = {
    **COMMON_REMEDIATION,
    **PYTHON_REMEDIATION,
    **JAVASCRIPT_REMEDIATION,
    **CSHARP_REMEDIATION,
    **RUBY_REMEDIATION,
    **PHP_REMEDIATION,
    **JAVA_REMEDIATION,
    **GO_REMEDIATION,
}

__all__ = [
    "COMMON_PATTERNS",
    "COMMON_REMEDIATION",
    "PYTHON_PATTERNS",
    "PYTHON_REMEDIATION",
    "JAVASCRIPT_PATTERNS",
    "JAVASCRIPT_REMEDIATION",
    "CSHARP_PATTERNS",
    "CSHARP_REMEDIATION",
    "RUBY_PATTERNS",
    "RUBY_REMEDIATION",
    "PHP_PATTERNS",
    "PHP_REMEDIATION",
    "JAVA_PATTERNS",
    "JAVA_REMEDIATION",
    "GO_PATTERNS",
    "GO_REMEDIATION",
    "LANGUAGE_PATTERNS",
    "EXTENSION_MAP",
    "REMEDIATION_MAP",
]
