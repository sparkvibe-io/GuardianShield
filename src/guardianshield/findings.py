"""Data models for security findings.

Defines the core :class:`Finding` dataclass and supporting enums used
across all GuardianShield scanners.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Severity level for a security finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    """Type/category of a security finding."""

    SECRET = "secret"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_FUNCTION = "insecure_function"
    INSECURE_PATTERN = "insecure_pattern"
    PROMPT_INJECTION = "prompt_injection"
    PII_LEAK = "pii_leak"
    CONTENT_VIOLATION = "content_violation"


@dataclass
class Finding:
    """A single security finding from any scanner.

    Attributes:
        finding_type: The category of the finding.
        severity: How severe the finding is.
        message: Human-readable description.
        matched_text: The text that triggered the finding (redacted for secrets/PII).
        line_number: 1-based line number where the finding was detected.
        file_path: Optional file path associated with the finding.
        scanner: Name of the scanner that produced this finding.
        finding_id: Unique identifier for this finding.
        metadata: Additional scanner-specific data.
    """

    finding_type: FindingType
    severity: Severity
    message: str
    matched_text: str = ""
    line_number: int = 0
    file_path: Optional[str] = None
    scanner: str = ""
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        d = asdict(self)
        d["finding_type"] = self.finding_type.value
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Deserialize from a plain dict."""
        data = dict(data)  # shallow copy
        data["finding_type"] = FindingType(data["finding_type"])
        data["severity"] = Severity(data["severity"])
        return cls(**data)
