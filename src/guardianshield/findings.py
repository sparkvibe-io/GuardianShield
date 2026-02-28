"""Data models for security findings.

Defines the core :class:`Finding` dataclass and supporting enums used
across all GuardianShield scanners.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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
    DEPENDENCY_VULNERABILITY = "dependency_vulnerability"


@dataclass
class Range:
    """Character-level source range in LSP diagnostic format.

    All values are 0-based to match the LSP specification.
    """

    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def to_lsp(self) -> dict[str, Any]:
        """Serialize to LSP ``Range`` format."""
        return {
            "start": {"line": self.start_line, "character": self.start_col},
            "end": {"line": self.end_line, "character": self.end_col},
        }

    @classmethod
    def from_lsp(cls, data: dict[str, Any]) -> Range:
        """Deserialize from LSP ``Range`` format."""
        return cls(
            start_line=data["start"]["line"],
            start_col=data["start"]["character"],
            end_line=data["end"]["line"],
            end_col=data["end"]["character"],
        )


@dataclass
class Remediation:
    """Machine-readable fix suggestion for a finding.

    Attributes:
        description: Human-readable description of the fix.
        before: Example of the vulnerable code.
        after: Example of the fixed code.
        auto_fixable: Whether the fix can be applied automatically.
    """

    description: str
    before: str = ""
    after: str = ""
    auto_fixable: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict, omitting empty strings."""
        d: dict[str, Any] = {"description": self.description}
        if self.before:
            d["before"] = self.before
        if self.after:
            d["after"] = self.after
        if self.auto_fixable:
            d["auto_fixable"] = self.auto_fixable
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Remediation:
        """Deserialize from a plain dict."""
        return cls(
            description=data.get("description", ""),
            before=data.get("before", ""),
            after=data.get("after", ""),
            auto_fixable=data.get("auto_fixable", False),
        )


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
        range: Precise character range in LSP format (0-based).
        confidence: Detection confidence (0.0-1.0).
        cwe_ids: List of CWE identifiers (e.g. ``["CWE-89"]``).
        remediation: Machine-readable fix suggestion.
    """

    finding_type: FindingType
    severity: Severity
    message: str
    matched_text: str = ""
    line_number: int = 0
    file_path: str | None = None
    scanner: str = ""
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    metadata: dict[str, Any] = field(default_factory=dict)
    range: Range | None = None
    confidence: float | None = None
    cwe_ids: list[str] = field(default_factory=list)
    remediation: Remediation | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict.

        ``None`` fields and empty ``cwe_ids`` are omitted for backward
        compatibility — consumers that only know v0.1 fields will not
        see unexpected keys.
        """
        d: dict[str, Any] = {
            "finding_type": self.finding_type.value,
            "severity": self.severity.value,
            "message": self.message,
            "matched_text": self.matched_text,
            "line_number": self.line_number,
            "file_path": self.file_path,
            "scanner": self.scanner,
            "finding_id": self.finding_id,
            "metadata": self.metadata,
        }
        if self.range is not None:
            d["range"] = self.range.to_lsp()
        if self.confidence is not None:
            d["confidence"] = self.confidence
        if self.cwe_ids:
            d["cwe_ids"] = list(self.cwe_ids)
        if self.remediation is not None:
            d["remediation"] = self.remediation.to_dict()
        return d

    def to_json(self) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Deserialize from a plain dict.

        Tolerates missing v0.2 fields so older serialized findings
        can be loaded without error.
        """
        data = dict(data)  # shallow copy
        data["finding_type"] = FindingType(data["finding_type"])
        data["severity"] = Severity(data["severity"])

        # Reconstitute nested dataclasses when present.
        raw_range = data.pop("range", None)
        if raw_range is not None:
            data["range"] = Range.from_lsp(raw_range)

        raw_remediation = data.pop("remediation", None)
        if raw_remediation is not None:
            data["remediation"] = Remediation.from_dict(raw_remediation)

        # Ensure list default for cwe_ids.
        if "cwe_ids" not in data:
            data["cwe_ids"] = []

        return cls(**data)
