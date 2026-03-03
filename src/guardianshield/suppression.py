"""Inline suppression comments for GuardianShield.

Allows developers to suppress specific findings by adding inline comments
in their source code, similar to ``# noqa`` or ``// eslint-disable``.

Syntax (all comment styles supported)::

    code()   # guardianshield:ignore                     -- suppress all
    code()   # guardianshield:ignore[sql_injection]      -- suppress one rule
    code()   # guardianshield:ignore[sql_injection,xss]  -- suppress multiple
    code()   # guardianshield:ignore[xss] -- known safe  -- with reason
    code();  // guardianshield:ignore[xss]               -- JS/Go/Java/C#
    code();  /* guardianshield:ignore */                  -- C-style block
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .findings import Finding


@dataclass
class SuppressionDirective:
    """Parsed inline suppression comment."""

    rules: list[str] = field(default_factory=list)  # empty = suppress all
    reason: str = ""  # from: # guardianshield:ignore[rule] -- reason text
    line_number: int = 0


# Regex: supports # (Python/Ruby), // (JS/Go/Java/C#), /* */ (C-style)
_SUPPRESSION_RE = re.compile(
    r"""(?:\#|//|/\*)\s*guardianshield:ignore(?:\[([^\]]*)\])?\s*(?:\*/)?\s*(?:--\s*(.*))?""",
)


def parse_suppression_comment(line: str) -> SuppressionDirective | None:
    """Parse a suppression directive from a code line.

    Returns None if no directive found. The directive can appear anywhere on
    the line (typically at the end, after the code).
    """
    m = _SUPPRESSION_RE.search(line)
    if m is None:
        return None

    rules_str = m.group(1)
    reason = (m.group(2) or "").strip()

    rules: list[str] = []
    if rules_str:
        rules = [r.strip() for r in rules_str.split(",") if r.strip()]

    return SuppressionDirective(rules=rules, reason=reason)


def filter_suppressed_findings(
    findings: list[Finding], code: str
) -> list[Finding]:
    """Filter findings against inline suppression comments in the code.

    Suppressed findings are NOT removed -- they get
    ``metadata["suppressed"] = True`` and ``metadata["suppression_reason"]``
    set.  This preserves auditability.

    Args:
        findings: List of findings from scanning.
        code: The source code that was scanned (needed to read suppression
            comments).

    Returns:
        The same list of findings, with suppressed ones annotated in metadata.
    """
    if not findings or not code:
        return findings

    # Parse suppression directives by line number (1-based)
    lines = code.splitlines()
    suppressions: dict[int, SuppressionDirective] = {}
    for idx, line in enumerate(lines):
        directive = parse_suppression_comment(line)
        if directive is not None:
            line_num = idx + 1  # findings use 1-based line numbers
            directive.line_number = line_num
            suppressions[line_num] = directive

    if not suppressions:
        return findings

    for finding in findings:
        directive = suppressions.get(finding.line_number)
        if directive is None:
            continue

        # Check if this finding is suppressed
        if not directive.rules:
            # Blanket suppression -- suppress all findings on this line
            finding.metadata["suppressed"] = True
            if directive.reason:
                finding.metadata["suppression_reason"] = directive.reason
        else:
            # Rule-specific -- check if finding's type or pattern_name matches
            finding_type = finding.finding_type.value
            pattern_name = finding.metadata.get("pattern_name", "")
            matched = any(
                rule in (finding_type, pattern_name)
                for rule in directive.rules
            )
            if matched:
                finding.metadata["suppressed"] = True
                if directive.reason:
                    finding.metadata["suppression_reason"] = directive.reason

    return findings
