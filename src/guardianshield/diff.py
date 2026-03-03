"""Unified diff parsing and bulk scanning.

Parses unified diffs (e.g. from ``git diff``) into structured hunks
and scans only the added lines for vulnerabilities.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .patterns import EXTENSION_MAP

if TYPE_CHECKING:
    from .core import GuardianShield
    from .findings import Finding


@dataclass
class DiffHunk:
    """Parsed hunk from a unified diff."""

    file_path: str = ""
    added_lines: dict[int, str] = field(default_factory=dict)  # line_number -> content
    language: str | None = None


# Regex for diff headers
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_unified_diff(diff_text: str) -> list[DiffHunk]:
    """Parse a unified diff into DiffHunks.

    Extracts file paths and added lines (+ prefixed) with correct line numbers.
    Only processes text files — binary diffs are skipped.

    Args:
        diff_text: The unified diff text (e.g., from ``git diff``).

    Returns:
        List of DiffHunk, one per file in the diff.
    """
    if not diff_text or not diff_text.strip():
        return []

    hunks: list[DiffHunk] = []
    current_hunk: DiffHunk | None = None
    current_line_num = 0

    for line in diff_text.splitlines():
        # New file
        file_match = _DIFF_FILE_RE.match(line)
        if file_match:
            file_path = file_match.group(1)
            # Detect language from extension
            ext = os.path.splitext(file_path)[1].lower()
            language = EXTENSION_MAP.get(ext)
            current_hunk = DiffHunk(file_path=file_path, language=language)
            hunks.append(current_hunk)
            continue

        # Hunk header
        hunk_match = _HUNK_HEADER_RE.match(line)
        if hunk_match:
            current_line_num = int(hunk_match.group(1))
            continue

        if current_hunk is None:
            continue

        # Added line
        if line.startswith("+") and not line.startswith("+++"):
            current_hunk.added_lines[current_line_num] = line[1:]
            current_line_num += 1
        elif line.startswith("-") and not line.startswith("---"):
            # Removed line — don't increment new-file line counter
            pass
        else:
            # Context line (or empty) — increment line counter
            current_line_num += 1

    return hunks


def scan_diff(shield: GuardianShield, diff_text: str) -> list[Finding]:
    """Parse a unified diff and scan only added lines for vulnerabilities.

    Args:
        shield: GuardianShield instance to use for scanning.
        diff_text: Unified diff text.

    Returns:
        List of findings, only from added lines with correct line numbers.
    """

    hunks = parse_unified_diff(diff_text)
    all_findings: list[Finding] = []

    for hunk in hunks:
        if not hunk.added_lines:
            continue

        # Reconstruct code from added lines and scan it
        added_code = "\n".join(hunk.added_lines.values())
        if not added_code.strip():
            continue

        findings = shield.scan_code(
            added_code,
            file_path=hunk.file_path,
            language=hunk.language,
        )

        # Map finding line numbers back to actual diff line numbers
        added_line_nums = sorted(hunk.added_lines.keys())
        for finding in findings:
            # finding.line_number is 1-based within the added_code
            idx = finding.line_number - 1
            if 0 <= idx < len(added_line_nums):
                finding.line_number = added_line_nums[idx]
                finding.file_path = hunk.file_path
            all_findings.append(finding)

    return all_findings
