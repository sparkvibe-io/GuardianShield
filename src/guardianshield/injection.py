"""Prompt injection detection module.

Scans input text for patterns commonly used in prompt injection attacks,
including instruction overrides, role hijacking, system prompt extraction,
delimiter abuse, ChatML injection, jailbreak keywords, information extraction,
encoding evasion, and instruction tag injection.
"""

from __future__ import annotations

import re
from typing import Any

from guardianshield.findings import Finding, FindingType, Range, Severity

# ---------------------------------------------------------------------------
# Compiled detection patterns
# ---------------------------------------------------------------------------
# Each entry: (name, compiled_regex, severity, description, confidence, cwe_ids)

_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str, float, list[str]]] = [
    # 1. Instruction Override
    (
        "instruction_override",
        re.compile(
            r"(?:ignore\s+(?:all\s+|previous\s+)instructions"
            r"|disregard\s+(?:all\s+|previous\s+)(?:instructions|directives)"
            r"|forget\s+your\s+instructions"
            r"|override\s+(?:previous\s+|prior\s+)?instructions)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Attempt to override or nullify the model's existing instructions.",
        0.9,
        ["CWE-77"],
    ),
    # 2. Role Hijacking
    (
        "role_hijacking",
        re.compile(
            r"(?:you\s+are\s+now\b"
            r"|act\s+as\b"
            r"|pretend\s+to\s+be\b"
            r"|roleplay\s+as\b"
            r"|you\s+must\s+act\b)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Attempt to reassign the model's role or persona.",
        0.6,
        ["CWE-77"],
    ),
    # 3. System Prompt Extraction
    (
        "system_prompt_extraction",
        re.compile(
            r"(?:show\s+(?:me\s+)?your\s+system\s+prompt"
            r"|reveal\s+your\s+instructions"
            r"|what\s+are\s+your\s+rules"
            r"|print\s+your\s+prompt"
            r"|display\s+your\s+(?:system\s+)?instructions"
            r"|output\s+your\s+(?:system\s+)?prompt)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Attempt to extract the model's system prompt or instructions.",
        0.8,
        ["CWE-77"],
    ),
    # 4. Delimiter / Separator Abuse
    (
        "delimiter_abuse",
        re.compile(
            r"(?:^|\n)(?:-{3,}|={3,}|\*{3,}|`{3,})(?:\s*\n)(?:-{3,}|={3,}|\*{3,}|`{3,})",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "Suspicious use of repeated delimiters that may break prompt context.",
        0.4,
        ["CWE-77"],
    ),
    # 5. ChatML Injection
    (
        "chatml_injection",
        re.compile(
            r"(?:<\|system\|>"
            r"|<\|user\|>"
            r"|<\|assistant\|>"
            r"|<\|endoftext\|>"
            r"|\[INST\]"
            r"|\[/INST\])",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "ChatML or special token injection that may manipulate conversation structure.",
        0.95,
        ["CWE-77"],
    ),
    # 6. Jailbreak Keywords
    (
        "jailbreak_keywords",
        re.compile(
            r"(?:\bDAN\b"
            r"|\bjailbreak\b"
            r"|do\s+anything\s+now"
            r"|\bbypass\b\s*(?:filters?|restrictions?|safety|guidelines?|rules?)?"
            r"|unrestricted\s+mode)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Jailbreak attempt to remove safety restrictions.",
        0.7,
        ["CWE-77"],
    ),
    # 7. Information Extraction
    (
        "information_extraction",
        re.compile(
            r"(?:list\s+(?:all\s+)?(?:your\s+)?tools"
            r"|show\s+(?:all\s+)?available\s+functions"
            r"|what\s+tools\s+do\s+you\s+have"
            r"|enumerate\s+your\s+capabilities"
            r"|list\s+(?:all\s+)?available\s+(?:tools|functions|commands))",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "Attempt to enumerate the model's internal tools or capabilities.",
        0.5,
        ["CWE-77"],
    ),
    # 8. Encoding Evasion
    (
        "encoding_evasion",
        re.compile(
            r"(?:decode\s+(?:this\s+)?base64"
            r"|base64[\s\-_]*(?:decode|encoded?)"
            r"|convert\s+(?:from\s+)?hex(?:adecimal)?"
            r"|\brot13\b"
            r"|hex[\s\-_]*(?:decode|encoded?)"
            r"|decode\s+(?:this\s+)?hex)",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "Attempt to use encoding schemes to evade content filters.",
        0.5,
        ["CWE-77"],
    ),
    # 9. Instruction Tags
    (
        "instruction_tags",
        re.compile(
            r"(?:\{\{SYSTEM\}\}"
            r"|<<SYS>>"
            r"|<</SYS>>"
            r"|\[system\]"
            r"|<system>"
            r"|</system>"
            r"|\[/system\])",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Injection of instruction/system tags to manipulate prompt boundaries.",
        0.85,
        ["CWE-77"],
    ),
]

# ---------------------------------------------------------------------------
# Severity ranking for sensitivity filtering
# ---------------------------------------------------------------------------
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_SENSITIVITY_THRESHOLD: dict[str, int] = {
    "low": _SEVERITY_RANK[Severity.CRITICAL],   # CRITICAL only
    "medium": _SEVERITY_RANK[Severity.MEDIUM],   # MEDIUM and above (skip LOW/INFO)
    "high": _SEVERITY_RANK[Severity.INFO],        # everything
}


def _line_number_for_position(text: str, pos: int) -> int:
    """Return the 1-based line number for a character position in *text*."""
    return text[:pos].count("\n") + 1


def _position_to_line_col(text: str, pos: int) -> tuple[int, int]:
    """Convert absolute position to 0-based (line, col)."""
    line = text[:pos].count("\n")
    last_nl = text.rfind("\n", 0, pos)
    col = pos if last_nl == -1 else pos - last_nl - 1
    return line, col


def check_injection(text: str, sensitivity: str = "medium") -> list[Finding]:
    """Scan *text* for prompt injection patterns.

    Parameters
    ----------
    text:
        The full input text to analyse.
    sensitivity:
        Detection sensitivity level -- ``"low"`` reports only CRITICAL
        findings, ``"medium"`` (default) skips LOW/INFO, and ``"high"``
        reports everything.

    Returns
    -------
    list[Finding]
        A list of :class:`Finding` objects for every match, sorted by line
        number.
    """
    if not text:
        return []

    threshold = _SENSITIVITY_THRESHOLD.get(sensitivity, _SENSITIVITY_THRESHOLD["medium"])
    findings: list[Finding] = []

    for name, pattern, severity, description, confidence, cwe_ids in _PATTERNS:
        # Apply sensitivity filter early to avoid unnecessary work.
        if _SEVERITY_RANK[severity] < threshold:
            continue

        for match in pattern.finditer(text):
            matched_text = match.group()
            if len(matched_text) > 100:
                matched_text = matched_text[:100]

            line_number = _line_number_for_position(text, match.start())

            start_line, start_col = _position_to_line_col(text, match.start())
            end_line, end_col = _position_to_line_col(text, match.end())
            range_obj = Range(
                start_line=start_line,
                start_col=start_col,
                end_line=end_line,
                end_col=end_col,
            )

            metadata: dict[str, Any] = {"injection_type": name}

            findings.append(
                Finding(
                    finding_type=FindingType.PROMPT_INJECTION,
                    severity=severity,
                    message=description,
                    matched_text=matched_text,
                    line_number=line_number,
                    scanner="injection_detector",
                    metadata=metadata,
                    range=range_obj,
                    confidence=confidence,
                    cwe_ids=list(cwe_ids),
                )
            )

    # Sort by line number for deterministic, readable output.
    findings.sort(key=lambda f: f.line_number)
    return findings
