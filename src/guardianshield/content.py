"""Heuristic content moderation scanner.

Performs keyword/pattern-based content moderation across violence, self-harm,
and illegal-activity categories.  Patterns are intentionally tuned to match
*instructional* or *encouraging* content rather than neutral mentions
(e.g. news, history, security research) so as to minimise false positives.
"""

from __future__ import annotations

import re

from guardianshield.enrichment import enrich_finding
from guardianshield.findings import Finding, FindingType, Range, Severity

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------
# Each entry is (compiled_regex, human-readable description, confidence,
#                cwe_ids).
# All patterns are case-insensitive and use word boundaries where appropriate
# to reduce false positives on partial matches.

_FLAGS = re.IGNORECASE

ContentPattern = tuple[re.Pattern[str], str, float, list[str]]

CONTENT_PATTERNS: dict[str, list[ContentPattern]] = {
    # ------------------------------------------------------------------
    # VIOLENCE  (severity: HIGH)
    # Target: graphic descriptions, instructions, or encouragement of
    # violence.  Avoid matching educational / news / historical usage.
    # ------------------------------------------------------------------
    "violence": [
        (
            re.compile(
                r"\b(?:how\s+to|instructions?\s+(?:for|to|on)|steps?\s+to|guide\s+to)\s+"
                r"(?:kill|murder|assassinate|strangle|stab|shoot|dismember)\b",
                _FLAGS,
            ),
            "instructions_to_kill",
            0.8,
            [],
        ),
        (
            re.compile(
                r"\b(?:i\s+(?:will|want\s+to|am\s+going\s+to|plan\s+to)|let'?s)\s+"
                r"(?:kill|murder|assassinate|strangle|stab|shoot|attack|assault)\b",
                _FLAGS,
            ),
            "intent_to_harm",
            0.8,
            [],
        ),
        (
            re.compile(
                r"\b(?:you\s+should|you\s+must|you\s+need\s+to|go\s+ahead\s+and)\s+"
                r"(?:kill|murder|attack|assault|shoot|stab|strangle)\b",
                _FLAGS,
            ),
            "encouraging_violence",
            0.7,
            [],
        ),
        (
            re.compile(
                r"\b(?:best\s+(?:way|method)s?\s+to\s+(?:kill|murder|torture|attack))\b",
                _FLAGS,
            ),
            "best_methods_violence",
            0.7,
            [],
        ),
        (
            re.compile(
                r"\b(?:make|build|construct|assemble)\s+(?:a\s+)?(?:bomb|explosive|ied|weapon)\b",
                _FLAGS,
            ),
            "weapon_construction",
            0.8,
            [],
        ),
    ],
    # ------------------------------------------------------------------
    # SELF-HARM  (severity: CRITICAL)
    # ------------------------------------------------------------------
    "self_harm": [
        (
            re.compile(
                r"\b(?:how\s+to|ways?\s+to|methods?\s+(?:of|to|for)|steps?\s+to|guide\s+to)\s+"
                r"(?:kill\s+yourself|commit\s+suicide|end\s+(?:your|my)\s+life|hang\s+yourself"
                r"|slit\s+(?:your|my)\s+wrists?|overdose)\b",
                _FLAGS,
            ),
            "self_harm_instructions",
            0.9,
            [],
        ),
        (
            re.compile(
                r"\b(?:you\s+should|you\s+deserve\s+to|just\s+go\s+ahead\s+and|why\s+don'?t\s+you)"
                r"(?:\s+\w+){0,3}?\s+"
                r"(?:kill\s+yourself|end\s+(?:your|it)\s+(?:all|life)|hurt\s+yourself"
                r"|cut\s+yourself)\b",
                _FLAGS,
            ),
            "encouraging_self_harm",
            0.9,
            [],
        ),
        (
            re.compile(
                r"\b(?:best|easiest|most\s+painless|quickest|effective)\s+"
                r"(?:way|method)s?\s+to\s+(?:die|end\s+(?:it|your\s+life)|kill\s+yourself"
                r"|commit\s+suicide)\b",
                _FLAGS,
            ),
            "self_harm_best_methods",
            0.8,
            [],
        ),
        (
            re.compile(
                r"\b(?:i\s+(?:want\s+to|am\s+going\s+to|plan\s+to|will))\s+"
                r"(?:kill\s+myself|end\s+my\s+life|hurt\s+myself|cut\s+myself"
                r"|commit\s+suicide)\b",
                _FLAGS,
            ),
            "self_harm_intent",
            0.9,
            [],
        ),
        (
            re.compile(
                r"\b(?:lethal\s+dose|fatal\s+amount)\s+of\b",
                _FLAGS,
            ),
            "lethal_dosage_info",
            0.8,
            [],
        ),
    ],
    # ------------------------------------------------------------------
    # ILLEGAL ACTIVITY  (severity: HIGH)
    # Target: instructional content on drug manufacturing, fraud, or
    # hacking (not security research / CTFs / education).
    # ------------------------------------------------------------------
    "illegal_activity": [
        (
            re.compile(
                r"\b(?:how\s+to|instructions?\s+(?:for|to|on)|steps?\s+to|guide\s+to|recipe\s+(?:for|to))\s+"
                r"(?:make|cook|synthesize|manufacture|produce)\s+"
                r"(?:meth|methamphetamine|cocaine|crack|heroin|fentanyl|lsd|mdma|ecstasy)\b",
                _FLAGS,
            ),
            "drug_manufacturing",
            0.8,
            [],
        ),
        (
            re.compile(
                r"\b(?:how\s+to|instructions?\s+(?:for|to|on)|steps?\s+to|guide\s+to)\s+"
                r"(?:hack\s+into|break\s+into|compromise|exploit)\s+"
                r"(?:someone'?s?|a\s+person'?s?|their|bank|email|account|system)\b",
                _FLAGS,
            ),
            "hacking_instructions",
            0.7,
            [],
        ),
        (
            re.compile(
                r"\b(?:how\s+to|instructions?\s+(?:for|to|on)|steps?\s+to|guide\s+to)\s+"
                r"(?:commit|perform|carry\s+out|execute)\s+"
                r"(?:fraud|identity\s+theft|money\s+laundering|tax\s+evasion"
                r"|credit\s+card\s+fraud|wire\s+fraud)\b",
                _FLAGS,
            ),
            "fraud_instructions",
            0.7,
            [],
        ),
        (
            re.compile(
                r"\b(?:how\s+to|instructions?\s+(?:for|to|on)|steps?\s+to|guide\s+to)\s+"
                r"(?:forge|counterfeit|fake)\s+(?:a\s+)?"
                r"(?:documents?|passport|id|identity|money|currency|checks?|cheques?)\b",
                _FLAGS,
            ),
            "forgery_instructions",
            0.7,
            [],
        ),
        (
            re.compile(
                r"\b(?:how\s+to|instructions?\s+(?:for|to|on)|steps?\s+to|guide\s+to)\s+"
                r"(?:steal|shoplift|rob|burglarize|loot)\b",
                _FLAGS,
            ),
            "theft_instructions",
            0.8,
            [],
        ),
    ],
}

# Map categories to their severity level.
_CATEGORY_SEVERITY: dict[str, Severity] = {
    "violence": Severity.HIGH,
    "self_harm": Severity.CRITICAL,
    "illegal_activity": Severity.HIGH,
}

# Sensitivity thresholds -- which severities are *included* for each level.
_SENSITIVITY_ALLOWED: dict[str, set[Severity]] = {
    "low": {Severity.CRITICAL},
    "medium": {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM},
    "high": {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO},
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_content(
    text: str,
    sensitivity: str = "medium",
    blocked_categories: list[str] | None = None,
) -> list[Finding]:
    """Scan *text* for content-policy violations.

    Parameters
    ----------
    text:
        The text to moderate.
    sensitivity:
        One of ``"low"``, ``"medium"``, or ``"high"``.
        * ``"low"``  -- only report CRITICAL findings.
        * ``"medium"`` -- report CRITICAL, HIGH, and MEDIUM findings.
        * ``"high"`` -- report all severities.
    blocked_categories:
        If provided and non-empty, only scan these categories.
        If ``None`` or empty, scan **all** categories.

    Returns
    -------
    list[Finding]
        A (possibly empty) list of content-violation findings.
    """
    allowed_sevs = _SENSITIVITY_ALLOWED.get(sensitivity, _SENSITIVITY_ALLOWED["medium"])

    # Decide which categories to scan.
    if blocked_categories:
        categories_to_check = [c for c in blocked_categories if c in CONTENT_PATTERNS]
    else:
        categories_to_check = list(CONTENT_PATTERNS.keys())

    findings: list[Finding] = []
    lines = text.splitlines()

    for category in categories_to_check:
        sev = _CATEGORY_SEVERITY[category]

        # Sensitivity gate: skip this category entirely if its severity
        # is outside the allowed set.
        if sev not in allowed_sevs:
            continue

        patterns = CONTENT_PATTERNS[category]

        for line_idx, line in enumerate(lines, start=1):
            for pattern, description, confidence, cwe_ids in patterns:
                match = pattern.search(line)
                if match:
                    matched_text = match.group()
                    if len(matched_text) > 100:
                        matched_text = matched_text[:100]

                    range_obj = Range(
                        start_line=line_idx - 1,
                        start_col=match.start(),
                        end_line=line_idx - 1,
                        end_col=match.end(),
                    )

                    finding = Finding(
                        finding_type=FindingType.CONTENT_VIOLATION,
                        severity=sev,
                        message=(
                            f"Content violation detected: {category} "
                            f"({description})"
                        ),
                        matched_text=matched_text,
                        line_number=line_idx,
                        scanner="content_moderator",
                        metadata={
                            "category": category,
                            "pattern_name": description,
                        },
                        range=range_obj,
                        confidence=confidence,
                        cwe_ids=list(cwe_ids),
                    )
                    finding.details["content_category"] = category
                    enrich_finding(finding, source=text)
                    findings.append(finding)

    return findings
