"""Finding enrichment module.

Adds structured context to findings so that consumers (AI agents, humans,
IDEs) can understand *why* a pattern matched, see surrounding code, and
follow authoritative references (CWE, CVE, OWASP) without needing
additional lookups.
"""

from __future__ import annotations

from typing import Any

from .findings import Finding

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) mapping for common CWEs
# ---------------------------------------------------------------------------

_CWE_OWASP_MAP: dict[str, tuple[str, str]] = {
    "CWE-77": ("A03:2021", "Injection"),
    "CWE-78": ("A03:2021", "Injection"),
    "CWE-79": ("A03:2021", "Injection"),
    "CWE-89": ("A03:2021", "Injection"),
    "CWE-90": ("A03:2021", "Injection"),
    "CWE-91": ("A03:2021", "Injection"),
    "CWE-94": ("A03:2021", "Injection"),
    "CWE-95": ("A03:2021", "Injection"),
    "CWE-96": ("A03:2021", "Injection"),
    "CWE-22": ("A01:2021", "Broken Access Control"),
    "CWE-23": ("A01:2021", "Broken Access Control"),
    "CWE-36": ("A01:2021", "Broken Access Control"),
    "CWE-73": ("A01:2021", "Broken Access Control"),
    "CWE-259": ("A07:2021", "Identification and Authentication Failures"),
    "CWE-287": ("A07:2021", "Identification and Authentication Failures"),
    "CWE-798": ("A07:2021", "Identification and Authentication Failures"),
    "CWE-321": ("A02:2021", "Cryptographic Failures"),
    "CWE-327": ("A02:2021", "Cryptographic Failures"),
    "CWE-328": ("A02:2021", "Cryptographic Failures"),
    "CWE-330": ("A02:2021", "Cryptographic Failures"),
    "CWE-326": ("A02:2021", "Cryptographic Failures"),
    "CWE-311": ("A02:2021", "Cryptographic Failures"),
    "CWE-312": ("A02:2021", "Cryptographic Failures"),
    "CWE-359": ("A02:2021", "Cryptographic Failures"),
    "CWE-502": ("A08:2021", "Software and Data Integrity Failures"),
    "CWE-611": ("A05:2021", "Security Misconfiguration"),
    "CWE-776": ("A05:2021", "Security Misconfiguration"),
    "CWE-918": ("A10:2021", "Server-Side Request Forgery"),
    "CWE-200": ("A01:2021", "Broken Access Control"),
    "CWE-209": ("A05:2021", "Security Misconfiguration"),
    "CWE-250": ("A04:2021", "Insecure Design"),
    "CWE-269": ("A01:2021", "Broken Access Control"),
    "CWE-284": ("A01:2021", "Broken Access Control"),
    "CWE-285": ("A01:2021", "Broken Access Control"),
    "CWE-352": ("A01:2021", "Broken Access Control"),
    "CWE-434": ("A04:2021", "Insecure Design"),
    "CWE-601": ("A01:2021", "Broken Access Control"),
    "CWE-732": ("A01:2021", "Broken Access Control"),
    "CWE-915": ("A08:2021", "Software and Data Integrity Failures"),
    "CWE-1004": ("A07:2021", "Identification and Authentication Failures"),
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def extract_code_context(
    source: str,
    line_number: int,
    window: int = 3,
) -> dict[str, Any]:
    """Extract surrounding lines of code around a finding.

    Args:
        source: Full source text.
        line_number: 1-based line number of the finding.
        window: Number of context lines before and after.

    Returns:
        A dict with ``before`` (list of strings), ``target_line`` (str),
        ``after`` (list of strings), and ``line_number`` (int).
    """
    lines = source.splitlines()
    idx = line_number - 1  # convert to 0-based

    if idx < 0 or idx >= len(lines):
        return {
            "before": [],
            "target_line": "",
            "after": [],
            "line_number": line_number,
        }

    start = max(0, idx - window)
    end = min(len(lines), idx + window + 1)

    return {
        "before": lines[start:idx],
        "target_line": lines[idx],
        "after": lines[idx + 1 : end],
        "line_number": line_number,
    }


def build_match_explanation(
    pattern_name: str,
    finding_type: str,
    matched_text: str,
    confidence: float,
) -> str:
    """Build a human-readable explanation of why a pattern matched.

    Args:
        pattern_name: Internal name of the pattern (e.g. ``"sql_string_format"``).
        finding_type: The finding type value (e.g. ``"sql_injection"``).
        matched_text: The text that triggered the match.
        confidence: Detection confidence (0.0-1.0).

    Returns:
        A sentence explaining the match.
    """
    display_type = finding_type.replace("_", " ")
    # Truncate very long matched text for readability
    display_match = matched_text
    if len(display_match) > 80:
        display_match = display_match[:77] + "..."
    return (
        f"This code matches the '{pattern_name}' pattern "
        f"(confidence: {confidence:.0%}) because "
        f"`{display_match}` indicates a potential {display_type} vulnerability."
    )


def build_references(
    cwe_ids: list[str],
    vuln_id: str | None = None,
) -> list[dict[str, str]]:
    """Build reference links for CWEs, CVEs, and OWASP mappings.

    Args:
        cwe_ids: List of CWE identifiers (e.g. ``["CWE-89"]``).
        vuln_id: Optional vulnerability ID (CVE or GHSA).

    Returns:
        A list of reference dicts with ``type``, ``id``, ``url``, and
        optionally ``name`` keys.
    """
    refs: list[dict[str, str]] = []

    for cwe in cwe_ids:
        # Extract numeric ID from "CWE-89" format
        cwe_num = cwe.replace("CWE-", "") if cwe.startswith("CWE-") else cwe
        refs.append({
            "type": "CWE",
            "id": cwe,
            "url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
        })

        # Add OWASP mapping if available
        owasp = _CWE_OWASP_MAP.get(cwe)
        if owasp:
            owasp_id, owasp_name = owasp
            # Avoid duplicate OWASP entries
            if not any(r.get("id") == owasp_id for r in refs):
                refs.append({
                    "type": "OWASP",
                    "id": owasp_id,
                    "name": owasp_name,
                })

    if vuln_id:
        if vuln_id.startswith("CVE-"):
            refs.append({
                "type": "CVE",
                "id": vuln_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
            })
        elif vuln_id.startswith("GHSA-"):
            refs.append({
                "type": "OSV",
                "id": vuln_id,
                "url": f"https://osv.dev/vulnerability/{vuln_id}",
            })
        else:
            refs.append({
                "type": "OSV",
                "id": vuln_id,
                "url": f"https://osv.dev/vulnerability/{vuln_id}",
            })

    return refs


def enrich_finding(
    finding: Finding,
    source: str | None = None,
) -> Finding:
    """Enrich a finding with structured context details.

    Populates ``finding.details`` with code context, match explanation,
    references, and scanner metadata.  Mutates the finding in-place and
    returns it for convenience.

    Args:
        finding: The finding to enrich.
        source: Full source text (for extracting code context).

    Returns:
        The same finding, now with ``details`` populated.
    """
    # Merge into existing details dict (preserving scanner-specific fields
    # that were set before this call).
    details = finding.details

    # Code context (only when source text is available)
    if source and finding.line_number > 0:
        details["code_context"] = extract_code_context(
            source, finding.line_number
        )

    # Match explanation
    pattern_name = finding.metadata.get(
        "pattern_name",
        finding.metadata.get("injection_type", ""),
    )
    if pattern_name and finding.matched_text:
        details["match_explanation"] = build_match_explanation(
            pattern_name=pattern_name,
            finding_type=finding.finding_type.value,
            matched_text=finding.matched_text,
            confidence=finding.confidence or 0.0,
        )

    # References
    vuln_id = finding.metadata.get("vuln_id")
    aliases = finding.metadata.get("aliases", [])
    # Use first CVE alias as vuln_id if available
    if not vuln_id and aliases:
        for alias in aliases:
            if alias.startswith("CVE-"):
                vuln_id = alias
                break
    if finding.cwe_ids or vuln_id:
        details["references"] = build_references(
            finding.cwe_ids, vuln_id=vuln_id
        )

    # Scanner metadata
    details["vulnerability_class"] = finding.finding_type.value
    if finding.scanner:
        details["scanner"] = finding.scanner
    if pattern_name:
        details["pattern_name"] = pattern_name

    return finding
