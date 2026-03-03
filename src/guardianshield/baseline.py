"""Baseline / delta scanning for GuardianShield.

Saves a snapshot of current findings as a baseline JSON file, then
compares future scans against the baseline to surface only new findings.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import __version__
from .dedup import _fingerprint
from .findings import Finding


@dataclass
class BaselineResult:
    """Result of comparing findings against a baseline."""

    new: list[Finding] = field(default_factory=list)  # NOT in baseline
    unchanged: list[Finding] = field(default_factory=list)  # still present from baseline
    fixed: list[str] = field(default_factory=list)  # baseline fingerprints no longer present


_BASELINE_VERSION = "1.0"
_DEFAULT_PATH = ".guardianshield-baseline.json"


def save_baseline(findings: list[Finding], path: str | None = None) -> dict:
    """Save findings as a baseline JSON file.

    Args:
        findings: List of findings to baseline.
        path: Output file path. Defaults to .guardianshield-baseline.json

    Returns:
        Dict with fingerprints count and path.
    """
    if path is None:
        path = _DEFAULT_PATH

    fingerprints = [_fingerprint(f) for f in findings]

    data = {
        "version": _BASELINE_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": __version__,
        "fingerprints": fingerprints,
    }

    # Ensure parent directory exists
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return {"fingerprints": len(fingerprints), "path": path}


def load_baseline(path: str | None = None) -> set[str]:
    """Load fingerprints from a baseline JSON file.

    Args:
        path: Baseline file path. Defaults to .guardianshield-baseline.json

    Returns:
        Set of fingerprint strings.

    Raises:
        FileNotFoundError: If the baseline file does not exist.
        ValueError: If the file format is invalid or version unsupported.
    """
    if path is None:
        path = _DEFAULT_PATH

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Invalid baseline format: expected JSON object")

    version = data.get("version")
    if version != _BASELINE_VERSION:
        raise ValueError(f"Unsupported baseline version: {version}")

    fingerprints = data.get("fingerprints", [])
    if not isinstance(fingerprints, list):
        raise ValueError("Invalid baseline format: 'fingerprints' must be a list")

    return set(fingerprints)


def filter_baseline_findings(
    findings: list[Finding], baseline: set[str]
) -> BaselineResult:
    """Compare findings against a baseline and categorize them.

    Args:
        findings: Current scan findings.
        baseline: Set of fingerprints from the baseline.

    Returns:
        BaselineResult with new, unchanged, and fixed findings.
    """
    new: list[Finding] = []
    unchanged: list[Finding] = []
    seen_fps: set[str] = set()

    for finding in findings:
        fp = _fingerprint(finding)
        seen_fps.add(fp)
        if fp in baseline:
            unchanged.append(finding)
        else:
            new.append(finding)

    fixed = sorted(baseline - seen_fps)

    return BaselineResult(new=new, unchanged=unchanged, fixed=fixed)
