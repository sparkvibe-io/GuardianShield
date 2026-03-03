"""Result pipeline for multi-engine finding dedup and merge.

When multiple analysis engines scan the same code, they may report the
same vulnerability independently.  This module merges duplicate findings
(same location + type from different engines), boosts confidence when
engines agree, and records engine provenance in finding details.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

from .engines import AnalysisEngine
from .findings import Finding

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class EngineTimingResult:
    """Timing result for a single engine run."""

    engine_name: str
    duration_ms: float
    finding_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine_name": self.engine_name,
            "duration_ms": self.duration_ms,
            "finding_count": self.finding_count,
        }


# ---------------------------------------------------------------------------
# Timed engine execution
# ---------------------------------------------------------------------------


def timed_analyze(
    engine: AnalysisEngine,
    code: str,
    language: str | None = None,
    sensitivity: str = "medium",
    file_path: str | None = None,
) -> tuple[list[Finding], EngineTimingResult]:
    """Run ``engine.analyze()`` with timing.

    Returns ``(findings, timing)`` where *timing* captures the engine
    name, duration in milliseconds, and finding count.
    """
    start = time.monotonic()
    findings = engine.analyze(
        code,
        language=language,
        sensitivity=sensitivity,
        file_path=file_path,
    )
    duration_ms = (time.monotonic() - start) * 1000
    timing = EngineTimingResult(
        engine_name=engine.name,
        duration_ms=round(duration_ms, 2),
        finding_count=len(findings),
    )
    return findings, timing


# ---------------------------------------------------------------------------
# Cross-engine merge fingerprint
# ---------------------------------------------------------------------------


def _merge_fingerprint(finding: Finding) -> str:
    """Compute a coarse fingerprint for cross-engine dedup.

    Uses ``file_path``, ``line_number``, and ``finding_type`` only —
    deliberately omitting ``pattern_name`` and ``matched_text`` which
    differ between engines reporting the same vulnerability.
    """
    parts = [
        finding.file_path or "",
        str(finding.line_number),
        finding.finding_type.value,
    ]
    key = ":".join(parts)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Merge engine findings
# ---------------------------------------------------------------------------


def merge_engine_findings(all_findings: list[Finding]) -> list[Finding]:
    """Merge findings from multiple engines, deduplicating by location + type.

    - Single-engine groups: pass through with ``details["engines"]`` set.
    - Multi-engine groups: keep highest confidence, merge engine names,
      boost confidence by ``+0.1`` per additional engine (capped at 1.0),
      and set ``details["multi_engine_confirmed"] = True``.
    """
    if not all_findings:
        return []

    # Group by merge fingerprint.
    groups: dict[str, list[Finding]] = {}
    for f in all_findings:
        fp = _merge_fingerprint(f)
        groups.setdefault(fp, []).append(f)

    merged: list[Finding] = []

    for group in groups.values():
        engines_in_group = {f.details.get("engine", "unknown") for f in group}

        if len(engines_in_group) <= 1:
            # All from the same engine — keep every finding as-is.
            for f in group:
                engine = f.details.get("engine", "unknown")
                if "engines" not in f.details:
                    f.details["engines"] = [engine]
                merged.append(f)
        else:
            # Multiple engines — merge into one representative finding.
            group.sort(
                key=lambda f: f.confidence if f.confidence is not None else 0.0,
                reverse=True,
            )
            base = group[0]

            engine_names: list[str] = []
            engine_evidence: dict[str, Any] = {}
            for f in group:
                engine = f.details.get("engine", "unknown")
                if engine not in engine_names:
                    engine_names.append(engine)
                # Collect engine-specific evidence.
                evidence: dict[str, Any] = {}
                for key in ("taint_chain", "engine_evidence", "match_explanation"):
                    if key in f.details:
                        evidence[key] = f.details[key]
                if evidence:
                    engine_evidence[engine] = evidence

            base.details["engines"] = engine_names
            if engine_evidence:
                base.details["engine_evidence"] = engine_evidence
            base.details["multi_engine_confirmed"] = True

            max_conf = base.confidence if base.confidence is not None else 0.0
            n_engines = len(engine_names)
            base.confidence = min(1.0, max_conf + 0.1 * (n_engines - 1))

            merged.append(base)

    return merged
