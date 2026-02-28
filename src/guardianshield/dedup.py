"""Finding deduplication via fingerprinting.

Tracks fingerprints of previously seen findings so re-scans can return
only new, changed, or removed findings instead of the full list.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any

from .findings import Finding


def _fingerprint(finding: Finding) -> str:
    """Compute a stable SHA-256 fingerprint for a Finding.

    The fingerprint is based on: file_path, line_number, finding_type,
    pattern_name (from metadata), and matched_text.  This means the
    same vulnerability at the same location produces the same fingerprint
    across scans, even if the finding_id differs.
    """
    parts = [
        finding.file_path or "",
        str(finding.line_number),
        finding.finding_type.value,
        finding.metadata.get("pattern_name", ""),
        finding.matched_text,
    ]
    key = ":".join(parts)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


@dataclass
class DedupResult:
    """Result of deduplicating findings against a previous scan.

    Attributes:
        scan_id: Unique identifier for this scan session.
        new: Findings that were not present in the previous scan.
        unchanged: Findings that match a previous fingerprint.
        removed: Fingerprints from the previous scan that are no longer present.
        all_findings: The complete list of current findings.
    """

    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    new: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    all_findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "new_count": len(self.new),
            "unchanged_count": len(self.unchanged),
            "removed_count": len(self.removed),
            "total": len(self.all_findings),
            "new": [f.to_dict() for f in self.new],
            "removed_fingerprints": self.removed,
        }


class FindingDeduplicator:
    """Tracks finding fingerprints across scans.

    Usage::

        dedup = FindingDeduplicator()

        # First scan — everything is new.
        result1 = dedup.deduplicate(findings_1)

        # Second scan — only delta is reported.
        result2 = dedup.deduplicate(findings_2)
    """

    def __init__(self) -> None:
        self._previous: dict[str, Finding] = {}

    @property
    def previous_fingerprints(self) -> set[str]:
        """Return the set of fingerprints from the last scan."""
        return set(self._previous.keys())

    def deduplicate(self, findings: list[Finding]) -> DedupResult:
        """Compare *findings* against the last scan and return a delta.

        After this call, the internal state is updated to reflect *findings*
        as the new baseline.
        """
        current: dict[str, Finding] = {}
        for f in findings:
            fp = _fingerprint(f)
            current[fp] = f

        previous_fps = set(self._previous.keys())
        current_fps = set(current.keys())

        new_fps = current_fps - previous_fps
        unchanged_fps = current_fps & previous_fps
        removed_fps = previous_fps - current_fps

        result = DedupResult(
            new=[current[fp] for fp in new_fps],
            unchanged=[current[fp] for fp in unchanged_fps],
            removed=sorted(removed_fps),
            all_findings=findings,
        )

        # Update baseline.
        self._previous = current
        return result

    def reset(self) -> None:
        """Clear the fingerprint baseline."""
        self._previous.clear()
