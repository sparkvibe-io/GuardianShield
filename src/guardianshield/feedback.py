"""False positive feedback loop.

Stores per-project false positive feedback in a local SQLite database.
When findings are produced, they can be annotated against the feedback DB
so that known false positives are flagged and similar patterns are marked
as potential false positives.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

from .findings import Finding

# ---------------------------------------------------------------------------
# Default DB location
# ---------------------------------------------------------------------------

_DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".guardianshield")


def _default_db_path() -> str:
    """Return the default feedback DB path."""
    return os.path.join(_DEFAULT_DIR, "feedback.db")


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------


def _fingerprint(finding: Finding) -> str:
    """Compute a stable fingerprint for a finding.

    Uses the same hashing approach as ``dedup.py`` — SHA-256 of
    ``file_path:line_number:finding_type:pattern_name:matched_text``,
    truncated to 16 hex characters.
    """
    pattern_name = finding.metadata.get(
        "pattern_name",
        finding.metadata.get("injection_type", ""),
    )
    parts = [
        finding.file_path or "",
        str(finding.line_number),
        finding.finding_type.value,
        pattern_name,
        finding.matched_text,
    ]
    key = ":".join(parts)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _pattern_key(finding: Finding) -> tuple[str, str, str]:
    """Extract the (pattern_name, finding_type, scanner) tuple."""
    pattern_name = finding.metadata.get(
        "pattern_name",
        finding.metadata.get("injection_type", ""),
    )
    return (pattern_name, finding.finding_type.value, finding.scanner)


# ---------------------------------------------------------------------------
# FalsePositiveDB
# ---------------------------------------------------------------------------


class FalsePositiveDB:
    """Thread-safe SQLite store for false positive feedback.

    Args:
        db_path: Path to the SQLite database file.  Use ``":memory:"`` for
            an in-memory database (useful in tests).  Defaults to
            ``~/.guardianshield/feedback.db``.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or _default_db_path()
        if self._db_path != ":memory:":
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

        # In-memory caches for fast annotation lookups.
        self._fp_fingerprints: set[str] | None = None
        self._fp_pattern_keys: set[tuple[str, str, str]] | None = None

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS false_positives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                pattern_name TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                scanner TEXT NOT NULL,
                reason TEXT DEFAULT '',
                file_path TEXT,
                matched_text TEXT,
                created_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                UNIQUE(fingerprint)
            );
            CREATE INDEX IF NOT EXISTS idx_fp_pattern
                ON false_positives(pattern_name, finding_type, scanner);
            CREATE INDEX IF NOT EXISTS idx_fp_active
                ON false_positives(is_active);
        """)
        self._conn.commit()

    def _invalidate_cache(self) -> None:
        """Invalidate the in-memory annotation caches."""
        self._fp_fingerprints = None
        self._fp_pattern_keys = None

    def _ensure_cache(self) -> None:
        """Load caches from DB if not yet populated."""
        if self._fp_fingerprints is not None:
            return

        rows = self._conn.execute(
            "SELECT fingerprint, pattern_name, finding_type, scanner "
            "FROM false_positives WHERE is_active = 1"
        ).fetchall()

        self._fp_fingerprints = set()
        self._fp_pattern_keys = set()
        for row in rows:
            self._fp_fingerprints.add(row["fingerprint"])
            self._fp_pattern_keys.add(
                (row["pattern_name"], row["finding_type"], row["scanner"])
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def mark(self, finding: Finding, reason: str = "") -> int:
        """Mark a finding as false positive.

        Args:
            finding: The finding to mark.
            reason: Optional explanation from the user.

        Returns:
            The database record ID.
        """
        fp = _fingerprint(finding)
        pname, ftype, scanner = _pattern_key(finding)

        with self._lock:
            self._conn.execute(
                """INSERT INTO false_positives
                   (fingerprint, pattern_name, finding_type, scanner,
                    reason, file_path, matched_text, created_at, is_active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                   ON CONFLICT(fingerprint) DO UPDATE SET
                    reason = excluded.reason,
                    is_active = 1,
                    created_at = excluded.created_at""",
                (
                    fp,
                    pname,
                    ftype,
                    scanner,
                    reason,
                    finding.file_path or "",
                    finding.matched_text,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()
            row_id = self._conn.execute(
                "SELECT id FROM false_positives WHERE fingerprint = ?", (fp,)
            ).fetchone()["id"]
            self._invalidate_cache()

        return row_id

    def unmark(self, fingerprint: str) -> bool:
        """Remove a false positive record by fingerprint.

        Args:
            fingerprint: The fingerprint to remove.

        Returns:
            True if a record was found and deactivated.
        """
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE false_positives SET is_active = 0 WHERE fingerprint = ? AND is_active = 1",
                (fingerprint,),
            )
            self._conn.commit()
            self._invalidate_cache()
            return cursor.rowcount > 0

    def list_fps(
        self,
        scanner: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List active false positive records.

        Args:
            scanner: Optional filter by scanner name.
            limit: Maximum number of records to return.

        Returns:
            A list of dicts with false positive details.
        """
        if scanner:
            rows = self._conn.execute(
                "SELECT * FROM false_positives WHERE is_active = 1 AND scanner = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (scanner, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM false_positives WHERE is_active = 1 "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

        return [
            {
                "id": row["id"],
                "fingerprint": row["fingerprint"],
                "pattern_name": row["pattern_name"],
                "finding_type": row["finding_type"],
                "scanner": row["scanner"],
                "reason": row["reason"],
                "file_path": row["file_path"],
                "matched_text": row["matched_text"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def annotate(self, findings: list[Finding]) -> list[Finding]:
        """Annotate findings with false positive metadata.

        - Exact fingerprint match: ``metadata["false_positive"] = True``
        - Same (pattern_name, finding_type, scanner) but different location:
          ``metadata["potential_false_positive"] = True``

        Mutates findings in place and returns the same list.
        """
        if not findings:
            return findings

        with self._lock:
            self._ensure_cache()
            assert self._fp_fingerprints is not None
            assert self._fp_pattern_keys is not None

            for finding in findings:
                fp = _fingerprint(finding)
                if fp in self._fp_fingerprints:
                    finding.metadata["false_positive"] = True
                elif _pattern_key(finding) in self._fp_pattern_keys:
                    finding.metadata["potential_false_positive"] = True

        return findings

    def stats(self) -> dict[str, Any]:
        """Return aggregate statistics about false positive records."""
        total = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM false_positives WHERE is_active = 1"
        ).fetchone()["cnt"]

        by_scanner: dict[str, int] = {}
        for row in self._conn.execute(
            "SELECT scanner, COUNT(*) as cnt FROM false_positives "
            "WHERE is_active = 1 GROUP BY scanner"
        ).fetchall():
            by_scanner[row["scanner"]] = row["cnt"]

        return {
            "total_active": total,
            "by_scanner": by_scanner,
            "db_path": self._db_path,
        }

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
