"""SQLite-backed audit log for GuardianShield scans.

Records every scan invocation and its findings to a local SQLite
database so operators can review history, compute statistics, and
satisfy compliance requirements.  Uses only the Python standard library
(sqlite3, threading, os, json, datetime).
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

from guardianshield.findings import Finding

_DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".guardianshield")
_DEFAULT_DB = os.path.join(_DEFAULT_DIR, "audit.db")

_CREATE_AUDIT_LOG = """\
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    profile TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    metadata TEXT
);
"""

_CREATE_FINDINGS = """\
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER NOT NULL,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    matched_text TEXT,
    line_number INTEGER,
    file_path TEXT,
    scanner TEXT,
    finding_id TEXT NOT NULL,
    metadata TEXT,
    FOREIGN KEY (audit_id) REFERENCES audit_log(id)
);
"""


class AuditLog:
    """Thread-safe SQLite audit log.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.  When *None* (the default) the
        database is stored at ``~/.guardianshield/audit.db``.
    """

    def __init__(self, db_path: str | None = None) -> None:
        if db_path is None:
            db_path = _DEFAULT_DB

        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._conn.execute(_CREATE_AUDIT_LOG)
        self._conn.execute(_CREATE_FINDINGS)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_scan(
        self,
        scan_type: str,
        profile: str,
        input_hash: str,
        findings: list[Finding],
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Record a scan and its findings.

        Returns the ``audit_log.id`` of the newly created row.
        """
        now = datetime.now(timezone.utc).isoformat()
        meta_json = json.dumps(metadata, ensure_ascii=False) if metadata else None

        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO audit_log (timestamp, scan_type, profile, input_hash, "
                "finding_count, metadata) VALUES (?, ?, ?, ?, ?, ?)",
                (now, scan_type, profile, input_hash, len(findings), meta_json),
            )
            audit_id: int = cursor.lastrowid  # type: ignore[assignment]

            if findings:
                self._conn.executemany(
                    "INSERT INTO findings (audit_id, finding_type, severity, message, "
                    "matched_text, line_number, file_path, scanner, finding_id, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        (
                            audit_id,
                            f.finding_type.value if hasattr(f.finding_type, "value") else f.finding_type,
                            f.severity.value if hasattr(f.severity, "value") else f.severity,
                            f.message,
                            f.matched_text or None,
                            f.line_number or None,
                            f.file_path,
                            f.scanner or None,
                            f.finding_id,
                            json.dumps(f.metadata, ensure_ascii=False) if f.metadata else None,
                        )
                        for f in findings
                    ],
                )

            self._conn.commit()
        return audit_id

    def query_log(
        self,
        scan_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return audit log entries, newest first.

        Parameters
        ----------
        scan_type:
            When provided, only rows matching this scan type are returned.
        limit:
            Maximum number of rows.
        offset:
            Number of rows to skip (for pagination).
        """
        with self._lock:
            if scan_type is not None:
                rows = self._conn.execute(
                    "SELECT * FROM audit_log WHERE scan_type = ? "
                    "ORDER BY id DESC LIMIT ? OFFSET ?",
                    (scan_type, limit, offset),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_findings(
        self,
        audit_id: int | None = None,
        finding_type: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return finding rows with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []

        if audit_id is not None:
            clauses.append("audit_id = ?")
            params.append(audit_id)
        if finding_type is not None:
            clauses.append("finding_type = ?")
            params.append(finding_type)
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        query = f"SELECT * FROM findings{where} ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        """Compute aggregate statistics over the audit database."""
        with self._lock:
            total_scans: int = self._conn.execute(
                "SELECT COUNT(*) FROM audit_log"
            ).fetchone()[0]

            total_findings: int = self._conn.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()[0]

            by_severity: dict[str, int] = {}
            for row in self._conn.execute(
                "SELECT severity, COUNT(*) AS cnt FROM findings GROUP BY severity"
            ).fetchall():
                by_severity[row["severity"]] = row["cnt"]

            by_type: dict[str, int] = {}
            for row in self._conn.execute(
                "SELECT finding_type, COUNT(*) AS cnt FROM findings GROUP BY finding_type"
            ).fetchall():
                by_type[row["finding_type"]] = row["cnt"]

            last_row = self._conn.execute(
                "SELECT timestamp FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            last_scan_time: str | None = last_row["timestamp"] if last_row else None

        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "findings_by_severity": by_severity,
            "findings_by_type": by_type,
            "last_scan_time": last_scan_time,
        }

    def close(self) -> None:
        """Close the underlying database connection."""
        with self._lock:
            self._conn.close()
