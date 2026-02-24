"""Local-first dependency vulnerability scanner using OSV.dev.

Syncs vulnerability data from OSV.dev to a local SQLite cache at
~/.guardianshield/osv_cache.db. All lookups after initial sync are local —
instant, offline, and private.

Architecture:
    - sync_vulnerabilities() fetches from OSV.dev REST API via urllib (stdlib)
    - OsvCache class manages SQLite with sync(), lookup(), is_stale()
    - check_dependencies() returns Finding list with DEPENDENCY_VULNERABILITY type
    - CVSS mapping: >= 9.0 CRITICAL, >= 7.0 HIGH, >= 4.0 MEDIUM, else LOW
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from guardianshield.findings import (
    Finding,
    FindingType,
    Remediation,
    Severity,
)

logger = logging.getLogger("guardianshield.osv")

# Default cache location
DEFAULT_CACHE_PATH = os.path.join(
    os.path.expanduser("~"), ".guardianshield", "osv_cache.db"
)

# OSV.dev API endpoint
OSV_API_URL = "https://api.osv.dev/v1"

# Supported ecosystems (Tier 1)
SUPPORTED_ECOSYSTEMS = ("PyPI", "npm")


def _cvss_to_severity(score: float) -> Severity:
    """Map a CVSS score to a GuardianShield severity level."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


@dataclass
class Dependency:
    """A single package dependency to check.

    Attributes:
        name: Package name (e.g. "requests", "lodash").
        version: Installed version string (e.g. "2.28.0").
        ecosystem: Package ecosystem ("PyPI" or "npm").
    """

    name: str
    version: str
    ecosystem: str = "PyPI"


class OsvCache:
    """Local SQLite cache for OSV vulnerability data.

    Args:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or DEFAULT_CACHE_PATH
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id TEXT PRIMARY KEY,
                ecosystem TEXT NOT NULL,
                package TEXT NOT NULL,
                summary TEXT,
                details TEXT,
                severity_score REAL,
                cwe_ids TEXT,  -- JSON array
                affected_ranges TEXT,  -- JSON array of version ranges
                fixed_version TEXT,
                aliases TEXT,  -- JSON array (CVE IDs etc.)
                published TEXT,
                modified TEXT,
                fetched_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_vuln_package
                ON vulnerabilities(ecosystem, package);
            CREATE TABLE IF NOT EXISTS sync_metadata (
                ecosystem TEXT PRIMARY KEY,
                last_sync REAL NOT NULL,
                package_count INTEGER DEFAULT 0
            );
        """)
        self._conn.commit()

    def is_stale(self, ecosystem: str, max_age_hours: float = 24.0) -> bool:
        """Check if the cache for an ecosystem is stale."""
        row = self._conn.execute(
            "SELECT last_sync FROM sync_metadata WHERE ecosystem = ?",
            (ecosystem,),
        ).fetchone()
        if row is None:
            return True
        age_hours = (time.time() - row["last_sync"]) / 3600
        return age_hours > max_age_hours

    def sync(
        self,
        ecosystem: str = "PyPI",
        packages: list[str] | None = None,
    ) -> int:
        """Sync vulnerability data from OSV.dev for given packages.

        Args:
            ecosystem: Package ecosystem to sync.
            packages: Specific packages to sync. If None, syncs nothing
                (caller must provide packages).

        Returns:
            Number of vulnerabilities synced.
        """
        if ecosystem not in SUPPORTED_ECOSYSTEMS:
            raise ValueError(
                f"Unsupported ecosystem: {ecosystem}. "
                f"Supported: {', '.join(SUPPORTED_ECOSYSTEMS)}"
            )

        if not packages:
            return 0

        count = 0
        for package in packages:
            try:
                vulns = self._query_osv(ecosystem, package)
                count += self._store_vulns(vulns)
            except (urllib.error.URLError, json.JSONDecodeError) as exc:
                logger.warning("Failed to sync %s/%s: %s", ecosystem, package, exc)
                continue

        self._conn.execute(
            """INSERT OR REPLACE INTO sync_metadata (ecosystem, last_sync, package_count)
               VALUES (?, ?, ?)""",
            (ecosystem, time.time(), len(packages)),
        )
        self._conn.commit()
        return count

    def _query_osv(self, ecosystem: str, package: str) -> list[dict[str, Any]]:
        """Query OSV.dev API for vulnerabilities affecting a package."""
        url = f"{OSV_API_URL}/query"
        payload = json.dumps({
            "package": {"name": package, "ecosystem": ecosystem},
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        return data.get("vulns", [])

    def _store_vulns(self, vulns: list[dict[str, Any]]) -> int:
        """Store vulnerability records in the cache."""
        count = 0
        for vuln in vulns:
            vuln_id = vuln.get("id", "")
            if not vuln_id:
                continue

            # Extract severity score
            severity_score = 0.0
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    try:
                        score_str = sev.get("score", "0")
                        severity_score = float(score_str) if isinstance(
                            score_str, (int, float, str)
                        ) else 0.0
                    except (ValueError, TypeError):
                        pass

            # Extract CWE IDs from aliases
            cwe_ids = []
            for alias in vuln.get("aliases", []):
                if isinstance(alias, str) and alias.startswith("CWE-"):
                    cwe_ids.append(alias)

            # Extract affected packages and fixed versions
            affected_ranges = []
            fixed_version = None
            for affected in vuln.get("affected", []):
                for rng in affected.get("ranges", []):
                    affected_ranges.append(rng)
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixed_version = event["fixed"]

            # Extract ecosystem and package from first affected entry
            ecosystem = ""
            package = ""
            if vuln.get("affected"):
                pkg_info = vuln["affected"][0].get("package", {})
                ecosystem = pkg_info.get("ecosystem", "")
                package = pkg_info.get("name", "")

            aliases = [a for a in vuln.get("aliases", []) if not a.startswith("CWE-")]

            self._conn.execute(
                """INSERT OR REPLACE INTO vulnerabilities
                   (vuln_id, ecosystem, package, summary, details,
                    severity_score, cwe_ids, affected_ranges, fixed_version,
                    aliases, published, modified, fetched_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    vuln_id,
                    ecosystem,
                    package,
                    vuln.get("summary", ""),
                    vuln.get("details", ""),
                    severity_score,
                    json.dumps(cwe_ids),
                    json.dumps(affected_ranges),
                    fixed_version,
                    json.dumps(aliases),
                    vuln.get("published", ""),
                    vuln.get("modified", ""),
                    time.time(),
                ),
            )
            count += 1

        self._conn.commit()
        return count

    def lookup(self, ecosystem: str, package: str) -> list[dict[str, Any]]:
        """Look up cached vulnerabilities for a package.

        Returns a list of dicts with vuln_id, summary, severity_score,
        cwe_ids, fixed_version, and aliases.
        """
        rows = self._conn.execute(
            """SELECT vuln_id, summary, severity_score, cwe_ids,
                      fixed_version, aliases, details
               FROM vulnerabilities
               WHERE ecosystem = ? AND package = ?""",
            (ecosystem, package),
        ).fetchall()

        results = []
        for row in rows:
            results.append({
                "vuln_id": row["vuln_id"],
                "summary": row["summary"],
                "severity_score": row["severity_score"],
                "cwe_ids": json.loads(row["cwe_ids"]) if row["cwe_ids"] else [],
                "fixed_version": row["fixed_version"],
                "aliases": json.loads(row["aliases"]) if row["aliases"] else [],
                "details": row["details"],
            })

        return results

    def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        total = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM vulnerabilities"
        ).fetchone()["cnt"]

        syncs = {}
        for row in self._conn.execute("SELECT * FROM sync_metadata").fetchall():
            syncs[row["ecosystem"]] = {
                "last_sync": row["last_sync"],
                "package_count": row["package_count"],
            }

        return {
            "db_path": self._db_path,
            "total_vulnerabilities": total,
            "ecosystems": syncs,
        }

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()


def check_dependencies(
    dependencies: list[Dependency],
    cache: OsvCache | None = None,
    auto_sync: bool = True,
) -> list[Finding]:
    """Check a list of dependencies for known vulnerabilities.

    Args:
        dependencies: List of Dependency objects to check.
        cache: Optional OsvCache instance (creates default if None).
        auto_sync: If True, syncs packages that aren't cached yet.

    Returns:
        List of Finding objects for vulnerable dependencies.
    """
    if cache is None:
        cache = OsvCache()

    findings: list[Finding] = []

    # Group dependencies by ecosystem for efficient syncing
    by_ecosystem: dict[str, list[Dependency]] = {}
    for dep in dependencies:
        by_ecosystem.setdefault(dep.ecosystem, []).append(dep)

    for ecosystem, deps in by_ecosystem.items():
        if auto_sync:
            packages = [d.name for d in deps]
            try:
                cache.sync(ecosystem=ecosystem, packages=packages)
            except Exception as exc:
                logger.warning("Sync failed for %s: %s", ecosystem, exc)

        for dep in deps:
            vulns = cache.lookup(dep.ecosystem, dep.name)
            for vuln in vulns:
                severity = _cvss_to_severity(vuln.get("severity_score", 0))
                cwe_ids = vuln.get("cwe_ids", [])
                aliases = vuln.get("aliases", [])
                fixed = vuln.get("fixed_version")

                # Build CVE reference string
                cve_refs = [a for a in aliases if a.startswith("CVE-")]
                cve_str = ", ".join(cve_refs) if cve_refs else vuln["vuln_id"]

                message = (
                    f"{cve_str}: {vuln.get('summary', 'Known vulnerability')} "
                    f"in {dep.name}=={dep.version} ({dep.ecosystem})"
                )

                remediation = None
                if fixed:
                    remediation = Remediation(
                        description=f"Upgrade {dep.name} to >= {fixed}",
                        before=f"{dep.name}=={dep.version}",
                        after=f"{dep.name}>={fixed}",
                        auto_fixable=True,
                    )

                findings.append(
                    Finding(
                        finding_type=FindingType.DEPENDENCY_VULNERABILITY,
                        severity=severity,
                        message=message,
                        matched_text=f"{dep.name}=={dep.version}",
                        scanner="osv",
                        confidence=1.0,
                        cwe_ids=cwe_ids,
                        remediation=remediation,
                        metadata={
                            "vuln_id": vuln["vuln_id"],
                            "ecosystem": dep.ecosystem,
                            "package": dep.name,
                            "version": dep.version,
                            "fixed_version": fixed,
                            "aliases": aliases,
                        },
                    )
                )

    return findings
