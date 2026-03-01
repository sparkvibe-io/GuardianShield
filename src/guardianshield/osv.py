"""Local-first dependency vulnerability scanner using OSV.dev.

Syncs vulnerability data from OSV.dev to a local SQLite cache at
~/.guardianshield/osv_cache.db. All lookups after initial sync are local —
instant, offline, and private.

Architecture:
    - sync_vulnerabilities() fetches from OSV.dev REST API via urllib (stdlib)
    - OsvCache class manages SQLite with sync(), lookup(), is_stale()
    - check_dependencies() returns Finding list with DEPENDENCY_VULNERABILITY type
    - CVSS mapping: >= 9.0 CRITICAL, >= 7.0 HIGH, >= 4.0 MEDIUM, else LOW
    - Version-aware filtering: compares dependency version against affected ranges
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from guardianshield.enrichment import build_references
from guardianshield.findings import (
    Finding,
    FindingType,
    Remediation,
    Severity,
)

logger = logging.getLogger("guardianshield.osv")

# Compiled regex for extracting CVSS base score from vector strings.
_CVSS_SCORE_RE = re.compile(r"(\d+(?:\.\d+))$")

# ---------------------------------------------------------------------------
# Version parsing and comparison (stdlib only, no external deps)
# ---------------------------------------------------------------------------

# PEP 440 pre-release label ordering: dev < alpha < beta < rc < (release)
_PEP440_PRE_ORDER = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "rc": 3, "c": 3}

# Regex for PEP 440 version strings (simplified but covers common formats)
_PEP440_RE = re.compile(
    r"^v?(?P<epoch>\d+!)?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_label>dev|a|alpha|b|beta|rc|c)(?P<pre_num>\d*))?"
    r"(?:\.post(?P<post>\d*))?",
    re.IGNORECASE,
)

# Regex for semver pre-release (npm): 1.2.3-beta.1
_SEMVER_RE = re.compile(
    r"^v?(?P<release>\d+(?:\.\d+)*)"
    r"(?:-(?P<pre>[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*))?",
    re.IGNORECASE,
)


def _parse_pep440(version: str) -> tuple[tuple[int, ...], bool, int, int, int]:
    """Parse a PEP 440 version string into a comparable tuple.

    Returns:
        (release_tuple, is_release, pre_order, pre_num, post_num) where:
        - release_tuple: numeric release segments, e.g. (1, 2, 3)
        - is_release: True if no pre-release suffix (final or post release)
        - pre_order: ordering of pre-release label (0=dev .. 3=rc)
        - pre_num: numeric part of pre-release label
        - post_num: post-release number (0 if not post-release)
    """
    m = _PEP440_RE.match(version.strip())
    if not m:
        raise ValueError(f"Cannot parse PEP 440 version: {version!r}")

    release = tuple(int(x) for x in m.group("release").split("."))

    pre_label = m.group("pre_label")
    if pre_label:
        label = pre_label.lower()
        pre_order = _PEP440_PRE_ORDER.get(label, 0)
        pre_num = int(m.group("pre_num")) if m.group("pre_num") else 0
        return (release, False, pre_order, pre_num, 0)

    # Post-release: sorts after the base release
    post_str = m.group("post")
    post_num = int(post_str) if post_str is not None and post_str != "" else 0
    if post_str is not None:
        return (release, True, 99, 0, post_num + 1)

    # Final release (no pre or post suffix)
    return (release, True, 99, 0, 0)


def _parse_semver(version: str) -> tuple[tuple[int, ...], bool, str]:
    """Parse a semver version string into a comparable tuple.

    Returns:
        (release_tuple, is_release, pre_release_str) where:
        - release_tuple: numeric release segments, e.g. (1, 2, 3)
        - is_release: True if no pre-release suffix
        - pre_release_str: pre-release identifier string (for sorting)
    """
    m = _SEMVER_RE.match(version.strip())
    if not m:
        raise ValueError(f"Cannot parse semver version: {version!r}")

    release = tuple(int(x) for x in m.group("release").split("."))

    pre_str = m.group("pre")
    if pre_str:
        return (release, False, pre_str)

    return (release, True, "")


def parse_version(version: str, ecosystem: str = "PyPI") -> tuple:
    """Parse a version string into a comparable tuple.

    Args:
        version: Version string to parse.
        ecosystem: Package ecosystem ("PyPI" or "npm").

    Returns:
        A tuple that supports ordering comparison for the given ecosystem.

    Raises:
        ValueError: If the version string cannot be parsed.
    """
    if ecosystem == "npm":
        return _parse_semver(version)
    return _parse_pep440(version)


def compare_versions(v1: str, v2: str, ecosystem: str = "PyPI") -> int:
    """Compare two version strings.

    Args:
        v1: First version string.
        v2: Second version string.
        ecosystem: Package ecosystem ("PyPI" or "npm").

    Returns:
        -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.

    Raises:
        ValueError: If either version string cannot be parsed.
    """
    t1 = parse_version(v1, ecosystem)
    t2 = parse_version(v2, ecosystem)
    if t1 < t2:
        return -1
    if t1 > t2:
        return 1
    return 0


def _is_version_affected(
    version: str,
    affected_ranges: list[dict],
    ecosystem: str = "PyPI",
) -> bool | None:
    """Check if a version falls within any of the affected ranges.

    OSV range format uses event pairs: {"introduced": "X"} and {"fixed": "Y"}.
    A version V is affected if V >= introduced AND V < fixed. If there is no
    "fixed" event, all versions >= introduced are affected.

    Args:
        version: The version to check.
        affected_ranges: List of OSV range dicts with "type" and "events".
        ecosystem: Package ecosystem for version comparison.

    Returns:
        True if version is confirmed affected, False if confirmed not affected,
        None if version matching could not be performed (unparseable versions,
        no usable ranges).
    """
    if not affected_ranges:
        return None

    had_usable_range = False

    for rng in affected_ranges:
        rng_type = rng.get("type", "")
        events = rng.get("events", [])

        # We can compare ECOSYSTEM and SEMVER type ranges
        if rng_type not in ("ECOSYSTEM", "SEMVER"):
            continue

        # Parse event pairs: walk events to find introduced/fixed pairs
        # OSV events are ordered: introduced, fixed, introduced, fixed, ...
        introduced = None
        for event in events:
            if "introduced" in event:
                introduced = event["introduced"]
            elif "fixed" in event and introduced is not None:
                fixed = event["fixed"]
                had_usable_range = True
                try:
                    # "0" means "all versions from the beginning"
                    if introduced == "0":
                        v_ge_intro = True
                    else:
                        v_ge_intro = compare_versions(
                            version, introduced, ecosystem
                        ) >= 0

                    if v_ge_intro:
                        v_lt_fixed = compare_versions(
                            version, fixed, ecosystem
                        ) < 0
                        if v_lt_fixed:
                            return True
                except ValueError:
                    continue
                introduced = None

        # Handle case where introduced has no fixed (all versions affected)
        if introduced is not None:
            had_usable_range = True
            try:
                if introduced == "0":
                    return True
                if compare_versions(version, introduced, ecosystem) >= 0:
                    return True
            except ValueError:
                pass

    if not had_usable_range:
        return None

    # We had usable ranges but the version didn't match any
    return False


# Default cache location
DEFAULT_CACHE_PATH = os.path.join(
    os.path.expanduser("~"), ".guardianshield", "osv_cache.db"
)

# OSV.dev API endpoint
OSV_API_URL = "https://api.osv.dev/v1"

# Supported ecosystems (Tier 1 + Tier 2)
SUPPORTED_ECOSYSTEMS = ("PyPI", "npm", "Go", "Packagist")

# Maximum pages to fetch per package (safety limit for pagination)
MAX_PAGES_PER_PACKAGE = 10


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
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
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
        for i, package in enumerate(packages):
            # Rate-limit: small delay between packages to avoid hitting OSV.dev limits
            if i > 0:
                time.sleep(0.1)
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
        """Query OSV.dev API for vulnerabilities affecting a package.

        Follows pagination via ``next_page_token`` up to
        ``MAX_PAGES_PER_PACKAGE`` pages to collect all results.

        Retries up to 3 times with exponential backoff (1s, 2s, 4s) on
        HTTP 429 (Too Many Requests) and 5xx server errors.
        """
        url = f"{OSV_API_URL}/query"
        all_vulns: list[dict[str, Any]] = []
        page_token: str | None = None

        for _ in range(MAX_PAGES_PER_PACKAGE):
            body: dict[str, Any] = {
                "package": {"name": package, "ecosystem": ecosystem},
            }
            if page_token is not None:
                body["page_token"] = page_token

            payload = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            # Retry with exponential backoff on 429 / 5xx
            last_exc: Exception | None = None
            max_retries = 3
            for attempt in range(max_retries + 1):
                try:
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                    last_exc = None
                    break
                except urllib.error.HTTPError as exc:
                    if exc.code == 429 or exc.code >= 500:
                        last_exc = exc
                        if attempt < max_retries:
                            delay = 2 ** attempt  # 1s, 2s, 4s
                            time.sleep(delay)
                            continue
                    raise

            if last_exc is not None:
                raise last_exc

            all_vulns.extend(data.get("vulns", []))

            page_token = data.get("next_page_token")
            if not page_token:
                break

        return all_vulns

    def _store_vulns(self, vulns: list[dict[str, Any]]) -> int:
        """Store vulnerability records in the cache."""
        count = 0
        for vuln in vulns:
            vuln_id = vuln.get("id", "")
            if not vuln_id:
                continue

            # Extract severity score (prefer CVSS v3 > v4 > v2)
            severity_score = 0.0
            scores_by_type: dict[str, float] = {}
            for sev in vuln.get("severity", []):
                sev_type = sev.get("type", "")
                if sev_type not in ("CVSS_V3", "CVSS_V4", "CVSS_V2"):
                    continue
                try:
                    score_str = sev.get("score", "0")
                    if isinstance(score_str, (int, float)):
                        scores_by_type[sev_type] = float(score_str)
                    elif isinstance(score_str, str):
                        try:
                            scores_by_type[sev_type] = float(score_str)
                        except ValueError:
                            # CVSS vector string (e.g. "CVSS:3.1/AV:N/...").
                            # Extract base score from the vector's trailing
                            # numeric segment if present, otherwise skip.
                            m = _CVSS_SCORE_RE.search(score_str)
                            if m:
                                scores_by_type[sev_type] = float(m.group(1))
                            else:
                                logger.debug(
                                    "Unparseable CVSS score for %s: %s",
                                    vuln_id, score_str,
                                )
                except (ValueError, TypeError):
                    pass
            # Apply preference order
            for pref in ("CVSS_V3", "CVSS_V4", "CVSS_V2"):
                if pref in scores_by_type:
                    severity_score = scores_by_type[pref]
                    break

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
        cwe_ids, fixed_version, aliases, details, and affected_ranges.
        """
        rows = self._conn.execute(
            """SELECT vuln_id, summary, severity_score, cwe_ids,
                      fixed_version, aliases, details, affected_ranges
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
                "affected_ranges": (
                    json.loads(row["affected_ranges"])
                    if row["affected_ranges"]
                    else []
                ),
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
        if auto_sync and cache.is_stale(ecosystem):
            packages = [d.name for d in deps]
            try:
                cache.sync(ecosystem=ecosystem, packages=packages)
            except (OSError, urllib.error.URLError, ValueError, sqlite3.Error) as exc:
                logger.warning("Sync failed for %s: %s", ecosystem, exc)

        for dep in deps:
            vulns = cache.lookup(dep.ecosystem, dep.name)
            for vuln in vulns:
                affected_ranges = vuln.get("affected_ranges", [])

                # Version-aware filtering
                affected = _is_version_affected(
                    dep.version, affected_ranges, dep.ecosystem
                )

                # Skip vulns where version is confirmed not affected
                if affected is False:
                    continue

                # Set confidence based on version match quality
                confidence = 1.0 if affected is True else 0.7

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

                finding = Finding(
                    finding_type=FindingType.DEPENDENCY_VULNERABILITY,
                    severity=severity,
                    message=message,
                    matched_text=f"{dep.name}=={dep.version}",
                    scanner="osv",
                    confidence=confidence,
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

                # Enrich with structured details
                # Build reference links from CWEs and CVE aliases
                primary_vuln_id = None
                for a in aliases:
                    if a.startswith("CVE-"):
                        primary_vuln_id = a
                        break
                if not primary_vuln_id:
                    primary_vuln_id = vuln["vuln_id"]

                finding.details = {
                    "vulnerability_id": vuln["vuln_id"],
                    "ecosystem": dep.ecosystem,
                    "package": dep.name,
                    "installed_version": dep.version,
                    "fixed_version": fixed,
                    "cvss_score": vuln.get("severity_score", 0),
                    "published": vuln.get("published", ""),
                    "references": build_references(
                        cwe_ids, vuln_id=primary_vuln_id
                    ),
                    "match_explanation": (
                        f"Package {dep.name} {dep.version} is affected by "
                        f"{primary_vuln_id}"
                        + (f" (fixed in {fixed})" if fixed else "")
                        + f". {vuln.get('summary', '')}"
                    ),
                    "vulnerability_class": "dependency_vulnerability",
                    "scanner": "osv",
                }
                findings.append(finding)

    return findings
