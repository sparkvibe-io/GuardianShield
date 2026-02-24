"""Tests for OSV.dev dependency vulnerability scanner."""

import json
import sqlite3
import time
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from guardianshield.findings import FindingType, Severity
from guardianshield.osv import (
    Dependency,
    OsvCache,
    _cvss_to_severity,
    check_dependencies,
)

# -----------------------------------------------------------------------
# Helper: build a mock urllib response
# -----------------------------------------------------------------------

def _mock_urlopen(data: dict):
    """Return a MagicMock that behaves like urllib.request.urlopen context manager."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(data).encode("utf-8")
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# A reusable OSV vulnerability payload
SAMPLE_VULN = {
    "id": "PYSEC-2023-001",
    "summary": "XSS vulnerability in flask",
    "details": "A cross-site scripting issue was found.",
    "aliases": ["CVE-2023-1234"],
    "affected": [{
        "package": {"name": "flask", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"},
            {"fixed": "2.3.0"},
        ]}],
    }],
    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
    "published": "2023-06-01T00:00:00Z",
    "modified": "2023-06-15T00:00:00Z",
}


# -----------------------------------------------------------------------
# 1. _cvss_to_severity mapping
# -----------------------------------------------------------------------

class TestCvssSeverityMapping:

    def test_critical_score(self):
        assert _cvss_to_severity(9.0) == Severity.CRITICAL

    def test_critical_score_above(self):
        assert _cvss_to_severity(10.0) == Severity.CRITICAL

    def test_high_score(self):
        assert _cvss_to_severity(7.0) == Severity.HIGH

    def test_high_score_mid(self):
        assert _cvss_to_severity(8.5) == Severity.HIGH

    def test_medium_score(self):
        assert _cvss_to_severity(4.0) == Severity.MEDIUM

    def test_medium_score_mid(self):
        assert _cvss_to_severity(6.9) == Severity.MEDIUM

    def test_low_score(self):
        assert _cvss_to_severity(3.9) == Severity.LOW

    def test_zero_score(self):
        assert _cvss_to_severity(0.0) == Severity.LOW


# -----------------------------------------------------------------------
# 2. Dependency dataclass
# -----------------------------------------------------------------------

class TestDependency:

    def test_create_with_defaults(self):
        dep = Dependency(name="requests", version="2.28.0")
        assert dep.name == "requests"
        assert dep.version == "2.28.0"
        assert dep.ecosystem == "PyPI"

    def test_create_with_npm(self):
        dep = Dependency(name="lodash", version="4.17.21", ecosystem="npm")
        assert dep.ecosystem == "npm"


# -----------------------------------------------------------------------
# 3. OsvCache initialization
# -----------------------------------------------------------------------

class TestOsvCacheInit:

    def test_creates_tables(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        cache = OsvCache(db_path=db_path)
        conn = sqlite3.connect(db_path)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        assert "vulnerabilities" in tables
        assert "sync_metadata" in tables
        conn.close()
        cache.close()

    def test_creates_directory(self, tmp_path):
        db_path = str(tmp_path / "sub" / "dir" / "test.db")
        cache = OsvCache(db_path=db_path)
        assert (tmp_path / "sub" / "dir").is_dir()
        cache.close()


# -----------------------------------------------------------------------
# 4-5. OsvCache.is_stale
# -----------------------------------------------------------------------

class TestOsvCacheIsStale:

    def test_stale_when_no_data(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        assert cache.is_stale("PyPI") is True
        cache.close()

    def test_not_stale_after_recent_sync(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        cache._conn.execute(
            "INSERT INTO sync_metadata (ecosystem, last_sync, package_count) VALUES (?, ?, ?)",
            ("PyPI", time.time(), 5),
        )
        cache._conn.commit()
        assert cache.is_stale("PyPI") is False
        cache.close()

    def test_stale_after_max_age(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        old_time = time.time() - (25 * 3600)  # 25 hours ago
        cache._conn.execute(
            "INSERT INTO sync_metadata (ecosystem, last_sync, package_count) VALUES (?, ?, ?)",
            ("PyPI", old_time, 5),
        )
        cache._conn.commit()
        assert cache.is_stale("PyPI", max_age_hours=24.0) is True
        cache.close()


# -----------------------------------------------------------------------
# 6. OsvCache.sync with mocked urllib
# -----------------------------------------------------------------------

class TestOsvCacheSync:

    def test_sync_stores_vulns(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        mock_resp = _mock_urlopen({"vulns": [SAMPLE_VULN]})

        with patch("urllib.request.urlopen", return_value=mock_resp):
            count = cache.sync(ecosystem="PyPI", packages=["flask"])

        assert count == 1
        results = cache.lookup("PyPI", "flask")
        assert len(results) == 1
        assert results[0]["vuln_id"] == "PYSEC-2023-001"
        cache.close()

    def test_sync_unsupported_ecosystem_raises(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        with pytest.raises(ValueError, match="Unsupported ecosystem"):
            cache.sync(ecosystem="RubyGems", packages=["rails"])
        cache.close()

    def test_sync_empty_packages_returns_zero(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        count = cache.sync(ecosystem="PyPI", packages=[])
        assert count == 0
        cache.close()

    def test_sync_none_packages_returns_zero(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        count = cache.sync(ecosystem="PyPI", packages=None)
        assert count == 0
        cache.close()

    def test_sync_network_error_continues(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("timeout"),
        ):
            count = cache.sync(ecosystem="PyPI", packages=["badpkg"])

        assert count == 0
        cache.close()

    def test_sync_updates_metadata(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        mock_resp = _mock_urlopen({"vulns": []})

        with patch("urllib.request.urlopen", return_value=mock_resp):
            cache.sync(ecosystem="PyPI", packages=["flask"])

        assert cache.is_stale("PyPI") is False
        cache.close()

    def test_sync_multiple_packages(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))

        vuln_a = {**SAMPLE_VULN, "id": "PYSEC-2023-001"}
        vuln_b = {
            **SAMPLE_VULN,
            "id": "PYSEC-2023-002",
            "summary": "SSRF in requests",
            "affected": [{
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"},
                    {"fixed": "2.29.0"},
                ]}],
            }],
        }

        call_count = 0

        def mock_urlopen_multi(req, timeout=30):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_urlopen({"vulns": [vuln_a]})
            return _mock_urlopen({"vulns": [vuln_b]})

        with patch("urllib.request.urlopen", side_effect=mock_urlopen_multi):
            count = cache.sync(ecosystem="PyPI", packages=["flask", "requests"])

        assert count == 2
        assert len(cache.lookup("PyPI", "flask")) == 1
        assert len(cache.lookup("PyPI", "requests")) == 1
        cache.close()


# -----------------------------------------------------------------------
# 7. OsvCache.lookup
# -----------------------------------------------------------------------

class TestOsvCacheLookup:

    def test_lookup_returns_stored_vulns(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        mock_resp = _mock_urlopen({"vulns": [SAMPLE_VULN]})

        with patch("urllib.request.urlopen", return_value=mock_resp):
            cache.sync(ecosystem="PyPI", packages=["flask"])

        results = cache.lookup("PyPI", "flask")
        assert len(results) == 1
        r = results[0]
        assert r["vuln_id"] == "PYSEC-2023-001"
        assert r["summary"] == "XSS vulnerability in flask"
        assert r["severity_score"] == 7.5
        assert r["fixed_version"] == "2.3.0"
        assert "CVE-2023-1234" in r["aliases"]
        cache.close()

    def test_lookup_returns_empty_for_unknown(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        results = cache.lookup("PyPI", "nonexistent-pkg")
        assert results == []
        cache.close()


# -----------------------------------------------------------------------
# 8. OsvCache.stats
# -----------------------------------------------------------------------

class TestOsvCacheStats:

    def test_stats_empty_cache(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        s = cache.stats()
        assert s["total_vulnerabilities"] == 0
        assert s["ecosystems"] == {}
        assert s["db_path"] == str(tmp_path / "test.db")
        cache.close()

    def test_stats_after_sync(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        mock_resp = _mock_urlopen({"vulns": [SAMPLE_VULN]})

        with patch("urllib.request.urlopen", return_value=mock_resp):
            cache.sync(ecosystem="PyPI", packages=["flask"])

        s = cache.stats()
        assert s["total_vulnerabilities"] == 1
        assert "PyPI" in s["ecosystems"]
        assert s["ecosystems"]["PyPI"]["package_count"] == 1
        cache.close()


# -----------------------------------------------------------------------
# 9. OsvCache._store_vulns edge cases
# -----------------------------------------------------------------------

class TestStoreVulnsEdgeCases:

    def test_vuln_without_id_skipped(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        count = cache._store_vulns([{"summary": "no id field"}])
        assert count == 0
        cache.close()

    def test_vuln_with_cwe_in_aliases(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        vuln = {
            **SAMPLE_VULN,
            "id": "PYSEC-2023-CWE",
            "aliases": ["CVE-2023-5678", "CWE-79"],
        }
        count = cache._store_vulns([vuln])
        assert count == 1
        results = cache.lookup("PyPI", "flask")
        r = results[0]
        assert "CWE-79" in r["cwe_ids"]
        # CWE should not appear in aliases
        assert "CWE-79" not in r["aliases"]
        assert "CVE-2023-5678" in r["aliases"]
        cache.close()


# -----------------------------------------------------------------------
# 10-16. check_dependencies
# -----------------------------------------------------------------------

class TestCheckDependencies:

    def _make_cache(self, tmp_path):
        """Create a pre-populated cache with SAMPLE_VULN."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        cache._store_vulns([SAMPLE_VULN])
        return cache

    def test_returns_findings_for_vulnerable_dep(self, tmp_path):
        cache = self._make_cache(tmp_path)
        deps = [Dependency(name="flask", version="2.2.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) >= 1
        cache.close()

    def test_finding_type_is_dependency_vulnerability(self, tmp_path):
        cache = self._make_cache(tmp_path)
        deps = [Dependency(name="flask", version="2.2.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert findings[0].finding_type == FindingType.DEPENDENCY_VULNERABILITY

    def test_finding_has_remediation_when_fix_exists(self, tmp_path):
        cache = self._make_cache(tmp_path)
        deps = [Dependency(name="flask", version="2.2.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        f = findings[0]
        assert f.remediation is not None
        assert "2.3.0" in f.remediation.description
        assert f.remediation.auto_fixable is True

    def test_finding_severity_maps_from_cvss(self, tmp_path):
        cache = self._make_cache(tmp_path)
        deps = [Dependency(name="flask", version="2.2.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        # SAMPLE_VULN has severity_score 7.5 -> HIGH
        assert findings[0].severity == Severity.HIGH

    def test_finding_scanner_is_osv(self, tmp_path):
        cache = self._make_cache(tmp_path)
        deps = [Dependency(name="flask", version="2.2.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert findings[0].scanner == "osv"

    def test_finding_confidence_is_one(self, tmp_path):
        cache = self._make_cache(tmp_path)
        deps = [Dependency(name="flask", version="2.2.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert findings[0].confidence == 1.0

    def test_finding_metadata_contains_details(self, tmp_path):
        cache = self._make_cache(tmp_path)
        deps = [Dependency(name="flask", version="2.2.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        m = findings[0].metadata
        assert m["vuln_id"] == "PYSEC-2023-001"
        assert m["ecosystem"] == "PyPI"
        assert m["package"] == "flask"
        assert m["version"] == "2.2.0"
        assert m["fixed_version"] == "2.3.0"
        cache.close()

    def test_finding_message_contains_cve(self, tmp_path):
        cache = self._make_cache(tmp_path)
        deps = [Dependency(name="flask", version="2.2.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert "CVE-2023-1234" in findings[0].message
        cache.close()

    def test_no_findings_for_unknown_package(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        deps = [Dependency(name="safepkg", version="1.0.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert findings == []
        cache.close()

    def test_multiple_dependencies_checked(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        # Store two different vulns
        vuln_requests = {
            **SAMPLE_VULN,
            "id": "PYSEC-2023-002",
            "summary": "SSRF in requests",
            "affected": [{
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"},
                    {"fixed": "2.29.0"},
                ]}],
            }],
        }
        cache._store_vulns([SAMPLE_VULN, vuln_requests])

        deps = [
            Dependency(name="flask", version="2.2.0"),
            Dependency(name="requests", version="2.28.0"),
        ]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) == 2
        packages_found = {f.metadata["package"] for f in findings}
        assert packages_found == {"flask", "requests"}
        cache.close()

    def test_auto_sync_calls_osv(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        mock_resp = _mock_urlopen({"vulns": [SAMPLE_VULN]})

        deps = [Dependency(name="flask", version="2.2.0")]
        with patch("urllib.request.urlopen", return_value=mock_resp):
            findings = check_dependencies(deps, cache=cache, auto_sync=True)

        assert len(findings) >= 1
        assert findings[0].finding_type == FindingType.DEPENDENCY_VULNERABILITY
        cache.close()

    def test_auto_sync_failure_handled_gracefully(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))

        deps = [Dependency(name="flask", version="2.2.0")]
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("network down"),
        ):
            # Should not raise; returns empty findings
            findings = check_dependencies(deps, cache=cache, auto_sync=True)

        assert findings == []
        cache.close()

    def test_finding_without_fix_has_no_remediation(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        vuln_no_fix = {
            "id": "PYSEC-2023-NOFIX",
            "summary": "Vuln with no fix",
            "aliases": ["CVE-2023-9999"],
            "affected": [{
                "package": {"name": "oldpkg", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"},
                ]}],
            }],
            "severity": [{"type": "CVSS_V3", "score": "5.0"}],
        }
        cache._store_vulns([vuln_no_fix])

        deps = [Dependency(name="oldpkg", version="1.0.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) == 1
        assert findings[0].remediation is None
        assert findings[0].severity == Severity.MEDIUM
        cache.close()

    def test_npm_ecosystem(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        npm_vuln = {
            "id": "GHSA-2023-001",
            "summary": "Prototype pollution in lodash",
            "aliases": ["CVE-2023-5555"],
            "affected": [{
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"},
                    {"fixed": "4.17.21"},
                ]}],
            }],
            "severity": [{"type": "CVSS_V3", "score": "9.1"}],
        }
        cache._store_vulns([npm_vuln])

        deps = [Dependency(name="lodash", version="4.17.20", ecosystem="npm")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].metadata["ecosystem"] == "npm"
        cache.close()
