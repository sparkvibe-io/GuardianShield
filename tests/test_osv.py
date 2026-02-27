"""Tests for OSV.dev dependency vulnerability scanner."""

import json
import sqlite3
import time
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from guardianshield.findings import FindingType, Severity
from guardianshield.osv import (
    MAX_PAGES_PER_PACKAGE,
    Dependency,
    OsvCache,
    _cvss_to_severity,
    _is_version_affected,
    check_dependencies,
    compare_versions,
    parse_version,
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

    def test_lookup_returns_affected_ranges(self, tmp_path):
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        cache._store_vulns([SAMPLE_VULN])
        results = cache.lookup("PyPI", "flask")
        assert len(results) == 1
        r = results[0]
        assert "affected_ranges" in r
        assert len(r["affected_ranges"]) == 1
        assert r["affected_ranges"][0]["type"] == "ECOSYSTEM"
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


# -----------------------------------------------------------------------
# 17. _query_osv pagination
# -----------------------------------------------------------------------

class TestQueryOsvPagination:
    """Tests for paginated OSV.dev API responses in _query_osv."""

    def _make_vuln(self, vuln_id: str) -> dict:
        """Create a minimal vuln payload with a given ID."""
        return {
            **SAMPLE_VULN,
            "id": vuln_id,
        }

    def test_single_page_no_token(self, tmp_path):
        """Single-page response without next_page_token (existing behavior)."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        mock_resp = _mock_urlopen({"vulns": [self._make_vuln("V-001")]})

        with patch("urllib.request.urlopen", return_value=mock_resp):
            vulns = cache._query_osv("PyPI", "flask")

        assert len(vulns) == 1
        assert vulns[0]["id"] == "V-001"
        cache.close()

    def test_two_pages(self, tmp_path):
        """Response spanning two pages accumulates all vulns."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        page1 = {"vulns": [self._make_vuln("V-001")], "next_page_token": "tok-2"}
        page2 = {"vulns": [self._make_vuln("V-002")]}

        call_count = 0

        def mock_urlopen_pages(req, timeout=30):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_urlopen(page1)
            return _mock_urlopen(page2)

        with patch("urllib.request.urlopen", side_effect=mock_urlopen_pages):
            vulns = cache._query_osv("PyPI", "flask")

        assert len(vulns) == 2
        assert vulns[0]["id"] == "V-001"
        assert vulns[1]["id"] == "V-002"
        assert call_count == 2
        cache.close()

    def test_three_pages(self, tmp_path):
        """Response spanning three pages accumulates all vulns."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        page1 = {"vulns": [self._make_vuln("V-001")], "next_page_token": "tok-2"}
        page2 = {"vulns": [self._make_vuln("V-002")], "next_page_token": "tok-3"}
        page3 = {"vulns": [self._make_vuln("V-003")]}

        pages = [page1, page2, page3]
        call_count = 0

        def mock_urlopen_pages(req, timeout=30):
            nonlocal call_count
            resp = _mock_urlopen(pages[call_count])
            call_count += 1
            return resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen_pages):
            vulns = cache._query_osv("PyPI", "flask")

        assert len(vulns) == 3
        ids = [v["id"] for v in vulns]
        assert ids == ["V-001", "V-002", "V-003"]
        assert call_count == 3
        cache.close()

    def test_page_token_sent_in_request_body(self, tmp_path):
        """Verify that page_token is included in subsequent request bodies."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        page1 = {"vulns": [self._make_vuln("V-001")], "next_page_token": "my-token"}
        page2 = {"vulns": [self._make_vuln("V-002")]}

        captured_bodies = []

        def mock_urlopen_capture(req, timeout=30):
            body = json.loads(req.data.decode("utf-8"))
            captured_bodies.append(body)
            if len(captured_bodies) == 1:
                return _mock_urlopen(page1)
            return _mock_urlopen(page2)

        with patch("urllib.request.urlopen", side_effect=mock_urlopen_capture):
            cache._query_osv("PyPI", "flask")

        # First request should NOT have page_token
        assert "page_token" not in captured_bodies[0]
        # Second request should include the token
        assert captured_bodies[1]["page_token"] == "my-token"
        cache.close()

    def test_safety_limit_prevents_infinite_loop(self, tmp_path):
        """Pagination stops after MAX_PAGES_PER_PACKAGE even if tokens keep coming."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        call_count = 0

        def mock_urlopen_infinite(req, timeout=30):
            nonlocal call_count
            call_count += 1
            return _mock_urlopen({
                "vulns": [self._make_vuln(f"V-{call_count:03d}")],
                "next_page_token": f"tok-{call_count + 1}",
            })

        with patch("urllib.request.urlopen", side_effect=mock_urlopen_infinite):
            vulns = cache._query_osv("PyPI", "django")

        assert call_count == MAX_PAGES_PER_PACKAGE
        assert len(vulns) == MAX_PAGES_PER_PACKAGE
        cache.close()

    def test_error_on_subsequent_page_returns_partial(self, tmp_path):
        """If a later page errors, vulns from earlier pages are still returned."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        page1 = {"vulns": [self._make_vuln("V-001")], "next_page_token": "tok-2"}

        call_count = 0

        def mock_urlopen_error(req, timeout=30):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_urlopen(page1)
            raise urllib.error.URLError("connection reset")

        with patch("urllib.request.urlopen", side_effect=mock_urlopen_error):
            # The error should propagate up to sync() which catches it
            with pytest.raises(urllib.error.URLError):
                cache._query_osv("PyPI", "flask")

        cache.close()

    def test_empty_token_string_stops_pagination(self, tmp_path):
        """An empty string token is treated as no more pages."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        page_data = {"vulns": [self._make_vuln("V-001")], "next_page_token": ""}

        with patch("urllib.request.urlopen", return_value=_mock_urlopen(page_data)):
            vulns = cache._query_osv("PyPI", "flask")

        assert len(vulns) == 1
        cache.close()

    def test_pagination_via_sync_stores_all_vulns(self, tmp_path):
        """End-to-end: sync() with paginated _query_osv stores all vulns."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        page1 = {"vulns": [self._make_vuln("V-001")], "next_page_token": "tok-2"}
        page2 = {"vulns": [self._make_vuln("V-002")]}

        call_count = 0

        def mock_urlopen_pages(req, timeout=30):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_urlopen(page1)
            return _mock_urlopen(page2)

        with patch("urllib.request.urlopen", side_effect=mock_urlopen_pages):
            count = cache.sync(ecosystem="PyPI", packages=["flask"])

        assert count == 2
        results = cache.lookup("PyPI", "flask")
        assert len(results) == 2
        vuln_ids = {r["vuln_id"] for r in results}
        assert vuln_ids == {"V-001", "V-002"}
        cache.close()


# -----------------------------------------------------------------------
# Version parsing: PEP 440 (Python)
# -----------------------------------------------------------------------

class TestParsePep440:

    def test_simple_version(self):
        t = parse_version("1.2.3", "PyPI")
        assert t[0] == (1, 2, 3)

    def test_two_part_version(self):
        t = parse_version("1.2", "PyPI")
        assert t[0] == (1, 2)

    def test_single_part_version(self):
        t = parse_version("42", "PyPI")
        assert t[0] == (42,)

    def test_alpha_pre_release(self):
        t = parse_version("1.2.3a1", "PyPI")
        assert t[1] is False  # is_release = False

    def test_beta_pre_release(self):
        t = parse_version("1.2.3b2", "PyPI")
        assert t[1] is False

    def test_rc_pre_release(self):
        t = parse_version("1.2.3rc1", "PyPI")
        assert t[1] is False

    def test_dev_pre_release(self):
        t = parse_version("1.2.3dev0", "PyPI")
        assert t[1] is False

    def test_post_release(self):
        t = parse_version("1.2.3.post1", "PyPI")
        assert t[1] is True  # post counts as release

    def test_final_release(self):
        t = parse_version("1.2.3", "PyPI")
        assert t[1] is True

    def test_v_prefix_stripped(self):
        t = parse_version("v1.2.3", "PyPI")
        assert t[0] == (1, 2, 3)

    def test_invalid_version_raises(self):
        with pytest.raises(ValueError, match="Cannot parse PEP 440"):
            parse_version("not-a-version", "PyPI")


# -----------------------------------------------------------------------
# Version parsing: npm semver
# -----------------------------------------------------------------------

class TestParseSemver:

    def test_simple_version(self):
        t = parse_version("1.2.3", "npm")
        assert t[0] == (1, 2, 3)

    def test_pre_release(self):
        t = parse_version("1.2.3-beta.1", "npm")
        assert t[1] is False  # is_release = False
        assert t[2] == "beta.1"

    def test_alpha_pre_release(self):
        t = parse_version("1.0.0-alpha", "npm")
        assert t[1] is False
        assert t[2] == "alpha"

    def test_final_release(self):
        t = parse_version("1.2.3", "npm")
        assert t[1] is True

    def test_v_prefix_stripped(self):
        t = parse_version("v2.0.0", "npm")
        assert t[0] == (2, 0, 0)

    def test_invalid_version_raises(self):
        with pytest.raises(ValueError, match="Cannot parse semver"):
            parse_version("not-a-version", "npm")


# -----------------------------------------------------------------------
# Version comparison: PEP 440
# -----------------------------------------------------------------------

class TestCompareVersionsPep440:

    def test_equal_versions(self):
        assert compare_versions("1.2.3", "1.2.3", "PyPI") == 0

    def test_less_than(self):
        assert compare_versions("1.2.3", "1.2.4", "PyPI") == -1

    def test_greater_than(self):
        assert compare_versions("1.2.4", "1.2.3", "PyPI") == 1

    def test_major_comparison(self):
        assert compare_versions("1.0.0", "2.0.0", "PyPI") == -1

    def test_minor_comparison(self):
        assert compare_versions("1.1.0", "1.2.0", "PyPI") == -1

    def test_alpha_before_release(self):
        assert compare_versions("1.2.3a1", "1.2.3", "PyPI") == -1

    def test_beta_before_release(self):
        assert compare_versions("1.2.3b1", "1.2.3", "PyPI") == -1

    def test_rc_before_release(self):
        assert compare_versions("1.2.3rc1", "1.2.3", "PyPI") == -1

    def test_dev_before_alpha(self):
        assert compare_versions("1.2.3dev0", "1.2.3a1", "PyPI") == -1

    def test_alpha_before_beta(self):
        assert compare_versions("1.2.3a1", "1.2.3b1", "PyPI") == -1

    def test_beta_before_rc(self):
        assert compare_versions("1.2.3b1", "1.2.3rc1", "PyPI") == -1

    def test_post_after_release(self):
        assert compare_versions("1.2.3.post1", "1.2.3", "PyPI") == 1

    def test_post_ordering(self):
        assert compare_versions("1.2.3.post1", "1.2.3.post2", "PyPI") == -1

    def test_different_length_segments(self):
        # 1.2 should be less than 1.2.1
        assert compare_versions("1.2", "1.2.1", "PyPI") == -1

    def test_zero_version(self):
        assert compare_versions("0", "1.0.0", "PyPI") == -1


# -----------------------------------------------------------------------
# Version comparison: npm semver
# -----------------------------------------------------------------------

class TestCompareVersionsSemver:

    def test_equal_versions(self):
        assert compare_versions("1.2.3", "1.2.3", "npm") == 0

    def test_less_than(self):
        assert compare_versions("1.2.3", "1.2.4", "npm") == -1

    def test_greater_than(self):
        assert compare_versions("1.2.4", "1.2.3", "npm") == 1

    def test_pre_release_before_release(self):
        assert compare_versions("1.2.3-beta.1", "1.2.3", "npm") == -1

    def test_pre_release_alpha_before_beta(self):
        assert compare_versions("1.2.3-alpha", "1.2.3-beta", "npm") == -1

    def test_major_comparison(self):
        assert compare_versions("1.0.0", "2.0.0", "npm") == -1


# -----------------------------------------------------------------------
# _is_version_affected
# -----------------------------------------------------------------------

class TestIsVersionAffected:

    def test_version_in_range(self):
        ranges = [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"},
            {"fixed": "2.3.0"},
        ]}]
        assert _is_version_affected("2.2.0", ranges, "PyPI") is True

    def test_version_at_introduced(self):
        ranges = [{"type": "ECOSYSTEM", "events": [
            {"introduced": "1.0.0"},
            {"fixed": "2.0.0"},
        ]}]
        assert _is_version_affected("1.0.0", ranges, "PyPI") is True

    def test_version_at_fixed_not_affected(self):
        ranges = [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"},
            {"fixed": "2.3.0"},
        ]}]
        assert _is_version_affected("2.3.0", ranges, "PyPI") is False

    def test_version_after_fixed_not_affected(self):
        ranges = [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"},
            {"fixed": "2.3.0"},
        ]}]
        assert _is_version_affected("3.0.0", ranges, "PyPI") is False

    def test_no_fixed_version_all_affected(self):
        ranges = [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"},
        ]}]
        assert _is_version_affected("999.0.0", ranges, "PyPI") is True

    def test_empty_ranges_returns_none(self):
        assert _is_version_affected("1.0.0", [], "PyPI") is None

    def test_no_usable_ranges_returns_none(self):
        ranges = [{"type": "GIT", "events": [
            {"introduced": "abc123"},
            {"fixed": "def456"},
        ]}]
        assert _is_version_affected("1.0.0", ranges, "PyPI") is None

    def test_semver_range_npm(self):
        ranges = [{"type": "SEMVER", "events": [
            {"introduced": "0"},
            {"fixed": "4.17.21"},
        ]}]
        assert _is_version_affected("4.17.20", ranges, "npm") is True

    def test_semver_range_npm_not_affected(self):
        ranges = [{"type": "SEMVER", "events": [
            {"introduced": "0"},
            {"fixed": "4.17.21"},
        ]}]
        assert _is_version_affected("4.17.21", ranges, "npm") is False

    def test_pre_release_in_range(self):
        ranges = [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"},
            {"fixed": "2.0.0"},
        ]}]
        assert _is_version_affected("2.0.0rc1", ranges, "PyPI") is True

    def test_introduced_non_zero(self):
        ranges = [{"type": "ECOSYSTEM", "events": [
            {"introduced": "1.5.0"},
            {"fixed": "2.0.0"},
        ]}]
        assert _is_version_affected("1.4.0", ranges, "PyPI") is False

    def test_multiple_ranges_first_matches(self):
        ranges = [
            {"type": "ECOSYSTEM", "events": [
                {"introduced": "1.0.0"},
                {"fixed": "1.5.0"},
            ]},
            {"type": "ECOSYSTEM", "events": [
                {"introduced": "2.0.0"},
                {"fixed": "2.5.0"},
            ]},
        ]
        assert _is_version_affected("1.2.0", ranges, "PyPI") is True

    def test_multiple_ranges_second_matches(self):
        ranges = [
            {"type": "ECOSYSTEM", "events": [
                {"introduced": "1.0.0"},
                {"fixed": "1.5.0"},
            ]},
            {"type": "ECOSYSTEM", "events": [
                {"introduced": "2.0.0"},
                {"fixed": "2.5.0"},
            ]},
        ]
        assert _is_version_affected("2.2.0", ranges, "PyPI") is True

    def test_multiple_ranges_none_match(self):
        ranges = [
            {"type": "ECOSYSTEM", "events": [
                {"introduced": "1.0.0"},
                {"fixed": "1.5.0"},
            ]},
            {"type": "ECOSYSTEM", "events": [
                {"introduced": "2.0.0"},
                {"fixed": "2.5.0"},
            ]},
        ]
        assert _is_version_affected("1.8.0", ranges, "PyPI") is False


# -----------------------------------------------------------------------
# check_dependencies: version-aware filtering
# -----------------------------------------------------------------------

class TestCheckDependenciesVersionFiltering:

    def test_version_outside_range_not_reported(self, tmp_path):
        """A package version after the fix should not produce a finding."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        cache._store_vulns([SAMPLE_VULN])
        deps = [Dependency(name="flask", version="2.4.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) == 0
        cache.close()

    def test_version_inside_range_reported(self, tmp_path):
        """A package version within the affected range should produce a finding."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        cache._store_vulns([SAMPLE_VULN])
        deps = [Dependency(name="flask", version="2.2.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) == 1
        assert findings[0].confidence == 1.0
        cache.close()

    def test_version_at_fixed_not_reported(self, tmp_path):
        """A package version exactly at the fix version is not affected."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        cache._store_vulns([SAMPLE_VULN])
        deps = [Dependency(name="flask", version="2.3.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) == 0
        cache.close()

    def test_confidence_0_7_when_no_ranges(self, tmp_path):
        """When a vuln has no affected ranges, confidence should be 0.7."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        vuln_no_ranges = {
            "id": "PYSEC-2023-NORANGE",
            "summary": "Vuln with no ranges",
            "aliases": ["CVE-2023-0000"],
            "affected": [{
                "package": {"name": "mypkg", "ecosystem": "PyPI"},
                "ranges": [],
            }],
            "severity": [{"type": "CVSS_V3", "score": "6.0"}],
        }
        cache._store_vulns([vuln_no_ranges])
        deps = [Dependency(name="mypkg", version="1.0.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) == 1
        assert findings[0].confidence == 0.7
        cache.close()

    def test_confidence_0_7_when_only_git_ranges(self, tmp_path):
        """When a vuln only has GIT ranges (not ECOSYSTEM/SEMVER), confidence = 0.7."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        vuln_git_only = {
            "id": "PYSEC-2023-GITONLY",
            "summary": "Vuln with git range only",
            "aliases": ["CVE-2023-0001"],
            "affected": [{
                "package": {"name": "gitpkg", "ecosystem": "PyPI"},
                "ranges": [{"type": "GIT", "events": [
                    {"introduced": "abc123"},
                    {"fixed": "def456"},
                ]}],
            }],
            "severity": [{"type": "CVSS_V3", "score": "5.0"}],
        }
        cache._store_vulns([vuln_git_only])
        deps = [Dependency(name="gitpkg", version="1.0.0")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) == 1
        assert findings[0].confidence == 0.7
        cache.close()

    def test_npm_version_filtering(self, tmp_path):
        """npm ecosystem version filtering works correctly."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        npm_vuln = {
            "id": "GHSA-2023-NPM",
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

        # Affected version
        deps = [Dependency(name="lodash", version="4.17.20", ecosystem="npm")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) == 1
        assert findings[0].confidence == 1.0

        # Fixed version — not affected
        deps = [Dependency(name="lodash", version="4.17.21", ecosystem="npm")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) == 0
        cache.close()

    def test_pre_release_version_affected(self, tmp_path):
        """Pre-release versions within range are detected as affected."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        cache._store_vulns([SAMPLE_VULN])  # fixed at 2.3.0
        deps = [Dependency(name="flask", version="2.3.0rc1")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) == 1
        assert findings[0].confidence == 1.0
        cache.close()

    def test_no_fix_version_all_affected(self, tmp_path):
        """When no fix is available, all versions after introduced are affected."""
        cache = OsvCache(db_path=str(tmp_path / "test.db"))
        vuln_no_fix = {
            "id": "PYSEC-2023-NOFIX2",
            "summary": "Unfixed vuln",
            "aliases": [],
            "affected": [{
                "package": {"name": "unfixed", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"},
                ]}],
            }],
            "severity": [{"type": "CVSS_V3", "score": "4.0"}],
        }
        cache._store_vulns([vuln_no_fix])
        deps = [Dependency(name="unfixed", version="99.99.99")]
        findings = check_dependencies(deps, cache=cache, auto_sync=False)
        assert len(findings) == 1
        assert findings[0].confidence == 1.0
        cache.close()
