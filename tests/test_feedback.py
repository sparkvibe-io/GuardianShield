"""Tests for the false positive feedback loop."""

from __future__ import annotations

import unittest

from guardianshield.feedback import FalsePositiveDB, _fingerprint, _pattern_key
from guardianshield.findings import Finding, FindingType, Severity


class TestFingerprint(unittest.TestCase):
    """Tests for fingerprint and pattern_key helpers."""

    def _make_finding(self, **kwargs: object) -> Finding:
        defaults = {
            "finding_type": FindingType.SQL_INJECTION,
            "severity": Severity.HIGH,
            "message": "SQL injection detected",
            "matched_text": "SELECT * FROM users",
            "line_number": 10,
            "file_path": "app.py",
            "scanner": "code_scanner",
            "metadata": {"pattern_name": "sql_string_format"},
        }
        defaults.update(kwargs)
        return Finding(**defaults)  # type: ignore[arg-type]

    def test_fingerprint_deterministic(self) -> None:
        f1 = self._make_finding()
        f2 = self._make_finding()
        self.assertEqual(_fingerprint(f1), _fingerprint(f2))

    def test_fingerprint_differs_by_line(self) -> None:
        f1 = self._make_finding(line_number=10)
        f2 = self._make_finding(line_number=20)
        self.assertNotEqual(_fingerprint(f1), _fingerprint(f2))

    def test_fingerprint_differs_by_file(self) -> None:
        f1 = self._make_finding(file_path="a.py")
        f2 = self._make_finding(file_path="b.py")
        self.assertNotEqual(_fingerprint(f1), _fingerprint(f2))

    def test_fingerprint_length(self) -> None:
        f = self._make_finding()
        self.assertEqual(len(_fingerprint(f)), 16)

    def test_pattern_key(self) -> None:
        f = self._make_finding()
        key = _pattern_key(f)
        self.assertEqual(key, ("sql_string_format", "sql_injection", "code_scanner"))

    def test_pattern_key_injection_type(self) -> None:
        f = self._make_finding(
            finding_type=FindingType.PROMPT_INJECTION,
            scanner="injection_detector",
            metadata={"injection_type": "instruction_override"},
        )
        key = _pattern_key(f)
        self.assertEqual(key[0], "instruction_override")


class TestFalsePositiveDB(unittest.TestCase):
    """Tests for the FalsePositiveDB class."""

    def setUp(self) -> None:
        self.db = FalsePositiveDB(db_path=":memory:")

    def tearDown(self) -> None:
        self.db.close()

    def _make_finding(self, **kwargs: object) -> Finding:
        defaults = {
            "finding_type": FindingType.SQL_INJECTION,
            "severity": Severity.HIGH,
            "message": "SQL injection detected",
            "matched_text": "SELECT * FROM users",
            "line_number": 10,
            "file_path": "app.py",
            "scanner": "code_scanner",
            "metadata": {"pattern_name": "sql_string_format"},
        }
        defaults.update(kwargs)
        return Finding(**defaults)  # type: ignore[arg-type]

    def test_mark_returns_id(self) -> None:
        f = self._make_finding()
        record_id = self.db.mark(f, reason="test FP")
        self.assertIsInstance(record_id, int)
        self.assertGreater(record_id, 0)

    def test_mark_duplicate_is_idempotent(self) -> None:
        f = self._make_finding()
        id1 = self.db.mark(f, reason="first")
        id2 = self.db.mark(f, reason="updated")
        # OR REPLACE means same fingerprint updates the row
        self.assertEqual(id1, id2)

    def test_list_fps_empty(self) -> None:
        records = self.db.list_fps()
        self.assertEqual(records, [])

    def test_list_fps_after_mark(self) -> None:
        f = self._make_finding()
        self.db.mark(f, reason="known FP")
        records = self.db.list_fps()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["pattern_name"], "sql_string_format")
        self.assertEqual(records[0]["reason"], "known FP")

    def test_list_fps_filter_by_scanner(self) -> None:
        f1 = self._make_finding(scanner="code_scanner")
        f2 = self._make_finding(
            scanner="secrets",
            finding_type=FindingType.SECRET,
            metadata={"pattern_name": "aws_key"},
            matched_text="AKIA1234",
        )
        self.db.mark(f1)
        self.db.mark(f2)

        code_fps = self.db.list_fps(scanner="code_scanner")
        self.assertEqual(len(code_fps), 1)

        secret_fps = self.db.list_fps(scanner="secrets")
        self.assertEqual(len(secret_fps), 1)

        all_fps = self.db.list_fps()
        self.assertEqual(len(all_fps), 2)

    def test_unmark_existing(self) -> None:
        f = self._make_finding()
        self.db.mark(f)
        fp = _fingerprint(f)
        result = self.db.unmark(fp)
        self.assertTrue(result)

        # After unmarking, list should be empty
        records = self.db.list_fps()
        self.assertEqual(len(records), 0)

    def test_unmark_nonexistent(self) -> None:
        result = self.db.unmark("nonexistent_fingerprint")
        self.assertFalse(result)

    def test_annotate_exact_match(self) -> None:
        f = self._make_finding()
        self.db.mark(f)

        # Create identical finding (same location, same pattern)
        f2 = self._make_finding()
        self.db.annotate([f2])
        self.assertTrue(f2.metadata.get("false_positive"))

    def test_annotate_potential_fp(self) -> None:
        f = self._make_finding(line_number=10, file_path="a.py")
        self.db.mark(f)

        # Same pattern but different location
        f2 = self._make_finding(line_number=20, file_path="b.py")
        self.db.annotate([f2])
        self.assertTrue(f2.metadata.get("potential_false_positive"))
        self.assertFalse(f2.metadata.get("false_positive", False))

    def test_annotate_no_match(self) -> None:
        f = self._make_finding(
            metadata={"pattern_name": "different_pattern"},
            finding_type=FindingType.XSS,
        )
        self.db.annotate([f])
        self.assertFalse(f.metadata.get("false_positive", False))
        self.assertFalse(f.metadata.get("potential_false_positive", False))

    def test_annotate_empty_list(self) -> None:
        result = self.db.annotate([])
        self.assertEqual(result, [])

    def test_annotate_after_unmark(self) -> None:
        f = self._make_finding()
        self.db.mark(f)
        fp = _fingerprint(f)
        self.db.unmark(fp)

        # After unmarking, should not annotate
        f2 = self._make_finding()
        self.db.annotate([f2])
        self.assertFalse(f2.metadata.get("false_positive", False))
        self.assertFalse(f2.metadata.get("potential_false_positive", False))

    def test_stats_empty(self) -> None:
        stats = self.db.stats()
        self.assertEqual(stats["total_active"], 0)
        self.assertEqual(stats["by_scanner"], {})

    def test_stats_after_marks(self) -> None:
        f1 = self._make_finding(scanner="code_scanner")
        f2 = self._make_finding(
            scanner="secrets",
            finding_type=FindingType.SECRET,
            metadata={"pattern_name": "aws_key"},
            matched_text="AKIA1234",
        )
        self.db.mark(f1)
        self.db.mark(f2)

        stats = self.db.stats()
        self.assertEqual(stats["total_active"], 2)
        self.assertEqual(stats["by_scanner"]["code_scanner"], 1)
        self.assertEqual(stats["by_scanner"]["secrets"], 1)

    def test_cache_invalidation_on_mark(self) -> None:
        f1 = self._make_finding(line_number=10)
        self.db.annotate([f1])  # Populates cache
        self.assertFalse(f1.metadata.get("false_positive", False))

        # Mark and re-annotate — cache should be invalidated
        self.db.mark(f1)
        f2 = self._make_finding(line_number=10)
        self.db.annotate([f2])
        self.assertTrue(f2.metadata.get("false_positive"))

    def test_cache_invalidation_on_unmark(self) -> None:
        f = self._make_finding()
        self.db.mark(f)

        # Populate cache via annotate
        f2 = self._make_finding()
        self.db.annotate([f2])
        self.assertTrue(f2.metadata.get("false_positive"))

        # Unmark and re-annotate
        fp = _fingerprint(f)
        self.db.unmark(fp)
        f3 = self._make_finding()
        self.db.annotate([f3])
        self.assertFalse(f3.metadata.get("false_positive", False))

    def test_list_fps_limit(self) -> None:
        for i in range(10):
            f = self._make_finding(
                line_number=i + 1,
                matched_text=f"match_{i}",
            )
            self.db.mark(f)

        limited = self.db.list_fps(limit=3)
        self.assertEqual(len(limited), 3)


class TestFalsePositiveDBWithReason(unittest.TestCase):
    """Tests for FP records with user-provided reasons."""

    def setUp(self) -> None:
        self.db = FalsePositiveDB(db_path=":memory:")

    def tearDown(self) -> None:
        self.db.close()

    def test_reason_stored(self) -> None:
        f = Finding(
            finding_type=FindingType.SQL_INJECTION,
            severity=Severity.HIGH,
            message="test",
            matched_text="test_query",
            line_number=1,
            scanner="code_scanner",
            metadata={"pattern_name": "sql_test"},
        )
        self.db.mark(f, reason="This is a parameterized query, not injectable")
        records = self.db.list_fps()
        self.assertEqual(records[0]["reason"], "This is a parameterized query, not injectable")


class TestCoreIntegration(unittest.TestCase):
    """Integration tests for FP feedback in GuardianShield core."""

    def test_core_scan_code_annotates_fps(self) -> None:
        from guardianshield.core import GuardianShield
        from guardianshield.feedback import FalsePositiveDB

        db = FalsePositiveDB(db_path=":memory:")
        shield = GuardianShield(feedback_db=db)

        code = "query = 'SELECT * FROM users WHERE id=' + user_id"

        # First scan — get findings
        findings = shield.scan_code(code)
        self.assertTrue(len(findings) > 0)

        # Mark first finding as FP
        shield.mark_false_positive(findings[0].to_dict(), reason="test")

        # Second scan — should annotate as FP
        findings2 = shield.scan_code(code)
        fp_findings = [f for f in findings2 if f.metadata.get("false_positive")]
        self.assertTrue(len(fp_findings) > 0)

        shield.close()

    def test_core_list_false_positives(self) -> None:
        from guardianshield.core import GuardianShield
        from guardianshield.feedback import FalsePositiveDB

        db = FalsePositiveDB(db_path=":memory:")
        shield = GuardianShield(feedback_db=db)

        code = "query = 'SELECT * FROM users WHERE id=' + user_id"
        findings = shield.scan_code(code)
        shield.mark_false_positive(findings[0].to_dict())

        fps = shield.list_false_positives()
        self.assertEqual(len(fps), 1)

        shield.close()

    def test_core_unmark_false_positive(self) -> None:
        from guardianshield.core import GuardianShield
        from guardianshield.feedback import FalsePositiveDB, _fingerprint

        db = FalsePositiveDB(db_path=":memory:")
        shield = GuardianShield(feedback_db=db)

        code = "query = 'SELECT * FROM users WHERE id=' + user_id"
        findings = shield.scan_code(code)
        shield.mark_false_positive(findings[0].to_dict())

        fp = _fingerprint(findings[0])
        result = shield.unmark_false_positive(fp)
        self.assertTrue(result["success"])

        fps = shield.list_false_positives()
        self.assertEqual(len(fps), 0)

        shield.close()

    def test_core_status_includes_fp_stats(self) -> None:
        from guardianshield.core import GuardianShield
        from guardianshield.feedback import FalsePositiveDB

        db = FalsePositiveDB(db_path=":memory:")
        shield = GuardianShield(feedback_db=db)

        code = "query = 'SELECT * FROM users WHERE id=' + user_id"
        findings = shield.scan_code(code)
        shield.mark_false_positive(findings[0].to_dict())

        status = shield.status()
        self.assertIn("false_positives", status)
        self.assertEqual(status["false_positives"]["total_active"], 1)

        shield.close()

    def test_potential_fp_across_files(self) -> None:
        """Test that same pattern in different file gets potential_false_positive."""
        from guardianshield.core import GuardianShield
        from guardianshield.feedback import FalsePositiveDB

        db = FalsePositiveDB(db_path=":memory:")
        shield = GuardianShield(feedback_db=db)

        code = "query = 'SELECT * FROM users WHERE id=' + user_id"

        # Scan with file_path A
        findings_a = shield.scan_code(code, file_path="a.py")
        self.assertTrue(len(findings_a) > 0)
        shield.mark_false_positive(findings_a[0].to_dict())

        # Scan with file_path B — same pattern, different file
        findings_b = shield.scan_code(code, file_path="b.py")
        potential = [
            f for f in findings_b
            if f.metadata.get("potential_false_positive")
        ]
        self.assertTrue(len(potential) > 0)

        shield.close()


class TestMCPIntegration(unittest.TestCase):
    """Tests for FP MCP tools."""

    def _init_server(self) -> object:
        from guardianshield.core import GuardianShield
        from guardianshield.feedback import FalsePositiveDB
        from guardianshield.mcp_server import GuardianShieldMCPServer

        db = FalsePositiveDB(db_path=":memory:")
        shield = GuardianShield(feedback_db=db)
        server = GuardianShieldMCPServer(shield=shield)
        server._initialized = True
        return server

    def test_tools_list_includes_fp_tools(self) -> None:
        from guardianshield.mcp_server import TOOLS

        tool_names = [t["name"] for t in TOOLS]
        self.assertIn("mark_false_positive", tool_names)
        self.assertIn("list_false_positives", tool_names)
        self.assertIn("unmark_false_positive", tool_names)

    def test_tool_count(self) -> None:
        from guardianshield.mcp_server import TOOLS

        self.assertEqual(len(TOOLS), 19)

    def test_mark_fp_via_mcp(self) -> None:
        import json
        server = self._init_server()

        # First scan to get a finding
        scan_result = server._tool_scan_code({"code": "query = 'SELECT * FROM ' + x"})
        result_data = json.loads(scan_result["content"][0]["text"])
        self.assertGreater(result_data["finding_count"], 0)

        finding = result_data["findings"][0]

        # Mark as FP
        mark_result = server._tool_mark_false_positive({
            "finding": finding,
            "reason": "test FP",
        })
        mark_data = json.loads(mark_result["content"][0]["text"])
        self.assertIn("fingerprint", mark_data)

        # List FPs
        list_result = server._tool_list_false_positives({})
        list_data = json.loads(list_result["content"][0]["text"])
        self.assertEqual(list_data["count"], 1)

        # Unmark FP
        unmark_result = server._tool_unmark_false_positive({
            "fingerprint": mark_data["fingerprint"],
        })
        unmark_data = json.loads(unmark_result["content"][0]["text"])
        self.assertTrue(unmark_data["success"])

    def test_mark_fp_missing_finding(self) -> None:
        server = self._init_server()
        result = server._tool_mark_false_positive({})
        self.assertTrue(result.get("isError"))

    def test_unmark_fp_missing_fingerprint(self) -> None:
        server = self._init_server()
        result = server._tool_unmark_false_positive({})
        self.assertTrue(result.get("isError"))


if __name__ == "__main__":
    unittest.main()
