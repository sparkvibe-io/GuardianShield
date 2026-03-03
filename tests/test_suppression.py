"""Tests for inline suppression comments."""

from __future__ import annotations

import unittest

from guardianshield.findings import Finding, FindingType, Severity
from guardianshield.suppression import (
    SuppressionDirective,
    filter_suppressed_findings,
    parse_suppression_comment,
)


class TestSuppressionDirective(unittest.TestCase):
    """Tests for the SuppressionDirective dataclass."""

    def test_defaults(self) -> None:
        d = SuppressionDirective()
        self.assertEqual(d.rules, [])
        self.assertEqual(d.reason, "")
        self.assertEqual(d.line_number, 0)

    def test_with_rules(self) -> None:
        d = SuppressionDirective(rules=["xss", "sql_injection"])
        self.assertEqual(d.rules, ["xss", "sql_injection"])

    def test_with_reason(self) -> None:
        d = SuppressionDirective(reason="known safe")
        self.assertEqual(d.reason, "known safe")

    def test_with_line_number(self) -> None:
        d = SuppressionDirective(line_number=42)
        self.assertEqual(d.line_number, 42)

    def test_rules_independent_instances(self) -> None:
        """Each instance should get its own list."""
        d1 = SuppressionDirective()
        d2 = SuppressionDirective()
        d1.rules.append("xss")
        self.assertEqual(d2.rules, [])


class TestParseSuppressionComment(unittest.TestCase):
    """Tests for parse_suppression_comment."""

    # --- Python # style ---

    def test_python_blanket(self) -> None:
        d = parse_suppression_comment("code()  # guardianshield:ignore")
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, [])
        self.assertEqual(d.reason, "")

    def test_python_single_rule(self) -> None:
        d = parse_suppression_comment(
            "code()  # guardianshield:ignore[sql_injection]"
        )
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, ["sql_injection"])

    def test_python_multi_rule(self) -> None:
        d = parse_suppression_comment(
            "code()  # guardianshield:ignore[sql_injection,xss]"
        )
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, ["sql_injection", "xss"])

    def test_python_with_reason(self) -> None:
        d = parse_suppression_comment(
            "code()  # guardianshield:ignore[xss] -- known safe"
        )
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, ["xss"])
        self.assertEqual(d.reason, "known safe")

    def test_python_blanket_with_reason(self) -> None:
        d = parse_suppression_comment(
            "code()  # guardianshield:ignore -- legacy code"
        )
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, [])
        self.assertEqual(d.reason, "legacy code")

    # --- JS // style ---

    def test_js_blanket(self) -> None:
        d = parse_suppression_comment("code();  // guardianshield:ignore")
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, [])

    def test_js_single_rule(self) -> None:
        d = parse_suppression_comment(
            "code();  // guardianshield:ignore[xss]"
        )
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, ["xss"])

    def test_js_with_reason(self) -> None:
        d = parse_suppression_comment(
            "code();  // guardianshield:ignore[xss] -- sanitized above"
        )
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, ["xss"])
        self.assertEqual(d.reason, "sanitized above")

    # --- C-style /* */ ---

    def test_c_style_blanket(self) -> None:
        d = parse_suppression_comment("code();  /* guardianshield:ignore */")
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, [])

    def test_c_style_with_rule(self) -> None:
        d = parse_suppression_comment(
            "code();  /* guardianshield:ignore[command_injection] */"
        )
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, ["command_injection"])

    def test_c_style_with_reason(self) -> None:
        d = parse_suppression_comment(
            "code();  /* guardianshield:ignore[xss] */ -- safe context"
        )
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, ["xss"])

    # --- Edge cases ---

    def test_no_directive(self) -> None:
        self.assertIsNone(parse_suppression_comment("code()  # normal comment"))

    def test_no_comment(self) -> None:
        self.assertIsNone(parse_suppression_comment("plain code here"))

    def test_empty_string(self) -> None:
        self.assertIsNone(parse_suppression_comment(""))

    def test_empty_brackets(self) -> None:
        d = parse_suppression_comment("code()  # guardianshield:ignore[]")
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, [])

    def test_whitespace_in_rules(self) -> None:
        d = parse_suppression_comment(
            "code()  # guardianshield:ignore[ sql_injection , xss ]"
        )
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, ["sql_injection", "xss"])

    def test_extra_whitespace_before_directive(self) -> None:
        d = parse_suppression_comment(
            "code()  #   guardianshield:ignore[xss]"
        )
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, ["xss"])

    def test_directive_only_line(self) -> None:
        """A line that is only a suppression comment."""
        d = parse_suppression_comment("# guardianshield:ignore[secret]")
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, ["secret"])

    def test_three_rules(self) -> None:
        d = parse_suppression_comment(
            "code()  # guardianshield:ignore[xss,sql_injection,secret]"
        )
        self.assertIsNotNone(d)
        self.assertEqual(d.rules, ["xss", "sql_injection", "secret"])

    def test_reason_with_special_chars(self) -> None:
        d = parse_suppression_comment(
            "code()  # guardianshield:ignore -- FP: ticket #123 (verified)"
        )
        self.assertIsNotNone(d)
        self.assertEqual(d.reason, "FP: ticket #123 (verified)")

    def test_partial_match_no_colon(self) -> None:
        """guardianshield without :ignore should not match."""
        self.assertIsNone(
            parse_suppression_comment("# guardianshield: something else")
        )


# --- Helper ---

def _make_finding(
    finding_type: FindingType = FindingType.SQL_INJECTION,
    line_number: int = 1,
    pattern_name: str = "sql_string_format",
    **kwargs: object,
) -> Finding:
    defaults = {
        "finding_type": finding_type,
        "severity": Severity.HIGH,
        "message": "Test finding",
        "matched_text": "test",
        "line_number": line_number,
        "file_path": "app.py",
        "scanner": "code_scanner",
        "metadata": {"pattern_name": pattern_name},
    }
    defaults.update(kwargs)
    return Finding(**defaults)  # type: ignore[arg-type]


class TestFilterSuppressed(unittest.TestCase):
    """Tests for filter_suppressed_findings."""

    def test_blanket_suppresses_all(self) -> None:
        code = "query(user_input)  # guardianshield:ignore\n"
        f = _make_finding(line_number=1)
        result = filter_suppressed_findings([f], code)
        self.assertTrue(result[0].metadata.get("suppressed"))

    def test_blanket_suppresses_multiple_findings_same_line(self) -> None:
        code = "dangerous(user_input)  # guardianshield:ignore\n"
        f1 = _make_finding(
            finding_type=FindingType.SQL_INJECTION, line_number=1
        )
        f2 = _make_finding(finding_type=FindingType.XSS, line_number=1)
        filter_suppressed_findings([f1, f2], code)
        self.assertTrue(f1.metadata.get("suppressed"))
        self.assertTrue(f2.metadata.get("suppressed"))

    def test_rule_specific_by_finding_type(self) -> None:
        code = "query(user_input)  # guardianshield:ignore[sql_injection]\n"
        f = _make_finding(
            finding_type=FindingType.SQL_INJECTION, line_number=1
        )
        filter_suppressed_findings([f], code)
        self.assertTrue(f.metadata.get("suppressed"))

    def test_rule_specific_by_pattern_name(self) -> None:
        code = "query(user_input)  # guardianshield:ignore[sql_string_format]\n"
        f = _make_finding(
            finding_type=FindingType.SQL_INJECTION,
            line_number=1,
            pattern_name="sql_string_format",
        )
        filter_suppressed_findings([f], code)
        self.assertTrue(f.metadata.get("suppressed"))

    def test_rule_specific_non_matching(self) -> None:
        code = "query(user_input)  # guardianshield:ignore[xss]\n"
        f = _make_finding(
            finding_type=FindingType.SQL_INJECTION, line_number=1
        )
        filter_suppressed_findings([f], code)
        self.assertNotIn("suppressed", f.metadata)

    def test_multi_rule_first_matches(self) -> None:
        code = "code()  # guardianshield:ignore[sql_injection,xss]\n"
        f = _make_finding(
            finding_type=FindingType.SQL_INJECTION, line_number=1
        )
        filter_suppressed_findings([f], code)
        self.assertTrue(f.metadata.get("suppressed"))

    def test_multi_rule_second_matches(self) -> None:
        code = "code()  # guardianshield:ignore[sql_injection,xss]\n"
        f = _make_finding(finding_type=FindingType.XSS, line_number=1)
        filter_suppressed_findings([f], code)
        self.assertTrue(f.metadata.get("suppressed"))

    def test_multi_rule_none_matches(self) -> None:
        code = "code()  # guardianshield:ignore[xss,secret]\n"
        f = _make_finding(
            finding_type=FindingType.SQL_INJECTION, line_number=1
        )
        filter_suppressed_findings([f], code)
        self.assertNotIn("suppressed", f.metadata)

    def test_no_suppression_in_code(self) -> None:
        code = "query(user_input)\n"
        f = _make_finding(line_number=1)
        filter_suppressed_findings([f], code)
        self.assertNotIn("suppressed", f.metadata)

    def test_empty_findings(self) -> None:
        code = "code()  # guardianshield:ignore\n"
        result = filter_suppressed_findings([], code)
        self.assertEqual(result, [])

    def test_empty_code(self) -> None:
        f = _make_finding(line_number=1)
        result = filter_suppressed_findings([f], "")
        self.assertEqual(len(result), 1)
        self.assertNotIn("suppressed", f.metadata)

    def test_finding_on_different_line(self) -> None:
        code = "clean_line()\nquery(user_input)  # guardianshield:ignore\n"
        f = _make_finding(line_number=1)  # finding on line 1, suppress on 2
        filter_suppressed_findings([f], code)
        self.assertNotIn("suppressed", f.metadata)

    def test_multiple_lines_different_directives(self) -> None:
        code = (
            "query(x)  # guardianshield:ignore[sql_injection]\n"
            "safe_line()\n"
            "render(y)  # guardianshield:ignore[xss]\n"
        )
        f_sql = _make_finding(
            finding_type=FindingType.SQL_INJECTION, line_number=1
        )
        f_xss = _make_finding(finding_type=FindingType.XSS, line_number=3)
        filter_suppressed_findings([f_sql, f_xss], code)
        self.assertTrue(f_sql.metadata.get("suppressed"))
        self.assertTrue(f_xss.metadata.get("suppressed"))

    def test_returns_same_list(self) -> None:
        code = "code()  # guardianshield:ignore\n"
        findings = [_make_finding(line_number=1)]
        result = filter_suppressed_findings(findings, code)
        self.assertIs(result, findings)

    def test_js_comment_suppression(self) -> None:
        code = "fetch(url);  // guardianshield:ignore\n"
        f = _make_finding(line_number=1)
        filter_suppressed_findings([f], code)
        self.assertTrue(f.metadata.get("suppressed"))

    def test_c_style_comment_suppression(self) -> None:
        code = "run(cmd);  /* guardianshield:ignore */\n"
        f = _make_finding(line_number=1)
        filter_suppressed_findings([f], code)
        self.assertTrue(f.metadata.get("suppressed"))


class TestMetadataPreservation(unittest.TestCase):
    """Tests for metadata preservation during suppression."""

    def test_suppressed_flag_set(self) -> None:
        code = "code()  # guardianshield:ignore\n"
        f = _make_finding(line_number=1)
        filter_suppressed_findings([f], code)
        self.assertIs(f.metadata["suppressed"], True)

    def test_suppression_reason_set(self) -> None:
        code = "code()  # guardianshield:ignore -- legacy code\n"
        f = _make_finding(line_number=1)
        filter_suppressed_findings([f], code)
        self.assertEqual(f.metadata["suppression_reason"], "legacy code")

    def test_no_reason_key_when_no_reason(self) -> None:
        code = "code()  # guardianshield:ignore\n"
        f = _make_finding(line_number=1)
        filter_suppressed_findings([f], code)
        self.assertNotIn("suppression_reason", f.metadata)

    def test_unsuppressed_no_suppressed_key(self) -> None:
        code = "code()  # guardianshield:ignore[xss]\n"
        f = _make_finding(
            finding_type=FindingType.SQL_INJECTION, line_number=1
        )
        filter_suppressed_findings([f], code)
        self.assertNotIn("suppressed", f.metadata)

    def test_existing_metadata_preserved(self) -> None:
        code = "code()  # guardianshield:ignore\n"
        f = _make_finding(line_number=1)
        f.metadata["custom_key"] = "custom_value"
        filter_suppressed_findings([f], code)
        self.assertEqual(f.metadata["custom_key"], "custom_value")
        self.assertTrue(f.metadata["suppressed"])

    def test_existing_pattern_name_preserved(self) -> None:
        code = "code()  # guardianshield:ignore\n"
        f = _make_finding(line_number=1, pattern_name="sql_string_format")
        filter_suppressed_findings([f], code)
        self.assertEqual(f.metadata["pattern_name"], "sql_string_format")
        self.assertTrue(f.metadata["suppressed"])

    def test_rule_match_by_pattern_name_preserves_metadata(self) -> None:
        code = "code()  # guardianshield:ignore[sql_string_format] -- reviewed\n"
        f = _make_finding(line_number=1, pattern_name="sql_string_format")
        f.metadata["extra"] = 42
        filter_suppressed_findings([f], code)
        self.assertTrue(f.metadata["suppressed"])
        self.assertEqual(f.metadata["suppression_reason"], "reviewed")
        self.assertEqual(f.metadata["extra"], 42)
        self.assertEqual(f.metadata["pattern_name"], "sql_string_format")

    def test_multiple_findings_mixed_suppression(self) -> None:
        """Some suppressed, some not -- metadata correct for each."""
        code = "code()  # guardianshield:ignore[xss]\n"
        f_xss = _make_finding(finding_type=FindingType.XSS, line_number=1)
        f_sql = _make_finding(
            finding_type=FindingType.SQL_INJECTION, line_number=1
        )
        filter_suppressed_findings([f_xss, f_sql], code)
        self.assertTrue(f_xss.metadata.get("suppressed"))
        self.assertNotIn("suppressed", f_sql.metadata)


if __name__ == "__main__":
    unittest.main()
