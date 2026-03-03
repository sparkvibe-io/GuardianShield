"""Tests for SARIF 2.1.0 export module.

NOTE: This file creates Finding objects with intentional vulnerability pattern
strings as test data. No vulnerable code is executed.
"""

import json

from guardianshield.findings import (
    Finding,
    FindingType,
    Range,
    Remediation,
    Severity,
)
from guardianshield.sarif import (
    _SARIF_SCHEMA,
    _SARIF_VERSION,
    _build_cwe_taxonomy,
    _build_result,
    _build_rule,
    _finding_fingerprint,
    _finding_rule_id,
    _make_uri,
    _severity_to_sarif_level,
    _severity_to_score,
    findings_to_sarif,
    findings_to_sarif_json,
)

# -- Helpers ------------------------------------------------------------------


def _make_finding(**overrides):
    defaults = dict(
        finding_type=FindingType.SQL_INJECTION,
        severity=Severity.HIGH,
        message="SQL injection detected",
        matched_text="query = 'SELECT * FROM ' + x",
        line_number=10,
        file_path="src/app.py",
        scanner="code_scanner",
        metadata={"pattern_name": "raw_query"},
        cwe_ids=["CWE-89"],
    )
    defaults.update(overrides)
    return Finding(**defaults)


# -- TestSeverityMapping ------------------------------------------------------


class TestSeverityMapping:
    def test_critical_maps_to_error(self):
        assert _severity_to_sarif_level(Severity.CRITICAL) == "error"

    def test_high_maps_to_error(self):
        assert _severity_to_sarif_level(Severity.HIGH) == "error"

    def test_medium_maps_to_warning(self):
        assert _severity_to_sarif_level(Severity.MEDIUM) == "warning"

    def test_low_maps_to_note(self):
        assert _severity_to_sarif_level(Severity.LOW) == "note"

    def test_info_maps_to_none(self):
        assert _severity_to_sarif_level(Severity.INFO) == "none"

    def test_critical_score(self):
        assert _severity_to_score(Severity.CRITICAL) == 9.0

    def test_high_score(self):
        assert _severity_to_score(Severity.HIGH) == 7.0

    def test_medium_score(self):
        assert _severity_to_score(Severity.MEDIUM) == 4.0

    def test_low_score(self):
        assert _severity_to_score(Severity.LOW) == 1.0

    def test_info_score(self):
        assert _severity_to_score(Severity.INFO) == 0.1


# -- TestRuleIdGeneration -----------------------------------------------------


class TestRuleIdGeneration:
    def test_rule_id_with_pattern_name(self):
        f = _make_finding()
        assert _finding_rule_id(f) == "sql_injection/raw_query"

    def test_rule_id_without_pattern_name(self):
        f = _make_finding(metadata={})
        assert _finding_rule_id(f) == "sql_injection"

    def test_rule_id_empty_pattern_name(self):
        f = _make_finding(metadata={"pattern_name": ""})
        assert _finding_rule_id(f) == "sql_injection"

    def test_rule_id_special_characters_in_pattern(self):
        f = _make_finding(metadata={"pattern_name": "eval_exec/danger"})
        assert _finding_rule_id(f) == "sql_injection/eval_exec/danger"

    def test_rule_id_different_finding_types(self):
        f_xss = _make_finding(finding_type=FindingType.XSS)
        f_secret = _make_finding(finding_type=FindingType.SECRET)
        assert _finding_rule_id(f_xss).startswith("xss/")
        assert _finding_rule_id(f_secret).startswith("secret/")

    def test_rule_id_with_spaces_in_pattern(self):
        f = _make_finding(metadata={"pattern_name": "raw query builder"})
        assert _finding_rule_id(f) == "sql_injection/raw query builder"


# -- TestBuildRule ------------------------------------------------------------


class TestBuildRule:
    def test_rule_has_id(self):
        f = _make_finding()
        rule = _build_rule(f, "sql_injection/raw_query")
        assert rule["id"] == "sql_injection/raw_query"

    def test_rule_short_description(self):
        f = _make_finding(message="Potential SQL injection")
        rule = _build_rule(f, "sql_injection/raw_query")
        assert rule["shortDescription"]["text"] == "Potential SQL injection"

    def test_rule_security_severity(self):
        f = _make_finding(severity=Severity.CRITICAL)
        rule = _build_rule(f, "test")
        assert rule["properties"]["security-severity"] == "9.0"

    def test_rule_with_remediation_text(self):
        remediation = Remediation(description="Use parameterized queries")
        f = _make_finding(remediation=remediation)
        rule = _build_rule(f, "test")
        assert rule["help"]["text"] == "Use parameterized queries"

    def test_rule_with_remediation_markdown(self):
        remediation = Remediation(
            description="Use parameterized queries",
            before="query = 'SELECT * FROM ' + x",
            after="cursor.execute('SELECT * FROM ?', [x])",
        )
        f = _make_finding(remediation=remediation)
        rule = _build_rule(f, "test")
        assert "markdown" in rule["help"]
        assert "**Before:**" in rule["help"]["markdown"]
        assert "**After:**" in rule["help"]["markdown"]

    def test_rule_without_remediation(self):
        f = _make_finding(remediation=None)
        rule = _build_rule(f, "test")
        assert "help" not in rule

    def test_rule_remediation_text_only_no_markdown(self):
        remediation = Remediation(description="Fix it")
        f = _make_finding(remediation=remediation)
        rule = _build_rule(f, "test")
        assert rule["help"]["text"] == "Fix it"
        assert "markdown" not in rule["help"]

    def test_rule_cwe_relationships(self):
        f = _make_finding(cwe_ids=["CWE-89", "CWE-564"])
        rule = _build_rule(f, "test")
        assert "relationships" in rule
        assert len(rule["relationships"]) == 2
        ids = [r["target"]["id"] for r in rule["relationships"]]
        assert "CWE-89" in ids
        assert "CWE-564" in ids

    def test_rule_cwe_relationship_structure(self):
        f = _make_finding(cwe_ids=["CWE-89"])
        rule = _build_rule(f, "test")
        rel = rule["relationships"][0]
        assert rel["target"]["toolComponent"]["name"] == "CWE"
        assert rel["target"]["toolComponent"]["index"] == 0
        assert rel["kinds"] == ["superset"]

    def test_rule_no_cwe_ids(self):
        f = _make_finding(cwe_ids=[])
        rule = _build_rule(f, "test")
        assert "relationships" not in rule


# -- TestBuildResult ----------------------------------------------------------


class TestBuildResult:
    def test_result_rule_id(self):
        f = _make_finding()
        result = _build_result(f, "sql_injection/raw_query", None)
        assert result["ruleId"] == "sql_injection/raw_query"

    def test_result_level(self):
        f = _make_finding(severity=Severity.MEDIUM)
        result = _build_result(f, "test", None)
        assert result["level"] == "warning"

    def test_result_message(self):
        f = _make_finding(message="Bad query")
        result = _build_result(f, "test", None)
        assert result["message"]["text"] == "Bad query"

    def test_result_fingerprint(self):
        f = _make_finding()
        result = _build_result(f, "test", None)
        fp = result["partialFingerprints"]["primaryLocationLineHash"]
        assert isinstance(fp, str)
        assert len(fp) == 16

    def test_result_location_uri(self):
        f = _make_finding(file_path="src/app.py")
        result = _build_result(f, "test", None)
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "src/app.py"

    def test_result_region_from_line_number(self):
        f = _make_finding(line_number=42, range=None)
        result = _build_result(f, "test", None)
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 42

    def test_result_region_from_range(self):
        r = Range(start_line=9, start_col=4, end_line=9, end_col=30)
        f = _make_finding(range=r)
        result = _build_result(f, "test", None)
        region = result["locations"][0]["physicalLocation"]["region"]
        # LSP 0-based -> SARIF 1-based
        assert region["startLine"] == 10
        assert region["startColumn"] == 5
        assert region["endLine"] == 10
        assert region["endColumn"] == 31

    def test_result_no_file_path(self):
        f = _make_finding(file_path=None)
        result = _build_result(f, "test", None)
        assert "locations" not in result

    def test_result_line_number_zero_no_region(self):
        f = _make_finding(line_number=0, range=None)
        result = _build_result(f, "test", None)
        loc = result["locations"][0]["physicalLocation"]
        assert "region" not in loc

    def test_fingerprint_consistent_with_module_function(self):
        f = _make_finding()
        result = _build_result(f, "test", None)
        fp_from_result = result["partialFingerprints"]["primaryLocationLineHash"]
        fp_direct = _finding_fingerprint(f)
        assert fp_from_result == fp_direct


# -- TestFindingsToSarif ------------------------------------------------------


class TestFindingsToSarif:
    def test_empty_findings(self):
        sarif = findings_to_sarif([])
        assert sarif["version"] == _SARIF_VERSION
        assert sarif["$schema"] == _SARIF_SCHEMA
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_single_finding(self):
        f = _make_finding()
        sarif = findings_to_sarif([f])
        run = sarif["runs"][0]
        assert len(run["results"]) == 1
        assert len(run["tool"]["driver"]["rules"]) == 1

    def test_multiple_findings(self):
        f1 = _make_finding(line_number=1)
        f2 = _make_finding(line_number=2, finding_type=FindingType.XSS,
                           metadata={"pattern_name": "dom_xss"}, cwe_ids=["CWE-79"])
        sarif = findings_to_sarif([f1, f2])
        run = sarif["runs"][0]
        assert len(run["results"]) == 2
        assert len(run["tool"]["driver"]["rules"]) == 2

    def test_rules_dedup(self):
        """Two findings with the same rule_id should produce only one rule."""
        f1 = _make_finding(line_number=1)
        f2 = _make_finding(line_number=2)
        sarif = findings_to_sarif([f1, f2])
        run = sarif["runs"][0]
        assert len(run["results"]) == 2
        assert len(run["tool"]["driver"]["rules"]) == 1

    def test_tool_name_default(self):
        sarif = findings_to_sarif([])
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "GuardianShield"

    def test_tool_name_custom(self):
        sarif = findings_to_sarif([], tool_name="CustomTool")
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "CustomTool"

    def test_tool_version_custom(self):
        sarif = findings_to_sarif([], tool_version="2.0.0")
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["version"] == "2.0.0"

    def test_information_uri(self):
        sarif = findings_to_sarif([])
        driver = sarif["runs"][0]["tool"]["driver"]
        assert "github.com" in driver["informationUri"]

    def test_no_taxonomy_when_no_cwes(self):
        f = _make_finding(cwe_ids=[])
        sarif = findings_to_sarif([f])
        assert "taxonomies" not in sarif["runs"][0]


# -- TestBasePathHandling -----------------------------------------------------


class TestBasePathHandling:
    def test_relative_path_with_base(self):
        uri = _make_uri("/project/src/app.py", "/project")
        assert uri == "src/app.py"

    def test_no_base_path(self):
        uri = _make_uri("src/app.py", None)
        assert uri == "src/app.py"

    def test_base_path_in_result(self):
        f = _make_finding(file_path="/project/src/app.py")
        result = _build_result(f, "test", "/project")
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "src/app.py"

    def test_findings_to_sarif_with_base_path(self):
        f = _make_finding(file_path="/project/src/app.py")
        sarif = findings_to_sarif([f], base_path="/project")
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "src/app.py"

    def test_forward_slashes_on_backslash_paths(self):
        uri = _make_uri("src\\models\\user.py", None)
        assert "\\" not in uri
        assert uri == "src/models/user.py"


# -- TestFindingsToSarifJson --------------------------------------------------


class TestFindingsToSarifJson:
    def test_valid_json_output(self):
        f = _make_finding()
        result = findings_to_sarif_json([f])
        parsed = json.loads(result)
        assert parsed["version"] == _SARIF_VERSION

    def test_indent_parameter(self):
        f = _make_finding()
        compact = findings_to_sarif_json([f], indent=None)
        indented = findings_to_sarif_json([f], indent=4)
        assert len(indented) > len(compact)
        assert "\n" not in compact
        assert "\n" in indented

    def test_round_trip_parse(self):
        f = _make_finding()
        json_str = findings_to_sarif_json([f])
        parsed = json.loads(json_str)
        assert parsed["$schema"] == _SARIF_SCHEMA
        assert len(parsed["runs"][0]["results"]) == 1

    def test_default_indent_is_two(self):
        json_str = findings_to_sarif_json([])
        # Default indent=2 means lines start with spaces in multiples of 2
        lines = json_str.split("\n")
        # Second line should be indented by 2 spaces
        assert lines[1].startswith("  ")

    def test_unicode_content(self):
        f = _make_finding(message="Inyeccion SQL detectada")
        json_str = findings_to_sarif_json([f])
        assert "Inyeccion" in json_str
        parsed = json.loads(json_str)
        assert parsed["runs"][0]["results"][0]["message"]["text"] == "Inyeccion SQL detectada"


# -- TestCWETaxonomies --------------------------------------------------------


class TestCWETaxonomies:
    def test_single_cwe(self):
        f = _make_finding(cwe_ids=["CWE-89"])
        sarif = findings_to_sarif([f])
        taxonomies = sarif["runs"][0]["taxonomies"]
        assert len(taxonomies) == 1
        assert taxonomies[0]["name"] == "CWE"
        assert len(taxonomies[0]["taxa"]) == 1
        assert taxonomies[0]["taxa"][0]["id"] == "CWE-89"

    def test_multiple_cwes_across_findings(self):
        f1 = _make_finding(cwe_ids=["CWE-89"])
        f2 = _make_finding(
            finding_type=FindingType.XSS,
            metadata={"pattern_name": "xss"},
            cwe_ids=["CWE-79"],
            line_number=20,
        )
        sarif = findings_to_sarif([f1, f2])
        taxa = sarif["runs"][0]["taxonomies"][0]["taxa"]
        ids = [t["id"] for t in taxa]
        assert "CWE-79" in ids
        assert "CWE-89" in ids

    def test_cwe_dedup_across_findings(self):
        """Two findings with the same CWE should produce one taxonomy entry."""
        f1 = _make_finding(line_number=1, cwe_ids=["CWE-89"])
        f2 = _make_finding(line_number=2, cwe_ids=["CWE-89"])
        sarif = findings_to_sarif([f1, f2])
        taxa = sarif["runs"][0]["taxonomies"][0]["taxa"]
        assert len(taxa) == 1

    def test_no_cwes_no_taxonomy(self):
        f = _make_finding(cwe_ids=[])
        sarif = findings_to_sarif([f])
        assert "taxonomies" not in sarif["runs"][0]

    def test_taxonomy_organization(self):
        f = _make_finding(cwe_ids=["CWE-89"])
        sarif = findings_to_sarif([f])
        taxonomy = sarif["runs"][0]["taxonomies"][0]
        assert taxonomy["organization"] == "MITRE"
        assert "Common Weakness" in taxonomy["shortDescription"]["text"]

    def test_taxa_sorted(self):
        f = _make_finding(cwe_ids=["CWE-564", "CWE-89", "CWE-79"])
        sarif = findings_to_sarif([f])
        taxa = sarif["runs"][0]["taxonomies"][0]["taxa"]
        ids = [t["id"] for t in taxa]
        assert ids == sorted(ids)

    def test_build_cwe_taxonomy_directly(self):
        taxonomy = _build_cwe_taxonomy({"CWE-79", "CWE-89"})
        assert taxonomy["name"] == "CWE"
        assert len(taxonomy["taxa"]) == 2


# -- TestEdgeCases ------------------------------------------------------------


class TestEdgeCases:
    def test_none_file_path(self):
        f = _make_finding(file_path=None)
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert "locations" not in result

    def test_empty_matched_text(self):
        f = _make_finding(matched_text="")
        sarif = findings_to_sarif([f])
        assert len(sarif["runs"][0]["results"]) == 1

    def test_missing_metadata(self):
        f = _make_finding(metadata={})
        rule_id = _finding_rule_id(f)
        assert rule_id == "sql_injection"

    def test_no_range_uses_line_number(self):
        f = _make_finding(range=None, line_number=42)
        result = _build_result(f, "test", None)
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 42
        assert "startColumn" not in region

    def test_fingerprint_with_none_file_path(self):
        f = _make_finding(file_path=None)
        fp = _finding_fingerprint(f)
        assert isinstance(fp, str) and len(fp) == 16

    def test_fingerprint_hex_chars(self):
        f = _make_finding()
        fp = _finding_fingerprint(f)
        assert all(c in "0123456789abcdef" for c in fp)

    def test_all_finding_types_produce_valid_sarif(self):
        findings = []
        for ft in FindingType:
            findings.append(_make_finding(
                finding_type=ft,
                metadata={"pattern_name": ft.value},
                line_number=findings.__len__() + 1,
            ))
        sarif = findings_to_sarif(findings)
        assert len(sarif["runs"][0]["results"]) == len(FindingType)

    def test_all_severities_produce_valid_sarif(self):
        findings = []
        for sev in Severity:
            findings.append(_make_finding(
                severity=sev,
                line_number=findings.__len__() + 1,
            ))
        sarif = findings_to_sarif(findings)
        assert len(sarif["runs"][0]["results"]) == len(Severity)


# -- TestGitHubCodeScanningCompat ---------------------------------------------


class TestGitHubCodeScanningCompat:
    """Validates required fields for GitHub Code Scanning SARIF upload.

    GitHub requires: $schema, version, runs[].tool.driver.name,
    runs[].results[].ruleId, runs[].results[].message.text,
    runs[].results[].locations[].physicalLocation.artifactLocation.uri
    """

    def test_schema_present(self):
        sarif = findings_to_sarif([])
        assert "$schema" in sarif

    def test_version_is_2_1_0(self):
        sarif = findings_to_sarif([])
        assert sarif["version"] == "2.1.0"

    def test_driver_name_present(self):
        sarif = findings_to_sarif([])
        assert sarif["runs"][0]["tool"]["driver"]["name"]

    def test_result_has_rule_id(self):
        f = _make_finding()
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert "ruleId" in result
        assert isinstance(result["ruleId"], str)

    def test_result_has_message_text(self):
        f = _make_finding()
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert "text" in result["message"]

    def test_result_has_location_uri(self):
        f = _make_finding()
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert "uri" in loc["artifactLocation"]

    def test_result_has_level(self):
        f = _make_finding()
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert result["level"] in ("error", "warning", "note", "none")

    def test_result_has_partial_fingerprints(self):
        f = _make_finding()
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert "partialFingerprints" in result

    def test_rules_have_security_severity(self):
        f = _make_finding()
        sarif = findings_to_sarif([f])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "security-severity" in rule["properties"]

    def test_full_sarif_is_valid_json(self):
        f = _make_finding()
        json_str = findings_to_sarif_json([f])
        parsed = json.loads(json_str)
        # Structural checks
        assert "runs" in parsed
        assert "tool" in parsed["runs"][0]
        assert "results" in parsed["runs"][0]
