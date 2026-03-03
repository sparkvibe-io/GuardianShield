"""Tests for the CWE-specific triage prompts module."""

from __future__ import annotations

import pytest

from guardianshield.findings import FindingType
from guardianshield.triage import (
    TRIAGE_GUIDES,
    available_finding_types,
    build_triage_prompt,
    get_all_triage_guides,
    get_triage_guide,
)

# ===================================================================
# TestTriageGuideStructure
# ===================================================================


_REQUIRED_KEYS = frozenset({
    "cwe_ids",
    "owasp",
    "description",
    "true_positive_indicators",
    "false_positive_indicators",
    "questions",
    "context_to_examine",
    "languages",
})


class TestTriageGuideStructure:
    """Validate that every triage guide has the required keys and shapes."""

    def test_all_guides_have_required_keys(self):
        for name, guide in TRIAGE_GUIDES.items():
            missing = _REQUIRED_KEYS - set(guide.keys())
            assert not missing, f"Guide '{name}' missing keys: {missing}"

    def test_cwe_ids_are_lists(self):
        for name, guide in TRIAGE_GUIDES.items():
            assert isinstance(guide["cwe_ids"], list), f"{name}: cwe_ids not a list"
            assert len(guide["cwe_ids"]) >= 1, f"{name}: cwe_ids empty"
            for cwe in guide["cwe_ids"]:
                assert cwe.startswith("CWE-"), f"{name}: bad CWE format: {cwe}"

    def test_owasp_format(self):
        for name, guide in TRIAGE_GUIDES.items():
            owasp = guide["owasp"]
            assert isinstance(owasp, str), f"{name}: owasp not a string"
            assert ":" in owasp, f"{name}: owasp missing colon: {owasp}"

    def test_descriptions_are_nonempty(self):
        for name, guide in TRIAGE_GUIDES.items():
            assert len(guide["description"]) > 20, f"{name}: description too short"

    def test_indicators_are_lists_with_content(self):
        for name, guide in TRIAGE_GUIDES.items():
            tp = guide["true_positive_indicators"]
            fp = guide["false_positive_indicators"]
            assert isinstance(tp, list) and len(tp) >= 4, f"{name}: need >= 4 TP indicators"
            assert isinstance(fp, list) and len(fp) >= 4, f"{name}: need >= 4 FP indicators"

    def test_questions_are_lists_with_content(self):
        for name, guide in TRIAGE_GUIDES.items():
            qs = guide["questions"]
            assert isinstance(qs, list) and len(qs) >= 3, f"{name}: need >= 3 questions"

    def test_context_to_examine_are_lists(self):
        for name, guide in TRIAGE_GUIDES.items():
            ctx = guide["context_to_examine"]
            assert isinstance(ctx, list) and len(ctx) >= 3, f"{name}: need >= 3 context items"

    def test_languages_are_lists(self):
        for name, guide in TRIAGE_GUIDES.items():
            langs = guide["languages"]
            assert isinstance(langs, list) and len(langs) >= 1, f"{name}: need >= 1 language"

    def test_guide_count(self):
        assert len(TRIAGE_GUIDES) == 7

    def test_all_keys_are_valid_finding_types(self):
        valid_types = {ft.value for ft in FindingType}
        for key in TRIAGE_GUIDES:
            assert key in valid_types, f"Guide key '{key}' not a valid FindingType"


# ===================================================================
# TestGetTriageGuide
# ===================================================================


class TestGetTriageGuide:
    def test_sql_injection(self):
        guide = get_triage_guide("sql_injection")
        assert guide is not None
        assert "CWE-89" in guide["cwe_ids"]

    def test_xss(self):
        guide = get_triage_guide("xss")
        assert guide is not None
        assert "CWE-79" in guide["cwe_ids"]

    def test_command_injection(self):
        guide = get_triage_guide("command_injection")
        assert guide is not None
        assert "CWE-78" in guide["cwe_ids"]

    def test_path_traversal(self):
        guide = get_triage_guide("path_traversal")
        assert guide is not None
        assert "CWE-22" in guide["cwe_ids"]

    def test_insecure_function(self):
        guide = get_triage_guide("insecure_function")
        assert guide is not None
        assert "CWE-94" in guide["cwe_ids"]

    def test_insecure_pattern(self):
        guide = get_triage_guide("insecure_pattern")
        assert guide is not None
        assert "CWE-327" in guide["cwe_ids"]

    def test_secret(self):
        guide = get_triage_guide("secret")
        assert guide is not None
        assert "CWE-798" in guide["cwe_ids"]

    def test_no_guide_for_prompt_injection(self):
        guide = get_triage_guide("prompt_injection")
        assert guide is None

    def test_no_guide_for_pii_leak(self):
        guide = get_triage_guide("pii_leak")
        assert guide is None

    def test_no_guide_for_content_violation(self):
        guide = get_triage_guide("content_violation")
        assert guide is None

    def test_no_guide_for_dependency_vulnerability(self):
        guide = get_triage_guide("dependency_vulnerability")
        assert guide is None

    def test_invalid_finding_type_raises(self):
        with pytest.raises(ValueError, match="Unknown finding type"):
            get_triage_guide("not_a_real_type")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            get_triage_guide("")


# ===================================================================
# TestGetAllTriageGuides
# ===================================================================


class TestGetAllTriageGuides:
    def test_returns_dict(self):
        guides = get_all_triage_guides()
        assert isinstance(guides, dict)

    def test_returns_all_seven(self):
        guides = get_all_triage_guides()
        assert len(guides) == 7

    def test_returns_copy(self):
        guides = get_all_triage_guides()
        assert guides is not TRIAGE_GUIDES

    def test_keys_match(self):
        guides = get_all_triage_guides()
        assert set(guides.keys()) == set(TRIAGE_GUIDES.keys())


# ===================================================================
# TestAvailableFindingTypes
# ===================================================================


class TestAvailableFindingTypes:
    def test_returns_sorted_list(self):
        types = available_finding_types()
        assert types == sorted(types)

    def test_contains_seven_types(self):
        assert len(available_finding_types()) == 7

    def test_sql_injection_included(self):
        assert "sql_injection" in available_finding_types()

    def test_secret_included(self):
        assert "secret" in available_finding_types()

    def test_prompt_injection_not_included(self):
        assert "prompt_injection" not in available_finding_types()


# ===================================================================
# TestBuildTriagePrompt
# ===================================================================


class TestBuildTriagePrompt:
    def test_basic_prompt(self):
        prompt = build_triage_prompt("sql_injection")
        assert "CWE-89" in prompt
        assert "True Positive" in prompt
        assert "False Positive" in prompt
        assert "Questions" in prompt

    def test_includes_code_snippet(self):
        code = 'cursor.run("SELECT * FROM users WHERE id=" + user_id)'
        prompt = build_triage_prompt("sql_injection", code_snippet=code)
        assert code in prompt
        assert "```" in prompt

    def test_includes_file_path(self):
        prompt = build_triage_prompt(
            "sql_injection", code_snippet="x = 1", file_path="app/models.py"
        )
        assert "app/models.py" in prompt

    def test_includes_language(self):
        prompt = build_triage_prompt(
            "sql_injection", code_snippet="x = 1", language="python"
        )
        assert "python" in prompt

    def test_verdict_format_included(self):
        prompt = build_triage_prompt("sql_injection")
        assert "true_positive" in prompt
        assert "false_positive" in prompt
        assert "needs_more_context" in prompt

    def test_all_types_produce_prompts(self):
        for finding_type in available_finding_types():
            prompt = build_triage_prompt(finding_type)
            assert len(prompt) > 100, f"{finding_type}: prompt too short"

    def test_invalid_type_raises(self):
        with pytest.raises(ValueError, match="No triage guide"):
            build_triage_prompt("prompt_injection")

    def test_completely_invalid_type_raises(self):
        with pytest.raises(ValueError):
            build_triage_prompt("not_a_real_type")

    def test_xss_prompt_content(self):
        prompt = build_triage_prompt("xss")
        assert "CWE-79" in prompt
        assert "A03:2021" in prompt

    def test_command_injection_prompt_content(self):
        prompt = build_triage_prompt("command_injection")
        assert "CWE-78" in prompt

    def test_secret_prompt_content(self):
        prompt = build_triage_prompt("secret")
        assert "CWE-798" in prompt

    def test_without_code_no_code_block(self):
        prompt = build_triage_prompt("sql_injection")
        assert "Code Under Review" not in prompt

    def test_with_code_has_code_block(self):
        prompt = build_triage_prompt("sql_injection", code_snippet="SELECT 1")
        assert "Code Under Review" in prompt

    def test_indicators_included(self):
        guide = get_triage_guide("sql_injection")
        prompt = build_triage_prompt("sql_injection")
        assert guide["true_positive_indicators"][0] in prompt
        assert guide["false_positive_indicators"][0] in prompt


# ===================================================================
# TestTriageGuideContent
# ===================================================================


class TestTriageGuideContent:
    """Validate that triage guides contain domain-specific security knowledge."""

    def test_sql_injection_mentions_parameterized(self):
        guide = get_triage_guide("sql_injection")
        fp_text = " ".join(guide["false_positive_indicators"])
        assert "parameterized" in fp_text.lower() or "prepared" in fp_text.lower()

    def test_xss_mentions_escaping(self):
        guide = get_triage_guide("xss")
        all_text = " ".join(
            guide["true_positive_indicators"]
            + guide["false_positive_indicators"]
        )
        assert "escap" in all_text.lower()

    def test_command_injection_mentions_shell(self):
        guide = get_triage_guide("command_injection")
        all_text = " ".join(guide["true_positive_indicators"])
        assert "shell" in all_text.lower()

    def test_path_traversal_mentions_path_validation(self):
        guide = get_triage_guide("path_traversal")
        all_text = " ".join(guide["false_positive_indicators"])
        assert "realpath" in all_text.lower() or "resolve" in all_text.lower()

    def test_insecure_function_mentions_dangerous_functions(self):
        guide = get_triage_guide("insecure_function")
        all_text = " ".join(guide["true_positive_indicators"])
        lower = all_text.lower()
        assert "exec" in lower or "deserialization" in lower or "loads" in lower

    def test_insecure_pattern_mentions_weak_crypto(self):
        guide = get_triage_guide("insecure_pattern")
        all_text = " ".join(guide["true_positive_indicators"])
        assert "md5" in all_text.lower() or "sha1" in all_text.lower()

    def test_secret_mentions_placeholder(self):
        guide = get_triage_guide("secret")
        fp_text = " ".join(guide["false_positive_indicators"])
        assert "placeholder" in fp_text.lower()


# ===================================================================
# TestMCPIntegration
# ===================================================================


class TestMCPTriagePrompt:
    """Test the triage-finding prompt via the MCP server."""

    def _make_server(self, tmp_path):

        from guardianshield.core import GuardianShield
        from guardianshield.mcp_server import GuardianShieldMCPServer

        db = str(tmp_path / "audit.db")
        shield = GuardianShield(profile="general", audit_path=db)
        server = GuardianShieldMCPServer(shield=shield)
        server._initialized = True
        return server

    def _run_mcp(self, tmp_path, method_params):
        import io
        import json
        import sys

        server = self._make_server(tmp_path)
        msgs = [method_params]
        input_lines = "\n".join(json.dumps(m) for m in msgs) + "\n"

        old_stdin = sys.stdin
        old_stdout = sys.stdout
        sys.stdin = io.StringIO(input_lines)
        sys.stdout = io.StringIO()
        try:
            server.run()
        finally:
            output = sys.stdout.getvalue()
            sys.stdin = old_stdin
            sys.stdout = old_stdout

        responses = []
        for line in output.strip().split("\n"):
            if line.strip():
                responses.append(json.loads(line))
        return responses[-1] if responses else {}

    def test_triage_prompt_listed(self, tmp_path):
        resp = self._run_mcp(tmp_path, {
            "jsonrpc": "2.0", "id": 1,
            "method": "prompts/list", "params": {},
        })
        names = {p["name"] for p in resp["result"]["prompts"]}
        assert "triage-finding" in names

    def test_triage_prompt_get(self, tmp_path):
        resp = self._run_mcp(tmp_path, {
            "jsonrpc": "2.0", "id": 1,
            "method": "prompts/get",
            "params": {
                "name": "triage-finding",
                "arguments": {"finding_type": "sql_injection"},
            },
        })
        result = resp["result"]
        assert "messages" in result
        assert "CWE-89" in result["messages"][0]["content"]["text"]

    def test_triage_prompt_with_code(self, tmp_path):
        resp = self._run_mcp(tmp_path, {
            "jsonrpc": "2.0", "id": 1,
            "method": "prompts/get",
            "params": {
                "name": "triage-finding",
                "arguments": {
                    "finding_type": "xss",
                    "code": "<div>{user_input}</div>",
                    "language": "javascript",
                },
            },
        })
        text = resp["result"]["messages"][0]["content"]["text"]
        assert "{user_input}" in text
        assert "javascript" in text

    def test_triage_prompt_missing_type(self, tmp_path):
        resp = self._run_mcp(tmp_path, {
            "jsonrpc": "2.0", "id": 1,
            "method": "prompts/get",
            "params": {
                "name": "triage-finding",
                "arguments": {},
            },
        })
        assert "error" in resp["result"]

    def test_triage_prompt_invalid_type(self, tmp_path):
        resp = self._run_mcp(tmp_path, {
            "jsonrpc": "2.0", "id": 1,
            "method": "prompts/get",
            "params": {
                "name": "triage-finding",
                "arguments": {"finding_type": "prompt_injection"},
            },
        })
        assert "error" in resp["result"]

    def test_triage_prompt_description(self, tmp_path):
        resp = self._run_mcp(tmp_path, {
            "jsonrpc": "2.0", "id": 1,
            "method": "prompts/get",
            "params": {
                "name": "triage-finding",
                "arguments": {"finding_type": "command_injection"},
            },
        })
        result = resp["result"]
        assert "command_injection" in result["description"]
