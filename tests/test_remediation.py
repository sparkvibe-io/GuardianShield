"""Tests for structured remediation (Phase 2A)."""

from guardianshield.findings import Finding, Remediation
from guardianshield.patterns import REMEDIATION_MAP
from guardianshield.patterns.common import COMMON_REMEDIATION
from guardianshield.patterns.javascript import JAVASCRIPT_REMEDIATION
from guardianshield.patterns.python import PYTHON_REMEDIATION
from guardianshield.scanner import scan_code

# -- Remediation map coverage ------------------------------------------------

def test_common_remediation_has_all_common_patterns():
    expected = {"xss_innerhtml", "xss_document_write", "command_injection_eval"}
    assert expected == set(COMMON_REMEDIATION.keys())


def test_python_remediation_has_all_python_patterns():
    expected = {
        "sql_injection_string_format", "sql_injection_fstring",
        "sql_injection_raw_query", "sql_injection_raw_query_fstring",
        "xss_template_safe", "xss_template_autoescape_off", "xss_markup",
        "command_injection_os_system", "command_injection_subprocess_shell",
        "command_injection_exec",
        "path_traversal_open", "path_traversal_os_path_join",
        "insecure_pickle", "insecure_hash", "insecure_random",
    }
    assert expected == set(PYTHON_REMEDIATION.keys())


def test_javascript_remediation_has_all_js_patterns():
    expected = {
        "js_function_constructor", "js_child_process_exec",
        "js_dangerously_set_html", "js_dynamic_require",
        "js_template_sql", "js_prototype_pollution",
        "js_dom_insert_adjacent",
    }
    assert expected == set(JAVASCRIPT_REMEDIATION.keys())


def test_combined_remediation_map_has_all():
    total = len(COMMON_REMEDIATION) + len(PYTHON_REMEDIATION) + len(JAVASCRIPT_REMEDIATION)
    assert len(REMEDIATION_MAP) == total


def test_every_remediation_has_required_fields():
    for name, rem in REMEDIATION_MAP.items():
        assert "description" in rem, f"{name} missing description"
        assert isinstance(rem["description"], str)
        assert len(rem["description"]) > 5, f"{name} description too short"


# -- Scanner attaches remediation to findings --------------------------------

def test_python_sql_injection_has_remediation():
    code = 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")'
    findings = scan_code(code, sensitivity="high", language="python")
    assert len(findings) >= 1
    f = findings[0]
    assert f.remediation is not None
    assert isinstance(f.remediation, Remediation)
    assert "parameterized" in f.remediation.description.lower()


def test_python_exec_pattern_has_remediation():
    # exec() pattern from Python patterns
    code = "exec(user_code)"
    findings = scan_code(code, sensitivity="high", language="python")
    matched = [f for f in findings if f.metadata.get("pattern_name") == "command_injection_exec"]
    assert len(matched) >= 1
    assert matched[0].remediation is not None


def test_js_dangerously_set_html_has_remediation():
    code = '<div dangerouslySetInnerHTML={{ __html: content }} />'
    findings = scan_code(code, sensitivity="high", language="javascript")
    matched = [f for f in findings if f.metadata.get("pattern_name") == "js_dangerously_set_html"]
    assert len(matched) >= 1
    assert matched[0].remediation is not None
    assert "DOMPurify" in matched[0].remediation.after


def test_js_prototype_pollution_has_remediation():
    code = 'obj.__proto__[key] = value'
    findings = scan_code(code, sensitivity="high", language="javascript")
    matched = [f for f in findings if f.metadata.get("pattern_name") == "js_prototype_pollution"]
    assert len(matched) >= 1
    assert matched[0].remediation is not None


def test_remediation_serializes_in_finding():
    code = "os.system('rm -rf /')"
    findings = scan_code(code, sensitivity="high", language="python")
    matched = [f for f in findings if f.metadata.get("pattern_name") == "command_injection_os_system"]
    assert len(matched) >= 1
    d = matched[0].to_dict()
    assert "remediation" in d
    assert d["remediation"]["description"]
    assert "subprocess" in d["remediation"]["after"].lower()


def test_auto_fixable_patterns():
    """Some patterns are marked auto_fixable."""
    code = "hashlib.md5(data).hexdigest()"
    findings = scan_code(code, sensitivity="high", language="python")
    matched = [f for f in findings if f.metadata.get("pattern_name") == "insecure_hash"]
    assert len(matched) >= 1
    assert matched[0].remediation is not None
    assert matched[0].remediation.auto_fixable is True


def test_safe_filter_auto_fixable():
    code = "{{ user_input|safe }}"
    findings = scan_code(code, sensitivity="high", language="python")
    matched = [f for f in findings if f.metadata.get("pattern_name") == "xss_template_safe"]
    assert len(matched) >= 1
    assert matched[0].remediation.auto_fixable is True


def test_remediation_round_trip():
    code = 'pickle.loads(data)'
    findings = scan_code(code, sensitivity="high", language="python")
    matched = [f for f in findings if f.metadata.get("pattern_name") == "insecure_pickle"]
    assert len(matched) >= 1
    d = matched[0].to_dict()
    restored = Finding.from_dict(d)
    assert restored.remediation is not None
    assert restored.remediation.description == matched[0].remediation.description
