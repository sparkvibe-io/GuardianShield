"""Tests for language-specific vulnerability patterns and scanner integration."""

from guardianshield.findings import FindingType, Severity
from guardianshield.patterns import (
    COMMON_PATTERNS,
    EXTENSION_MAP,
    JAVASCRIPT_PATTERNS,
    LANGUAGE_PATTERNS,
    PYTHON_PATTERNS,
)
from guardianshield.scanner import VULNERABILITY_PATTERNS, scan_code

# ===================================================================
# 1. Import / Structure tests
# ===================================================================


class TestPatternImports:
    """All pattern modules can be imported and have expected structure."""

    def test_common_patterns_importable(self):
        assert isinstance(COMMON_PATTERNS, list)
        assert len(COMMON_PATTERNS) == 3

    def test_python_patterns_importable(self):
        assert isinstance(PYTHON_PATTERNS, list)
        assert len(PYTHON_PATTERNS) == 15

    def test_javascript_patterns_importable(self):
        assert isinstance(JAVASCRIPT_PATTERNS, list)
        assert len(JAVASCRIPT_PATTERNS) == 7

    def test_language_patterns_dict(self):
        assert isinstance(LANGUAGE_PATTERNS, dict)
        assert "python" in LANGUAGE_PATTERNS
        assert "javascript" in LANGUAGE_PATTERNS

    def test_extension_map_dict(self):
        assert isinstance(EXTENSION_MAP, dict)
        assert ".py" in EXTENSION_MAP
        assert ".js" in EXTENSION_MAP

    def test_pattern_tuple_has_seven_elements(self):
        """Every pattern tuple should have 7 elements (Phase 1A format)."""
        for p in COMMON_PATTERNS + PYTHON_PATTERNS + JAVASCRIPT_PATTERNS:
            assert len(p) == 7, f"Pattern {p[0]} has {len(p)} elements, expected 7"

    def test_backward_compat_vulnerability_patterns(self):
        """VULNERABILITY_PATTERNS should equal COMMON + PYTHON patterns."""
        assert VULNERABILITY_PATTERNS == COMMON_PATTERNS + PYTHON_PATTERNS


# ===================================================================
# 2. Language aliases
# ===================================================================


class TestLanguageAliases:
    """LANGUAGE_PATTERNS aliases resolve to the correct pattern list."""

    def test_python_aliases(self):
        assert LANGUAGE_PATTERNS["python"] is LANGUAGE_PATTERNS["py"]

    def test_javascript_aliases(self):
        js = LANGUAGE_PATTERNS["javascript"]
        assert LANGUAGE_PATTERNS["js"] is js
        assert LANGUAGE_PATTERNS["typescript"] is js
        assert LANGUAGE_PATTERNS["ts"] is js
        assert LANGUAGE_PATTERNS["jsx"] is js
        assert LANGUAGE_PATTERNS["tsx"] is js


# ===================================================================
# 3. Extension mapping
# ===================================================================


class TestExtensionMapping:
    """File extension -> language mapping works correctly."""

    def test_py_extension(self):
        assert EXTENSION_MAP[".py"] == "python"

    def test_pyw_extension(self):
        assert EXTENSION_MAP[".pyw"] == "python"

    def test_js_extension(self):
        assert EXTENSION_MAP[".js"] == "javascript"

    def test_jsx_extension(self):
        assert EXTENSION_MAP[".jsx"] == "javascript"

    def test_ts_extension(self):
        assert EXTENSION_MAP[".ts"] == "typescript"

    def test_tsx_extension(self):
        assert EXTENSION_MAP[".tsx"] == "typescript"

    def test_mjs_extension(self):
        assert EXTENSION_MAP[".mjs"] == "javascript"

    def test_cjs_extension(self):
        assert EXTENSION_MAP[".cjs"] == "javascript"


# ===================================================================
# 4. Python patterns via scan_code(language="python")
# ===================================================================


class TestPythonLanguageParam:
    """scan_code with language='python' returns Python-specific findings."""

    def test_sql_injection_string_format(self):
        code = 'query = "SELECT * FROM users WHERE id = " + user_id'
        findings = scan_code(code, sensitivity="high", language="python")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1

    def test_fstring_sql(self):
        code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        findings = scan_code(code, sensitivity="high", language="python")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1

    def test_os_system(self):
        code = 'os.system("rm -rf " + path)'
        findings = scan_code(code, sensitivity="high", language="python")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1

    def test_pickle_load(self):
        code = "obj = pickle.loads(data)"
        findings = scan_code(code, sensitivity="high", language="python")
        insec = [f for f in findings if f.finding_type == FindingType.INSECURE_FUNCTION]
        assert len(insec) >= 1

    def test_insecure_hash(self):
        code = "digest = hashlib.md5(password.encode())"
        findings = scan_code(code, sensitivity="high", language="python")
        insec = [f for f in findings if f.finding_type == FindingType.INSECURE_FUNCTION]
        assert len(insec) >= 1
        assert insec[0].severity == Severity.LOW


# ===================================================================
# 5. JavaScript patterns via scan_code(language="javascript")
# ===================================================================


class TestJavaScriptLanguageParam:
    """scan_code with language='javascript' returns JS-specific findings."""

    def test_js_finds_function_constructor(self):
        # new Function() — dynamic code generation
        code = 'const fn = new Function("return " + userInput);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        cmdi = [f for f in findings if f.metadata.get("pattern_name") == "js_function_constructor"]
        assert len(cmdi) == 1
        assert cmdi[0].severity == Severity.HIGH
        assert cmdi[0].finding_type == FindingType.COMMAND_INJECTION

    def test_js_finds_child_process(self):
        # child_process usage
        code = 'child_process("rm -rf " + path);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        cmdi = [f for f in findings if f.metadata.get("pattern_name") == "js_child_process_exec"]
        assert len(cmdi) == 1
        assert cmdi[0].severity == Severity.HIGH

    def test_js_finds_dangerously_set_html(self):
        code = '<div dangerouslySetInnerHTML={{ __html: userContent }} />'
        findings = scan_code(code, sensitivity="high", language="javascript")
        xss = [f for f in findings if f.metadata.get("pattern_name") == "js_dangerously_set_html"]
        assert len(xss) == 1
        assert xss[0].severity == Severity.HIGH
        assert xss[0].finding_type == FindingType.XSS

    def test_js_finds_dynamic_require(self):
        code = 'const mod = require(userPath + "/module");'
        findings = scan_code(code, sensitivity="high", language="javascript")
        pt = [f for f in findings if f.metadata.get("pattern_name") == "js_dynamic_require"]
        assert len(pt) == 1
        assert pt[0].finding_type == FindingType.PATH_TRAVERSAL

    def test_js_finds_template_sql(self):
        code = 'const query = `SELECT * FROM users WHERE id=${userId}`;'
        findings = scan_code(code, sensitivity="high", language="javascript")
        sqli = [f for f in findings if f.metadata.get("pattern_name") == "js_template_sql"]
        assert len(sqli) == 1
        assert sqli[0].finding_type == FindingType.SQL_INJECTION

    def test_js_finds_prototype_pollution(self):
        code = 'obj.__proto__[key] = value;'
        findings = scan_code(code, sensitivity="high", language="javascript")
        pp = [f for f in findings if f.metadata.get("pattern_name") == "js_prototype_pollution"]
        assert len(pp) == 1
        assert pp[0].finding_type == FindingType.INSECURE_PATTERN
        assert pp[0].severity == Severity.HIGH

    def test_js_finds_insert_adjacent_html(self):
        code = 'el.insertAdjacentHTML("beforeend", userHtml);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        xss = [f for f in findings if f.metadata.get("pattern_name") == "js_dom_insert_adjacent"]
        assert len(xss) == 1
        assert xss[0].finding_type == FindingType.XSS


# ===================================================================
# 6. Individual JS pattern tests — positive + negative
# ===================================================================


class TestJsFunctionConstructor:
    """Function constructor detection."""

    def test_positive_new_function(self):
        code = 'var f = new Function("return " + x);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_function_constructor" in names

    def test_negative_function_declaration(self):
        code = "function myFunc() { return 1; }"
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_function_constructor" not in names


class TestJsChildProcess:
    """child_process detection."""

    def test_positive_child_process(self):
        code = 'child_process("ls -la " + dir);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_child_process_exec" in names

    def test_positive_exec_sync(self):
        code = 'execSync("git status");'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_child_process_exec" in names

    def test_positive_spawn(self):
        code = 'spawn("node", [script]);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_child_process_exec" in names

    def test_positive_spawn_sync(self):
        code = 'spawnSync("ls", ["-la"]);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_child_process_exec" in names

    def test_positive_exec_file(self):
        code = 'execFile("/bin/sh", ["-c", cmd]);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_child_process_exec" in names


class TestJsDangerouslySetHtml:
    """React dangerouslySetInnerHTML detection."""

    def test_positive(self):
        code = '<div dangerouslySetInnerHTML={{ __html: content }} />'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_dangerously_set_html" in names

    def test_negative_safe_jsx(self):
        code = "<div>{sanitizedContent}</div>"
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_dangerously_set_html" not in names


class TestJsDynamicRequire:
    """Dynamic require detection."""

    def test_positive_concat(self):
        code = 'const m = require(base + "/mod");'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_dynamic_require" in names

    def test_positive_template_literal(self):
        code = 'const m = require(`${basePath}/mod`);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_dynamic_require" in names

    def test_negative_static_require(self):
        code = "const fs = require('fs');"
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_dynamic_require" not in names


class TestJsTemplateSql:
    """Template literal SQL injection detection."""

    def test_positive_select(self):
        code = 'const q = `SELECT * FROM users WHERE id=${userId}`;'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_template_sql" in names

    def test_positive_delete(self):
        code = 'const q = `DELETE FROM sessions WHERE token=${token}`;'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_template_sql" in names

    def test_positive_insert(self):
        code = 'const q = `INSERT INTO logs VALUES (${data})`;'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_template_sql" in names

    def test_negative_static_template(self):
        code = "const msg = `Hello ${name}`;"
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_template_sql" not in names


class TestJsPrototypePollution:
    """Prototype pollution detection."""

    def test_positive_bracket(self):
        code = "obj.__proto__[key] = value;"
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_prototype_pollution" in names

    def test_positive_dot(self):
        code = "obj.__proto__.constructor = evil;"
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_prototype_pollution" in names

    def test_negative_no_proto(self):
        code = "obj.prototype.method = fn;"
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_prototype_pollution" not in names


class TestJsInsertAdjacentHtml:
    """insertAdjacentHTML detection."""

    def test_positive(self):
        code = 'el.insertAdjacentHTML("beforeend", userHtml);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_dom_insert_adjacent" in names

    def test_negative_insert_adjacent_text(self):
        code = 'el.insertAdjacentText("beforeend", text);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_dom_insert_adjacent" not in names


# ===================================================================
# 7. Language auto-detection from file_path
# ===================================================================


class TestLanguageAutoDetection:
    """Language is auto-detected from file_path extension."""

    def test_js_file_detects_javascript(self):
        code = 'const fn = new Function("return " + x);'
        findings = scan_code(code, sensitivity="high", file_path="app.js")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_function_constructor" in names

    def test_ts_file_detects_typescript(self):
        code = "obj.__proto__[key] = value;"
        findings = scan_code(code, sensitivity="high", file_path="app.ts")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_prototype_pollution" in names

    def test_tsx_file_detects_tsx(self):
        code = '<div dangerouslySetInnerHTML={{ __html: x }} />'
        findings = scan_code(code, sensitivity="high", file_path="component.tsx")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_dangerously_set_html" in names

    def test_jsx_file_detects_jsx(self):
        code = 'el.insertAdjacentHTML("beforeend", html);'
        findings = scan_code(code, sensitivity="high", file_path="view.jsx")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_dom_insert_adjacent" in names

    def test_mjs_file_detects_javascript(self):
        code = 'child_process("ls");'
        findings = scan_code(code, sensitivity="high", file_path="server.mjs")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_child_process_exec" in names

    def test_cjs_file_detects_javascript(self):
        code = 'const q = `SELECT * FROM t WHERE id=${x}`;'
        findings = scan_code(code, sensitivity="high", file_path="db.cjs")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "js_template_sql" in names

    def test_py_file_detects_python(self):
        code = "os.system('ls')"
        findings = scan_code(code, sensitivity="high", file_path="app.py")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "command_injection_os_system" in names

    def test_pyw_file_detects_python(self):
        code = "pickle.loads(data)"
        findings = scan_code(code, sensitivity="high", file_path="gui.pyw")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "insecure_pickle" in names

    def test_language_param_overrides_file_path(self):
        """Explicit language parameter takes precedence over file_path."""
        code = "os.system('ls')"
        # file_path says JS, but language says Python
        findings = scan_code(
            code, sensitivity="high", file_path="app.js", language="python"
        )
        names = [f.metadata["pattern_name"] for f in findings]
        assert "command_injection_os_system" in names

    def test_unknown_extension_falls_back_to_python(self):
        code = "os.system('ls')"
        findings = scan_code(code, sensitivity="high", file_path="script.xyz")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "command_injection_os_system" in names


# ===================================================================
# 8. Backward compatibility — no language param
# ===================================================================


class TestBackwardCompatibility:
    """scan_code() without language param still finds Python patterns."""

    def test_default_finds_python_sql_injection(self):
        code = 'query = "SELECT * FROM users WHERE id = " + user_id'
        findings = scan_code(code, sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1

    def test_default_finds_python_os_system(self):
        code = 'os.system("rm -rf " + path)'
        findings = scan_code(code, sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1

    def test_default_finds_python_pickle(self):
        code = "obj = pickle.loads(data)"
        findings = scan_code(code, sensitivity="high")
        insec = [f for f in findings if f.finding_type == FindingType.INSECURE_FUNCTION]
        assert len(insec) >= 1

    def test_default_finds_common_eval(self):
        """eval is a common pattern -- fires even without language."""
        code = "result = eval(user_input)"
        findings = scan_code(code, sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1


# ===================================================================
# 9. Common patterns fire for both Python and JS
# ===================================================================


class TestCommonPatternsCrossLanguage:
    """Common patterns fire regardless of language setting."""

    def test_innerhtml_fires_for_python(self):
        code = "element.innerHTML = data;"
        findings = scan_code(code, sensitivity="high", language="python")
        xss = [f for f in findings if f.metadata.get("pattern_name") == "xss_innerhtml"]
        assert len(xss) == 1

    def test_innerhtml_fires_for_javascript(self):
        code = "element.innerHTML = data;"
        findings = scan_code(code, sensitivity="high", language="javascript")
        xss = [f for f in findings if f.metadata.get("pattern_name") == "xss_innerhtml"]
        assert len(xss) == 1

    def test_document_write_fires_for_python(self):
        code = "document.write(data);"
        findings = scan_code(code, sensitivity="high", language="python")
        xss = [f for f in findings if f.metadata.get("pattern_name") == "xss_document_write"]
        assert len(xss) == 1

    def test_document_write_fires_for_javascript(self):
        code = "document.write(data);"
        findings = scan_code(code, sensitivity="high", language="javascript")
        xss = [f for f in findings if f.metadata.get("pattern_name") == "xss_document_write"]
        assert len(xss) == 1

    def test_eval_fires_for_python(self):
        code = "eval(user_input)"
        findings = scan_code(code, sensitivity="high", language="python")
        cmdi = [f for f in findings if f.metadata.get("pattern_name") == "command_injection_eval"]
        assert len(cmdi) == 1

    def test_eval_fires_for_javascript(self):
        code = "eval(user_input)"
        findings = scan_code(code, sensitivity="high", language="javascript")
        cmdi = [f for f in findings if f.metadata.get("pattern_name") == "command_injection_eval"]
        assert len(cmdi) == 1


# ===================================================================
# 10. No cross-contamination
# ===================================================================


class TestNoCrossContamination:
    """Language-specific patterns don't fire for the wrong language."""

    def test_python_patterns_not_in_javascript(self):
        """Python-only patterns should NOT fire when language='javascript'."""
        code = "\n".join([
            "os.system('ls')",
            "subprocess.call(cmd, shell=True)",
            "pickle.loads(data)",
            "hashlib.md5(x)",
        ])
        findings = scan_code(code, sensitivity="high", language="javascript")
        python_only_names = {
            "command_injection_os_system",
            "command_injection_subprocess_shell",
            "insecure_pickle",
            "insecure_hash",
        }
        found_names = {f.metadata["pattern_name"] for f in findings}
        assert found_names.isdisjoint(python_only_names), (
            f"Python patterns found in JS scan: {found_names & python_only_names}"
        )

    def test_javascript_patterns_not_in_python(self):
        """JS-only patterns should NOT fire when language='python'."""
        code = "\n".join([
            'const fn = new Function("return " + x);',
            '<div dangerouslySetInnerHTML={{ __html: x }} />',
            'require(base + "/mod");',
            '`SELECT * FROM users WHERE id=${id}`;',
            'obj.__proto__[k] = v;',
            'el.insertAdjacentHTML("beforeend", h);',
        ])
        findings = scan_code(code, sensitivity="high", language="python")
        js_only_names = {
            "js_function_constructor",
            "js_dangerously_set_html",
            "js_dynamic_require",
            "js_template_sql",
            "js_prototype_pollution",
            "js_dom_insert_adjacent",
        }
        found_names = {f.metadata["pattern_name"] for f in findings}
        assert found_names.isdisjoint(js_only_names), (
            f"JS patterns found in Python scan: {found_names & js_only_names}"
        )


# ===================================================================
# 11. Comment skipping for JS
# ===================================================================


class TestJSCommentSkipping:
    """JavaScript comments should be skipped."""

    def test_js_single_line_comment(self):
        code = '// new Function("return " + x);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        assert len(findings) == 0

    def test_js_block_comment_opening(self):
        code = '/* obj.__proto__[k] = v; */'
        findings = scan_code(code, sensitivity="high", language="javascript")
        assert len(findings) == 0

    def test_js_star_continuation(self):
        code = '* dangerouslySetInnerHTML={{ __html: x }}'
        findings = scan_code(code, sensitivity="high", language="javascript")
        assert len(findings) == 0

    def test_python_hash_comment_in_js(self):
        code = '# obj.__proto__[k] = v;'
        findings = scan_code(code, sensitivity="high", language="javascript")
        assert len(findings) == 0

    def test_indented_js_comment(self):
        code = '    // el.insertAdjacentHTML("beforeend", h);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        assert len(findings) == 0


# ===================================================================
# 12. CWE IDs and confidence on JS patterns
# ===================================================================


class TestJsPatternMetadata:
    """JS patterns include CWE IDs and confidence scores."""

    def test_function_constructor_cwe(self):
        code = 'new Function("return " + x);'
        findings = scan_code(code, sensitivity="high", language="javascript")
        fc = [f for f in findings if f.metadata["pattern_name"] == "js_function_constructor"]
        assert len(fc) == 1
        assert "CWE-94" in fc[0].cwe_ids

    def test_prototype_pollution_cwe(self):
        code = "obj.__proto__[k] = v;"
        findings = scan_code(code, sensitivity="high", language="javascript")
        pp = [f for f in findings if f.metadata["pattern_name"] == "js_prototype_pollution"]
        assert len(pp) == 1
        assert "CWE-1321" in pp[0].cwe_ids

    def test_template_sql_cwe(self):
        code = "`SELECT * FROM t WHERE id=${x}`;"
        findings = scan_code(code, sensitivity="high", language="javascript")
        sqli = [f for f in findings if f.metadata["pattern_name"] == "js_template_sql"]
        assert len(sqli) == 1
        assert "CWE-89" in sqli[0].cwe_ids

    def test_dangerously_set_html_confidence(self):
        code = '<div dangerouslySetInnerHTML={{ __html: x }} />'
        findings = scan_code(code, sensitivity="high", language="javascript")
        dsh = [f for f in findings if f.metadata["pattern_name"] == "js_dangerously_set_html"]
        assert len(dsh) == 1
        assert dsh[0].confidence is not None
        assert dsh[0].confidence > 0.0

    def test_child_process_has_range(self):
        code = 'child_process("command");'
        findings = scan_code(code, sensitivity="high", language="javascript")
        cp = [f for f in findings if f.metadata["pattern_name"] == "js_child_process_exec"]
        assert len(cp) == 1
        assert cp[0].range is not None
        assert cp[0].range.start_line == 0  # 0-based
        assert cp[0].range.start_col >= 0


# ===================================================================
# 13. Multiple JS vulnerabilities in one scan
# ===================================================================


class TestMultipleJsFindings:
    """Multiple JS vulnerabilities detected in a single scan."""

    def test_multi_vuln_js_file(self):
        code = "\n".join([
            'const fn = new Function("return " + x);',
            'child_process("rm -rf " + path);',
            '<div dangerouslySetInnerHTML={{ __html: x }} />',
            'require(base + "/mod");',
            '`SELECT * FROM users WHERE id=${id}`;',
            'obj.__proto__[k] = v;',
            'el.insertAdjacentHTML("beforeend", h);',
        ])
        findings = scan_code(code, sensitivity="high", language="javascript")
        names = {f.metadata["pattern_name"] for f in findings}
        assert "js_function_constructor" in names
        assert "js_child_process_exec" in names
        assert "js_dangerously_set_html" in names
        assert "js_dynamic_require" in names
        assert "js_template_sql" in names
        assert "js_prototype_pollution" in names
        assert "js_dom_insert_adjacent" in names

    def test_line_numbers_correct_for_js(self):
        code = "\n".join([
            "const x = 1;",
            'new Function("return " + x);',
            "const y = 2;",
        ])
        findings = scan_code(code, sensitivity="high", language="javascript")
        fc = [f for f in findings if f.metadata["pattern_name"] == "js_function_constructor"]
        assert len(fc) == 1
        assert fc[0].line_number == 2


# ===================================================================
# 14. Clean JS code — no false positives
# ===================================================================


class TestCleanJsCode:
    """Clean JavaScript code should produce no findings."""

    def test_clean_js(self):
        code = "\n".join([
            "const express = require('express');",
            "const app = express();",
            "",
            "app.get('/', (req, res) => {",
            "  res.json({ message: 'Hello' });",
            "});",
            "",
            "app.listen(3000);",
        ])
        findings = scan_code(code, sensitivity="high", language="javascript")
        # require('express') is static — should NOT trigger js_dynamic_require.
        dyn_req = [f for f in findings if f.metadata["pattern_name"] == "js_dynamic_require"]
        assert len(dyn_req) == 0
