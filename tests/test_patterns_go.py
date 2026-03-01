"""Tests for Go-specific vulnerability patterns and scanner integration."""

from guardianshield.findings import Severity
from guardianshield.patterns import (
    EXTENSION_MAP,
    GO_PATTERNS,
    LANGUAGE_PATTERNS,
    REMEDIATION_MAP,
)
from guardianshield.scanner import scan_code

# ===================================================================
# 1. Import / Structure tests
# ===================================================================


class TestGoPatternImports:
    """Go pattern module has the expected structure."""

    def test_go_patterns_importable(self):
        assert isinstance(GO_PATTERNS, list)
        assert len(GO_PATTERNS) == 13

    def test_go_in_language_patterns(self):
        assert "go" in LANGUAGE_PATTERNS
        assert LANGUAGE_PATTERNS["go"] is GO_PATTERNS

    def test_golang_alias(self):
        assert "golang" in LANGUAGE_PATTERNS
        assert LANGUAGE_PATTERNS["golang"] is GO_PATTERNS

    def test_go_extension_mapping(self):
        assert EXTENSION_MAP[".go"] == "go"

    def test_pattern_tuple_has_seven_elements(self):
        for p in GO_PATTERNS:
            assert len(p) == 7, f"Pattern {p[0]} has {len(p)} elements, expected 7"

    def test_all_patterns_have_remediation(self):
        for p in GO_PATTERNS:
            name = p[0]
            assert name in REMEDIATION_MAP, f"Pattern {name} missing from REMEDIATION_MAP"


# ===================================================================
# 2. SQL Injection patterns
# ===================================================================


class TestGoSqlInjectionSprintf:
    """go_sql_injection_sprintf detection."""

    def test_positive_sprintf_select(self):
        code = 'query := fmt.Sprintf("SELECT * FROM users WHERE id=%s", userID)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_sql_injection_sprintf" in names

    def test_positive_sprintf_delete(self):
        code = 'q := fmt.Sprintf("DELETE FROM sessions WHERE token=%s", tok)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_sql_injection_sprintf" in names

    def test_positive_fprintf(self):
        code = 'fmt.Fprintf(w, "SELECT name FROM users WHERE id=%d", id)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_sql_injection_sprintf" in names

    def test_negative_parameterized(self):
        code = 'db.Query("SELECT * FROM users WHERE id=$1", userID)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_sql_injection_sprintf" not in names

    def test_severity_is_critical(self):
        code = 'fmt.Sprintf("SELECT * FROM users WHERE id=%s", id)'
        findings = scan_code(code, sensitivity="high", language="go")
        sqli = [f for f in findings if f.metadata["pattern_name"] == "go_sql_injection_sprintf"]
        assert sqli[0].severity == Severity.CRITICAL

    def test_cwe_89(self):
        code = 'fmt.Sprintf("SELECT * FROM users WHERE id=%s", id)'
        findings = scan_code(code, sensitivity="high", language="go")
        sqli = [f for f in findings if f.metadata["pattern_name"] == "go_sql_injection_sprintf"]
        assert "CWE-89" in sqli[0].cwe_ids


class TestGoSqlInjectionConcat:
    """go_sql_injection_concat detection."""

    def test_positive_query_concat(self):
        code = 'db.Query("SELECT * FROM users WHERE name=" + name)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_sql_injection_concat" in names

    def test_positive_exec_concat(self):
        code = 'db.Exec("DELETE FROM users WHERE id=" + id)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_sql_injection_concat" in names

    def test_positive_query_row_concat(self):
        code = 'db.QueryRow("SELECT * FROM users WHERE email=" + email)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_sql_injection_concat" in names

    def test_negative_parameterized_query(self):
        code = 'db.Query("SELECT * FROM users WHERE id=$1", userID)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_sql_injection_concat" not in names


# ===================================================================
# 3. Command Injection patterns
# ===================================================================


class TestGoCommandInjectionExec:
    """go_command_injection_exec detection."""

    def test_positive_concat(self):
        code = 'cmd := exec.Command("ls " + userDir)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_command_injection_exec" in names

    def test_positive_sprintf(self):
        code = 'cmd := exec.Command(fmt.Sprintf("cmd %s", arg))'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_command_injection_exec" in names

    def test_negative_static_command(self):
        code = 'cmd := exec.Command("ls", "-la", "/tmp")'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_command_injection_exec" not in names


class TestGoCommandInjectionShell:
    """go_command_injection_shell detection."""

    def test_positive_bin_sh(self):
        code = 'cmd := exec.Command("/bin/sh", "-c", userInput)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_command_injection_shell" in names

    def test_positive_bin_bash(self):
        code = 'cmd := exec.Command("/bin/bash", "-c", script)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_command_injection_shell" in names

    def test_positive_cmd_exe(self):
        code = 'cmd := exec.Command("cmd.exe", "-c", script)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_command_injection_shell" in names

    def test_negative_no_shell(self):
        code = 'cmd := exec.Command("git", "status")'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_command_injection_shell" not in names

    def test_severity_is_critical(self):
        code = 'exec.Command("/bin/sh", "-c", input)'
        findings = scan_code(code, sensitivity="high", language="go")
        shell = [f for f in findings if f.metadata["pattern_name"] == "go_command_injection_shell"]
        assert shell[0].severity == Severity.CRITICAL


# ===================================================================
# 4. Path Traversal patterns
# ===================================================================


class TestGoPathTraversal:
    """go_path_traversal detection."""

    def test_positive_os_open_with_user_input(self):
        code = "f, err := os.Open(filepath.Join(baseDir, req.URL.Path))"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_path_traversal" in names

    def test_positive_readfile_user_input(self):
        code = 'data, err := os.ReadFile(filepath.Join(dir, request.FormValue("file")))'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_path_traversal" in names

    def test_negative_static_path(self):
        code = 'f, err := os.Open("/etc/config.yaml")'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_path_traversal" not in names


class TestGoPathTraversalHttpDir:
    """go_path_traversal_http_dir detection."""

    def test_positive_concat(self):
        code = 'fs := http.FileServer(http.Dir(basePath + "/static"))'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_path_traversal_http_dir" in names

    def test_positive_sprintf(self):
        code = 'fs := http.FileServer(http.Dir(fmt.Sprintf("%s/assets", root)))'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_path_traversal_http_dir" in names

    def test_negative_static(self):
        code = 'fs := http.FileServer(http.Dir("/var/www/static"))'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_path_traversal_http_dir" not in names


# ===================================================================
# 5. Insecure TLS
# ===================================================================


class TestGoInsecureTls:
    """go_insecure_tls detection."""

    def test_positive_skip_verify(self):
        code = "tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_insecure_tls" in names

    def test_negative_secure_tls(self):
        code = "tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_insecure_tls" not in names

    def test_negative_false(self):
        code = "cfg := &tls.Config{InsecureSkipVerify: false}"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_insecure_tls" not in names

    def test_confidence_high(self):
        code = "InsecureSkipVerify: true"
        findings = scan_code(code, sensitivity="high", language="go")
        tls_f = [f for f in findings if f.metadata["pattern_name"] == "go_insecure_tls"]
        assert tls_f[0].confidence == 0.95

    def test_cwe_295(self):
        code = "InsecureSkipVerify: true"
        findings = scan_code(code, sensitivity="high", language="go")
        tls_f = [f for f in findings if f.metadata["pattern_name"] == "go_insecure_tls"]
        assert "CWE-295" in tls_f[0].cwe_ids


# ===================================================================
# 6. SSRF
# ===================================================================


class TestGoSsrf:
    """go_ssrf detection."""

    def test_positive_get_concat(self):
        code = "resp, err := http.Get(baseURL + path)"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_ssrf" in names

    def test_positive_post_sprintf(self):
        code = 'resp, err := http.Post(fmt.Sprintf("http://%s/api", host), "application/json", body)'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_ssrf" in names

    def test_negative_static_url(self):
        code = 'resp, err := http.Get("https://api.example.com/health")'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_ssrf" not in names


# ===================================================================
# 7. Weak Crypto
# ===================================================================


class TestGoWeakCrypto:
    """go_weak_crypto detection."""

    def test_positive_md5_new(self):
        code = "h := md5.New()"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_weak_crypto" in names

    def test_positive_sha1_sum(self):
        code = "hash := sha1.Sum(data)"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_weak_crypto" in names

    def test_negative_sha256(self):
        code = "h := sha256.New()"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_weak_crypto" not in names

    def test_severity_low(self):
        code = "h := md5.New()"
        findings = scan_code(code, sensitivity="high", language="go")
        wk = [f for f in findings if f.metadata["pattern_name"] == "go_weak_crypto"]
        assert wk[0].severity == Severity.LOW


# ===================================================================
# 8. Template Injection
# ===================================================================


class TestGoTextTemplate:
    """go_text_template_unescaped detection."""

    def test_positive_text_template_import(self):
        code = '"text/template"'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_text_template_unescaped" in names

    def test_negative_html_template(self):
        code = '"html/template"'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_text_template_unescaped" not in names

    def test_cwe_79(self):
        code = '"text/template"'
        findings = scan_code(code, sensitivity="high", language="go")
        tt = [f for f in findings if f.metadata["pattern_name"] == "go_text_template_unescaped"]
        assert "CWE-79" in tt[0].cwe_ids


# ===================================================================
# 9. Unsafe Deserialization
# ===================================================================


class TestGoUnsafeDeserialization:
    """go_unsafe_deserialization detection."""

    def test_positive_gob_request_body(self):
        code = "dec := gob.NewDecoder(r.Body)"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_unsafe_deserialization" in names

    def test_positive_xml_request_body(self):
        code = "dec := xml.NewDecoder(req.Body)"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_unsafe_deserialization" in names

    def test_negative_json_decoder(self):
        code = "dec := json.NewDecoder(r.Body)"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_unsafe_deserialization" not in names

    def test_negative_gob_from_file(self):
        code = "dec := gob.NewDecoder(file)"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_unsafe_deserialization" not in names


# ===================================================================
# 10. Hardcoded Credentials
# ===================================================================


class TestGoHardcodedPassword:
    """go_hardcoded_password detection."""

    def test_positive_password(self):
        code = 'password := "SuperSecret123!"'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_hardcoded_password" in names

    def test_positive_api_key(self):
        code = 'apiKey := "sk-1234567890abcdef"'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_hardcoded_password" in names

    def test_positive_token_assign(self):
        code = 'token = "eyJhbGciOiJIUzI1NiJ9.payload.sig"'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_hardcoded_password" in names

    def test_negative_env_var(self):
        code = 'password := os.Getenv("DB_PASSWORD")'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_hardcoded_password" not in names

    def test_negative_empty_string(self):
        code = 'password := ""'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_hardcoded_password" not in names

    def test_negative_short_value(self):
        code = 'secret := "ab"'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_hardcoded_password" not in names


# ===================================================================
# 11. Unhandled Errors
# ===================================================================


class TestGoUnhandledError:
    """go_unhandled_error detection."""

    def test_positive_query_ignored(self):
        code = 'rows, _ := db.Query("SELECT * FROM users")'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_unhandled_error" in names

    def test_positive_open_ignored(self):
        code = "f, _ := os.Open(path)"
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_unhandled_error" in names

    def test_negative_error_handled(self):
        code = 'rows, err := db.Query("SELECT * FROM users")'
        findings = scan_code(code, sensitivity="high", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_unhandled_error" not in names


# ===================================================================
# 12. Language auto-detection from .go file
# ===================================================================


class TestGoAutoDetection:
    """Language is auto-detected from .go file extension."""

    def test_go_file_detects_go(self):
        code = "InsecureSkipVerify: true"
        findings = scan_code(code, sensitivity="high", file_path="main.go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_insecure_tls" in names

    def test_go_file_no_python_patterns(self):
        # Python-specific pattern should not fire for .go file
        code = "hashlib.md5(data)"
        findings = scan_code(code, sensitivity="high", file_path="main.go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "insecure_hash" not in names

    def test_language_param_overrides_extension(self):
        code = "InsecureSkipVerify: true"
        findings = scan_code(code, sensitivity="high", file_path="main.py", language="go")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "go_insecure_tls" in names


# ===================================================================
# 13. No cross-contamination
# ===================================================================


class TestGoNoCrossContamination:
    """Go patterns don't fire for other languages and vice versa."""

    def test_python_patterns_not_in_go(self):
        # These are Python-only patterns used as test strings
        code = "\n".join([
            "subprocess.call(cmd, shell=True)",
            "hashlib.md5(x)",
        ])
        findings = scan_code(code, sensitivity="high", language="go")
        python_only = {
            "command_injection_subprocess_shell",
            "insecure_hash",
        }
        found = {f.metadata["pattern_name"] for f in findings}
        assert found.isdisjoint(python_only), (
            f"Python patterns found in Go scan: {found & python_only}"
        )

    def test_go_patterns_not_in_python(self):
        code = "\n".join([
            "InsecureSkipVerify: true",
            'exec.Command("/bin/sh", "-c", input)',
            'db.Query("SELECT * FROM t WHERE id=" + id)',
        ])
        findings = scan_code(code, sensitivity="high", language="python")
        go_only = {
            "go_insecure_tls",
            "go_command_injection_shell",
            "go_sql_injection_concat",
        }
        found = {f.metadata["pattern_name"] for f in findings}
        assert found.isdisjoint(go_only), (
            f"Go patterns found in Python scan: {found & go_only}"
        )


# ===================================================================
# 14. Comment skipping for Go
# ===================================================================


class TestGoCommentSkipping:
    """Go comments should be skipped."""

    def test_single_line_comment(self):
        code = "// InsecureSkipVerify: true"
        findings = scan_code(code, sensitivity="high", language="go")
        assert len(findings) == 0

    def test_block_comment(self):
        code = "/* InsecureSkipVerify: true */"
        findings = scan_code(code, sensitivity="high", language="go")
        assert len(findings) == 0

    def test_star_continuation(self):
        code = '* db.Query("SELECT * FROM t WHERE id=" + id)'
        findings = scan_code(code, sensitivity="high", language="go")
        assert len(findings) == 0


# ===================================================================
# 15. Multiple Go vulnerabilities in one scan
# ===================================================================


class TestMultipleGoFindings:
    """Multiple Go vulnerabilities detected in a single scan."""

    def test_multi_vuln_go_file(self):
        code = "\n".join([
            'query := fmt.Sprintf("SELECT * FROM users WHERE id=%s", id)',
            'db.Query("SELECT * FROM users WHERE name=" + name)',
            'exec.Command("/bin/sh", "-c", input)',
            "InsecureSkipVerify: true",
            "h := md5.New()",
            '"text/template"',
        ])
        findings = scan_code(code, sensitivity="high", language="go")
        names = {f.metadata["pattern_name"] for f in findings}
        assert "go_sql_injection_sprintf" in names
        assert "go_sql_injection_concat" in names
        assert "go_command_injection_shell" in names
        assert "go_insecure_tls" in names
        assert "go_weak_crypto" in names
        assert "go_text_template_unescaped" in names

    def test_line_numbers_correct(self):
        code = "\n".join([
            "package main",
            "",
            "InsecureSkipVerify: true",
        ])
        findings = scan_code(code, sensitivity="high", language="go")
        tls_f = [f for f in findings if f.metadata["pattern_name"] == "go_insecure_tls"]
        assert len(tls_f) == 1
        assert tls_f[0].line_number == 3


# ===================================================================
# 16. Clean Go code — no false positives
# ===================================================================


class TestCleanGoCode:
    """Clean Go code should produce no findings."""

    def test_clean_go_handler(self):
        code = "\n".join([
            "package main",
            "",
            "import (",
            '    "database/sql"',
            '    "net/http"',
            '    "encoding/json"',
            ")",
            "",
            "func handler(w http.ResponseWriter, r *http.Request) {",
            '    rows, err := db.Query("SELECT * FROM users WHERE id=$1", r.URL.Query().Get("id"))',
            "    if err != nil {",
            "        http.Error(w, err.Error(), 500)",
            "        return",
            "    }",
            "    defer rows.Close()",
            "    json.NewEncoder(w).Encode(results)",
            "}",
        ])
        findings = scan_code(code, sensitivity="high", language="go")
        go_findings = [f for f in findings if f.metadata["pattern_name"].startswith("go_")]
        assert len(go_findings) == 0


# ===================================================================
# 17. Remediation metadata
# ===================================================================


class TestGoRemediation:
    """Go patterns have remediation attached via REMEDIATION_MAP."""

    def test_sql_injection_has_remediation(self):
        code = 'fmt.Sprintf("SELECT * FROM users WHERE id=%s", id)'
        findings = scan_code(code, sensitivity="high", language="go")
        sqli = [f for f in findings if f.metadata["pattern_name"] == "go_sql_injection_sprintf"]
        assert len(sqli) == 1
        assert sqli[0].remediation is not None
        assert "parameterized" in sqli[0].remediation.description.lower()

    def test_insecure_tls_has_remediation(self):
        code = "InsecureSkipVerify: true"
        findings = scan_code(code, sensitivity="high", language="go")
        tls_f = [f for f in findings if f.metadata["pattern_name"] == "go_insecure_tls"]
        assert len(tls_f) == 1
        assert tls_f[0].remediation is not None
        assert tls_f[0].remediation.auto_fixable is True

    def test_weak_crypto_has_remediation(self):
        code = "h := md5.New()"
        findings = scan_code(code, sensitivity="high", language="go")
        wk = [f for f in findings if f.metadata["pattern_name"] == "go_weak_crypto"]
        assert len(wk) == 1
        assert wk[0].remediation is not None
        assert wk[0].remediation.auto_fixable is True

    def test_command_shell_has_remediation(self):
        code = 'exec.Command("/bin/sh", "-c", input)'
        findings = scan_code(code, sensitivity="high", language="go")
        shell = [f for f in findings if f.metadata["pattern_name"] == "go_command_injection_shell"]
        assert len(shell) == 1
        assert shell[0].remediation is not None
        assert shell[0].remediation.before != ""
        assert shell[0].remediation.after != ""
