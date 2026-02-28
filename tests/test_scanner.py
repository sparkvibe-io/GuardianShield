"""Tests for the code vulnerability scanner."""

from guardianshield.findings import FindingType, Severity
from guardianshield.scanner import scan_code

# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------

class TestSQLInjectionStringFormat:
    """SQL injection via string formatting."""

    def test_string_concatenation(self):
        code = 'query = "SELECT * FROM users WHERE id = " + user_id'
        findings = scan_code(code, sensitivity="high")
        assert len(findings) >= 1
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1
        assert sqli[0].severity == Severity.HIGH

    def test_percent_formatting(self):
        code = 'query = "SELECT * FROM users WHERE name = %s" % username'
        findings = scan_code(code, sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1
        assert sqli[0].severity == Severity.HIGH

    def test_fstring_sql(self):
        code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        findings = scan_code(code, sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1
        assert sqli[0].severity == Severity.HIGH


class TestSQLInjectionRawQuery:
    """SQL injection via cursor.execute with unsanitized input."""

    def test_cursor_execute_concat(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        findings = scan_code(code, sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        crit = [f for f in sqli if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1

    def test_cursor_execute_fstring(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        findings = scan_code(code, sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        crit = [f for f in sqli if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1

    def test_db_execute_concat(self):
        code = 'db.execute("DELETE FROM records WHERE id = " + record_id)'
        findings = scan_code(code, sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        crit = [f for f in sqli if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------

class TestXSSInnerHTML:
    """XSS via innerHTML assignment."""

    def test_innerhtml(self):
        code = 'element.innerHTML = userInput;'
        findings = scan_code(code, sensitivity="high")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1
        assert xss[0].severity == Severity.MEDIUM


class TestXSSDocumentWrite:
    """XSS via document.write()."""

    def test_document_write(self):
        code = 'document.write(userData);'
        findings = scan_code(code, sensitivity="high")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1
        assert xss[0].severity == Severity.MEDIUM


class TestXSSTemplateRendering:
    """XSS via unsanitized template rendering."""

    def test_safe_filter(self):
        code = '{{ user_content | safe }}'
        findings = scan_code(code, sensitivity="high")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1
        assert xss[0].severity == Severity.HIGH

    def test_autoescape_off(self):
        code = '{% autoescape off %}'
        findings = scan_code(code, sensitivity="high")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1
        assert xss[0].severity == Severity.HIGH

    def test_markup(self):
        code = 'html = Markup(user_input)'
        findings = scan_code(code, sensitivity="high")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1
        assert xss[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Command Injection
# ---------------------------------------------------------------------------

class TestCommandInjectionOsSystem:
    """Command injection via os.system()."""

    def test_os_system(self):
        code = 'os.system("rm -rf " + user_input)'
        findings = scan_code(code, sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1
        assert any(f.severity == Severity.HIGH for f in cmdi)


class TestCommandInjectionSubprocess:
    """Command injection via subprocess with shell=True."""

    def test_subprocess_shell_true(self):
        code = 'subprocess.call(cmd, shell=True)'
        findings = scan_code(code, sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1
        assert cmdi[0].severity == Severity.HIGH

    def test_subprocess_run_shell_true(self):
        code = 'subprocess.run(["ls"], shell=True)'
        findings = scan_code(code, sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1

    def test_subprocess_popen_shell_true(self):
        code = 'subprocess.Popen(cmd, shell=True)'
        findings = scan_code(code, sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1


class TestCommandInjectionEvalExec:
    """Command injection via eval()/exec()."""

    def test_eval(self):
        code = 'result = eval(user_input)'
        findings = scan_code(code, sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        crit = [f for f in cmdi if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1

    def test_exec(self):
        code = 'exec(code_string)'
        findings = scan_code(code, sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        crit = [f for f in cmdi if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1


# ---------------------------------------------------------------------------
# Path Traversal
# ---------------------------------------------------------------------------

class TestPathTraversalOpen:
    """Path traversal via open() with concatenation."""

    def test_open_concat(self):
        code = 'f = open(base_dir + filename, "r")'
        findings = scan_code(code, sensitivity="high")
        pt = [f for f in findings if f.finding_type == FindingType.PATH_TRAVERSAL]
        assert len(pt) >= 1
        assert pt[0].severity == Severity.MEDIUM

    def test_open_fstring(self):
        code = 'f = open(f"/uploads/{user_file}", "r")'
        findings = scan_code(code, sensitivity="high")
        pt = [f for f in findings if f.finding_type == FindingType.PATH_TRAVERSAL]
        assert len(pt) >= 1


class TestPathTraversalOsPathJoin:
    """Path traversal via os.path.join with user-controlled segments."""

    def test_os_path_join_request(self):
        code = 'path = os.path.join(upload_dir, request.filename)'
        findings = scan_code(code, sensitivity="high")
        pt = [f for f in findings if f.finding_type == FindingType.PATH_TRAVERSAL]
        assert len(pt) >= 1
        assert pt[0].severity == Severity.MEDIUM

    def test_os_path_join_user_input(self):
        code = 'path = os.path.join("/var/data", user_input)'
        findings = scan_code(code, sensitivity="high")
        pt = [f for f in findings if f.finding_type == FindingType.PATH_TRAVERSAL]
        assert len(pt) >= 1


# ---------------------------------------------------------------------------
# Insecure Functions
# ---------------------------------------------------------------------------

class TestInsecurePickle:
    """Insecure deserialization via pickle."""

    def test_pickle_loads(self):
        code = 'obj = pickle.loads(data)'
        findings = scan_code(code, sensitivity="high")
        insec = [f for f in findings if f.finding_type == FindingType.INSECURE_FUNCTION]
        assert len(insec) >= 1
        assert insec[0].severity == Severity.HIGH

    def test_pickle_load(self):
        code = 'obj = pickle.load(open("data.pkl", "rb"))'
        findings = scan_code(code, sensitivity="high")
        insec = [f for f in findings if f.finding_type == FindingType.INSECURE_FUNCTION]
        assert len(insec) >= 1


class TestInsecureHash:
    """Weak hash algorithms."""

    def test_hashlib_md5(self):
        code = 'digest = hashlib.md5(password.encode())'
        findings = scan_code(code, sensitivity="high")
        insec = [f for f in findings if f.finding_type == FindingType.INSECURE_FUNCTION]
        assert len(insec) >= 1
        assert insec[0].severity == Severity.LOW

    def test_hashlib_sha1(self):
        code = 'digest = hashlib.sha1(data)'
        findings = scan_code(code, sensitivity="high")
        insec = [f for f in findings if f.finding_type == FindingType.INSECURE_FUNCTION]
        assert len(insec) >= 1
        assert insec[0].severity == Severity.LOW


class TestInsecureRandom:
    """Non-cryptographic random for security."""

    def test_random_random(self):
        code = 'token = str(random.random())'
        findings = scan_code(code, sensitivity="high")
        insec = [f for f in findings if f.finding_type == FindingType.INSECURE_FUNCTION]
        assert len(insec) >= 1
        assert insec[0].severity == Severity.MEDIUM

    def test_random_randint(self):
        code = 'otp = random.randint(100000, 999999)'
        findings = scan_code(code, sensitivity="high")
        insec = [f for f in findings if f.finding_type == FindingType.INSECURE_FUNCTION]
        assert len(insec) >= 1


# ---------------------------------------------------------------------------
# Comment skipping
# ---------------------------------------------------------------------------

class TestCommentSkipping:
    """Lines that are comments should be skipped entirely."""

    def test_python_comment_skipped(self):
        code = '# eval(user_input)'
        findings = scan_code(code, sensitivity="high")
        assert len(findings) == 0

    def test_js_comment_skipped(self):
        code = '// document.write(data);'
        findings = scan_code(code, sensitivity="high")
        assert len(findings) == 0

    def test_block_comment_skipped(self):
        code = '/* os.system("ls") */'
        findings = scan_code(code, sensitivity="high")
        assert len(findings) == 0

    def test_star_comment_skipped(self):
        code = '* pickle.loads(data)'
        findings = scan_code(code, sensitivity="high")
        assert len(findings) == 0

    def test_indented_comment_skipped(self):
        code = '    # eval(user_input)'
        findings = scan_code(code, sensitivity="high")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Sensitivity filtering
# ---------------------------------------------------------------------------

class TestSensitivityFiltering:
    """Sensitivity level controls which findings are returned."""

    def test_low_sensitivity_only_critical(self):
        code = "\n".join([
            'cursor.execute("SELECT * FROM users WHERE id = " + uid)',  # CRITICAL
            'os.system("ls")',  # HIGH
            'element.innerHTML = data;',  # MEDIUM
            'hashlib.md5(x)',  # LOW
        ])
        findings = scan_code(code, sensitivity="low")
        for f in findings:
            assert f.severity == Severity.CRITICAL

    def test_medium_sensitivity_skips_low(self):
        code = "\n".join([
            'cursor.execute("SELECT * FROM users WHERE id = " + uid)',  # CRITICAL
            'os.system("ls")',  # HIGH
            'element.innerHTML = data;',  # MEDIUM
            'hashlib.md5(x)',  # LOW
        ])
        findings = scan_code(code, sensitivity="medium")
        severities = {f.severity for f in findings}
        assert Severity.LOW not in severities
        # Should still have CRITICAL, HIGH, and MEDIUM
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities

    def test_high_sensitivity_returns_all(self):
        code = "\n".join([
            'cursor.execute("SELECT * FROM users WHERE id = " + uid)',  # CRITICAL
            'os.system("ls")',  # HIGH
            'element.innerHTML = data;',  # MEDIUM
            'hashlib.md5(x)',  # LOW
        ])
        findings = scan_code(code, sensitivity="high")
        severities = {f.severity for f in findings}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities
        assert Severity.LOW in severities

    def test_default_sensitivity_is_medium(self):
        code = 'hashlib.md5(x)'  # LOW severity
        findings = scan_code(code)
        assert len(findings) == 0  # LOW is filtered out by default


# ---------------------------------------------------------------------------
# Clean code
# ---------------------------------------------------------------------------

class TestCleanCode:
    """Clean code should produce no findings."""

    def test_no_findings_for_clean_python(self):
        code = "\n".join([
            "import os",
            "from pathlib import Path",
            "",
            "def greet(name: str) -> str:",
            '    return f"Hello, {name}!"',
            "",
            "if __name__ == '__main__':",
            "    print(greet('world'))",
        ])
        findings = scan_code(code, sensitivity="high")
        assert len(findings) == 0

    def test_no_findings_for_parameterized_query(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        findings = scan_code(code, sensitivity="high")
        # Parameterized queries should NOT match the raw concatenation pattern
        sqli_crit = [
            f for f in findings
            if f.finding_type == FindingType.SQL_INJECTION
            and f.severity == Severity.CRITICAL
        ]
        assert len(sqli_crit) == 0


# ---------------------------------------------------------------------------
# file_path passthrough
# ---------------------------------------------------------------------------

class TestFilePathPassthrough:
    """file_path argument should be attached to every finding."""

    def test_file_path_set(self):
        code = 'eval(user_input)'
        findings = scan_code(code, sensitivity="high", file_path="app/views.py")
        assert len(findings) >= 1
        for f in findings:
            assert f.file_path == "app/views.py"

    def test_file_path_none_by_default(self):
        code = 'eval(user_input)'
        findings = scan_code(code, sensitivity="high")
        assert len(findings) >= 1
        for f in findings:
            assert f.file_path is None


# ---------------------------------------------------------------------------
# Multi-line scanning
# ---------------------------------------------------------------------------

class TestMultiLineCode:
    """Multi-line code should detect multiple different vulnerabilities."""

    def test_multiple_vulnerabilities(self):
        code = "\n".join([
            'import os',
            'import pickle',
            '',
            'query = "SELECT * FROM users WHERE id = " + user_id',
            'element.innerHTML = response;',
            'os.system("rm -rf " + path)',
            'obj = pickle.loads(data)',
            'result = eval(expr)',
        ])
        findings = scan_code(code, sensitivity="high")
        types_found = {f.finding_type for f in findings}
        assert FindingType.SQL_INJECTION in types_found
        assert FindingType.XSS in types_found
        assert FindingType.COMMAND_INJECTION in types_found
        assert FindingType.INSECURE_FUNCTION in types_found

    def test_line_numbers_are_correct(self):
        code = "\n".join([
            'safe_line = True',
            'eval(user_input)',
            'safe_again = True',
        ])
        findings = scan_code(code, sensitivity="high")
        assert len(findings) >= 1
        assert findings[0].line_number == 2

    def test_scanner_name(self):
        code = 'eval(user_input)'
        findings = scan_code(code, sensitivity="high")
        assert len(findings) >= 1
        for f in findings:
            assert f.scanner == "code_scanner"
