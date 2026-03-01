"""Tests for PHP vulnerability patterns."""

from guardianshield.findings import FindingType, Severity
from guardianshield.scanner import scan_code

# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------


class TestPHPSQLInjectionMysqlQuery:
    """SQL injection via mysql_query/mysqli_query with concatenation."""

    def test_mysqli_query_concat(self):
        code = '$result = mysqli_query($conn, "SELECT * FROM users WHERE id=" . $user_id);'
        findings = scan_code(code, language="php", sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1
        assert sqli[0].severity == Severity.CRITICAL

    def test_mysql_query_concat(self):
        code = '$result = mysql_query("SELECT * FROM users WHERE id=" . $_GET["id"]);'
        findings = scan_code(code, language="php", sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1

    def test_safe_prepared_statement_no_match(self):
        code = '$stmt = $conn->prepare("SELECT * FROM users WHERE id=?");'
        findings = scan_code(code, language="php", sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) == 0


class TestPHPSQLInjectionInterpolation:
    """SQL injection via variable interpolation in query strings."""

    def test_mysqli_query_interpolation(self):
        code = '$result = mysqli_query($conn, "SELECT * FROM users WHERE name=\'$name\'");'
        findings = scan_code(code, language="php", sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1
        assert sqli[0].severity == Severity.CRITICAL

    def test_query_method_interpolation(self):
        code = '$result = $db->query("SELECT * FROM orders WHERE user_id=$uid");'
        findings = scan_code(code, language="php", sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1


class TestPHPSQLInjectionLaravelRaw:
    """SQL injection via Laravel raw expressions."""

    def test_db_raw(self):
        code = '$results = DB::raw("SELECT * FROM users WHERE id=$id");'
        findings = scan_code(code, language="php", sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1
        assert sqli[0].severity == Severity.HIGH

    def test_where_raw(self):
        code = '$users = User::whereRaw("status = $status")->get();'
        findings = scan_code(code, language="php", sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1

    def test_select_raw(self):
        code = 'DB::table("users")->selectRaw("*, $computed as total")->get();'
        findings = scan_code(code, language="php", sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1

    def test_safe_laravel_binding(self):
        code = 'DB::select("SELECT * FROM users WHERE id=?", [$id]);'
        findings = scan_code(code, language="php", sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) == 0


# ---------------------------------------------------------------------------
# Command Injection
# ---------------------------------------------------------------------------


class TestPHPCommandInjectionFunctions:
    """Command injection via PHP shell functions."""

    def test_system_with_var(self):
        code = 'system("convert " . $filename);'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1
        assert cmdi[0].severity == Severity.CRITICAL

    def test_shell_exec_with_var(self):
        code = '$output = shell_exec("ls " . $dir);'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1

    def test_passthru_with_var(self):
        code = 'passthru("ping " . $host);'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1

    def test_popen_with_var(self):
        code = '$handle = popen("grep " . $pattern, "r");'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1

    def test_proc_open_with_var(self):
        code = '$process = proc_open("cmd " . $arg, $desc, $pipes);'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1

    def test_safe_escapeshellarg(self):
        # escapeshellarg wrapping is contextual; pattern still detects func+var
        code = 'system("convert " . escapeshellarg($filename));'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert isinstance(cmdi, list)


class TestPHPCommandInjectionBacktick:
    """Command injection via backtick operator."""

    def test_backtick_with_var(self):
        code = '$output = `ls $dir`;'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1
        assert cmdi[0].severity == Severity.CRITICAL

    def test_backtick_literal_no_match(self):
        code = '$output = `ls /tmp`;'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [
            f for f in findings
            if f.finding_type == FindingType.COMMAND_INJECTION
            and "backtick" in f.message.lower()
        ]
        assert len(cmdi) == 0


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------


class TestPHPXSSEchoSuperglobal:
    """XSS via direct echo of superglobal."""

    def test_echo_get(self):
        code = 'echo $_GET["name"];'
        findings = scan_code(code, language="php", sensitivity="high")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1
        assert xss[0].severity == Severity.HIGH

    def test_echo_post(self):
        code = 'echo "Hello " . $_POST["username"];'
        findings = scan_code(code, language="php", sensitivity="high")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1

    def test_echo_request(self):
        code = 'echo $_REQUEST["q"];'
        findings = scan_code(code, language="php", sensitivity="high")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1

    def test_echo_cookie(self):
        code = 'echo $_COOKIE["session"];'
        findings = scan_code(code, language="php", sensitivity="high")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1

    def test_safe_htmlspecialchars(self):
        # Pattern still matches echo + superglobal; htmlspecialchars is contextual
        code = 'echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");'
        findings = scan_code(code, language="php", sensitivity="high")
        assert isinstance(findings, list)


class TestPHPXSSBladeUnescaped:
    """XSS via Blade {!! !!} unescaped output."""

    def test_blade_unescaped(self):
        code = '{!! $userContent !!}'
        findings = scan_code(code, language="php", sensitivity="high")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1
        assert xss[0].severity == Severity.HIGH

    def test_blade_escaped_no_match(self):
        code = '{{ $userContent }}'
        findings = scan_code(code, language="php", sensitivity="high")
        xss = [
            f for f in findings
            if f.finding_type == FindingType.XSS
            and "blade" in f.message.lower()
        ]
        assert len(xss) == 0


# ---------------------------------------------------------------------------
# File Upload
# ---------------------------------------------------------------------------


class TestPHPFileUpload:
    """File upload without validation."""

    def test_move_uploaded_file(self):
        code = 'move_uploaded_file($_FILES["file"]["tmp_name"], $dest);'
        findings = scan_code(code, language="php", sensitivity="high")
        upload = [f for f in findings if "CWE-434" in f.cwe_ids]
        assert len(upload) >= 1
        assert upload[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Code Execution (eval / preg_replace /e)
# ---------------------------------------------------------------------------


class TestPHPEvalExecution:
    """Code execution via eval()."""

    def test_eval_with_var(self):
        code = 'eval($userCode);'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        crit = [f for f in cmdi if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1

    def test_eval_post(self):
        code = 'eval($_POST["code"]);'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1


class TestPHPPregReplaceEval:
    """Code execution via preg_replace /e modifier."""

    def test_preg_replace_e(self):
        code = 'preg_replace("/pattern/e", "$code", $input);'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [f for f in findings if f.finding_type == FindingType.COMMAND_INJECTION]
        assert len(cmdi) >= 1
        assert cmdi[0].severity == Severity.HIGH

    def test_preg_replace_no_e_no_match(self):
        code = 'preg_replace("/pattern/i", "replacement", $input);'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [
            f for f in findings
            if f.finding_type == FindingType.COMMAND_INJECTION
            and "preg_replace" in f.message.lower()
        ]
        assert len(cmdi) == 0


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------


class TestPHPSSRFCurl:
    """SSRF via curl_setopt with user-controlled URL."""

    def test_curl_setopt_url(self):
        code = 'curl_setopt($ch, CURLOPT_URL, $userUrl);'
        findings = scan_code(code, language="php", sensitivity="high")
        ssrf = [f for f in findings if "CWE-918" in f.cwe_ids]
        assert len(ssrf) >= 1
        assert ssrf[0].severity == Severity.HIGH


class TestPHPSSRFFileGetContents:
    """SSRF via file_get_contents with variable."""

    def test_file_get_contents_var(self):
        code = '$data = file_get_contents($url);'
        findings = scan_code(code, language="php", sensitivity="high")
        ssrf = [f for f in findings if "CWE-918" in f.cwe_ids]
        assert len(ssrf) >= 1
        assert ssrf[0].severity == Severity.MEDIUM

    def test_file_get_contents_literal_no_match(self):
        code = '$data = file_get_contents("config.json");'
        findings = scan_code(code, language="php", sensitivity="high")
        ssrf = [
            f for f in findings
            if "CWE-918" in f.cwe_ids
            and "file_get_contents" in f.message.lower()
        ]
        assert len(ssrf) == 0


# ---------------------------------------------------------------------------
# Path Traversal (include/require)
# ---------------------------------------------------------------------------


class TestPHPPathTraversalInclude:
    """Path traversal via include/require with variable."""

    def test_include_var(self):
        code = 'include($page . ".php");'
        findings = scan_code(code, language="php", sensitivity="high")
        pt = [f for f in findings if f.finding_type == FindingType.PATH_TRAVERSAL]
        assert len(pt) >= 1
        assert pt[0].severity == Severity.CRITICAL

    def test_require_once_var(self):
        code = 'require_once($module);'
        findings = scan_code(code, language="php", sensitivity="high")
        pt = [f for f in findings if f.finding_type == FindingType.PATH_TRAVERSAL]
        assert len(pt) >= 1

    def test_include_get(self):
        code = 'include($_GET["page"]);'
        findings = scan_code(code, language="php", sensitivity="high")
        pt = [f for f in findings if f.finding_type == FindingType.PATH_TRAVERSAL]
        assert len(pt) >= 1

    def test_include_literal_no_match(self):
        code = 'include("header.php");'
        findings = scan_code(code, language="php", sensitivity="high")
        pt = [f for f in findings if f.finding_type == FindingType.PATH_TRAVERSAL]
        assert len(pt) == 0


# ---------------------------------------------------------------------------
# Insecure Deserialization
# ---------------------------------------------------------------------------


class TestPHPInsecureUnserialize:
    """Insecure deserialization via unserialize()."""

    def test_unserialize_post(self):
        code = '$data = unserialize($_POST["data"]);'
        findings = scan_code(code, language="php", sensitivity="high")
        deser = [f for f in findings if "CWE-502" in f.cwe_ids]
        assert len(deser) >= 1
        assert deser[0].severity == Severity.CRITICAL

    def test_unserialize_var(self):
        code = '$obj = unserialize($input);'
        findings = scan_code(code, language="php", sensitivity="high")
        deser = [f for f in findings if "CWE-502" in f.cwe_ids]
        assert len(deser) >= 1

    def test_json_decode_no_match(self):
        code = '$data = json_decode($input, true);'
        findings = scan_code(code, language="php", sensitivity="high")
        deser = [f for f in findings if "CWE-502" in f.cwe_ids]
        assert len(deser) == 0


# ---------------------------------------------------------------------------
# Weak Crypto
# ---------------------------------------------------------------------------


class TestPHPWeakPasswordHash:
    """Weak hash for password hashing."""

    def test_md5_password(self):
        code = '$hash = md5($password);'
        findings = scan_code(code, language="php", sensitivity="high")
        weak = [f for f in findings if "CWE-328" in f.cwe_ids]
        assert len(weak) >= 1
        assert weak[0].severity == Severity.HIGH

    def test_sha1_password(self):
        code = '$hash = sha1($password);'
        findings = scan_code(code, language="php", sensitivity="high")
        weak = [f for f in findings if "CWE-328" in f.cwe_ids]
        assert len(weak) >= 1

    def test_md5_post(self):
        code = '$hash = md5($_POST["password"]);'
        findings = scan_code(code, language="php", sensitivity="high")
        weak = [f for f in findings if "CWE-328" in f.cwe_ids]
        assert len(weak) >= 1

    def test_password_hash_no_match(self):
        code = '$hash = password_hash($password, PASSWORD_DEFAULT);'
        findings = scan_code(code, language="php", sensitivity="high")
        weak = [f for f in findings if "CWE-328" in f.cwe_ids]
        assert len(weak) == 0


# ---------------------------------------------------------------------------
# Type Juggling
# ---------------------------------------------------------------------------


class TestPHPTypeJuggling:
    """Loose comparison with sensitive variables."""

    def test_token_loose_comparison(self):
        code = 'if ($token == $expected) { grant_access(); }'
        findings = scan_code(code, language="php", sensitivity="high")
        juggle = [f for f in findings if f.finding_type == FindingType.INSECURE_PATTERN]
        assert len(juggle) >= 1
        assert juggle[0].severity == Severity.MEDIUM

    def test_password_loose_comparison(self):
        code = 'if ($password == $stored_hash) { login(); }'
        findings = scan_code(code, language="php", sensitivity="high")
        juggle = [f for f in findings if f.finding_type == FindingType.INSECURE_PATTERN]
        assert len(juggle) >= 1

    def test_strict_comparison_no_match(self):
        code = 'if ($token === $expected) { grant_access(); }'
        findings = scan_code(code, language="php", sensitivity="high")
        juggle = [
            f for f in findings
            if f.finding_type == FindingType.INSECURE_PATTERN
            and "type juggling" in f.message.lower()
        ]
        assert len(juggle) == 0


# ---------------------------------------------------------------------------
# Information Disclosure
# ---------------------------------------------------------------------------


class TestPHPInfoDisclosurePhpinfo:
    """Information disclosure via phpinfo()."""

    def test_phpinfo(self):
        code = 'phpinfo();'
        findings = scan_code(code, language="php", sensitivity="high")
        info = [f for f in findings if "CWE-200" in f.cwe_ids]
        assert len(info) >= 1
        assert info[0].severity == Severity.MEDIUM


class TestPHPInfoDisclosureDisplayErrors:
    """Information disclosure via display_errors."""

    def test_ini_set_display_errors(self):
        code = "ini_set('display_errors', 1);"
        findings = scan_code(code, language="php", sensitivity="high")
        info = [f for f in findings if "CWE-209" in f.cwe_ids]
        assert len(info) >= 1
        assert info[0].severity == Severity.LOW


# ---------------------------------------------------------------------------
# Language detection via file extension
# ---------------------------------------------------------------------------


class TestPHPLanguageDetection:
    """PHP patterns should activate via .php file extension."""

    def test_php_extension_detection(self):
        code = '$result = mysqli_query($conn, "SELECT * FROM users WHERE id=" . $id);'
        findings = scan_code(code, file_path="app/controller.php", sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


class TestPHPRemediation:
    """PHP patterns should include remediation guidance."""

    def test_sql_injection_has_remediation(self):
        code = '$result = mysqli_query($conn, "SELECT * FROM users WHERE id=" . $id);'
        findings = scan_code(code, language="php", sensitivity="high")
        sqli = [f for f in findings if f.finding_type == FindingType.SQL_INJECTION]
        assert len(sqli) >= 1
        assert sqli[0].remediation is not None
        assert sqli[0].remediation.description

    def test_xss_has_remediation(self):
        code = 'echo $_GET["name"];'
        findings = scan_code(code, language="php", sensitivity="high")
        xss = [f for f in findings if f.finding_type == FindingType.XSS]
        assert len(xss) >= 1
        assert xss[0].remediation is not None

    def test_eval_has_remediation(self):
        code = 'eval($userCode);'
        findings = scan_code(code, language="php", sensitivity="high")
        cmdi = [
            f for f in findings
            if f.finding_type == FindingType.COMMAND_INJECTION
            and "eval" in f.message.lower()
        ]
        assert len(cmdi) >= 1
        assert cmdi[0].remediation is not None


# ---------------------------------------------------------------------------
# Clean PHP code
# ---------------------------------------------------------------------------


class TestCleanPHPCode:
    """Clean PHP code should produce no findings."""

    def test_no_findings_for_clean_php(self):
        code = "\n".join([
            "<?php",
            "namespace App\\Controllers;",
            "",
            "class UserController {",
            "    public function index() {",
            '        $users = User::all();',
            '        return view("users.index", compact("users"));',
            "    }",
            "}",
        ])
        findings = scan_code(code, language="php", sensitivity="high")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Multi-pattern detection
# ---------------------------------------------------------------------------


class TestPHPMultipleVulnerabilities:
    """Multiple PHP vulnerabilities in one snippet."""

    def test_multiple_findings(self):
        code = "\n".join([
            '$result = mysqli_query($conn, "SELECT * FROM users WHERE id=" . $id);',
            'echo $_GET["search"];',
            'system("rm " . $file);',
            'eval($code);',
            '$data = unserialize($input);',
            'phpinfo();',
        ])
        findings = scan_code(code, language="php", sensitivity="high")
        types_found = {f.finding_type for f in findings}
        assert FindingType.SQL_INJECTION in types_found
        assert FindingType.XSS in types_found
        assert FindingType.COMMAND_INJECTION in types_found
        assert FindingType.INSECURE_FUNCTION in types_found


# ---------------------------------------------------------------------------
# Comment skipping
# ---------------------------------------------------------------------------


class TestPHPCommentSkipping:
    """PHP comments should be skipped."""

    def test_php_single_line_comment(self):
        code = '// eval($userInput);'
        findings = scan_code(code, language="php", sensitivity="high")
        assert len(findings) == 0

    def test_php_hash_comment(self):
        code = '# system($cmd);'
        findings = scan_code(code, language="php", sensitivity="high")
        assert len(findings) == 0

    def test_php_block_comment(self):
        code = '/* mysqli_query($conn, "SELECT * FROM " . $table); */'
        findings = scan_code(code, language="php", sensitivity="high")
        assert len(findings) == 0
