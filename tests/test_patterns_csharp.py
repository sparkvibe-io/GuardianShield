"""Tests for C# / ASP.NET vulnerability patterns."""

from guardianshield.findings import FindingType, Severity
from guardianshield.patterns import (
    CSHARP_PATTERNS,
    CSHARP_REMEDIATION,
    EXTENSION_MAP,
    LANGUAGE_PATTERNS,
    REMEDIATION_MAP,
)
from guardianshield.scanner import scan_code

# ===================================================================
# 1. Import / Structure tests
# ===================================================================


class TestCSharpPatternImports:
    """C# pattern module can be imported and has expected structure."""

    def test_csharp_patterns_importable(self):
        assert isinstance(CSHARP_PATTERNS, list)
        assert len(CSHARP_PATTERNS) >= 12

    def test_csharp_in_language_patterns(self):
        assert "csharp" in LANGUAGE_PATTERNS
        assert "cs" in LANGUAGE_PATTERNS

    def test_csharp_aliases_same_list(self):
        assert LANGUAGE_PATTERNS["csharp"] is LANGUAGE_PATTERNS["cs"]

    def test_cs_extension_mapped(self):
        assert EXTENSION_MAP[".cs"] == "csharp"

    def test_pattern_tuple_has_seven_elements(self):
        for p in CSHARP_PATTERNS:
            assert len(p) == 7, f"Pattern {p[0]} has {len(p)} elements, expected 7"

    def test_all_patterns_have_remediation(self):
        for p in CSHARP_PATTERNS:
            name = p[0]
            assert name in CSHARP_REMEDIATION, f"Pattern {name} missing remediation"
            assert name in REMEDIATION_MAP, f"Pattern {name} not in global REMEDIATION_MAP"

    def test_remediation_has_required_fields(self):
        for name, rem in CSHARP_REMEDIATION.items():
            assert "description" in rem, f"Remediation {name} missing 'description'"
            assert "before" in rem, f"Remediation {name} missing 'before'"
            assert "after" in rem, f"Remediation {name} missing 'after'"
            assert "auto_fixable" in rem, f"Remediation {name} missing 'auto_fixable'"


# ===================================================================
# 2. SQL Injection patterns
# ===================================================================


class TestCSharpSqlInjectionStringConcat:
    """SQL injection via SqlCommand string concatenation."""

    def test_positive_sqlcommand_concat(self):
        code = 'var cmd = new SqlCommand("SELECT * FROM users WHERE id=" + userId, conn);'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_sql_injection_string_concat" in names

    def test_positive_sqldataadapter_concat(self):
        code = (
            'var adapter = new SqlDataAdapter("SELECT * FROM orders WHERE status="'
            " + status, conn);"
        )
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_sql_injection_string_concat" in names

    def test_negative_parameterized(self):
        code = 'var cmd = new SqlCommand("SELECT * FROM users WHERE id=@id", conn);'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_sql_injection_string_concat" not in names


class TestCSharpSqlInjectionStringFormat:
    """SQL injection via string interpolation."""

    def test_positive_interpolation(self):
        code = "cmd.CommandText = $\"SELECT * FROM users WHERE name='{name}'\";"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_sql_injection_string_format" in names

    def test_positive_string_format(self):
        code = (
            'cmd.CommandText = string.Format('
            '"SELECT * FROM users WHERE id={0}", userId);'
        )
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_sql_injection_string_format" in names

    def test_negative_literal_command(self):
        code = 'cmd.CommandText = "SELECT * FROM users WHERE id=@id";'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_sql_injection_string_format" not in names


class TestCSharpSqlInjectionExecuteConcat:
    """SQL injection via Execute method with concatenation."""

    def test_positive_execute_reader(self):
        code = '.ExecuteReader("SELECT * FROM users WHERE id=" + id);'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_sql_injection_execute_concat" in names

    def test_positive_execute_non_query(self):
        code = '.ExecuteNonQuery("DELETE FROM users WHERE id=" + id);'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_sql_injection_execute_concat" in names

    def test_negative_no_concat(self):
        code = "cmd.ExecuteReader();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_sql_injection_execute_concat" not in names


# ===================================================================
# 3. Command Injection patterns
# ===================================================================


class TestCSharpCommandInjectionProcessStart:
    """Command injection via Process.Start."""

    def test_positive_concat(self):
        code = 'Process.Start("cmd.exe", "/c " + userInput);'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_command_injection_process_start" in names

    def test_positive_interpolation(self):
        code = 'Process.Start("cmd.exe", $"/c {userInput}");'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_command_injection_process_start" in names

    def test_negative_static_args(self):
        code = 'Process.Start("notepad.exe", "readme.txt");'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_command_injection_process_start" not in names


class TestCSharpCommandInjectionFilename:
    """Command injection via ProcessStartInfo."""

    def test_positive_filename_concat(self):
        code = 'psi.FileName = userInput + ".exe";'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_command_injection_process_filename" in names

    def test_positive_arguments_interpolation(self):
        code = 'psi.Arguments = $"--config {configPath}";'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_command_injection_process_filename" in names

    def test_negative_static_filename(self):
        code = 'psi.FileName = "notepad.exe";'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_command_injection_process_filename" not in names


# ===================================================================
# 4. Path Traversal patterns
# ===================================================================


class TestCSharpPathTraversal:
    """Path traversal via file operations."""

    def test_positive_readalltext_concat(self):
        code = 'var text = File.ReadAllText(basePath + "/" + userFile);'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_path_traversal" in names

    def test_positive_path_combine_interpolation(self):
        code = 'var path = Path.Combine($"/uploads/{userId}", filename);'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_path_traversal" in names

    def test_positive_directory_getfiles(self):
        code = "var files = Directory.GetFiles(baseDir + userSubDir);"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_path_traversal" in names

    def test_negative_static_path(self):
        code = 'var text = File.ReadAllText("config.json");'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_path_traversal" not in names


# ===================================================================
# 5. XSS patterns
# ===================================================================


class TestCSharpXssHtmlRaw:
    """XSS via Html.Raw."""

    def test_positive_html_raw(self):
        code = "@Html.Raw(userContent)"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_xss_html_raw" in names

    def test_positive_html_raw_variable(self):
        code = "var html = Html.Raw(model.Description);"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_xss_html_raw" in names

    def test_negative_html_encode(self):
        code = "Html.Encode(userContent)"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_xss_html_raw" not in names


class TestCSharpXssResponseWrite:
    """XSS via Response.Write."""

    def test_positive_response_write(self):
        code = "Response.Write(userInput);"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_xss_response_write" in names

    def test_negative_no_response_write(self):
        code = "Console.WriteLine(userInput);"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_xss_response_write" not in names


# ===================================================================
# 6. Insecure Deserialization patterns
# ===================================================================


class TestCSharpBinaryFormatter:
    """BinaryFormatter detection."""

    def test_positive(self):
        code = "var formatter = new BinaryFormatter();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_deserialization_binary_formatter" in names

    def test_severity_is_critical(self):
        code = "var formatter = new BinaryFormatter();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        bf = [
            f
            for f in findings
            if f.metadata["pattern_name"]
            == "cs_insecure_deserialization_binary_formatter"
        ]
        assert bf[0].severity == Severity.CRITICAL

    def test_negative_json_serializer(self):
        code = "var obj = JsonSerializer.Deserialize<MyType>(json);"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_deserialization_binary_formatter" not in names


class TestCSharpTypeNameHandling:
    """TypeNameHandling.All detection."""

    def test_positive_all(self):
        code = "settings.TypeNameHandling = TypeNameHandling.All;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_deserialization_type_name_handling" in names

    def test_positive_auto(self):
        code = "settings.TypeNameHandling = TypeNameHandling.Auto;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_deserialization_type_name_handling" in names

    def test_positive_objects(self):
        code = "settings.TypeNameHandling = TypeNameHandling.Objects;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_deserialization_type_name_handling" in names

    def test_negative_none(self):
        code = "settings.TypeNameHandling = TypeNameHandling.None;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_deserialization_type_name_handling" not in names


class TestCSharpJavaScriptSerializer:
    """JavaScriptSerializer detection."""

    def test_positive(self):
        code = "var ser = new JavaScriptSerializer();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_deserialization_javascript_serializer" in names

    def test_negative_json_serializer(self):
        code = "var ser = new JsonSerializer();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_deserialization_javascript_serializer" not in names


# ===================================================================
# 7. XXE patterns
# ===================================================================


class TestCSharpXxeXmlDocument:
    """XXE via XmlDocument."""

    def test_positive(self):
        code = "var doc = new XmlDocument();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_xxe_xml_document" in names

    def test_negative_safe_xml_reader(self):
        code = "var reader = XmlReader.Create(stream, safeSettings);"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_xxe_xml_document" not in names


class TestCSharpXxeDtdProcessing:
    """XXE via DtdProcessing.Parse."""

    def test_positive(self):
        code = "settings.DtdProcessing = DtdProcessing.Parse;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_xxe_dtd_processing_parse" in names

    def test_negative_prohibit(self):
        code = "settings.DtdProcessing = DtdProcessing.Prohibit;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_xxe_dtd_processing_parse" not in names


# ===================================================================
# 8. LDAP Injection
# ===================================================================


class TestCSharpLdapInjection:
    """LDAP injection detection."""

    def test_positive_directory_searcher_concat(self):
        code = 'var searcher = new DirectorySearcher("(cn=" + userInput + ")");'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_ldap_injection" in names

    def test_positive_directory_entry_interpolation(self):
        code = 'var entry = new DirectoryEntry($"LDAP://dc={domain}");'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_ldap_injection" in names

    def test_negative_static_filter(self):
        code = 'var searcher = new DirectorySearcher("(objectClass=user)");'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_ldap_injection" not in names


# ===================================================================
# 9. Weak Cryptography
# ===================================================================


class TestCSharpWeakCrypto:
    """Weak crypto algorithm detection."""

    def test_positive_md5(self):
        code = "var hash = MD5.Create();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_weak_crypto" in names

    def test_positive_sha1(self):
        code = "var hash = SHA1.Create();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_weak_crypto" in names

    def test_positive_des(self):
        code = "var cipher = DES.Create();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_weak_crypto" in names

    def test_positive_triple_des(self):
        code = "var cipher = TripleDES.Create();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_weak_crypto" in names

    def test_negative_sha256(self):
        code = "var hash = SHA256.Create();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_weak_crypto" not in names


class TestCSharpEcbMode:
    """ECB cipher mode detection."""

    def test_positive(self):
        code = "aes.Mode = CipherMode.ECB;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_weak_crypto_ecb_mode" in names

    def test_negative_cbc(self):
        code = "aes.Mode = CipherMode.CBC;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_weak_crypto_ecb_mode" not in names


# ===================================================================
# 10. Hardcoded Connection Strings
# ===================================================================


class TestCSharpHardcodedConnectionString:
    """Hardcoded connection string detection."""

    def test_positive_server_password(self):
        code = 'var conn = new SqlConnection("Server=mydb;Password=secret123;");'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_hardcoded_connection_string" in names

    def test_positive_data_source(self):
        code = (
            'connectionString = "Data Source=server;Initial Catalog=mydb;'
            'User Id=admin;Password=pass;";'
        )
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_hardcoded_connection_string" in names

    def test_negative_config_reference(self):
        code = (
            "var conn = new SqlConnection("
            'Configuration.GetConnectionString("Default"));'
        )
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_hardcoded_connection_string" not in names


# ===================================================================
# 11. Insecure Cookie
# ===================================================================


class TestCSharpInsecureCookieHttpOnly:
    """HttpOnly=false detection."""

    def test_positive(self):
        code = "cookie.HttpOnly = false;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_cookie_httponly" in names

    def test_negative_true(self):
        code = "cookie.HttpOnly = true;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_cookie_httponly" not in names


class TestCSharpInsecureCookieSecure:
    """Secure=false detection."""

    def test_positive(self):
        code = "cookie.Secure = false;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_cookie_secure" in names

    def test_negative_true(self):
        code = "cookie.Secure = true;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_cookie_secure" not in names


# ===================================================================
# 12. CSRF
# ===================================================================


class TestCSharpCsrfIgnore:
    """IgnoreAntiforgeryToken detection."""

    def test_positive(self):
        code = "[IgnoreAntiforgeryToken]"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_csrf_ignore" in names

    def test_negative_validate(self):
        code = "[ValidateAntiForgeryToken]"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_csrf_ignore" not in names


# ===================================================================
# 13. Open Redirect
# ===================================================================


class TestCSharpOpenRedirect:
    """Open redirect detection."""

    def test_positive_request_query(self):
        code = 'return Redirect(Request.Query["returnUrl"]);'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_open_redirect" in names

    def test_positive_request_property(self):
        code = "return Redirect(Request.GetQueryString());"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_open_redirect" in names

    def test_positive_concat(self):
        code = "return Redirect(baseUrl + returnPath);"
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_open_redirect" in names

    def test_negative_static_redirect(self):
        code = 'return Redirect("/home");'
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_open_redirect" not in names


# ===================================================================
# 14. Language auto-detection from file extension
# ===================================================================


class TestCSharpAutoDetection:
    """Language auto-detected from .cs file extension."""

    def test_cs_file_detects_csharp(self):
        code = "var formatter = new BinaryFormatter();"
        findings = scan_code(code, sensitivity="high", file_path="Program.cs")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_deserialization_binary_formatter" in names

    def test_cs_file_does_not_run_python_patterns(self):
        # Python-specific pattern should not fire for .cs files
        code = "hashlib.md5(data)"
        findings = scan_code(code, sensitivity="high", file_path="Program.cs")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "insecure_hash" not in names

    def test_language_param_overrides_extension(self):
        code = "var formatter = new BinaryFormatter();"
        findings = scan_code(
            code, sensitivity="high", file_path="app.py", language="csharp"
        )
        names = [f.metadata["pattern_name"] for f in findings]
        assert "cs_insecure_deserialization_binary_formatter" in names


# ===================================================================
# 15. No cross-contamination
# ===================================================================


class TestCSharpNoCrossContamination:
    """C#-specific patterns don't fire for other languages."""

    def test_csharp_patterns_not_in_python(self):
        code = "\n".join([
            "var formatter = new BinaryFormatter();",
            "settings.TypeNameHandling = TypeNameHandling.All;",
            "var doc = new XmlDocument();",
            "@Html.Raw(content)",
        ])
        findings = scan_code(code, sensitivity="high", language="python")
        cs_names = {p[0] for p in CSHARP_PATTERNS}
        found_names = {f.metadata["pattern_name"] for f in findings}
        assert found_names.isdisjoint(cs_names), (
            f"C# patterns found in Python scan: {found_names & cs_names}"
        )

    def test_csharp_patterns_not_in_javascript(self):
        code = "\n".join([
            "var formatter = new BinaryFormatter();",
            "settings.TypeNameHandling = TypeNameHandling.All;",
            "var doc = new XmlDocument();",
            "@Html.Raw(content)",
        ])
        findings = scan_code(code, sensitivity="high", language="javascript")
        cs_names = {p[0] for p in CSHARP_PATTERNS}
        found_names = {f.metadata["pattern_name"] for f in findings}
        assert found_names.isdisjoint(cs_names), (
            f"C# patterns found in JS scan: {found_names & cs_names}"
        )


# ===================================================================
# 16. Comment skipping
# ===================================================================


class TestCSharpCommentSkipping:
    """C# comments should be skipped."""

    def test_single_line_comment(self):
        code = "// var formatter = new BinaryFormatter();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        assert len(findings) == 0

    def test_block_comment(self):
        code = "/* settings.TypeNameHandling = TypeNameHandling.All; */"
        findings = scan_code(code, sensitivity="high", language="csharp")
        assert len(findings) == 0

    def test_xml_doc_comment(self):
        code = "/// Html.Raw(content)"
        findings = scan_code(code, sensitivity="high", language="csharp")
        assert len(findings) == 0


# ===================================================================
# 17. CWE IDs and metadata
# ===================================================================


class TestCSharpPatternMetadata:
    """C# patterns include correct CWE IDs, severity, and confidence."""

    def test_binary_formatter_cwe(self):
        code = "new BinaryFormatter();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        bf = [
            f
            for f in findings
            if f.metadata["pattern_name"]
            == "cs_insecure_deserialization_binary_formatter"
        ]
        assert len(bf) == 1
        assert "CWE-502" in bf[0].cwe_ids
        assert bf[0].severity == Severity.CRITICAL
        assert bf[0].confidence == 0.95

    def test_xxe_dtd_cwe(self):
        code = "settings.DtdProcessing = DtdProcessing.Parse;"
        findings = scan_code(code, sensitivity="high", language="csharp")
        xxe = [
            f
            for f in findings
            if f.metadata["pattern_name"] == "cs_xxe_dtd_processing_parse"
        ]
        assert len(xxe) == 1
        assert "CWE-611" in xxe[0].cwe_ids

    def test_sql_injection_severity(self):
        code = (
            'var cmd = new SqlCommand("SELECT * FROM x WHERE id=" + id, conn);'
        )
        findings = scan_code(code, sensitivity="high", language="csharp")
        sqli = [
            f
            for f in findings
            if f.metadata["pattern_name"] == "cs_sql_injection_string_concat"
        ]
        assert len(sqli) == 1
        assert sqli[0].severity == Severity.CRITICAL
        assert sqli[0].finding_type == FindingType.SQL_INJECTION

    def test_weak_crypto_cwe(self):
        code = "var hash = MD5.Create();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        wc = [
            f for f in findings if f.metadata["pattern_name"] == "cs_weak_crypto"
        ]
        assert len(wc) == 1
        assert "CWE-327" in wc[0].cwe_ids

    def test_finding_has_range(self):
        code = "var formatter = new BinaryFormatter();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        bf = [
            f
            for f in findings
            if f.metadata["pattern_name"]
            == "cs_insecure_deserialization_binary_formatter"
        ]
        assert len(bf) == 1
        assert bf[0].range is not None
        assert bf[0].range.start_line == 0
        assert bf[0].range.start_col >= 0

    def test_finding_has_remediation(self):
        code = "var formatter = new BinaryFormatter();"
        findings = scan_code(code, sensitivity="high", language="csharp")
        bf = [
            f
            for f in findings
            if f.metadata["pattern_name"]
            == "cs_insecure_deserialization_binary_formatter"
        ]
        assert len(bf) == 1
        assert bf[0].remediation is not None
        assert "BinaryFormatter" in bf[0].remediation.description


# ===================================================================
# 18. Multiple vulnerabilities in one scan
# ===================================================================


class TestCSharpMultipleFindings:
    """Multiple C# vulnerabilities detected in a single scan."""

    def test_multi_vuln_cs_file(self):
        code = "\n".join([
            'var cmd = new SqlCommand("SELECT * FROM users WHERE id=" + userId, conn);',
            'Process.Start("cmd.exe", "/c " + userInput);',
            "@Html.Raw(userContent)",
            "var formatter = new BinaryFormatter();",
            "settings.TypeNameHandling = TypeNameHandling.All;",
            "var doc = new XmlDocument();",
            "var hash = MD5.Create();",
            "cookie.HttpOnly = false;",
            "cookie.Secure = false;",
            "[IgnoreAntiforgeryToken]",
            'return Redirect(Request.Query["url"]);',
        ])
        findings = scan_code(code, sensitivity="high", language="csharp")
        names = {f.metadata["pattern_name"] for f in findings}
        assert "cs_sql_injection_string_concat" in names
        assert "cs_command_injection_process_start" in names
        assert "cs_xss_html_raw" in names
        assert "cs_insecure_deserialization_binary_formatter" in names
        assert "cs_insecure_deserialization_type_name_handling" in names
        assert "cs_xxe_xml_document" in names
        assert "cs_weak_crypto" in names
        assert "cs_insecure_cookie_httponly" in names
        assert "cs_insecure_cookie_secure" in names
        assert "cs_csrf_ignore" in names
        assert "cs_open_redirect" in names

    def test_line_numbers_correct(self):
        code = "\n".join([
            "var x = 1;",
            "var formatter = new BinaryFormatter();",
            "var y = 2;",
        ])
        findings = scan_code(code, sensitivity="high", language="csharp")
        bf = [
            f
            for f in findings
            if f.metadata["pattern_name"]
            == "cs_insecure_deserialization_binary_formatter"
        ]
        assert len(bf) == 1
        assert bf[0].line_number == 2


# ===================================================================
# 19. Clean C# code -- no false positives
# ===================================================================


class TestCleanCSharpCode:
    """Clean C# code should produce minimal false positives."""

    def test_clean_aspnet_controller(self):
        code = "\n".join([
            "using Microsoft.AspNetCore.Mvc;",
            "",
            "[ApiController]",
            '[Route("api/[controller]")]',
            "public class UsersController : ControllerBase",
            "{",
            "    [HttpGet]",
            "    public IActionResult Get()",
            "    {",
            '        return Ok(new { message = "Hello" });',
            "    }",
            "}",
        ])
        findings = scan_code(code, sensitivity="high", language="csharp")
        cs_findings = [
            f for f in findings if f.metadata["pattern_name"].startswith("cs_")
        ]
        assert len(cs_findings) == 0

    def test_safe_sql_parameterized(self):
        code = "\n".join([
            'var cmd = new SqlCommand("SELECT * FROM users WHERE id=@id", conn);',
            'cmd.Parameters.AddWithValue("@id", userId);',
            "var reader = cmd.ExecuteReader();",
        ])
        findings = scan_code(code, sensitivity="high", language="csharp")
        sqli = [
            f
            for f in findings
            if "sql_injection" in f.metadata["pattern_name"]
        ]
        assert len(sqli) == 0
