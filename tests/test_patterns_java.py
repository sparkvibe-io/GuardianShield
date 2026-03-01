"""Tests for Java security vulnerability patterns."""

from guardianshield.findings import FindingType, Severity
from guardianshield.patterns import EXTENSION_MAP, JAVA_PATTERNS, LANGUAGE_PATTERNS
from guardianshield.scanner import scan_code

# ===================================================================
# 1. Import / Structure tests
# ===================================================================


class TestJavaPatternImports:
    """Java pattern module has expected structure."""

    def test_java_patterns_importable(self):
        assert isinstance(JAVA_PATTERNS, list)
        assert len(JAVA_PATTERNS) == 17

    def test_java_in_language_patterns(self):
        assert "java" in LANGUAGE_PATTERNS
        assert LANGUAGE_PATTERNS["java"] is JAVA_PATTERNS

    def test_java_extension_mapping(self):
        assert ".java" in EXTENSION_MAP
        assert EXTENSION_MAP[".java"] == "java"

    def test_pattern_tuple_has_seven_elements(self):
        for p in JAVA_PATTERNS:
            assert len(p) == 7, f"Pattern {p[0]} has {len(p)} elements, expected 7"


# ===================================================================
# 2. SQL Injection patterns
# ===================================================================


class TestJavaSqlInjection:
    """SQL injection detection in Java code."""

    def test_positive_execute_query_concat(self):
        code = 'stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_sql_injection_string_concat" in names

    def test_positive_execute_update_concat(self):
        code = 'stmt.executeUpdate("DELETE FROM sessions WHERE token=" + token);'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_sql_injection_string_concat" in names

    def test_positive_prepare_statement_concat(self):
        code = 'conn.prepareStatement("SELECT * FROM users WHERE name=" + name);'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_sql_injection_string_concat" in names

    def test_negative_parameterized_query(self):
        code = 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_sql_injection_string_concat" not in names

    def test_severity_is_critical(self):
        code = 'stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);'
        findings = scan_code(code, sensitivity="high", language="java")
        sqli = [f for f in findings if f.metadata["pattern_name"] == "java_sql_injection_string_concat"]
        assert sqli[0].severity == Severity.CRITICAL
        assert sqli[0].finding_type == FindingType.SQL_INJECTION


# ===================================================================
# 3. Command Injection patterns
# ===================================================================


class TestJavaCommandInjection:
    """Command injection detection in Java code."""

    def test_positive_runtime_exec(self):
        code = 'Runtime.getRuntime().exec("cmd " + userInput);'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_command_injection_runtime_exec" in names

    def test_positive_process_builder(self):
        code = "new ProcessBuilder(cmd).start();"
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_command_injection_process_builder" in names

    def test_negative_no_runtime_exec(self):
        code = 'String result = "Runtime info";'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_command_injection_runtime_exec" not in names

    def test_runtime_exec_severity(self):
        code = 'Runtime.getRuntime().exec("ls -la");'
        findings = scan_code(code, sensitivity="high", language="java")
        rt = [f for f in findings if f.metadata["pattern_name"] == "java_command_injection_runtime_exec"]
        assert rt[0].severity == Severity.HIGH
        assert rt[0].finding_type == FindingType.COMMAND_INJECTION


# ===================================================================
# 4. Path Traversal patterns
# ===================================================================


class TestJavaPathTraversal:
    """Path traversal detection in Java code."""

    def test_positive_file_with_request_param(self):
        code = 'new File(baseDir, request.getParameter("file"));'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_path_traversal_file_constructor" in names

    def test_positive_file_with_user_input(self):
        code = 'new File(uploadDir, userInput);'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_path_traversal_file_constructor" in names

    def test_negative_static_file_path(self):
        code = 'new File("/etc/config.properties");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_path_traversal_file_constructor" not in names


# ===================================================================
# 5. XXE patterns
# ===================================================================


class TestJavaXxe:
    """XXE vulnerability detection in Java code."""

    def test_positive_document_builder_factory(self):
        code = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();"
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_xxe_document_builder" in names

    def test_positive_sax_parser_factory(self):
        code = "SAXParserFactory spf = SAXParserFactory.newInstance();"
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_xxe_sax_parser" in names

    def test_positive_xmlinputfactory(self):
        code = "XMLInputFactory xif = XMLInputFactory.newInstance();"
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_xxe_xmlinputfactory" in names

    def test_xxe_severity_and_cwe(self):
        code = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();"
        findings = scan_code(code, sensitivity="high", language="java")
        xxe = [f for f in findings if f.metadata["pattern_name"] == "java_xxe_document_builder"]
        assert xxe[0].severity == Severity.HIGH
        assert "CWE-611" in xxe[0].cwe_ids
        assert xxe[0].finding_type == FindingType.INSECURE_PATTERN


# ===================================================================
# 6. Insecure Deserialization patterns
# ===================================================================


class TestJavaInsecureDeserialization:
    """Insecure deserialization detection in Java code."""

    def test_positive_object_input_stream(self):
        code = "ObjectInputStream ois = new ObjectInputStream(input);"
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_insecure_deserialization" in names

    def test_positive_read_object(self):
        code = "Object obj = ois.readObject();"
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_insecure_deserialization" in names

    def test_positive_read_unshared(self):
        code = "Object obj = ois.readUnshared();"
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_insecure_deserialization" in names

    def test_severity_is_critical(self):
        code = "ObjectInputStream ois = new ObjectInputStream(input);"
        findings = scan_code(code, sensitivity="high", language="java")
        deser = [f for f in findings if f.metadata["pattern_name"] == "java_insecure_deserialization"]
        assert deser[0].severity == Severity.CRITICAL
        assert "CWE-502" in deser[0].cwe_ids

    def test_negative_json_parse(self):
        code = 'ObjectMapper mapper = new ObjectMapper(); User u = mapper.readValue(json, User.class);'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_insecure_deserialization" not in names


# ===================================================================
# 7. SSRF patterns
# ===================================================================


class TestJavaSsrf:
    """SSRF detection in Java code."""

    def test_positive_url_with_request_param(self):
        code = 'URL url = new URL(request.getParameter("target"));'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_ssrf_url_connection" in names

    def test_positive_url_with_user_input(self):
        code = "URL url = new URL(userInput);"
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_ssrf_url_connection" in names

    def test_negative_static_url(self):
        code = 'URL url = new URL("https://api.example.com/data");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_ssrf_url_connection" not in names

    def test_ssrf_cwe(self):
        code = 'URL url = new URL(request.getParameter("url"));'
        findings = scan_code(code, sensitivity="high", language="java")
        ssrf = [f for f in findings if f.metadata["pattern_name"] == "java_ssrf_url_connection"]
        assert "CWE-918" in ssrf[0].cwe_ids


# ===================================================================
# 8. LDAP Injection patterns
# ===================================================================


class TestJavaLdapInjection:
    """LDAP injection detection in Java code."""

    def test_positive_search_with_user_input(self):
        code = 'ctx.search("ou=users", "uid=" + userInput, constraints);'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_ldap_injection" in names

    def test_positive_lookup_with_param(self):
        code = 'ctx.lookup("cn=" + request.getParameter("name"));'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_ldap_injection" in names

    def test_negative_static_search(self):
        code = 'ctx.search("ou=users", "uid=admin", constraints);'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_ldap_injection" not in names


# ===================================================================
# 9. XSS patterns
# ===================================================================


class TestJavaXss:
    """XSS detection in Java code."""

    def test_positive_getwriter_with_param(self):
        code = 'response.getWriter().println(request.getParameter("name"));'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_xss_response_writer" in names

    def test_positive_getoutputstream_with_header(self):
        code = 'response.getOutputStream().write(request.getHeader("Referer").getBytes());'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_xss_response_writer" in names

    def test_negative_static_response(self):
        code = 'response.getWriter().println("Hello World");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_xss_response_writer" not in names

    def test_xss_cwe(self):
        code = 'response.getWriter().println(request.getParameter("q"));'
        findings = scan_code(code, sensitivity="high", language="java")
        xss = [f for f in findings if f.metadata["pattern_name"] == "java_xss_response_writer"]
        assert xss[0].severity == Severity.HIGH
        assert "CWE-79" in xss[0].cwe_ids
        assert xss[0].finding_type == FindingType.XSS


# ===================================================================
# 10. Weak Cryptography patterns
# ===================================================================


class TestJavaWeakCrypto:
    """Weak cryptography detection in Java code."""

    def test_positive_md5(self):
        code = 'MessageDigest md = MessageDigest.getInstance("MD5");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_weak_crypto_md5_sha1" in names

    def test_positive_sha1(self):
        code = 'MessageDigest md = MessageDigest.getInstance("SHA-1");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_weak_crypto_md5_sha1" in names

    def test_positive_sha1_no_hyphen(self):
        code = 'MessageDigest md = MessageDigest.getInstance("SHA1");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_weak_crypto_md5_sha1" in names

    def test_negative_sha256(self):
        code = 'MessageDigest md = MessageDigest.getInstance("SHA-256");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_weak_crypto_md5_sha1" not in names

    def test_positive_des(self):
        code = 'Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_weak_crypto_des_ecb" in names

    def test_positive_ecb_mode(self):
        code = 'Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_weak_crypto_des_ecb" in names

    def test_negative_aes_gcm(self):
        code = 'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_weak_crypto_des_ecb" not in names

    def test_md5_severity(self):
        code = 'MessageDigest.getInstance("MD5");'
        findings = scan_code(code, sensitivity="high", language="java")
        md5 = [f for f in findings if f.metadata["pattern_name"] == "java_weak_crypto_md5_sha1"]
        assert md5[0].severity == Severity.LOW
        assert "CWE-328" in md5[0].cwe_ids

    def test_des_severity(self):
        code = 'Cipher.getInstance("DES");'
        findings = scan_code(code, sensitivity="high", language="java")
        des = [f for f in findings if f.metadata["pattern_name"] == "java_weak_crypto_des_ecb"]
        assert des[0].severity == Severity.HIGH
        assert "CWE-327" in des[0].cwe_ids


# ===================================================================
# 11. Log Injection patterns
# ===================================================================


class TestJavaLogInjection:
    """Log injection detection in Java code."""

    def test_positive_logger_info_with_param(self):
        code = 'logger.info("User login: " + request.getParameter("user"));'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_log_injection" in names

    def test_positive_log_error_with_input(self):
        code = 'LOG.error("Failed: " + userInput);'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_log_injection" in names

    def test_negative_static_log(self):
        code = 'logger.info("Application started successfully");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_log_injection" not in names

    def test_log_injection_cwe(self):
        code = 'logger.warn("Bad input: " + request.getParameter("q"));'
        findings = scan_code(code, sensitivity="high", language="java")
        log = [f for f in findings if f.metadata["pattern_name"] == "java_log_injection"]
        assert "CWE-117" in log[0].cwe_ids
        assert log[0].severity == Severity.MEDIUM


# ===================================================================
# 12. Insecure Random patterns
# ===================================================================


class TestJavaInsecureRandom:
    """Insecure random detection in Java code."""

    def test_positive_new_random(self):
        code = "Random rand = new Random();"
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_insecure_random" in names

    def test_positive_fully_qualified(self):
        code = "java.util.Random rand = new java.util.Random();"
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_insecure_random" in names

    def test_negative_secure_random(self):
        code = "SecureRandom rand = new SecureRandom();"
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_insecure_random" not in names

    def test_insecure_random_cwe(self):
        code = "Random r = new Random();"
        findings = scan_code(code, sensitivity="high", language="java")
        rnd = [f for f in findings if f.metadata["pattern_name"] == "java_insecure_random"]
        assert "CWE-330" in rnd[0].cwe_ids
        assert rnd[0].severity == Severity.MEDIUM


# ===================================================================
# 13. Hardcoded Secrets patterns
# ===================================================================


class TestJavaHardcodedSecrets:
    """Hardcoded secret detection in Java code."""

    def test_positive_hardcoded_password(self):
        code = 'String password = "SuperSecret123";'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_hardcoded_password" in names

    def test_positive_api_key(self):
        code = 'String apiKey = "sk-1234567890abcdef";'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_hardcoded_password" in names

    def test_negative_env_var(self):
        code = 'String password = System.getenv("DB_PASSWORD");'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_hardcoded_password" not in names

    def test_negative_short_value(self):
        code = 'String pwd = "ab";'
        findings = scan_code(code, sensitivity="high", language="java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_hardcoded_password" not in names

    def test_hardcoded_cwe(self):
        code = 'String secret = "mySecretValue123";'
        findings = scan_code(code, sensitivity="high", language="java")
        sec = [f for f in findings if f.metadata["pattern_name"] == "java_hardcoded_password"]
        assert "CWE-798" in sec[0].cwe_ids
        assert sec[0].finding_type == FindingType.SECRET


# ===================================================================
# 14. Language auto-detection from file_path
# ===================================================================


class TestJavaLanguageAutoDetection:
    """Java language is auto-detected from .java file extension."""

    def test_java_file_detects_java(self):
        code = 'Runtime.getRuntime().exec("cmd");'
        findings = scan_code(code, sensitivity="high", file_path="App.java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_command_injection_runtime_exec" in names

    def test_java_file_xxe_detection(self):
        code = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();"
        findings = scan_code(code, sensitivity="high", file_path="XmlParser.java")
        names = [f.metadata["pattern_name"] for f in findings]
        assert "java_xxe_document_builder" in names


# ===================================================================
# 15. No cross-contamination
# ===================================================================


class TestJavaNoCrossContamination:
    """Java-specific patterns don't fire for other languages."""

    def test_java_patterns_not_in_python(self):
        code = "\n".join([
            'Runtime.getRuntime().exec("ls");',
            "DocumentBuilderFactory.newInstance();",
            "new Random();",
            'MessageDigest.getInstance("MD5");',
        ])
        findings = scan_code(code, sensitivity="high", language="python")
        java_names = {
            "java_command_injection_runtime_exec",
            "java_xxe_document_builder",
            "java_insecure_random",
            "java_weak_crypto_md5_sha1",
        }
        found_names = {f.metadata["pattern_name"] for f in findings}
        assert found_names.isdisjoint(java_names), (
            f"Java patterns found in Python scan: {found_names & java_names}"
        )

    def test_java_patterns_not_in_javascript(self):
        code = "\n".join([
            'Runtime.getRuntime().exec("ls");',
            "DocumentBuilderFactory.newInstance();",
            "ObjectInputStream ois = new ObjectInputStream(input);",
        ])
        findings = scan_code(code, sensitivity="high", language="javascript")
        java_names = {
            "java_command_injection_runtime_exec",
            "java_xxe_document_builder",
            "java_insecure_deserialization",
        }
        found_names = {f.metadata["pattern_name"] for f in findings}
        assert found_names.isdisjoint(java_names), (
            f"Java patterns found in JS scan: {found_names & java_names}"
        )


# ===================================================================
# 16. Comment skipping for Java
# ===================================================================


class TestJavaCommentSkipping:
    """Java comments should be skipped."""

    def test_single_line_comment(self):
        code = '// Runtime.getRuntime().exec("cmd");'
        findings = scan_code(code, sensitivity="high", language="java")
        assert len(findings) == 0

    def test_block_comment(self):
        code = '/* DocumentBuilderFactory.newInstance(); */'
        findings = scan_code(code, sensitivity="high", language="java")
        assert len(findings) == 0

    def test_star_continuation(self):
        code = '* ObjectInputStream ois = new ObjectInputStream(input);'
        findings = scan_code(code, sensitivity="high", language="java")
        assert len(findings) == 0


# ===================================================================
# 17. Multiple findings in one scan
# ===================================================================


class TestMultipleJavaFindings:
    """Multiple Java vulnerabilities detected in a single scan."""

    def test_multi_vuln_java_file(self):
        code = "\n".join([
            'stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);',
            'Runtime.getRuntime().exec("cmd " + input);',
            "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();",
            "ObjectInputStream ois = new ObjectInputStream(stream);",
            'MessageDigest md = MessageDigest.getInstance("MD5");',
            "Random r = new Random();",
        ])
        findings = scan_code(code, sensitivity="high", language="java")
        names = {f.metadata["pattern_name"] for f in findings}
        assert "java_sql_injection_string_concat" in names
        assert "java_command_injection_runtime_exec" in names
        assert "java_xxe_document_builder" in names
        assert "java_insecure_deserialization" in names
        assert "java_weak_crypto_md5_sha1" in names
        assert "java_insecure_random" in names

    def test_line_numbers_correct(self):
        code = "\n".join([
            "public class App {",
            '    Runtime.getRuntime().exec("ls");',
            "    int x = 1;",
        ])
        findings = scan_code(code, sensitivity="high", language="java")
        rt = [f for f in findings if f.metadata["pattern_name"] == "java_command_injection_runtime_exec"]
        assert len(rt) == 1
        assert rt[0].line_number == 2


# ===================================================================
# 18. Clean Java code -- no false positives
# ===================================================================


class TestCleanJavaCode:
    """Clean Java code should produce no (or minimal) findings."""

    def test_clean_spring_controller(self):
        code = "\n".join([
            "import org.springframework.web.bind.annotation.*;",
            "",
            "@RestController",
            "public class UserController {",
            '    @GetMapping("/users/{id}")',
            "    public User getUser(@PathVariable Long id) {",
            "        return userService.findById(id);",
            "    }",
            "}",
        ])
        findings = scan_code(code, sensitivity="high", language="java")
        java_pattern_names = {f.metadata["pattern_name"] for f in findings}
        # Should not trigger any Java-specific vulnerability patterns
        assert not any(n.startswith("java_") for n in java_pattern_names)


# ===================================================================
# 19. Remediation metadata
# ===================================================================


class TestJavaRemediation:
    """Java patterns include remediation guidance."""

    def test_sql_injection_has_remediation(self):
        code = 'stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);'
        findings = scan_code(code, sensitivity="high", language="java")
        sqli = [f for f in findings if f.metadata["pattern_name"] == "java_sql_injection_string_concat"]
        assert sqli[0].remediation is not None
        assert "PreparedStatement" in sqli[0].remediation.description

    def test_xxe_has_remediation(self):
        code = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();"
        findings = scan_code(code, sensitivity="high", language="java")
        xxe = [f for f in findings if f.metadata["pattern_name"] == "java_xxe_document_builder"]
        assert xxe[0].remediation is not None
        assert "external entities" in xxe[0].remediation.description.lower()

    def test_deserialization_has_remediation(self):
        code = "ObjectInputStream ois = new ObjectInputStream(input);"
        findings = scan_code(code, sensitivity="high", language="java")
        deser = [f for f in findings if f.metadata["pattern_name"] == "java_insecure_deserialization"]
        assert deser[0].remediation is not None

    def test_weak_crypto_auto_fixable(self):
        code = 'MessageDigest.getInstance("MD5");'
        findings = scan_code(code, sensitivity="high", language="java")
        md5 = [f for f in findings if f.metadata["pattern_name"] == "java_weak_crypto_md5_sha1"]
        assert md5[0].remediation is not None
        assert md5[0].remediation.auto_fixable is True


# ===================================================================
# 20. Range and confidence metadata
# ===================================================================


class TestJavaPatternMetadata:
    """Java patterns include proper range and confidence metadata."""

    def test_has_range(self):
        code = 'Runtime.getRuntime().exec("cmd");'
        findings = scan_code(code, sensitivity="high", language="java")
        rt = [f for f in findings if f.metadata["pattern_name"] == "java_command_injection_runtime_exec"]
        assert rt[0].range is not None
        assert rt[0].range.start_line == 0
        assert rt[0].range.start_col >= 0

    def test_has_confidence(self):
        code = "DocumentBuilderFactory.newInstance();"
        findings = scan_code(code, sensitivity="high", language="java")
        xxe = [f for f in findings if f.metadata["pattern_name"] == "java_xxe_document_builder"]
        assert xxe[0].confidence is not None
        assert xxe[0].confidence > 0.0

    def test_has_cwe_ids(self):
        code = "ObjectInputStream ois = new ObjectInputStream(input);"
        findings = scan_code(code, sensitivity="high", language="java")
        deser = [f for f in findings if f.metadata["pattern_name"] == "java_insecure_deserialization"]
        assert len(deser[0].cwe_ids) > 0
