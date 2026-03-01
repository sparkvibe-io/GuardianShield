"""Java security vulnerability patterns for enterprise SaaS applications."""

from __future__ import annotations

import re
from typing import Any

from guardianshield.findings import FindingType, Severity

# Each entry: (name, compiled_regex, finding_type, severity, description,
#              confidence, cwe_ids)
JAVA_PATTERNS: list[
    tuple[str, re.Pattern[str], FindingType, Severity, str, float, list[str]]
] = [
    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------
    (
        "java_sql_injection_string_concat",
        re.compile(
            r"""(?:execute(?:Query|Update)?|prepareStatement)\s*\(\s*["'].*?["']\s*\+""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via string concatenation in JDBC query.",
        0.9,
        ["CWE-89"],
    ),
    (
        "java_sql_injection_statement_execute",
        re.compile(
            r"""(?:Statement|createStatement)\s*\(\s*\)[\s\S]*?\.execute(?:Query|Update)?\s*\(\s*\w+\s*\+""",
            re.IGNORECASE | re.MULTILINE,
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via Statement with string concatenation.",
        0.85,
        ["CWE-89"],
    ),
    # ------------------------------------------------------------------
    # Command Injection
    # ------------------------------------------------------------------
    (
        "java_command_injection_runtime_exec",
        re.compile(
            r"""Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(""",
        ),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Command injection risk via Runtime.exec().",
        0.85,
        ["CWE-78"],
    ),
    (
        "java_command_injection_process_builder",
        re.compile(
            r"""new\s+ProcessBuilder\s*\(""",
        ),
        FindingType.COMMAND_INJECTION,
        Severity.MEDIUM,
        "Potential command injection via ProcessBuilder. Ensure arguments are not user-controlled.",
        0.6,
        ["CWE-78"],
    ),
    # ------------------------------------------------------------------
    # Path Traversal
    # ------------------------------------------------------------------
    (
        "java_path_traversal_file_constructor",
        re.compile(
            r"""new\s+File\s*\(.*(?:request|param|input|user|getParameter|getHeader)\b""",
            re.IGNORECASE,
        ),
        FindingType.PATH_TRAVERSAL,
        Severity.HIGH,
        "Path traversal risk via File constructor with user-controlled input.",
        0.7,
        ["CWE-22"],
    ),
    # ------------------------------------------------------------------
    # XXE (XML External Entity)
    # ------------------------------------------------------------------
    (
        "java_xxe_document_builder",
        re.compile(
            r"""DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.HIGH,
        "Potential XXE vulnerability. DocumentBuilderFactory defaults allow external entities.",
        0.7,
        ["CWE-611"],
    ),
    (
        "java_xxe_sax_parser",
        re.compile(
            r"""SAXParserFactory\s*\.\s*newInstance\s*\(\s*\)""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.HIGH,
        "Potential XXE vulnerability via SAXParserFactory without secure configuration.",
        0.7,
        ["CWE-611"],
    ),
    (
        "java_xxe_xmlinputfactory",
        re.compile(
            r"""XMLInputFactory\s*\.\s*newInstance\s*\(\s*\)""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.HIGH,
        "Potential XXE vulnerability via XMLInputFactory without secure configuration.",
        0.7,
        ["CWE-611"],
    ),
    # ------------------------------------------------------------------
    # Insecure Deserialization
    # ------------------------------------------------------------------
    (
        "java_insecure_deserialization",
        re.compile(
            r"""(?:ObjectInputStream|readObject|readUnshared)\s*\(""",
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.CRITICAL,
        "Insecure deserialization via ObjectInputStream can lead to remote code execution.",
        0.85,
        ["CWE-502"],
    ),
    # ------------------------------------------------------------------
    # SSRF (Server-Side Request Forgery)
    # ------------------------------------------------------------------
    (
        "java_ssrf_url_connection",
        re.compile(
            r"""new\s+URL\s*\(.*(?:request|param|input|user|getParameter|getHeader)\b""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_PATTERN,
        Severity.HIGH,
        "Potential SSRF via URL constructed from user-controlled input.",
        0.7,
        ["CWE-918"],
    ),
    # ------------------------------------------------------------------
    # LDAP Injection
    # ------------------------------------------------------------------
    (
        "java_ldap_injection",
        re.compile(
            r"""(?:search|lookup)\s*\(.*["']\s*\+\s*(?:request|param|input|user|getParameter)""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.HIGH,
        "Potential LDAP injection via unsanitized user input in search filter.",
        0.75,
        ["CWE-90"],
    ),
    # ------------------------------------------------------------------
    # XSS (Cross-Site Scripting)
    # ------------------------------------------------------------------
    (
        "java_xss_response_writer",
        re.compile(
            r"""(?:getWriter|getOutputStream)\s*\(\s*\)\s*\.\s*(?:print(?:ln)?|write)\s*\(.*(?:request|param|getParameter|getHeader)\b""",
            re.IGNORECASE,
        ),
        FindingType.XSS,
        Severity.HIGH,
        "Potential XSS via unsanitized user input written directly to HTTP response.",
        0.8,
        ["CWE-79"],
    ),
    # ------------------------------------------------------------------
    # Weak Cryptography
    # ------------------------------------------------------------------
    (
        "java_weak_crypto_md5_sha1",
        re.compile(
            r"""MessageDigest\s*\.\s*getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']\s*\)""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.LOW,
        "Use of weak hash algorithm (MD5/SHA-1) unsuitable for security purposes.",
        0.7,
        ["CWE-328"],
    ),
    (
        "java_weak_crypto_des_ecb",
        re.compile(
            r"""Cipher\s*\.\s*getInstance\s*\(\s*["'](?:DES(?:/[^"']*)?|[^"']*/ECB(?:/[^"']*)?)["']\s*\)""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.HIGH,
        "Use of weak cipher (DES) or insecure block mode (ECB).",
        0.85,
        ["CWE-327"],
    ),
    # ------------------------------------------------------------------
    # Log Injection
    # ------------------------------------------------------------------
    (
        "java_log_injection",
        re.compile(
            r"""(?:log(?:ger)?|LOG)\s*\.\s*(?:info|warn|error|debug|trace|fatal)\s*\(.*(?:request|param|getParameter|getHeader|input)\b""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_PATTERN,
        Severity.MEDIUM,
        "Potential log injection via unsanitized user input in log statement.",
        0.6,
        ["CWE-117"],
    ),
    # ------------------------------------------------------------------
    # Insecure Random
    # ------------------------------------------------------------------
    (
        "java_insecure_random",
        re.compile(
            r"""new\s+(?:java\.util\.)?Random\s*\(""",
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.MEDIUM,
        "Use of java.util.Random for security-sensitive operations. Use SecureRandom instead.",
        0.5,
        ["CWE-330"],
    ),
    # ------------------------------------------------------------------
    # Hardcoded Secrets
    # ------------------------------------------------------------------
    (
        "java_hardcoded_password",
        re.compile(
            r"""(?:password|passwd|pwd|secret|apiKey|api_key)\s*=\s*["'][^"']{4,}["']""",
            re.IGNORECASE,
        ),
        FindingType.SECRET,
        Severity.HIGH,
        "Potential hardcoded password or secret in source code.",
        0.7,
        ["CWE-798"],
    ),
]

# Remediation guidance keyed by pattern name.
JAVA_REMEDIATION: dict[str, dict[str, Any]] = {
    "java_sql_injection_string_concat": {
        "description": "Use PreparedStatement with parameterized queries.",
        "before": 'stmt.executeQuery("SELECT * FROM users WHERE id=" + userId)',
        "after": 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?"); ps.setString(1, userId);',
        "auto_fixable": False,
    },
    "java_sql_injection_statement_execute": {
        "description": "Replace Statement with PreparedStatement using parameterized queries.",
        "before": 'Statement stmt = conn.createStatement(); stmt.executeQuery(query + userInput);',
        "after": 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?"); ps.setString(1, userInput);',
        "auto_fixable": False,
    },
    "java_command_injection_runtime_exec": {
        "description": "Use ProcessBuilder with a command list instead of Runtime.exec() with a single string.",
        "before": 'Runtime.getRuntime().exec("cmd " + userInput)',
        "after": 'new ProcessBuilder(Arrays.asList("cmd", sanitizedInput)).start()',
        "auto_fixable": False,
    },
    "java_command_injection_process_builder": {
        "description": "Validate and sanitize all arguments passed to ProcessBuilder.",
        "before": "new ProcessBuilder(userCmd).start()",
        "after": 'new ProcessBuilder(Arrays.asList(allowedCommand, sanitizedArg)).start()',
        "auto_fixable": False,
    },
    "java_path_traversal_file_constructor": {
        "description": "Validate and canonicalize file paths. Ensure they stay within the allowed directory.",
        "before": 'new File(baseDir, request.getParameter("file"))',
        "after": 'File f = new File(baseDir, param).getCanonicalFile(); if (!f.toPath().startsWith(baseDir)) throw new SecurityException();',
        "auto_fixable": False,
    },
    "java_xxe_document_builder": {
        "description": "Disable external entities and DTDs on DocumentBuilderFactory.",
        "before": "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();",
        "after": 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
        "auto_fixable": False,
    },
    "java_xxe_sax_parser": {
        "description": "Disable external entities and DTDs on SAXParserFactory.",
        "before": "SAXParserFactory spf = SAXParserFactory.newInstance();",
        "after": 'SAXParserFactory spf = SAXParserFactory.newInstance(); spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
        "auto_fixable": False,
    },
    "java_xxe_xmlinputfactory": {
        "description": "Disable external entities on XMLInputFactory.",
        "before": "XMLInputFactory xif = XMLInputFactory.newInstance();",
        "after": "XMLInputFactory xif = XMLInputFactory.newInstance(); xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);",
        "auto_fixable": False,
    },
    "java_insecure_deserialization": {
        "description": "Avoid deserializing untrusted data. Use allowlists or safe serialization formats (JSON).",
        "before": "ObjectInputStream ois = new ObjectInputStream(input); Object obj = ois.readObject();",
        "after": "ObjectMapper mapper = new ObjectMapper(); MyClass obj = mapper.readValue(input, MyClass.class);",
        "auto_fixable": False,
    },
    "java_ssrf_url_connection": {
        "description": "Validate and allowlist URLs before making requests.",
        "before": 'URL url = new URL(request.getParameter("url"));',
        "after": 'String target = request.getParameter("url"); if (!ALLOWED_HOSTS.contains(new URL(target).getHost())) throw new SecurityException();',
        "auto_fixable": False,
    },
    "java_ldap_injection": {
        "description": "Use parameterized LDAP queries or sanitize special characters.",
        "before": 'ctx.search("ou=users", "uid=" + userInput, constraints)',
        "after": 'String safe = LdapEncoder.filterEncode(userInput); ctx.search("ou=users", "uid=" + safe, constraints)',
        "auto_fixable": False,
    },
    "java_xss_response_writer": {
        "description": "Encode output before writing to HTTP response.",
        "before": 'response.getWriter().println(request.getParameter("name"))',
        "after": 'response.getWriter().println(HtmlUtils.htmlEscape(request.getParameter("name")))',
        "auto_fixable": False,
    },
    "java_weak_crypto_md5_sha1": {
        "description": "Use SHA-256 or stronger hash algorithms.",
        "before": 'MessageDigest.getInstance("MD5")',
        "after": 'MessageDigest.getInstance("SHA-256")',
        "auto_fixable": True,
    },
    "java_weak_crypto_des_ecb": {
        "description": "Use AES with GCM or CBC mode instead of DES or ECB.",
        "before": 'Cipher.getInstance("DES/ECB/PKCS5Padding")',
        "after": 'Cipher.getInstance("AES/GCM/NoPadding")',
        "auto_fixable": False,
    },
    "java_log_injection": {
        "description": "Sanitize user input before logging to prevent log forging.",
        "before": 'logger.info("User login: " + request.getParameter("user"))',
        "after": 'logger.info("User login: {}", sanitize(request.getParameter("user")))',
        "auto_fixable": False,
    },
    "java_insecure_random": {
        "description": "Use java.security.SecureRandom for security-sensitive operations.",
        "before": "Random rand = new Random();",
        "after": "SecureRandom rand = new SecureRandom();",
        "auto_fixable": True,
    },
    "java_hardcoded_password": {
        "description": "Store secrets in environment variables or a secrets manager.",
        "before": 'String password = "SuperSecret123";',
        "after": 'String password = System.getenv("DB_PASSWORD");',
        "auto_fixable": False,
    },
}
