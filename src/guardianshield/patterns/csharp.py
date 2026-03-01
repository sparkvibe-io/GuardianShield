"""C# / ASP.NET vulnerability patterns."""

from __future__ import annotations

import re
from typing import Any

from guardianshield.findings import FindingType, Severity

# Each entry: (name, compiled_regex, finding_type, severity, description,
#              confidence, cwe_ids)
CSHARP_PATTERNS: list[
    tuple[str, re.Pattern[str], FindingType, Severity, str, float, list[str]]
] = [
    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------
    (
        "cs_sql_injection_string_concat",
        re.compile(
            r"""(?:SqlCommand|SqlDataAdapter|OleDbCommand|OdbcCommand)\s*\("""
            r"""[^)]*["']\s*\+""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via string concatenation in SqlCommand constructor.",
        0.9,
        ["CWE-89"],
    ),
    (
        "cs_sql_injection_string_format",
        re.compile(
            r"""(?:CommandText|SqlCommand|SqlDataAdapter)\s*[=(]\s*"""
            r"""(?:string\.Format\s*\(|"""
            r"""\$\s*["'])""",
            re.IGNORECASE,
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via string interpolation or String.Format in SQL command.",
        0.85,
        ["CWE-89"],
    ),
    (
        "cs_sql_injection_execute_concat",
        re.compile(
            r"""\.(?:ExecuteReader|ExecuteNonQuery|ExecuteScalar)\s*\([^)]*"""
            r"""["']\s*\+""",
        ),
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL injection via string concatenation passed to Execute method.",
        0.9,
        ["CWE-89"],
    ),
    # ------------------------------------------------------------------
    # Command Injection
    # ------------------------------------------------------------------
    (
        "cs_command_injection_process_start",
        re.compile(
            r"""Process\.Start\s*\([^)]*(?:\+|\$["']|string\.Format)""",
            re.IGNORECASE,
        ),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Command injection risk via Process.Start with dynamic arguments.",
        0.8,
        ["CWE-78"],
    ),
    (
        "cs_command_injection_process_filename",
        re.compile(
            r"""\.(?:FileName|Arguments)\s*=\s*(?:\w+\s*\+|\$["']|string\.Format)""",
        ),
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        "Command injection risk via dynamic ProcessStartInfo.FileName or Arguments.",
        0.75,
        ["CWE-78"],
    ),
    # ------------------------------------------------------------------
    # Path Traversal
    # ------------------------------------------------------------------
    (
        "cs_path_traversal",
        re.compile(
            r"""(?:Path\.Combine|File\.(?:ReadAllText|ReadAllBytes|WriteAllText|"""
            r"""WriteAllBytes|Open|Copy|Move|Delete)|"""
            r"""Directory\.(?:GetFiles|GetDirectories|Delete))\s*\([^)]*(?:\+|\$["'])""",
        ),
        FindingType.PATH_TRAVERSAL,
        Severity.HIGH,
        "Path traversal risk via file/directory operation with dynamic path.",
        0.7,
        ["CWE-22"],
    ),
    # ------------------------------------------------------------------
    # XSS
    # ------------------------------------------------------------------
    (
        "cs_xss_html_raw",
        re.compile(
            r"""Html\.Raw\s*\(""",
        ),
        FindingType.XSS,
        Severity.HIGH,
        "Potential XSS via Html.Raw() bypassing Razor auto-escaping.",
        0.8,
        ["CWE-79"],
    ),
    (
        "cs_xss_response_write",
        re.compile(
            r"""Response\.Write\s*\(""",
        ),
        FindingType.XSS,
        Severity.MEDIUM,
        "Potential XSS via Response.Write() with unescaped output.",
        0.7,
        ["CWE-79"],
    ),
    # ------------------------------------------------------------------
    # Insecure Deserialization
    # ------------------------------------------------------------------
    (
        "cs_insecure_deserialization_binary_formatter",
        re.compile(
            r"""BinaryFormatter\s*\(""",
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.CRITICAL,
        "Insecure deserialization via BinaryFormatter can execute arbitrary code.",
        0.95,
        ["CWE-502"],
    ),
    (
        "cs_insecure_deserialization_type_name_handling",
        re.compile(
            r"""TypeNameHandling\s*[=:]\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)""",
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.CRITICAL,
        "Insecure deserialization via JsonConvert TypeNameHandling allows arbitrary type instantiation.",
        0.9,
        ["CWE-502"],
    ),
    (
        "cs_insecure_deserialization_javascript_serializer",
        re.compile(
            r"""JavaScriptSerializer\s*\(""",
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.HIGH,
        "JavaScriptSerializer with type resolvers can lead to insecure deserialization.",
        0.7,
        ["CWE-502"],
    ),
    # ------------------------------------------------------------------
    # XXE (XML External Entity)
    # ------------------------------------------------------------------
    (
        "cs_xxe_xml_document",
        re.compile(
            r"""new\s+XmlDocument\s*\(""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.HIGH,
        "Potential XXE vulnerability via XmlDocument without disabling DTD processing.",
        0.7,
        ["CWE-611"],
    ),
    (
        "cs_xxe_dtd_processing_parse",
        re.compile(
            r"""DtdProcessing\s*=\s*DtdProcessing\.Parse""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.CRITICAL,
        "XXE vulnerability: DtdProcessing.Parse enables external entity processing.",
        0.95,
        ["CWE-611"],
    ),
    # ------------------------------------------------------------------
    # LDAP Injection
    # ------------------------------------------------------------------
    (
        "cs_ldap_injection",
        re.compile(
            r"""(?:DirectorySearcher|DirectoryEntry)\s*\([^)]*(?:\+|\$["']|string\.Format)""",
        ),
        FindingType.SQL_INJECTION,
        Severity.HIGH,
        "LDAP injection via string concatenation in DirectorySearcher/DirectoryEntry.",
        0.8,
        ["CWE-90"],
    ),
    # ------------------------------------------------------------------
    # Weak Cryptography
    # ------------------------------------------------------------------
    (
        "cs_weak_crypto",
        re.compile(
            r"""(?:MD5|SHA1|DES|TripleDES|RC2)\.Create\s*\(""",
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.MEDIUM,
        "Use of weak cryptographic algorithm (MD5/SHA1/DES/TripleDES/RC2).",
        0.8,
        ["CWE-327", "CWE-328"],
    ),
    (
        "cs_weak_crypto_ecb_mode",
        re.compile(
            r"""CipherMode\.ECB""",
        ),
        FindingType.INSECURE_FUNCTION,
        Severity.HIGH,
        "Use of ECB cipher mode which does not provide semantic security.",
        0.9,
        ["CWE-327"],
    ),
    # ------------------------------------------------------------------
    # Hardcoded Connection Strings
    # ------------------------------------------------------------------
    (
        "cs_hardcoded_connection_string",
        re.compile(
            r"""(?:connectionString|ConnectionString|SqlConnection)\s*"""
            r"""[=(]\s*["'](?=.*(?:Server|Data Source|Password|Pwd|Initial Catalog))""",
            re.IGNORECASE,
        ),
        FindingType.SECRET,
        Severity.HIGH,
        "Hardcoded connection string with potential credentials.",
        0.8,
        ["CWE-798"],
    ),
    # ------------------------------------------------------------------
    # Insecure Cookie
    # ------------------------------------------------------------------
    (
        "cs_insecure_cookie_httponly",
        re.compile(
            r"""\.HttpOnly\s*=\s*false""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_PATTERN,
        Severity.MEDIUM,
        "Cookie HttpOnly flag explicitly set to false, allowing client-side script access.",
        0.85,
        ["CWE-1004"],
    ),
    (
        "cs_insecure_cookie_secure",
        re.compile(
            r"""\.Secure\s*=\s*false""",
            re.IGNORECASE,
        ),
        FindingType.INSECURE_PATTERN,
        Severity.MEDIUM,
        "Cookie Secure flag explicitly set to false, allowing transmission over HTTP.",
        0.85,
        ["CWE-614"],
    ),
    # ------------------------------------------------------------------
    # CSRF disabled
    # ------------------------------------------------------------------
    (
        "cs_csrf_ignore",
        re.compile(
            r"""\[IgnoreAntiforgeryToken\]""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.MEDIUM,
        "Anti-forgery token validation explicitly ignored, increasing CSRF risk.",
        0.8,
        ["CWE-352"],
    ),
    # ------------------------------------------------------------------
    # Open Redirect
    # ------------------------------------------------------------------
    (
        "cs_open_redirect",
        re.compile(
            r"""(?:Redirect|RedirectPermanent)\s*\(\s*(?:\w+\s*\+|\$["']|"""
            r"""(?:Request|request)\s*[\[.])""",
        ),
        FindingType.INSECURE_PATTERN,
        Severity.MEDIUM,
        "Open redirect via dynamic URL in Redirect() potentially controlled by user input.",
        0.7,
        ["CWE-601"],
    ),
]

# Remediation guidance keyed by pattern name.
CSHARP_REMEDIATION: dict[str, dict[str, Any]] = {
    "cs_sql_injection_string_concat": {
        "description": "Use parameterized queries with SqlParameter instead of string concatenation.",
        "before": 'var cmd = new SqlCommand("SELECT * FROM users WHERE id=" + userId, conn);',
        "after": 'var cmd = new SqlCommand("SELECT * FROM users WHERE id=@id", conn);\ncmd.Parameters.AddWithValue("@id", userId);',
        "auto_fixable": False,
    },
    "cs_sql_injection_string_format": {
        "description": "Use parameterized queries instead of string interpolation.",
        "before": 'cmd.CommandText = $"SELECT * FROM users WHERE name=\'{name}\'";',
        "after": 'cmd.CommandText = "SELECT * FROM users WHERE name=@name";\ncmd.Parameters.AddWithValue("@name", name);',
        "auto_fixable": False,
    },
    "cs_sql_injection_execute_concat": {
        "description": "Use parameterized queries with SqlParameter.",
        "before": 'cmd.ExecuteReader("SELECT * FROM users WHERE id=" + id)',
        "after": 'cmd.CommandText = "SELECT * FROM users WHERE id=@id";\ncmd.Parameters.AddWithValue("@id", id);\ncmd.ExecuteReader();',
        "auto_fixable": False,
    },
    "cs_command_injection_process_start": {
        "description": "Validate and sanitize input before passing to Process.Start. Use an allow-list.",
        "before": 'Process.Start("cmd.exe", "/c " + userInput)',
        "after": 'Process.Start(new ProcessStartInfo { FileName = "tool.exe", Arguments = allowedArg, UseShellExecute = false })',
        "auto_fixable": False,
    },
    "cs_command_injection_process_filename": {
        "description": "Use a whitelist of allowed commands and arguments.",
        "before": 'psi.FileName = userInput + ".exe";',
        "after": 'psi.FileName = allowList.Contains(cmd) ? cmd : throw new ArgumentException();',
        "auto_fixable": False,
    },
    "cs_path_traversal": {
        "description": "Validate paths stay within the expected base directory using Path.GetFullPath.",
        "before": 'var content = File.ReadAllText(basePath + "/" + userFile);',
        "after": 'var full = Path.GetFullPath(Path.Combine(basePath, userFile));\nif (!full.StartsWith(Path.GetFullPath(basePath))) throw new UnauthorizedAccessException();\nvar content = File.ReadAllText(full);',
        "auto_fixable": False,
    },
    "cs_xss_html_raw": {
        "description": "Sanitize HTML before using Html.Raw(), or use Razor auto-escaping.",
        "before": "@Html.Raw(userContent)",
        "after": "@Html.Raw(HtmlSanitizer.Sanitize(userContent))",
        "auto_fixable": False,
    },
    "cs_xss_response_write": {
        "description": "Use HttpUtility.HtmlEncode before writing to response.",
        "before": "Response.Write(userInput);",
        "after": "Response.Write(HttpUtility.HtmlEncode(userInput));",
        "auto_fixable": False,
    },
    "cs_insecure_deserialization_binary_formatter": {
        "description": "Replace BinaryFormatter with System.Text.Json or a safe serializer.",
        "before": "var formatter = new BinaryFormatter();\nvar obj = formatter.Deserialize(stream);",
        "after": "var obj = JsonSerializer.Deserialize<MyType>(stream);",
        "auto_fixable": False,
    },
    "cs_insecure_deserialization_type_name_handling": {
        "description": "Set TypeNameHandling to None (default) or use a custom SerializationBinder.",
        "before": 'JsonConvert.DeserializeObject(json, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All })',
        "after": 'JsonConvert.DeserializeObject<MyType>(json, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None })',
        "auto_fixable": False,
    },
    "cs_insecure_deserialization_javascript_serializer": {
        "description": "Replace JavaScriptSerializer with System.Text.Json.JsonSerializer.",
        "before": "var ser = new JavaScriptSerializer();\nvar obj = ser.Deserialize<object>(json);",
        "after": "var obj = JsonSerializer.Deserialize<MyType>(json);",
        "auto_fixable": False,
    },
    "cs_xxe_xml_document": {
        "description": "Set XmlResolver to null or use XmlReaderSettings with DtdProcessing.Prohibit.",
        "before": "var doc = new XmlDocument();\ndoc.LoadXml(xml);",
        "after": "var doc = new XmlDocument { XmlResolver = null };\ndoc.LoadXml(xml);",
        "auto_fixable": False,
    },
    "cs_xxe_dtd_processing_parse": {
        "description": "Set DtdProcessing to Prohibit instead of Parse.",
        "before": "settings.DtdProcessing = DtdProcessing.Parse;",
        "after": "settings.DtdProcessing = DtdProcessing.Prohibit;",
        "auto_fixable": True,
    },
    "cs_ldap_injection": {
        "description": "Use parameterized LDAP queries or sanitize input with LDAP encoding.",
        "before": 'var searcher = new DirectorySearcher("(cn=" + userInput + ")");',
        "after": 'var filter = $"(cn={LdapFilterEncode(userInput)})";\nvar searcher = new DirectorySearcher(filter);',
        "auto_fixable": False,
    },
    "cs_weak_crypto": {
        "description": "Use SHA256 or SHA512 for hashing, AES for encryption.",
        "before": "var hash = MD5.Create();",
        "after": "var hash = SHA256.Create();",
        "auto_fixable": True,
    },
    "cs_weak_crypto_ecb_mode": {
        "description": "Use CBC or GCM mode instead of ECB.",
        "before": "aes.Mode = CipherMode.ECB;",
        "after": "aes.Mode = CipherMode.CBC;",
        "auto_fixable": True,
    },
    "cs_hardcoded_connection_string": {
        "description": "Store connection strings in configuration files or environment variables.",
        "before": 'var conn = new SqlConnection("Server=db;Password=secret;");',
        "after": 'var conn = new SqlConnection(Configuration.GetConnectionString("Default"));',
        "auto_fixable": False,
    },
    "cs_insecure_cookie_httponly": {
        "description": "Set HttpOnly to true to prevent client-side script access.",
        "before": "cookie.HttpOnly = false;",
        "after": "cookie.HttpOnly = true;",
        "auto_fixable": True,
    },
    "cs_insecure_cookie_secure": {
        "description": "Set Secure to true to ensure cookies are only sent over HTTPS.",
        "before": "cookie.Secure = false;",
        "after": "cookie.Secure = true;",
        "auto_fixable": True,
    },
    "cs_csrf_ignore": {
        "description": "Remove [IgnoreAntiforgeryToken] and use [ValidateAntiForgeryToken] on state-changing actions.",
        "before": "[IgnoreAntiforgeryToken]\npublic IActionResult Transfer() { }",
        "after": "[ValidateAntiForgeryToken]\npublic IActionResult Transfer() { }",
        "auto_fixable": True,
    },
    "cs_open_redirect": {
        "description": "Use Url.IsLocalUrl() to validate redirect targets.",
        "before": "return Redirect(Request.Query[\"returnUrl\"]);",
        "after": 'var url = Request.Query["returnUrl"];\nif (Url.IsLocalUrl(url)) return Redirect(url);\nreturn RedirectToAction("Index");',
        "auto_fixable": False,
    },
}
