"""CWE-specific triage prompts for AI-assisted finding evaluation.

Strategy: AI-as-filter with zero telemetry.

Instead of collecting user feedback or telemetry to improve false positive
rates, GuardianShield provides CWE-specific triage guidance that teaches the
user's AI agent how to evaluate findings locally. Each triage guide contains
true/false positive indicators, targeted questions, and context examination
instructions derived from real-world security analysis patterns.

Research supports this approach: Semgrep achieves 96% agreement with human
reviewers when CWE-specific context is provided, and ZeroFalse demonstrates
F1 > 0.95 with structured triage prompts. By embedding this security
knowledge directly into prompt resources, every AI agent consuming
GuardianShield findings can make informed triage decisions without any data
leaving the user's environment.

The triage guides are exposed as MCP prompt resources so that any connected
AI agent can request structured evaluation guidance for a specific finding
type, apply it to the code context, and return a verdict.
"""

from __future__ import annotations

from typing import Any

from .findings import FindingType

# ---------------------------------------------------------------------------
# Triage guide registry
# ---------------------------------------------------------------------------
# Each guide is keyed by FindingType.value (str) and contains structured
# security knowledge for that vulnerability class. Guides are intentionally
# comprehensive -- the build_triage_prompt() function selects relevant
# sections when constructing a prompt for a specific finding.

TRIAGE_GUIDES: dict[str, dict[str, Any]] = {
    # ------------------------------------------------------------------
    # 1. SQL Injection
    # ------------------------------------------------------------------
    "sql_injection": {
        "cwe_ids": ["CWE-89"],
        "owasp": "A03:2021 Injection",
        "description": (
            "SQL injection occurs when untrusted input is concatenated or "
            "interpolated into SQL queries without parameterization. Attackers "
            "can modify query logic, extract data, or run administrative "
            "operations on the database."
        ),
        "true_positive_indicators": [
            "String concatenation (+ operator) or f-strings used to build SQL queries with variables derived from user input",
            "str.format() or %-formatting used to insert variables into SQL query strings",
            "Raw SQL passed to cursor.execute() where the query string is not a static literal",
            "User input (request.args, request.form, params, sys.argv) flows into query construction without parameterization",
            "ORM .raw() or .extra() methods called with dynamically constructed SQL fragments",
            "Query string built across multiple lines using concatenation with variables that trace back to external input",
        ],
        "false_positive_indicators": [
            "Parameterized queries using placeholders (?, %s, :name) with separate parameter tuple/dict passed to the execute method",
            "ORM query builder methods (filter(), where(), select()) used without raw SQL fragments",
            "Query string is a static literal with no variable interpolation (constants or hardcoded values only)",
            "Variables in the query are derived from internal constants, enums, or a fixed allowlist -- not from user input",
            "The code is in a test file constructing queries against an in-memory or test database with controlled inputs",
            "Database abstraction layer (SQLAlchemy Core, Django ORM, Knex) handles parameterization internally",
        ],
        "questions": [
            "Does any variable in the SQL string trace back to user-controlled input (HTTP params, CLI args, file contents, environment variables from untrusted sources)?",
            "Is the query parameterized -- are placeholders (?, %s, $1, :name) used with a separate parameter argument to the execute method?",
            "If an ORM is used, does the specific method (.raw(), .extra(), RawSQL) bypass the ORM's built-in parameterization?",
            "Could an attacker control the table name, column name, or ORDER BY clause even if values are parameterized?",
            "Is there any input validation or allowlist check between the user input source and the query construction?",
        ],
        "context_to_examine": [
            "Trace the variable(s) in the query string backward to their origin -- identify whether they come from user input or internal constants",
            "Check the execute/query call signature for a second argument (parameter tuple/dict) indicating parameterized execution",
            "Look for input validation, sanitization, or allowlist checks applied to variables before they enter the query",
            "Examine import statements to identify the database library and whether it supports automatic parameterization",
        ],
        "languages": ["python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp"],
    },
    # ------------------------------------------------------------------
    # 2. Cross-Site Scripting (XSS)
    # ------------------------------------------------------------------
    "xss": {
        "cwe_ids": ["CWE-79"],
        "owasp": "A03:2021 Injection",
        "description": (
            "Cross-site scripting occurs when untrusted data is included in "
            "web output without proper encoding or sanitization. Attackers can "
            "inject scripts that run in other users' browsers, stealing "
            "sessions, credentials, or performing actions on their behalf."
        ),
        "true_positive_indicators": [
            "innerHTML, outerHTML, or document.write() used with data derived from user input, URL parameters, or external sources",
            "React's dangerouslySetInnerHTML set with a value that includes unsanitized user input",
            "Template engine auto-escaping explicitly disabled (|safe in Jinja2/Django, {!! !!} in Blade, <%- %> in EJS, != in Pug)",
            "markupsafe.Markup() or equivalent wrapping user-controlled strings, bypassing template auto-escaping",
            "Server-side HTML string concatenation with user input rendered directly in HTTP response body",
            "jQuery .html(), .append(), or .prepend() called with user-controlled content without sanitization",
        ],
        "false_positive_indicators": [
            "Template engine with auto-escaping enabled by default (Jinja2 with autoescape=True, Django templates, React JSX expressions)",
            "DOMPurify.sanitize(), bleach.clean(), or equivalent sanitization library applied before output",
            "Output is textContent, innerText, or setAttribute on non-event/non-URL attributes (safe DOM APIs)",
            "Content-Type is application/json or text/plain -- not rendered as HTML by the browser",
            "The value being rendered is from a hardcoded string, integer, or server-controlled enumeration -- not user input",
            "Content Security Policy (CSP) with strict nonce/hash-based script-src is enforced (defense in depth, not a full fix)",
        ],
        "questions": [
            "Does the data rendered in HTML trace back to user-controlled input (URL params, form data, database fields populated by users, WebSocket messages)?",
            "Is the template engine's auto-escaping active for this specific output, or has it been explicitly bypassed with |safe, Markup(), or raw output syntax?",
            "If using a JavaScript framework (React, Vue, Angular), does the code use an escape-hatch API (dangerouslySetInnerHTML, v-html, [innerHTML])?",
            "Is there a sanitization step (DOMPurify, bleach, sanitize-html) between the user input source and the HTML output?",
            "What is the output context -- HTML body, HTML attribute, JavaScript string, URL, or CSS? Each requires different encoding.",
        ],
        "context_to_examine": [
            "Check the template file or rendering function for auto-escape configuration and whether raw output directives are used",
            "Trace the rendered variable to its data source -- distinguish between user-generated content and server-controlled values",
            "Look for sanitization middleware, output encoding functions, or Content Security Policy headers in the response pipeline",
            "Identify the output context (HTML element content, attribute value, script block, URL) as it determines which encoding is needed",
        ],
        "languages": ["javascript", "typescript", "python", "java", "ruby", "php", "csharp"],
    },
    # ------------------------------------------------------------------
    # 3. Command Injection
    # ------------------------------------------------------------------
    "command_injection": {
        "cwe_ids": ["CWE-78"],
        "owasp": "A03:2021 Injection",
        "description": (
            "Command injection occurs when untrusted input is passed to a "
            "system shell for execution. Attackers can chain additional "
            "commands using shell metacharacters (;, |, &&, $()) to run "
            "arbitrary code on the server."
        ),
        "true_positive_indicators": [
            "subprocess.Popen/call/run with shell=True and a command string that includes user-controlled variables",
            "os.system(), os.popen(), or commands.getoutput() called with any string containing user input",
            "Child process exec/execSync (Node.js) or backtick execution with interpolated user data",
            "Command string built via concatenation or formatting with variables tracing back to HTTP params, CLI args, or file contents",
            "Runtime.getRuntime().exec() (Java) with a single command string containing user input (parsed by shell)",
            "system(), passthru(), shell_exec() (PHP) with user-controlled arguments",
        ],
        "false_positive_indicators": [
            "subprocess with shell=False (default) and command/arguments passed as a list with no shell interpretation",
            "shlex.quote() or equivalent shell escaping applied to all user-controlled arguments before inclusion",
            "Command and all arguments are hardcoded string literals or constants with no external input",
            "User input is validated against a strict allowlist of permitted values (e.g., enum of known commands)",
            "The subprocess call is in a test/build script that never receives user input at runtime",
            "execFile/spawn (Node.js) with arguments as an array -- no shell interpretation occurs",
        ],
        "questions": [
            "Is shell=True (Python) or a shell-interpreted execution function used, or are commands passed as an argument list without shell?",
            "Do any parts of the command string or argument list trace back to user-controlled input (HTTP params, CLI args, file names from user uploads)?",
            "Is shlex.quote(), escapeshellarg(), or an equivalent escaping function applied to every user-controlled component?",
            "Could an attacker inject shell metacharacters (;, |, &&, ||, $(), backticks, newlines) to chain additional commands?",
            "Is there an allowlist check that restricts input to known-safe values before it reaches the command execution?",
        ],
        "context_to_examine": [
            "Check the shell parameter value (True/False) and whether the command is a string or list of arguments",
            "Trace every variable in the command string backward to determine if any originate from external input",
            "Look for shlex.quote(), pipes.quote(), escapeshellarg(), or manual sanitization applied to user input",
            "Check for input validation or allowlist logic (if/match/switch on permitted values) before the subprocess call",
        ],
        "languages": ["python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp"],
    },
    # ------------------------------------------------------------------
    # 4. Path Traversal
    # ------------------------------------------------------------------
    "path_traversal": {
        "cwe_ids": ["CWE-22"],
        "owasp": "A01:2021 Broken Access Control",
        "description": (
            "Path traversal occurs when user-controlled input is used to "
            "construct file system paths without proper validation. Attackers "
            "can use ../ sequences or absolute paths to read, write, or "
            "delete files outside the intended directory."
        ),
        "true_positive_indicators": [
            "User input (filename, path parameter) passed directly to open(), read_file(), or file stream constructors without validation",
            "os.path.join() or path concatenation with user input but no subsequent realpath/abspath check or prefix validation",
            "No check that the resolved path starts with (is a child of) the intended base directory",
            "File serving endpoint constructs a path from URL parameters without stripping or rejecting ../ sequences",
            "send_file(), send_from_directory(), or static file handlers with user-controlled path components and no sandboxing",
            "Zip/archive extraction that uses entry names directly as file paths without sanitization (Zip Slip)",
        ],
        "false_positive_indicators": [
            "Path is constructed from configuration constants, environment variables set at deploy time, or hardcoded values only",
            "os.path.realpath() or Path.resolve() is called and the result is verified to start with the allowed base directory",
            "User input is validated against an allowlist of permitted filenames or matched against a strict pattern (e.g., UUID only)",
            "A sandboxed file access API (e.g., Django's FileSystemStorage, chroot jail) restricts access to a specific directory",
            "The ../ and absolute path characters are explicitly stripped or rejected before the path is constructed",
            "The code operates on in-memory data or database BLOBs -- no actual filesystem path is constructed from user input",
        ],
        "questions": [
            "Does any component of the file path (directory, filename, extension) originate from user-controlled input?",
            "After constructing the full path, is os.path.realpath()/Path.resolve() called and the result checked to be within the allowed base directory?",
            "Are ../ sequences, null bytes, and absolute path prefixes explicitly rejected or stripped from the user input?",
            "Could an attacker use symbolic links, encoded path separators (%2F, %5C), or null bytes to bypass the validation?",
            "Is the file operation read-only or can the attacker also write/delete files at the traversed path?",
        ],
        "context_to_examine": [
            "Trace the file path argument backward to identify which components come from user input vs. server configuration",
            "Check for os.path.realpath(), os.path.abspath(), Path.resolve(), or equivalent canonicalization before the file operation",
            "Look for a prefix check (startswith, is_relative_to) that verifies the resolved path stays within the intended directory",
            "Examine the web framework's static file handling configuration for built-in path traversal protections",
        ],
        "languages": ["python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp"],
    },
    # ------------------------------------------------------------------
    # 5. Insecure Function (eval/exec/deserialization)
    # ------------------------------------------------------------------
    "insecure_function": {
        "cwe_ids": ["CWE-94", "CWE-95"],
        "owasp": "A03:2021 Injection",
        "description": (
            "Use of dangerous functions like eval(), exec(), pickle.loads(), "
            "or yaml.load() that can execute arbitrary code. When these "
            "functions receive untrusted input, attackers can achieve remote "
            "code execution."
        ),
        "true_positive_indicators": [
            "eval() or exec() called with a string that includes user-controlled input (HTTP params, form data, file contents)",
            "pickle.loads(), pickle.load(), or shelve.open() deserializing data from network requests, untrusted files, or shared storage",
            "yaml.load() called without Loader=SafeLoader on data from external sources (default Loader allows arbitrary Python objects)",
            "marshal.loads() or jsonpickle.decode() on untrusted data -- these allow code execution during deserialization",
            "Dynamic code generation (compile() + exec()) with templates that include user-controlled fragments",
            "PHP unserialize(), Ruby Marshal.load(), or Java ObjectInputStream.readObject() on untrusted data",
        ],
        "false_positive_indicators": [
            "eval() of a compile()d AST node that was constructed programmatically without user input (e.g., math expression parsers with AST validation)",
            "pickle.loads() only ever receives data from a trusted local source (same-process cache, signed/encrypted local file)",
            "yaml.safe_load() or yaml.load(data, Loader=SafeLoader) is used instead of unsafe yaml.load()",
            "The function is in a REPL, debugger, development tool, or test harness -- never exposed to untrusted input in production",
            "exec() runs a fixed, hardcoded code string with no variable interpolation or external input",
            "A restricted execution environment (RestrictedPython, sandbox, seccomp) limits what the evaluated code can do",
        ],
        "questions": [
            "Does the argument to eval()/exec()/loads() contain or derive from user-controlled input, or is it purely server-generated?",
            "For deserialization (pickle, yaml, marshal): what is the source of the serialized data -- local trusted storage or external/network input?",
            "If yaml.load() is used, is the Loader parameter explicitly set to SafeLoader, BaseLoader, or a custom safe loader?",
            "Is there AST validation, sandboxing, or input filtering that restricts what the evaluated expression can do?",
            "Is this code path reachable in production, or is it limited to development/testing contexts?",
        ],
        "context_to_examine": [
            "Identify the exact function called and trace its argument to the data source -- distinguish trusted local data from external input",
            "For yaml.load(), check whether a Loader parameter is passed and its value (SafeLoader vs FullLoader vs Loader=None)",
            "Look for sandboxing, AST whitelisting, or expression validation that restricts the evaluated code's capabilities",
            "Check if the code is behind authentication, rate limiting, or access control that limits who can trigger the dangerous function",
        ],
        "languages": ["python", "javascript", "typescript", "java", "ruby", "php", "csharp"],
    },
    # ------------------------------------------------------------------
    # 6. Insecure Pattern (crypto, creds, deserialization)
    # ------------------------------------------------------------------
    "insecure_pattern": {
        "cwe_ids": ["CWE-327", "CWE-328", "CWE-330", "CWE-798", "CWE-502"],
        "owasp": "A02:2021 Cryptographic Failures",
        "description": (
            "Insecure patterns include use of weak or broken cryptographic "
            "algorithms (MD5, SHA1 for security purposes), weak random number "
            "generation for security-sensitive operations, hardcoded "
            "credentials, and insecure deserialization. The severity depends "
            "on the specific pattern and its usage context."
        ),
        "true_positive_indicators": [
            "MD5 or SHA1 used for password hashing, digital signatures, integrity verification of security-sensitive data, or HMAC construction",
            "random.random(), Math.random(), or rand() used to generate security tokens, session IDs, CSRF tokens, or cryptographic nonces",
            "Hardcoded passwords, API keys, or connection strings in production source code (not in test/example files)",
            "DES, RC4, ECB mode, or other known-broken ciphers used for encrypting sensitive data",
            "Insecure deserialization (pickle, Marshal, ObjectInputStream) of data from untrusted sources with no integrity verification",
            "Static IV or key reuse in symmetric encryption -- same key/IV pair used across multiple encryptions",
        ],
        "false_positive_indicators": [
            "MD5/SHA1 used for non-security purposes: cache key generation, content-addressable storage, ETags, deduplication checksums, file integrity in non-adversarial contexts",
            "random.random() used for non-security purposes: shuffling UI elements, sampling data, test data generation, simulation",
            "Credentials are placeholder/example values in documentation, config templates, or default development settings",
            "The code is in a test file using known-weak algorithms for testing purposes against test data",
            "hashlib.md5(usedforsecurity=False) (Python 3.9+) explicitly marking non-security use",
            "The 'hardcoded credential' is actually an environment variable lookup (os.environ, process.env) or secrets manager call",
        ],
        "questions": [
            "Is the weak algorithm (MD5, SHA1, DES, RC4) being used for a security-sensitive purpose (authentication, encryption, signing) or a non-security purpose (checksums, caching, fingerprinting)?",
            "Is the random number generator used for security-sensitive tokens/keys, or for non-security purposes like UI, sampling, or testing?",
            "For apparent hardcoded credentials: is this a real production value, a placeholder/example, or actually loaded from environment/secrets at runtime?",
            "Is this code in a test, example, documentation, or configuration template file where weak algorithms or fake credentials are expected?",
            "For deserialization findings: is the serialized data from a trusted source with integrity verification, or from an untrusted external source?",
        ],
        "context_to_examine": [
            "Determine the purpose of the hash/random/encryption operation from surrounding code and variable names -- security vs. non-security use",
            "Check the file path and surrounding code for test markers, example comments, or template indicators",
            "For credential findings, trace the value to determine if it is a literal string or loaded from environment variables / secrets manager",
            "Look for Python's usedforsecurity=False parameter or equivalent documentation of non-security intent",
        ],
        "languages": ["python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp"],
    },
    # ------------------------------------------------------------------
    # 7. Secret / Hardcoded Credential
    # ------------------------------------------------------------------
    "secret": {
        "cwe_ids": ["CWE-798"],
        "owasp": "A07:2021 Identification and Authentication Failures",
        "description": (
            "Hardcoded secrets, API keys, tokens, passwords, and private keys "
            "embedded directly in source code. If committed to version "
            "control, these credentials may be exposed to anyone with "
            "repository access and are difficult to rotate."
        ),
        "true_positive_indicators": [
            "String matches a known credential format with valid structure (AWS AKIA prefix + 16 chars, GitHub ghp_/gho_/ghs_ prefix, Stripe sk_live_/sk_test_ prefix)",
            "Value has high entropy (mix of alphanumeric + special characters) and is assigned to a variable named password, secret, token, api_key, or similar",
            "Private key block (-----BEGIN RSA PRIVATE KEY-----, -----BEGIN EC PRIVATE KEY-----) with actual key material (not a placeholder)",
            "JWT token (eyJ...) with a real payload containing claims -- not a documentation example",
            "Database connection string with embedded username:password in a source file (not an environment variable reference)",
            "The value differs from common placeholder patterns and has sufficient length/entropy to be a real credential",
        ],
        "false_positive_indicators": [
            "Value is a known placeholder: 'xxx', 'your-api-key-here', 'CHANGE_ME', 'TODO', 'sk_test_...', 'example', 'dummy', 'fake', 'test'",
            "Value is loaded from environment variable (os.environ[], process.env., System.getenv()), secrets manager, or vault at runtime",
            "The file is a configuration template (.example, .template, .sample) or documentation with example values",
            "The file is a test fixture with fake/mock credentials that are not valid for any real service",
            "The string is a hash/checksum output (e.g., SHA256 of known content) not a secret",
            "Variable is assigned from a function call to a secrets manager (get_secret(), vault.read(), SSM.get_parameter())",
        ],
        "questions": [
            "Does the detected string have the structure and entropy of a real credential, or does it match common placeholder patterns?",
            "Is the value a literal string in source code, or is it actually loaded from an environment variable, secrets manager, or configuration file at runtime?",
            "Is this file a template, example, test fixture, or documentation where placeholder credentials are expected?",
            "For API keys with known prefixes (AKIA, ghp_, sk_live_): does the full key match the expected format and length for a valid key?",
            "Would this credential grant access to a real service if used -- is it a production, staging, or test-environment credential?",
        ],
        "context_to_examine": [
            "Check the variable name and surrounding comments for indicators like 'example', 'placeholder', 'TODO', or 'test'",
            "Examine the file extension and path for test/example/template/documentation indicators",
            "Look for adjacent code that loads the real value from environment or secrets manager (the detected string may be a fallback default)",
            "Check .gitignore, .env.example, and repository structure to understand if this file is intended to be committed",
        ],
        "languages": ["python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp"],
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_triage_guide(finding_type: str) -> dict[str, Any] | None:
    """Look up a triage guide by finding type string.

    Parameters:
        finding_type: A finding type value (e.g. ``"sql_injection"``).
            Must correspond to a valid :class:`FindingType` value.

    Returns:
        The triage guide dict if one exists for the given finding type,
        or ``None`` if no guide is available.

    Raises:
        ValueError: If *finding_type* is not a valid ``FindingType`` value.
    """
    # Validate that the finding type is a recognized enum value.
    try:
        FindingType(finding_type)
    except ValueError:
        raise ValueError(
            f"Unknown finding type: {finding_type!r}. "
            f"Valid types: {[ft.value for ft in FindingType]}"
        ) from None

    return TRIAGE_GUIDES.get(finding_type)


def get_all_triage_guides() -> dict[str, dict[str, Any]]:
    """Return all triage guides.

    Returns:
        A dict mapping finding type strings to their triage guide dicts.
        This is a shallow copy -- callers should not mutate the returned
        guides.
    """
    return dict(TRIAGE_GUIDES)


def build_triage_prompt(
    finding_type: str,
    code_snippet: str = "",
    file_path: str = "",
    language: str = "",
) -> str:
    """Build a structured prompt that teaches an AI how to evaluate a finding.

    The returned prompt contains CWE-specific triage guidance including
    true/false positive indicators, targeted questions to answer, and
    instructions for rendering a verdict.

    Parameters:
        finding_type: The finding type to build a prompt for (e.g.
            ``"sql_injection"``).
        code_snippet: Optional source code surrounding the finding for
            the AI to analyze.
        file_path: Optional file path for additional context (e.g. test
            files are more likely to be false positives).
        language: Optional programming language hint.

    Returns:
        A formatted prompt string ready to be sent to an AI for finding
        evaluation.

    Raises:
        ValueError: If *finding_type* has no triage guide available.
    """
    guide = get_triage_guide(finding_type)
    if guide is None:
        raise ValueError(
            f"No triage guide available for finding type: {finding_type!r}. "
            f"Available types: {available_finding_types()}"
        )

    sections: list[str] = []

    # -- Header --
    sections.append("# Security Finding Triage")
    sections.append("")
    sections.append(f"**Finding Type**: {finding_type}  ")
    sections.append(f"**CWE**: {', '.join(guide['cwe_ids'])}  ")
    sections.append(f"**OWASP**: {guide['owasp']}")
    sections.append("")

    # -- Description --
    sections.append("## Vulnerability Description")
    sections.append("")
    sections.append(guide["description"])
    sections.append("")

    # -- Code context --
    if code_snippet:
        sections.append("## Code Under Review")
        sections.append("")
        if file_path:
            sections.append(f"**File**: `{file_path}`  ")
        if language:
            sections.append(f"**Language**: {language}")
        sections.append("")
        sections.append(f"```{language}")
        sections.append(code_snippet)
        sections.append("```")
        sections.append("")

    # -- True positive indicators --
    sections.append("## True Positive Indicators")
    sections.append("")
    sections.append(
        "The finding is likely a **real vulnerability** if any of the "
        "following apply:"
    )
    sections.append("")
    for indicator in guide["true_positive_indicators"]:
        sections.append(f"- {indicator}")
    sections.append("")

    # -- False positive indicators --
    sections.append("## False Positive Indicators")
    sections.append("")
    sections.append(
        "The finding is likely a **false positive** (safe to ignore) if "
        "any of the following apply:"
    )
    sections.append("")
    for indicator in guide["false_positive_indicators"]:
        sections.append(f"- {indicator}")
    sections.append("")

    # -- Questions to answer --
    sections.append("## Questions to Answer")
    sections.append("")
    sections.append(
        "Analyze the code and answer each question. Your answers will "
        "determine the verdict."
    )
    sections.append("")
    for i, question in enumerate(guide["questions"], 1):
        sections.append(f"{i}. {question}")
    sections.append("")

    # -- Context to examine --
    sections.append("## Context to Examine")
    sections.append("")
    sections.append(
        "Before rendering your verdict, examine the following aspects of "
        "the surrounding code:"
    )
    sections.append("")
    for item in guide["context_to_examine"]:
        sections.append(f"- {item}")
    sections.append("")

    # -- Verdict instructions --
    sections.append("## Instructions")
    sections.append("")
    sections.append(
        "Based on your analysis, provide a structured evaluation with the "
        "following format:"
    )
    sections.append("")
    sections.append("```")
    sections.append("Verdict: <true_positive | false_positive | needs_more_context>")
    sections.append("Confidence: <high | medium | low>")
    sections.append("Reasoning: <1-3 sentences explaining your determination>")
    sections.append(
        "Key Evidence: <the specific code pattern or data flow that supports your verdict>"
    )
    sections.append("```")
    sections.append("")
    sections.append("Guidelines for your verdict:")
    sections.append("")
    sections.append(
        "- **true_positive**: The code is vulnerable. User input reaches "
        "a dangerous operation without adequate protection."
    )
    sections.append(
        "- **false_positive**: The code is safe. The pattern matched but "
        "the code uses proper protections, or the flagged data is not "
        "user-controlled."
    )
    sections.append(
        "- **needs_more_context**: You cannot determine the verdict from "
        "the visible code alone. Specify what additional context is needed "
        "(e.g., the definition of a called function, the data source for "
        "a variable, the configuration of a framework)."
    )

    return "\n".join(sections)


def available_finding_types() -> list[str]:
    """Return a sorted list of finding types that have triage guides.

    Returns:
        List of finding type strings (e.g. ``["command_injection",
        "insecure_function", ...]``).
    """
    return sorted(TRIAGE_GUIDES.keys())
