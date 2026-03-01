---
title: Architecture
description: Understand GuardianShield's modular architecture, data flow, and design principles.
---

# Architecture

GuardianShield follows a modular, layered architecture designed for clarity, testability, and zero-dependency operation. Each scanner is an independent module with no cross-dependencies, the core orchestrator ties them together based on the active safety profile, and the MCP server exposes everything to AI clients via JSON-RPC 2.0 over stdio.

---

## Architecture Diagram

```text
[Any MCP Client: Claude Code / VS Code / Cursor / etc.]
    |  JSON-RPC over stdin/stdout
    |
[GuardianShieldMCPServer]         <- mcp_server.py (21 tools)
    |
[GuardianShield core]             <- core.py (orchestrator)
    |
    |-- scan_code()      -> scanner.py (patterns/) + secrets.py  -> Finding[]
    |-- scan_file()      -> auto-detect lang -> scan_code()      -> Finding[]
    |-- scan_directory() -> walk + scan_file() per file          -> Finding[]
    |-- scan_input()     -> injection.py                         -> Finding[]
    |-- scan_output()    -> pii.py + content.py                  -> Finding[]
    |-- check_secrets()  -> secrets.py                           -> Finding[]
    |-- check_deps()     -> osv.py -> SQLite cache               -> Finding[]
    |
    |-- [EngineRegistry]  <- engines.py (RegexEngine + pluggable)
    |-- [AuditLog]       -> SQLite (audit.py)
    |-- [ProjectConfig]  <- config.py (.guardianshield.json/yaml)
    |-- [Deduplicator]   <- dedup.py (SHA-256 fingerprints)
    |-- [FalsePositiveDB] <- feedback.py (per-project SQLite)
    '-- [SafetyProfile]  <- profiles.py + YAML
```

The architecture has three distinct layers:

1. **Transport layer** — `mcp_server.py` handles the JSON-RPC 2.0 protocol over stdio, parsing requests and serializing responses.
2. **Orchestration layer** — `core.py` routes scan requests through the appropriate scanners based on the active safety profile configuration.
3. **Scanner layer** — Independent scanner modules (`scanner.py`, `secrets.py`, `injection.py`, `pii.py`, `content.py`) each perform a single type of analysis and return `Finding` objects.

---

## Module Descriptions

### `mcp_server.py` — MCP Server

Hand-rolled JSON-RPC 2.0 server that implements the full MCP protocol without any SDK dependency. Reads from `stdin`, writes to `stdout`, and handles `initialize`, `tools/list`, `tools/call`, and all required MCP lifecycle methods. Exposes 21 security tools to any MCP-compatible client.

### `core.py` — Orchestrator

Central orchestrator that creates and manages scanner instances and routes scan requests through them. Reads the active safety profile to determine which scanners are enabled and at what sensitivity level. Provides five scan surfaces: `scan_code()`, `scan_file()`, `scan_directory()`, `scan_input()`, and `scan_output()`. Accepts an optional `ProjectConfig` for per-project customization.

### `scanner.py` — Code Vulnerability Scanner

Detects insecure code patterns using compiled regular expressions. Delegates to the `patterns/` package for language-specific pattern sets across 7 languages (108 patterns total). Patterns are compiled at module load time for performance. Each pattern includes CWE IDs, confidence scores, and remediation suggestions.

### `engines.py` — Analysis Engine Framework

Defines the `AnalysisEngine` Protocol for pluggable analysis strategies and the `EngineRegistry` for managing them. Ships with `RegexEngine`, which wraps `scanner.scan_code()` and tags findings with `details["engine"] = "regex"`. Each `GuardianShield` instance owns its own registry, and engines can be selected per-scan or per-session via `set_engine`.

### `secrets.py` — Secret & Credential Detector

Identifies 12+ types of secrets and credentials including AWS access keys, GitHub tokens, Stripe keys, JWTs, private keys, database connection strings, and generic high-entropy strings. All matched secrets are automatically redacted in findings — the raw value is never exposed.

### `injection.py` — Prompt Injection Detector

Detects prompt injection attacks using 9+ heuristic patterns. Catches instruction override attempts, role hijacking, system prompt extraction, ChatML injection, base64-encoded payloads, delimiter abuse, and jailbreak techniques.

### `pii.py` — PII Detector

Identifies personally identifiable information using a regex-based MVP scanner. Detects email addresses, Social Security numbers, credit card numbers, phone numbers, and IP addresses. Supports an optional Presidio backend (`pip install guardianshield[presidio]`) for enhanced entity recognition.

### `content.py` — Content Moderator

Category-based content filtering engine. Evaluates text against configurable content categories with per-category sensitivity thresholds. Categories and thresholds are driven by the active safety profile — for example, the `children` profile applies maximum filtering across all categories.

### `audit.py` — Audit Logger

Thread-safe SQLite audit logger that records every scan operation, its findings, and metadata. Input text is never stored — only SHA-256 hashes are persisted, ensuring the audit trail is useful for compliance without becoming a liability. Supports querying by time range, severity, and finding type.

### `findings.py` — Finding Model

Defines the `Finding` dataclass and its associated enums (`Severity`, `FindingType`). Every scanner returns a list of `Finding` objects, providing a uniform interface across all scan types. Severity levels: `critical`, `high`, `medium`, `low`, `info`.

### `profiles.py` — Safety Profile System

Loads and manages safety profiles from YAML configuration files. Ships with 5 built-in profiles (`general`, `education`, `healthcare`, `finance`, `children`) that configure scanner sensitivity, enabled/disabled scanners, and content moderation thresholds. Custom profiles can be defined by adding YAML files to the profiles directory.

### `patterns/` — Language-Specific Pattern Sets

A sub-package containing vulnerability detection patterns organized by language. The registry (`__init__.py`) provides `LANGUAGE_PATTERNS`, `EXTENSION_MAP` (maps file extensions to language keys), and `REMEDIATION_MAP` (maps pattern names to `Remediation` objects). Pattern modules: `common.py` (3), `python.py` (15), `javascript.py` (7), `go.py` (13), `java.py` (12), `ruby.py` (16), `php.py` (20), `csharp.py` (22). Each pattern is a 7-element tuple: `(name, regex, finding_type, severity, description, confidence, cwe_ids)`.

### `config.py` — Project Configuration

Discovers and loads `.guardianshield.json` or `.guardianshield.yaml` files from the project directory tree. Supports per-project settings including profile selection, severity overrides, exclude paths, and custom patterns. The `discover_config()` function walks up from the current directory to find the nearest config file.

### `enrichment.py` — Finding Enrichment

Enriches every finding with contextual details: surrounding code lines, match explanation, CWE/OWASP Top 10 references, vulnerability class, and scanner metadata. The `enrich_finding()` function is called during scanning and merges into the finding's `details` dict.

### `feedback.py` — False Positive Feedback

Per-project SQLite store (`FalsePositiveDB`) that tracks false positive records. Findings are auto-annotated with `metadata["false_positive"]` (exact match) or `metadata["potential_false_positive"]` (pattern match). Records are managed via `mark_false_positive`, `list_false_positives`, and `unmark_false_positive` MCP tools.

### `dedup.py` — Finding Deduplication

Computes stable SHA-256 fingerprints for findings based on file path, line number, finding type, pattern name, and matched text. The `FindingDeduplicator` class tracks fingerprints across scans and returns a `DedupResult` with new, unchanged, and removed findings — enabling efficient delta reporting on re-scans.

### `osv.py` — Dependency Vulnerability Scanner

Local-first dependency vulnerability scanner using the OSV.dev API. Syncs vulnerability data to a local SQLite cache (`~/.guardianshield/osv_cache.db`), enabling offline lookups. Supports PyPI, npm, Go, and Packagist ecosystems. Maps CVSS scores to GuardianShield severity levels and returns findings with `DEPENDENCY_VULNERABILITY` type.

### `manifest.py` — Manifest File Parser

Parses 11 dependency manifest formats into `Dependency` objects for vulnerability checking. Supports requirements.txt (and variants), package.json, pyproject.toml, package-lock.json, yarn.lock, pnpm-lock.yaml, Pipfile.lock, go.mod, go.sum, composer.json, and composer.lock. All parsers are stdlib-only with zero external dependencies. The `parse_manifest()` function auto-detects the format from the filename and dispatches to the appropriate parser.

---

## Design Principles

!!! abstract "Zero External Dependencies"
    The core functionality runs on Python's standard library alone. No third-party packages are required for installation or operation. This eliminates supply-chain risk and simplifies deployment across any environment with Python 3.9+.

!!! abstract "Hand-Rolled JSON-RPC"
    The MCP server implements JSON-RPC 2.0 from scratch rather than using an MCP SDK. This gives full control over protocol handling, avoids SDK version churn, and maintains the zero-dependency guarantee.

!!! abstract "Compiled Regex at Module Level"
    All scanner patterns are compiled into `re.Pattern` objects at module load time using `re.compile()`. This means the regex compilation cost is paid once at startup, and all subsequent scans use the pre-compiled patterns for maximum throughput.

!!! abstract "Input Text Is Never Stored"
    Scanned text is never persisted to disk. The audit log stores only SHA-256 hashes of inputs, ensuring that even if the audit database is compromised, no sensitive source code, prompts, or outputs can be recovered.

!!! abstract "Automatic Redaction"
    When a secret or PII match is found, the matched value is always redacted in the `Finding` object. The finding includes the pattern name, location, and severity — but never the raw secret or PII value itself.

!!! abstract "Thread-Safe Audit Logging"
    The `AuditLog` class uses thread-safe SQLite writes, ensuring correct behavior when the MCP server handles concurrent or rapid-fire scan requests.

!!! abstract "MemoryMesh Architectural Pattern"
    GuardianShield follows the MemoryMesh pattern for MCP servers: a hand-rolled JSON-RPC server with stdio transport, modular tool handlers, and structured data models — optimized for reliability and minimal footprint.

---

## Data Flow

The following walkthrough traces what happens when a client calls the `scan_code` tool.

```text
1. MCP Client                    2. mcp_server.py
   |                                |
   |-- JSON-RPC request ----------->|
   |   {"method":"tools/call",      |
   |    "params":{"name":           |
   |    "scan_code", ...}}          |
   |                                |
   |                             3. Dispatches to
   |                                _tool_scan_code()
   |                                |
   |                             4. core.py
   |                                GuardianShield.scan_code()
   |                                |
   |                                |-- Checks active profile config
   |                                |
   |                             5. Scanner layer
   |                                |-- scanner.scan_code(text)
   |                                |-- secrets.check_secrets(text)
   |                                |
   |                             6. Combines Finding[] results
   |                                |-- Logs to audit.db (SHA-256 only)
   |                                |
   |   <--- JSON-RPC response ------|
   |   {"result": [Finding, ...]}   7. Returns findings as JSON
```

**Step-by-step:**

1. **MCP client sends JSON-RPC request** — The AI client (Claude Code, VS Code, Cursor, etc.) sends a `tools/call` request with `name: "scan_code"` and the code to scan as an argument, serialized as JSON-RPC 2.0 over stdin.

2. **Server dispatches to handler** — `GuardianShieldMCPServer` in `mcp_server.py` parses the JSON-RPC envelope, validates the method, and routes to the `_tool_scan_code` handler.

3. **Handler calls core** — The handler extracts the `code` argument and calls `GuardianShield.scan_code()` on the core orchestrator instance.

4. **Core checks active profile** — The orchestrator reads the active `SafetyProfile` to determine which scanners are enabled and their sensitivity levels.

5. **Scanners execute** — The core calls `scanner.scan_code()` for vulnerability detection and `secrets.check_secrets()` for credential detection. If a `file_path` or `language` is provided, the scanner loads the appropriate language-specific patterns from the `patterns/` package (auto-detected from extension via `EXTENSION_MAP`). Each scanner returns a list of `Finding` objects with LSP ranges, confidence scores, CWE IDs, and remediation suggestions.

6. **Findings are combined and logged** — The core merges all findings, deduplicates if necessary, and writes an audit record to the SQLite database. The audit record contains the SHA-256 hash of the input — never the raw text.

7. **Response returned** — The findings are serialized into the JSON-RPC response format and written to stdout, where the MCP client receives them.

---

## Project Structure

```text
GuardianShield/
|-- src/
|   '-- guardianshield/
|       |-- __init__.py          # Package init, public API exports
|       |-- mcp_server.py        # JSON-RPC 2.0 MCP server (21 tools)
|       |-- core.py              # Orchestrator — routes scans through scanners
|       |-- scanner.py           # Code vulnerability scanner (uses patterns/)
|       |-- engines.py           # AnalysisEngine protocol, RegexEngine, EngineRegistry
|       |-- patterns/            # Language-specific vulnerability patterns
|       |   |-- __init__.py      # Registry: LANGUAGE_PATTERNS, EXTENSION_MAP, REMEDIATION_MAP
|       |   |-- common.py        # 3 cross-language patterns + remediation
|       |   |-- python.py        # 15 Python patterns + remediation
|       |   |-- javascript.py    # 7 JS/TS patterns + remediation
|       |   |-- go.py            # 13 Go patterns + remediation
|       |   |-- java.py          # 12 Java patterns + remediation
|       |   |-- ruby.py          # 16 Ruby/Rails patterns + remediation
|       |   |-- php.py           # 20 PHP patterns + remediation
|       |   '-- csharp.py        # 22 C#/ASP.NET patterns + remediation
|       |-- secrets.py           # Secret/credential detector (12+ patterns)
|       |-- injection.py         # Prompt injection detector (9+ heuristics)
|       |-- pii.py               # PII detector (regex MVP + optional Presidio)
|       |-- content.py           # Content moderator (category-based filtering)
|       |-- audit.py             # SQLite audit logger (thread-safe)
|       |-- findings.py          # Finding, Range, Remediation, Severity, FindingType
|       |-- profiles.py          # Safety profile loader and manager
|       |-- config.py            # Project config discovery (.guardianshield.json/yaml)
|       |-- dedup.py             # Finding deduplication (SHA-256 fingerprints)
|       |-- enrichment.py        # Finding enrichment (code context, CWE/OWASP refs)
|       |-- feedback.py          # False positive feedback loop (per-project SQLite)
|       |-- osv.py               # OSV.dev dependency scanner (SQLite cache)
|       |-- manifest.py          # Manifest file parser (11 formats)
|       '-- profiles/
|           |-- general.yaml     # Balanced defaults for everyday development
|           |-- education.yaml   # Content safety for learning environments
|           |-- healthcare.yaml  # HIPAA-aware PII and PHI protection
|           |-- finance.yaml     # PCI-DSS compliant secret handling
|           '-- children.yaml    # Maximum content filtering and safety
|-- tests/
|   |-- test_audit.py
|   |-- test_config.py           # Project config discovery tests
|   |-- test_content.py
|   |-- test_core.py
|   |-- test_dedup.py            # Deduplication tests
|   |-- test_file_scanning.py    # scan_file / scan_directory tests
|   |-- test_findings.py
|   |-- test_injection.py
|   |-- test_mcp_server.py
|   |-- test_manifest.py         # Manifest parser tests
|   |-- test_osv.py              # OSV dependency scanner tests
|   |-- test_patterns.py         # Language pattern tests
|   |-- test_pii.py
|   |-- test_profiles.py
|   |-- test_scanner.py
|   '-- test_secrets.py
|-- docs/                        # MkDocs Material documentation
|-- .github/workflows/           # CI/CD pipelines
|-- mkdocs.yml                   # MkDocs configuration
|-- pyproject.toml               # Python packaging (PEP 621)
|-- Makefile                     # Development shortcuts
|-- LICENSE                      # Apache-2.0
'-- README.md
```

!!! info "One module, one responsibility"
    Every scanner module is self-contained with no imports from other scanner modules. This makes it straightforward to test, extend, or replace any individual scanner without affecting the rest of the system.

---

## Transport

### stdio (Primary)

GuardianShield uses **stdio transport** as its primary communication channel. The MCP server reads JSON-RPC 2.0 messages from `stdin` and writes responses to `stdout`, one message per line. This is the standard transport for local MCP servers and is supported by all major MCP clients.

```text
MCP Client  <--stdin/stdout-->  guardianshield-mcp
```

Advantages of stdio transport:

- **Universal compatibility** — Every MCP client supports stdio. No configuration of ports, hosts, or TLS certificates required.
- **Process isolation** — The server runs as a child process of the client, with natural lifecycle management (start on connect, terminate on disconnect).
- **Zero network exposure** — No listening sockets, no attack surface beyond the local process boundary.
- **Simple debugging** — Pipe JSON-RPC messages directly for testing: `echo '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{}}' | guardianshield-mcp`

### Streamable HTTP (Future)

!!! note "Planned for a future release"
    Streamable HTTP transport (SSE-based) is under consideration for scenarios that require remote access to a shared GuardianShield instance — such as team-wide policy enforcement or centralized audit logging. The stdio transport will remain the recommended default for local development.
