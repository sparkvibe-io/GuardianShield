# GuardianShield — AI Agent Instructions

GuardianShield is a universal AI security layer exposed as an MCP server.
**Version**: 1.1.0 | **Tests**: 1627 | **Dependencies**: zero (stdlib only)

## Available MCP Tools (21)

### Scanning
- **scan_code**: Scan source code for vulnerabilities and hardcoded secrets (Python, JS/TS, Go, Java, Ruby, PHP, C#)
- **scan_file**: Scan a single file (auto-detects language from extension)
- **scan_directory**: Recursively scan a directory with extension/exclude filtering and streaming progress
- **scan_input**: Check input for prompt injection attempts
- **scan_output**: Check AI output for PII leaks and content violations
- **check_secrets**: Dedicated secret/credential detection
- **check_dependencies**: Check packages for known CVEs via local OSV.dev cache (PyPI, npm, Go, Packagist)
- **sync_vulnerabilities**: Sync the local OSV vulnerability database
- **parse_manifest**: Parse any supported manifest file (11 formats) into dependency objects
- **scan_dependencies**: Scan a directory for manifest files and check all dependencies for vulnerabilities

### False Positive Feedback
- **mark_false_positive**: Mark a finding as false positive (flags future matches, annotates similar patterns)
- **list_false_positives**: List active false positive records with optional scanner filter
- **unmark_false_positive**: Remove a false positive record by fingerprint

### Engine Management
- **list_engines**: List available analysis engines with capabilities and enabled status
- **set_engine**: Set which analysis engines are active for code scanning

### Configuration & Utilities
- **get_profile**: View current safety profile
- **set_profile**: Switch safety profiles (general/education/healthcare/finance/children)
- **test_pattern**: Test a regex pattern against sample code (returns matches with positions)
- **audit_log**: Query the security audit log
- **get_findings**: Retrieve past findings with filters
- **shield_status**: Get health, capabilities, OSV cache stats, FP stats, and configuration

## Usage Guidelines

1. Use `scan_code` or `scan_file` before committing or reviewing code changes
2. Use `scan_directory` to audit an entire project
3. Use `scan_input` to validate untrusted user inputs
4. Use `scan_output` before returning AI-generated content to users
5. Use `check_secrets` on configuration files and environment setups
6. Use `check_dependencies` to audit package.json or requirements.txt deps
7. Use `parse_manifest` to parse any dependency manifest file into structured objects
8. Use `scan_dependencies` to audit all manifests in a directory at once
9. Use `test_pattern` to develop and debug custom vulnerability regex patterns
10. Switch profiles with `set_profile` based on the domain context
11. Use `mark_false_positive` to flag known false positives; similar patterns get auto-annotated
12. Use `list_false_positives` and `unmark_false_positive` to manage false positive records

## Project Structure

```
src/guardianshield/
├── findings.py      # Finding, Range, Remediation, Severity, FindingType
├── profiles.py      # SafetyProfile loader + 5 built-in profiles
├── scanner.py       # Code vulnerability scanner (language-aware)
├── engines.py       # AnalysisEngine protocol, RegexEngine, EngineRegistry
├── deep_engine.py   # DeepEngine: cross-line taint tracking (ast for Python, regex for JS)
├── semantic_engine.py # SemanticEngine: structure-aware confidence adjustment
├── pipeline.py      # Result pipeline: multi-engine merge, dedup, timing
├── triage.py        # CWE-specific triage prompts for AI-assisted FP filtering
├── patterns/        # Language-specific pattern sets
│   ├── __init__.py  # Registry: LANGUAGE_PATTERNS, EXTENSION_MAP, REMEDIATION_MAP
│   ├── common.py    # 3 cross-language patterns + remediation
│   ├── python.py    # 15 Python patterns + remediation
│   ├── javascript.py # 7 JS/TS patterns + remediation
│   ├── go.py        # 13 Go patterns + remediation
│   ├── java.py      # 12 Java patterns + remediation
│   ├── ruby.py      # 16 Ruby/Rails patterns + remediation
│   ├── php.py       # 20 PHP patterns + remediation
│   └── csharp.py    # 22 C#/ASP.NET patterns + remediation
├── secrets.py       # Secret/credential detection (12+ patterns)
├── injection.py     # Prompt injection detector (9+ patterns)
├── pii.py           # PII detection (regex + optional Presidio)
├── content.py       # Content moderation (heuristic patterns)
├── config.py        # Project config discovery (.guardianshield.yaml/.json)
├── enrichment.py    # Finding enrichment (code context, explanations, CWE/OWASP references)
├── feedback.py      # False positive feedback loop (per-project SQLite store)
├── dedup.py         # Finding deduplication via SHA-256 fingerprinting
├── osv.py           # OSV.dev local-first dependency scanner (PyPI, npm, Go, Packagist)
├── manifest.py      # Manifest file parser (11 formats, 4 ecosystems)
├── audit.py         # SQLite audit log
├── core.py          # GuardianShield orchestrator (scan_file, scan_directory, scan_dependencies_in_directory)
└── mcp_server.py    # MCP server (21 tools, 3 resources, 3 prompts)
```

## Key Concepts

- **Finding fields**: All findings include `range` (LSP format), `confidence` (0.0–1.0), `cwe_ids`, optional `remediation`, and `details` (enriched context)
- **Enriched details**: Every finding includes `details` dict with code context (surrounding lines), match explanation, CWE/OWASP references, and scanner metadata
- **False positive feedback**: `FalsePositiveDB` stores per-project FP records; findings are auto-annotated with `false_positive` or `potential_false_positive` metadata
- **Language detection**: `scan_file` and `scan_code` auto-detect language from file extension via `EXTENSION_MAP`
- **Deduplication**: `FindingDeduplicator` tracks fingerprints across scans, returns delta (new/unchanged/removed)
- **Project config**: Place `.guardianshield.json` or `.guardianshield.yaml` in project root for profile, severity overrides, and exclude paths
- **Streaming**: `scan_directory` emits JSON-RPC notifications (`guardianshield/scanProgress`, `guardianshield/finding`)
- **Redaction**: `GuardianShieldMCPServer(redact_responses=True)` replaces matched_text with `[REDACTED:<hash>]`
- **Manifest parsing**: `parse_manifest` auto-detects 11 formats; `scan_dependencies` walks directories to find and scan all manifests
- **Version-aware CVE matching**: PEP 440 + semver parsing with affected range filtering (confidence 1.0 confirmed, 0.7 indeterminate)
- **4 ecosystems**: PyPI, npm, Go, Packagist — all backed by local OSV.dev SQLite cache
- **Analysis engines**: Pluggable `AnalysisEngine` protocol with `RegexEngine` (line-by-line patterns), `DeepEngine` (cross-line taint tracking), and `SemanticEngine` (confidence adjustment); `EngineRegistry` per `GuardianShield` instance; `scan_code` delegates through enabled engines; default engines: `["regex"]`
- **DeepEngine**: 5-phase taint analysis — assignment extraction (Python AST / JS regex), source identification (19 Python + 10 JS patterns), multi-pass propagation (max 5, scope-aware), sink detection (12 Python + 10 JS sinks), finding conversion with confidence 0.70–0.90
- **SemanticEngine**: Post-processing confidence adjuster — test files (-0.3), dead code (-0.3), exception handlers (-0.15), uncalled functions (-0.2), unused imports (-0.25); cumulative with floor 0.1; Python AST + JS regex heuristics
- **Result pipeline**: `merge_engine_findings()` deduplicates cross-engine findings by (file_path, line_number, finding_type), boosts confidence +0.1 per confirming engine; `timed_analyze()` wraps engines with timing; `EngineTimingResult` in `status()`
- **CWE-specific triage prompts**: `triage.py` provides 7 vulnerability-type triage guides (SQL injection, XSS, command injection, path traversal, insecure function, insecure pattern, secret) with true/false positive indicators, targeted questions, and context guidance. Exposed as `triage-finding` MCP prompt (3 prompts total). Zero telemetry — AI evaluates findings locally.
- **Graceful audit degradation**: `_log()` catches all exceptions so scans succeed even when audit DB is unwritable
- **scan_dependencies_in_directory**: Returns `(findings, metadata)` tuple — metadata contains `manifests_found` and `dependency_count` directly (no audit log round-trip)

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v          # 1627 tests
ruff check src/ tests/    # Linting
```

## Memory (MemoryMesh)

MemoryMesh is configured as an MCP tool in this project. It adds persistent,
structured, cross-tool memory on top of your existing memory system. Use it
alongside your default memory -- it enhances, not replaces.

### At the start of every conversation

Call `mcp__memorymesh__recall` with a summary of the user's request to load
prior context, decisions, and patterns. If `session_start` is available,
call it to load user profile, guardrails, and project context.

### When to `recall`

- **Start of every conversation**: Check for relevant prior context.
- **Before making decisions**: Check if this was decided before.
- **When debugging**: Check if this problem was encountered previously.

### When to `remember`

- **When the user says "remember this"**: Store it with a category.
- **After completing a task**: Store key decisions and patterns.
  Use `category` to classify: `"decision"`, `"pattern"`, `"context"`.
- **When the user teaches you something**: Use `category: "preference"`
  or `category: "guardrail"` -- these auto-route to global scope.
- **After fixing a non-trivial bug**: Use `category: "mistake"`.

### Scope guidance

Categories auto-route scope. If not using categories:
- Use `scope: "project"` for project-specific decisions.
- Use `scope: "global"` for user preferences and identity.
