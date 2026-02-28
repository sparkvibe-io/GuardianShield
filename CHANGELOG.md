# Changelog

All notable changes to GuardianShield are documented here.

## [1.0.0] — 2025-06-01

### Added
- **Version-aware CVE matching**: PEP 440 + npm semver parsing with affected range filtering
- **11 manifest parsers**: requirements.txt, package.json, pyproject.toml, package-lock.json, yarn.lock, pnpm-lock.yaml, Pipfile.lock, go.mod, go.sum, composer.json, composer.lock
- **4 ecosystems**: PyPI, npm, Go, Packagist — all backed by local OSV.dev SQLite cache
- **`scan_dependencies` tool**: Recursively scan directories for manifest files and check all dependencies
- **`parse_manifest` tool**: Parse any supported manifest file into structured dependency objects
- **`scan_file` tool**: Scan a single source file with auto-detected language
- **`scan_directory` tool**: Recursive directory scanning with filtering and streaming progress
- **`test_pattern` tool**: Regex sandbox for developing custom vulnerability patterns
- **`check_dependencies` tool**: Check packages for known CVEs via OSV.dev
- **`sync_vulnerabilities` tool**: Sync local OSV vulnerability database
- **MCP integration tests**: Comprehensive tests for parse_manifest, double-initialize, BrokenPipeError
- **Connection management**: BrokenPipeError handling, SIGTERM signal handler
- **CVSS v2/v3/v4 fallback**: Preference order v3 > v4 > v2 for severity mapping
- **Staleness-aware sync**: Auto-sync stale OSV data before dependency checks
- **Rate limiting**: Inter-package delay + exponential backoff on 429/5xx responses

### Changed
- Total MCP tools: 9 → 16
- Total tests: 450 → 934
- Version classifier upgraded to "Production/Stable"

## [0.2.0] — 2025-05-01

### Added
- **Language-aware code scanning**: Auto-detects Python/JS/TS from file extension via `EXTENSION_MAP`
- **Pattern system**: `patterns/` package with common, Python (15 patterns), and JavaScript (7 patterns) modules
- **Remediation guidance**: Before/after code examples and auto-fixable flags on findings
- **LSP-compatible ranges**: All findings include `Range` with start/end line/character
- **Finding deduplication**: SHA-256 fingerprinting returns delta (new/unchanged/removed)
- **Project config**: `.guardianshield.json`/`.yaml` with profile, severity overrides, exclude paths
- **`shield_status` tool**: Health, capabilities, and configuration status
- **Response redaction**: `redact_responses=True` replaces matched_text with `[REDACTED:<hash>]`
- **Confidence scores**: 0.0–1.0 on all findings
- **CWE IDs**: Associated CWE identifiers on vulnerability findings
- **SQLite audit log**: Persistent scan history at `~/.guardianshield/audit.db`

### Changed
- Finding model expanded with `range`, `confidence`, `cwe_ids`, `remediation` fields
- Pattern tuples now 7-element: (name, regex, finding_type, severity, description, confidence, cwe_ids)

## [0.1.0] — 2025-04-01

### Added
- Initial release
- **`scan_code`**: Code vulnerability scanning (SQL injection, XSS, command injection, path traversal)
- **`scan_input`**: Prompt injection detection (9+ patterns)
- **`scan_output`**: PII detection and content moderation
- **`check_secrets`**: Secret/credential detection (12+ patterns)
- **`get_profile` / `set_profile`**: 5 safety profiles (general, education, healthcare, finance, children)
- **`audit_log` / `get_findings`**: Audit log querying and finding retrieval
- MCP server over stdio JSON-RPC
- Zero external dependencies (Python stdlib only)
- Python 3.9+ support
