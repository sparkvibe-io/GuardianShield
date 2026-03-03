# Changelog

All notable changes to GuardianShield are documented here.

## [1.2.0] — 2026-03-02

### Added
- **SARIF 2.1.0 export**: New `export_sarif` MCP tool and `findings_to_sarif()` / `findings_to_sarif_json()` Python API
- SARIF output compatible with GitHub Code Scanning, VS Code SARIF Viewer, and CI pipelines
- Includes `partialFingerprints` for GitHub upload compatibility
- CWE taxonomy and security-severity scoring in SARIF output

### Changed
- MCP tools: 21 → 22 | Tests: 1627 → 1707

## [1.1.1] — 2026-03-03

### Changed
- Documentation updated for SemanticEngine, result pipeline, and CWE-specific triage prompts
- ROADMAP rewritten as phased vision document (v1.2–v1.5) with cross-AI review findings
- `server-card.json` includes `triage-finding` prompt
- AI instruction files (CLAUDE.md, AGENTS.md) removed from version control

## [1.1.0] — 2026-03-02

### Added
- **Multi-engine analysis pipeline**: Pluggable `AnalysisEngine` protocol
- **RegexEngine**: Existing scanner wrapped with engine tagging
- **DeepEngine**: Cross-line taint tracking (Python `ast` + JS/TS regex). 19+10 source patterns, 12+10 sink patterns, confidence 0.70–0.90
- **SemanticEngine**: Structure-aware confidence adjustment — test files (-0.3), dead code (-0.3), exception handlers (-0.15), uncalled functions (-0.2), unused imports (-0.25)
- **Result pipeline**: `merge_engine_findings()` cross-engine dedup + confidence boost; `timed_analyze()` with `EngineTimingResult`
- **CWE-specific triage prompts**: `triage-finding` MCP prompt for 7 vulnerability types
- **Engine management**: `list_engines` and `set_engine` MCP tools
- **Finding enrichment**: Code context, CWE/OWASP references in `details` dict
- **False positive feedback**: Per-project SQLite with `mark_false_positive`, `list_false_positives`, `unmark_false_positive`
- 5 new language pattern sets: Go (13), Java (12), Ruby (16), PHP (20), C# (22)

### Changed
- MCP tools: 16 → 21 | Prompts: 2 → 3 | Engines: 1 → 3
- Patterns: 25 → 108+ (7 languages) | Tests: 934 → 1627
- `scan_code` gains optional `engines` parameter
- `shield_status` includes `engine_timings`

## [1.0.2] — 2026-02-28

### Fixed
- **CVSS vector parsing**: OSV API returns CVSS vector strings, not numeric scores — all vulnerabilities were incorrectly mapped to LOW severity
- **Stale version in status()**: `core.py` hardcoded `"0.2.0"` instead of using `__version__`
- **Double audit logging**: `scan_dependencies_in_directory` logged twice (once via `check_dependencies`, once directly)
- **Silent file/manifest skipping**: Added logging for files and manifests skipped during directory scans
- **Notification callback errors**: Wrapped MCP notification callbacks to prevent scan aborts on broken pipes
- **Overly broad exception handling**: Narrowed bare `except Exception` blocks in osv.py and manifest.py

### Added
- MCP registry ownership tag (`mcp-name`) in README for Official MCP Registry validation
- `dependencies` and `directory_dependencies` to audit_log scan_type enum

## [1.0.1] — 2026-02-27

### Added
- CI workflow: Python 3.9/3.11/3.13 matrix with ruff linting and pytest
- PyPI publish workflow: trusted publisher via OIDC on GitHub release
- Registry configs: smithery.yaml, glama.json, server.json, MCP server-card.json
- CHANGELOG.md with full version history
- 400×400 PNG logo for marketplace submissions
- MCP autodiscovery via .well-known/mcp/server-card.json

### Changed
- README: expanded tool table from 9→16, added badges, features, config section
- Docs workflow: copies .well-known into site/ for autodiscovery
- .gitignore: excludes research/vision/critique files

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
