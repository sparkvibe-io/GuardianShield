---
title: API Reference
description: Complete Python API reference for GuardianShield — classes, methods, and data types.
---

# API Reference

GuardianShield can be used as a **Python library** in addition to running as an MCP server. Import the top-level class, create an instance, and call its scan methods directly -- no server process required.

```python
from guardianshield import GuardianShield

shield = GuardianShield()
findings = shield.scan_code('password = "hunter2"')
findings = shield.scan_input("Ignore previous instructions")
findings = shield.scan_output("My SSN is 123-45-6789")
```

All public symbols are available from the `guardianshield` package:

```python
from guardianshield import (
    GuardianShield,
    Finding,
    FindingType,
    Severity,
    Range,
    Remediation,
    SafetyProfile,
    ScannerConfig,
)

# v0.2 additions
from guardianshield.config import ProjectConfig, discover_config
from guardianshield.dedup import FindingDeduplicator, DedupResult
from guardianshield.osv import Dependency, OsvCache, check_dependencies
```

---

## GuardianShield

::: guardianshield.core.GuardianShield

The main orchestrator that ties together all scanner modules, safety profiles, and the audit log. Each scan method checks the active profile, calls the relevant scanner(s), logs results to the audit database, and returns a list of `Finding` objects.

### Constructor

```python
GuardianShield(
    profile: str = "general",
    audit_path: str | None = None,
    project_config: ProjectConfig | None = None,
)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `profile` | `str` | `"general"` | Name of the safety profile to activate. One of the built-in profiles (`general`, `education`, `healthcare`, `finance`, `children`) or a custom YAML profile name. |
| `audit_path` | `str \| None` | `None` | Path to the SQLite audit database. `None` uses the default `~/.guardianshield/audit.db`. |
| `project_config` | `ProjectConfig \| None` | `None` | Optional project configuration loaded from `.guardianshield.json` or `.guardianshield.yaml`. If the config specifies a `profile` and the `profile` argument is `"general"` (default), the config file's profile is used. |

```python
shield = GuardianShield()                                  # defaults
shield = GuardianShield(profile="healthcare")              # stricter profile
shield = GuardianShield(audit_path="/tmp/audit.db")        # custom audit path

# With project config
from guardianshield.config import discover_config
config = discover_config()
shield = GuardianShield(project_config=config)
```

### Methods

#### `scan_code`

Scan source code for vulnerabilities and hardcoded secrets. Combines the code vulnerability scanner and the secret detector according to the active profile.

```python
scan_code(
    code: str,
    file_path: str | None = None,
    language: str | None = None,
) -> list[Finding]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `code` | `str` | -- | The source code to scan. |
| `file_path` | `str \| None` | `None` | Optional file path for context in findings. |
| `language` | `str \| None` | `None` | Programming language hint (e.g. `"python"`, `"javascript"`). |

**Returns:** `list[Finding]` -- all detected vulnerabilities and secrets.

---

#### `scan_input`

Check user or agent input for prompt injection attempts.

```python
scan_input(text: str) -> list[Finding]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `text` | `str` | -- | The input text to analyse. |

**Returns:** `list[Finding]` -- any detected prompt injection patterns.

---

#### `scan_output`

Check AI-generated output for PII leaks and content-policy violations.

```python
scan_output(text: str) -> list[Finding]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `text` | `str` | -- | The output text to analyse. |

**Returns:** `list[Finding]` -- detected PII and content violations.

---

#### `check_secrets`

Dedicated secret and credential detection scan.

```python
check_secrets(
    text: str,
    file_path: str | None = None,
) -> list[Finding]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `text` | `str` | -- | The text to scan for secrets. |
| `file_path` | `str \| None` | `None` | Optional file path for context in findings. |

**Returns:** `list[Finding]` -- detected secrets and credentials.

---

#### `scan_file`

Scan a single source file for vulnerabilities and secrets. Reads the file, auto-detects language from extension if not provided, and delegates to `scan_code`.

```python
scan_file(
    path: str,
    language: str | None = None,
) -> list[Finding]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `path` | `str` | -- | Absolute or relative path to the file. |
| `language` | `str \| None` | `None` | Optional language hint. Auto-detected from extension when omitted. |

**Returns:** `list[Finding]` -- all detected vulnerabilities and secrets in the file.

**Raises:** `FileNotFoundError` if the path does not exist. `IsADirectoryError` if the path is a directory.

---

#### `scan_directory`

Recursively scan a directory for vulnerabilities and secrets across all supported file types.

```python
scan_directory(
    path: str,
    extensions: list[str] | None = None,
    exclude: list[str] | None = None,
    on_progress: Callable[[str, int, int], None] | None = None,
    on_finding: Callable[[Finding], None] | None = None,
) -> list[Finding]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `path` | `str` | -- | Root directory to scan. |
| `extensions` | `list[str] \| None` | `None` | File extensions to include (e.g. `[".py", ".js"]`). Defaults to all extensions in `EXTENSION_MAP`. |
| `exclude` | `list[str] \| None` | `None` | Glob patterns for paths to skip (e.g. `["node_modules/*", ".git/*"]`). |
| `on_progress` | `Callable \| None` | `None` | Optional callback `(file_path, files_done, total)` invoked before each file is scanned. |
| `on_finding` | `Callable \| None` | `None` | Optional callback invoked for each individual `Finding`. |

**Returns:** `list[Finding]` -- a flat list of all findings across all scanned files.

**Raises:** `NotADirectoryError` if the path is not a directory.

---

#### `scan_dependencies_in_directory`

Walk a directory tree, detect manifest files (requirements.txt, package.json, go.mod, composer.json, etc.), parse dependencies, and check them for known vulnerabilities.

```python
scan_dependencies_in_directory(
    path: str,
    exclude: list[str] | None = None,
    on_finding: Callable[[Finding], None] | None = None,
) -> list[Finding]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `path` | `str` | -- | Root directory to walk. |
| `exclude` | `list[str] \| None` | `None` | Glob patterns for paths to skip. |
| `on_finding` | `Callable \| None` | `None` | Optional callback invoked for each `Finding`. |

**Returns:** `list[Finding]` -- findings with `FindingType.DEPENDENCY_VULNERABILITY` for any packages with known CVEs.

**Raises:** `NotADirectoryError` if the path is not a directory.

---

#### `set_profile`

Switch to a different safety profile at runtime.

```python
set_profile(name: str) -> SafetyProfile
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `name` | `str` | -- | Profile name. One of the built-in profiles or a custom YAML profile. |

**Returns:** The newly-activated `SafetyProfile` instance.

**Raises:** `ValueError` if the profile name is unknown.

---

#### `get_audit_log`

Query the audit log for past scan events.

```python
get_audit_log(
    scan_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `scan_type` | `str \| None` | `None` | Filter by scan type (`"code"`, `"input"`, `"output"`, `"secrets"`). `None` returns all. |
| `limit` | `int` | `50` | Maximum number of entries to return. |
| `offset` | `int` | `0` | Number of entries to skip (for pagination). |

**Returns:** `list[dict]` -- audit log entries, newest first.

---

#### `get_findings`

Retrieve past findings stored in the audit database.

```python
get_findings(
    audit_id: int | None = None,
    finding_type: str | None = None,
    severity: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `audit_id` | `int \| None` | `None` | Filter findings by a specific audit log entry ID. |
| `finding_type` | `str \| None` | `None` | Filter by finding type (e.g. `"secret"`, `"sql_injection"`). |
| `severity` | `str \| None` | `None` | Filter by minimum severity (e.g. `"high"`). |
| `limit` | `int` | `100` | Maximum number of findings to return. |

**Returns:** `list[dict]` -- serialized finding records.

---

#### `status`

Return health and configuration information for the current instance.

```python
status() -> dict[str, Any]
```

**Returns:** A dict containing:

| Key | Type | Description |
|---|---|---|
| `version` | `str` | GuardianShield version. |
| `profile` | `str` | Active profile name. |
| `available_profiles` | `list[str]` | All known profile names. |
| `scanners` | `dict[str, bool]` | Enabled/disabled state for each scanner. |
| `audit` | `dict` | Aggregate statistics from the audit log. |

---

#### `close`

Close the underlying audit database connection.

```python
close() -> None
```

---

### Properties

| Property | Type | Description |
|---|---|---|
| `profile` | `SafetyProfile` | The currently active safety profile (read-only). |
| `project_config` | `ProjectConfig \| None` | The active project configuration, if any (read-only). |

---

## Finding

::: guardianshield.findings.Finding

A `@dataclass` representing a single security finding produced by any scanner.

```python
@dataclass
class Finding:
    finding_type: FindingType
    severity: Severity
    message: str
    matched_text: str = ""
    line_number: int = 0
    file_path: str | None = None
    scanner: str = ""
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    metadata: dict[str, Any] = field(default_factory=dict)
    range: Range | None = None
    confidence: float | None = None
    cwe_ids: list[str] = field(default_factory=list)
    remediation: Remediation | None = None
```

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `finding_type` | `FindingType` | -- | The category of the finding. |
| `severity` | `Severity` | -- | How severe the finding is. |
| `message` | `str` | -- | Human-readable description. |
| `matched_text` | `str` | `""` | The text that triggered the finding. Redacted for secrets and PII. |
| `line_number` | `int` | `0` | 1-based line number where the finding was detected. |
| `file_path` | `str \| None` | `None` | File path associated with the finding. |
| `scanner` | `str` | `""` | Name of the scanner that produced this finding. |
| `finding_id` | `str` | *(auto-generated)* | Unique 12-character hex identifier. |
| `metadata` | `dict[str, Any]` | `{}` | Additional scanner-specific data. |
| `range` | `Range \| None` | `None` | Precise character range in LSP diagnostic format (0-based). |
| `confidence` | `float \| None` | `None` | Detection confidence between 0.0 and 1.0. |
| `cwe_ids` | `list[str]` | `[]` | List of CWE identifiers (e.g. `["CWE-89"]`). |
| `remediation` | `Remediation \| None` | `None` | Machine-readable fix suggestion with before/after examples. |

### Methods

#### `to_dict`

Serialize the finding to a plain Python dict. Enum values are converted to their string representations.

```python
to_dict() -> dict[str, Any]
```

#### `to_json`

Serialize the finding to a JSON string.

```python
to_json() -> str
```

#### `from_dict` *(classmethod)*

Deserialize a finding from a plain dict.

```python
Finding.from_dict(data: dict[str, Any]) -> Finding
```

| Parameter | Type | Description |
|---|---|---|
| `data` | `dict[str, Any]` | Dict with keys matching the `Finding` fields. Values for `finding_type` and `severity` should be the string enum values. |

---

## Severity

::: guardianshield.findings.Severity

A `str` enum representing the severity level of a finding. Values are ordered from most to least severe.

```python
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"
```

| Member | Value | Description |
|---|---|---|
| `CRITICAL` | `"critical"` | Immediate security risk. Must be addressed before deployment. |
| `HIGH` | `"high"` | Serious vulnerability or exposure. |
| `MEDIUM` | `"medium"` | Moderate risk that should be reviewed. |
| `LOW` | `"low"` | Minor issue or informational finding. |
| `INFO` | `"info"` | Purely informational, no action required. |

---

## FindingType

::: guardianshield.findings.FindingType

A `str` enum categorizing the kind of security finding.

```python
class FindingType(str, Enum):
    SECRET                   = "secret"
    SQL_INJECTION            = "sql_injection"
    XSS                      = "xss"
    COMMAND_INJECTION        = "command_injection"
    PATH_TRAVERSAL           = "path_traversal"
    INSECURE_FUNCTION        = "insecure_function"
    INSECURE_PATTERN         = "insecure_pattern"
    PROMPT_INJECTION         = "prompt_injection"
    PII_LEAK                 = "pii_leak"
    CONTENT_VIOLATION        = "content_violation"
    DEPENDENCY_VULNERABILITY = "dependency_vulnerability"
```

| Member | Value | Description |
|---|---|---|
| `SECRET` | `"secret"` | Hardcoded secret, API key, token, or credential. |
| `SQL_INJECTION` | `"sql_injection"` | SQL injection vulnerability via string formatting or concatenation. |
| `XSS` | `"xss"` | Cross-site scripting vulnerability. |
| `COMMAND_INJECTION` | `"command_injection"` | OS command injection via shell execution functions. |
| `PATH_TRAVERSAL` | `"path_traversal"` | Directory traversal vulnerability. |
| `INSECURE_FUNCTION` | `"insecure_function"` | Use of a known insecure function. |
| `INSECURE_PATTERN` | `"insecure_pattern"` | General insecure coding pattern. |
| `PROMPT_INJECTION` | `"prompt_injection"` | Prompt injection or jailbreak attempt. |
| `PII_LEAK` | `"pii_leak"` | Personally identifiable information detected in output. |
| `CONTENT_VIOLATION` | `"content_violation"` | Content that violates the active moderation policy. |
| `DEPENDENCY_VULNERABILITY` | `"dependency_vulnerability"` | Known CVE in a project dependency (detected via OSV.dev). |

---

## SafetyProfile

::: guardianshield.profiles.SafetyProfile

A `@dataclass` bundling scanner configurations and content policies into a named profile.

```python
@dataclass
class SafetyProfile:
    name: str
    description: str
    code_scanner: ScannerConfig = ScannerConfig()
    secret_scanner: ScannerConfig = ScannerConfig()
    injection_detector: ScannerConfig = ScannerConfig()
    pii_detector: ScannerConfig = ScannerConfig()
    content_moderator: ScannerConfig = ScannerConfig()
    blocked_categories: list[str] = field(default_factory=list)
```

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | `str` | -- | Short identifier for the profile (e.g. `"general"`, `"healthcare"`). |
| `description` | `str` | -- | Human-readable description of the profile's purpose. |
| `code_scanner` | `ScannerConfig` | `ScannerConfig()` | Configuration for the code vulnerability scanner. |
| `secret_scanner` | `ScannerConfig` | `ScannerConfig()` | Configuration for the secret/credential scanner. |
| `injection_detector` | `ScannerConfig` | `ScannerConfig()` | Configuration for the prompt injection detector. |
| `pii_detector` | `ScannerConfig` | `ScannerConfig()` | Configuration for the PII detector. |
| `content_moderator` | `ScannerConfig` | `ScannerConfig()` | Configuration for the content moderator. |
| `blocked_categories` | `list[str]` | `[]` | Content categories to block outright (e.g. `"violence"`, `"self_harm"`, `"illegal_activity"`). |

### Built-in Profiles

| Profile | Sensitivity | Blocked Categories | Use Case |
|---|---|---|---|
| `general` | medium | *(none)* | General-purpose development. |
| `education` | medium | `violence`, `self_harm` | Educational platforms. |
| `healthcare` | high | `violence` | Healthcare applications with strict PII protection. |
| `finance` | high | `illegal_activity` | Financial applications with critical secret detection. |
| `children` | high | `violence`, `self_harm`, `illegal_activity` | Child-facing applications with maximum sensitivity. |

### Methods

#### `to_dict`

```python
to_dict() -> dict[str, Any]
```

Serialize the profile to a plain dict.

#### `from_dict` *(classmethod)*

```python
SafetyProfile.from_dict(data: dict[str, Any]) -> SafetyProfile
```

Deserialize a profile from a plain dict.

---

## ScannerConfig

::: guardianshield.profiles.ScannerConfig

A `@dataclass` representing the configuration for an individual scanner within a safety profile.

```python
@dataclass
class ScannerConfig:
    enabled: bool = True
    sensitivity: str = "medium"
    custom_patterns: list[str] = field(default_factory=list)
```

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | `bool` | `True` | Whether the scanner is active. |
| `sensitivity` | `str` | `"medium"` | Detection sensitivity: `"low"`, `"medium"`, or `"high"`. Higher sensitivity produces more findings but may increase false positives. |
| `custom_patterns` | `list[str]` | `[]` | Extra regex patterns the scanner should check in addition to its built-in rules. |

### Methods

#### `to_dict`

```python
to_dict() -> dict[str, Any]
```

Serialize to a plain dict.

#### `from_dict` *(classmethod)*

```python
ScannerConfig.from_dict(data: dict[str, Any]) -> ScannerConfig
```

Deserialize from a plain dict.

---

## Range

::: guardianshield.findings.Range

An LSP-compatible character range for precise finding location. All values are 0-based to match the [LSP Diagnostic specification](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#range).

```python
@dataclass
class Range:
    start_line: int
    start_col: int
    end_line: int
    end_col: int
```

### Fields

| Field | Type | Description |
|---|---|---|
| `start_line` | `int` | 0-based line number of the range start. |
| `start_col` | `int` | 0-based column offset of the range start. |
| `end_line` | `int` | 0-based line number of the range end. |
| `end_col` | `int` | 0-based column offset of the range end. |

### Methods

#### `to_lsp`

Serialize to LSP `Range` format (`{"start": {"line": ..., "character": ...}, "end": ...}`).

```python
to_lsp() -> dict[str, Any]
```

#### `from_lsp` *(classmethod)*

Deserialize from LSP `Range` format.

```python
Range.from_lsp(data: dict[str, Any]) -> Range
```

---

## Remediation

::: guardianshield.findings.Remediation

A machine-readable fix suggestion attached to a finding.

```python
@dataclass
class Remediation:
    description: str
    before: str = ""
    after: str = ""
    auto_fixable: bool = False
```

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `description` | `str` | -- | Human-readable description of the fix. |
| `before` | `str` | `""` | Example of the vulnerable code. |
| `after` | `str` | `""` | Example of the fixed code. |
| `auto_fixable` | `bool` | `False` | Whether the fix can be applied automatically. |

### Methods

#### `to_dict`

```python
to_dict() -> dict[str, Any]
```

Serialize to a plain dict. Empty strings are omitted.

#### `from_dict` *(classmethod)*

```python
Remediation.from_dict(data: dict[str, Any]) -> Remediation
```

Deserialize from a plain dict.

---

## ProjectConfig

::: guardianshield.config.ProjectConfig

Per-project GuardianShield configuration loaded from `.guardianshield.json` or `.guardianshield.yaml`.

```python
@dataclass
class ProjectConfig:
    profile: str | None = None
    severity_overrides: dict[str, str] = field(default_factory=dict)
    exclude_paths: list[str] = field(default_factory=list)
    custom_patterns: list[dict[str, Any]] = field(default_factory=list)
    config_path: str | None = None
```

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `profile` | `str \| None` | `None` | Name of the safety profile to use. |
| `severity_overrides` | `dict[str, str]` | `{}` | Map of `pattern_name` to severity override (e.g. `{"sql_concat": "critical"}`). |
| `exclude_paths` | `list[str]` | `[]` | Glob patterns for paths to exclude from directory scanning. |
| `custom_patterns` | `list[dict]` | `[]` | Custom pattern definitions. |
| `config_path` | `str \| None` | `None` | Path to the config file that was loaded. |

---

## `discover_config`

::: guardianshield.config.discover_config

Walk up the directory tree from a starting directory looking for a `.guardianshield.json`, `.guardianshield.yaml`, or `.guardianshield.yml` file.

```python
discover_config(
    start_dir: str | None = None,
    max_depth: int = 10,
) -> ProjectConfig | None
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `start_dir` | `str \| None` | `None` | Directory to start searching from. Defaults to the current working directory. |
| `max_depth` | `int` | `10` | Maximum number of parent directories to traverse. |

**Returns:** A `ProjectConfig` if a config file is found, otherwise `None`.

---

## FindingDeduplicator

::: guardianshield.dedup.FindingDeduplicator

Tracks finding fingerprints across scans. On each call to `deduplicate()`, returns a `DedupResult` with delta information (new, unchanged, removed).

```python
dedup = FindingDeduplicator()

# First scan — everything is new.
result1 = dedup.deduplicate(findings_1)

# Second scan — only delta is reported.
result2 = dedup.deduplicate(findings_2)
```

### Methods

#### `deduplicate`

```python
deduplicate(findings: list[Finding]) -> DedupResult
```

Compare findings against the previous scan and return a delta. Updates the internal baseline.

#### `reset`

```python
reset() -> None
```

Clear the fingerprint baseline.

### Properties

| Property | Type | Description |
|---|---|---|
| `previous_fingerprints` | `set[str]` | The set of fingerprints from the last scan. |

---

## DedupResult

::: guardianshield.dedup.DedupResult

Result of deduplicating findings against a previous scan.

```python
@dataclass
class DedupResult:
    scan_id: str = field(default_factory=...)
    new: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    all_findings: list[Finding] = field(default_factory=list)
```

### Fields

| Field | Type | Description |
|---|---|---|
| `scan_id` | `str` | Unique 12-character hex identifier for this scan session. |
| `new` | `list[Finding]` | Findings not present in the previous scan. |
| `unchanged` | `list[Finding]` | Findings matching a previous fingerprint. |
| `removed` | `list[str]` | Fingerprints from the previous scan that are no longer present. |
| `all_findings` | `list[Finding]` | The complete list of current findings. |

---

## Dependency

::: guardianshield.osv.Dependency

A single package dependency to check for known vulnerabilities.

```python
@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str = "PyPI"
```

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | `str` | -- | Package name (e.g. `"requests"`, `"lodash"`). |
| `version` | `str` | -- | Installed version string (e.g. `"2.28.0"`). |
| `ecosystem` | `str` | `"PyPI"` | Package ecosystem: `"PyPI"`, `"npm"`, `"Go"`, or `"Packagist"`. |

---

## OsvCache

::: guardianshield.osv.OsvCache

Local SQLite cache for OSV.dev vulnerability data. Enables offline dependency scanning after initial sync.

```python
cache = OsvCache()                            # default path
cache = OsvCache(db_path="/tmp/osv_cache.db") # custom path
```

### Constructor

| Parameter | Type | Default | Description |
|---|---|---|---|
| `db_path` | `str \| None` | `None` | Path to the SQLite cache file. Default: `~/.guardianshield/osv_cache.db`. |

### Methods

#### `sync`

Fetch vulnerability data from OSV.dev and update the local cache.

```python
sync(ecosystems: list[str] | None = None) -> dict[str, Any]
```

#### `lookup`

Look up vulnerabilities for a specific package.

```python
lookup(name: str, version: str, ecosystem: str) -> list[dict]
```

#### `is_stale`

Check if the cache is older than a given threshold.

```python
is_stale(max_age_hours: int = 24) -> bool
```

---

## `check_dependencies`

::: guardianshield.osv.check_dependencies

Check a list of dependencies against the local OSV vulnerability cache.

```python
from guardianshield.osv import check_dependencies, Dependency

deps = [
    Dependency("requests", "2.28.0", "PyPI"),
    Dependency("lodash", "4.17.20", "npm"),
]
findings = check_dependencies(deps)
```

| Parameter | Type | Description |
|---|---|---|
| `dependencies` | `list[Dependency]` | List of dependencies to check. |

**Returns:** `list[Finding]` -- findings with `FindingType.DEPENDENCY_VULNERABILITY` for any packages with known CVEs.

---

## `parse_manifest`

::: guardianshield.manifest.parse_manifest

Auto-detect manifest format from filename and parse dependencies.

```python
from guardianshield.manifest import parse_manifest

deps = parse_manifest("requests==2.28.0\nflask>=2.0.0\n", "requirements.txt")
```

| Parameter | Type | Description |
|---|---|---|
| `text` | `str` | Contents of the manifest file. |
| `filename` | `str` | Filename for format detection (e.g. `"requirements.txt"`, `"package.json"`, `"go.mod"`). |

**Returns:** `list[Dependency]` -- parsed dependencies with name, version, and ecosystem.

**Raises:** `ValueError` if the filename is not recognized.

**Supported filenames:**

| Filename | Ecosystem | Parser |
|---|---|---|
| `requirements.txt` | PyPI | `parse_requirements_txt` |
| `package.json` | npm | `parse_package_json` |
| `pyproject.toml` | PyPI | `parse_pyproject_toml` |
| `package-lock.json` | npm | `parse_package_lock_json` |
| `yarn.lock` | npm | `parse_yarn_lock` |
| `pnpm-lock.yaml` | npm | `parse_pnpm_lock_yaml` |
| `Pipfile.lock` | PyPI | `parse_pipfile_lock` |
| `go.mod` | Go | `parse_go_mod` |
| `go.sum` | Go | `parse_go_sum` |
| `composer.json` | Packagist | `parse_composer_json` |
| `composer.lock` | Packagist | `parse_composer_lock` |

### Individual Parsers

Each parser can be called directly for fine-grained control:

```python
from guardianshield.manifest import (
    parse_requirements_txt,
    parse_package_json,
    parse_pyproject_toml,
    parse_package_lock_json,
    parse_yarn_lock,
    parse_pnpm_lock_yaml,
    parse_pipfile_lock,
    parse_go_mod,
    parse_go_sum,
    parse_composer_json,
    parse_composer_lock,
)
```

All parsers accept a single `text: str` parameter (the file contents) and return `list[Dependency]`.

---

## Low-level Scanner Functions

For advanced use cases, you can call individual scanner modules directly, bypassing profile configuration and audit logging.

!!! note
    The high-level `GuardianShield` class is the recommended API. These low-level functions are useful when you need fine-grained control over individual scanners or want to integrate a single scanner into your own pipeline.

### `guardianshield.scanner.scan_code`

Scan source code for common security vulnerabilities (SQL injection, XSS, command injection, path traversal, insecure functions).

```python
from guardianshield.scanner import scan_code

scan_code(
    code: str,
    sensitivity: str = "medium",
    file_path: str | None = None,
    language: str | None = None,
) -> list[Finding]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `code` | `str` | -- | Source code to scan. |
| `sensitivity` | `str` | `"medium"` | Detection sensitivity: `"low"`, `"medium"`, or `"high"`. |
| `file_path` | `str \| None` | `None` | File path for finding context. |
| `language` | `str \| None` | `None` | Language hint for the scanner. |

---

### `guardianshield.secrets.check_secrets`

Scan text for hardcoded secrets, API keys, tokens, and credentials. Matched values are automatically redacted in the returned findings.

```python
from guardianshield.secrets import check_secrets

check_secrets(
    text: str,
    sensitivity: str = "medium",
    file_path: str | None = None,
) -> list[Finding]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `text` | `str` | -- | Text to scan for secrets. |
| `sensitivity` | `str` | `"medium"` | Detection sensitivity: `"low"`, `"medium"`, or `"high"`. |
| `file_path` | `str \| None` | `None` | File path for finding context. |

---

### `guardianshield.injection.check_injection`

Scan input text for prompt injection patterns including instruction overrides, role hijacking, system prompt extraction, delimiter abuse, and jailbreak attempts.

```python
from guardianshield.injection import check_injection

check_injection(
    text: str,
    sensitivity: str = "medium",
) -> list[Finding]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `text` | `str` | -- | Input text to analyse. |
| `sensitivity` | `str` | `"medium"` | Detection sensitivity: `"low"` reports only CRITICAL findings; `"medium"` adds HIGH; `"high"` includes all. |

---

### `guardianshield.pii.check_pii`

Scan text for personally identifiable information -- emails, SSNs, credit card numbers, phone numbers, IP addresses, and more.

```python
from guardianshield.pii import check_pii

check_pii(
    text: str,
    sensitivity: str = "medium",
    use_presidio: bool = False,
) -> list[Finding]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `text` | `str` | -- | Text to scan for PII. |
| `sensitivity` | `str` | `"medium"` | Detection sensitivity: `"low"`, `"medium"`, or `"high"`. |
| `use_presidio` | `bool` | `False` | If `True`, use the [Presidio](https://github.com/microsoft/presidio) backend for enhanced NER-based detection. Requires `presidio-analyzer` to be installed. |

---

### `guardianshield.content.check_content`

Scan text for content-policy violations across violence, self-harm, and illegal-activity categories.

```python
from guardianshield.content import check_content

check_content(
    text: str,
    sensitivity: str = "medium",
    blocked_categories: list[str] | None = None,
) -> list[Finding]
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `text` | `str` | -- | Text to moderate. |
| `sensitivity` | `str` | `"medium"` | Detection sensitivity: `"low"`, `"medium"`, or `"high"`. |
| `blocked_categories` | `list[str] \| None` | `None` | Restrict scanning to specific categories (e.g. `["violence", "self_harm"]`). `None` checks all categories. |
