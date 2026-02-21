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
    SafetyProfile,
    ScannerConfig,
)
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
)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `profile` | `str` | `"general"` | Name of the safety profile to activate. One of the built-in profiles (`general`, `education`, `healthcare`, `finance`, `children`) or a custom YAML profile name. |
| `audit_path` | `str \| None` | `None` | Path to the SQLite audit database. `None` uses the default `~/.guardianshield/audit.db`. |

```python
shield = GuardianShield()                                  # defaults
shield = GuardianShield(profile="healthcare")              # stricter profile
shield = GuardianShield(audit_path="/tmp/audit.db")        # custom audit path
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
    SECRET              = "secret"
    SQL_INJECTION       = "sql_injection"
    XSS                 = "xss"
    COMMAND_INJECTION   = "command_injection"
    PATH_TRAVERSAL      = "path_traversal"
    INSECURE_FUNCTION   = "insecure_function"
    INSECURE_PATTERN    = "insecure_pattern"
    PROMPT_INJECTION    = "prompt_injection"
    PII_LEAK            = "pii_leak"
    CONTENT_VIOLATION   = "content_violation"
```

| Member | Value | Description |
|---|---|---|
| `SECRET` | `"secret"` | Hardcoded secret, API key, token, or credential. |
| `SQL_INJECTION` | `"sql_injection"` | SQL injection vulnerability via string formatting or concatenation. |
| `XSS` | `"xss"` | Cross-site scripting vulnerability. |
| `COMMAND_INJECTION` | `"command_injection"` | OS command injection via `os.system`, `subprocess`, or similar. |
| `PATH_TRAVERSAL` | `"path_traversal"` | Directory traversal vulnerability. |
| `INSECURE_FUNCTION` | `"insecure_function"` | Use of a known insecure function (e.g. `eval`, `exec`). |
| `INSECURE_PATTERN` | `"insecure_pattern"` | General insecure coding pattern. |
| `PROMPT_INJECTION` | `"prompt_injection"` | Prompt injection or jailbreak attempt. |
| `PII_LEAK` | `"pii_leak"` | Personally identifiable information detected in output. |
| `CONTENT_VIOLATION` | `"content_violation"` | Content that violates the active moderation policy. |

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
