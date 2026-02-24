---
title: Configuration
description: Configure GuardianShield safety profiles, scanners, and environment variables.
---

# Configuration

GuardianShield is designed to work out of the box with sensible defaults, but every aspect of its behavior can be tailored to your needs. Configuration is supported through four interfaces:

- **Project config file** -- `.guardianshield.json` or `.guardianshield.yaml` in your project root
- **Environment variables** -- ideal for MCP server deployments and CI/CD pipelines
- **Python API** -- programmatic control when using GuardianShield as a library
- **MCP tool calls** -- runtime profile switching from any connected AI client

---

## Project Configuration File

Place a `.guardianshield.json` or `.guardianshield.yaml` file in your project root to customize GuardianShield behavior per-project. The `discover_config()` function walks up the directory tree from the current working directory to find the nearest config file.

### Supported Fields

| Field | Type | Description |
|---|---|---|
| `profile` | `string` | Safety profile to use (`general`, `education`, `healthcare`, `finance`, `children`). |
| `severity_overrides` | `object` | Map of pattern name to severity override (e.g. `{"sql_concat": "critical"}`). |
| `exclude_paths` | `string[]` | Glob patterns for paths to exclude from directory scanning. |
| `custom_patterns` | `array` | Custom pattern definitions to add to the scanner. |

### Example: JSON

```json title=".guardianshield.json"
{
  "profile": "finance",
  "severity_overrides": {
    "hardcoded_password": "critical",
    "sql_concat": "critical"
  },
  "exclude_paths": [
    "tests/fixtures/*",
    "vendor/*",
    "*.min.js"
  ],
  "custom_patterns": []
}
```

### Example: YAML

```yaml title=".guardianshield.yaml"
profile: healthcare
severity_overrides:
  hardcoded_password: critical
exclude_paths:
  - "tests/fixtures/*"
  - "vendor/*"
  - "*.min.js"
```

!!! info "JSON always works; YAML requires PyYAML"
    The JSON format uses Python's built-in `json` module — no extra dependencies. To use YAML format, install PyYAML: `pip install pyyaml`.

### Discovery Behavior

The `discover_config()` function searches for config files in this priority order:

1. `.guardianshield.json`
2. `.guardianshield.yaml`
3. `.guardianshield.yml`

It starts in the current directory and walks up to 10 parent directories. The first file found is loaded.

### Python API Usage

```python
from guardianshield import GuardianShield
from guardianshield.config import discover_config

# Auto-discover project config
config = discover_config()
shield = GuardianShield(project_config=config)

# Scan a directory — exclude_paths from config are applied automatically
findings = shield.scan_directory("src/")
```

---

## Environment Variables

Set these before launching the `guardianshield-mcp` server or importing the library.

| Variable | Description | Default |
|---|---|---|
| `GUARDIANSHIELD_PROFILE` | Active safety profile name | `general` |
| `GUARDIANSHIELD_AUDIT_PATH` | Path to the SQLite audit database | `~/.guardianshield/audit.db` |
| `GUARDIANSHIELD_DEBUG` | Enable debug logging to stderr | `false` |

### `GUARDIANSHIELD_PROFILE`

Selects which safety profile is loaded at startup. Valid values are:

- `general` -- balanced defaults for everyday development
- `education` -- content safety for learning environments
- `healthcare` -- HIPAA-aware PII and PHI protection
- `finance` -- PCI-DSS compliant secret and credential handling
- `children` -- maximum content filtering and safety

```bash
export GUARDIANSHIELD_PROFILE=healthcare
```

### `GUARDIANSHIELD_AUDIT_PATH`

Controls where the SQLite audit database is stored. Every scan, finding, and profile change is logged here with SHA-256 hashed inputs -- raw content is never persisted.

```bash
export GUARDIANSHIELD_AUDIT_PATH=/var/log/guardianshield/audit.db
```

!!! note
    The parent directory must exist and be writable. GuardianShield will create the database file automatically on first use.

### `GUARDIANSHIELD_DEBUG`

Set to `"1"` or `"true"` to enable verbose debug logging to stderr. Useful for troubleshooting scanner behavior and profile resolution.

```bash
export GUARDIANSHIELD_DEBUG=1
```

!!! warning
    Debug mode may log sensitive pattern matches to stderr. Do not enable in production environments where stderr is captured or forwarded to external logging systems.

---

## Safety Profiles

Safety profiles are the primary configuration mechanism in GuardianShield. Each profile defines a complete security policy that controls:

- **Scanner toggles** -- enable or disable each scanner independently
- **Sensitivity level** -- how aggressively findings are reported
- **Blocked content categories** -- which content types trigger violations
- **Custom regex patterns** -- additional detection rules per scanner

| Profile | Sensitivity | Scanners Enabled | Focus |
|---|---|---|---|
| `general` | `medium` | All | Balanced defaults |
| `education` | `high` | All | Content safety |
| `healthcare` | `high` | All (PII emphasized) | HIPAA / PHI |
| `finance` | `high` | All (secrets emphasized) | PCI-DSS / credentials |
| `children` | `high` | All | Maximum filtering |

!!! tip "Full profile reference"
    For complete profile definitions, including per-scanner overrides and blocked category lists, see the [Safety Profiles](profiles.md) page.

---

## Scanner Configuration

GuardianShield includes five independent scanners. Each can be enabled or disabled per profile, and each supports custom regex patterns for extending detection coverage.

### Code Scanner

**Profile key:** `code_scanner`

Analyzes source code for common vulnerability patterns using 75+ language-aware rules. The scanner auto-detects language from file extension and loads the appropriate pattern set: Python (15 patterns), JavaScript/TypeScript (7 patterns), plus 3 cross-language patterns. Every finding includes CWE IDs and remediation suggestions with before/after code examples.

| Detection | Examples |
|---|---|
| SQL injection | String-concatenated queries, unsanitized `WHERE` clauses |
| Cross-site scripting (XSS) | Unescaped template output, `innerHTML` assignments |
| Command injection | Shell execution with unsanitized input |
| Path traversal | `../` sequences, unsanitized file path construction |
| Insecure functions | Dangerous function calls (language-specific) |

### Secret Scanner

**Profile key:** `secret_scanner`

Detects credentials and secrets using 12+ regex patterns:

| Detection | Examples |
|---|---|
| API keys | AWS access keys, Google API keys, Stripe keys |
| Tokens | GitHub tokens, Slack tokens, JWTs |
| Passwords | Hardcoded password strings, connection strings |
| Credentials | Database URIs, private keys, OAuth secrets |

### Injection Scanner

**Profile key:** `injection_scanner`

Identifies prompt injection attempts using 9+ heuristic patterns:

| Detection | Examples |
|---|---|
| Instruction override | "Ignore previous instructions", "disregard all rules" |
| Role hijacking | "You are now a...", "act as an unrestricted AI" |
| ChatML injection | Embedded `<|im_start|>` or `[INST]` tokens |
| Jailbreak attempts | DAN prompts, encoding-based bypasses |
| Data exfiltration | Requests to output system prompts or hidden context |

### PII Scanner

**Profile key:** `pii_scanner`

Detects personally identifiable information across seven categories:

| Category | Pattern |
|---|---|
| Email addresses | Standard email format detection |
| Social Security numbers | XXX-XX-XXXX and variants |
| Credit card numbers | Visa, Mastercard, Amex, Discover formats |
| Phone numbers | US and international formats |
| IP addresses | IPv4 and IPv6 |
| Dates of birth | Common date formats in context |
| Physical addresses | Street address patterns |

### Content Scanner

**Profile key:** `content_scanner`

Flags content that violates moderation policies:

| Category | Description |
|---|---|
| `violence` | Graphic violence, threats, weapon instructions |
| `self_harm` | Self-harm instructions or encouragement |
| `illegal_activity` | Drug manufacturing, fraud guides, exploitation |

!!! info
    Content categories can be customized per profile. The `children` profile blocks all categories at maximum sensitivity, while the `general` profile uses a balanced threshold.

---

## Sensitivity Levels

Each profile specifies a sensitivity level that controls the severity threshold for reported findings.

| Level | Behavior | Reported Severities |
|---|---|---|
| `low` | Only the most critical findings | `CRITICAL` only |
| `medium` | Skips low-priority noise | `CRITICAL`, `HIGH`, `MEDIUM` |
| `high` | Reports everything | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |

```text
                    low         medium        high
                  --------    ----------    ----------
  CRITICAL        [x]         [x]           [x]
  HIGH                        [x]           [x]
  MEDIUM                      [x]           [x]
  LOW                                       [x]
```

!!! tip
    Start with `medium` sensitivity (the default for the `general` profile) and adjust based on your noise tolerance. Use `high` in regulated environments where every potential finding must be reviewed.

---

## Python Configuration

When using GuardianShield as a Python library, configure it programmatically:

### Initialization

```python
from guardianshield import GuardianShield

# Initialize with a specific profile and audit path
shield = GuardianShield(
    profile="healthcare",
    audit_path="/tmp/audit.db"
)
```

### Runtime Profile Switching

```python
# Switch to a different profile at any time
shield.set_profile("finance")

# Retrieve the current profile configuration
current = shield.get_profile()
print(current["name"])         # "finance"
print(current["sensitivity"])  # "high"
```

### Scanning

```python
# Scan code for vulnerabilities
result = shield.scan_code("user_input = request.args['q']")

# Check text for secrets
result = shield.check_secrets("api_key = 'AKIA...'")

# Scan for PII
result = shield.scan_output("Contact me at john@example.com")
```

!!! note
    Environment variables are still respected when using the Python API. Explicit constructor arguments take precedence over environment variables.

---

## MCP Configuration

To configure GuardianShield when running as an MCP server, pass environment variables through your client's MCP configuration file.

### Standard MCP Configuration

```json title=".mcp.json"
{
  "mcpServers": {
    "guardianshield": {
      "command": "guardianshield-mcp",
      "env": {
        "GUARDIANSHIELD_PROFILE": "healthcare",
        "GUARDIANSHIELD_AUDIT_PATH": "/path/to/audit.db"
      }
    }
  }
}
```

### Client-Specific Examples

=== "Claude Code"

    ```bash
    claude mcp add guardianshield \
      -e GUARDIANSHIELD_PROFILE=healthcare \
      -e GUARDIANSHIELD_AUDIT_PATH=/path/to/audit.db \
      -- guardianshield-mcp
    ```

=== "VS Code"

    ```json title=".vscode/mcp.json"
    {
      "servers": {
        "guardianshield": {
          "type": "stdio",
          "command": "guardianshield-mcp",
          "env": {
            "GUARDIANSHIELD_PROFILE": "finance",
            "GUARDIANSHIELD_AUDIT_PATH": "/path/to/audit.db"
          }
        }
      }
    }
    ```

=== "Cursor"

    ```json title=".cursor/mcp.json"
    {
      "mcpServers": {
        "guardianshield": {
          "command": "guardianshield-mcp",
          "env": {
            "GUARDIANSHIELD_PROFILE": "education",
            "GUARDIANSHIELD_AUDIT_PATH": "/path/to/audit.db"
          }
        }
      }
    }
    ```

### Runtime Profile Switching via MCP

Once the server is running, any connected AI client can switch profiles using the `set_profile` tool:

```text
Tool: set_profile
Arguments: { "profile": "finance" }
```

The profile change takes effect immediately for all subsequent scans within the session.

!!! info
    Profile changes made via MCP tool calls are session-scoped. Restarting the server resets to the profile defined by the `GUARDIANSHIELD_PROFILE` environment variable.

---

## Configuration Precedence

When multiple configuration sources are present, GuardianShield resolves settings in the following order (highest priority first):

1. **MCP tool calls** -- `set_profile` at runtime
2. **Python API** -- constructor arguments and `set_profile()` method
3. **Project config file** -- `.guardianshield.json` or `.guardianshield.yaml`
4. **Environment variables** -- `GUARDIANSHIELD_PROFILE`, `GUARDIANSHIELD_AUDIT_PATH`
5. **Built-in defaults** -- `general` profile, `~/.guardianshield/audit.db`

!!! example "Practical example"
    If `GUARDIANSHIELD_PROFILE=general` is set in the environment but a client calls `set_profile("finance")` via MCP, the `finance` profile is used for all subsequent scans until the server restarts.
