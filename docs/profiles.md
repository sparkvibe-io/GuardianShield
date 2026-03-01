---
title: Safety Profiles
description: Configure industry-specific safety profiles for healthcare, finance, education, and more.
---

# Safety Profiles

## Overview

Safety profiles are pre-configured security policies that control which scanners are active, their sensitivity levels, and content filtering rules. Instead of manually tuning each scanner for your use case, you select a profile and GuardianShield applies the appropriate settings automatically.

GuardianShield ships with **5 built-in profiles** designed for common industries and compliance requirements. You can also create custom profiles via YAML for specialized needs.

!!! tip "Profiles are applied at runtime"
    Switching profiles takes effect immediately — no restart required. All subsequent scans use the new profile's settings until you switch again.

---

## Built-in Profiles

### General (default)

The **General** profile provides balanced security defaults suitable for everyday software development. All five scanners are active at medium sensitivity with standard content filtering.

- **Code Scanner** — enabled, medium sensitivity
- **Secret Scanner** — enabled, medium sensitivity
- **PII Scanner** — enabled, medium sensitivity
- **Injection Scanner** — enabled, medium sensitivity
- **Content Scanner** — enabled, medium sensitivity
- **Blocked Content** — `violence`, `self_harm`, `illegal_activity`

!!! note "This is the default"
    If you don't set a profile, GuardianShield uses General automatically. It works well for most development workflows without any configuration.

---

### Education

The **Education** profile raises all scanners to high sensitivity and adds stricter content filtering. It is designed for schools, learning platforms, and educational applications where student safety is a priority.

- **Code Scanner** — enabled, high sensitivity
- **Secret Scanner** — enabled, high sensitivity
- **PII Scanner** — enabled, high sensitivity
- **Injection Scanner** — enabled, high sensitivity
- **Content Scanner** — enabled, high sensitivity
- **Blocked Content** — `violence`, `self_harm`, `illegal_activity`, `adult_content`, `hate_speech`

!!! tip "Learning environments"
    The Education profile is a good starting point for any platform where content is presented to students or minors in a supervised setting.

---

### Healthcare

The **Healthcare** profile is tuned for medical applications and HIPAA compliance. PII and secret detection run at high sensitivity to catch protected health information (PHI), API keys, and credentials. Content filtering is narrowed to categories most relevant to healthcare contexts.

- **Code Scanner** — enabled, medium sensitivity
- **Secret Scanner** — enabled, high sensitivity
- **PII Scanner** — enabled, high sensitivity
- **Injection Scanner** — enabled, medium sensitivity
- **Content Scanner** — enabled, medium sensitivity
- **Blocked Content** — `self_harm`, `illegal_activity`

!!! warning "HIPAA is more than scanning"
    GuardianShield helps detect PII and secrets, but HIPAA compliance requires a broader program — access controls, encryption, audit trails, staff training, and BAAs with vendors. Use this profile as one layer of defense, not the entire strategy.

---

### Finance

The **Finance** profile targets banking, fintech, and payment processing applications. Secret detection, PII detection, and code scanning all run at high sensitivity to support PCI-DSS requirements. Content filtering focuses on illegal activity.

- **Code Scanner** — enabled, high sensitivity
- **Secret Scanner** — enabled, high sensitivity
- **PII Scanner** — enabled, high sensitivity
- **Injection Scanner** — enabled, medium sensitivity
- **Content Scanner** — enabled, medium sensitivity
- **Blocked Content** — `illegal_activity`

!!! note "PCI-DSS alignment"
    The Finance profile catches credit card numbers, API keys, and code vulnerabilities at high sensitivity. Pair it with GuardianShield's [audit logging](audit.md) for a comprehensive compliance trail.

---

### Children (COPPA)

The **Children** profile applies maximum protection across all scanners. Every scanner runs at high sensitivity and all content categories are blocked. This profile is designed for applications targeting minors and COPPA compliance.

- **Code Scanner** — enabled, high sensitivity
- **Secret Scanner** — enabled, high sensitivity
- **PII Scanner** — enabled, high sensitivity
- **Injection Scanner** — enabled, high sensitivity
- **Content Scanner** — enabled, high sensitivity
- **Blocked Content** — **all categories** (`violence`, `self_harm`, `illegal_activity`, `adult_content`, `hate_speech`)

!!! warning "Maximum restriction"
    The Children profile is intentionally aggressive. It may produce more findings than other profiles due to its high sensitivity across all scanners and complete content blocking. Review findings carefully and adjust custom patterns if needed.

---

## Profile Comparison

The table below compares all five built-in profiles side by side.

| Feature | General | Education | Healthcare | Finance | Children |
|---|:---:|:---:|:---:|:---:|:---:|
| **Code Scanner** | :white_check_mark: Medium | :white_check_mark: High | :white_check_mark: Medium | :white_check_mark: High | :white_check_mark: High |
| **Secret Scanner** | :white_check_mark: Medium | :white_check_mark: High | :white_check_mark: High | :white_check_mark: High | :white_check_mark: High |
| **PII Scanner** | :white_check_mark: Medium | :white_check_mark: High | :white_check_mark: High | :white_check_mark: High | :white_check_mark: High |
| **Injection Scanner** | :white_check_mark: Medium | :white_check_mark: High | :white_check_mark: Medium | :white_check_mark: Medium | :white_check_mark: High |
| **Content Scanner** | :white_check_mark: Medium | :white_check_mark: High | :white_check_mark: Medium | :white_check_mark: Medium | :white_check_mark: High |
| **Blocks violence** | :white_check_mark: | :white_check_mark: | — | — | :white_check_mark: |
| **Blocks self_harm** | :white_check_mark: | :white_check_mark: | :white_check_mark: | — | :white_check_mark: |
| **Blocks illegal_activity** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **Blocks adult_content** | — | :white_check_mark: | — | — | :white_check_mark: |
| **Blocks hate_speech** | — | :white_check_mark: | — | — | :white_check_mark: |
| **Best for** | Everyday dev | Schools & learning | Medical & HIPAA | Banking & PCI-DSS | Apps for minors |

---

## Switching Profiles

There are three ways to switch the active safety profile.

### Environment Variable

Set the `GUARDIANSHIELD_PROFILE` environment variable before starting GuardianShield. The profile is applied when the instance initializes.

```bash
export GUARDIANSHIELD_PROFILE=healthcare
```

Valid values: `general`, `education`, `healthcare`, `finance`, `children`.

### Python API

Switch profiles programmatically at any point during execution:

```python
from guardianshield import GuardianShield

shield = GuardianShield()

# Start with the default (general) profile
findings = shield.scan_code('SELECT * FROM users WHERE id = ' + user_id)

# Switch to healthcare for medical data processing
shield.set_profile("healthcare")
findings = shield.scan_output("Patient SSN: 123-45-6789")
```

### MCP Tool

Use the `set_profile` tool from any MCP-compatible AI client:

```json
{
  "tool": "set_profile",
  "arguments": {
    "profile": "finance"
  }
}
```

You can also retrieve the current profile with the `get_profile` tool:

```json
{
  "tool": "get_profile",
  "arguments": {}
}
```

!!! tip "Check before switching"
    Use `get_profile` to inspect the current scanner configuration before switching. This helps you understand what will change.

---

## Profile Structure

Each profile configures five scanners using a `ScannerConfig` object. Understanding the structure helps when creating custom profiles or fine-tuning built-in ones.

### ScannerConfig Fields

| Field | Type | Description |
|---|---|---|
| `enabled` | `bool` | Toggle the scanner on or off. When `False`, the scanner is skipped entirely during scans. |
| `sensitivity` | `str` | Detection sensitivity level. Accepts `"low"`, `"medium"`, or `"high"`. Higher sensitivity catches more potential issues but may increase false positives. |
| `custom_patterns` | `list[str]` | Additional regex patterns to match during scanning. These are appended to the scanner's built-in patterns. |
| `blocked_categories` | `list[str]` | Content categories to block. **Applies to the content scanner only.** Available categories: `violence`, `self_harm`, `illegal_activity`, `adult_content`, `hate_speech`. |

### Example: Profile as Python Dictionary

```python
{
    "code_scanner": {
        "enabled": True,
        "sensitivity": "high",
        "custom_patterns": [r"eval\(", r"exec\("],
    },
    "secret_scanner": {
        "enabled": True,
        "sensitivity": "high",
        "custom_patterns": [],
    },
    "pii_scanner": {
        "enabled": True,
        "sensitivity": "medium",
        "custom_patterns": [],
    },
    "injection_scanner": {
        "enabled": True,
        "sensitivity": "high",
        "custom_patterns": [],
    },
    "content_scanner": {
        "enabled": True,
        "sensitivity": "medium",
        "blocked_categories": ["violence", "self_harm"],
    },
}
```

!!! note "Sensitivity levels explained"
    - **Low** — catches only high-confidence, obvious matches. Fewest false positives, but may miss subtle issues.
    - **Medium** — balanced detection. Good trade-off between coverage and noise.
    - **High** — catches a wider range of potential issues including ambiguous matches. May produce more false positives but minimizes missed detections.

---

## Custom Profiles via YAML

For projects that need a tailored profile beyond the five built-ins, you can define a custom profile in a YAML file.

!!! warning "Requires PyYAML"
    Custom YAML profiles require the `PyYAML` package. Install it with:

    ```bash
    pip install pyyaml
    ```

### Creating a Custom Profile

Create a YAML file with your desired scanner configuration:

```yaml title="my-custom-profile.yaml"
name: my-custom
description: Custom profile for our app
code_scanner:
  enabled: true
  sensitivity: high
secret_scanner:
  enabled: true
  sensitivity: high
pii_scanner:
  enabled: true
  sensitivity: medium
injection_scanner:
  enabled: true
  sensitivity: high
content_scanner:
  enabled: true
  sensitivity: medium
  blocked_categories:
    - violence
    - self_harm
```

### Loading a Custom Profile

Load your YAML profile and apply it to a GuardianShield instance:

```python
import yaml
from guardianshield import GuardianShield

# Load custom profile from YAML
with open("my-custom-profile.yaml") as f:
    custom_profile = yaml.safe_load(f)

# Apply to GuardianShield
shield = GuardianShield()
shield.load_profile(custom_profile)

# All scans now use the custom profile
findings = shield.scan_code('password = os.environ["DB_PASS"]')
```

### Adding Custom Patterns

Custom profiles support additional regex patterns for any scanner. This is useful for catching project-specific patterns that the built-in rules don't cover:

```yaml title="custom-with-patterns.yaml"
name: acme-corp
description: Custom rules for ACME Corp internal standards
code_scanner:
  enabled: true
  sensitivity: high
  custom_patterns:
    - "ACME_INTERNAL_\\w+"
    - "localhost:\\d{4}"
secret_scanner:
  enabled: true
  sensitivity: high
  custom_patterns:
    - "acme_api_key_[a-zA-Z0-9]{32}"
    - "acme_secret_[a-zA-Z0-9]{64}"
pii_scanner:
  enabled: true
  sensitivity: high
  custom_patterns:
    - "EMP-\\d{6}"
injection_scanner:
  enabled: true
  sensitivity: high
content_scanner:
  enabled: true
  sensitivity: medium
  blocked_categories:
    - violence
    - self_harm
    - illegal_activity
```

!!! tip "Iterate on custom patterns"
    Start with a built-in profile, export it, and modify from there. Test your custom patterns against known inputs with `scan_code` or `scan_input` before deploying to production.

---

## Next Steps

- **[Configuration](configuration.md)** — Fine-tune individual scanner settings beyond profiles.
- **[MCP Server](mcp-server.md)** — Learn about all 21 MCP tools including `get_profile` and `set_profile`.
- **[Audit & Compliance](audit.md)** — Explore the audit trail and compliance reporting.
