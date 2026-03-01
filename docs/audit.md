---
title: Audit & Compliance
description: SQLite audit logging for security compliance — HIPAA, PCI-DSS, SOC 2, and GDPR.
---

# Audit & Compliance

Every scan performed by GuardianShield is automatically logged to a local SQLite database, creating a complete audit trail of all security events. Input text is never stored — only a SHA-256 hash (first 16 characters) is recorded, allowing scan correlation without exposing raw data.

This built-in audit capability supports compliance workflows for regulated industries and provides full visibility into the security posture of your AI-assisted development environment.

---

## Audit Database

By default, the audit database is stored at:

```
~/.guardianshield/audit.db
```

You can override this location by setting the `GUARDIANSHIELD_AUDIT_PATH` environment variable:

```bash
export GUARDIANSHIELD_AUDIT_PATH=/path/to/custom/audit.db
```

!!! info "Automatic initialization"
    The database and all required tables are created automatically on the first scan. No manual setup or migration is required.

---

## Database Schema

The audit database consists of two tables: `audit_log` for scan events and `findings` for individual security findings linked to each scan.

### `audit_log`

Stores one row per scan operation.

| Column | Type | Description |
|---|---|---|
| `id` | `INTEGER` | Primary key, auto-incremented |
| `timestamp` | `TEXT` | ISO 8601 timestamp of the scan |
| `scan_type` | `TEXT` | Type of scan — `code`, `input`, or `output` |
| `input_hash` | `TEXT` | SHA-256 hash of the input (first 16 chars) |
| `profile` | `TEXT` | Safety profile active at scan time |
| `finding_count` | `INTEGER` | Number of findings produced by the scan |
| `max_severity` | `TEXT` | Highest severity among findings (`critical`, `high`, `medium`, `low`, `info`) |

### `findings`

Stores individual findings linked to a parent scan via foreign key.

| Column | Type | Description |
|---|---|---|
| `id` | `INTEGER` | Primary key, auto-incremented |
| `audit_id` | `INTEGER` | Foreign key referencing `audit_log.id` |
| `finding_type` | `TEXT` | Category — `vulnerability`, `secret`, `pii`, `injection`, etc. |
| `severity` | `TEXT` | Severity level — `critical`, `high`, `medium`, `low`, `info` |
| `message` | `TEXT` | Human-readable description of the finding |
| `file_path` | `TEXT` | File path, if applicable |
| `line_number` | `INTEGER` | Line number, if applicable |
| `matched_text` | `TEXT` | Matched content (automatically redacted) |
| `metadata` | `TEXT` | JSON-encoded additional context |

!!! warning "Matched text is always redacted"
    The `matched_text` column never contains raw secrets, PII, or sensitive content. GuardianShield automatically redacts matched text before writing it to the audit database. For example, an API key match would be stored as `AKIAIOSFODNN7E******` rather than the full key.

---

## Querying the Audit Log

Retrieve scan history through the MCP `audit_log` tool or the Python API.

### MCP Tool

The `audit_log` tool returns recent scan entries with optional filtering.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | `integer` | `50` | Maximum number of entries to return |
| `scan_type` | `string` | — | Filter by scan type: `code`, `input`, `output`, `secrets`, `dependencies`, `directory_dependencies` |

**Example MCP response:**

```json
{
  "entries": [
    {
      "id": 42,
      "timestamp": "2026-02-20T14:30:00Z",
      "scan_type": "code",
      "input_hash": "a1b2c3d4e5f67890",
      "profile": "general",
      "finding_count": 3,
      "max_severity": "high"
    }
  ]
}
```

### Python API

```python
from guardianshield import GuardianShield

shield = GuardianShield()

# Get the 10 most recent scans
entries = shield.get_audit_log(limit=10)

# Filter by scan type
code_scans = shield.get_audit_log(limit=10, scan_type="code")

for entry in entries:
    print(f"[{entry['timestamp']}] {entry['scan_type']} — "
          f"{entry['finding_count']} findings (max: {entry['max_severity']})")
```

---

## Retrieving Findings

Query individual security findings across all scans using the MCP `get_findings` tool or the Python API.

### MCP Tool

The `get_findings` tool returns findings with optional filtering by severity and type.

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | `integer` | `50` | Maximum number of findings to return |
| `severity` | `string` | — | Filter by severity: `critical`, `high`, `medium`, `low`, `info` |
| `finding_type` | `string` | — | Filter by type: `vulnerability`, `secret`, `pii`, `injection`, etc. |

**Example MCP response:**

```json
{
  "findings": [
    {
      "id": 87,
      "audit_id": 42,
      "finding_type": "secret",
      "severity": "critical",
      "message": "AWS access key detected",
      "file_path": "config.py",
      "line_number": 12,
      "matched_text": "AKIAIOSFODNN7E******"
    }
  ]
}
```

### Python API

```python
from guardianshield import GuardianShield

shield = GuardianShield()

# Get all critical findings
critical = shield.get_findings(severity="critical")

# Get only secret-type findings
secrets = shield.get_findings(finding_type="secret")

# Combine filters with a limit
recent_pii = shield.get_findings(severity="high", finding_type="pii", limit=20)

for finding in critical:
    print(f"[{finding['severity']}] {finding['finding_type']}: {finding['message']}")
```

---

## Statistics

The `shield_status()` MCP tool and the Python API provide aggregate statistics about scan activity and findings.

### MCP Tool

Call the `shield_status` tool to retrieve a summary of your security posture:

```json
{
  "status": "active",
  "profile": "general",
  "audit": {
    "total_scans": 1284,
    "total_findings": 347,
    "severity_breakdown": {
      "critical": 12,
      "high": 45,
      "medium": 128,
      "low": 97,
      "info": 65
    },
    "most_common_types": [
      {"type": "vulnerability", "count": 142},
      {"type": "secret", "count": 89},
      {"type": "pii", "count": 67},
      {"type": "injection", "count": 49}
    ]
  }
}
```

### Python API

```python
from guardianshield import GuardianShield

shield = GuardianShield()

status = shield.shield_status()

print(f"Total scans: {status['audit']['total_scans']}")
print(f"Total findings: {status['audit']['total_findings']}")

for severity, count in status['audit']['severity_breakdown'].items():
    print(f"  {severity}: {count}")
```

!!! tip "Dashboard integration"
    The statistics output is structured JSON, making it straightforward to feed into monitoring dashboards, CI/CD reports, or compliance documentation pipelines.

---

## Privacy & Security

GuardianShield's audit system is designed with privacy as a core principle.

!!! warning "Raw input is never stored"
    The audit database does not contain the original text that was scanned. Only a truncated SHA-256 hash is recorded, making it impossible to reconstruct the source material from the audit log alone.

**Key privacy and security properties:**

| Property | Detail |
|---|---|
| **Input hashing** | Only the first 16 characters of the SHA-256 hash are stored — sufficient for correlation, insufficient for reversal |
| **Secret redaction** | Detected secrets (API keys, tokens, passwords) are automatically redacted before being written to the findings table |
| **PII redaction** | Detected PII (emails, SSNs, credit card numbers) is redacted in `matched_text` before storage |
| **Thread safety** | SQLite WAL (Write-Ahead Logging) mode is enabled for safe concurrent access from multiple threads |
| **Local-only storage** | The audit database is stored exclusively on your local filesystem — no data is transmitted to external servers or cloud services |

!!! info "No network access required"
    GuardianShield operates entirely offline. The audit database, all scanning logic, and all detection patterns run locally. No telemetry, no cloud APIs, no external dependencies. Your code and security data never leave your machine.

---

## Compliance Use Cases

GuardianShield's audit trail and security scanning capabilities map directly to requirements in several regulatory frameworks.

### HIPAA

Track all PII and PHI scans across healthcare applications. The audit log provides evidence that sensitive health information is being systematically detected and redacted in AI-generated output.

```python
shield = GuardianShield(profile="healthcare")
findings = shield.get_findings(finding_type="pii")
# Export findings for HIPAA compliance documentation
```

### PCI-DSS

Audit secret detection activity for financial applications. Demonstrate that API keys, credentials, and payment card data are continuously monitored and never persisted in application code.

```python
shield = GuardianShield(profile="finance")
secrets = shield.get_findings(finding_type="secret", severity="critical")
# Generate PCI-DSS audit report from findings
```

### SOC 2

Demonstrate continuous security monitoring as part of SOC 2 Trust Services Criteria. The audit log serves as evidence of ongoing security controls applied to AI-assisted development workflows.

```python
status = shield.shield_status()
# total_scans and severity_breakdown support SOC 2 reporting
```

### GDPR

Show PII detection and redaction capabilities to support data protection compliance. The audit trail proves that personal data exposure is actively monitored and mitigated.

```python
pii_findings = shield.get_findings(finding_type="pii")
# Document PII detection for GDPR Data Protection Impact Assessments
```

!!! tip "Combine with safety profiles"
    For maximum compliance coverage, pair the audit system with a domain-specific safety profile. The `healthcare` profile enables HIPAA-aware detection, `finance` activates PCI-DSS patterns, and all profiles feed into the same unified audit trail. See the [Profiles guide](profiles.md) for details.

---

## Next Steps

- **[Getting Started](getting-started.md)** — Install GuardianShield and run your first scan.
- **[MCP Server](mcp-server.md)** — Full reference for all 21 MCP tools including `audit_log` and `get_findings`.
- **[Safety Profiles](profiles.md)** — Configure domain-specific security policies for your industry.
