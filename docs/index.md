---
title: Universal AI Security Layer
description: Free, open-source MCP server for code scanning, PII detection, prompt injection defense, secret detection, and audit logging.
hide:
  - toc
  - navigation
---

<div class="hero-section" markdown>

# GuardianShield

<p class="hero-sub">
Universal AI security layer — protect every AI coding agent with
code scanning, PII detection, prompt injection defense, secret detection, and audit logging.
</p>

<div class="hero-badges">
  <span class="hero-badge accent"><span class="material-symbols-rounded">verified_user</span> MCP Server</span>
  <span class="hero-badge">Apache-2.0</span>
  <span class="hero-badge">Python 3.9+</span>
  <span class="hero-badge accent"><span class="material-symbols-rounded">lock</span> Zero Dependencies</span>
</div>

<div class="hero-install">pip install guardianshield</div>

<div class="hero-buttons" markdown>

[Get Started](getting-started.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/sparkvibe-io/GuardianShield){ .md-button }

</div>

</div>

<!-- Stats -->
<div class="gs-section" markdown>

<div class="stats-row">
  <div class="stat-card">
    <span class="stat-number">16</span>
    <span class="stat-label">MCP Tools</span>
  </div>
  <div class="stat-card">
    <span class="stat-number">5</span>
    <span class="stat-label">Safety Profiles</span>
  </div>
  <div class="stat-card">
    <span class="stat-number">68</span>
    <span class="stat-label">Detection Patterns</span>
  </div>
  <div class="stat-card">
    <span class="stat-number">0</span>
    <span class="stat-label">Dependencies</span>
  </div>
</div>

</div>

<!-- Threats -->
<div class="gs-section" markdown>

## :material-alert-circle: Threats AI Agents Face

AI coding agents operate with broad access to your codebase, secrets, and infrastructure. Without guardrails, they can introduce or leak critical security issues.

<div class="threat-grid">
  <div class="threat-card">
    <h4><span class="material-symbols-rounded ms-red">vpn_key</span> Secret Leakage</h4>
    <p>API keys, tokens, and credentials accidentally committed to code or exposed through AI-generated output.</p>
  </div>
  <div class="threat-card">
    <h4><span class="material-symbols-rounded ms-red">gpp_bad</span> Prompt Injection</h4>
    <p>Malicious instructions hidden in code comments, issues, or data that hijack AI agent behavior.</p>
  </div>
  <div class="threat-card">
    <h4><span class="material-symbols-rounded ms-red">privacy_tip</span> PII Exposure</h4>
    <p>Personal data — SSNs, emails, credit cards — leaking through AI-generated code or responses.</p>
  </div>
  <div class="threat-card">
    <h4><span class="material-symbols-rounded ms-red">bug_report</span> Code Vulnerabilities</h4>
    <p>SQL injection, XSS, command injection, and path traversal patterns introduced by AI agents.</p>
  </div>
</div>

</div>

<!-- Shield Protection -->
<div class="gs-section" markdown>

## :material-shield-check: How GuardianShield Protects

GuardianShield sits between your AI agent and your codebase, scanning every interaction in real-time.

<div class="shield-grid">
  <div class="shield-card">
    <h4><span class="material-symbols-rounded ms-green">policy</span> Code Scanning</h4>
    <p>Detects SQL injection, XSS, command injection, path traversal, and insecure functions before code is committed.</p>
  </div>
  <div class="shield-card">
    <h4><span class="material-symbols-rounded ms-green">enhanced_encryption</span> Secret Detection</h4>
    <p>12+ patterns catch AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, and database credentials.</p>
  </div>
  <div class="shield-card">
    <h4><span class="material-symbols-rounded ms-green">block</span> Injection Defense</h4>
    <p>9+ heuristic patterns identify instruction overrides, role hijacking, ChatML injection, and jailbreak attempts.</p>
  </div>
  <div class="shield-card">
    <h4><span class="material-symbols-rounded ms-green">visibility</span> PII Detection</h4>
    <p>Catches emails, SSNs, credit cards, phone numbers, and IP addresses — with automatic redaction.</p>
  </div>
  <div class="shield-card">
    <h4><span class="material-symbols-rounded ms-green">package_2</span> Dependency Scanning</h4>
    <p>Check project dependencies for known CVEs using a local-first OSV.dev vulnerability cache.</p>
  </div>
  <div class="shield-card">
    <h4><span class="material-symbols-rounded ms-green">code</span> Language-Aware</h4>
    <p>68 patterns across 5 scanners (code, secrets, injection, PII, content) with CWE mapping — auto-detected from file extension.</p>
  </div>
</div>

</div>

<!-- 16 MCP Tools -->
<div class="gs-section" markdown>

## :material-wrench: 16 MCP Tools

Every security capability is exposed as a standard MCP tool — callable from any compatible AI client.

<div class="tool-grid">
  <div class="tool-card">
    <h3>scan_code</h3>
    <p>Analyze source code for vulnerabilities, insecure patterns, and embedded secrets.</p>
  </div>
  <div class="tool-card">
    <h3>scan_input</h3>
    <p>Check user prompts and inputs for prompt injection and manipulation attempts.</p>
  </div>
  <div class="tool-card">
    <h3>scan_output</h3>
    <p>Scan AI-generated output for PII leaks, sensitive content, and policy violations.</p>
  </div>
  <div class="tool-card">
    <h3>check_secrets</h3>
    <p>Detect API keys, tokens, passwords, and credentials in any text.</p>
  </div>
  <div class="tool-card">
    <h3>get_profile</h3>
    <p>Retrieve the current safety profile configuration and active rules.</p>
  </div>
  <div class="tool-card">
    <h3>set_profile</h3>
    <p>Switch between safety profiles — general, education, healthcare, finance, children.</p>
  </div>
  <div class="tool-card">
    <h3>audit_log</h3>
    <p>Query the SQLite audit trail of all scans, findings, and security events.</p>
  </div>
  <div class="tool-card">
    <h3>get_findings</h3>
    <p>Retrieve security findings filtered by severity, type, or time range.</p>
  </div>
  <div class="tool-card">
    <h3>shield_status</h3>
    <p>Check the health and configuration of your GuardianShield instance.</p>
  </div>
  <div class="tool-card">
    <h3>scan_file</h3>
    <p>Scan a single source file with auto language detection from extension.</p>
  </div>
  <div class="tool-card">
    <h3>scan_directory</h3>
    <p>Recursively scan a directory with extension filtering and progress streaming.</p>
  </div>
  <div class="tool-card">
    <h3>test_pattern</h3>
    <p>Test custom regex patterns against sample code — returns matches with positions.</p>
  </div>
  <div class="tool-card">
    <h3>check_dependencies</h3>
    <p>Check project dependencies for known CVEs via a local OSV.dev cache.</p>
  </div>
  <div class="tool-card">
    <h3>sync_vulnerabilities</h3>
    <p>Sync the local OSV vulnerability database for PyPI, npm, Go, and Packagist ecosystems.</p>
  </div>
  <div class="tool-card">
    <h3>parse_manifest</h3>
    <p>Parse any supported manifest file into structured dependency objects for analysis.</p>
  </div>
  <div class="tool-card">
    <h3>scan_dependencies</h3>
    <p>Scan a directory for manifest files and check all dependencies for known vulnerabilities.</p>
  </div>
</div>

</div>

<!-- Works Everywhere -->
<div class="gs-section" markdown>

## :material-earth: Works Everywhere

One install. Every AI editor. GuardianShield speaks MCP — the universal protocol for AI tool integration.

<div class="chip-grid">
  <span class="icon-chip"><span class="chip-dot" style="background:#6366f1"></span> Claude Code</span>
  <span class="icon-chip"><span class="chip-dot" style="background:#007ACC"></span> VS Code</span>
  <span class="icon-chip"><span class="chip-dot" style="background:#00b4d8"></span> Cursor</span>
  <span class="icon-chip"><span class="chip-dot" style="background:#ff6b6b"></span> Windsurf</span>
  <span class="icon-chip"><span class="chip-dot" style="background:#f59e0b"></span> Claude Desktop</span>
  <span class="icon-chip"><span class="chip-dot" style="background:#10b981"></span> OpenSpek</span>
  <span class="icon-chip"><span class="chip-dot" style="background:#8b5cf6"></span> Gemini</span>
  <span class="icon-chip"><span class="chip-dot" style="background:#ef4444"></span> Grok</span>
  <span class="icon-chip"><span class="chip-dot" style="background:#22d3ee"></span> Codex</span>
  <span class="icon-chip"><span class="chip-dot" style="background:#a3a3a3"></span> Any MCP Client</span>
</div>

</div>

<!-- Quick Setup -->
<div class="gs-section" markdown>

## :material-lightning-bolt: Quick Setup

=== "Claude Code"

    ```bash
    claude mcp add guardianshield -- guardianshield-mcp
    ```

=== "VS Code"

    ```json title=".vscode/mcp.json"
    {
      "servers": {
        "guardianshield": {
          "type": "stdio",
          "command": "guardianshield-mcp"
        }
      }
    }
    ```

=== "Cursor"

    ```json title=".cursor/mcp.json"
    {
      "mcpServers": {
        "guardianshield": {
          "command": "guardianshield-mcp"
        }
      }
    }
    ```

=== "Claude Desktop"

    ```json title="claude_desktop_config.json"
    {
      "mcpServers": {
        "guardianshield": {
          "command": "guardianshield-mcp"
        }
      }
    }
    ```

</div>

<!-- Safety Profiles -->
<div class="gs-section" markdown>

## :material-target: Safety Profiles

Pre-configured security policies for different industries and use cases. Switch profiles with a single MCP call.

<div class="profile-grid">
  <div class="profile-card">
    <span class="pc-icon"><span class="material-symbols-rounded ms-lg">language</span></span>
    <h4>General</h4>
    <p>Balanced defaults for everyday development</p>
  </div>
  <div class="profile-card">
    <span class="pc-icon"><span class="material-symbols-rounded ms-lg">school</span></span>
    <h4>Education</h4>
    <p>Content safety for learning environments</p>
  </div>
  <div class="profile-card">
    <span class="pc-icon"><span class="material-symbols-rounded ms-lg">local_hospital</span></span>
    <h4>Healthcare</h4>
    <p>HIPAA-aware PII and PHI protection</p>
  </div>
  <div class="profile-card">
    <span class="pc-icon"><span class="material-symbols-rounded ms-lg">account_balance</span></span>
    <h4>Finance</h4>
    <p>PCI-DSS compliant secret handling</p>
  </div>
  <div class="profile-card">
    <span class="pc-icon"><span class="material-symbols-rounded ms-lg">child_care</span></span>
    <h4>Children</h4>
    <p>Maximum content filtering and safety</p>
  </div>
</div>

</div>

<!-- Core Features -->
<div class="gs-section" markdown>

## :material-creation: Core Features

<div class="feature-grid">
  <div class="feature-card">
    <span class="fc-icon"><span class="material-symbols-rounded ms-lg">inventory_2</span></span>
    <h3>Zero Dependencies</h3>
    <p>Pure Python stdlib — no pip install headaches, no supply chain risk.</p>
  </div>
  <div class="feature-card">
    <span class="fc-icon"><span class="material-symbols-rounded ms-lg">menu_book</span></span>
    <h3>Audit Trail</h3>
    <p>Every scan logged to SQLite with SHA-256 hashed inputs — never stores raw data.</p>
  </div>
  <div class="feature-card">
    <span class="fc-icon"><span class="material-symbols-rounded ms-lg">shield</span></span>
    <h3>Auto Redaction</h3>
    <p>Secrets and PII are automatically redacted in all findings and logs.</p>
  </div>
  <div class="feature-card">
    <span class="fc-icon"><span class="material-symbols-rounded ms-lg">extension</span></span>
    <h3>Composable</h3>
    <p>Use as MCP server, Python library, or integrate into CI/CD pipelines.</p>
  </div>
  <div class="feature-card">
    <span class="fc-icon"><span class="material-symbols-rounded ms-lg">settings</span></span>
    <h3>Configurable</h3>
    <p>Sensitivity levels, custom patterns, and per-scanner toggles via profiles.</p>
  </div>
  <div class="feature-card">
    <span class="fc-icon"><span class="material-symbols-rounded ms-lg">balance</span></span>
    <h3>Apache-2.0</h3>
    <p>Free forever. Patent-protected open source — security for humanity.</p>
  </div>
  <div class="feature-card">
    <span class="fc-icon"><span class="material-symbols-rounded ms-lg">link</span></span>
    <h3>CWE Mapping</h3>
    <p>Every finding links to CWE IDs — trace vulnerabilities to the industry-standard weakness catalog.</p>
  </div>
  <div class="feature-card">
    <span class="fc-icon"><span class="material-symbols-rounded ms-lg">package_2</span></span>
    <h3>Dependency Scanning</h3>
    <p>Local-first OSV.dev integration — check PyPI, npm, Go, and Packagist packages for known CVEs offline.</p>
  </div>
</div>

</div>

<!-- Comparison -->
<div class="gs-section" markdown>

## :material-chart-bar: How GuardianShield Compares

| Feature | NeMo Guardrails | Guardrails AI | Llama Guard | Presidio | **GuardianShield** |
|---|---|---|---|---|---|
| Code Scanning | — | — | — | — | **:material-check-circle:{ .gs-check }** |
| Secret Detection | — | — | — | — | **:material-check-circle:{ .gs-check }** |
| Prompt Injection | :material-check-circle: | Partial | :material-check-circle: | — | **:material-check-circle:{ .gs-check }** |
| PII Detection | — | Partial | — | :material-check-circle: | **:material-check-circle:{ .gs-check }** |
| Content Moderation | :material-check-circle: | :material-check-circle: | :material-check-circle: | — | **:material-check-circle:{ .gs-check }** |
| Audit Logging | — | — | — | — | **:material-check-circle:{ .gs-check }** |
| Safety Profiles | — | — | — | — | **:material-check-circle:{ .gs-check }** |
| MCP Integration | — | — | — | — | **:material-check-circle:{ .gs-check }** |
| Zero Dependencies | — | — | — | — | **:material-check-circle:{ .gs-check }** |
| File-Level Scanning | — | — | — | — | **:material-check-circle:{ .gs-check }** |
| Dependency Scanning | — | Partial | — | — | **:material-check-circle:{ .gs-check }** |
| CWE Mapping | — | — | — | — | **:material-check-circle:{ .gs-check }** |
| Finding Dedup | — | — | — | — | **:material-check-circle:{ .gs-check }** |
| Response Redaction | — | — | — | — | **:material-check-circle:{ .gs-check }** |
| **Manifest Parsing** | — | — | — | — | **:material-check-circle:{ .gs-check }** |
| **Directory Dep Scan** | — | — | — | — | **:material-check-circle:{ .gs-check }** |
| **GuardianShield** | **1 of 16** | **2 of 16** | **2 of 16** | **1 of 16** | **16 of 16** |

</div>

<!-- Community -->
<div class="gs-section" markdown>

## :material-account-group: Community

<div class="community-row">
  <a href="https://github.com/sparkvibe-io/GuardianShield" class="community-card">
    <span class="cc-icon"><span class="material-symbols-rounded ms-lg">star</span></span>
    <h4>Star on GitHub</h4>
    <p>Show your support and stay updated with releases</p>
  </a>
  <a href="https://github.com/sparkvibe-io/GuardianShield/issues" class="community-card">
    <span class="cc-icon"><span class="material-symbols-rounded ms-lg">bug_report</span></span>
    <h4>Report Issues</h4>
    <p>Found a bug or have a feature request? Let us know</p>
  </a>
  <a href="contributing.md" class="community-card">
    <span class="cc-icon"><span class="material-symbols-rounded ms-lg">handshake</span></span>
    <h4>Contribute</h4>
    <p>Help make AI security accessible to everyone</p>
  </a>
</div>

</div>

<!-- CTA -->
<div class="cta-section" markdown>

## Secure Your AI Agents Today

<div class="hero-install">pip install guardianshield</div>

<div class="hero-buttons" markdown>

[Get Started :material-arrow-right:](getting-started.md){ .md-button .md-button--primary }
[Read the Docs :material-book-open-variant:](mcp-server.md){ .md-button }

</div>

</div>
