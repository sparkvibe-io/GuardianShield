---
title: FAQ
description: Frequently asked questions about GuardianShield — installation, configuration, and troubleshooting.
---

# Frequently Asked Questions

Common questions about GuardianShield — what it does, how it works, and how to get the most out of it.

---

## General

??? question "What is GuardianShield?"

    GuardianShield is a **free, open-source MCP server** that acts as a universal AI security layer. It sits between your AI coding agent and your codebase, providing real-time code scanning, PII detection, prompt injection defense, secret detection, and audit logging.

    GuardianShield exposes 21 MCP tools that any compatible AI client can call — giving every AI agent the same security guardrails, regardless of which editor or platform you use.

??? question "Is it really free?"

    Yes. GuardianShield is licensed under the **Apache-2.0** license and is free forever — for individuals, teams, startups, and enterprises alike. There are no paid tiers, no usage limits, and no telemetry.

    Apache-2.0 also provides an express grant of patent rights, so you can adopt GuardianShield without legal uncertainty.

??? question "What AI editors and clients does it support?"

    GuardianShield works with **any MCP-compatible client**, including:

    - **Claude Code** — one-command setup via `claude mcp add`
    - **VS Code** — via `.vscode/mcp.json`
    - **Cursor** — via `.cursor/mcp.json`
    - **Windsurf** — via MCP configuration
    - **Claude Desktop** — via `claude_desktop_config.json`
    - **OpenSpek** — native MCP support
    - **Gemini, Grok, Codex** — and any other client that speaks the MCP protocol

    If your tool supports MCP, it supports GuardianShield.

??? question "Does it require an internet connection?"

    No. GuardianShield runs **entirely locally** on your machine. All scanning, detection, and audit logging happens offline using compiled regex patterns and local SQLite storage. No data is sent to any external service, ever.

---

## Technical

??? question "Why does GuardianShield have zero dependencies?"

    Security tooling should not introduce supply chain risk. Every third-party dependency is a potential attack vector — and a dependency of a security tool is an especially attractive target.

    GuardianShield is built entirely on the **Python standard library**. The `re`, `hashlib`, `sqlite3`, `json`, and `logging` modules provide everything needed for pattern matching, hashing, audit storage, and MCP communication. Zero dependencies means zero supply chain risk.

??? question "How accurate is the detection?"

    GuardianShield uses **68 compiled regex patterns** across five scanners (code, secrets, injection, PII, and content). Detection accuracy depends on the scanner and the sensitivity level configured in your safety profile:

    - **High sensitivity** — catches more potential issues but may produce more false positives
    - **Medium sensitivity** — balanced defaults suitable for everyday development
    - **Low sensitivity** — only the most critical findings are reported

    GuardianShield is designed as a **real-time guardrail for AI agents**, not a replacement for dedicated SAST tools like Semgrep or Snyk for production code review. It excels at catching the most common security mistakes that AI agents introduce during interactive development.

??? question "Does it store my code or data?"

    **Never.** GuardianShield does not persist any raw input — not code, not prompts, not outputs.

    For audit logging, input content is **SHA-256 hashed** before storage. The hash allows you to correlate audit events (e.g., "this scan produced these findings") without retaining the original content. Findings include pattern match descriptions but never the full input text.

??? question "Can I use GuardianShield as a Python library?"

    Yes. GuardianShield works both as an MCP server and as a standalone Python library:

    ```python
    from guardianshield import GuardianShield

    shield = GuardianShield(profile="general")

    # Scan code for vulnerabilities and secrets
    findings = shield.scan_code('password = "hunter2"')

    # Check for prompt injection
    findings = shield.scan_input("Ignore all previous instructions")

    # Scan output for PII
    findings = shield.scan_output("Email: john@example.com")
    ```

    This is useful for integrating GuardianShield into CI/CD pipelines, custom tooling, or test suites. See the [Getting Started](getting-started.md) guide for more examples.

??? question "What Python versions are supported?"

    GuardianShield requires **Python 3.9 or higher**. It is tested against Python 3.9, 3.10, 3.11, 3.12, and 3.13. Since it has zero external dependencies, it works anywhere a compatible Python interpreter is available.

---

## Troubleshooting

??? question "The MCP server is not starting. What should I check?"

    If `guardianshield-mcp` fails to start, work through the following:

    1. **Verify the command is in your PATH:**

        ```bash
        which guardianshield-mcp
        ```

        If this returns nothing, the package may not be installed or your PATH does not include the Python scripts directory. Reinstall with `pip install guardianshield` and ensure `pip`'s bin directory is on your PATH.

    2. **Check your Python version:**

        ```bash
        python --version
        ```

        GuardianShield requires Python 3.9 or higher.

    3. **Test the server directly:**

        ```bash
        guardianshield-mcp
        ```

        The server communicates over stdin/stdout using the MCP protocol. If it starts without errors, the issue is likely in your editor's MCP configuration.

    4. **Enable debug logging:**

        ```bash
        GUARDIANSHIELD_DEBUG=1 guardianshield-mcp
        ```

        Debug output is written to stderr and can help pinpoint configuration issues.

??? question "I am getting too many false positives. How do I reduce them?"

    If GuardianShield is flagging too many benign patterns, you have several options:

    - **Switch to the `general` profile**, which uses medium sensitivity:

        ```bash
        export GUARDIANSHIELD_PROFILE=general
        ```

    - **Lower the sensitivity level** in your profile configuration to `low`, which reports only `CRITICAL` severity findings.

    - **Adjust individual scanners** — disable specific scanners that are noisy for your use case by configuring the profile's scanner toggles. See [Configuration](configuration.md) for details.

    !!! tip
        Start with `medium` sensitivity and adjust based on your workflow. Regulated environments (healthcare, finance) benefit from `high` sensitivity, while general development typically works best with `medium`.

??? question "How do I see what was scanned and what was found?"

    GuardianShield provides two MCP tools for reviewing scan history:

    - **`audit_log`** — Query the full audit trail of all scans, including timestamps, input hashes, scanner results, and finding counts.
    - **`shield_status`** — Check the current configuration, active profile, scanner status, and summary statistics.

    You can also query the SQLite audit database directly:

    ```bash
    sqlite3 ~/.guardianshield/audit.db "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 10;"
    ```

    !!! note
        The audit database stores SHA-256 hashes of inputs, not raw content. This design ensures your code and data are never persisted to disk by GuardianShield.
