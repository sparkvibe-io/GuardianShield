# GuardianShield — AI Agent Instructions

GuardianShield is a universal AI security layer exposed as an MCP server.

## Available MCP Tools

- **scan_code**: Scan source code for vulnerabilities and hardcoded secrets
- **scan_input**: Check input for prompt injection attempts
- **scan_output**: Check AI output for PII leaks and content violations
- **check_secrets**: Dedicated secret/credential detection
- **get_profile**: View current safety profile
- **set_profile**: Switch safety profiles (general/education/healthcare/finance/children)
- **audit_log**: Query the security audit log
- **get_findings**: Retrieve past findings with filters
- **shield_status**: Get health and configuration status

## Usage Guidelines

1. Use `scan_code` before committing or reviewing code changes
2. Use `scan_input` to validate untrusted user inputs
3. Use `scan_output` before returning AI-generated content to users
4. Use `check_secrets` on configuration files and environment setups
5. Switch profiles with `set_profile` based on the domain context

## Project Structure

```
src/guardianshield/
├── findings.py      # Finding dataclass + Severity/FindingType enums
├── profiles.py      # SafetyProfile loader + built-in profiles
├── secrets.py       # Secret/credential detection (12+ patterns)
├── scanner.py       # Code vulnerability scanner
├── injection.py     # Prompt injection detector (9+ patterns)
├── pii.py           # PII detection (regex + optional Presidio)
├── content.py       # Content moderation (heuristic patterns)
├── audit.py         # SQLite audit log
├── core.py          # GuardianShield orchestrator
└── mcp_server.py    # MCP server (JSON-RPC over stdio)
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
ruff check src/ tests/
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
