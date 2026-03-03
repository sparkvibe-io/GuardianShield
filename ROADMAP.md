# GuardianShield Roadmap

> Last updated: 2026-03-02
>
> Master vision document incorporating strategic feedback from cross-AI review
> (Gemini CLI + Codex CLI, March 2026). Each phase builds on the previous,
> maintaining zero dependencies and backward compatibility throughout.

---

## Current State (v1.2.1)

- **27 MCP tools** | **3 prompts** | **1883 tests** | **Zero dependencies**
- 3 analysis engines: RegexEngine, DeepEngine, SemanticEngine
- 108+ detection patterns across 7 languages (Python, JS/TS, Go, Java, Ruby, PHP, C#)
- CWE-specific triage prompts for AI-assisted false positive filtering
- False positive feedback loop (per-project SQLite, pattern-level learning)
- Local OSV.dev dependency scanner (PyPI, npm, Go, Packagist)
- 5 safety profiles with per-scanner sensitivity control

---

## v1.1 — Multi-Engine Analysis Pipeline [RELEASED]

### Architecture

```
MCP Client
    │
    ▼
core.py (Orchestrator)
    │
    ▼
┌─── AnalysisEngine (Protocol) ──────────────────────────┐
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │ RegexEngine (default)                           │    │
│  │ 108+ compiled patterns, line-by-line, ~1ms/1K   │    │
│  └─────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────┐    │
│  │ DeepEngine                                       │    │
│  │ Cross-line taint tracking (ast + regex), ~10ms/1K│    │
│  └─────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────┐    │
│  │ SemanticEngine                                   │    │
│  │ Confidence adjustment (test/dead/uncalled code)  │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─── Result Pipeline ──────────────────────────────────────┐
│  1. timed_analyze() per engine                           │
│  2. merge_engine_findings() — dedup + confidence boost   │
│  3. SemanticEngine.adjust_findings()                     │
│  4. False positive annotation                            │
│  5. Return unified list[Finding]                         │
└──────────────────────────────────────────────────────────┘
```

### Implementation Phases — All ✅ DONE

- **Phase 1**: Engine abstraction + RegexEngine wrapper (v1.1.0b1)
- **Phase 2**: DeepEngine — cross-line taint tracking (v1.1.0b1)
- **Phase 3**: SemanticEngine — structure-aware confidence adjustment (v1.1.0)
- **Phase 4**: Result pipeline — multi-engine merge, timing, confidence boost (v1.1.0)
- **Phase 5**: CWE-specific triage prompts — 7 vulnerability types (v1.1.0)

---

## v1.2 — Developer Experience & CI Integration [RELEASED]

### Strategic Direction

Make GuardianShield the easiest SAST tool to adopt in CI/CD and daily development.
Focus on output interoperability, developer workflow integration, and reducing
friction for teams adopting security scanning.

### Features — All Done

**SARIF Export** — Standard SARIF 2.1.0 output for GitHub Code Scanning, VS Code
SARIF Viewer, and other security ecosystem tools. `export_sarif` MCP tool +
`findings_to_sarif()` / `findings_to_sarif_json()` Python API. (v1.2.0)

**Inline Suppression** — `# guardianshield:ignore[rule]` comments for intentional
dismissals. Supports Python `#`, JS `//`, and C-style `/* */` comments. Suppressed
findings get `metadata["suppressed"] = True` (preserves auditability). Optional
reason via `-- reason text` suffix. (v1.2.1)

**CI Quality Gates** — `check_quality_gate` MCP tool with configurable thresholds
(fail on HIGH+, warn on MEDIUM). Returns pass/fail/warn verdict with exit codes
(0=pass, 1=fail). Suppressed findings optionally excluded. (v1.2.1)

**Baseline / Delta Scanning** — `save_baseline` and `scan_with_baseline` MCP tools.
Save finding fingerprints as a JSON baseline; subsequent scans report only new
findings. Uses SHA-256 fingerprinting from `dedup.py`. (v1.2.1)

**Bulk MCP APIs** — `scan_files` (multiple files in one call) and `scan_diff`
(parse unified diff, scan only added lines with correct line mapping) for batch
scanning workflows. (v1.2.1)

---

## v1.3 — Analysis Depth & Accuracy

### Strategic Direction

Deepen analysis capabilities and establish measurable accuracy benchmarks.
Move from "good enough" pattern matching to verified precision/recall numbers
that users can trust.

### Features

**Enhanced JS/TS Analysis** — Improved AST-level analysis for JavaScript and
TypeScript (tree-sitter or improved regex-based AST). Close the gap between
Python's `ast`-based analysis and JS/TS regex heuristics.

**Inter-File Analysis** — Basic cross-file taint tracking. Follow data flow
across imports within a project (single-repo scope). Start with Python's
well-defined import system.

**Precision/Recall Benchmark Suite** — Automated benchmarks against OWASP
Benchmark, NIST Juliet Test Suite, and custom test corpora. Track P/R per
vulnerability type per language across releases.

**Richer Dedup Fingerprinting** — Add semantic context to finding fingerprints
so that code reformatting doesn't create "new" findings. Reduce churn in
delta scans.

**IaC Scanning** — Infrastructure-as-code pattern detection for Terraform
(`.tf`), Dockerfiles, and Kubernetes YAML. Detect publicly exposed ports,
overprivileged IAM, unencrypted storage.

### Design Constraints

- Cross-file analysis must remain stdlib-only (no tree-sitter C bindings)
- Benchmarks must be reproducible and run in CI
- IaC patterns follow the same 7-element tuple format as code patterns

---

## v1.4 — AI-Native Security

### Strategic Direction

Leverage GuardianShield's unique position as an MCP server to build security
features that only make sense in an AI-agent context. These features use the
AI client's reasoning capabilities as a force multiplier.

### Features

**Agent Action Firewall** — Scan shell commands, file writes, and network
requests before the AI agent executes them. The MCP client sends the proposed
action; GuardianShield evaluates it and returns allow/block/warn.

**Security Unit Test Generator** — For confirmed true positive findings,
generate targeted unit tests that verify the vulnerability exists and that
the fix resolves it. Output as pytest/jest test files.

**AI-Driven Remediation Proposals** — Generate contextual patches for confirmed
findings. The triage prompt identifies the issue; the remediation prompt
produces a diff that fixes it, respecting the project's coding patterns.

**Contextual Secure Coding Copilot** — Real-time warnings as code is written.
The AI client sends incremental code; GuardianShield returns immediate
feedback on security implications.

**Patch-Risk Simulator** — Given a diff, estimate the security risk delta.
"This PR increases command injection surface by adding 2 new shell calls
with user-controlled arguments."

### Design Constraints

- Action firewall must be fast (<50ms per check) to avoid blocking agent flow
- Generated tests must be self-contained and runnable without project setup
- Remediation patches must preserve existing code style

---

## v1.5 — Enterprise & Ecosystem

### Strategic Direction

Enable team-wide deployment, policy enforcement, and ecosystem integration
for organizations adopting GuardianShield across multiple projects and teams.

### Features

**Streamable HTTP Transport** — SSE-based HTTP transport for remote/centralized
deployment. Team-wide policy enforcement from a shared GuardianShield instance.
Centralized audit logging across multiple developers. The stdio transport
remains the default for local development.

**Policy-as-Code Enforcement** — `.guardianshield-policy.yaml` files that define
organizational security policies. Block merges with unresolved HIGH+ findings,
require suppression justifications, enforce minimum scan coverage.

**Custom Pattern SDK** — User-defined pattern packs loaded from
`.guardianshield/patterns/`. Pattern testing workflow (using existing
`test_pattern` tool). Community pattern marketplace via Git repositories.
Pattern performance profiling with regex complexity warnings.

**License Compliance Scanning** — SPDX and CycloneDX SBOM generation.
License compatibility checking. Flag GPL dependencies in MIT/Apache projects.

**Local Security Dashboard** — HTML report generation with finding trends,
severity distribution, and remediation progress over time. Standalone HTML
file with embedded charts — no external dependencies.

**Attack-Path Mode** — Combine code vulnerability findings with dependency
CVE data to map potential exploit chains. "User input → SQL injection in
app/db.py → database contains credentials for AWS (found in .env)."

### Design Constraints

- HTTP transport must support both SSE (streaming) and batch (request/response)
- Policy files must be human-readable YAML with schema validation
- Dashboard must be a single self-contained HTML file

---

## Long-Term Vision

Features under consideration for future releases, not yet scheduled:

- **Semantic code search** — Natural language queries for vulnerability patterns
  ("find all places where user input reaches a database query")
- **Cross-language cross-file analysis** — Track data flow across language
  boundaries (e.g., Python backend → JavaScript frontend)
- **Runtime security monitoring** — Correlate static findings with runtime
  behavior for confirmed exploitability
- **AI model security scanning** — Detect prompt injection vulnerabilities
  in AI application code (system prompts, tool definitions)
- **Compliance report generation** — Automated SOC 2, HIPAA, PCI-DSS
  compliance reports based on scan results and policy adherence

---

## Design Principles (All Releases)

1. **Zero dependencies** — stdlib only. Always. Every feature must work with
   `pip install guardianshield` and nothing else.
2. **MCP-first** — Every feature is accessible via the MCP tool interface.
   The Python API mirrors MCP tools 1:1.
3. **Embedded storage** — All state in local SQLite. No external services,
   no cloud accounts, no API keys required.
4. **Backward compatible** — New features are additive. Existing clients
   and tests never break.
5. **Independent component** — GuardianShield is a black box. Clients send
   code in, get findings back. Internal strategy is an implementation detail.
6. **Privacy-first** — No telemetry, no phone-home. All analysis happens
   locally. False positive filtering via AI triage prompts, not data collection.
7. **Measurable accuracy** — From v1.3 onward, every release includes
   precision/recall benchmarks against standard test suites.

---

## Cross-AI Review Summary

This roadmap incorporates strategic feedback from independent reviews by
**Gemini CLI** and **Codex CLI** (March 2026). Key consensus findings:

- **CI integration is the #1 adoption blocker** — SARIF + GitHub Actions
  templates are critical for team adoption (→ v1.2)
- **Accuracy must be measurable** — Without benchmarks, users can't compare
  GuardianShield to alternatives (→ v1.3)
- **AI-native features are the differentiator** — Action firewall, test
  generation, and remediation proposals are unique to MCP-first architecture
  (→ v1.4)
- **Enterprise features unlock organizational adoption** — Policy enforcement
  and centralized deployment are table stakes for security tools (→ v1.5)
- **Novel ideas prioritized**: agent action firewall, security test generator,
  patch-risk simulator, attack-path mode
