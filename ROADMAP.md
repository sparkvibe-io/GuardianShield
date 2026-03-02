# GuardianShield Roadmap

> Living document tracking planned features, architecture evolution,
> and release milestones. Updated as designs are validated.

---

## Current State (v1.1.0)

- **21 MCP tools** | **~1550 tests** | **Zero dependencies**
- 7 language scanners (Python, JS/TS, Go, Java, Ruby, PHP, C#) with 108+ patterns
- 3 analysis engines: RegexEngine (pattern matching), DeepEngine (taint tracking),
  SemanticEngine (confidence adjustment)
- Result pipeline: multi-engine dedup, confidence merging, engine timing
- Enriched finding details (code context, match explanations, CWE/OWASP references)
- False positive feedback loop (per-project SQLite, pattern-level learning)
- Local OSV.dev dependency scanner (PyPI, npm, Go, Packagist)
- 5 safety profiles with per-scanner sensitivity control

---

## v1.1 — Multi-Engine Analysis Pipeline

### Vision

Currently, all scanning uses a single strategy: **regex pattern matching**.
This is fast and effective for known vulnerability shapes, but has blind spots:

- Cannot track data flow across lines (e.g., a user input assigned on line 5,
  used in a SQL query on line 20)
- Cannot reason about code structure (e.g., whether a function is reachable
  from an HTTP handler)
- Cannot assess whether a matched pattern is actually exploitable in context

v1.1 introduces **Analysis Engines** — pluggable scanning strategies that
iterate through the same code, each adding findings from their perspective.
Results are compiled, merged (deduplicated), and then annotated with false
positive feedback before being returned to the client.

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
│  class AnalysisEngine(Protocol):                        │
│      name: str                                          │
│      def analyze(code, language, sensitivity)            │
│          -> list[Finding]                                │
│      def capabilities() -> dict                         │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │ RegexEngine (built-in, default)                 │    │
│  │                                                 │    │
│  │ What it does today — compiled regex patterns    │    │
│  │ per language, line-by-line matching.             │    │
│  │                                                 │    │
│  │ Strengths: Fast, deterministic, zero deps       │    │
│  │ Blind spots: No cross-line, no data flow        │    │
│  │ Speed: ~1ms per 1K lines                        │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │ DeepEngine (built-in)                            │    │
│  │                                                 │    │
│  │ Cross-line analysis using taint tracking        │    │
│  │ (ast for Python, regex for JS/TS):              │    │
│  │                                                 │    │
│  │ - Variable assignment tracking (x = input())    │    │
│  │ - Taint propagation (y = f"SELECT {x}")         │    │
│  │ - Sink detection (cursor.execute(y))            │    │
│  │ - Cross-function flow (within same file)        │    │
│  │                                                 │    │
│  │ Strengths: Catches multi-line vulnerabilities   │    │
│  │ Blind spots: No cross-file, no type inference   │    │
│  │ Speed: ~10ms per 1K lines                       │    │
│  │ Deps: Zero (stdlib ast for Python, regex for JS) │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │ SemanticEngine (built-in)                        │    │
│  │                                                 │    │
│  │ Structure-aware confidence adjustment using      │    │
│  │ Python's ast (stdlib) and regex heuristics       │    │
│  │ for JS/TS:                                      │    │
│  │                                                 │    │
│  │ - Test file detection (-0.3 confidence)         │    │
│  │ - Dead code detection (-0.3)                    │    │
│  │ - Exception handler context (-0.15)             │    │
│  │ - Uncalled function detection (-0.2)            │    │
│  │ - Unused import detection (-0.25)               │    │
│  │                                                 │    │
│  │ Strengths: Reduces false positives via context  │    │
│  │ Blind spots: Single-file only                   │    │
│  │ Speed: fast (post-processing, no new findings)  │    │
│  │ Deps: Zero (ast is stdlib for Python)           │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─── Result Pipeline (pipeline.py) ──────────────────────┐
│                                                         │
│  1. Run engines with timed_analyze() (skip semantic)   │
│  2. merge_engine_findings():                            │
│     - Group by (file_path, line, finding_type)          │
│     - Single-engine groups: pass through                │
│     - Multi-engine groups: keep highest confidence,     │
│       boost +0.1 per extra engine, merge evidence       │
│  3. SemanticEngine.adjust_findings() (if enabled)       │
│  4. Annotate with false positive feedback               │
│  5. Return unified list[Finding]                        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Scan Flow

When a scan is requested:

1. **Engine selection** — The profile specifies which engines to run
   (default: all enabled). Clients can override via an `engine` parameter.
2. **Parallel execution** — Each engine analyzes the same code independently.
3. **Result compilation** — Findings from all engines are collected into a
   single list.
4. **Deduplication** — If RegexEngine and DeepEngine both find the same
   SQL injection on line 20, keep the one with higher confidence.
5. **Confidence merging** — When DeepEngine confirms a RegexEngine finding
   with data flow evidence, confidence is boosted.
6. **FP annotation** — False positive feedback is applied last.
7. **Return** — Client receives one unified `list[Finding]` regardless of
   how many engines ran.

### MCP Interface Changes

New/modified tools:

```
list_engines        → Returns available engines, their capabilities, and status
set_engine          → Enable/disable engines, set default engine for profile
scan_code           → New optional "engines" param (list of engine names)
shield_status       → Includes engine info in response
```

The `Finding.details` dict gains an `engine` field:
```python
{
    "engine": "deep_engine",
    "engine_evidence": "Data flows from user_input (line 5) to sql_query (line 20)",
    ...existing fields...
}
```

### Design Constraints

- **Zero external dependencies** — All engines use Python stdlib only.
  DeepEngine uses regex-based data flow. SemanticEngine uses `ast` (stdlib)
  for Python, regex heuristics for other languages.
- **Backward compatible** — Existing scans work exactly as before.
  RegexEngine wraps the current `scanner.py` code. New engines are additive.
- **Same Finding format** — Clients don't need to change. A finding from
  DeepEngine looks identical to one from RegexEngine, just with richer
  `details`.
- **Profile-controlled** — Engine selection integrates with the existing
  profile system. The `ScannerConfig` gains an `engines` field.
- **Embedded storage** — Engine configurations, capabilities, and state
  stored in SQLite. No external config files required.

### Implementation Phases

**Phase 1: Engine abstraction + RegexEngine wrapper** ✅ DONE (v1.1.0b1)
- Define `AnalysisEngine` protocol
- Wrap current `scanner.py` as `RegexEngine`
- Add engine registry to core.py
- Add `list_engines` MCP tool
- All existing tests continue to pass

**Phase 2: DeepEngine (cross-line data flow)** ✅ DONE (v1.1.0b1)
- Variable assignment tracking (ast for Python, regex for JS/TS)
- Taint source identification (user input, request params, env vars)
- Sink detection (SQL exec, shell exec, file write, response render)
- Propagation through string formatting, concatenation, function args
- Confidence 0.70–0.90 based on TaintKind + chain length

**Phase 3: SemanticEngine (structure-aware)** ✅ DONE (v1.1.1)
- Python: `ast` module for dead code, exception handlers, uncalled functions, unused imports
- JS/TS: regex-based function/call/export detection
- Test file detection via 11 path patterns (all languages)
- Context-aware confidence adjustment (cumulative, floor 0.1)

**Phase 4: Result pipeline** ✅ DONE (v1.1.1)
- `merge_engine_findings()`: cross-engine dedup by (file, line, type)
- Confidence boost (+0.1 per confirming engine, cap 1.0)
- `timed_analyze()`: engine timing with `EngineTimingResult`
- Engine evidence collection in `details["engine_evidence"]`
- `status()` includes `engine_timings` from latest scan

---

## v1.2 — AI-Assisted Triage + Developer Experience

### Strategic Direction

91%+ of SAST findings are false positives (Ghost Security, 2025). Traditional
tools address this with either telemetry pipelines (privacy concerns, low
adoption) or manual triage workflows (slow, error-prone). Neither works for
AI-first development.

GuardianShield's MCP architecture uniquely positions it to solve this
differently: **the AI client already has full code context**. Instead of
collecting feedback or phoning home, we teach the AI to triage findings using
domain-specific knowledge — the same approach validated at scale by Semgrep
Assistant (96% researcher agreement using Claude with CWE-specific context)
and ZeroFalse (F1 > 0.95 with CWE-specialized prompts).

### Features

**CWE-Specific Triage Prompts** (MCP prompts)

Structured per-vulnerability-type guidance that teaches the user's AI how to
evaluate findings. Each triage prompt covers a specific CWE and includes:

- True positive indicators (what makes this finding real)
- False positive indicators (what makes this finding safe)
- Specific questions to answer about the code context
- What surrounding code to examine (sanitizers, validators, framework guards)

Covered vulnerability types:
- SQL injection (CWE-89)
- Cross-site scripting / XSS (CWE-79)
- Command injection (CWE-78)
- Path traversal (CWE-22)
- Insecure deserialization (CWE-502)
- Hardcoded secrets (CWE-798)
- Server-side request forgery / SSRF (CWE-918)
- And more as patterns are added

The AI client receives findings + triage prompts, applies them using its full
view of the codebase, and returns only actionable results. No data leaves the
developer's machine.

**Inline Suppression** (planned)

`# guardianshield:ignore` comments for intentional dismissals — lets developers
mark known-safe patterns directly in source code.

**SARIF Export** (planned)

Standard SARIF output format for interoperability with GitHub Code Scanning,
VS Code SARIF Viewer, and other tools in the security ecosystem.

---

## v1.3 — Streamable HTTP Transport

Planned SSE-based HTTP transport for remote/centralized scenarios:

- Team-wide policy enforcement from a shared GuardianShield instance
- Centralized audit logging across multiple developers
- The stdio transport remains the default for local development

See `docs/architecture.md` for design notes.

---

## v1.4 — Custom Pattern SDK

- User-defined pattern packs (load from `.guardianshield/patterns/`)
- Pattern testing workflow (`test_pattern` tool already exists)
- Community pattern marketplace (share pattern packs via Git)
- Pattern performance profiling (regex complexity warnings)

---

## Design Principles (All Releases)

1. **Zero dependencies** — stdlib only. Always.
2. **MCP-first** — Every feature is accessible via the MCP tool interface.
3. **Embedded storage** — All state in local SQLite. No external services.
4. **Backward compatible** — New features are additive. Existing clients
   and tests never break.
5. **Independent component** — GuardianShield is a black box. Clients send
   code in, get findings back. Internal strategy is an implementation detail.
6. **Privacy-first** — No telemetry, no phone-home. False positive filtering
   happens locally via AI triage prompts.
