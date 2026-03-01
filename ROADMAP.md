# GuardianShield Roadmap

> Living document tracking planned features, architecture evolution,
> and release milestones. Updated as designs are validated.

---

## Current State (v1.0.2)

- **19 MCP tools** | **1362 tests** | **Zero dependencies**
- 7 language scanners (Python, JS/TS, Go, Java, Ruby, PHP, C#) with 83+ patterns
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
│  │ DeepEngine (built-in, new)                      │    │
│  │                                                 │    │
│  │ Cross-line analysis using lightweight AST-free  │    │
│  │ data flow tracking:                             │    │
│  │                                                 │    │
│  │ - Variable assignment tracking (x = input())    │    │
│  │ - Taint propagation (y = f"SELECT {x}")         │    │
│  │ - Sink detection (cursor.execute(y))            │    │
│  │ - Cross-function flow (within same file)        │    │
│  │                                                 │    │
│  │ Strengths: Catches multi-line vulnerabilities   │    │
│  │ Blind spots: No cross-file, no type inference   │    │
│  │ Speed: ~10ms per 1K lines                       │    │
│  │ Deps: Zero (stdlib only, no AST library)        │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │ SemanticEngine (built-in, new)                  │    │
│  │                                                 │    │
│  │ Structure-aware analysis using Python's ast     │    │
│  │ module (stdlib) for Python code, and regex-     │    │
│  │ based block detection for other languages:      │    │
│  │                                                 │    │
│  │ - Function/class scope awareness                │    │
│  │ - Import chain analysis                         │    │
│  │ - Reachability from entry points                │    │
│  │ - Context-aware confidence adjustment           │    │
│  │   (e.g., test files get lower confidence)       │    │
│  │                                                 │    │
│  │ Strengths: Reduces false positives via context  │    │
│  │ Blind spots: Single-file only                   │    │
│  │ Speed: ~50ms per 1K lines                       │    │
│  │ Deps: Zero (ast is stdlib for Python)           │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─── Result Pipeline ────────────────────────────────────┐
│                                                         │
│  1. Collect findings from all active engines            │
│  2. Deduplicate (FindingDeduplicator)                   │
│  3. Merge confidence scores (highest wins)              │
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

**Phase 1: Engine abstraction + RegexEngine wrapper**
- Define `AnalysisEngine` protocol
- Wrap current `scanner.py` as `RegexEngine`
- Add engine registry to core.py
- Add `list_engines` MCP tool
- All existing tests continue to pass

**Phase 2: DeepEngine (cross-line data flow)**
- Variable assignment tracker (regex-based, no AST)
- Taint source identification (user input, request params, env vars)
- Sink detection (SQL exec, shell exec, file write, response render)
- Propagation through string formatting, concatenation, function args
- New finding type or confidence boost for confirmed data flows

**Phase 3: SemanticEngine (structure-aware)**
- Python: `ast` module for scope, imports, reachability
- Other languages: regex-based block/function detection
- Context-aware confidence adjustment
- Test file detection (lower confidence for test code)

**Phase 4: Result pipeline**
- Multi-engine dedup with confidence merging
- Engine-specific evidence in `details`
- Performance benchmarks and engine selection heuristics

---

## v1.2 — Streamable HTTP Transport

Planned SSE-based HTTP transport for remote/centralized scenarios:

- Team-wide policy enforcement from a shared GuardianShield instance
- Centralized audit logging across multiple developers
- The stdio transport remains the default for local development

See `docs/architecture.md` for design notes.

---

## v1.3 — Custom Pattern SDK

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
