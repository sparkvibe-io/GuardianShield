# AGENTS.md

## MemoryMesh Synced Memories

> Synced from MemoryMesh. Last synced: 2026-02-21 06:04 UTC

### Common Mistakes

- Key lesson from agent feedback: AI agents can't read logs or manually debug. Silent failures are fatal for MCP tools. Always: (1) provide a health/status tool, (2) include diagnostics in error messages showing what was tried, (3) offer runtime reconfiguration without restart, (4) proactively warn in session_start when something is degraded. <!-- memorymesh:importance=0.95 -->

### Patterns & Conventions

- Hero CSS: premium dark gradient (#0a0a0f → #1a1a2e), glassmorphism cards, CSS custom properties for theming, mobile-first grid, backdrop-filter for depth. <!-- memorymesh:importance=0.85 -->
- Docs guidelines: tabbed interfaces for multi-lang, copy-paste code blocks, progressive disclosure, dark-first theme, concrete examples over abstract descriptions. <!-- memorymesh:importance=0.85 -->
- Landing page research (2026-02): Analyzed Supabase, Linear, Vercel, Raycast. Best practices: hero with code snippet, dark-first, gradient accents, tabbed features, social proof. <!-- memorymesh:importance=0.80 -->
- Website review: spawn 3 parallel agents for design, copy, and technical review. Compare against 5+ competitor sites. Check mobile, dark mode, accessibility. <!-- memorymesh:importance=0.80 -->

### Guardrails

- Design principles: simplicity, zero dependencies, framework-agnostic, cross-platform, privacy-first (no telemetry/cloud unless configured). <!-- memorymesh:importance=0.70 -->

### User Profile

- Code conventions: type hints, Google-style docstrings, dataclasses over dicts, no global mutable state, MIT license, ruff + pytest. <!-- memorymesh:importance=0.70 -->

### Other

- GuardianShield architecture map is maintained at `.openspek/architecture.json` and uses the OpenSpek node/edge schema (nodes: id/label/node_type/icon/description/children; edges: from/to/label/direction). <!-- memorymesh:importance=0.92 -->

### User-Patterns

- Krishna's patterns: asks 'what does this mean' before acting, tests CLI hands-on, wants brutal honesty, prefers speed once decided, thinks about accessibility for everyone. <!-- memorymesh:importance=0.90 -->
