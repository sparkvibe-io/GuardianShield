"""DeepEngine — cross-line data flow analysis via taint tracking.

Implements the second analysis engine for GuardianShield's multi-engine
pipeline.  While the regex engine matches patterns line-by-line, DeepEngine
tracks data flowing across lines — e.g., user input assigned on line 5
used in a SQL query on line 20.

Uses Python's stdlib ``ast`` module for Python analysis and regex-based
assignment extraction for JavaScript/TypeScript.  Zero external dependencies.
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .enrichment import enrich_finding
from .findings import Finding, FindingType, Range, Severity
from .patterns import EXTENSION_MAP

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


class TaintKind(str, Enum):
    """Category of taint origin."""

    USER_INPUT = "user_input"
    REQUEST_PARAM = "request_param"
    ENV_VAR = "env_var"
    FILE_READ = "file_read"
    EXTERNAL_DATA = "external_data"


@dataclass
class TaintSource:
    """A point where tainted data enters the program."""

    variable: str
    kind: TaintKind
    line_number: int
    expression: str
    scope: str


@dataclass
class TaintSink:
    """A dangerous function call that consumes data."""

    function: str
    finding_type: FindingType
    severity: Severity
    cwe_ids: list[str]
    line_number: int
    argument_text: str
    scope: str


@dataclass
class TaintedVariable:
    """A variable known to carry tainted data."""

    name: str
    source: TaintSource
    line_number: int
    propagation_chain: list[str]
    scope: str


@dataclass
class DataFlowChain:
    """A complete source-to-sink data flow path."""

    source: TaintSource
    sink: TaintSink
    variables: list[TaintedVariable]
    confidence: float

    def evidence_string(self) -> str:
        """Build a human-readable evidence string."""
        if self.variables:
            chain_str = " -> ".join(self.variables[-1].propagation_chain)
        else:
            chain_str = "(direct)"
        return (
            f"Tainted data flows from {self.source.expression!r} "
            f"(line {self.source.line_number}, {self.source.kind.value}) "
            f"through [{chain_str}] "
            f"to {self.sink.function}() (line {self.sink.line_number})"
        )


# ---------------------------------------------------------------------------
# Internal assignment representation
# ---------------------------------------------------------------------------


@dataclass
class _Assignment:
    """An extracted variable assignment."""

    target: str
    value_text: str
    line_number: int
    scope: str


# ---------------------------------------------------------------------------
# Comment detection (reuses scanner.py convention)
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"""^\s*(?:#|//|/\*|\*)""")

# ---------------------------------------------------------------------------
# Severity helpers (mirrors scanner.py logic)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def _min_severity(sensitivity: str) -> int:
    s = sensitivity.lower()
    if s == "low":
        return _SEVERITY_ORDER[Severity.CRITICAL]
    if s == "medium":
        return _SEVERITY_ORDER[Severity.MEDIUM]
    return _SEVERITY_ORDER[Severity.INFO]


# ---------------------------------------------------------------------------
# Python taint source patterns (~19)
# ---------------------------------------------------------------------------

_PYTHON_SOURCES: list[tuple[re.Pattern[str], TaintKind]] = [
    # User input
    (re.compile(r"\binput\s*\("), TaintKind.USER_INPUT),
    # Flask / Werkzeug request
    (re.compile(r"\brequest\.args\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\brequest\.form\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\brequest\.data\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\brequest\.json\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\brequest\.values\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\brequest\.files\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\brequest\.cookies\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\brequest\.headers\b"), TaintKind.REQUEST_PARAM),
    # Django request
    (re.compile(r"\brequest\.GET\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\brequest\.POST\b"), TaintKind.REQUEST_PARAM),
    # FastAPI / DRF
    (re.compile(r"\brequest\.query_params\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\brequest\.path_params\b"), TaintKind.REQUEST_PARAM),
    # Environment variables
    (re.compile(r"\bos\.environ\b"), TaintKind.ENV_VAR),
    (re.compile(r"\bos\.getenv\s*\("), TaintKind.ENV_VAR),
    # File reads
    (re.compile(r"\.read\s*\("), TaintKind.FILE_READ),
    (re.compile(r"\.readlines?\s*\("), TaintKind.FILE_READ),
    # External data deserialization
    (re.compile(r"\bjson\.loads?\s*\("), TaintKind.EXTERNAL_DATA),
    (re.compile(r"\byaml\.(?:safe_)?load\s*\("), TaintKind.EXTERNAL_DATA),
]

# ---------------------------------------------------------------------------
# JavaScript / TypeScript taint source patterns (~10)
# ---------------------------------------------------------------------------

_JS_SOURCES: list[tuple[re.Pattern[str], TaintKind]] = [
    # Express request
    (re.compile(r"\breq\.params\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\breq\.query\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\breq\.body\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\breq\.headers\b"), TaintKind.REQUEST_PARAM),
    (re.compile(r"\breq\.cookies\b"), TaintKind.REQUEST_PARAM),
    # Environment
    (re.compile(r"\bprocess\.env\b"), TaintKind.ENV_VAR),
    # DOM / browser
    (re.compile(r"\.getElementById\s*\(.*\)\.value\b"), TaintKind.USER_INPUT),
    (re.compile(r"\.querySelector\s*\(.*\)\.value\b"), TaintKind.USER_INPUT),
    (re.compile(r"\bwindow\.location\b"), TaintKind.USER_INPUT),
    # File system
    (re.compile(r"\bfs\.readFileSync\s*\("), TaintKind.FILE_READ),
]

# ---------------------------------------------------------------------------
# Sink pattern type alias
# ---------------------------------------------------------------------------

_SinkDef = tuple[re.Pattern[str], str, FindingType, Severity, list[str]]

# ---------------------------------------------------------------------------
# Python taint sink patterns (~12)
# ---------------------------------------------------------------------------

_PYTHON_SINKS: list[_SinkDef] = [
    # SQL Injection
    (
        re.compile(
            r"(?:cursor|conn(?:ection)?|db|session)"
            r"\s*\.\s*execute(?:many)?\s*\("
        ),
        "cursor.execute",
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        ["CWE-89"],
    ),
    # Command Injection
    (
        re.compile(r"\bos\.system\s*\("),
        "os.system",
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(
            r"\bsubprocess\."
            r"(?:call|run|Popen|check_output|check_call)\s*\("
        ),
        "subprocess",
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"\bexec\s*\(\s*(?![\"']\s*\))"),
        "exec",
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        ["CWE-94"],
    ),
    (
        re.compile(r"\beval\s*\(\s*(?![\"']\s*\))"),
        "eval",
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        ["CWE-94"],
    ),
    # Path Traversal
    (
        re.compile(r"\bopen\s*\("),
        "open",
        FindingType.PATH_TRAVERSAL,
        Severity.HIGH,
        ["CWE-22"],
    ),
    (
        re.compile(r"\bos\.path\.join\s*\("),
        "os.path.join",
        FindingType.PATH_TRAVERSAL,
        Severity.MEDIUM,
        ["CWE-22"],
    ),
    # XSS / Template Injection
    (
        re.compile(r"\brender_template_string\s*\("),
        "render_template_string",
        FindingType.XSS,
        Severity.HIGH,
        ["CWE-79"],
    ),
    (
        re.compile(r"\bMarkup\s*\("),
        "Markup",
        FindingType.XSS,
        Severity.HIGH,
        ["CWE-79"],
    ),
    (
        re.compile(r"\bmake_response\s*\("),
        "make_response",
        FindingType.XSS,
        Severity.MEDIUM,
        ["CWE-79"],
    ),
]

# ---------------------------------------------------------------------------
# JavaScript / TypeScript taint sink patterns (~10)
# ---------------------------------------------------------------------------

_JS_SINKS: list[_SinkDef] = [
    # SQL Injection
    (
        re.compile(r"(?:db|connection|pool|client)\s*\.\s*query\s*\("),
        "db.query",
        FindingType.SQL_INJECTION,
        Severity.CRITICAL,
        ["CWE-89"],
    ),
    # Command Injection — detection patterns for scanning target code.
    # These are regex matchers, NOT actual exec() calls.
    (
        re.compile(r"child_process\s*\.\s*exec\w*\s*\("),
        "child_process.exec",
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"\bexecSync\s*\("),
        "execSync",
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"\beval\s*\("),
        "eval",
        FindingType.COMMAND_INJECTION,
        Severity.CRITICAL,
        ["CWE-94"],
    ),
    (
        re.compile(r"\bnew\s+Function\s*\("),
        "new Function",
        FindingType.COMMAND_INJECTION,
        Severity.HIGH,
        ["CWE-94"],
    ),
    # XSS
    (
        re.compile(r"\.innerHTML\s*="),
        "innerHTML",
        FindingType.XSS,
        Severity.HIGH,
        ["CWE-79"],
    ),
    (
        re.compile(r"\bdocument\.write\s*\("),
        "document.write",
        FindingType.XSS,
        Severity.HIGH,
        ["CWE-79"],
    ),
    (
        re.compile(r"\bres\.send\s*\("),
        "res.send",
        FindingType.XSS,
        Severity.MEDIUM,
        ["CWE-79"],
    ),
    # Path Traversal
    (
        re.compile(
            r"\bfs\.(?:readFileSync|writeFileSync|appendFileSync)\s*\("
        ),
        "fs.writeFileSync",
        FindingType.PATH_TRAVERSAL,
        Severity.HIGH,
        ["CWE-22"],
    ),
]

# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

_BASE_CONFIDENCE: dict[TaintKind, float] = {
    TaintKind.USER_INPUT: 0.85,
    TaintKind.REQUEST_PARAM: 0.90,
    TaintKind.ENV_VAR: 0.70,
    TaintKind.FILE_READ: 0.75,
    TaintKind.EXTERNAL_DATA: 0.80,
}


def _compute_confidence(chain: DataFlowChain) -> float:
    """Compute confidence for a data flow chain (0.70-0.90)."""
    base = _BASE_CONFIDENCE.get(chain.source.kind, 0.75)
    hops = len(chain.variables[-1].propagation_chain) if chain.variables else 1
    base -= max(0, hops - 1) * 0.02
    return max(0.70, min(0.90, base))


# ---------------------------------------------------------------------------
# AST scope walker (Python)
# ---------------------------------------------------------------------------


def _walk_with_scope(
    node: ast.AST,
    scope: str = "__module__",
):
    """Yield ``(node, scope)`` pairs, tracking function scopes."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        # The def node itself lives in the parent scope;
        # its body lives in the function's scope.
        yield node, scope
        for child in ast.iter_child_nodes(node):
            yield from _walk_with_scope(child, node.name)
    else:
        yield node, scope
        for child in ast.iter_child_nodes(node):
            yield from _walk_with_scope(child, scope)


# ---------------------------------------------------------------------------
# Assignment extraction — Python (AST with regex fallback)
# ---------------------------------------------------------------------------

_PY_ASSIGN_RE = re.compile(r"^\s*(\w+)\s*=\s*(.+)$")


def _extract_target_names(node: ast.AST) -> list[str]:
    """Extract variable names from an AST assignment target."""
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in node.elts:
            names.extend(_extract_target_names(elt))
        return names
    return []


def _extract_assignments_python(
    code: str,
    lines: list[str],
) -> list[_Assignment]:
    """Extract assignments from Python code using AST (regex fallback)."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return _extract_assignments_regex(lines, _PY_ASSIGN_RE)

    assignments: list[_Assignment] = []
    for node, scope in _walk_with_scope(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                for name in _extract_target_names(target):
                    line_idx = node.lineno - 1
                    vt = lines[line_idx] if 0 <= line_idx < len(lines) else ""
                    assignments.append(_Assignment(
                        target=name,
                        value_text=vt,
                        line_number=node.lineno,
                        scope=scope,
                    ))
        elif (
            isinstance(node, ast.AnnAssign)
            and node.value is not None
            and isinstance(node.target, ast.Name)
        ):
            line_idx = node.lineno - 1
            vt = lines[line_idx] if 0 <= line_idx < len(lines) else ""
            assignments.append(_Assignment(
                target=node.target.id,
                value_text=vt,
                line_number=node.lineno,
                scope=scope,
            ))
    return assignments


# ---------------------------------------------------------------------------
# Assignment extraction — regex (JS and Python fallback)
# ---------------------------------------------------------------------------

_JS_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?(\w+)\s*=\s*(.+?);\s*$"
)


def _extract_assignments_regex(
    lines: list[str],
    pattern: re.Pattern[str],
) -> list[_Assignment]:
    """Extract assignments via regex (no scope tracking)."""
    assignments: list[_Assignment] = []
    for i, line in enumerate(lines, 1):
        m = pattern.match(line)
        if m:
            assignments.append(_Assignment(
                target=m.group(1),
                value_text=line,
                line_number=i,
                scope="__module__",
            ))
    return assignments


# ---------------------------------------------------------------------------
# Assignment extraction — JavaScript
# ---------------------------------------------------------------------------

_JS_FUNC_RE = re.compile(
    r"(?:function\s+(\w+)\s*\(|"
    r"(?:const|let|var)\s+(\w+)\s*=\s*"
    r"(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>))"
)


def _build_scope_map_js(lines: list[str]) -> dict[int, str]:
    """Build a line-number-to-scope map for JS using brace tracking."""
    scope_map: dict[int, str] = {}
    scope_stack: list[tuple[str, int]] = []
    current_scope = "__module__"
    brace_depth = 0

    for i, line in enumerate(lines, 1):
        m = _JS_FUNC_RE.search(line)
        if m and "{" in line[m.end():]:
            name = m.group(1) or m.group(2) or f"_anon_{i}"
            scope_stack.append((current_scope, brace_depth))
            current_scope = name

        scope_map[i] = current_scope

        brace_depth += line.count("{") - line.count("}")

        while scope_stack and brace_depth <= scope_stack[-1][1]:
            current_scope, _ = scope_stack.pop()

    return scope_map


def _extract_assignments_js(lines: list[str]) -> list[_Assignment]:
    """Extract assignments from JavaScript code."""
    scope_map = _build_scope_map_js(lines)
    assignments: list[_Assignment] = []
    for i, line in enumerate(lines, 1):
        m = _JS_ASSIGN_RE.match(line)
        if m:
            assignments.append(_Assignment(
                target=m.group(1),
                value_text=line,
                line_number=i,
                scope=scope_map.get(i, "__module__"),
            ))
    return assignments


# ---------------------------------------------------------------------------
# Scope map — Python (AST-based)
# ---------------------------------------------------------------------------


def _build_scope_map_python(code: str, line_count: int) -> dict[int, str]:
    """Map 1-based line numbers to function scope names."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {i: "__module__" for i in range(1, line_count + 1)}

    func_ranges: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = node.end_lineno or node.lineno
            func_ranges.append((node.lineno, end, node.name))

    scope_map: dict[int, str] = {}
    for line_num in range(1, line_count + 1):
        scope = "__module__"
        best_size = float("inf")
        for start, end, name in func_ranges:
            if start <= line_num <= end:
                size = end - start
                if size < best_size:
                    best_size = size
                    scope = name
        scope_map[line_num] = scope

    return scope_map


# ---------------------------------------------------------------------------
# Phase 2 — Identify taint sources
# ---------------------------------------------------------------------------


def _identify_sources(
    assignments: list[_Assignment],
    source_patterns: list[tuple[re.Pattern[str], TaintKind]],
) -> list[TaintedVariable]:
    """Match assignment RHS against source patterns."""
    tainted: list[TaintedVariable] = []
    for assign in assignments:
        for pattern, kind in source_patterns:
            if pattern.search(assign.value_text):
                source = TaintSource(
                    variable=assign.target,
                    kind=kind,
                    line_number=assign.line_number,
                    expression=assign.value_text.strip(),
                    scope=assign.scope,
                )
                tainted.append(TaintedVariable(
                    name=assign.target,
                    source=source,
                    line_number=assign.line_number,
                    propagation_chain=[assign.target],
                    scope=assign.scope,
                ))
                break  # first source pattern match wins
    return tainted


# ---------------------------------------------------------------------------
# Phase 3 — Propagate taint
# ---------------------------------------------------------------------------


def _propagate_taint(
    assignments: list[_Assignment],
    tainted: list[TaintedVariable],
    max_passes: int = 5,
) -> list[TaintedVariable]:
    """Multi-pass taint propagation through assignments."""
    for _ in range(max_passes):
        new_tainted: list[TaintedVariable] = []
        tainted_keys = {(tv.name, tv.scope) for tv in tainted}

        for assign in assignments:
            if (assign.target, assign.scope) in tainted_keys:
                continue  # already tainted

            for tv in tainted:
                # Scope check: tainted var must be accessible
                if tv.scope != assign.scope and tv.scope != "__module__":
                    continue

                if re.search(rf"\b{re.escape(tv.name)}\b", assign.value_text):
                    new_tv = TaintedVariable(
                        name=assign.target,
                        source=tv.source,
                        line_number=assign.line_number,
                        propagation_chain=[*tv.propagation_chain, assign.target],
                        scope=assign.scope,
                    )
                    new_tainted.append(new_tv)
                    tainted_keys.add((assign.target, assign.scope))
                    break  # first taint source wins

        if not new_tainted:
            break  # fixed point reached

        tainted.extend(new_tainted)

    return tainted


# ---------------------------------------------------------------------------
# Phase 4 — Detect sinks
# ---------------------------------------------------------------------------


def _detect_sinks(
    lines: list[str],
    sinks: list[_SinkDef],
    tainted: list[TaintedVariable],
    scope_map: dict[int, str],
) -> list[DataFlowChain]:
    """Scan lines for sink patterns and check for tainted arguments."""
    chains: list[DataFlowChain] = []

    # Index tainted vars by scope for fast lookup
    taint_by_scope: dict[str, dict[str, TaintedVariable]] = {}
    for tv in tainted:
        scope_dict = taint_by_scope.setdefault(tv.scope, {})
        scope_dict[tv.name] = tv
    module_tainted = taint_by_scope.get("__module__", {})

    seen: set[tuple[int, str]] = set()  # (line_num, sink_func) dedup

    for line_num, line in enumerate(lines, 1):
        if _COMMENT_RE.match(line):
            continue

        line_scope = scope_map.get(line_num, "__module__")

        for pattern, func_name, finding_type, severity, cwe_ids in sinks:
            m = pattern.search(line)
            if not m:
                continue

            dedup_key = (line_num, func_name)
            if dedup_key in seen:
                continue

            # Text after the match (arguments / assignment RHS)
            arg_text = line[m.end():]

            # Merge same-scope + module-scope tainted vars
            scope_tainted = taint_by_scope.get(line_scope, {})
            candidates = {**module_tainted, **scope_tainted}

            for var_name, tv in candidates.items():
                if re.search(rf"\b{re.escape(var_name)}\b", arg_text):
                    sink = TaintSink(
                        function=func_name,
                        finding_type=finding_type,
                        severity=severity,
                        cwe_ids=list(cwe_ids),
                        line_number=line_num,
                        argument_text=arg_text.strip().rstrip(")"),
                        scope=line_scope,
                    )
                    chain = DataFlowChain(
                        source=tv.source,
                        sink=sink,
                        variables=[tv],
                        confidence=0.0,
                    )
                    chain.confidence = _compute_confidence(chain)
                    chains.append(chain)
                    seen.add(dedup_key)
                    break  # one finding per sink per line

    return chains


# ---------------------------------------------------------------------------
# Phase 5 — Convert chains to findings
# ---------------------------------------------------------------------------


def _chain_to_finding(
    chain: DataFlowChain,
    code: str,
    file_path: str | None,
) -> Finding:
    """Convert a DataFlowChain into a Finding."""
    sink = chain.sink
    source = chain.source
    lines = code.splitlines()

    message = (
        f"Data flow: {source.kind.value} from line {source.line_number} "
        f"reaches {sink.function}() at line {sink.line_number} "
        f"({sink.finding_type.value})"
    )

    end_col = (
        len(lines[sink.line_number - 1])
        if sink.line_number <= len(lines)
        else 0
    )
    range_obj = Range(
        start_line=sink.line_number - 1,
        start_col=0,
        end_line=sink.line_number - 1,
        end_col=end_col,
    )

    finding = Finding(
        finding_type=sink.finding_type,
        severity=sink.severity,
        message=message,
        matched_text=sink.argument_text,
        line_number=sink.line_number,
        file_path=file_path,
        scanner="deep_engine",
        range=range_obj,
        confidence=chain.confidence,
        cwe_ids=list(sink.cwe_ids),
    )

    tv = chain.variables[-1] if chain.variables else None
    finding.details["engine"] = "deep"
    finding.details["engine_evidence"] = chain.evidence_string()
    finding.details["source_line"] = source.line_number
    finding.details["sink_line"] = sink.line_number
    finding.details["taint_kind"] = source.kind.value
    if tv:
        finding.details["propagation_chain"] = tv.propagation_chain

    return finding


# ---------------------------------------------------------------------------
# DeepEngine
# ---------------------------------------------------------------------------


class DeepEngine:
    """Cross-line data flow analysis engine via taint tracking.

    Tracks tainted data from sources (user input, request params,
    environment variables, file reads, deserialized data) through
    variable assignments to dangerous sinks (SQL execute, OS commands,
    eval, file operations, template rendering).

    Supports Python (via ``ast``) and JavaScript/TypeScript (via regex).
    """

    @property
    def name(self) -> str:
        return "deep"

    def analyze(
        self,
        code: str,
        language: str | None = None,
        sensitivity: str = "medium",
        file_path: str | None = None,
    ) -> list[Finding]:
        """Analyze code for cross-line data flow vulnerabilities."""
        lang = self._resolve_language(language, file_path)
        if lang not in ("python", "javascript"):
            return []

        lines = code.splitlines()
        if not lines:
            return []

        # Select patterns for this language
        sources = _PYTHON_SOURCES if lang == "python" else _JS_SOURCES
        sinks = _PYTHON_SINKS if lang == "python" else _JS_SINKS

        # Phase 1: Extract assignments
        if lang == "python":
            assignments = _extract_assignments_python(code, lines)
            scope_map = _build_scope_map_python(code, len(lines))
        else:
            assignments = _extract_assignments_js(lines)
            scope_map = _build_scope_map_js(lines)

        # Phase 2: Identify taint sources
        tainted = _identify_sources(assignments, sources)
        if not tainted:
            return []

        # Phase 3: Propagate taint
        tainted = _propagate_taint(assignments, tainted)

        # Phase 4: Detect sinks
        chains = _detect_sinks(lines, sinks, tainted, scope_map)
        if not chains:
            return []

        # Phase 5: Convert to findings (with sensitivity filter)
        min_sev = _min_severity(sensitivity)
        findings: list[Finding] = []
        for chain in chains:
            finding = _chain_to_finding(chain, code, file_path)
            if _SEVERITY_ORDER[finding.severity] >= min_sev:
                enrich_finding(finding, source=code)
                findings.append(finding)

        return findings

    def capabilities(self) -> dict[str, Any]:
        return {
            "description": "Cross-line data flow analysis via taint tracking",
            "analysis_type": "data_flow",
            "supported_languages": ["javascript", "python"],
            "speed": "moderate",
            "cross_line": True,
            "data_flow": True,
            "semantic": False,
        }

    @staticmethod
    def _resolve_language(
        language: str | None,
        file_path: str | None,
    ) -> str | None:
        """Resolve language from hint or file extension."""
        if language:
            return language.lower()
        if file_path:
            ext = os.path.splitext(file_path)[1].lower()
            return EXTENSION_MAP.get(ext)
        return None
