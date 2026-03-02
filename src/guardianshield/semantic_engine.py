"""SemanticEngine — structure-aware confidence adjustment.

Implements the third analysis engine for GuardianShield's multi-engine
pipeline.  Unlike RegexEngine and DeepEngine which *find* vulnerabilities,
SemanticEngine *adjusts confidence* on existing findings by analysing code
structure — test files get lower confidence, dead code is de-prioritised,
exception handlers are contextualised, and uncalled functions are flagged.

Uses Python's stdlib ``ast`` module for Python analysis and regex-based
heuristics for JavaScript/TypeScript.  Zero external dependencies.
"""

from __future__ import annotations

import ast
import os
import re
from typing import Any

from .findings import Finding

# ---------------------------------------------------------------------------
# Test file detection
# ---------------------------------------------------------------------------

_TEST_FILE_PATTERNS = [
    re.compile(r"(^|/)test_[^/]*\.py$"),
    re.compile(r"(^|/)[^/]*_test\.py$"),
    re.compile(r"(^|/)[^/]*_test\.go$"),
    re.compile(r"(^|/)[^/]*\.test\.[jt]sx?$"),
    re.compile(r"(^|/)[^/]*\.spec\.[jt]sx?$"),
    re.compile(r"(^|/)[^/]*_spec\.rb$"),
    re.compile(r"(^|/)tests/"),
    re.compile(r"(^|/)__tests__/"),
    re.compile(r"(^|/)spec/"),
    re.compile(r"(^|/)conftest\.py$"),
    re.compile(r"(^|/)test_helper\.rb$"),
]


def is_test_file(file_path: str | None) -> bool:
    """Return True if *file_path* matches a common test file pattern."""
    if file_path is None:
        return False
    normalised = file_path.replace(os.sep, "/")
    return any(p.search(normalised) for p in _TEST_FILE_PATTERNS)


# ---------------------------------------------------------------------------
# Python AST helpers  (all return empty on SyntaxError)
# ---------------------------------------------------------------------------

_TERMINAL = (ast.Return, ast.Raise, ast.Break, ast.Continue)


def _find_dead_code_lines(code: str) -> set[int]:
    """1-based line numbers of unreachable statements after return/raise/break/continue."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()

    dead: set[int] = set()

    def _check_body(stmts: list[ast.stmt]) -> None:
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, _TERMINAL) and i + 1 < len(stmts):
                for s in stmts[i + 1 :]:
                    end = getattr(s, "end_lineno", s.lineno)
                    for line in range(s.lineno, end + 1):
                        dead.add(line)
                break

    for node in ast.walk(tree):
        for attr in ("body", "orelse", "finalbody", "handlers"):
            body = getattr(node, attr, None)
            if isinstance(body, list) and body and isinstance(body[0], ast.stmt):
                _check_body(body)

    return dead


def _find_try_except_ranges(code: str) -> list[tuple[int, int, list[str]]]:
    """``(start_line, end_line, exception_names)`` for each handler body.

    Lines are 1-based.  *exception_names* may be empty for bare ``except:``.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    ranges: list[tuple[int, int, list[str]]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                start = handler.body[0].lineno if handler.body else handler.lineno
                end = max(
                    (getattr(s, "end_lineno", s.lineno) for s in handler.body),
                    default=start,
                )
                names: list[str] = []
                if handler.type is not None:
                    if isinstance(handler.type, ast.Name):
                        names.append(handler.type.id)
                    elif isinstance(handler.type, ast.Tuple):
                        for elt in handler.type.elts:
                            if isinstance(elt, ast.Name):
                                names.append(elt.id)
                ranges.append((start, end, names))

    return ranges


def _find_defined_functions(code: str) -> dict[str, tuple[int, int]]:
    """``{name: (start_line, end_line)}`` for Python function definitions.  1-based."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {}

    funcs: dict[str, tuple[int, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            funcs[node.name] = (node.lineno, end)
    return funcs


def _find_called_functions(code: str) -> set[str]:
    """Names invoked via ``ast.Call`` nodes."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()

    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called.add(node.func.attr)
    return called


def _find_unused_import_lines(code: str) -> set[int]:
    """1-based line numbers of import statements whose names are never referenced."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()

    # Collect imported names → line number.
    imported: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                imported[name] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue
                name = alias.asname or alias.name
                imported[name] = node.lineno

    if not imported:
        return set()

    # ast.Name nodes are *references* — imports don't produce Name nodes.
    referenced: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            referenced.add(node.id)

    return {lineno for name, lineno in imported.items() if name not in referenced}


# ---------------------------------------------------------------------------
# JS/TS heuristics  (regex-based)
# ---------------------------------------------------------------------------

_JS_FUNC_DEF = re.compile(
    r"(?:^|\n)\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(\w+)",
)
_JS_ARROW_CONST = re.compile(
    r"(?:^|\n)\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*="
    r"\s*(?:async\s+)?(?:\([^)]*\)|\w+)\s*=>",
)
_JS_FUNC_EXPR = re.compile(
    r"(?:^|\n)\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*="
    r"\s*(?:async\s+)?function\s*\(",
)
_JS_EXPORT_NAME = re.compile(
    r"(?:^|\n)\s*export\s+(?:default\s+)?(?:async\s+)?"
    r"(?:function|const|let|var|class)\s+(\w+)",
)
_JS_EXPORT_BLOCK = re.compile(r"export\s*\{([^}]+)\}")
_JS_CALL = re.compile(r"(?<!function )\b(\w+)\s*\(")


def _find_brace_end(lines: list[str], start_idx: int) -> int:
    """1-based end line of a brace-delimited block (simple heuristic)."""
    depth = 0
    found_open = False
    for i in range(start_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                found_open = True
            elif ch == "}":
                depth -= 1
                if found_open and depth == 0:
                    return i + 1
    return len(lines)


def _find_js_functions(
    code: str,
) -> list[tuple[str, int, int, bool]]:
    """``[(name, start_line, end_line, is_exported), ...]`` for JS/TS."""
    lines = code.split("\n")

    # Collect exports.
    exports: set[str] = set()
    for m in _JS_EXPORT_NAME.finditer(code):
        exports.add(m.group(1))
    for m in _JS_EXPORT_BLOCK.finditer(code):
        for name in m.group(1).split(","):
            name = name.strip().split(" ")[0]
            if name:
                exports.add(name)

    # Collect function definitions.
    defs: list[tuple[str, int]] = []
    for pat in (_JS_FUNC_DEF, _JS_ARROW_CONST, _JS_FUNC_EXPR):
        for m in pat.finditer(code):
            line_no = code[: m.start()].count("\n") + 1
            defs.append((m.group(1), line_no))

    # De-dup (a function might match multiple patterns).
    seen: set[str] = set()
    unique: list[tuple[str, int]] = []
    for name, line in defs:
        if name not in seen:
            seen.add(name)
            unique.append((name, line))

    functions: list[tuple[str, int, int, bool]] = []
    for name, start_line in unique:
        end_line = _find_brace_end(lines, start_line - 1)
        functions.append((name, start_line, end_line, name in exports))

    return functions


def _find_js_calls(code: str) -> set[str]:
    """Function call sites in JS/TS code."""
    return {m.group(1) for m in _JS_CALL.finditer(code)}


# ---------------------------------------------------------------------------
# SemanticEngine
# ---------------------------------------------------------------------------


class SemanticEngine:
    """Structure-aware confidence adjuster.

    Satisfies the :class:`AnalysisEngine` protocol but returns no findings
    from :meth:`analyze`.  Its primary work happens in :meth:`adjust_findings`,
    called as a post-processing step by ``core.py``.
    """

    @property
    def name(self) -> str:
        return "semantic"

    def analyze(
        self,
        code: str,
        language: str | None = None,
        sensitivity: str = "medium",
        file_path: str | None = None,
    ) -> list[Finding]:
        """Protocol compliance — SemanticEngine finds nothing new."""
        return []

    def capabilities(self) -> dict[str, Any]:
        return {
            "description": (
                "Structure-aware confidence adjustment "
                "(test files, dead code, exception handlers, uncalled functions)"
            ),
            "analysis_type": "confidence_adjustment",
            "supported_languages": ["python", "javascript", "typescript"],
            "speed": "fast",
            "cross_line": True,
            "data_flow": False,
            "semantic": True,
        }

    # ---------------------------------------------------------------
    # Post-processing
    # ---------------------------------------------------------------

    def adjust_findings(
        self,
        findings: list[Finding],
        code: str,
        language: str | None = None,
        file_path: str | None = None,
    ) -> list[Finding]:
        """Adjust confidence on existing findings based on code structure.

        Mutates *findings* in place and returns the same list.

        Adjustment rules (cumulative, floor 0.1):

        ============= ====== ============
        Check         Delta  Languages
        ============= ====== ============
        Test file     -0.3   All
        Dead code     -0.3   Python
        Except body   -0.15  Python
        Uncalled func -0.2   Python, JS
        Unused import -0.25  Python
        ============= ====== ============
        """
        if not findings:
            return findings

        test_file = is_test_file(file_path)

        # --- Python structural analysis ---
        dead_lines: set[int] = set()
        except_ranges: list[tuple[int, int, list[str]]] = []
        py_uncalled: list[tuple[int, int]] = []
        unused_import_lines: set[int] = set()

        if language == "python":
            dead_lines = _find_dead_code_lines(code)
            except_ranges = _find_try_except_ranges(code)
            defined = _find_defined_functions(code)
            called = _find_called_functions(code)
            for fn_name, (start, end) in defined.items():
                if fn_name not in called:
                    py_uncalled.append((start, end))
            unused_import_lines = _find_unused_import_lines(code)

        # --- JS/TS structural analysis ---
        js_uncalled: list[tuple[int, int]] = []
        if language in ("javascript", "typescript"):
            js_funcs = _find_js_functions(code)
            js_calls = _find_js_calls(code)
            for fname, start, end, is_exported in js_funcs:
                if fname not in js_calls and not is_exported:
                    js_uncalled.append((start, end))

        # --- Apply adjustments ---
        for finding in findings:
            adjustments: list[dict[str, Any]] = []
            original = finding.confidence if finding.confidence is not None else 0.5
            current = original
            line = finding.line_number

            if test_file:
                current -= 0.3
                adjustments.append(
                    {"reason": "test_file", "delta": -0.3, "original": original, "adjusted": current}
                )

            if line in dead_lines:
                current -= 0.3
                adjustments.append(
                    {"reason": "dead_code", "delta": -0.3, "original": original, "adjusted": current}
                )

            if any(s <= line <= e for s, e, _ in except_ranges):
                current -= 0.15
                adjustments.append(
                    {"reason": "exception_handler", "delta": -0.15, "original": original, "adjusted": current}
                )

            if any(s <= line <= e for s, e in py_uncalled):
                current -= 0.2
                adjustments.append(
                    {"reason": "uncalled_function", "delta": -0.2, "original": original, "adjusted": current}
                )

            if any(s <= line <= e for s, e in js_uncalled):
                current -= 0.2
                adjustments.append(
                    {"reason": "uncalled_function", "delta": -0.2, "original": original, "adjusted": current}
                )

            if line in unused_import_lines:
                current -= 0.25
                adjustments.append(
                    {"reason": "unused_import", "delta": -0.25, "original": original, "adjusted": current}
                )

            if adjustments:
                finding.confidence = max(0.1, current)
                finding.details["semantic_adjustments"] = adjustments
                finding.details["semantic_adjusted"] = True

        return findings
