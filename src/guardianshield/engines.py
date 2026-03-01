"""Analysis engine abstraction for GuardianShield.

Defines the :class:`AnalysisEngine` protocol, the :class:`RegexEngine`
wrapper around the existing regex-based scanner, and an
:class:`EngineRegistry` for managing available engines.

This is the foundation of the v1.1 multi-engine analysis pipeline.
Phase 1 wraps the existing scanner; future phases add data-flow and
semantic engines.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from .findings import Finding


@runtime_checkable
class AnalysisEngine(Protocol):
    """Protocol for pluggable analysis engines.

    Any class that implements ``name``, ``analyze()``, and
    ``capabilities()`` satisfies this protocol — no inheritance required.
    """

    @property
    def name(self) -> str:
        """Short unique identifier for this engine (e.g. ``"regex"``)."""
        ...

    def analyze(
        self,
        code: str,
        language: str | None = None,
        sensitivity: str = "medium",
        file_path: str | None = None,
    ) -> list[Finding]:
        """Analyze *code* and return a list of findings.

        Args:
            code: The source code text to analyze.
            language: Optional language hint (e.g. ``"python"``).
            sensitivity: Detection sensitivity — ``"low"``, ``"medium"``,
                or ``"high"``.
            file_path: Optional file path for context / language detection.

        Returns:
            A list of :class:`Finding` instances.
        """
        ...

    def capabilities(self) -> dict[str, Any]:
        """Return a description of this engine's capabilities.

        Expected keys: ``description``, ``analysis_type``,
        ``supported_languages``, ``speed``, ``cross_line``,
        ``data_flow``, ``semantic``.
        """
        ...


class RegexEngine:
    """Wraps the existing regex-based code scanner as an analysis engine.

    Delegates to :func:`scanner.scan_code` and tags every resulting
    finding with ``details["engine"] = "regex"``.
    """

    @property
    def name(self) -> str:
        return "regex"

    def analyze(
        self,
        code: str,
        language: str | None = None,
        sensitivity: str = "medium",
        file_path: str | None = None,
    ) -> list[Finding]:
        # Deferred import to avoid circular dependency.
        from .scanner import scan_code

        findings = scan_code(
            code,
            sensitivity=sensitivity,
            file_path=file_path,
            language=language,
        )
        for f in findings:
            f.details["engine"] = "regex"
        return findings

    def capabilities(self) -> dict[str, Any]:
        from .patterns import EXTENSION_MAP

        languages = sorted({v for v in EXTENSION_MAP.values()})
        return {
            "description": "Regex-based pattern matching for common vulnerabilities",
            "analysis_type": "pattern_matching",
            "supported_languages": languages,
            "speed": "fast",
            "cross_line": False,
            "data_flow": False,
            "semantic": False,
        }


class EngineRegistry:
    """Registry of available analysis engines.

    Each :class:`GuardianShield` instance owns its own registry,
    following the same pattern as ``_audit``, ``_osv_cache``, and
    ``_feedback_db``.
    """

    def __init__(self) -> None:
        self._engines: dict[str, AnalysisEngine] = {}

    def register(self, engine: AnalysisEngine) -> None:
        """Register an engine.

        Raises:
            TypeError: If *engine* does not satisfy :class:`AnalysisEngine`.
            ValueError: If an engine with the same name is already registered.
        """
        if not isinstance(engine, AnalysisEngine):
            raise TypeError(
                f"Expected an AnalysisEngine, got {type(engine).__name__}"
            )
        if engine.name in self._engines:
            raise ValueError(
                f"Engine {engine.name!r} is already registered"
            )
        self._engines[engine.name] = engine

    def get(self, name: str) -> AnalysisEngine:
        """Return the engine registered under *name*.

        Raises:
            KeyError: If no engine is registered with that name.
        """
        try:
            return self._engines[name]
        except KeyError:
            available = ", ".join(sorted(self._engines)) or "(none)"
            raise KeyError(
                f"Unknown engine {name!r}. Available: {available}"
            ) from None

    def list_engines(
        self,
        enabled_names: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return info dicts for all registered engines.

        Each dict contains ``name``, ``enabled`` (bool), and
        ``capabilities``.  If *enabled_names* is provided, engines
        whose name is in the list are marked ``enabled=True``.
        """
        enabled_set = set(enabled_names) if enabled_names else set()
        result = []
        for name in sorted(self._engines):
            engine = self._engines[name]
            result.append({
                "name": name,
                "enabled": name in enabled_set if enabled_names is not None else True,
                "capabilities": engine.capabilities(),
            })
        return result

    def enabled_engines(
        self,
        engine_names: list[str],
    ) -> list[AnalysisEngine]:
        """Return engines matching *engine_names*, in order.

        Unknown names are silently skipped so that stale profile
        configs don't break scanning.
        """
        result = []
        for name in engine_names:
            engine = self._engines.get(name)
            if engine is not None:
                result.append(engine)
        return result

    @property
    def available_names(self) -> list[str]:
        """Sorted list of all registered engine names."""
        return sorted(self._engines)
