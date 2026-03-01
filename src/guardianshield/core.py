"""Core orchestrator for GuardianShield.

Ties together all scanner modules, profiles, and the audit log into a
single :class:`GuardianShield` façade.  Each scan method checks the
active profile configuration, calls the relevant scanner(s), logs results
to the audit database, and returns a list of findings.
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import os
from typing import Any, Callable

from . import __version__
from .audit import AuditLog
from .config import ProjectConfig
from .content import check_content
from .engines import AnalysisEngine, EngineRegistry, RegexEngine
from .feedback import FalsePositiveDB
from .findings import Finding
from .injection import check_injection
from .manifest import parse_manifest
from .osv import Dependency, OsvCache
from .osv import check_dependencies as _check_dependencies
from .patterns import EXTENSION_MAP
from .pii import check_pii
from .profiles import SafetyProfile, list_profiles, load_profile
from .secrets import check_secrets

logger = logging.getLogger(__name__)


class GuardianShield:
    """Main orchestrator that delegates to individual scanners.

    Args:
        profile: Name of the safety profile to activate (default ``"general"``).
        audit_path: Path to the SQLite audit database.  ``None`` uses the
            default ``~/.guardianshield/audit.db``.
    """

    def __init__(
        self,
        profile: str = "general",
        audit_path: str | None = None,
        project_config: ProjectConfig | None = None,
        osv_cache: OsvCache | None = None,
        feedback_db: FalsePositiveDB | None = None,
    ) -> None:
        # If project_config specifies a profile, use it (but explicit
        # profile arg takes precedence over config file).
        if project_config and project_config.profile and profile == "general":
            profile = project_config.profile
        self._profile = load_profile(profile)
        self._audit = AuditLog(db_path=audit_path)
        self._project_config = project_config
        self._osv_cache = osv_cache
        self._feedback_db = feedback_db
        self._engine_registry = EngineRegistry()
        self._engine_registry.register(RegexEngine())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_input(text: str) -> str:
        """Return a truncated SHA-256 hex digest of *text*.

        Only the first 16 characters are kept so the audit log never
        stores raw user input.
        """
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]

    def _log(
        self,
        scan_type: str,
        text: str,
        findings: list[Finding],
        metadata: dict[str, Any] | None = None,
    ) -> int | None:
        """Persist a scan event to the audit log.

        Returns the ``audit_log.id`` on success, or ``None`` if logging
        failed.  Scan results are never discarded due to an audit failure.
        """
        try:
            return self._audit.log_scan(
                scan_type=scan_type,
                profile=self._profile.name,
                input_hash=self._hash_input(text),
                findings=findings,
                metadata=metadata,
            )
        except Exception:
            logger.warning(
                "Audit logging failed for scan_type=%s; "
                "scan results are still returned.",
                scan_type,
                exc_info=True,
            )
            return None

    def _annotate_fps(self, findings: list[Finding]) -> list[Finding]:
        """Annotate findings with false positive info if feedback DB is available."""
        if self._feedback_db is None:
            self._feedback_db = FalsePositiveDB()
        return self._feedback_db.annotate(findings)

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    @property
    def profile(self) -> SafetyProfile:
        """Return the active safety profile."""
        return self._profile

    @property
    def project_config(self) -> ProjectConfig | None:
        """Return the project configuration, if any."""
        return self._project_config

    def set_profile(self, name: str) -> SafetyProfile:
        """Switch to a different safety profile.

        Args:
            name: One of the built-in profile names or a custom YAML profile.

        Returns:
            The newly-activated :class:`SafetyProfile`.

        Raises:
            ValueError: If the profile is unknown.
        """
        self._profile = load_profile(name)
        return self._profile

    # ------------------------------------------------------------------
    # Engine management
    # ------------------------------------------------------------------

    @property
    def engine_registry(self) -> EngineRegistry:
        """Return the engine registry for this instance."""
        return self._engine_registry

    def list_engines(self) -> list[dict]:
        """Return info about all registered engines with enabled status."""
        return self._engine_registry.list_engines(
            enabled_names=self._profile.code_scanner.engines,
        )

    def set_engines(self, engine_names: list[str]) -> list[str]:
        """Set the active engines for code scanning.

        Args:
            engine_names: List of engine names to enable.

        Returns:
            The updated list of enabled engine names.

        Raises:
            ValueError: If any name is not a registered engine.
        """
        available = set(self._engine_registry.available_names)
        unknown = [n for n in engine_names if n not in available]
        if unknown:
            raise ValueError(
                f"Unknown engine(s): {', '.join(unknown)}. "
                f"Available: {', '.join(sorted(available))}"
            )
        self._profile.code_scanner.engines = list(engine_names)
        return list(engine_names)

    def register_engine(self, engine: AnalysisEngine) -> None:
        """Register a custom analysis engine."""
        self._engine_registry.register(engine)

    # ------------------------------------------------------------------
    # Scan methods
    # ------------------------------------------------------------------

    def scan_code(
        self,
        code: str,
        file_path: str | None = None,
        language: str | None = None,
        engines: list[str] | None = None,
    ) -> list[Finding]:
        """Scan source code for vulnerabilities and hardcoded secrets.

        Combines the code vulnerability scanner and the secret detector.

        Args:
            code: Source code to scan.
            file_path: Optional file path for context and language detection.
            language: Optional language hint.
            engines: Optional list of engine names to use for this scan.
                When ``None``, uses the engines configured in the active
                profile's ``code_scanner.engines``.
        """
        findings: list[Finding] = []

        cfg = self._profile.code_scanner
        if cfg.enabled:
            engine_names = engines if engines is not None else cfg.engines
            active_engines = self._engine_registry.enabled_engines(engine_names)
            for engine in active_engines:
                findings.extend(
                    engine.analyze(
                        code,
                        language=language,
                        sensitivity=cfg.sensitivity,
                        file_path=file_path,
                    )
                )

        sec_cfg = self._profile.secret_scanner
        if sec_cfg.enabled:
            findings.extend(
                check_secrets(
                    code,
                    sensitivity=sec_cfg.sensitivity,
                    file_path=file_path,
                )
            )

        self._annotate_fps(findings)
        self._log("code", code, findings, {"file_path": file_path})
        return findings

    def scan_input(self, text: str) -> list[Finding]:
        """Check user/agent input for prompt injection attempts."""
        findings: list[Finding] = []

        cfg = self._profile.injection_detector
        if cfg.enabled:
            findings.extend(
                check_injection(text, sensitivity=cfg.sensitivity)
            )

        self._annotate_fps(findings)
        self._log("input", text, findings)
        return findings

    def scan_output(self, text: str) -> list[Finding]:
        """Check AI output for PII leaks and content violations."""
        findings: list[Finding] = []

        pii_cfg = self._profile.pii_detector
        if pii_cfg.enabled:
            findings.extend(
                check_pii(text, sensitivity=pii_cfg.sensitivity)
            )

        content_cfg = self._profile.content_moderator
        if content_cfg.enabled:
            findings.extend(
                check_content(
                    text,
                    sensitivity=content_cfg.sensitivity,
                    blocked_categories=self._profile.blocked_categories or None,
                )
            )

        self._annotate_fps(findings)
        self._log("output", text, findings)
        return findings

    def scan_file(
        self,
        path: str,
        language: str | None = None,
    ) -> list[Finding]:
        """Scan a single source file for vulnerabilities and secrets.

        Reads the file, auto-detects language from extension if not
        provided, and delegates to :meth:`scan_code`.

        Args:
            path: Absolute or relative path to the file.
            language: Optional language hint.  Auto-detected from
                extension when omitted.

        Returns:
            A list of :class:`Finding` instances.

        Raises:
            FileNotFoundError: If *path* does not exist.
            IsADirectoryError: If *path* is a directory.
        """
        path = os.path.abspath(path)
        with open(path, encoding="utf-8", errors="replace") as fh:
            code = fh.read()
        return self.scan_code(code, file_path=path, language=language)

    def scan_directory(
        self,
        path: str,
        extensions: list[str] | None = None,
        exclude: list[str] | None = None,
        on_progress: Callable[[str, int, int], None] | None = None,
        on_finding: Callable[[Finding], None] | None = None,
    ) -> list[Finding]:
        """Recursively scan a directory for vulnerabilities and secrets.

        Args:
            path: Root directory to scan.
            extensions: File extensions to include (e.g. ``[".py", ".js"]``).
                Defaults to all extensions in :data:`EXTENSION_MAP`.
            exclude: Glob patterns for paths to skip
                (e.g. ``["node_modules/*", ".git/*"]``).
            on_progress: Optional callback ``(file_path, files_done, total)``
                invoked before each file is scanned.
            on_finding: Optional callback invoked for each individual Finding.

        Returns:
            A flat list of all findings across all scanned files.
        """
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            raise NotADirectoryError(f"Not a directory: {path}")

        if extensions is None:
            extensions = list(EXTENSION_MAP.keys())
        # Normalise extensions to lowercase with leading dot.
        extensions = [
            ext if ext.startswith(".") else f".{ext}"
            for ext in extensions
        ]

        # Combine user excludes with project config excludes.
        exclude_patterns = list(exclude or [])
        if self._project_config and self._project_config.exclude_paths:
            exclude_patterns.extend(self._project_config.exclude_paths)

        # Collect matching files.
        files: list[str] = []
        for dirpath, dirnames, filenames in os.walk(path):
            # Skip hidden directories and common noise.
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith(".")
                and d not in ("node_modules", "__pycache__", ".git")
            ]
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                ext = os.path.splitext(fname)[1].lower()
                if ext not in extensions:
                    continue
                # Check exclude patterns against relative path.
                rel = os.path.relpath(fpath, path)
                if any(fnmatch.fnmatch(rel, pat) for pat in exclude_patterns):
                    continue
                files.append(fpath)

        all_findings: list[Finding] = []
        total = len(files)

        for idx, fpath in enumerate(sorted(files)):
            if on_progress:
                on_progress(fpath, idx, total)
            try:
                findings = self.scan_file(fpath)
            except (OSError, UnicodeDecodeError) as exc:
                logger.warning("Skipped file %s: %s", fpath, exc)
                continue
            if on_finding:
                for f in findings:
                    on_finding(f)
            all_findings.extend(findings)

        return all_findings

    def check_secrets(
        self,
        text: str,
        file_path: str | None = None,
    ) -> list[Finding]:
        """Dedicated secret detection scan."""
        findings: list[Finding] = []

        cfg = self._profile.secret_scanner
        if cfg.enabled:
            findings.extend(
                check_secrets(
                    text,
                    sensitivity=cfg.sensitivity,
                    file_path=file_path,
                )
            )

        self._annotate_fps(findings)
        self._log("secrets", text, findings, {"file_path": file_path})
        return findings

    def check_dependencies(
        self,
        dependencies: list[Dependency],
        auto_sync: bool = True,
    ) -> list[Finding]:
        """Check package dependencies for known vulnerabilities.

        Uses the OSV.dev local cache to look up CVEs for each dependency.
        Results are logged to the audit database under scan_type
        ``"dependencies"``.

        Args:
            dependencies: List of :class:`Dependency` objects to check.
            auto_sync: If ``True``, syncs packages that are not yet cached.

        Returns:
            A list of :class:`Finding` instances for vulnerable packages.
        """
        if self._osv_cache is None:
            self._osv_cache = OsvCache()

        findings = _check_dependencies(
            dependencies,
            cache=self._osv_cache,
            auto_sync=auto_sync,
        )

        self._annotate_fps(findings)

        # Build a stable, hashable representation for the audit log.
        dep_text = ";".join(
            f"{d.ecosystem}/{d.name}=={d.version}" for d in dependencies
        )
        metadata = {
            "dependency_count": len(dependencies),
            "ecosystems": list({d.ecosystem for d in dependencies}),
        }
        self._log("dependencies", dep_text, findings, metadata)
        return findings

    # Known manifest filenames to detect during directory walks.
    _MANIFEST_FILENAMES = frozenset({
        "requirements.txt",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Pipfile.lock",
        "go.mod",
        "go.sum",
        "composer.json",
        "composer.lock",
        "pyproject.toml",
    })

    # Directories to always skip when walking for manifests.
    _SKIP_DIRS = frozenset({
        "node_modules", "__pycache__", ".git", "vendor", "venv", ".venv",
    })

    @staticmethod
    def _is_requirements_variant(name: str) -> bool:
        """Return True for requirements-*.txt / requirements_*.txt files."""
        if not name.startswith("requirements"):
            return False
        if not name.endswith(".txt"):
            return False
        return name != "requirements.txt"  # exact match handled in set

    def scan_dependencies_in_directory(
        self,
        path: str,
        exclude: list[str] | None = None,
        on_finding: Callable[[Finding], None] | None = None,
    ) -> tuple[list[Finding], dict[str, Any]]:
        """Walk a directory tree, detect manifest files, and scan dependencies.

        Args:
            path: Root directory to walk.
            exclude: Glob patterns for paths to skip.
            on_finding: Optional callback invoked for each Finding.

        Returns:
            A tuple of ``(findings, metadata)`` where *metadata* contains
            ``manifests_found`` and ``dependency_count``.
        """
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            raise NotADirectoryError(f"Not a directory: {path}")

        # Combine user excludes with project config excludes.
        exclude_patterns = list(exclude or [])
        if self._project_config and self._project_config.exclude_paths:
            exclude_patterns.extend(self._project_config.exclude_paths)

        # Collect manifests.
        manifests_found: list[str] = []
        all_deps: list[Dependency] = []
        seen: set[tuple[str, str]] = set()  # (name, ecosystem) for dedup

        for dirpath, dirnames, filenames in os.walk(path):
            # Skip hidden dirs and common noise directories.
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith(".") and d not in self._SKIP_DIRS
            ]

            for fname in filenames:
                if fname not in self._MANIFEST_FILENAMES and not self._is_requirements_variant(fname):
                    continue

                fpath = os.path.join(dirpath, fname)
                rel = os.path.relpath(fpath, path)
                if any(fnmatch.fnmatch(rel, pat) for pat in exclude_patterns):
                    continue

                try:
                    with open(fpath, encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                    deps = parse_manifest(content, fname)
                except (OSError, ValueError) as exc:
                    logger.warning("Skipped manifest %s: %s", fpath, exc)
                    continue

                if deps:
                    manifests_found.append(rel)
                    for dep in deps:
                        key = (dep.name, dep.ecosystem)
                        if key not in seen:
                            seen.add(key)
                            all_deps.append(dep)

        # Check collected dependencies for vulnerabilities.
        # Use _check_dependencies directly to avoid double audit logging
        # (check_dependencies() logs under "dependencies", and we log below
        # under "directory_dependencies").
        if all_deps:
            if self._osv_cache is None:
                self._osv_cache = OsvCache()
            findings = _check_dependencies(all_deps, cache=self._osv_cache)
        else:
            findings = []

        self._annotate_fps(findings)

        if on_finding:
            for f in findings:
                on_finding(f)

        # Audit log with dedicated scan type.
        dep_text = ";".join(
            f"{d.ecosystem}/{d.name}=={d.version}" for d in all_deps
        ) or "(empty)"
        metadata = {
            "manifests_found": manifests_found,
            "dependency_count": len(all_deps),
        }
        self._log("directory_dependencies", dep_text, findings, metadata)

        return findings, metadata

    @property
    def osv_cache(self) -> OsvCache:
        """Return the shared :class:`OsvCache` instance, creating one if needed."""
        if self._osv_cache is None:
            self._osv_cache = OsvCache()
        return self._osv_cache

    # ------------------------------------------------------------------
    # False positive feedback
    # ------------------------------------------------------------------

    @property
    def feedback_db(self) -> FalsePositiveDB:
        """Return the shared :class:`FalsePositiveDB` instance."""
        if self._feedback_db is None:
            self._feedback_db = FalsePositiveDB()
        return self._feedback_db

    def mark_false_positive(
        self,
        finding_dict: dict[str, Any],
        reason: str = "",
    ) -> dict[str, Any]:
        """Mark a finding as false positive.

        Args:
            finding_dict: The finding dict as returned by a scan tool.
            reason: Optional user explanation.

        Returns:
            A dict with ``id``, ``fingerprint``, and ``message``.
        """
        from .findings import Finding as _Finding

        finding = _Finding.from_dict(finding_dict)
        record_id = self.feedback_db.mark(finding, reason=reason)

        from .feedback import _fingerprint
        fp = _fingerprint(finding)

        return {
            "id": record_id,
            "fingerprint": fp,
            "message": f"Finding marked as false positive (id={record_id}).",
        }

    def list_false_positives(
        self,
        scanner: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List active false positive records."""
        return self.feedback_db.list_fps(scanner=scanner, limit=limit)

    def unmark_false_positive(self, fingerprint: str) -> dict[str, Any]:
        """Remove a false positive record by fingerprint.

        Returns:
            A dict with ``success`` (bool) and ``message``.
        """
        removed = self.feedback_db.unmark(fingerprint)
        if removed:
            return {
                "success": True,
                "message": f"False positive record '{fingerprint}' removed.",
            }
        return {
            "success": False,
            "message": f"No active false positive record found for '{fingerprint}'.",
        }

    # ------------------------------------------------------------------
    # Audit / status
    # ------------------------------------------------------------------

    def get_audit_log(
        self,
        scan_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query the audit log."""
        return self._audit.query_log(
            scan_type=scan_type, limit=limit, offset=offset
        )

    def get_findings(
        self,
        audit_id: int | None = None,
        finding_type: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve past findings from the audit database."""
        return self._audit.get_findings(
            audit_id=audit_id,
            finding_type=finding_type,
            severity=severity,
            limit=limit,
        )

    def status(self) -> dict[str, Any]:
        """Return health / configuration information."""
        stats = self._audit.stats()
        result: dict[str, Any] = {
            "version": __version__,
            "profile": self._profile.name,
            "available_profiles": list_profiles(),
            "scanners": {
                "code_scanner": self._profile.code_scanner.enabled,
                "secret_scanner": self._profile.secret_scanner.enabled,
                "injection_detector": self._profile.injection_detector.enabled,
                "pii_detector": self._profile.pii_detector.enabled,
                "content_moderator": self._profile.content_moderator.enabled,
            },
            "audit": stats,
        }
        result["engines"] = self._engine_registry.list_engines(
            enabled_names=self._profile.code_scanner.engines,
        )
        if self._project_config:
            result["project_config"] = self._project_config.to_dict()
        # Include false positive feedback stats if DB is available.
        if self._feedback_db is not None:
            try:
                result["false_positives"] = self._feedback_db.stats()
            except Exception:
                result["false_positives"] = {"error": "unavailable"}
        return result

    def close(self) -> None:
        """Close database connections."""
        self._audit.close()
        if self._feedback_db is not None:
            self._feedback_db.close()
