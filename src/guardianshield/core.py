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
from typing import Any, Callable, List, Optional

from . import __version__
from .audit import AuditLog
from .config import ProjectConfig
from .content import check_content
from .findings import Finding
from .injection import check_injection
from .manifest import parse_manifest
from .osv import Dependency, OsvCache, check_dependencies as _check_dependencies
from .patterns import EXTENSION_MAP
from .pii import check_pii
from .profiles import SafetyProfile, load_profile, list_profiles
from .scanner import scan_code as _scan_code
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
        audit_path: Optional[str] = None,
        project_config: Optional[ProjectConfig] = None,
        osv_cache: Optional[OsvCache] = None,
    ) -> None:
        # If project_config specifies a profile, use it (but explicit
        # profile arg takes precedence over config file).
        if project_config and project_config.profile and profile == "general":
            profile = project_config.profile
        self._profile = load_profile(profile)
        self._audit = AuditLog(db_path=audit_path)
        self._project_config = project_config
        self._osv_cache = osv_cache

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
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Persist a scan event to the audit log."""
        self._audit.log_scan(
            scan_type=scan_type,
            profile=self._profile.name,
            input_hash=self._hash_input(text),
            findings=findings,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    @property
    def profile(self) -> SafetyProfile:
        """Return the active safety profile."""
        return self._profile

    @property
    def project_config(self) -> Optional[ProjectConfig]:
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
    # Scan methods
    # ------------------------------------------------------------------

    def scan_code(
        self,
        code: str,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
    ) -> list[Finding]:
        """Scan source code for vulnerabilities and hardcoded secrets.

        Combines the code vulnerability scanner and the secret detector.
        """
        findings: list[Finding] = []

        cfg = self._profile.code_scanner
        if cfg.enabled:
            findings.extend(
                _scan_code(
                    code,
                    sensitivity=cfg.sensitivity,
                    file_path=file_path,
                    language=language,
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

        self._log("output", text, findings)
        return findings

    def scan_file(
        self,
        path: str,
        language: Optional[str] = None,
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
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            code = fh.read()
        return self.scan_code(code, file_path=path, language=language)

    def scan_directory(
        self,
        path: str,
        extensions: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
        on_progress: Optional[Callable[[str, int, int], None]] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
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
        file_path: Optional[str] = None,
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
        exclude: Optional[List[str]] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
    ) -> list[Finding]:
        """Walk a directory tree, detect manifest files, and scan dependencies.

        Args:
            path: Root directory to walk.
            exclude: Glob patterns for paths to skip.
            on_finding: Optional callback invoked for each Finding.

        Returns:
            A list of :class:`Finding` instances for vulnerable dependencies.
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
                    with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
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

        return findings

    @property
    def osv_cache(self) -> OsvCache:
        """Return the shared :class:`OsvCache` instance, creating one if needed."""
        if self._osv_cache is None:
            self._osv_cache = OsvCache()
        return self._osv_cache

    # ------------------------------------------------------------------
    # Audit / status
    # ------------------------------------------------------------------

    def get_audit_log(
        self,
        scan_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query the audit log."""
        return self._audit.query_log(
            scan_type=scan_type, limit=limit, offset=offset
        )

    def get_findings(
        self,
        audit_id: Optional[int] = None,
        finding_type: Optional[str] = None,
        severity: Optional[str] = None,
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
        if self._project_config:
            result["project_config"] = self._project_config.to_dict()
        return result

    def close(self) -> None:
        """Close the audit database connection."""
        self._audit.close()
