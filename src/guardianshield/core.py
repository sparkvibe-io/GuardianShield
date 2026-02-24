"""Core orchestrator for GuardianShield.

Ties together all scanner modules, profiles, and the audit log into a
single :class:`GuardianShield` façade.  Each scan method checks the
active profile configuration, calls the relevant scanner(s), logs results
to the audit database, and returns a list of findings.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
from typing import Any, Callable, List, Optional

from .audit import AuditLog
from .config import ProjectConfig
from .content import check_content
from .findings import Finding
from .injection import check_injection
from .patterns import EXTENSION_MAP
from .pii import check_pii
from .profiles import SafetyProfile, load_profile, list_profiles
from .scanner import scan_code as _scan_code
from .secrets import check_secrets


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
    ) -> None:
        # If project_config specifies a profile, use it (but explicit
        # profile arg takes precedence over config file).
        if project_config and project_config.profile and profile == "general":
            profile = project_config.profile
        self._profile = load_profile(profile)
        self._audit = AuditLog(db_path=audit_path)
        self._project_config = project_config

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
            except (OSError, UnicodeDecodeError):
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
            "version": "0.2.0",
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
